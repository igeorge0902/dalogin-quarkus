'use strict';

var moviesControllers = angular.module('ngRepeat', ['ab-base64', 'ngRoute', 'ngCookies']);

/* ----------------------------------------------------------------
   HTTP interceptor – HMAC signing for all API requests
   ---------------------------------------------------------------- */
moviesControllers.config(function ($httpProvider) {
    $httpProvider.interceptors.push(function ($q) {
        return {
            'request': function (config) {
                if (config.url !== '/mbooks-1/rest/book/movies') {
                    if (!localStorage.sessionToken_) {
                        console.warn('No sessionToken to sign the request');
                        return $q.reject('No sessionToken to sign the request!');
                    }
                }
                config.headers['X-URL'] = config.url;
                return config || $q.when(config);
            },
            responseError: function (rejection) {
                return $q.reject(rejection);
            },
            requestError: function (rejection) {
                console.log(rejection);
                return $q.reject(rejection);
            },
            'response': function (response) {
                return response || $q.when(response);
            }
        };
    });

    // Custom request transformer – generates HMAC headers
    $httpProvider.defaults.transformRequest.push(function (data, headersGetter) {
        var guid = function () {
            var nav = window.navigator;
            var screen = window.screen;
            var guid = nav.mimeTypes.length;
            guid += nav.userAgent.replace(/\D+/g, '');
            guid += nav.plugins.length;
            guid += screen.height || '';
            guid += screen.width || '';
            guid += screen.pixelDepth || '';
            return guid;
        };

        var uuid = guid();
        var encodedString = encodeURIComponent(uuid);
        var microTime = new Date().getTime();

        var hmacSec = CryptoJS.HmacSHA512(headersGetter()['X-URL'], encodeURIComponent(uuid));
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

        var hash = CryptoJS.HmacSHA512(
            headersGetter()['X-URL'] + ':' + encodedString + ':' + microTime, hmacSec
        );
        var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

        headersGetter()['X-HMAC-HASH'] = hashInBase64;
        headersGetter()['X-MICRO-TIME'] = microTime;
        headersGetter()['X-Device'] = encodedString;
        headersGetter()['X-URL'] = '';

        if (localStorage.sessionToken_) {
            headersGetter()['X-Token'] = localStorage.sessionToken_;
        }
    });

    $httpProvider.defaults.headers.get = { 'My-Headers': 'value' };
});

/* ----------------------------------------------------------------
   Controller: repeatController – fetches movie list
   ---------------------------------------------------------------- */
moviesControllers.controller('repeatController', function ($scope, base64, $http, $route, $routeParams, $location) {
    $scope.$route = $route;
    $scope.$location = $location;
    $scope.$routeParams = $routeParams;
    $scope.movies = [];
    $scope.loadError = false;

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/movies',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Token': 'client-secret'
        }
    }).success(function (data, status, headers) {
        localStorage.sessionToken_ = headers('APIKEY');
        $scope.movies = data.movies || [];
    }).error(function () {
        $scope.loadError = true;
    });
});

/* ----------------------------------------------------------------
   Controller: BookController – fetches venues/locations for a movie
   ---------------------------------------------------------------- */
moviesControllers.controller('BookController', function ($http, $scope, $routeParams) {
    $scope.params = $routeParams;
    $scope.locations = [];

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/venue/v2/' + $scope.params.bookId,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    }).success(function (data) {
        $scope.locations = data.locations || [];
        // Scroll to content area
        setTimeout(function () { window.scrollTo({ top: 0, behavior: 'smooth' }); }, 100);
    });
});

/* ----------------------------------------------------------------
   Controller: ExampleController – dates + seat selection
   ---------------------------------------------------------------- */
moviesControllers.controller('ExampleController', function ($http, $scope, $routeParams) {
    $scope.params = $routeParams;
    $scope.dates = [];
    $scope.seats = [];
    $scope.data = {};
    $scope.seatsError = false;

    // Fetch screening dates
    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/dates/' + +$scope.params.venueId + '/' + +$scope.params.bookId,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    }).success(function (data) {
        $scope.dates = data.dates || [];
    }).error(function (data) {
        $scope.errorMsg = data;
    });

    // When user picks a date, fetch seats
    $scope.selectedItemChanged = function () {
        if (!$scope.data.model) return;
        $scope.seats = [];
        $scope.seatsError = false;

        $http({
            method: 'GET',
            url: '/mbooks-1/rest/book/seats/' + +$scope.data.model,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        }).success(function (data) {
            var rawSeats = data.seatsforscreen || [];
            // Add a 'selected' flag to each seat for UI toggling
            rawSeats.forEach(function (s) { s.selected = false; });
            $scope.seats = rawSeats;
        }).error(function () {
            $scope.seatsError = true;
        });
    };

    // Toggle seat selection (only if not already reserved)
    $scope.toggleSeat = function (seat) {
        if (seat.isReserved === '1') return;
        seat.selected = !seat.selected;
    };

    // Get the list of currently selected seats
    $scope.getSelectedSeats = function () {
        return $scope.seats.filter(function (s) { return s.selected; });
    };

    // Navigate to checkout page with selected seat IDs
    $scope.proceedToCheckout = function () {
        var selected = $scope.getSelectedSeats();
        var seatIds = selected.map(function (s) { return s.seatsId; }).join('-');
        var total = selected.length * 10;
        // Store in sessionStorage for the checkout page to pick up
        sessionStorage.setItem('checkout_seats', seatIds);
        sessionStorage.setItem('checkout_total', total);
        sessionStorage.setItem('checkout_screeningDateId', $scope.data.model);
        window.location.href = '/login/movies/checkout.html';
    };
});

/* ----------------------------------------------------------------
   Controller: CheckOutController – Braintree Drop-in + payment
   Fetches client token from the server API instead of using a
   hardcoded authorization string.
   ---------------------------------------------------------------- */
moviesControllers.controller('CheckOutController', function ($http, $scope) {
    $scope.dropinReady = false;
    $scope.dropinError = null;
    $scope.paymentSuccess = null;
    $scope.paymentError = null;
    $scope.paymentProcessing = false;

    // Restore order data from session storage
    $scope.selectedSeatIds = sessionStorage.getItem('checkout_seats') || '';
    $scope.totalAmount = sessionStorage.getItem('checkout_total') || '10';
    var screeningDateId = sessionStorage.getItem('checkout_screeningDateId') || '';

    var dropinInstance = null;

    // 1) Fetch a fresh client token from the backend
    $http({
        method: 'GET',
        url: '/login/CheckOut',
        headers: { 'Accept': 'application/json' }
    }).success(function (data) {
        var clientToken = data.clientToken;
        if (!clientToken) {
            $scope.dropinError = 'Unable to initialise payment: no client token received.';
            return;
        }

        // 2) Create the Braintree Drop-in UI
        if (typeof braintree === 'undefined' || !braintree.dropin) {
            $scope.dropinError = 'Payment library failed to load. Please refresh.';
            return;
        }

        braintree.dropin.create({
            authorization: clientToken,
            container: '#dropin-container',
            card: {
                overrides: {
                    styles: {
                        input: { 'font-size': '14px', color: '#333' },
                        'input.invalid': { color: '#e94560' },
                        'input.valid': { color: '#2e7d32' }
                    }
                }
            }
        }, function (createErr, instance) {
            $scope.$apply(function () {
                if (createErr) {
                    $scope.dropinError = 'Payment form error: ' + createErr.message;
                    return;
                }
                dropinInstance = instance;
                $scope.dropinReady = true;
            });
        });

    }).error(function () {
        $scope.dropinError = 'Could not connect to payment service. Are you logged in?';
    });

    // 3) Submit payment when user clicks Pay
    $scope.submitPayment = function () {
        if (!dropinInstance) return;
        $scope.paymentProcessing = true;
        $scope.paymentError = null;
        $scope.paymentSuccess = null;

        dropinInstance.requestPaymentMethod(function (tokenizeErr, payload) {
            if (tokenizeErr) {
                $scope.$apply(function () {
                    $scope.paymentError = 'Please complete the payment form.';
                    $scope.paymentProcessing = false;
                });
                return;
            }

            // Send nonce + order details to backend
            var postData = 'payment_method_nonce=' + encodeURIComponent(payload.nonce) +
                '&orderId=' + encodeURIComponent(screeningDateId) +
                '&seatsToBeReserved=' + encodeURIComponent($scope.selectedSeatIds);

            $http({
                method: 'POST',
                url: '/login/CheckOut',
                data: postData,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }).success(function (data) {
                $scope.paymentProcessing = false;
                if (data.Success === 'true') {
                    $scope.paymentSuccess = 'Transaction ' + (data.Status || 'completed') +
                        '. Auth code: ' + (data.AuthCode || 'N/A');
                    // Clean up session storage
                    sessionStorage.removeItem('checkout_seats');
                    sessionStorage.removeItem('checkout_total');
                    sessionStorage.removeItem('checkout_screeningDateId');
                } else {
                    $scope.paymentError = 'Transaction failed: ' + (data.ResponseText || 'Unknown error');
                }
            }).error(function () {
                $scope.paymentProcessing = false;
                $scope.paymentError = 'Payment request failed. Please try again.';
            });
        });
    };
});

/* ----------------------------------------------------------------
   Route configuration – maps URL paths to templates + controllers
   ---------------------------------------------------------------- */
moviesControllers.config(function ($routeProvider, $locationProvider) {
    $routeProvider
        .when('/mbooks-1/rest/book/venue/v2/:bookId', {
            templateUrl: 'venues.html',
            controller: 'BookController',
            resolve: {
                delay: function ($q, $timeout) {
                    var d = $q.defer();
                    $timeout(d.resolve, 10);
                    return d.promise;
                }
            }
        })
        .when('/mbooks-1/rest/book/dates/:venueId/:bookId', {
            templateUrl: 'dates.html',
            controller: 'ExampleController'
        });

    $locationProvider.html5Mode(true);
});

angular.element(document.getElementsByTagName('head')).append(
    angular.element('<base href="' + window.location.pathname + '" />')
);
