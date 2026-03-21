'use strict';

var app = angular.module('swiftCinemas', ['ngRoute']);

/* ================================================================
   HMAC-SHA512 HTTP interceptor (same logic as existing script.js)
   ================================================================ */
app.config(function ($httpProvider) {
    $httpProvider.interceptors.push(function ($q) {
        return {
            request: function (config) {
                var publicUrls = [
                    '/mbooks-1/rest/book/movies',
                    '/mbooks-1/rest/book/locations'
                ];
                var isPublic = publicUrls.indexOf(config.url) !== -1 ||
                    config.url.indexOf('/mbooks-1/rest/book/venue/') === 0 ||
                    config.url.indexOf('/mbooks-1/rest/book/dates/') === 0 ||
                    config.url.indexOf('/mbooks-1/rest/book/seats/') === 0 ||
                    config.url.indexOf('/login/') === 0;
                if (!isPublic) {
                    if (!localStorage.sessionToken_) {
                        console.warn('No sessionToken to sign the request');
                        return $q.reject('No sessionToken to sign the request!');
                    }
                }
                config.headers['X-URL'] = config.url;
                return config || $q.when(config);
            },
            responseError: function (r) { return $q.reject(r); },
            requestError: function (r) { console.log(r); return $q.reject(r); },
            response: function (r) { return r || $q.when(r); }
        };
    });

    $httpProvider.defaults.transformRequest.push(function (data, headersGetter) {
        var guid = function () {
            var nav = window.navigator, scr = window.screen;
            var g = (nav.mimeTypes ? nav.mimeTypes.length : 0);
            g += nav.userAgent.replace(/\D+/g, '');
            g += (nav.plugins ? nav.plugins.length : 0);
            g += scr.height || '';
            g += scr.width || '';
            g += scr.pixelDepth || '';
            return g;
        };
        var uuid = guid();
        var enc = encodeURIComponent(uuid);
        var t = new Date().getTime();
        var hmacSec = CryptoJS.HmacSHA512(headersGetter()['X-URL'], enc);
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);
        var hash = CryptoJS.HmacSHA512(headersGetter()['X-URL'] + ':' + enc + ':' + t, hmacSec);
        headersGetter()['X-HMAC-HASH'] = CryptoJS.enc.Base64.stringify(hash);
        headersGetter()['X-MICRO-TIME'] = t;
        headersGetter()['X-Device'] = enc;
        headersGetter()['X-URL'] = '';
        if (localStorage.sessionToken_) {
            headersGetter()['X-Token'] = localStorage.sessionToken_;
        }
        return data;
    });

    $httpProvider.defaults.headers.get = { 'My-Headers': 'value' };
});

/* ================================================================
   Route configuration — hashbang mode
   ================================================================ */
app.config(function ($routeProvider, $locationProvider) {
    $locationProvider.hashPrefix('!');
    $routeProvider
        .when('/', {
            templateUrl: 'templates/movies.html',
            controller: 'MoviesController'
        })
        .when('/venues-list', {
            templateUrl: 'templates/venues-list.html',
            controller: 'VenuesListController'
        })
        .when('/venue-movies/:locationId', {
            templateUrl: 'templates/venue-movies.html',
            controller: 'VenueMoviesController'
        })
        .when('/venues/:movieId', {
            templateUrl: 'templates/venues.html',
            controller: 'VenuesController'
        })
        .when('/dates/:locationId/:movieId', {
            templateUrl: 'templates/dates.html',
            controller: 'DatesSeatsController'
        })
        .when('/checkout', {
            templateUrl: 'templates/checkout.html',
            controller: 'CheckoutController'
        })
        .when('/purchases', {
            templateUrl: 'templates/purchases.html',
            controller: 'PurchasesController'
        })
        .when('/purchases/:purchaseId', {
            templateUrl: 'templates/purchase-detail.html',
            controller: 'PurchaseDetailController'
        })
        .when('/login', {
            templateUrl: 'templates/login.html',
            controller: 'LoginController'
        })
        .otherwise({ redirectTo: '/' });
});

/* ================================================================
   Global navigation helper + auth state
   ================================================================ */
app.run(function ($rootScope, $location, $http) {
    $rootScope.go = function (path) {
        $location.path(path);
    };

    // Auth state (shared across all controllers via $rootScope)
    $rootScope.isLoggedIn = false;
    $rootScope.loggedInUser = '';

    // Check if we have an existing valid session on startup
    // Use a lightweight session-protected endpoint to probe
    if (localStorage.getItem('filmReviewUser')) {
        $http({ method: 'GET', url: '/login/GetAllPurchases', headers: { Accept: 'application/json' } })
            .success(function () {
                $rootScope.isLoggedIn = true;
                $rootScope.loggedInUser = localStorage.getItem('filmReviewUser');
            })
            .error(function () {
                // Session expired or invalid — clear stale state
                $rootScope.isLoggedIn = false;
                $rootScope.loggedInUser = '';
                localStorage.removeItem('filmReviewUser');
            });
    }

    // Logout
    $rootScope.logout = function () {
        $http({ method: 'GET', url: '/login/logout' })
            .success(function () {
                $rootScope.isLoggedIn = false;
                $rootScope.loggedInUser = '';
                localStorage.removeItem('filmReviewUser');
                $location.path('/');
            })
            .error(function () {
                // Even if logout call fails, clear local state
                $rootScope.isLoggedIn = false;
                $rootScope.loggedInUser = '';
                localStorage.removeItem('filmReviewUser');
                $location.path('/');
            });
    };
});

/* ================================================================
   LoginController — in-app login (same HMAC logic as /login/ page)
   ================================================================ */
app.controller('LoginController', function ($scope, $http, $rootScope, $location) {
    $scope.credentials = { username: '', password: '' };
    $scope.processing = false;
    $scope.errorMsg = null;
    $scope.loggedIn = $rootScope.isLoggedIn;
    $scope.loggedInUser = $rootScope.loggedInUser;

    // Watch for external auth state changes
    $rootScope.$watch('isLoggedIn', function (v) {
        $scope.loggedIn = v;
        $scope.loggedInUser = $rootScope.loggedInUser;
    });

    $scope.login = function () {
        if (!$scope.credentials.username || !$scope.credentials.password) return;
        $scope.processing = true;
        $scope.errorMsg = null;

        var username = $scope.credentials.username;
        var password = $scope.credentials.password;

        // 1) Hash password with SHA3-512 (same as /login/ page jsR/app.js)
        var passHash = CryptoJS.SHA3(password, { outputLength: 512 });

        // 2) Generate HMAC secret: HmacSHA512(username, encodeURIComponent(passHash))
        var hmacSec = CryptoJS.HmacSHA512(username, encodeURIComponent(passHash));
        var hmacSecretB64 = CryptoJS.enc.Base64.stringify(hmacSec);

        // 3) Browser fingerprint as deviceId (same guid() as existing code)
        var nav = window.navigator, scr = window.screen;
        var deviceGuid = (nav.mimeTypes ? nav.mimeTypes.length : 0);
        deviceGuid += nav.userAgent.replace(/\D+/g, '');
        deviceGuid += (nav.plugins ? nav.plugins.length : 0);
        deviceGuid += scr.height || '';
        deviceGuid += scr.width || '';
        deviceGuid += scr.pixelDepth || '';

        // 4) Build form body
        var body = 'user=' + encodeURIComponent(username) +
                   '&pswrd=' + encodeURIComponent(passHash) +
                   '&deviceId=' + encodeURIComponent(deviceGuid);

        // 5) Compute login HMAC
        var microTime = new Date().getTime();
        var loginHmac = CryptoJS.HmacSHA512(
            '/login/HelloWorld:' + body + ':' + microTime + ':' + body.length,
            hmacSecretB64
        );
        var hmacHash = CryptoJS.enc.Base64.stringify(loginHmac);

        // 6) POST to /login/HelloWorld
        //    Override transformRequest to bypass the Film-Review HMAC transform —
        //    the login has its own HMAC formula matching the original /login/ page.
        $http({
            method: 'POST',
            url: '/login/HelloWorld',
            data: body,
            transformRequest: function (data) { return data; },
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-HMAC-HASH': hmacHash,
                'X-MICRO-TIME': String(microTime),
                'X-URL': ''
            }
        }).success(function (data, status, headers) {
            $scope.processing = false;
            if (data.Success === 'true' || data.Session === 'raked' || data.success === 1) {
                // Store session token for HMAC interceptor
                var token = headers('X-Token');
                if (token) {
                    localStorage.sessionToken_ = token;
                }
                localStorage.setItem('filmReviewUser', username);
                $rootScope.isLoggedIn = true;
                $rootScope.loggedInUser = username;
                $location.path('/');
            } else {
                $scope.errorMsg = 'Login failed. Please check your credentials.';
            }
        }).error(function (data) {
            $scope.processing = false;
            $scope.errorMsg = 'Login failed. Please check your username and password.';
        });
    };
});

/* ================================================================
   Image helper
   ================================================================ */
var IMG_BASE = '/simple-service-webapp/webapi/myresource';

/* ================================================================
   MoviesController — movie grid
   ================================================================ */
app.controller('MoviesController', function ($scope, $http) {
    $scope.movies = [];
    $scope.loading = true;
    $scope.loadError = false;
    $scope.search = '';

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/movies',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Token': 'client-secret' }
    }).success(function (data, status, headers) {
        localStorage.sessionToken_ = headers('APIKEY');
        $scope.movies = data.movies || [];
        $scope.loading = false;
    }).error(function () {
        $scope.loadError = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;
});

/* ================================================================
   VenuesController — location selection for a movie
   ================================================================ */
app.controller('VenuesController', function ($scope, $http, $routeParams) {
    $scope.movieId = $routeParams.movieId;
    $scope.locations = [];
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/venue/v2/' + $scope.movieId,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.locations = data.locations || [];
        $scope.loading = false;
    }).error(function () {
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;
});

/* ================================================================
   DatesSeatsController — date picker + seat map with multi-select
   ================================================================ */
app.controller('DatesSeatsController', function ($scope, $http, $routeParams, $location) {
    $scope.locationId = $routeParams.locationId;
    $scope.movieId = $routeParams.movieId;
    $scope.dates = [];
    $scope.seats = [];
    $scope.seatRows = [];
    // Use object property for ng-model so ng-if child scope inherits correctly (AngularJS dot rule)
    $scope.selection = { dateId: null };
    $scope.loading = true;
    $scope.seatsLoading = false;
    $scope.seatsError = false;
    $scope.error = false;

    // Fetch dates
    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/dates/' + $scope.locationId + '/' + $scope.movieId,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.dates = data.dates || [];
        $scope.loading = false;
    }).error(function (data, status) {
        console.error('Failed to load dates', status, data);
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;

    // Build seat rows from flat seat array
    function buildSeatRows(seats) {
        var rowMap = {};
        seats.forEach(function (s) {
            var key = s.seatRow;
            if (!rowMap[key]) rowMap[key] = [];
            rowMap[key].push(s);
        });
        var rows = [];
        Object.keys(rowMap).sort(function (a, b) { return parseInt(a) - parseInt(b); }).forEach(function (k) {
            rowMap[k].sort(function (a, b) {
                return a.seatNumber.localeCompare(b.seatNumber, undefined, { numeric: true });
            });
            rows.push({ label: rowMap[k][0].seatNumber.charAt(0), seats: rowMap[k] });
        });
        return rows;
    }

    // When a date is selected, fetch seats
    $scope.onDateChange = function () {
        console.log('[DatesSeats] onDateChange fired, dateId=', $scope.selection.dateId, typeof $scope.selection.dateId);
        if (!$scope.selection.dateId) return;
        $scope.seats = [];
        $scope.seatRows = [];
        $scope.seatsLoading = true;
        $scope.seatsError = false;

        var seatsUrl = '/mbooks-1/rest/book/seats/' + $scope.selection.dateId;
        console.log('[DatesSeats] Fetching seats from:', seatsUrl);

        $http({
            method: 'GET',
            url: seatsUrl,
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
        }).success(function (data) {
            console.log('[DatesSeats] Seats response received, seatsforscreen count:', (data.seatsforscreen || []).length);
            var raw = data.seatsforscreen || [];
            raw.forEach(function (s) { s.selected = false; });
            $scope.seats = raw;
            $scope.seatRows = buildSeatRows(raw);
            $scope.seatsLoading = false;
            console.log('[DatesSeats] seatRows built:', $scope.seatRows.length, 'rows');
        }).error(function (data, status) {
            console.error('[DatesSeats] Failed to load seats', status, data);
            $scope.seatsError = true;
            $scope.seatsLoading = false;
        });
    };

    $scope.toggleSeat = function (seat) {
        if (seat.isReserved === '1') return;
        seat.selected = !seat.selected;
    };

    $scope.getSelectedSeats = function () {
        return $scope.seats.filter(function (s) { return s.selected; });
    };

    $scope.getTotal = function () {
        var total = 0;
        $scope.getSelectedSeats().forEach(function (s) {
            total += s.price;
        });
        return total;
    };

    $scope.proceedToCheckout = function () {
        var selected = $scope.getSelectedSeats();
        // iOS client uses seatNumber (e.g. "A1") with trailing dash: "A1-B2-C3-"
        // Backend DAO.bookTickets queries by seatNumber, NOT seatId
        var seatNumbers = selected.map(function (s) { return s.seatNumber; }).join('-') + '-';
        var displaySeats = selected.map(function (s) { return s.seatNumber; }).join(', ');
        // Build the JSON structure that fullcheckout2 expects (same as iOS):
        // {"seatsToBeReserved":[{"screeningDateId":"N","seat":"A1-B2-C3-"}]}
        var seatsPayload = JSON.stringify({
            seatsToBeReserved: [{
                screeningDateId: String($scope.selection.dateId),
                seat: seatNumbers
            }]
        });
        sessionStorage.setItem('checkout_seats', displaySeats);
        sessionStorage.setItem('checkout_seats_payload', seatsPayload);
        sessionStorage.setItem('checkout_total', $scope.getTotal());
        sessionStorage.setItem('checkout_screeningDateId', String($scope.selection.dateId));
        $location.path('/checkout');
    };
});

/* ================================================================
   CheckoutController — Braintree Drop-in + payment
   ================================================================ */
app.controller('CheckoutController', function ($scope, $http, $window) {
    $scope.selectedSeatIds = sessionStorage.getItem('checkout_seats') || '';
    $scope.totalAmount = sessionStorage.getItem('checkout_total') || '0';
    var screeningDateId = sessionStorage.getItem('checkout_screeningDateId') || '';
    var seatsPayload = sessionStorage.getItem('checkout_seats_payload') || '';

    $scope.dropinReady = false;
    $scope.dropinError = null;
    $scope.paymentSuccess = null;
    $scope.paymentError = null;
    $scope.paymentProcessing = false;

    // Back navigation — go to previous page (seat selection)
    $scope.goBack = function () { $window.history.back(); };

    var dropinInstance = null;

    // 1) Fetch client token
    $http({
        method: 'GET',
        url: '/login/CheckOut',
        headers: { Accept: 'application/json' }
    }).success(function (data) {
        var clientToken = data.clientToken;
        if (!clientToken) {
            $scope.dropinError = 'No client token received. Please log in first.';
            return;
        }
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
        }, function (err, instance) {
            $scope.$apply(function () {
                if (err) { $scope.dropinError = 'Payment form error: ' + err.message; return; }
                dropinInstance = instance;
                $scope.dropinReady = true;
            });
        });
    }).error(function (data, status) {
        if (status === 502 || status === 401 || status === 403) {
            $scope.dropinError = 'You must be logged in to checkout. Please log in first.';
        } else {
            $scope.dropinError = 'Could not connect to payment service (HTTP ' + status + '). Are you logged in?';
        }
    });

    // 2) Submit payment
    $scope.submitPayment = function () {
        if (!dropinInstance) return;
        $scope.paymentProcessing = true;
        $scope.paymentError = null;
        $scope.paymentSuccess = null;

        dropinInstance.requestPaymentMethod(function (err, payload) {
            if (err) {
                $scope.$apply(function () {
                    $scope.paymentError = 'Please complete the payment form.';
                    $scope.paymentProcessing = false;
                });
                return;
            }
            // iOS client sends orderId as current time in millis
            var postData = 'payment_method_nonce=' + encodeURIComponent(payload.nonce) +
                '&orderId=' + encodeURIComponent(new Date().getTime()) +
                '&seatsToBeReserved=' + encodeURIComponent(seatsPayload);

            $http({
                method: 'POST',
                url: '/login/CheckOut',
                data: postData,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }).success(function (data) {
                $scope.paymentProcessing = false;
                if (data.Success === 'true') {
                    $scope.paymentSuccess = 'Transaction ' + (data.Status || 'completed') + '. Auth code: ' + (data.AuthCode || 'N/A');
                    sessionStorage.removeItem('checkout_seats');
                    sessionStorage.removeItem('checkout_seats_payload');
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

/* ================================================================
   VenuesListController — browse all cinema locations
   ================================================================ */
app.controller('VenuesListController', function ($scope, $http) {
    $scope.locations = [];
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/locations',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.locations = data.locations || [];
        $scope.loading = false;
    }).error(function () {
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;
});

/* ================================================================
   VenueMoviesController — movies screening at a selected venue
   ================================================================ */
app.controller('VenueMoviesController', function ($scope, $http, $routeParams) {
    $scope.locationId = $routeParams.locationId;
    $scope.movies = [];
    $scope.venueName = '';
    $scope.venuePicture = '';
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/venue/movies?locationId=' + $scope.locationId,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.movies = data.movies || [];
        var venues = data.venue || [];
        if (venues.length > 0) {
            $scope.venueName = venues[0].name || '';
            $scope.venuePicture = venues[0].venues_picture || '';
        }
        $scope.loading = false;
    }).error(function () {
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;
});

/* ================================================================
   PurchasesController — purchase history list
   ================================================================ */
app.controller('PurchasesController', function ($scope, $http) {
    $scope.purchases = [];
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: '/login/GetAllPurchases',
        headers: { Accept: 'application/json' }
    }).success(function (data) {
        $scope.purchases = data.purchases || [];
        $scope.loading = false;
    }).error(function () {
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;

    $scope.deletePurchase = function (purchaseId) {
        if (!confirm('Delete this entire purchase? This cannot be undone.')) return;
        $http({
            method: 'POST',
            url: '/login/ManagePurchases',
            data: 'purchaseId=' + encodeURIComponent(purchaseId),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }).success(function () {
            $scope.purchases = $scope.purchases.filter(function (p) {
                return p.purchaseId !== purchaseId;
            });
        }).error(function () {
            alert('Failed to delete purchase. Please try again.');
        });
    };
});

/* ================================================================
   PurchaseDetailController — tickets for a specific purchase
   ================================================================ */
app.controller('PurchaseDetailController', function ($scope, $http, $routeParams) {
    $scope.purchaseId = $routeParams.purchaseId;
    $scope.tickets = [];
    $scope.loading = true;
    $scope.error = false;
    $scope.cancelSuccess = null;
    $scope.cancelError = null;

    var loadTickets = function () {
        $http({
            method: 'GET',
            url: '/login/ManagePurchases?purchaseId=' + $scope.purchaseId,
            headers: { Accept: 'application/json' }
        }).success(function (data) {
            $scope.tickets = data.tickets || [];
            $scope.loading = false;
        }).error(function () {
            $scope.error = true;
            $scope.loading = false;
        });
    };

    loadTickets();

    $scope.imgBase = IMG_BASE;

    $scope.getSelectedTickets = function () {
        return $scope.tickets.filter(function (t) { return t.selected; });
    };

    $scope.toggleTicket = function (ticket) {
        ticket.selected = !ticket.selected;
    };

    $scope.cancelSelected = function () {
        var selected = $scope.getSelectedTickets();
        if (selected.length === 0) return;
        if (!confirm('Cancel ' + selected.length + ' ticket(s)?')) return;

        var ticketIds = selected.map(function (t) { return t.ticketId; });
        // Backend expects ticketsToBeCancelled as JSON: {"ticketIds": [1, 2, 3]}
        var ticketsPayload = JSON.stringify({ ticketIds: ticketIds });
        $scope.cancelSuccess = null;
        $scope.cancelError = null;

        $http({
            method: 'POST',
            url: '/login/ManagePurchases',
            data: 'purchaseId=' + encodeURIComponent($scope.purchaseId) +
                  '&ticketsToBeCancelled=' + encodeURIComponent(ticketsPayload),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }).success(function () {
            $scope.cancelSuccess = selected.length + ' ticket(s) cancelled successfully.';
            $scope.loading = true;
            loadTickets();
        }).error(function () {
            $scope.cancelError = 'Failed to cancel tickets. Please try again.';
        });
    };
});

