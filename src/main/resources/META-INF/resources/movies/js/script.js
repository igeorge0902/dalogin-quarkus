'use strict';

var moviesControllers = angular.module('ngRepeat', ['ab-base64', 'ngRoute', 'ngCookies']);

moviesControllers.config(function ($httpProvider) {
    // Add an HTTP interceptor which passes the request URL to the transformer
    // Allows to include the URL into the signature
    // Rejects request if no hmacSecret is available
    $httpProvider.interceptors.push(function ($q) {
        return {
            'request': function (config) {

                if (config.url != '/mbooks-1/rest/book/movies') {
                    if (!localStorage.sessionToken_) {
                        alert("No sessionToken to sign the request!");
                        return $q.reject('No sessionToken to sign the request!');
                    }
                }

                //TODO: get absolute path
                config.headers['X-URL'] = config.url;

                return config || $q.when(config);
            },

            // This is the responseError interceptor
            responseError: function (rejection) {

                if (rejection.status === 502) {
                }

                return $q.reject(rejection);
            },

            // On request failure
            requestError: function (rejection) {

                // Contains the data about the error on the request.
                console.log(rejection);

                // Return the promise rejection.
                return $q.reject(rejection);
            },

            // On response success
            'response': function (response) {

                // do something on success

                // Return the response or promise.
                return response || $q.when(response);
            },

        };
    });


    // Add a custom request transformer to generate required headers
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

        var uuid = guid()
        var encodedString = encodeURIComponent(uuid);

        // Add current time to prevent replay attacks
        var microTime = new Date().getTime();

        // Generate HMAC secret (sha512('username:password'))
        var hmacSec = CryptoJS.HmacSHA512(headersGetter()['X-URL'], encodeURIComponent(uuid));
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

        // 4RI "Message", "secret"
        var hash = CryptoJS.HmacSHA512(headersGetter()['X-URL'] + ':' + encodedString + ':' + microTime, hmacSec);
        var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

        // Finally generate HMAC and set header
        headersGetter()['X-HMAC-HASH'] = hashInBase64;
        headersGetter()['X-MICRO-TIME'] = microTime;
        headersGetter()['X-Device'] = encodedString;
        headersGetter()['X-URL'] = '';

        if (localStorage.sessionToken_) {
            headersGetter()['X-Token'] = localStorage.sessionToken_;
        }

    });

    $httpProvider.defaults.headers.get = {
        'My-Headers': 'value'
    }

});

moviesControllers.controller('repeatController', function ($scope, base64, $http, $route, $routeParams, $location) {
    $scope.$route = $route;
    $scope.$location = $location;
    $scope.$routeParams = $routeParams;
    $scope.url = '/mbooks-1/rest/book/movies';
    $scope.username = '';
    $scope.movies = [];

    var req = {
        method: 'GET',
        url: $scope.url,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Token': 'client-secret'
        }
    }

    $http(req).success(function (data, status, headers, config) {
        // Store session token 
        localStorage.sessionToken_ = headers('APIKEY');
        $scope.movies = data.movies;
    }).error(function (data, status, headers, config) {
        $scope.movies = data;
    });

    /*
    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/movies',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Token': 'client-secret'
        }
    }).
    success(function (data, status, headers, config) {

        $scope.movies = data.movies;

    }).
    error(function (data, status, headers, config) {

        $scope.errorMsg = data;
    });
    */
});

moviesControllers.controller('ExampleController', function ($http, $scope, $routeParams, $location, $cookies) {
    $scope.name = 'ExampleController';
    $scope.params = $routeParams;
    $scope.dates = [];
    $scope.seats = [];


    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/dates/' + +$scope.params.venueId + '/' + +$scope.params.bookId,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    }).success(function (data, status, headers, config) {
        $scope.dates = data.dates;
        window.scrollTo({top: y});

    }).error(function (data, status, headers, config) {
        $scope.errorMsg = data;
    });

    $scope.selectedItemChanged = function () {
        $http({
            method: 'GET',
            url: '/mbooks-1/rest/book/seats/' + +$scope.data.model,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        }).success(function (data, status, headers, config) {
            $scope.seats = data.seatsforscreen;
        }).error(function (data, status, headers, config) {
            $scope.errorMsg = data;
        });

    }

});


moviesControllers.controller('BookController', function ($http, $scope, $routeParams, $location, $cookies) {
    $scope.name = 'BookController';
    $scope.params = $routeParams;
    $scope.locations = [];

    $http({
        method: 'GET',
        url: '/mbooks-1/rest/book/venue/v2/' + $scope.params.bookId,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    }).success(function (data, status, headers, config) {
        $scope.locations = data.locations;

        const id = 'content';
        const yourElement = document.getElementById(id);
        const y = yourElement.getBoundingClientRect().top + window.pageYOffset;

        window.scrollTo({top: y});

    });
});

moviesControllers.controller('CheckOutController', function ($http, $scope, $routeParams, $location, $cookies) {

    var form = document.querySelector('#checkout-form');
    var submit = document.querySelector('input[type="submit"]');

    braintree.client.create({
        // Replace this with your own authorization.
        authorization: 'eyJ2ZXJzaW9uIjoyLCJhdXRob3JpemF0aW9uRmluZ2VycHJpbnQiOiJjNWY1MGIzZmEzODhjM2VkNjdlNjgwMzBhNDM0YWJmODc0ZmViM2VmZGM5NjU1MjE0YTRkOGFiYmM1YTNkYTlmfGNyZWF0ZWRfYXQ9MjAxNy0wNC0wN1QxMjozNzo0MS42NTcwNTUwNDMrMDAwMFx1MDAyNm1lcmNoYW50X2lkPWozbmRxcHpyaHk0Z3AycDdcdTAwMjZwdWJsaWNfa2V5PXJ6bXlyc2Jzd2IzaHdzbWsiLCJjb25maWdVcmwiOiJodHRwczovL2FwaS5zYW5kYm94LmJyYWludHJlZWdhdGV3YXkuY29tOjQ0My9tZXJjaGFudHMvajNuZHFwenJoeTRncDJwNy9jbGllbnRfYXBpL3YxL2NvbmZpZ3VyYXRpb24iLCJjaGFsbGVuZ2VzIjpbImN2diJdLCJlbnZpcm9ubWVudCI6InNhbmRib3giLCJjbGllbnRBcGlVcmwiOiJodHRwczovL2FwaS5zYW5kYm94LmJyYWludHJlZWdhdGV3YXkuY29tOjQ0My9tZXJjaGFudHMvajNuZHFwenJoeTRncDJwNy9jbGllbnRfYXBpIiwiYXNzZXRzVXJsIjoiaHR0cHM6Ly9hc3NldHMuYnJhaW50cmVlZ2F0ZXdheS5jb20iLCJhdXRoVXJsIjoiaHR0cHM6Ly9hdXRoLnZlbm1vLnNhbmRib3guYnJhaW50cmVlZ2F0ZXdheS5jb20iLCJhbmFseXRpY3MiOnsidXJsIjoiaHR0cHM6Ly9jbGllbnQtYW5hbHl0aWNzLnNhbmRib3guYnJhaW50cmVlZ2F0ZXdheS5jb20vajNuZHFwenJoeTRncDJwNyJ9LCJ0aHJlZURTZWN1cmVFbmFibGVkIjp0cnVlLCJwYXlwYWxFbmFibGVkIjp0cnVlLCJwYXlwYWwiOnsiZGlzcGxheU5hbWUiOiJUZXN0Q29tcGFueSIsImNsaWVudElkIjpudWxsLCJwcml2YWN5VXJsIjoiaHR0cDovL2V4YW1wbGUuY29tL3BwIiwidXNlckFncmVlbWVudFVybCI6Imh0dHA6Ly9leGFtcGxlLmNvbS90b3MiLCJiYXNlVXJsIjoiaHR0cHM6Ly9hc3NldHMuYnJhaW50cmVlZ2F0ZXdheS5jb20iLCJhc3NldHNVcmwiOiJodHRwczovL2NoZWNrb3V0LnBheXBhbC5jb20iLCJkaXJlY3RCYXNlVXJsIjpudWxsLCJhbGxvd0h0dHAiOnRydWUsImVudmlyb25tZW50Tm9OZXR3b3JrIjp0cnVlLCJlbnZpcm9ubWVudCI6Im9mZmxpbmUiLCJ1bnZldHRlZE1lcmNoYW50IjpmYWxzZSwiYnJhaW50cmVlQ2xpZW50SWQiOiJtYXN0ZXJjbGllbnQzIiwiYmlsbGluZ0FncmVlbWVudHNFbmFibGVkIjp0cnVlLCJtZXJjaGFudEFjY291bnRJZCI6InRlc3Rjb21wYW55IiwiY3VycmVuY3lJc29Db2RlIjoiRVVSIn0sImNvaW5iYXNlRW5hYmxlZCI6ZmFsc2UsIm1lcmNoYW50SWQiOiJqM25kcXB6cmh5NGdwMnA3IiwidmVubW8iOiJvZmYifQ=='

    }, function (clientErr, clientInstance) {
        if (clientErr) {
            // Handle error in client creation
            return;
        }

        braintree.hostedFields.create({
            client: clientInstance,
            styles: {
                'input': {
                    'font-size': '14pt'
                },
                'input.invalid': {
                    'color': 'red'
                },
                'input.valid': {
                    'color': 'green'
                }
            },
            fields: {
                number: {
                    selector: '#card-number',
                    placeholder: '4111 1111 1111 1111'
                },
                cvv: {
                    selector: '#cvv',
                    placeholder: '123'
                },
                expirationDate: {
                    selector: '#expiration-date',
                    placeholder: '10/2019'
                }
            }
        }, function (hostedFieldsErr, hostedFieldsInstance) {
            if (hostedFieldsErr) {
                // Handle error in Hosted Fields creation
                return;
            }

            submit.removeAttribute('disabled');

            form.addEventListener('submit', function (event) {
                event.preventDefault();

                hostedFieldsInstance.tokenize(function (tokenizeErr, payload) {
                    if (tokenizeErr) {
                        // Handle error in Hosted Fields tokenization
                        return;
                    }

                    // Put `payload.nonce` into the `payment_method_nonce` input, and then
                    // submit the form. Alternatively, you could send the nonce to your server
                    // with AJAX.
                    document.querySelector('input[name="payment_method_nonce_web"]').value = payload.nonce;
                    form.submit();
                });
            }, false);
        });
    });

});

moviesControllers.config(function ($routeProvider, $locationProvider) {
    $routeProvider
        .when('/mbooks-1/rest/book/venue/v2/:bookId', {
            templateUrl: 'venues.html',
            controller: 'BookController',
            name: 'venues',
            resolve: {
                // I will cause a 1 second delay
                delay: function ($q, $timeout) {
                    var delay = $q.defer();
                    $timeout(delay.resolve, 10);
                    return delay.promise;
                }
            }
        })
        .when('/mbooks-1/rest/book/dates/:venueId/:bookId', {
            templateUrl: 'dates.html',
            controller: 'ExampleController'
        });

    // configure html5 to get links working on jsfiddle
    $locationProvider.html5Mode(true);
});

angular.element(document.getElementsByTagName('head')).append(angular.element('<base href="' + window.location.pathname + '" />'));