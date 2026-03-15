var myRegController = angular.module('hmac', ['ab-base64', 'ng.deviceDetector']);

myRegController.config(function ($httpProvider) {
    // Add an HTTP interceptor which passes the request URL to the transformer
    // Allows to include the URL into the signature
    // Rejects request if no hmacSecret is available
    $httpProvider.interceptors.push(function ($q, jsonFilter) {
        return {
            'request': function (config) {
                if (!localStorage.hmacSecret) {
                    return $q.reject('No HMAC secret to sign request!');
                }
                //TODO: get absolute path
                config.headers['X-URL'] = config.url;
                return config || $q.when(config);
            },
            // This is the responseError interceptor
            responseError: function (rejection) {

                if (rejection.status === 412) {
                }

                return $q.reject(rejection);
            },

            // On request failure
            requestError: function (rejection) {
                console.log(rejection); // Contains the data about the error on the request.

                // Return the promise rejection.
                return $q.reject(rejection);
            },

            // On response success
            'response': function (response) {

                // do something on success
                //window.location.href = '/example/main.html'

                // Return the response or promise.
                return response || $q.when(response);
            },

        };
    });


    // Add a custom request transformer to generate required headers
    $httpProvider.defaults.transformRequest.push(function (data, headersGetter, jsonFilter) {
        if (data) {

            // Add session token header if available (this is the previous one now)
            // sessionToken will be used for API calls intead of JSESSIONID
            if (localStorage.sessionToken) {
                headersGetter()['X-SESSION-TOKEN'] = localStorage.sessionToken;
            }

            // Add current time to prevent replay attacks
            var microTime = new Date().getTime();
            headersGetter()['X-MICRO-TIME'] = microTime;

            // 4RI "Message", "secret"
            // TODO: add content-length
            var hash = CryptoJS.HmacSHA512(headersGetter()['X-URL'] + ':' + data + ':' + microTime + ':' + data.length, localStorage.hmacSecret);

            // var hash = CryptoJS.HmacSHA512(headersGetter()['X-URL'] + ':' + data + ':' + microTime, localStorage.hmacSecret);
            var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

            // Finally generate HMAC and set header
            headersGetter()['X-HMAC-HASH'] = hashInBase64;

            // And remove our temporary header
            headersGetter()['X-URL'] = '';

            localStorage.M = headersGetter()['M'];
            headersGetter()['M'] = localStorage.M;

        }
        return data;
    });
});


myRegController.controller('SearchCtrl', ['$scope', '$http',
    function ($scope, $http) {
        $scope.url = '/mbook-1/rest/newuser';
        $scope.username = '';
        $scope.errorMessage = '';

        // The function that will be executed on button click (ng-click="search()")
        $scope.search = function () {

            // Create the http post request
            // the data holds the keywords
            // The request is a JSON request.
            $http.get($scope.url + '/' + $scope.username)
                .success(function (data, status) {
                    $scope.successMsg_User = data;
                    $scope.errorMsg_User = '';
                })
                .error(function (data, status) {
                    $scope.successMsg_User = '';
                    $scope.errorMsg_User = "Username is already taken!";

                });
        }
    }]);

myRegController.controller('RegController', function ($scope, $http, base64, $location, jsonFilter) {
    $scope.modelP = {
        isDisabled: true
    };
    $scope.message = '';
    $scope.username = '';
    $scope.password = '';
    $scope.email = '';
    $scope.voucher_ = '';
    $scope.e_url = '/mbook-1/rest/newemail';
    $scope.url = '/mbook-1/rest/newuser';
    $scope.successMsg_User = '';
    $scope.errorMsg_User = '';
    $scope.successMsg = '';
    $scope.errorMsg = '';
    localStorage.hmacSecret = 'undefined';

    $scope.fields = function () {
        if ($scope.voucher_ != '' && $scope.password != '' && $scope.username != '' && $scope.errorMsg === '' && $scope.errorMsg_User === '') {
            $scope.modelP = {
                isDisabled: false
            };
        }
    }

    // The function that will be executed on button click (ng-click="search()")
    $scope.search = function () {

        // Create the http post request
        // the data holds the keywords
        // The request is a JSON request.
        $http.get($scope.url + '/' + $scope.username)
            .success(function (data, status) {
                $scope.successMsg_User = data.name;
                $scope.errorMsg_User = '';
            })
            .error(function (data, status) {
                $scope.successMsg_User = '';
                $scope.errorMsg_User = "Username is already taken!";
                $scope.modelP = {
                    isDisabled: true
                };
            });
    }

    // The function that will be executed on button click (ng-click="email_search()")
    $scope.email_search = function () {

        // Create the http post request
        // the data holds the keywords
        // The request is a JSON request.
        $http.get($scope.e_url + '/' + $scope.email)
            .success(function (data, status) {
                $scope.successMsg = data.name;
                $scope.errorMsg = '';
            })
            .error(function (data, status) {
                $scope.successMsg = '';
                $scope.errorMsg = "Email is already taken!";
                $scope.modelP = {
                    isDisabled: true
                };
            });
    }

    $scope.register = function () {
        var voucheR = $scope.voucher_;
        var encodedString_voucheR = 'voucher=' +
            encodeURIComponent(voucheR);

        $http({
            method: 'POST',
            url: '/login/voucher',
            data: encodedString_voucheR,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        }).success(function () {

            // Hash password
            var hash = CryptoJS.SHA3($scope.password, {
                outputLength: 512
            });


            // Generate HMAC secret (sha512('username:password'))
            var hmacSec = CryptoJS.HmacSHA512($scope.username, encodeURIComponent(hash));
            localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

            var token = '';
            var useR = $scope.username;
            $scope.password = hash;
            $scope.encoded = base64.encode(useR + ":" + hash);
            var token = $scope.encoded;

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

            var encodedString = 'user=' +
                encodeURIComponent($scope.username) +
                '&email=' +
                $scope.email +
                '&pswrd=' +
                encodeURIComponent(hash) +
                '&deviceId=' +
                encodeURIComponent(uuid) +
                '&voucher_=' +
                encodeURIComponent(voucheR);

            $scope.username = '';
            $scope.Result = [];

            $http({
                method: 'POST',
                url: '/login/register',
                data: encodedString,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'authorization': 'Basic ' + token
                }
            }).success(function (data, status, headers, config) {

                // Store session token
                localStorage.sessionToken = headers('X-Token');

                // Generate new HMAC secret out of our previous (username + password) and the new session token
                localStorage.hmacSecret = CryptoJS.SHA512(localStorage.sessionToken, localStorage.hmacSecret);
                $scope.Result = data;

                if (data.Session === 'raked') {
                    //
                    window.location.href = '/example/main.html';
                } else if (localStorage.M) {
                    //
                    window.location.href = '/example/tabularasa.html';
                } else {
                    //
                    console.log(data);
                    $scope.errorMsg = "Login not correct";
                }
            }).error(function (data, status, headers, config) {
                $scope.Result = data;
                $scope.errorMsg = data.Message;
            });


        }).error(function (data, status, headers, config) {
            $scope.errorMsg = "Login incorrect";
        });


    };

});

myRegController.controller('myCtrl', ['deviceDetector', function (deviceDetector) {
    var vm = this;
    vm.data = deviceDetector;
    vm.allData = JSON.stringify(vm.data, null, 2);

}]);
