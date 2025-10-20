var hmacApp = angular.module('hmac', ['ab-base64', 'ng.deviceDetector']);

hmacApp.config(function ($httpProvider) {
    // Add an HTTP interceptor which passes the request URL to the transformer
    // Allows to include the URL into the signature
    // Rejects request if no hmacSecret is available
    $httpProvider.interceptors.push(function ($q) {
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
        if (data) {

            // Add session token header if available (this is the previous one now)
            // sessionToken will be used for API calls intead of JSESSIONID. The header here is just a decoration.
            if (localStorage.sessionToken) {
                headersGetter()['X-SESSION-TOKEN'] = localStorage.sessionToken;
            }

            // Add current time to prevent replay attacks
            var microTime = new Date().getTime();
            headersGetter()['X-MICRO-TIME'] = microTime;


            //    var headers = headersGetter();
            //    var mDevice = headersGetter('M-Device');
            // ??
            //    if (mDevice != undefined) {
            //        var newData = '';
            //
            //        var originalId = /deviceId=[0-9]*/gi;
            //        var str = data;
            //        var newId = 'deviceId=' + headersGetter['M-Device'];
            //        newData = str.replace(originalId, newId);

            //        data = newData;
            //    }


            // 4RI "Message", "secret"
            var hash = CryptoJS.HmacSHA512(headersGetter()['X-URL'] + ':' + data + ':' + microTime + ':' + data.length, localStorage.hmacSecret);
            var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

            // Finally generate HMAC and set header
            headersGetter()['X-HMAC-HASH'] = hashInBase64;

            // And remove our temporary header
            headersGetter()['X-URL'] = localStorage.mobileDeviceId;

            // Create an unreadable header object that will handle the redirect (never checked readability at this point :D)
            // No legacy is so rich as honesty. - Shakespeare
            // put the Alert here to debug
            // inizialize this constant for mobileWebView
            localStorage.M = headersGetter()['M'];

        }
        return data;
    });
});

// TODO: pages (mobile first)
/*
hmacApp.config(['$routeProvider',
  function($routeProvider) {
    $routeProvider.
      when('/index', {
        templateUrl: '../main.html',
      //  controller: 'AddOrderController'
      });
  }]);
*/

hmacApp.controller('LoginController', function ($scope, $http, base64, $location) {
    $scope.message = '';
    $scope.username = '';
    $scope.password = '';

    $scope.login = function () {

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
            '&pswrd=' +
            encodeURIComponent(hash) +
            '&deviceId=' +
            encodeURIComponent(uuid);

        $scope.username = '';
        $scope.Result = [];

        $http({
            method: 'POST',
            url: '/login/HelloWorld',
            data: encodedString,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
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
                window.location.href = '/login/main.html';

                // We check only if localStorage.M = headersGetter()['M'] is an object. That's fine.
            } else if (localStorage.M) {
                //
                window.location.href = '/login/tabularasa.jsp';
            } else {
                // 
                $scope.errorMsg = data;
            }
        }).error(function (data, status, headers, config) {

            $scope.errorMsg = data;
        });
    };

});

hmacApp.controller('ForgetPSWController', function ($scope, $http, base64, $location) {
    $scope.email = '';
    $scope.uuid = '';
    $scope.modelE = {
        isDisabled: false
    };
    $scope.modelC = {
        isDisabled: true
    };
    $scope.modelP = {
        isDisabled: true
    };

    $scope.clearErrorMsg = function () {
        $scope.errorMsg = '';
    };

    $scope.forgetPsw = function () {

        // Hash email
        var hash = CryptoJS.SHA512($scope.email, {
            outputLength: 512
        });

        // Generate HMAC secret (sha512('email:email(SHA512)'))
        var hmacSec = CryptoJS.HmacSHA512($scope.email, encodeURIComponent(hash));
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

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

        $scope.uuid = guid()

        var encodedString = 'email=' +
            $scope.email +
            '&deviceId=' +
            encodeURIComponent($scope.uuid);

        /*
        var encodedString_ = {
            "email" : $scope.email,
            "deviceId" : encodeURIComponent($scope.uuid)
        }*/

        $scope.Result = [];

        $http({
            method: 'POST',
            url: '/login/forgotPSw',
            data: encodedString,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            }
        }).success(function (data, status, headers, config) {

            // Create &store session token 
            localStorage.sessionToken = CryptoJS.SHA512(headers('XSRF-TOKEN'), localStorage.hmacSecret);

            $scope.Result = data;

            if (data.Success === 'true') {

                $scope.successMsg = data;
                $scope.modelE = {
                    isDisabled: true
                };
                $scope.modelC = {
                    isDisabled: false
                };
                $scope.modelP = {
                    isDisabled: true
                };

            } else {

                $scope.errorMsg = data;
            }
        }).error(function (data, status, headers, config) {

            $scope.errorMsg = data;
        });

    };

    $scope.enterCode = function () {

        // Hash code
        var hash = CryptoJS.SHA512($scope.confirmationCode, {
            outputLength: 512
        });

        // Generate HMAC secret (sha512('email:confirmationCode(SHA512)'))
        var hmacSec = CryptoJS.HmacSHA512($scope.email, encodeURIComponent(hash));
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

        var encodedString =
            'email=' + $scope.email +
            '&cC=' + encodeURIComponent(hash) +
            '&deviceId=' + encodeURIComponent($scope.uuid);

        $scope.Result = [];

        $http({
            method: 'POST',
            url: '/login/forgotPSwCode',
            data: encodedString,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            }
        }).success(function (data, status, headers, config) {

            $scope.Result = data;

            $scope.modelE = {
                isDisabled: true
            };
            $scope.modelC = {
                isDisabled: true
            };
            $scope.modelP = {
                isDisabled: false
            };

            $scope.success_Msg = data;

        }).error(function (data, status, headers, config) {

            $scope.error_Msg = data;

        });

    };

    $scope.changePSw = function () {

        // Hash password
        var hash = CryptoJS.SHA3($scope.password, {
            outputLength: 512
        });

        // Hash code
        var hash_ = CryptoJS.SHA512($scope.confirmationCode, {
            outputLength: 512
        });

        // Generate HMAC secret (sha512('email:confirmationCode(SHA512)'))
        var hmacSec = CryptoJS.HmacSHA512($scope.email, encodeURIComponent(hash));
        localStorage.hmacSecret = CryptoJS.enc.Base64.stringify(hmacSec);

        var encodedString =
            'email=' + $scope.email +
            '&cC=' + encodeURIComponent(hash_) +
            '&pass=' + encodeURIComponent(hash) +
            '&deviceId=' + encodeURIComponent($scope.uuid);

        $scope.Result = [];

        $http({
            method: 'POST',
            url: '/login/forgotPSwNewPSw',
            data: encodedString,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            }
        }).success(function (data, status, headers, config) {

            $scope.Result = data;

            $scope.modelE = {
                isDisabled: true
            };
            $scope.modelC = {
                isDisabled: true
            };
            $scope.modelP = {
                isDisabled: true
            };

            $scope.successMsg_ = data;

            if (data.Success === 'true') {
                //
                window.location.href = '/login/index.html';

            } else {
                // 
                $scope.errorMsg_ = data;
            }

        }).error(function (data, status, headers, config) {

            $scope.modelE = {
                isDisabled: true
            };
            $scope.modelC = {
                isDisabled: true
            };
            $scope.modelP = {
                isDisabled: false
            };

            $scope.errorMsg_ = data;

        });

    };

});

hmacApp.controller('myCtrl', ['deviceDetector', function (deviceDetector) {
    var vm = this;
    vm.data = deviceDetector;
    vm.allData = JSON.stringify(vm.data, null, 2);


}]);