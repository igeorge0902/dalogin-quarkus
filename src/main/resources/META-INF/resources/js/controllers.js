'use strict';

var myAppControllers = angular.module('myAppControllers', []);

myAppControllers.factory('userApi', userApi)
    .factory('logoutApi', logoutApi)
    .factory('userService', userService)
    .config(function ($httpProvider) {
        // Add an HTTP interceptor which passes the request URL to the transformer
        // Allows to include the URL into the signature
        // Rejects request if no hmacSecret is available
        $httpProvider.interceptors.push(function ($q, $injector, userService) {
            return {
                // This is the request interceptor
                'request': function (config) {
                    localStorage.hmacSecret
                    if (!localStorage.hmacSecret) {
                        return $q.reject('No HMAC secret to sign request!');
                    }

                    //TODO: get absolute path
                    config.headers['X-URL'] = config.url;
                    return config || $q.when(config);
                },

                // This is the responseError interceptor
                responseError: function (rejection) {

                    var authenticate = function () {

                        var $modal = $injector.get('$modal');
                        var modal = $modal.open({
                            template: '<div style="padding: 15px">' +
                                '  <input type="password" ng-model="pwd">' +
                                '  <button ng-click="submit(pwd)">' +
                                '    Submit' +
                                '  </button>' +
                                '</div>',
                            controller: function ($scope, $modalInstance) {
                                $scope.submit = function (pwd) {
                                    $modalInstance.close(pwd);
                                };
                            }
                        });

                        /* `modal.result` is a promise that gets resolved when 
                         * $modalInstance.close() is called */
                        return modal.result.then(function (pwd) {
                            password = pwd;
                        });
                    };

                    var status = rejection.status;
                    var config = rejection.config;
                    var method = config.method;
                    var url = config.url;

                    if (rejection.status === 300) {
                        // Return a new promise
                        return authenticate().then(function () {
                            return $injector.get('$http')(rejection.config);
                        });

                    }

                    /* If not a 401, do nothing with this error.
                     * This is necessary to make a `responseError`
                     * interceptor a no-op. */
                    return $q.reject(rejection);
                }
            };
        });

    });

myAppControllers.controller('MainCtrl', function ($scope) {
    $scope.showModal = false;
    $scope.toggleModal = function () {
        $scope.showModal = !$scope.showModal;
    };
});


myAppControllers.controller('GetUser', ['$scope', 'userApi', function ($scope, userApi) {

    var loading = false;

    function isLoading() {
        return loading;
    }

    $scope.user = {};
    $scope.errorMessage = '';
    $scope.successMessage = '';
    $scope.isLoading = isLoading;
    $scope.refreshUser = refreshUser;

    function refreshUser() {
        loading = true;
        $scope.user = {};
        $scope.errorMessage = '';
        $scope.successMessage = '';

        var keySize = 128;
        var iterationCount = 1000;
        var plaintext = "G";
        var passphrase = "SP"
        var iv = "F27D5C9927726BCEFE7510B1BDD3D137";
        var salt = "3FF2EC019C627B945225DEBAD71A01B6985FE84C95A70EB132882F88C0A59A55";

        var aesUtil = new AesUtil(keySize, iterationCount);
        var text = aesUtil.encrypt(salt, iv, passphrase, plaintext);
        var text_ = aesUtil.decrypt(salt, iv, passphrase, text);

        userApi.getUser()
            .success(function (data, status, headers) {
                $scope.user = data;
                $scope.status = status;
                $scope.successMessage = "Hello!";
                loading = false;
            })
            .error(function (status) {
                $scope.errorMessage = "Error!";
                $scope.status = status;
                loading = false;
            });
    }

    // Auto-fetch profile on page load
    refreshUser();
}]);

myAppControllers.controller('LogOut', ['$scope', 'logoutApi', function ($scope, logoutApi) {

    var loading = false;

    function isLoading() {
        return loading;
    }

    $scope.user = [];
    $scope.errorMessage = '';
    $scope.successMessage = '';
    $scope.isLoading = isLoading;
    $scope.logOut = logOut;

    function logOut() {
        loading = true;
        $scope.user = [];
        $scope.errorMessage = '';
        $scope.successMessage = '';
        logoutApi.logOut_()
            .then(function (data) {
                $scope.user = data;
                $scope.successMessage = "LogOut is successfull!";
                loading = false;
            }),
            function () {
                $scope.errorMessage = "Error!";
                loading = false;
            };
    }
}]);

myAppControllers.controller('SearchCtrl', ['$scope', '$http',
    function ($scope, $http) {
        $scope.url = '/mbook-1/rest/newuser';
        $scope.keywords = '';
        $scope.errorMessage = '';
        $scope.successMessage = '';

        // The function that will be executed on change (ng-change="search()")
        $scope.search = function () {

            // Create the http post request
            // the data holds the keywords
            // The request is a JSON request.
            $http.get($scope.url + '/' + $scope.keywords)
                .success(function (data, status) {
                    $scope.status = status;
                    $scope.successMessage = "Okay";
                    $scope.data = data;
                    $scope.result = data; // Result
                })
                .error(function (data, status) {
                    $scope.data = data || "Request failed";
                    $scope.status = status;
                    $scope.errorMessage = 'Error!';

                });
        }
    }]);

function userApi($http) {

    if (!localStorage.sessionToken) {

        localStorage.sessionToken = 'undefined';

    }

    if (!localStorage.hmacSecret) {

        localStorage.hmacSecret = 'undefined';
    }

    return {
        getUser: function () {
            var url = '/login/admin';

            var ciphertext = localStorage.sessionToken;

            var config = {
                headers: {
                    'Ciphertext': ciphertext,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            };
            return $http.get(url, config);
        }
    };
}

function logoutApi($http) {
    return {
        logOut_: function () {
            var url = '/login/logout';
            return $http.get(url);
        }
    };
}

function userService() {
    return {
        getAuthorization: function () {
            return 'Taco';
        }
    };
}
