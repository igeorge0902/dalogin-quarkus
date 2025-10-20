(function (angular) {
    'use strict';
    angular.module('ngRouteExample', ['ngRoute'])

        .controller('repeatController', function ($scope, $http, $route, $routeParams, $location) {
            $scope.$route = $route;
            $scope.$location = $location;
            $scope.$routeParams = $routeParams;

            // movies array
            $scope.movies = [];

            $http({
                method: 'GET',
                url: '/mbooks-1/rest/book/movies',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            }).success(function (data, status, headers, config) {

                $scope.movies = data.movies;

            }).error(function (data, status, headers, config) {

                $scope.errorMsg = data;
            });
        })

        .controller('BookController', function ($http, $scope, $routeParams) {
            $scope.name = 'BookController';
            $scope.params = $routeParams;

            $scope.venues = [];

            $http({
                method: 'GET',
                url: '/mbooks-1/rest/book/venue/v2/' + $scope.params.bookId,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            }).success(function (data, status, headers, config) {

                $scope.locations = data.locations;

            });
        })

        .controller('ChapterController', function ($scope, $routeParams) {
            $scope.name = 'ChapterController';
            $scope.params = $routeParams;
        })

        .config(function ($routeProvider, $locationProvider) {
            $routeProvider
                .when('/mbooks-1/rest/book/venue/v2/:bookId', {
                    templateUrl: 'venues.html',
                    controller: 'BookController',
                    resolve: {
                        // I will cause a 1 second delay
                        delay: function ($q, $timeout) {
                            var delay = $q.defer();
                            $timeout(delay.resolve, 1000);
                            return delay.promise;
                        }
                    }
                });

            // configure html5 to get links working on jsfiddle
            $locationProvider.html5Mode(true);
        });

    angular.element(document.getElementsByTagName('head')).append(angular.element('<base href="' + window.location.pathname + '" />'));

})(window.angular);