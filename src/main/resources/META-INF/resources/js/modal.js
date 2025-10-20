angular.module('ui.bootstrap.m', ['ngAnimate', 'ui.bootstrap']);

// Controller with anonymus function
angular.module('ui.bootstrap.m').controller('ModalCtrl', function ($scope, $modal, $log) {

    $scope.animationsEnabled = true;

    $scope.open = function (size) {
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

    $scope.toggleAnimation = function () {
        $scope.animationsEnabled = !$scope.animationsEnabled;
    };

});