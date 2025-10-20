describe('LoginController', function () {
    beforeEach(module('hmacApp'));

    var $controller, $rootScope;

    beforeEach(inject(function (_$controller_, _$rootScope_) {
        // The injector unwraps the underscores (_) from around the parameter names when matching
        $controller = _$controller_;
        $rootScope = _$rootScope_;
    }));

    describe('$scope.grade', function () {
        it('sets the strength to "strong" if the password length is >8 chars', function () {
            var $scope = $rootScope.$new();
            var controller = $controller('LoginController', {$scope: $scope});
            $scope.password = 'longerthaneightchars';
            expect($scope.password).toEqual('strong');
        });
    });
});