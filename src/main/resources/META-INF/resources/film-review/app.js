'use strict';

var app = angular.module('swiftCinemas', ['ngRoute']);

var APP_BASE = (function () {
    var baseEl = document.querySelector('base');
    var baseHref = (baseEl && baseEl.getAttribute('href')) || '/login/film-review/';
    return baseHref.replace(/\/+$/, '');
})();

var API_BASE = {
    LOGIN: '/login',
    BOOK: '/mbooks-1/rest/book',
    USER: '/mbook-1/rest',
    IMAGE: '/simple-service-webapp/webapi/myresource'
};

function templatePath(name) {
    return APP_BASE + '/templates/' + name;
}

function apiUrl(base, path) {
    return base + path;
}

/* ================================================================
   HMAC-SHA512 HTTP interceptor (same logic as existing script.js)
   ================================================================ */
app.config(function ($httpProvider) {
    $httpProvider.interceptors.push(function ($q, $rootScope) {
        return {
            request: function (config) {
                var publicUrls = [
                    apiUrl(API_BASE.BOOK, '/movies'),
                    apiUrl(API_BASE.BOOK, '/locations')
                ];
                var isPublic = publicUrls.indexOf(config.url) !== -1 ||
                    config.url.indexOf(apiUrl(API_BASE.BOOK, '/venue/')) === 0 ||
                    config.url.indexOf(apiUrl(API_BASE.BOOK, '/dates/')) === 0 ||
                    config.url.indexOf(apiUrl(API_BASE.BOOK, '/seats/')) === 0 ||
                    config.url.indexOf(apiUrl(API_BASE.USER, '/newuser/')) === 0 ||
                    config.url.indexOf(apiUrl(API_BASE.USER, '/newemail/')) === 0 ||
                    config.url.indexOf(API_BASE.LOGIN + '/') === 0;
                if (!isPublic) {
                    if (!localStorage.sessionToken_) {
                        console.warn('No sessionToken to sign the request');
                        return $q.reject('No sessionToken to sign the request!');
                    }
                }
                config.headers['X-URL'] = config.url;
                return config || $q.when(config);
            },
            responseError: function (r) {
                if (r && r.status === 300) {
                    $rootScope.$broadcast('activation-required', r);
                }
                return $q.reject(r);
            },
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
   Route configuration — plain hash mode
   ================================================================ */
app.config(function ($routeProvider, $locationProvider) {
    $locationProvider.hashPrefix('');
    $routeProvider
        .when('/login', {
            templateUrl: templatePath('login.html'),
            controller: 'LoginController'
        })
        .when('/register', {
            templateUrl: templatePath('register.html'),
            controller: 'RegistrationController'
        })
        .when('/change-password', {
            templateUrl: templatePath('change-password.html'),
            controller: 'ChangePasswordController'
        })
        .when('/movies', {
            templateUrl: templatePath('movies.html'),
            controller: 'MoviesController'
        })
        .when('/venues-list', {
            templateUrl: templatePath('venues-list.html'),
            controller: 'VenuesListController'
        })
        .when('/venue-movies/:locationId', {
            templateUrl: templatePath('venue-movies.html'),
            controller: 'VenueMoviesController'
        })
        .when('/venues/:movieId', {
            templateUrl: templatePath('venues.html'),
            controller: 'VenuesController'
        })
        .when('/dates/:locationId/:movieId', {
            templateUrl: templatePath('dates.html'),
            controller: 'DatesSeatsController'
        })
        .when('/checkout', {
            templateUrl: templatePath('checkout.html'),
            controller: 'CheckoutController'
        })
        .when('/purchases', {
            templateUrl: templatePath('purchases.html'),
            controller: 'PurchasesController'
        })
        .when('/purchases/:purchaseId', {
            templateUrl: templatePath('purchase-detail.html'),
            controller: 'PurchaseDetailController'
        })
        .when('/', { redirectTo: '/login' })
        .otherwise({ redirectTo: '/login' });
});

/* ================================================================
   Shared booking state (movie/venue/date/seats) with session backup
   ================================================================ */
app.factory('StateService', function () {
    var KEY = 'filmReviewState';
    var state = {
        selectedMovie: null,
        selectedVenue: null,
        selectedDateId: null,
        selectedSeats: []
    };

    try {
        var fromStorage = JSON.parse(sessionStorage.getItem(KEY) || '{}');
        if (fromStorage && typeof fromStorage === 'object') {
            state.selectedMovie = fromStorage.selectedMovie || null;
            state.selectedVenue = fromStorage.selectedVenue || null;
            state.selectedDateId = fromStorage.selectedDateId || null;
            state.selectedSeats = fromStorage.selectedSeats || [];
        }
    } catch (e) {
        sessionStorage.removeItem(KEY);
    }

    function persist() {
        sessionStorage.setItem(KEY, JSON.stringify(state));
    }

    return {
        getState: function () { return state; },
        setSelectedMovie: function (movie) { state.selectedMovie = movie || null; persist(); },
        setSelectedVenue: function (venue) { state.selectedVenue = venue || null; persist(); },
        setSelectedDateId: function (dateId) { state.selectedDateId = dateId || null; persist(); },
        setSelectedSeats: function (seats) { state.selectedSeats = seats || []; persist(); },
        clearBooking: function () {
            state.selectedDateId = null;
            state.selectedSeats = [];
            persist();
        }
    };
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
    $rootScope.activationRequiredState = null;

    $rootScope.$on('activation-required', function (evt, rejection) {
        $rootScope.activationRequiredState = {
            at: Date.now(),
            url: rejection && rejection.config ? rejection.config.url : null
        };
    });

    // Check if we have an existing valid session on startup
    // Use a lightweight session-protected endpoint to probe
    if (localStorage.getItem('filmReviewUser')) {
        $http({ method: 'GET', url: apiUrl(API_BASE.LOGIN, '/GetAllPurchases'), headers: { Accept: 'application/json' } })
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
        $http({ method: 'GET', url: apiUrl(API_BASE.LOGIN, '/logout') })
            .success(function () {
                $rootScope.isLoggedIn = false;
                $rootScope.loggedInUser = '';
                localStorage.removeItem('filmReviewUser');
                $location.path('/login');
            })
            .error(function () {
                // Even if logout call fails, clear local state
                $rootScope.isLoggedIn = false;
                $rootScope.loggedInUser = '';
                localStorage.removeItem('filmReviewUser');
                $location.path('/login');
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
            apiUrl(API_BASE.LOGIN, '/HelloWorld') + ':' + body + ':' + microTime + ':' + body.length,
            hmacSecretB64
        );
        var hmacHash = CryptoJS.enc.Base64.stringify(loginHmac);

        // 6) POST to /login/HelloWorld
        //    Override transformRequest to bypass the Film-Review HMAC transform —
        //    the login has its own HMAC formula matching the original /login/ page.
        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/HelloWorld'),
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
                $location.path('/movies');
            } else {
                $scope.errorMsg = 'Login failed. Please check your credentials.';
            }
        }).error(function (data, status) {
            $scope.processing = false;
            if (status === 300) {
                $scope.errorMsg = 'Activation is required before protected access. Please open Register to resend activation email.';
                return;
            }
            $scope.errorMsg = 'Login failed. Please check your username and password.';
        });
    };
});

/* ================================================================
   ChangePasswordController — email/code/new-password reset flow
   ================================================================ */
app.controller('ChangePasswordController', function ($scope, $http, $location) {
    $scope.email = '';
    $scope.uuid = '';
    $scope.confirmationCode = '';
    $scope.password = '';
    $scope.modelE = { isDisabled: false };
    $scope.modelC = { isDisabled: true };
    $scope.modelP = { isDisabled: true };

    $scope.errorMsg = '';
    $scope.successMsg = '';
    $scope.error_Msg = '';
    $scope.success_Msg = '';
    $scope.errorMsg_ = '';
    $scope.successMsg_ = '';

    function deviceGuid() {
        var nav = window.navigator;
        var scr = window.screen;
        var g = (nav.mimeTypes ? nav.mimeTypes.length : 0);
        g += nav.userAgent.replace(/\D+/g, '');
        g += (nav.plugins ? nav.plugins.length : 0);
        g += scr.height || '';
        g += scr.width || '';
        g += scr.pixelDepth || '';
        return g;
    }

    $scope.clearErrorMsg = function () {
        $scope.errorMsg = '';
    };

    $scope.forgetPsw = function () {
        if (!$scope.email) return;
        $scope.uuid = deviceGuid();
        var encodedString = 'email=' + encodeURIComponent($scope.email) +
            '&deviceId=' + encodeURIComponent($scope.uuid);

        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/forgotPSw'),
            data: encodedString,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }
        }).success(function (data) {
            if (data.Success === 'true') {
                $scope.successMsg = data;
                $scope.errorMsg = '';
                $scope.modelE.isDisabled = true;
                $scope.modelC.isDisabled = false;
                $scope.modelP.isDisabled = true;
            } else {
                $scope.errorMsg = data;
            }
        }).error(function (data) {
            $scope.errorMsg = data || 'Failed to request reset code.';
        });
    };

    $scope.enterCode = function () {
        if (!$scope.email || !$scope.confirmationCode) return;
        var codeHash = CryptoJS.SHA512($scope.confirmationCode, { outputLength: 512 });
        var encodedString = 'email=' + encodeURIComponent($scope.email) +
            '&cC=' + encodeURIComponent(codeHash) +
            '&deviceId=' + encodeURIComponent($scope.uuid || deviceGuid());

        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/forgotPSwCode'),
            data: encodedString,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }
        }).success(function (data) {
            $scope.success_Msg = data;
            $scope.error_Msg = '';
            $scope.modelE.isDisabled = true;
            $scope.modelC.isDisabled = true;
            $scope.modelP.isDisabled = false;
        }).error(function (data) {
            $scope.error_Msg = data || 'Invalid confirmation code.';
        });
    };

    $scope.changePSw = function () {
        if (!$scope.email || !$scope.confirmationCode || !$scope.password) return;
        var passHash = CryptoJS.SHA3($scope.password, { outputLength: 512 });
        var codeHash = CryptoJS.SHA512($scope.confirmationCode, { outputLength: 512 });
        var encodedString = 'email=' + encodeURIComponent($scope.email) +
            '&cC=' + encodeURIComponent(codeHash) +
            '&pass=' + encodeURIComponent(passHash) +
            '&deviceId=' + encodeURIComponent($scope.uuid || deviceGuid());

        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/forgotPSwNewPSw'),
            data: encodedString,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }
        }).success(function (data) {
            if (data.Success === 'true') {
                $scope.successMsg_ = data;
                $scope.errorMsg_ = '';
                $scope.modelP.isDisabled = true;
                $scope.password = '';
                setTimeout(function () {
                    $scope.$apply(function () { $location.path('/login'); });
                }, 600);
            } else {
                $scope.errorMsg_ = data;
            }
        }).error(function (data) {
            $scope.errorMsg_ = data || 'Failed to update password.';
        });
    };
});

/* ================================================================
   Image helper
   ================================================================ */
var IMG_BASE = API_BASE.IMAGE;

/* ================================================================
   MoviesController — movie grid
   ================================================================ */
app.controller('MoviesController', function ($scope, $http, StateService, $location) {
    $scope.movies = [];
    $scope.loading = true;
    $scope.loadError = false;
    $scope.search = '';
    $scope.categories = ['All'];
    $scope.selectedCategory = 'All';

    function movieCategory(movie) {
        return movie.category || movie.categoryName || movie.genre || movie.genres || 'Uncategorized';
    }

    $http({
        method: 'GET',
        url: apiUrl(API_BASE.BOOK, '/movies'),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Token': 'client-secret' }
    }).success(function (data, status, headers) {
        localStorage.sessionToken_ = headers('APIKEY');
        $scope.movies = data.movies || [];
        var seen = {};
        $scope.movies.forEach(function (movie) {
            var cat = movieCategory(movie);
            if (!seen[cat]) {
                seen[cat] = true;
                $scope.categories.push(cat);
            }
        });
        $scope.loading = false;
    }).error(function () {
        $scope.loadError = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;

    $scope.selectMovie = function (movie) {
        StateService.setSelectedMovie({ movieId: movie.movieId, name: movie.name });
        $location.path('/venues/' + movie.movieId);
    };

    $scope.filteredMovies = function () {
        var term = ($scope.search || '').toLowerCase();
        return $scope.movies.filter(function (movie) {
            var inCategory = $scope.selectedCategory === 'All' || movieCategory(movie) === $scope.selectedCategory;
            if (!inCategory) return false;
            if (!term) return true;
            var title = (movie.name || '').toLowerCase();
            var detail = (movie.detail || '').toLowerCase();
            return title.indexOf(term) >= 0 || detail.indexOf(term) >= 0;
        });
    };
});

/* ================================================================
   VenuesController — location selection for a movie
   ================================================================ */
app.controller('VenuesController', function ($scope, $http, $routeParams, $location, StateService) {
    $scope.movieId = $routeParams.movieId;
    $scope.locations = [];
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: apiUrl(API_BASE.BOOK, '/venue/v2/') + $scope.movieId,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.locations = data.locations || [];
        $scope.loading = false;
    }).error(function () {
        $scope.error = true;
        $scope.loading = false;
    });

    $scope.imgBase = IMG_BASE;

    $scope.openDates = function (loc) {
        StateService.setSelectedVenue({
            locationId: loc.locationId,
            name: loc.name,
            picture: loc.thumbnail
        });
        $location.path('/dates/' + loc.locationId + '/' + $scope.movieId);
    };
});

/* ================================================================
   DatesSeatsController — date picker + seat map with multi-select
   ================================================================ */
app.controller('DatesSeatsController', function ($scope, $http, $routeParams, $location, StateService) {
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

    // Route params remain source of truth; state only helps after refresh/navigation.
    var persistedState = StateService.getState();
    if (!$scope.movieId && persistedState.selectedMovie) {
        $scope.movieId = persistedState.selectedMovie.movieId;
    }
    if (!$scope.locationId && persistedState.selectedVenue) {
        $scope.locationId = persistedState.selectedVenue.locationId;
    }

    // Fetch dates
    $http({
        method: 'GET',
        url: apiUrl(API_BASE.BOOK, '/dates/') + $scope.locationId + '/' + $scope.movieId,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }
    }).success(function (data) {
        $scope.dates = data.dates || [];
        var persistedDateId = persistedState.selectedDateId;
        if (persistedDateId) {
            var hasPersisted = $scope.dates.some(function (d) { return String(d.screeningDatesId) === String(persistedDateId); });
            if (hasPersisted) {
                $scope.selection.dateId = Number(persistedDateId);
                $scope.onDateChange();
            }
        }
        if (!$scope.selection.dateId && $scope.dates.length === 1) {
            $scope.selection.dateId = $scope.dates[0].screeningDatesId;
            $scope.onDateChange();
        }
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
        StateService.setSelectedDateId(String($scope.selection.dateId));
        $scope.seats = [];
        $scope.seatRows = [];
        $scope.seatsLoading = true;
        $scope.seatsError = false;

        var seatsUrl = apiUrl(API_BASE.BOOK, '/seats/') + $scope.selection.dateId;
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
        StateService.setSelectedSeats($scope.getSelectedSeats());
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
        StateService.setSelectedSeats(selected);
        $location.path('/checkout');
    };
});

/* ================================================================
   CheckoutController — Braintree Drop-in + payment
   ================================================================ */
app.controller('CheckoutController', function ($scope, $http, $window, StateService) {
    var currentState = StateService.getState();
    $scope.selectedSeatIds = sessionStorage.getItem('checkout_seats') ||
        (currentState.selectedSeats || []).map(function (s) { return s.seatNumber; }).join(', ');
    $scope.totalAmount = sessionStorage.getItem('checkout_total') ||
        (currentState.selectedSeats || []).reduce(function (sum, s) { return sum + (s.price || 0); }, 0);
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
        url: apiUrl(API_BASE.LOGIN, '/CheckOut'),
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
                url: apiUrl(API_BASE.LOGIN, '/CheckOut'),
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
                    StateService.clearBooking();
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
        url: apiUrl(API_BASE.BOOK, '/locations'),
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
app.controller('VenueMoviesController', function ($scope, $http, $routeParams, $location, StateService) {
    $scope.locationId = $routeParams.locationId;
    $scope.movies = [];
    $scope.venueName = '';
    $scope.venuePicture = '';
    $scope.loading = true;
    $scope.error = false;

    $http({
        method: 'GET',
        url: apiUrl(API_BASE.BOOK, '/venue/movies?locationId=') + $scope.locationId,
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

    $scope.openDates = function (movie) {
        StateService.setSelectedMovie({ movieId: movie.movieId, name: movie.name });
        $location.path('/dates/' + $scope.locationId + '/' + movie.movieId);
    };
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
        url: apiUrl(API_BASE.LOGIN, '/GetAllPurchases'),
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
            url: apiUrl(API_BASE.LOGIN, '/ManagePurchases'),
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
            url: apiUrl(API_BASE.LOGIN, '/ManagePurchases?purchaseId=') + $scope.purchaseId,
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
            url: apiUrl(API_BASE.LOGIN, '/ManagePurchases'),
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

/* ================================================================
   RegistrationController — Film-Review in-app registration
   ================================================================ */
app.controller('RegistrationController', function ($scope, $http, $location, $rootScope, $timeout) {
    $scope.form = {
        username: '',
        email: '',
        password: '',
        voucher: '',
        useVoucher: true
    };
    $scope.processing = false;
    $scope.usernameState = null; // available | taken | unknown
    $scope.emailState = null;    // available | taken | unknown
    $scope.dialog = null;        // { key, type, text }
    $scope.activationPending = false;
    $scope.activationResendBusy = false;
    $scope.lastRegistration = null; // { user, deviceId, token }

    var DIALOG_TEXT = {
        REG_VOUCHER_INVALID: 'Voucher is invalid or expired.',
        REG_VOUCHER_VALID: 'Voucher validated.',
        REG_ACTIVATION_REQUIRED: 'Activation is required before protected access.',
        REG_ACTIVATION_EMAIL_SENT: 'Activation email sent. Please check your inbox.',
        REG_ACTIVATION_RESEND_SUCCESS: 'Activation email resent. Please check your inbox.',
        REG_ACTIVATION_RESEND_FAILED: 'Activation resend failed. Please try again later.',
        REG_REGISTRATION_SUCCESS: 'Registration successful. You can now log in.',
        REG_REGISTRATION_FAILED: 'Registration failed. Please verify data and try again.'
    };

    function deviceGuid() {
        var nav = window.navigator;
        var scr = window.screen;
        var g = (nav.mimeTypes ? nav.mimeTypes.length : 0);
        g += nav.userAgent.replace(/\D+/g, '');
        g += (nav.plugins ? nav.plugins.length : 0);
        g += scr.height || '';
        g += scr.width || '';
        g += scr.pixelDepth || '';
        return String(g);
    }

    function clearDialog() {
        $scope.dialog = null;
    }

    $scope.clearDialog = clearDialog;

    function setDialog(key, type, textOverride) {
        $scope.dialog = { key: key, type: type, text: textOverride || DIALOG_TEXT[key] || 'Request failed.' };
    }

    if ($rootScope.activationRequiredState) {
        $scope.activationPending = true;
        setDialog('REG_ACTIVATION_REQUIRED', 'warn');
    }

    $scope.$on('activation-required', function () {
        $scope.activationPending = true;
        setDialog('REG_ACTIVATION_REQUIRED', 'warn');
    });

    function registrationMessage(path, username, email, passHash, deviceId, voucher) {
        var base = path + ':user=' + username + '&email=' + email + '&pswrd=' + passHash + '&deviceId=' + deviceId;
        if (voucher !== null) {
            base += '&voucher_=' + voucher;
        }
        return base;
    }

    function buildHmacHeaders(path, username, passHash, email, deviceId, voucherValue, body) {
        var secret = CryptoJS.HmacSHA512(username, passHash);
        var secretB64 = CryptoJS.enc.Base64.stringify(secret);
        var microTime = String(new Date().getTime());
        var msg = registrationMessage(path, username, email, passHash, deviceId, voucherValue);
        var signingString = msg + ':' + microTime + ':' + body.length;
        var h = CryptoJS.HmacSHA512(signingString, secretB64);
        return {
            hmac: CryptoJS.enc.Base64.stringify(h),
            microTime: microTime,
            auth: btoa(username + ':' + passHash)
        };
    }

    var USERNAME_MIN_LEN = 2;
    var USERNAME_DEBOUNCE_MS = 300;
    var EMAIL_DEBOUNCE_MS = 450;
    var usernameCheckTimer = null;
    var emailCheckTimer = null;
    var usernameReqSeq = 0;
    var emailReqSeq = 0;

    function cancelUsernameTimer() {
        if (usernameCheckTimer) {
            $timeout.cancel(usernameCheckTimer);
            usernameCheckTimer = null;
        }
    }

    function cancelEmailTimer() {
        if (emailCheckTimer) {
            $timeout.cancel(emailCheckTimer);
            emailCheckTimer = null;
        }
    }

    function isFullEmail(value) {
        if (!value) return false;
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
    }

    $scope.isFullEmail = isFullEmail;

    function hasText(value) {
        return !!(value && String(value).trim());
    }

    function validForSubmit() {
        var username = ($scope.form.username || '').trim();
        var email = ($scope.form.email || '').trim();
        if (username.length < USERNAME_MIN_LEN) return false;
        if (!isFullEmail(email)) return false;
        if (!hasText($scope.form.password)) return false;
        if ($scope.form.useVoucher && !hasText($scope.form.voucher)) return false;
        if ($scope.usernameState !== 'available') return false;
        if ($scope.emailState !== 'available') return false;
        if ($scope.usernameState === 'checking' || $scope.emailState === 'checking') return false;
        return true;
    }

    $scope.canSubmit = validForSubmit;

    $scope.checkUsername = function (immediate) {
        var raw = ($scope.form.username || '').trim();
        cancelUsernameTimer();

        if (!raw) {
            $scope.usernameState = null;
            return;
        }
        if (raw.length < USERNAME_MIN_LEN) {
            $scope.usernameState = null;
            return;
        }

        var run = function () {
            var reqId = ++usernameReqSeq;
            clearDialog();
            $scope.usernameState = 'checking';
            $http.get(apiUrl(API_BASE.USER, '/newuser/') + encodeURIComponent(raw))
                .success(function () {
                    if (reqId !== usernameReqSeq) return;
                    $scope.usernameState = 'available';
                })
                .error(function (data, status) {
                    if (reqId !== usernameReqSeq) return;
                    $scope.usernameState = (status === 412) ? 'taken' : 'unknown';
                });
        };

        if (immediate) {
            run();
            return;
        }
        usernameCheckTimer = $timeout(run, USERNAME_DEBOUNCE_MS);
    };

    $scope.checkEmail = function (immediate) {
        var raw = ($scope.form.email || '').trim();
        cancelEmailTimer();

        if (!raw) {
            $scope.emailState = null;
            return;
        }
        if (!isFullEmail(raw)) {
            $scope.emailState = null;
            return;
        }

        var run = function () {
            var reqId = ++emailReqSeq;
            clearDialog();
            $scope.emailState = 'checking';
            $http.get(apiUrl(API_BASE.USER, '/newemail/') + encodeURIComponent(raw))
                .success(function () {
                    if (reqId !== emailReqSeq) return;
                    $scope.emailState = 'available';
                })
                .error(function (data, status) {
                    if (reqId !== emailReqSeq) return;
                    $scope.emailState = (status === 412) ? 'taken' : 'unknown';
                });
        };

        if (immediate) {
            run();
            return;
        }
        emailCheckTimer = $timeout(run, EMAIL_DEBOUNCE_MS);
    };

    function validateVoucherThenRegister(next) {
        if (!$scope.form.useVoucher) {
            next();
            return;
        }
        var voucherBody = 'voucher=' + encodeURIComponent($scope.form.voucher);
        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/voucher'),
            data: voucherBody,
            transformRequest: function (d) { return d; },
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }).success(function () {
            setDialog('REG_VOUCHER_VALID', 'success');
            next();
        }).error(function () {
            $scope.processing = false;
            setDialog('REG_VOUCHER_INVALID', 'error');
        });
    }

    $scope.register = function () {
        clearDialog();
        if (!validForSubmit()) {
            setDialog('REG_REGISTRATION_FAILED', 'error', 'Please complete all required fields correctly.');
            return;
        }

        $scope.processing = true;
        var username = $scope.form.username.trim();
        var email = $scope.form.email.trim();
        var deviceId = deviceGuid();
        var passHash = CryptoJS.SHA3($scope.form.password, { outputLength: 512 }).toString();

        validateVoucherThenRegister(function () {
            var endpoint = $scope.form.useVoucher ? '/register' : '/registerWithoutVoucher';
            var voucherValue = $scope.form.useVoucher ? $scope.form.voucher.trim() : null;
            var body = 'user=' + encodeURIComponent(username) +
                '&email=' + encodeURIComponent(email) +
                '&pswrd=' + encodeURIComponent(passHash) +
                '&deviceId=' + encodeURIComponent(deviceId) +
                ($scope.form.useVoucher ? '&voucher_=' + encodeURIComponent(voucherValue) : '');

            // Server side helper uses /login/register signature format for both modes.
            var headers = buildHmacHeaders('/login/register', username, passHash, email, deviceId, voucherValue, body);

            $http({
                method: 'POST',
                url: apiUrl(API_BASE.LOGIN, endpoint),
                data: body,
                transformRequest: function (d) { return d; },
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'authorization': 'Basic ' + headers.auth,
                    'X-HMAC-HASH': headers.hmac,
                    'X-MICRO-TIME': headers.microTime,
                    'X-URL': ''
                }
            }).success(function (data, status, respHeaders) {
                $scope.processing = false;
                var token = respHeaders('X-Token') || data['X-Token'] || null;
                if (token) {
                    localStorage.sessionToken_ = token;
                }
                $scope.lastRegistration = { user: username, deviceId: deviceId, token: token };

                if (status === 300 || data.Response === 'S') {
                    $scope.activationPending = true;
                    setDialog('REG_ACTIVATION_REQUIRED', 'warn', 'Registration pending activation. Please activate your account by email.');
                    return;
                }

                if (data.Success === 'true' || data.success === 1 || data.Session === 'raked') {
                    setDialog('REG_REGISTRATION_SUCCESS', 'success');
                    localStorage.setItem('filmReviewUser', username);
                    $rootScope.isLoggedIn = true;
                    $rootScope.loggedInUser = username;
                    setTimeout(function () {
                        $scope.$apply(function () { $location.path('/movies'); });
                    }, 500);
                    return;
                }

                $scope.activationPending = true;
                setDialog('REG_ACTIVATION_REQUIRED', 'warn', 'Registration created but activation is required.');
            }).error(function (data, status) {
                $scope.processing = false;
                if (status === 300) {
                    $scope.activationPending = true;
                    setDialog('REG_ACTIVATION_REQUIRED', 'warn');
                    return;
                }
                setDialog('REG_REGISTRATION_FAILED', 'error');
            });
        });
    };

    $scope.resendActivation = function () {
        if (!$scope.lastRegistration || !$scope.lastRegistration.token) {
            setDialog('REG_ACTIVATION_RESEND_FAILED', 'error', 'Cannot resend activation yet. Please register again.');
            return;
        }
        $scope.activationResendBusy = true;
        $http({
            method: 'POST',
            url: apiUrl(API_BASE.LOGIN, '/activation'),
            data: {
                user: $scope.lastRegistration.user,
                deviceId: $scope.lastRegistration.deviceId
            },
            headers: {
                'Content-Type': 'application/json',
                'Ciphertext': $scope.lastRegistration.token
            }
        }).success(function () {
            $scope.activationResendBusy = false;
            setDialog('REG_ACTIVATION_RESEND_SUCCESS', 'success');
        }).error(function () {
            $scope.activationResendBusy = false;
            setDialog('REG_ACTIVATION_RESEND_FAILED', 'error');
        });
    };
});
