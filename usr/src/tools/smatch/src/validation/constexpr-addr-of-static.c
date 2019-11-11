static int a = 1;
static int b[2] = {1, 1};
static void c(void) {}

static int *d = &a;		// OK
static int *e = d;		// KO
static int *f = b;		// OK

static void (*g)(void) = c;	// OK
static void (*h)(void) = &c;	// OK

static int *i = &*&a;		// OK
static int *j = &*b;		// OK
static int *k = &*d;		// KO


static void l(void) {
	int a = 1;
	static int *b = &a;	// KO
}

static void m(void) {
	static int a = 1;
	static int *b = &a;	// OK
}

/*
 * check-name: constexpr static object address
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
constexpr-addr-of-static.c:6:17: warning: non-constant initializer for static object
constexpr-addr-of-static.c:14:19: warning: non-constant initializer for static object
constexpr-addr-of-static.c:19:26: warning: non-constant initializer for static object
 * check-error-end
 */
