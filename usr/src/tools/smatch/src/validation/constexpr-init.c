static int a = 1;					// OK
static int b[2] = {1, 1};				// OK
static void c(void) {}

struct A {
	int a;
	int b[2];
};

struct B {
	int c;
	struct A d;
};

static struct B d= {1, {1, {1, 1}}};				// OK
static struct B e= {a, {1, {1, 1}}};				// KO
static struct B f= {1, {a, {1, 1}}};				// KO
static struct B g= {1, {1, {a, 1}}};				// KO
static struct B h= {1, {1, {1, a}}};				// KO
static struct B i= {.c = 1, .d = {.a = 1, .b = {1, 1}}};	// OK
static struct B j= {.c = a, .d = {.a = 1, .b = {1, 1}}};	// KO
static struct B k= {.c = 1, .d = {.a = a, .b = {1, 1}}};	// KO
static struct B l= {.c = 1, .d = {.a = 1, .b = {a, 1}}};	// KO
static struct B m= {.c = 1, .d = {.a = 1, .b = {1, a}}};	// KO

static int n[] = {a, 1};				// KO
static int o[] = {1, a};				// KO
static int p[] = {[0] = a, [1] = 1};			// KO
static int q[] = {[0] = 1, [1] = a};			// KO

static void r(void) {
	int a = 0;
	int b = a;		// OK
}

static void s(void) {
	int a = 1;
	static int b = a;	// KO
}

/*
 * check-name: static storage object initializer constness verification.
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
constexpr-init.c:16:21: warning: non-constant initializer for static object
constexpr-init.c:17:25: warning: non-constant initializer for static object
constexpr-init.c:18:29: warning: non-constant initializer for static object
constexpr-init.c:19:32: warning: non-constant initializer for static object
constexpr-init.c:21:26: warning: non-constant initializer for static object
constexpr-init.c:22:40: warning: non-constant initializer for static object
constexpr-init.c:23:49: warning: non-constant initializer for static object
constexpr-init.c:24:52: warning: non-constant initializer for static object
constexpr-init.c:26:19: warning: non-constant initializer for static object
constexpr-init.c:27:22: warning: non-constant initializer for static object
constexpr-init.c:28:25: warning: non-constant initializer for static object
constexpr-init.c:29:34: warning: non-constant initializer for static object
constexpr-init.c:38:24: warning: non-constant initializer for static object
 * check-error-end
 */
