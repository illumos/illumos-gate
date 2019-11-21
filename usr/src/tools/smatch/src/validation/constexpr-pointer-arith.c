static int a = 1;
static int b[2] = {1, 1};

static int *c = &b[1];					// OK
static int *d = (int*)0 + 1;				// OK
static int *e = &b[1] + 1;				// OK
static int *f = b + 1;					// OK
static int *g = d + 1;					// KO
static int *h = &a + 1;				// OK
static int *i = &b[1] + 1;				// OK
static int *j = b + 1;					// OK
static int *k = d + 1;					// KO
static int *l = &*&b[1];				// OK
static int *m = &*(&a + 1);				// OK
static int *n = &*(&b[1] + 1);				// OK
static int *o = &*(b + 1);				// OK
static int *p = &*(d + 1);				// KO

/*
 * check-name: consrexprness pointer arithmetic
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
constexpr-pointer-arith.c:8:19: warning: non-constant initializer for static object
constexpr-pointer-arith.c:12:19: warning: non-constant initializer for static object
constexpr-pointer-arith.c:17:22: warning: non-constant initializer for static object
 * check-error-end
 */
