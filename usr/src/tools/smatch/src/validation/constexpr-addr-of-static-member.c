struct A {
	int a;
	int b[2];
};

struct B {
	int c;
	struct A d;
};

static struct B a= {1, {1, {1, 1}}};

static int *b = &a.d.a;	// OK
static int *c = &(&a.d)->a;	// OK
static int *d = a.d.b;		// OK
static int *e = (&a.d)->b;	// OK
static int *f = &a.d.b[1];	// OK
static int *g = &(&a.d)->b[1];	// OK

/*
 * check-name: address of static object's member constness verification.
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
 * check-error-end
 */
