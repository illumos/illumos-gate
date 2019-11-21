static void a(void) __attribute__((context));		// KO
static void b(void) __attribute__((context()));		// KO
static void c(void) __attribute__((context 1));		// KO
static void d(void) __attribute__((context 1,2));	// KO
static void e(void) __attribute__((context (1)));	// !!!!
static void f(void) __attribute__((context(0)));	// !!!!
static void g(void) __attribute__((context(0,1,2,3)));	// KO

static void h(void) __attribute__((context (1,2)));	// OK
static void i(void) __attribute__((context(0,1)));	// OK
static void j(void) __attribute__((context(0,1,2)));	// OK

extern int u, v;
static void x(void) __attribute__((context(0,1,v)));
static void y(void) __attribute__((context(0,u,1)));
static void z(void) __attribute__((context(0,u)));

/*
 * check-name: attr-context
 *
 * check-error-start
attr-context.c:1:43: error: Expected ( after context attribute
attr-context.c:1:43: error: got )
attr-context.c:2:44: error: Expected , after context 1st argument
attr-context.c:2:44: error: got )
attr-context.c:3:44: error: Expected ( after context attribute
attr-context.c:3:44: error: got 1
attr-context.c:4:44: error: Expected ( after context attribute
attr-context.c:4:44: error: got 1
attr-context.c:5:46: error: Expected , after context 1st argument
attr-context.c:5:46: error: got )
attr-context.c:6:45: error: Expected , after context 1st argument
attr-context.c:6:45: error: got )
attr-context.c:7:49: error: Expected ) after context 3rd argument
attr-context.c:7:49: error: got ,
attr-context.c:14:48: error: bad constant expression
attr-context.c:15:46: error: bad constant expression
attr-context.c:16:46: error: bad constant expression
 * check-error-end
 */
