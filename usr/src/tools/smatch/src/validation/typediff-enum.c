enum num { ZERO, ONE, MANY, };
typedef enum num num;

extern int v;
num v = 0;

extern num w;
int w = 0;

int foo(void);
num foo(void) { return ZERO; }

num bar(void);
int bar(void) { return ZERO; }

void baz(int a);
void baz(num a) { }

void qux(num a);
void qux(int a) { }

/*
 * check-name: typediff-enum
 * check-known-to-fail
 *
 * check-error-start
typediff-enum.c:5:5: error: symbol 'v' redeclared with different type (originally declared at typediff-enum.c:4) - different types
typediff-enum.c:8:5: error: symbol 'w' redeclared with different type (originally declared at typediff-enum.c:7) - different types
typediff-enum.c:11:5: error: symbol 'foo' redeclared with different type (originally declared at typediff-enum.c:10) - different types
typediff-enum.c:14:5: error: symbol 'bar' redeclared with different type (originally declared at typediff-enum.c:13) - different types
typediff-enum.c:17:6: error: symbol 'baz' redeclared with different type (originally declared at typediff-enum.c:16) - incompatible argument 1 (different types)
typediff-enum.c:20:6: error: symbol 'qux' redeclared with different type (originally declared at typediff-enum.c:19) - incompatible argument 1 (different types)
 * check-error-end
 */
