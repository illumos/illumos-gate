typedef int T;
extern void f1(int);
extern void f2(T);
static void (*f3)(int) = f2;
static void (*f4)(T) = f1;
extern void f5(void (int));
extern void f6(void (T));
static void z(int x)
{
	int (T) = x;
	f5(f2);
	f6(f3);
}
static void f8();
static int (x) = 1;
static void w1(y)
int y;
{
	x = y;
}
static void w2(int ());
static void w3(...);
static void f9(__attribute__((mode(DI))) T);
static void w4(int f(x,y));
static void bad1(__attribute__((mode(DI))) x);
static int (-bad2);
static void [2](*bad3);
/*
 * check-name: more on handling of ( in direct-declarator
 * check-error-start:
nested-declarator2.c:17:1: warning: non-ANSI definition of function 'w1'
nested-declarator2.c:21:21: warning: non-ANSI function declaration of function '<noident>'
nested-declarator2.c:22:16: warning: variadic functions must have one named argument
nested-declarator2.c:24:21: warning: identifier list not in definition
nested-declarator2.c:25:45: error: don't know how to apply mode to incomplete type
nested-declarator2.c:26:13: error: Expected ) in nested declarator
nested-declarator2.c:26:13: error: got -
nested-declarator2.c:27:16: error: Expected ; at the end of type declaration
nested-declarator2.c:27:16: error: got (
 * check-error-end:
 */
