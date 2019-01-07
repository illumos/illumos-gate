typedef int T;
extern void f(int);
static void g(int x)
{
	int (T);
	T = x;
	f(T);
}
static void h(void)
{
	static int [2](T)[3];
}
static int [2](*p)[3];
int i(void (void)(*f));
int j(int [2](*));
/*
 * check-name: nested declarator vs. parameters
 * check-error-start:
nested-declarator.c:11:23: warning: missing identifier in declaration
nested-declarator.c:11:23: error: Expected ; at the end of type declaration
nested-declarator.c:11:23: error: got (
nested-declarator.c:13:15: error: Expected ; at the end of type declaration
nested-declarator.c:13:15: error: got (
nested-declarator.c:14:18: error: Expected ) in function declarator
nested-declarator.c:14:18: error: got (
nested-declarator.c:15:14: error: Expected ) in function declarator
nested-declarator.c:15:14: error: got (
 * check-error-end:
 */
