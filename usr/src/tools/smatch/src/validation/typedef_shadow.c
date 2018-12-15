typedef int T;
static void f(int T)
{
	static T a;
}
/*
 * check-name: typedef shadowing
 * check-error-start:
typedef_shadow.c:4:16: warning: 'T' has implicit type
typedef_shadow.c:4:18: error: Expected ; at end of declaration
typedef_shadow.c:4:18: error: got a
 * check-error-end:
 */
