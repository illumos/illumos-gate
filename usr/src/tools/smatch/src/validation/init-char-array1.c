/*
 * for array of char, ("...") as the initializer is an gcc language
 * extension. check that a parenthesized string initializer is handled
 * correctly and that -Wparen-string warns about it's use.
 */
static const char u[] = ("hello");
static const char v[] = {"hello"};
static const char v1[] = {("hello")};
static const char w[] = "hello";
static const char x[5] = "hello";

static void f(void)
{
	char a[1/(sizeof(u) == 6)];
	char b[1/(sizeof(v) == 6)];
	char c[1/(sizeof(w) == 6)];
	char d[1/(sizeof(x) == 5)];
}
/*
 * check-name: parenthesized string initializer
 * check-command: sparse -Wparen-string $file
 *
 * check-error-start
init-char-array1.c:6:26: warning: array initialized from parenthesized string constant
init-char-array1.c:8:28: warning: array initialized from parenthesized string constant
 * check-error-end
 */
