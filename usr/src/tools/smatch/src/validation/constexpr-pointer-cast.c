static int *a = (int*)0;	// OK
static int b = 0;
static int *c = (int*)b;	// KO


/*
 * check-name: constexprness integer literal cast to pointer type
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
constexpr-pointer-cast.c:3:18: warning: non-constant initializer for static object
 * check-error-end
 */
