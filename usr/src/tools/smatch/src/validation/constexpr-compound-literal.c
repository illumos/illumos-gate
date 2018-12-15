static int *a = &(int){ 1 };	// OK
static int *b = &(int){ *a };	// KO

static void foo(void)
{
	int *b = &(int){ 1 };		// OK
	int *c = &(int){ *a };		// OK
	static int *d = &(int){ 1 };	// KO
}

/*
 * check-name: compound literal address constness verification
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
constexpr-compound-literal.c:2:25: warning: non-constant initializer for static object
constexpr-compound-literal.c:8:27: warning: non-constant initializer for static object
 * check-error-end
 */
