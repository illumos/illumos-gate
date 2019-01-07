extern void *memset (void *s, int c, int n);
static void test(void)
{
	struct { int foo;; } val;
	memset(&val, 0, sizeof(val));
}
/*
 * check-name: Double semicolon in struct
 */
