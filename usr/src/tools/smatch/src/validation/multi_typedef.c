typedef int T, *P;
static void f(void)
{
	unsigned P = 0;
	unsigned x = P;
}
static void g(void)
{
	int P = 0;
	int x = P;
}
/*
 * check-name: typedefs with many declarators
 * check-description: we didn't recognize P above as a typedef
 */
