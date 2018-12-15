extern int a(void);
extern int b(void);
extern int c(void);

static int or(void)
{
	return a() || b() || c();
}

static int and(void)
{
	return a() && b() && c();
}
/*
 * check-name: Logical and/or
 */

