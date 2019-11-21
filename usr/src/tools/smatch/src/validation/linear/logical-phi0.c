int a(void);
int b(void);
int c(void);

static int laa(void)
{
	return (a() && b()) && c();
}

static int lao(void)
{
	return (a() && b()) || c();
}

static int loa(void)
{
	return (a() || b()) && c();
}

static int loo(void)
{
	return (a() || b()) || c();
}

static int raa(void)
{
	return a() && (b() && c());
}

static int rao(void)
{
	return a() && (b() || c());
}

static int roa(void)
{
	return a() || (b() && c());
}

static int roo(void)
{
	return a() || (b() || c());
}

/*
 * check-name: bad-logical-phi0
 * check-command: sparse -vir -flinearize=last $file
 */
