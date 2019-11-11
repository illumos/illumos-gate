struct s {
	int c[1];
};

static struct s x, y;
static int p;

static void foo0(void)
{
	(x = y).c;		// x = y;
}

static void foo1(void)
{
	int *t = (x = y).c;	// x = y;
}

static void foo2(void)
{
	(x = y).c + 1;		// x = y;
}

static void foo3(void)
{
	(x = y).c[0];		// x = y;
}

static void foo4(void)
{
	(p ? x : y).c[0];	// ;
}

static void foo5(void)
{
	(p, y).c[0];		// ;
}

/*
 * check-name: kill-stores1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(4): load\\.
 * check-output-pattern(4): load\\..*0\\[y\\]
 * check-output-pattern(4): store\\.
 * check-output-pattern(4): store\\..*0\\[x\\]
 * check-output-excludes: select\\.
 */
