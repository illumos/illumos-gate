int xpc_add_ypc(int x, int y)
{
	return (x + 1) + (y + 1);
}

int xmc_add_ypc(int x, int y)
{
	return (x - 1) + (y + 1);
}

int xpc_add_ymc(int x, int y)
{
	return (x + 1) + (y - 1);
}

int xmc_add_ymc(int x, int y)
{
	return (x - 1) + (y - 1);
}

int xpc_sub_ypc(int x, int y)
{
	return (x + 1) - (y + 1);
}

int xmc_sub_ypc(int x, int y)
{
	return (x - 1) - (y + 1);
}

int xpc_sub_ymc(int x, int y)
{
	return (x + 1) - (y - 1);
}

int xmc_sub_ymc(int x, int y)
{
	return (x - 1) - (y - 1);
}

/*
 * check-name: canonical-add
 * check-description:
 *	1) verify that constants in add/sub chains are
 *	   pushed at the right of the whole chain.
 *	   For example '(a + 1) + b' must be canonicalized into '(a + b) + 1'
 *	   This is needed for '(a + 1) + b - 1' to be simplified into '(a + b)'
 *
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 * check-output-ignore

 * check-output-excludes: \\$1
 * check-output-excludes: \\$-1
 */
