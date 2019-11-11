static int badr(void)
{
	int *a;
	return *a;
}

static void badw(int v)
{
	int *a;
	*a = v;
}

/*
 * check-name: undef00
 * check-command: test-linearize -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(1): load\\.
 * check-output-pattern(1): load\\..*\\[UNDEF\\]
 * check-output-pattern(1): store\\.
 * check-output-pattern(1): store\\..*\\[UNDEF\\]
 */
