static float huge_valf(void)
{
	return __builtin_huge_valf();
}

static double huge_val(void)
{
	return __builtin_huge_val();
}

static long double huge_vall(void)
{
	return __builtin_huge_vall();
}


static float inff(void)
{
	return __builtin_inff();
}

static double inf(void)
{
	return __builtin_inf();
}

static long double infl(void)
{
	return __builtin_infl();
}

/*
 * check-name: builtin_huge_val expand
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-excludes: call
 */
