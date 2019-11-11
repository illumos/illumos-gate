static float nanf(void)
{
	return __builtin_nanf("0");
}

static double nan(void)
{
	return __builtin_nan("0");
}

static long double nanl(void)
{
	return __builtin_nanl("0");
}

/*
 * check-name: builtin_nan expand
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-excludes: call
 */
