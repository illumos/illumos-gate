int test(void)
{
	if (!__builtin_isnan(__builtin_nanf("0")))
		return 0;
	if (!__builtin_isnan(__builtin_nan("0")))
		return 0;
	if (!__builtin_isnan(__builtin_nanl("0")))
		return 0;

	return 1;
}

/*
 * check-name: builtin_isnan expand
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 */
