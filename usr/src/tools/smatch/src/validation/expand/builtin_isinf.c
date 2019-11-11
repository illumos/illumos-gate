int test(void)
{
	if (!__builtin_isinf(__builtin_inff()))
		return 0;
	if (!__builtin_isinf(__builtin_inf()))
		return 0;
	if (!__builtin_isinf(__builtin_infl()))
		return 0;

	return 1;
}

/*
 * check-name: builtin_isinf expand
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 */
