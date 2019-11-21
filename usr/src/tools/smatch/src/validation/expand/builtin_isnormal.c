int test(void)
{
	if (!__builtin_isnormal(1.0F))
		return 0;
	if (!__builtin_isnormal(1.0))
		return 0;
	if (!__builtin_isnormal(1.0L))
		return 0;

	return 1;
}

/*
 * check-name: builtin_isnormal expand
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 */
