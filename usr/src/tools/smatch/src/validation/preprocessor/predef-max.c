#define TEST_MAX(X, Z)	if (X != ((~ Z) >> 1))	return 1

int test_max(void)
{
	TEST_MAX(__INT_MAX__, 0U);
	TEST_MAX(__LONG_MAX__, 0UL);
	TEST_MAX(__LONG_LONG_MAX__, 0ULL);

	return 0;
}

/*
 * check-name: predefined __<type>_MAX__
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
