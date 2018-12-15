#define TEST_BIT(X, T)	if (__ ## X ## _BIT__  != 8 * sizeof(T)) return 1

int test(void)
{
	TEST_BIT(CHAR, char);

	return 0;
}

/*
 * check-name: predefined __<type>_BIT__
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
