#define TEST(X, T)	if (__SIZEOF_ ## X ## __ != sizeof(T))	return 1

int test_sizeof(void)
{
	TEST(SHORT, short);
	TEST(INT, int);
	TEST(LONG, long);
	TEST(LONG_LONG, long long);
	TEST(INT128, __int128);
	TEST(SIZE_T, __SIZE_TYPE__);
	TEST(POINTER, void*);
	TEST(FLOAT, float);
	TEST(DOUBLE, double);
	TEST(LONG_DOUBLE, long double);

	return 0;
}

/*
 * check-name: predefined __SIZEOF_<type>__
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
