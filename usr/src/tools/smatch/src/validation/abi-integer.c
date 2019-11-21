#define TEST(T, S, A)	\
	_Static_assert(sizeof(T) == S && _Alignof(T) == A, #T)

int main(void)
{
	TEST(int,    4, 4);

#if defined(__LP64__)
	TEST(long,      8, 8);
	TEST(void *,    8, 8);
	TEST(long long, 8, 8);
#elif defined(__LLP64__)
	TEST(long,      4, 4);
	TEST(void *,    8, 8);
	TEST(long long, 8, 8);
#elif defined(__x86_64__)
	TEST(long,      4, 4);
	TEST(void *,    4, 4);
	TEST(long long, 8, 8);
#else
	TEST(long,      4, 4);
	TEST(void *,    4, 4);
	TEST(long long, 8, 4);
#endif

	return 0;
}

/*
 * check-name: abi-integer
 */
