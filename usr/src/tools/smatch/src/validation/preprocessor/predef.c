#define BITS(T)		(sizeof(T) * 8)
#define SIGN_BIT(T)	(1ULL << (BITS(T) - 1))
#define SMASK(T)	(SIGN_BIT(T) - 1)
#define UMASK(T)	(SIGN_BIT(T) | SMASK(T))

int test(void);
int test(void)
{
#define TEST_BIT(X, T)	if (__ ## X ## _BIT__  != BITS(T)) return 1
	TEST_BIT(CHAR, char);

#define TEST_MAX(X, M)	if (__ ## X ## _MAX__ != M) return 1
#define TEST_SMAX(X, T)	TEST_MAX(X, SMASK(T))
#define TEST_UMAX(X, T)	TEST_MAX(X, UMASK(T))
	TEST_SMAX(SCHAR, signed char);
	TEST_SMAX(SHRT, short);
	TEST_SMAX(INT, int);
	TEST_SMAX(LONG, long);
	TEST_SMAX(LONG_LONG, long long);
	TEST_MAX( INT8,  0x7f);
	TEST_MAX(UINT8,  0xffU);
	TEST_MAX( INT16, 0x7fff);
	TEST_MAX(UINT16, 0xffffU);
	TEST_MAX( INT32, 0x7fffffff);
	TEST_MAX(UINT32, 0xffffffffU);
	TEST_MAX( INT64, 0x7fffffffffffffffLL);
	TEST_MAX(UINT64, 0xffffffffffffffffULL);
	TEST_SMAX(INTMAX, __INTMAX_TYPE__);
	TEST_UMAX(UINTMAX, __UINTMAX_TYPE__);
	TEST_SMAX(INTPTR, __INTPTR_TYPE__);
	TEST_UMAX(UINTPTR, __UINTPTR_TYPE__);
	TEST_SMAX(PTRDIFF, __PTRDIFF_TYPE__);
	TEST_UMAX(SIZE, __SIZE_TYPE__);

#define TEST_SIZEOF(X, T) if (__SIZEOF_ ## X ## __ != sizeof(T)) return 1
	TEST_SIZEOF(SHORT, short);
	TEST_SIZEOF(INT, int);
	TEST_SIZEOF(LONG, long);
	TEST_SIZEOF(LONG_LONG, long long);
	TEST_SIZEOF(INT128, __int128);
	TEST_SIZEOF(PTRDIFF_T, __PTRDIFF_TYPE__);
	TEST_SIZEOF(SIZE_T, __SIZE_TYPE__);
	TEST_SIZEOF(POINTER, void*);
	TEST_SIZEOF(FLOAT, float);
	TEST_SIZEOF(DOUBLE, double);
	TEST_SIZEOF(LONG_DOUBLE, long double);

	return 0;
}

/*
 * check-name: predefined macros: __SIZEOF_<type>__, ...
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
