// credit goes to Martin Uecker for the awesome ICE_P macro

#define ICE_P(x) \
    (__builtin_types_compatible_p(typeof(0?((void*)((long)(x)*0l)):(int*)1),int*))

#define T(x)		__builtin_choose_expr(ICE_P(x), 1, 0)
#define TEST(x, r)	_Static_assert(T(x) == r, #x " => " #r)

static void test(int n)
{
	char foo[n++];

	TEST(sizeof(foo), 0);
}

/*
 * check-name: vla-sizeof-ice
 * check-command: sparse -Wno-vla $file
 */
