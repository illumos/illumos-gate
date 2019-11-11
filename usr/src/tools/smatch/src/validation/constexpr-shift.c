#define __is_constexpr(x) \
        (sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

static void test(int x) {
	static int b[] = {
		[__builtin_choose_expr(__is_constexpr(1 << 1), 1, x)] = 0,
	};
}

/*
 * check-name: constexpr-shift
 */
