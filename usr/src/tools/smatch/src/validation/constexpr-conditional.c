static int a[] = {
	[0 ? : 0] = 0,						// OK
	[1 ? : 0] = 0,						// OK
	[0 ? 0 : 0] = 0,					// OK
	[1 ? 0 : 0] = 0,					// OK
	[0 ? 0 : __builtin_choose_expr(0, 0, 0)] = 0,		// OK
	[1 ? __builtin_choose_expr(0, 0, 0) : 0] = 0,		// OK
	[0 ? __builtin_choose_expr(0, 0, 0) : 0] = 0,		// OK
	[1 ? 1 : __builtin_choose_expr(0, 0, 0)] = 0,		// OK
	[__builtin_choose_expr(0, 0, 0) ? : 0] = 0,		// OK
	[__builtin_choose_expr(0, 0, 1) ? : 0] = 0,		// OK
	[0. ? : 0] = 0,					// KO
	[0 ? 0. : 0] = 0,					// KO
	[1 ? : 0.] = 0,					// KO
	[__builtin_choose_expr(0, 0., 0) ? : 0] = 0,		// OK
	[__builtin_choose_expr(0, 0, 0.) ? : 0] = 0,		// KO
	[0 ? __builtin_choose_expr(0, 0., 0) : 0] = 0,		// OK
	[0 ? __builtin_choose_expr(0, 0, 0.) : 0] = 0,		// KO
	[1 ? 0 : __builtin_choose_expr(0, 0., 0)] = 0,		// OK
	[1 ? 0 : __builtin_choose_expr(0, 0, 0.)] = 0,		// KO
};

/*
 * check-name: constexprness in conditionals
 *
 * check-error-start
constexpr-conditional.c:12:13: error: bad constant expression
constexpr-conditional.c:13:19: error: bad constant expression
constexpr-conditional.c:14:12: error: bad constant expression
constexpr-conditional.c:16:42: error: bad constant expression
constexpr-conditional.c:18:48: error: bad constant expression
constexpr-conditional.c:20:14: error: bad constant expression
 * check-error-end
 */
