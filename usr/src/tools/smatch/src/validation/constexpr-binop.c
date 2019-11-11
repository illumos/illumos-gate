static int a[] = {
	[0 + 0] = 0,						// OK
	[0 + 0.] = 0,						// KO
	[(void*)0 + 0] = 0,					// KO
	[0 + __builtin_choose_expr(0, 0, 0)] = 0,		// OK
	[0 + __builtin_choose_expr(0, 0., 0)] = 0,		// OK
	[0 + __builtin_choose_expr(0, 0, 0.)] = 0,		// KO
	[0 < 0] = 0,						// OK
	[0 < 0.] = 0,						// KO
	[0 < __builtin_choose_expr(0, 0, 0)] = 0,		// OK
	[0 < __builtin_choose_expr(0, 0., 0)] = 0,		// OK
	[0 < __builtin_choose_expr(0, 0, 0.)] = 0,		// KO
	[0 && 0] = 0,						// OK
	[0 && 0.] = 0,						// KO
	[0 && __builtin_choose_expr(0, 0, 0)] = 0,		// OK
	[0 && __builtin_choose_expr(0, 0., 0)] = 0,		// OK
	[0 && __builtin_choose_expr(0, 0, 0.)] = 0,		// KO
	[0 + __builtin_types_compatible_p(int, float)] = 0,	// OK
};

/*
 * check-name: constexprness in binops and alike
 *
 * check-error-start
constexpr-binop.c:3:12: error: bad constant expression
constexpr-binop.c:4:19: error: bad integer constant expression
constexpr-binop.c:7:12: error: bad constant expression
constexpr-binop.c:9:12: error: bad integer constant expression
constexpr-binop.c:12:12: error: bad integer constant expression
constexpr-binop.c:14:12: error: bad integer constant expression
constexpr-binop.c:17:12: error: bad integer constant expression
 * check-error-end
 */
