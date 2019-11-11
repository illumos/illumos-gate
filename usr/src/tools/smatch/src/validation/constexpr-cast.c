static int a[] = {
	[(int)0] = 0,		// OK
	[(int)(int)0] = 0,	// OK
	[(int)0.] = 0,		// OK
	[(int)(int)0.] = 0,	// OK
	[(int)__builtin_choose_expr(0, 0, 0)] = 0,	// OK
	[(int)__builtin_choose_expr(0, 0, 0.)] = 0,	// OK

	[(int)(float)0] = 0,	// KO
	[(int)(float)0.] = 0,	// KO

	[(int)(void*)0] = 0,	// KO
	[(int)(void*)0.] = 0,	// KO

};
/*
 * check-name: constexprness in casts
 *
 * check-error-start
constexpr-cast.c:9:11: error: bad integer constant expression
constexpr-cast.c:10:11: error: bad integer constant expression
constexpr-cast.c:12:11: error: bad integer constant expression
constexpr-cast.c:13:11: error: bad integer constant expression
 * check-error-end
 */
