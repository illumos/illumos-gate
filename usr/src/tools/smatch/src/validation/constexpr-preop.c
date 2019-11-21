static int a[] = {
  [+0] = 0,					// OK
  [+__builtin_choose_expr(0, 0, 0)] = 0,	// OK
  [+0.] = 0,					// KO
  [+__builtin_choose_expr(0, 0, 0.)] = 0,	// KO
  [-0] = 0,					// OK
  [-__builtin_choose_expr(0, 0, 0)] = 0,	// OK
  [-0.] = 0,					// KO
  [-__builtin_choose_expr(0, 0, 0.)] = 0,	// KO
  [~0] = 0,					// OK
  [~__builtin_choose_expr(0, 0, 0)] = 0,	// OK
  [!0] = 0,					// OK
  [!__builtin_choose_expr(0, 0, 0)] = 0,	// OK
  [!0.] = 0,					// KO
  [!__builtin_choose_expr(0, 0, 0.)] = 0,	// KO
};

/*
 * check-name: constexprness in preops
 *
 * check-error-start
constexpr-preop.c:4:5: error: bad constant expression
constexpr-preop.c:5:33: error: bad constant expression
constexpr-preop.c:8:4: error: bad constant expression
constexpr-preop.c:9:4: error: bad constant expression
constexpr-preop.c:14:4: error: bad integer constant expression
constexpr-preop.c:15:4: error: bad integer constant expression
constexpr-preop.c:10:4: error: index out of bounds in initializer
constexpr-preop.c:11:4: error: index out of bounds in initializer
 * check-error-end
 */
