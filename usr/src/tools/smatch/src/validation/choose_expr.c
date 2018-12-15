static int x = __builtin_choose_expr(0,(char *)0,(void)0);
static int y = __builtin_choose_expr(1,(char *)0,(void)0);
static char s[42];
static int z = 1/(sizeof(__builtin_choose_expr(1,s,0)) - 42);

/*
 * check-name: choose expr builtin
 * check-error-start
choose_expr.c:1:51: warning: incorrect type in initializer (different base types)
choose_expr.c:1:51:    expected int static [signed] [toplevel] x
choose_expr.c:1:51:    got void <noident>
choose_expr.c:2:41: warning: incorrect type in initializer (different base types)
choose_expr.c:2:41:    expected int static [signed] [toplevel] y
choose_expr.c:2:41:    got char *<noident>
choose_expr.c:4:17: warning: division by zero
 * check-error-end
 */
