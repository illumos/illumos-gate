static int icmp = 1 / (sizeof(int) - sizeof(1 > 0));
static int fcmp = 1 / (sizeof(int) - sizeof(1.0 == 2.0 - 1.0));
static int lnot = 1 / (sizeof(int) - sizeof(!!1.0));
static int land = 1 / (sizeof(int) - sizeof(2 && 3));
static int lor  = 1 / (sizeof(int) - sizeof('c' || 1.0f));

/*
 * check-name: result type of relational and logical operators
 *
 * check-error-start
cond_expr3.c:1:21: warning: division by zero
cond_expr3.c:2:21: warning: division by zero
cond_expr3.c:3:21: warning: division by zero
cond_expr3.c:4:21: warning: division by zero
cond_expr3.c:5:21: warning: division by zero
 * check-error-end
 */
