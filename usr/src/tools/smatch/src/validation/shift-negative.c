unsigned int fn1(unsigned int a) { return a >> -1; }
unsigned int fn2(unsigned int a) { return a >> ~0; }

unsigned int fo1(unsigned int a) { return a >> ((a & 0) | -1); }
unsigned int fo2(unsigned int a) { return a >> ((a & 0) ^ ~0); }

/*
 * check-name: shift-negative
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
shift-negative.c:1:45: warning: shift count is negative (-1)
shift-negative.c:2:45: warning: shift count is negative (-1)
shift-negative.c:4:59: warning: shift count is negative (-1)
shift-negative.c:5:59: warning: shift count is negative (-1)
 * check-error-end
 */
