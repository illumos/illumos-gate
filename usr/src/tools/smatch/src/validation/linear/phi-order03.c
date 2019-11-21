int fun(void);

static int foo(void) { return ((0 || fun()) && fun()); }

/*
 * check-name: phi-order03
 * check-command: sparse -vir -flinearize=last $file
 */
