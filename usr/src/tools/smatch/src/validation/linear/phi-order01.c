int fun(void);

static int foo(int a)
{
	return a && fun();
}

static int bar(int a)
{
	return a || fun();
}

/*
 * check-name: phi-order01
 * check-command: sparse -vir -flinearize=last $file
 */
