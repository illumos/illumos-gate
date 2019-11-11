extern void fun(void);

static void foo(int p)
{
l:
	if (p)
l:
		fun();
}

/*
 * check-name: label-redefined
 *
 * check-error-start
label-redefined.c:7:1: error: label 'l' redefined
 * check-error-end
 */
