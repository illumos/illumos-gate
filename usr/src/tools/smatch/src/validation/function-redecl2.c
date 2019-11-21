extern void exit (int __status) __attribute__ ((__noreturn__));

int func0(int a) __attribute__ ((pure));

__attribute__ ((pure))
int func0(int a)
{
	return 0;
}

__attribute__ ((noreturn)) void func1(int a);

void func1(int a)
{
	exit(0);
}

void func2(int a) __attribute__ ((noreturn));

__attribute__ ((noreturn))
void func2(int a)
{
	exit(0);
}

/*
 * check-name: function-redecl2
 *
 * check-known-to-fail
 *
 */
