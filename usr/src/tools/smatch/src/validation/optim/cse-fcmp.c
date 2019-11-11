extern void fun(void);

int foo(double a, double b)
{
	if (a < b)
		fun();
	if (a < b)
		return 1;

	return 0;
}

/*
 * check-name: cse-fcmp
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): fcmp
 */
