int ftest(double a, double b)
{
	return a == 0.125 || b == 0.125;
}

/*
 * check-name: CSE OP_SETFVAL
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): setfval\\.
 */
