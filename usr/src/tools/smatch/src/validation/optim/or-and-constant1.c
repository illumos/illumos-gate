unsigned int and_or_equ(unsigned int a)
{
	return (a | 3) & 3;
}

int and_or_eqs(int a)
{
	return (a | 3) & 3;
}

unsigned int or_and_equ(unsigned int a)
{
	return (a & 3) | 3;
}

int or_and_eqs(int a)
{
	return (a & 3) | 3;
}

/*
 * check-name: or-and-constant1
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-pattern(4): ret\\..*\\$3
 * check-output-excludes: or\\.
 */
