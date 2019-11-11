void foo(int p, volatile int *ptr)
{
	p ? : *ptr;
	p ? : *ptr;
}

/*
 * check-name: volatile-side-effect
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-pattern(2): load
 */
