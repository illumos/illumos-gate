void foo(volatile int *p)
{
	*p = 0;
	*p = 0;
}

void bar(void)
{
	extern volatile int i;
	i = 0;
	i = 0;
}


void baz(void)
{
	volatile int i;
	i = 0;
	i = 0;
}

/*
 * check-name: keep volatile stores
 * check-command: test-linearize -Wno-decl -fdump-ir=final $file
 * check-output-ignore
 * check-output-pattern(6): store\\.
 */
