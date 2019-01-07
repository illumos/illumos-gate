void foo(int a)
{
	int b = 1;
	if (a)
		b++;
	if (b)
		;
}

void bar(int a)
{
	if (a ? 1 : 2)
		;
}

/*
 * check-name: kill insert-branch
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: select\\.
 */
