extern int fun0(int a);
extern int fun1(int a);

int foo(int a);
int foo(int a)
{
	int v = fun0(a);
	return v;
}

void *bar(int a)
{
	return fun1;
}

int fun0(int a)
{
	return a + 0;
}

int fun1(int a)
{
	return a + 1;
}

/*
 * check-name: llvm function reference
 * check-command: sparse-llvm-dis -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: fun[0-9]\.[1-9]
 */
