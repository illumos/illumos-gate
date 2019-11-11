struct s {
	int c;
	int a[];
} s;
int f;

void fun(void);
void foo(void)
{
	for (f = 1;;)
		if (s.a[f])
			fun();
}

/*
 * check-name: global var as loop index
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-contains: load\\..*\\[f\\]
 */
