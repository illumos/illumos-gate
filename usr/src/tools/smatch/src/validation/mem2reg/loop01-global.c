extern int g;

void fun(void);
void loop01(void)
{
	int i;
	for (i = 0; i <= 2;)
		if (g)
			fun();
}

/*
 * check-name: loop01 global
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-excludes: load\\..*\\[i\\]
 * check-output-contains: load\\..*\\[g\\]
 */
