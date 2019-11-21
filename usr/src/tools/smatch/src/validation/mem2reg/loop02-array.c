

int foo(int i[])
{
	int j = 1;
	i[0] = 6;

	do {
		if (i[0] != 6)
			i[0]++;
		i[0]++;
	} while (i[0] != j);

	return j;
}

/*
 * check-name: loop02 array
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(0,4): load\\.
 * check-output-pattern(1,3): store\\.
 */
