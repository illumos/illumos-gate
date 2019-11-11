

int foo(void)
{
	int j = 1;
	int i = 6;

	do {
		if (i != 6)
			i++;
		i++;
	} while (i != j);

	return j;
}

/*
 * check-name: loop02 pointer
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 *
 * check-output-ignore
 * check-output-excludes: load\\.
 */
