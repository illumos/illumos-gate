void foo(int a, int *b, unsigned int g);
void foo(int a, int *b, unsigned int g)
{
	int d = 0;

	if ((!a || *b) && g)
		d = 16;
	else
		d = 8;
}

int bar(void);
int bar(void)
{
	int i;
	for (i = 0; i; i--)
		;
	return 0;
}

/*
 * check-name: kill-phi-node
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: phisrc\\.
 */
