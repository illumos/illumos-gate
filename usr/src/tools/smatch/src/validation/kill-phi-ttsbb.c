int def(void);
void use(int);

static void foo(int a, int b)
{
	int c;

	if (a)
		c = 1;
	else
		c = def();

	if (c)
		use(1);
	else
		use(0);
}

/*
 * check-name: kill-phi-ttsbb
 * check-description:
 *	Verify if OP_PHI usage is adjusted after successful try_to_simplify_bb()
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: phi\\.
 * check-output-excludes: phisrc\\.
 */
