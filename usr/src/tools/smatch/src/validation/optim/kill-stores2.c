extern void def(int *);

static void foo(void)
{
	int c;
	def(&c);
	if (c)
		c = c;
}

/*
 * check-name: kill-stores2
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: store\\.
 */
