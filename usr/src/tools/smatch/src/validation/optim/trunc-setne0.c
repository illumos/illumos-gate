struct s {
	unsigned int u:1;
};

unsigned int foo(struct s x)
{
	if (x.u)
		return 1;
	else
		return 0;
}

/*
 * check-name: trunc-setne0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: and\\.
 * check-output-excludes: trunc\\.
 */
