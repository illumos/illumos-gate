int foo(void);
int foo(void)
{
	int r;

	r = ({ label: 1; });
	return r;
}

/*
 * check-name: label-expr
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: ret\\.32\$
 * check-output-contains: ret\\.32 *\\$1
 */
