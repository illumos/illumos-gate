static int array(void)
{
	int a[2];

	a[1] = 1;
	a[0] = 0;
	return a[1];
}

static int sarray(void)
{
	struct {
		int a[2];
	} s;

	s.a[1] = 1;
	s.a[0] = 0;
	return s.a[1];
}

/*
 * check-name: init local array
 * check-command: test-linearize $file
 * check-output-ignore
 * check-output-excludes: load
 * check-output-excludes: store
 * check-output-pattern(2): ret.32 *\\$1
 */
