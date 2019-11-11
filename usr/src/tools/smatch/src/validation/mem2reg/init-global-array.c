struct s {
	int a[2];
};


static struct s s;

static int sarray(void)
{
	s.a[1] = 1;
	return s.a[1];
}

/*
 * check-name: init global array
 * check-command: test-linearize $file
 * check-output-ignore
 * check-output-excludes: load\\.
 * check-output-pattern(1): store\\.
 * check-output-pattern(1): ret.32 *\\$1
 */
