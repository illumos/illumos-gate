union u {
	char c;
	float f;
};

static int foo(void)
{
	union u u = { .f = 0.123 };
	return u.c;
}

/*
 * check-name: bug-expand-union
 * check description: must not infer the value from the float
 * check-command: test-linearize $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: load\\.
 * check-output-excludes: ret\\..*\\$
 */
