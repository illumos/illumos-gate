double uintfloat(void)
{
	union {
		int a;
		double f;
	} s;

	s.a = 1;
	return s.f;
}


int uarray(void)
{
	union {
		double d;
		int a[2];
	} s;

	s.d = 1;
	return s.a[0];
}

/*
 * check-name: init-local union 1
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(1): store\\.32
 * check-output-pattern(1): load\\.64
 * check-output-pattern(1): store\\.64
 * check-output-pattern(1): load\\.32
 */
