double uintfloat(void)
{
	union {
		int a;
		double f;
	} s;

	s.a = 1;
	return s.f;
}

/*
 * check-name: init-local union 0
 * check-command: test-linearize -Wno-decl -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-pattern(1): store\\.32
 * check-output-pattern(1): load\\.64
 */
