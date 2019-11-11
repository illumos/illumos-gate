int ssimple(void)
{
	struct {
		int a;
	} s;

	s.a = 1;
	return s.a;
}

double sdouble(void)
{
	struct {
		double a;
	} s;

	s.a = 1.23;
	return s.a;
}

/*
 * check-name: init-local64
 * check-command: test-linearize -Wno-decl -m64 -fdump-ir=mem2reg $file
 * check-output-ignore
 * check-output-excludes: load\\.
 * check-output-excludes: store\\.
 */
