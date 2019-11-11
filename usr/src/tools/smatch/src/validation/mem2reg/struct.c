struct s {
	int a;
	int b;
};

int f0(void)
{
	struct s s;

	s.a = 0;
	s.b = 1;

	return s.a;
}

int f1(void)
{
	struct s s;

	s.a = 1;
	s.b = 0;

	return s.b;
}

/*
 * check-name: struct
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(2): ret.32 *\\$0
 */
