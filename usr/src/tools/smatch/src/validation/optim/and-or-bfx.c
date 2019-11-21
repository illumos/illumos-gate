struct s {
	int f:3;
};

void foo(struct s *p, int a, int b)
{
	p->f = a;
	p->f = b;
}

/*
 * check-name: and-or-bfx
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(2): and\\.
 * check-output-pattern(1): or\\.
 */
