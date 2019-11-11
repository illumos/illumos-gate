struct s {
	int f:3;
};

void foo(struct s *p, int a)
{
	p->f = 1;
	p->f = a;
}

void bar(struct s *p, int a)
{
	p->f = a;
	p->f = 1;
}

/*
 * check-name: and-or-bf0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(3): and\\.
 * check-output-pattern(2): or\\.
 */
