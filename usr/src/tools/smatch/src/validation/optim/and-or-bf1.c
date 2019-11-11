struct s {
	int  :2;
	int f:3;
};

void foo(struct s *d, const struct s *s, int a)
{
	d->f = s->f | a;
}

/*
 * check-name: and-or-bf1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(2): and\\.
 * check-output-pattern(2): or\\.
 */
