struct s {
	int f;
};

static int foo(struct s *s)
{
	if (s->f)
		return 0;
	else if (!s->f)
		return 4;
	return -1;
}

/*
 * check-name: dup-cond0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: select
 */
