struct p {
	int x, y;
};

struct q {
	int w;
};

static int foo(void)
{
	int x = 1;
	int y = x;
	return &x == &y;
}

static int bar(struct p p)
{
	if (p.x != 0)
		;
}

static int baz(struct p p, struct q q)
{
	if (p.x != 0 || p.y != 1 || q.w == 0)
		;
}

/*
 * check-name: kill-stores0
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: store\\.
 */
