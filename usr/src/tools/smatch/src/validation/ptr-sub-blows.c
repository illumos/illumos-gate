static int ok(int *a, int *b)
{
	return a - b;
}

struct s {
	int a, b, c;
};

static int ko(struct s *a, struct s *b)
{
	return a - b;
}

/*
 * check-name: ptr-sub-blows
 * check-command: sparse -Wptr-subtraction-blows $file
 *
 * check-error-start
ptr-sub-blows.c:12:18: warning: potentially expensive pointer subtraction
ptr-sub-blows.c:12:18:     'struct s' has a non-power-of-2 size: 12
 * check-error-end
 */
