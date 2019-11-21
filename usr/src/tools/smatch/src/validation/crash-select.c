struct s {
	void *b;
	long c;
};

long d(void);
static long f(void)
{
	struct s s;
	s.c = d();
	if (s.c)
		s.c = 2;
	return s.c;
}

/*
 * check-name: crash-select
 */
