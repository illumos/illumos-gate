struct s {
	int (*fun)(void);
};

inline struct s *inl(struct s *p)
{
	1 + 0;
	return p;
}

static void tst(struct s *s)
{
	inl(s)->fun();
}

/*
 * check-name: function-pointer
 * check-command: test-linearize -fdump-ir $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.32.*\\$1, \\$0
 */
