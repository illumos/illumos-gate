extern void __abort(void);

struct s {
	int elem:3;
};

void foo(struct s *x);
void foo(struct s *x)
{
	if (x->elem == 0) {
		if (x->elem != 0 && x->elem != 1)
			__abort();
	}
}

/*
 * check-name: kill-casts
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: cast\\.
 */
