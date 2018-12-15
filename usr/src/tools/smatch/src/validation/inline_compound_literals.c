struct foo {
	int x;
};

static inline void baz(void)
{
	(struct foo) { .x = 0 };
}

static void barf(void)
{
	baz();
}

static void foo(void)
{
	baz();
}

/*
 * check-name: inline compound literals
 */
