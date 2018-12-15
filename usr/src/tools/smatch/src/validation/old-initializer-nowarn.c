struct s {
	int i;
};

static struct s the_s = { i: 1 };
/*
 * check-name: Old initializer with -Wno-old-initializer
 * check-command: sparse -Wno-old-initializer
 */
