struct s {
	int i;
};

static struct s the_s = { i: 1 };
/*
 * check-name: Old initializer
 *
 * check-error-start
old-initializer.c:5:27: warning: obsolete struct initializer, use C99 syntax
 * check-error-end
 */
