union foo {
	unsigned long		x;
	unsigned char		y;
	char			buf[128];
};

static union foo foo;

/*
 * check-name: Union code generation
 * check-command: sparsec -c $file -o tmp.o
 */
