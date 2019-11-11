extern void use(const char *);

const char *ret(void)
{
	return "abc";
}

const char *add(void)
{
	return "def" + 1;
}

void call(void)
{
	use("ijk");
}

/*
 * check-name: string-value
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
