static int and_bool(int x, int y)
{
	return x && y;
}

static unsigned int uand_bool(unsigned int x, unsigned int y)
{
	return x && y;
}

static int or_bool(int x, int y)
{
	return x || y;
}

static unsigned int uor_bool(unsigned int x, unsigned int y)
{
	return x || y;
}

/*
 * check-name: Logical operator code generation
 * check-command: sparsec -c $file -o tmp.o
 */
