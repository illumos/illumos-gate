static int shl(int x, int y)
{
	return x << y;
}

static unsigned int ushl(unsigned int x, unsigned int y)
{
	return x << y;
}

static int shr(int x, int y)
{
	return x >> y;
}

static unsigned int ushr(unsigned int x, unsigned int y)
{
	return x >> y;
}

static int and(int x, int y)
{
	return x & y;
}

static unsigned int uand(unsigned int x, unsigned int y)
{
	return x & y;
}

static int or(int x, int y)
{
	return x | y;
}

static unsigned int uor(unsigned int x, unsigned int y)
{
	return x | y;
}

static int xor(int x, int y)
{
	return x ^ y;
}

static unsigned int uxor(unsigned int x, unsigned int y)
{
	return x ^ y;
}

static int not(int x)
{
	return ~x;
}

static unsigned int unot(unsigned int x)
{
	return ~x;
}

/*
 * check-name: Bitwise operator code generation
 * check-command: sparsec -c $file -o tmp.o
 */
