static int sete(int x, int y)
{
	return x == y;
}

static int setne(int x, int y)
{
	return x != y;
}

static int setl(int x, int y)
{
	return x < y;
}

static int setg(int x, int y)
{
	return x > y;
}

static int setle(int x, int y)
{
	return x <= y;
}

static int setge(int x, int y)
{
	return x >= y;
}

static int setb(unsigned int x, unsigned int y)
{
	return x < y;
}

static int seta(unsigned int x, unsigned int y)
{
	return x > y;
}

static int setbe(unsigned int x, unsigned int y)
{
	return x <= y;
}

static int setae(unsigned int x, unsigned int y)
{
	return x >= y;
}

static int setfe(float x, float y)
{
	return x == y;
}

static int setfne(float x, float y)
{
	return x != y;
}

static int setfl(float x, float y)
{
	return x < y;
}

static int setfg(float x, float y)
{
	return x > y;
}

static int setfle(float x, float y)
{
	return x <= y;
}

static int setfge(float x, float y)
{
	return x >= y;
}

/*
 * check-name: Comparison operator code generation
 * check-command: sparsec -c $file -o tmp.o
 */
