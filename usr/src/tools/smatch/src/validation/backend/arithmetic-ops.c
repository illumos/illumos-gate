static int add(int x, int y)
{
	return x + y;
}

static unsigned int uadd(unsigned int x, unsigned int y)
{
	return x + y;
}

static float fadd(float x, float y)
{
	return x + y;
}

static double dadd(double x, double y)
{
	return x + y;
}

static int sub(int x, int y)
{
	return x - y;
}

static unsigned int usub(unsigned int x, unsigned int y)
{
	return x - y;
}

static float fsub(float x, float y)
{
	return x - y;
}

static double dsub(double x, double y)
{
	return x - y;
}

static int mul(int x, int y)
{
	return x * y;
}

static unsigned int umul(unsigned int x, unsigned int y)
{
	return x * y;
}

static float fmul(float x, float y)
{
	return x * y;
}

static double dmul(double x, double y)
{
	return x * y;
}

static int div(int x, int y)
{
	return x / y;
}

static unsigned int udiv(unsigned int x, unsigned int y)
{
	return x / y;
}

static float fdiv(float x, float y)
{
	return x / y;
}

static double ddiv(double x, double y)
{
	return x / y;
}

static int mod(int x, int y)
{
	return x % y;
}

static unsigned int umod(unsigned int x, unsigned int y)
{
	return x % y;
}

/*
 * check-name: Arithmetic operator code generation
 * check-command: sparsec -c $file -o tmp.o
 */
