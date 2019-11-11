long shift(long a, short b);
long shift(long a, short b)
{
	long r1 = a << b;
	long r2 = b << a;

	return r1 + r2;
}

/*
 * check-name: shift-special
 * check-command: sparsec -c $file -o tmp.o
 */
