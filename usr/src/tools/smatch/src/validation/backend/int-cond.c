static long foo(long a, long b, long c)
{
	return a? b:c;
}

static long foo_bool(_Bool a, long b, long c)
{
	return a? b:c;
}

static long bar(long a, long b, long c)
{
	if (a)
		return b;
	else
		return b + c;
}

static long bar_bool(_Bool a, long b, long c)
{
	if (a)
		return b;
	else
		return b + c;
}

/*
 * check-name: Non-bool condition values in branch/select
 * check-command: sparsec -c $file -o tmp.o
 */
