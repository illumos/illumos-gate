typedef int (*fn_t)(int x, int y);

static int run(fn_t fn, int x, int y)
{
	return fn(x, y);
}

/*
 * check-name: Function pointer code generation
 * check-command: sparsec -c $file -o tmp.o
 */
