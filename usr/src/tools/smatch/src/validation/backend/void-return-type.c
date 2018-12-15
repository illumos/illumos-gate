static void foo(void)
{
}

static void *bar(void *p)
{
	return p;
}

/*
 * check-name: void return type code generation
 * check-command: sparsec -c $file -o tmp.o
 */
