extern unsigned long foo;

static unsigned long bar(void)
{
	return foo;
}

/*
 * check-name: Extern symbol code generation
 * check-command: sparsec -c $file -o tmp.o
 */
