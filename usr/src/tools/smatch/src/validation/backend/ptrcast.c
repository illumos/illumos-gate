static char *ptrcast(unsigned long *x)
{
	return (unsigned char *) x;
}

/*
 * check-name: Pointer cast code generation
 * check-command: sparsec -c $file -o tmp.o
 */
