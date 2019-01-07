#include <stdio.h>

int main(int argc, char *argv[])
{
	puts("hello, world");

	return 0;
}

/*
 * check-name: 'hello, world' code generation
 * check-command: sparsec -c $file -o tmp.o
 */
