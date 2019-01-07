#include <stdio.h>
#include <stdlib.h>

static int sum(int n)
{
	int i, result = 0;

	for (i = 1; i <= n; ++i)
		result += i;
	return result;
}

int main(int argc, char **argv)
{
	printf("%d\n", sum(5));
	printf("%d\n", sum(100));
	return 0;
}

/*
 * check-name: sum from 1 to n
 * check-command: sparsei $file
 *
 * check-output-start
15
5050
 * check-output-end
 */
