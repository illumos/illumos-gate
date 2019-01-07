#include <stdio.h>
#include "check_debug.h"

int x = 42;

struct foo {
	int a, b, c;
};
struct foo aaa = {
	.a = 1, .b = 2, .c = 3,
};

int array[10];

int main(void)
{
	__smatch_implied(&x);
	__smatch_implied(&aaa);
	__smatch_implied(&aaa.b);
	__smatch_implied(array);
	__smatch_implied(&array[1]);

	return 0;
}

/*
 * check-name: smatch mtag #5
 * check-command: smatch -I.. sm_mtag5.c
 *
 * check-output-start
sm_mtag5.c:17 main() implied: &x = '799717014380380160'
sm_mtag5.c:18 main() implied: &aaa = '126458562737565696'
sm_mtag5.c:19 main() implied: &aaa.b = '126458562737565700'
sm_mtag5.c:20 main() implied: array = '7934625272050024448'
sm_mtag5.c:21 main() implied: &array[1] = '7934625272050024452'
 * check-output-end
 */
