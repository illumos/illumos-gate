#include "check_debug.h"

int x;
int array[10];

int main(void)
{
	__smatch_implied(&x);
	__smatch_implied((unsigned long)(array + 1) - (unsigned long)array);
	__smatch_implied(array + 1 - array);
	__smatch_implied(array + 1);
	__smatch_implied((int *)0 + 1);

	return 0;
}


/*
 * check-name: smatch mtag #3
 * check-command: smatch -I.. sm_mtag3.c
 *
 * check-output-start
sm_mtag3.c:8 main() implied: &x = '799717014380380160'
sm_mtag3.c:9 main() implied: (array[1]) - array = '4'
sm_mtag3.c:10 main() implied: array[1] - array = '1'
sm_mtag3.c:11 main() implied: array[1] = '7934625272050024452'
sm_mtag3.c:12 main() implied: 0 + 1 = '4'
 * check-output-end
 */
