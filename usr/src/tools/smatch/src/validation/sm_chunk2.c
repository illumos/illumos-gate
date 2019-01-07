#include "check_debug.h"

void initialize(void *p);

int main(int x)
{
	unsigned int aaa[10];
	int y, z;

	initialize(&aaa);
	initialize(&y);
	initialize(&z);

	if (aaa[5] > 3)
		return 0;
	aaa[0] = 42;
	__smatch_implied(aaa[0]);
	__smatch_implied(aaa[5]);
	aaa[y] = 10;
	__smatch_implied(aaa[5]);
	if (aaa[z] > 4)
		return 0;
	__smatch_implied(aaa[z]);
	z = 3;
	__smatch_implied(aaa[z]);

	return 0;
}

/*
 * check-name: smatch chunk #2
 * check-command: smatch -I.. sm_chunk2.c
 *
 * check-output-start
sm_chunk2.c:17 main() implied: aaa[0] = '42'
sm_chunk2.c:18 main() implied: aaa[5] = '0-3'
sm_chunk2.c:20 main() implied: aaa[5] = '0-u32max'
sm_chunk2.c:23 main() implied: aaa[z] = '0-4'
sm_chunk2.c:25 main() implied: aaa[z] = '0-u32max'
 * check-output-end
 */
