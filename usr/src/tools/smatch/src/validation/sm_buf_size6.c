#include "check_debug.h"

void *malloc(int size);

int function(void)
{
	int *p;
	int array[1000];

	p = malloc(4000);

	__smatch_buf_size(p);
	__smatch_buf_size(&p[0]);
	__smatch_buf_size(array);
	__smatch_buf_size(&array);
	__smatch_buf_size(&array[0]);

	return 0;
}
/*
 * check-name: smatch buf size #6
 * check-command: smatch --spammy -I.. sm_buf_size6.c
 *
 * check-output-start
sm_buf_size6.c:12 function() buf size: 'p' 1000 elements, 4000 bytes
sm_buf_size6.c:13 function() buf size: '&p[0]' 1000 elements, 4000 bytes
sm_buf_size6.c:14 function() buf size: 'array' 1000 elements, 4000 bytes
sm_buf_size6.c:15 function() buf size: '&array' 1000 elements, 4000 bytes
sm_buf_size6.c:16 function() buf size: '&array[0]' 1000 elements, 4000 bytes
 * check-output-end
 */
