#include "check_debug.h"

struct foo {
	char buf[42];
	int x[4];
};

int function(void)
{
	struct foo foo;

	__smatch_buf_size(&foo);
	__smatch_buf_size(&(foo.buf[0]));
	__smatch_buf_size(&foo.x[0]);
	__smatch_buf_size(&foo.x[1]);

	return 0;
}
/*
 * check-name: smatch buf size #5
 * check-command: smatch --spammy -I.. sm_buf_size5.c
 *
 * check-output-start
sm_buf_size5.c:12 function() buf size: '&foo' 1 elements, 60 bytes
sm_buf_size5.c:13 function() buf size: '&(foo.buf[0])' 42 elements, 42 bytes
sm_buf_size5.c:14 function() buf size: '&foo.x[0]' 4 elements, 16 bytes
sm_buf_size5.c:15 function() buf size: '&foo.x[1]' 3 elements, 12 bytes
 * check-output-end
 */
