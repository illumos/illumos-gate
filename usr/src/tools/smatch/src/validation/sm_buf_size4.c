#include "check_debug.h"

long long a[] = {1, 2};
int b[] = {3, 4};

int main(char *arg0)
{
	short *s = a;

	__smatch_buf_size(a);
	__smatch_buf_size(b);
	__smatch_buf_size(s);
	return 0;
}
/*
 * check-name: smatch buf size #4
 * check-command: smatch -I.. sm_buf_size4.c
 *
 * check-output-start
sm_buf_size4.c:10 main() buf size: 'a' 2 elements, 16 bytes
sm_buf_size4.c:11 main() buf size: 'b' 2 elements, 8 bytes
sm_buf_size4.c:12 main() buf size: 's' 8 elements, 16 bytes
 * check-output-end
 */
