#include <stdio.h>
#include <string.h>
#include "check_debug.h"

void *kmalloc(int size, int mask);

struct foo {
	int x, y, z;
	int buf[0];
};

int main(void)
{
	struct foo *p;

	p = kmalloc(sizeof(*p) + 100, 0);
	if (!p)
		return -12;
	__smatch_buf_size(p->buf);

	return 0;
}


/*
 * check-name: smatch: overflow check #5
 * check-command: smatch -p=kernel -I.. sm_array_overflow5.c
 *
 * check-output-start
sm_array_overflow5.c:19 main() buf size: 'p->buf' 25 elements, 100 bytes
 * check-output-end
 */
