#include "check_debug.h"

void memcpy(void *dest, void *src, int size);
void memset(void *dest, char c, int size);


struct foo {
	int x, y;
};

void test(void)
{
	struct foo src = {1, 41};
	struct foo dest;

	memcpy(&dest, &src, sizeof(dest));
	__smatch_implied(dest.x + dest.y);
	memset(&dest, 0, sizeof(dest));
	__smatch_implied(dest.x + dest.y);

}

/*
 * check-name: smatch struct assignment #1
 * check-command: smatch -I.. sm_struct_assign1.c
 *
 * check-output-start
sm_struct_assign1.c:17 test() implied: dest.x + dest.y = '42'
sm_struct_assign1.c:19 test() implied: dest.x + dest.y = '0'
 * check-output-end
 */
