#include "check_debug.h"

int copy_from_user(void *dest, void *src, int size);

struct my_struct {
	int x, y;
};

void *pointer;

void copy_stuff(struct my_struct *foo)
{
	copy_from_user(foo, pointer, sizeof(*foo));
}

void test(void)
{
	struct my_struct foo;

	copy_stuff(&foo);
	__smatch_user_rl(foo.x);
}
/*
 * check-name: smatch user data #1
 * check-command: smatch -p=kernel -I.. sm_user_data1.c
 *
 * check-output-start
sm_user_data1.c:21 test() user rl: 'foo.x' = 's32min-s32max'
 * check-output-end
 */
