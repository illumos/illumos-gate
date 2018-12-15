#include "check_debug.h"

int copy_from_user(void *dest, void *src, int size){}

struct my_struct {
	int x, y;
};

void *pointer;
struct my_struct *dest;

struct my_struct *returns_copy(void)
{
	copy_from_user(dest, pointer, sizeof(*dest));
	return dest;
}

struct my_struct *a;
void test(void)
{
	a = returns_copy();
	__smatch_user_rl(a->x);
}

/*
 * check-name: smatch user data #2
 * check-command: smatch -p=kernel -I.. sm_user_data2.c
 *
 * check-output-start
sm_user_data2.c:22 test() user rl: 'a->x' = 's32min-s32max'
 * check-output-end
 */
