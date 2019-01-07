#include "check_debug.h"

int copy_from_user(void *dest, void *src, int size){}

struct my_struct {
	int x, y;
};

struct my_struct *returns_filter(struct my_struct *p)
{
	return p;
}

struct my_struct *src, *a, *b;
void test(void)
{
	copy_from_user(a, src, sizeof(*a));
	b = returns_filter(a);
	__smatch_user_rl(b->y);
	b = returns_filter(src);
	__smatch_user_rl(b->y);
	b = returns_filter(a);
	__smatch_user_rl(b->y);
}

/*
 * check-name: smatch user data #3
 * check-command: smatch -p=kernel -I.. sm_user_data3.c
 *
 * check-output-start
sm_user_data3.c:19 test() user rl: 'b->y' = 's32min-s32max'
sm_user_data3.c:21 test() user rl: 'b->y' = ''
sm_user_data3.c:23 test() user rl: 'b->y' = 's32min-s32max'
 * check-output-end
 */
