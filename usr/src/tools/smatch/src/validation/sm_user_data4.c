#include "check_debug.h"

int copy_from_user(void *dest, void *src, int size);

struct ear {
	int x, y;
};

void *src;
int returns_user_data(void)
{
	int x;

	copy_from_user(&x, src, sizeof(int));
	return x;
}

struct ear *dest;
struct ear *returns_user_member(void)
{
	copy_from_user(&dest->x, src, sizeof(int));
	return dest;
}
void test(void)
{
	struct ear *p;
	int x;

	x = returns_user_data();
	__smatch_user_rl(x);
	p = returns_user_member();
	__smatch_user_rl(p);
	__smatch_user_rl(p->x);
}

/*
 * check-name: smatch user data #4
 * check-command: smatch -p=kernel -I.. sm_user_data4.c
 *
 * check-output-start
sm_user_data4.c:30 test() user rl: 'x' = 's32min-s32max'
sm_user_data4.c:32 test() user rl: 'p' = ''
sm_user_data4.c:33 test() user rl: 'p->x' = 's32min-s32max'
 * check-output-end
 */
