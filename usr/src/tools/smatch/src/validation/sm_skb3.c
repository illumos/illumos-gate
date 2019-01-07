#include "check_debug.h"

struct sk_buff {
	unsigned char *head, *data;
	unsigned short network_header;
};

struct foo {
	int a, b, c;
};

int frob(struct sk_buff *skb)
{
	struct foo *p;

	p = skb->data + sizeof(int) * 2;
	__smatch_user_rl(p->a);

	return 0;
}

/*
 * check-name: smatch: userdata from skb #3
 * check-command: smatch -p=kernel -I.. sm_skb3.c
 *
 * check-output-start
sm_skb3.c:17 frob() user rl: 'p->a' = 's32min-s32max'
 * check-output-end
 */
