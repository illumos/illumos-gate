#include "check_debug.h"

struct sk_buff {
	unsigned char *head, *data;
	unsigned short network_header;
};

struct foo {
	int a, b, c;
};

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}

static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

int frob(struct sk_buff *skb)
{
	struct foo *p;
	int x, y;

	__smatch_user_rl(*skb->data);
	__smatch_user_rl(skb->data + 1);
	__smatch_user_rl(*(int *)skb->data);
        __smatch_user_rl(skb->data - skb_network_header(skb));

	p = skb->data;
	x = *(int *)skb->data;
	y = skb->data[1];

	__smatch_user_rl(p->a);
	__smatch_user_rl(x);
	__smatch_user_rl(y);

	return 0;
}

/*
 * check-name: smatch: userdata from skb
 * check-command: smatch -p=kernel -I.. sm_skb2.c
 *
 * check-output-start
sm_skb2.c:27 frob() user rl: '*skb->data' = '0-255'
sm_skb2.c:28 frob() user rl: 'skb->data + 1' = ''
sm_skb2.c:29 frob() user rl: '*skb->data' = 's32min-s32max'
sm_skb2.c:30 frob() user rl: 'skb->data - skb_network_header(skb)' = ''
sm_skb2.c:36 frob() user rl: 'p->a' = 's32min-s32max'
sm_skb2.c:37 frob() user rl: 'x' = 's32min-s32max'
sm_skb2.c:38 frob() user rl: 'y' = '0-255'
 * check-output-end
 */
