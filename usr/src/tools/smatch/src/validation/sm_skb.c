struct sk_buff {
	int valuable_information;
};
struct foo {
	int x;
};
struct ture {
	struct sk_buff *skb;
};

struct wrap1 {
	struct ture *a;
};
struct wrap2 {
	struct foo *c; 
	struct wrap1 *b;
};
struct wrap3 {
	struct foo *c; 
};

struct sk_buff *skb;
struct sk_buff **ptr;
struct ture *x;
struct ture xx;
struct wrap1 *u;
struct wrap2 *y;
struct wrap3 *z;

void kfree(void *data);

void func (void)
{
	kfree(skb);
	kfree(x->skb);
	kfree(xx.skb);
	kfree(y->c);
	kfree(u->a->skb);
	kfree(u->a);
	kfree(y->b->a->skb);
	kfree(z->c);
	kfree(ptr);
}
/*
 * check-name: kfree_skb() test
 * check-command: smatch -p=kernel sm_skb.c
 *
 * check-output-start
sm_skb.c:34 func() error: use kfree_skb() here instead of kfree(skb)
sm_skb.c:35 func() error: use kfree_skb() here instead of kfree(x->skb)
sm_skb.c:36 func() error: use kfree_skb() here instead of kfree(xx.skb)
sm_skb.c:38 func() error: use kfree_skb() here instead of kfree(u->a->skb)
sm_skb.c:40 func() error: use kfree_skb() here instead of kfree(y->b->a->skb)
 * check-output-end
 */
