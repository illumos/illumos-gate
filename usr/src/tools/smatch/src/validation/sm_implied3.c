#define NULL ((void *)0)

struct ture {
	int *a;
};

struct ture *b;
struct ture *c;

void func (void)
{
	struct ture *ab;
	int ret = 0;

	if (b) {
		ret = -1;
		goto foo;
	}

	if (c) {}

	ab = some_func();
	if (NULL == ab) {
		ret = -1;
		goto foo;
	}
foo:
	if (ret) {
		return;
	}
	ab->a = 1;
}
/*
 * check-name: Smatch implied #3
 * check-command: smatch sm_implied3.c
 */
