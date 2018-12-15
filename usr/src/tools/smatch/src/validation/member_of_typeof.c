static struct foo {int x;} v;
static typeof(v) *p;
static void bar(void)
{
	p->x = 0;
}
/*
 * check-name: Expansion of typeof when dealing with member of struct
 * check-description: Used to expand SYM_TYPEOF too late
 */
