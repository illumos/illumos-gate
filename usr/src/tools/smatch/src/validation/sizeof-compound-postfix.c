struct foo {int x, y;};
static int a(void)
{
	return sizeof (struct foo){0,1}.y;
}
/*
 * check-name: Handling of sizeof compound-literal . member
 */
