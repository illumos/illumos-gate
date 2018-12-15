/*
 * Al Viro points out that we don't
 * do bitfield -> integer promotions
 * for array dereferences
 *
 * "warning: a.c:16:10: incompatible types for operation"
 */
static struct {
	int x:4;
} y;

extern int a[];

static int b(void)
{
	return a[y.x];
}

/*
 * check-name: bitfield to integer promotion
 */
