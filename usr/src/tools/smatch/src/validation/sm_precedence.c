struct foo {
	unsigned int x:1;
};

int frob();
int a,b,c,d, x, y;
struct foo *z;
static int options_write(void)
{
	if (x & y == 0)
		frob();
	if (x | y == 0)
		frob();
	if (a == b & c == d)
		frob();
	if (a == c == d)
		frob();
	if (!a == b)
		frob();
	c = !a & b;
	if (x + y == 0)
		frob();
	if (!a == !b)
		frob();
	if (!a == z->x)
		frob();
	if (!!a == b)
		frob();

}
/*
 * check-name: Smatch precedence check
 * check-command: smatch sm_precedence.c
 *
 * check-output-start
sm_precedence.c:10 options_write() warn: add some parenthesis here?
sm_precedence.c:12 options_write() warn: add some parenthesis here?
sm_precedence.c:14 options_write() warn: add some parenthesis here?
sm_precedence.c:16 options_write() warn: add some parenthesis here?
sm_precedence.c:18 options_write() warn: add some parenthesis here?
sm_precedence.c:20 options_write() warn: add some parenthesis here?
 * check-output-end
 */
