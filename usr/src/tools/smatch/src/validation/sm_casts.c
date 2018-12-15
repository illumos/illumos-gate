void frob(void);

char c;
static int options_write(void)
{
	char a;
	unsigned char b;

	a = (char)0xff;
	a = 0xff;
	(char)b = 0xff;
	b = 0xff;
	if (c > -400)
		frob();
	if (c < -400)
		frob();
	if (400 > c)
		frob();
	if (-400 > c)
		frob();
	b = -12;

}
/*
 * check-name: smatch cast handling
 * check-command: smatch sm_casts.c
 *
 * check-output-start
sm_casts.c:13 options_write() warn: always true condition '(c > -400) => ((-128)-127 > (-400))'
sm_casts.c:15 options_write() warn: impossible condition '(c < -400) => ((-128)-127 < (-400))'
sm_casts.c:17 options_write() warn: always true condition '(400 > c) => (400 > (-128)-127)'
sm_casts.c:19 options_write() warn: impossible condition '(-400 > c) => ((-400) > (-128)-127)'
sm_casts.c:21 options_write() warn: assigning (-12) to unsigned variable 'b'
 * check-output-end
 */
