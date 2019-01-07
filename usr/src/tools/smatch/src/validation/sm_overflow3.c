#include "check_debug.h"

void strcpy(char *to, char *from, int size);

void func (char *a, char *b)
{
	char c[4];
	char d[4];
	char e[4];
	char f[4];

	b = "1234";
	strcpy(a, b);
	a[5] = '\0';
	strcpy(c, b);
	strcpy(d, "123");
	strcpy(e, "1234");
	strcpy(f, "12");
	f[3] = '\0';
}
/*
 * check-name: smatch strcpy overflow
 * check-command: smatch -I.. sm_overflow3.c
 *
 * check-output-start
sm_overflow3.c:15 func() error: strcpy() 'b' too large for 'c' (5 vs 4)
sm_overflow3.c:17 func() error: strcpy() '"1234"' too large for 'e' (5 vs 4)
 * check-output-end
 */
