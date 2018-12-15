#include "check_debug.h"

void memdup(char *to, int size);
void strcpy(char *dest, char *src);

void func (char *a, char *b)
{
	char c[5];

	a = memdup(b, 5);
	strcpy(c, a);
	a[5] = '\0';
}
/*
 * check-name: smatch memdup overflow
 * check-command: smatch -I.. sm_overflow5.c
 *
 * check-output-start
sm_overflow5.c:12 func() error: buffer overflow 'a' 5 <= 5
 * check-output-end
 */
