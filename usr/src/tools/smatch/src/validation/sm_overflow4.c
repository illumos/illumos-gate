#include "check_debug.h"

void strndup(char *to, int size);
void strcpy(char *dest, char *src);

void func (char *a, char *b)
{
	char c[5];

	a = strndup(b, 5);
	strcpy(c, a);
}
/*
 * check-name: smatch strndup overflow
 * check-command: smatch -I.. sm_overflow4.c
 *
 * check-output-start
sm_overflow4.c:11 func() error: strcpy() 'a' too large for 'c' (6 vs 5)
 * check-output-end
 */
