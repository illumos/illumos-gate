#include "check_debug.h"

int strlen(const char *str);
int strnlen(const char *str, int limit);

int func(void)
{
	__smatch_implied(strlen("foo"));
	__smatch_implied(strnlen("foo", 2));
}

/*
 * check-name: Smatch strlen test #3
 * check-command: smatch -I.. sm_strlen3.c
 *
 * check-output-start
sm_strlen3.c:8 func() implied: strlen("foo") = '3'
sm_strlen3.c:9 func() implied: strnlen("foo", 2) = '2'
 * check-output-end
 */
