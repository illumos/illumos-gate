#include "check_debug.h"

int strlen(char *buf);
void strcpy(char *dest, char *src);
int snprintf(char *dest, int limit, char *format, char *str);
int sprintf(char *dest, char *format, char *str);

char *str;

int main(void)
{
	char buf[10];
	char buf1[10];

	if (strlen(str) > 11)
		return;
	snprintf(buf, 11, "%s", str);
	sprintf(buf1, "%s", str);
}
/*
 * check-name: smatch overflow #6
 * check-command: smatch -I.. sm_overflow6.c
 *
 * check-output-start
sm_overflow6.c:17 main() error: snprintf() is printing too much 11 vs 10
sm_overflow6.c:17 main() error: snprintf() chops off the last chars of 'str': 12 vs 11
sm_overflow6.c:18 main() error: sprintf() copies too much data from 'str': 12 vs 10
 * check-output-end
 */
