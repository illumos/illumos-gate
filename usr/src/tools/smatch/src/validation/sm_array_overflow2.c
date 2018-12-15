#include <stdio.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

int a[] = {1, 2, 3, 4};
int b[] = {
	[3] = 1,
};

int x;
int main(void)
{
	if (x < ARRAY_SIZE(a))
		a[x] = 1;
	if (x < ARRAY_SIZE(b))
		b[x] = 1;
	if (x < ARRAY_SIZE(b))
		b[4] = 1;
	printf("%d\n", ARRAY_SIZE(b));
}
/*
 * check-name: smatch indexed array check
 * check-command: smatch sm_array_overflow2.c
 *
 * check-output-start
sm_array_overflow2.c:18 main() error: buffer overflow 'b' 4 <= 4
 * check-output-end
 */
