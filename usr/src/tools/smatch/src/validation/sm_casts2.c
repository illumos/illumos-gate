#include <stdio.h>

unsigned int frob();

unsigned char *a;
unsigned int *b;
int *c;
unsigned char *****d;
int main(void)
{

	if (*a == (unsigned int)-1)
		frob();
	if (*b == (unsigned int)-1)
		frob();
	if (*c == (unsigned int)-1)
		frob();
	if (*d == (unsigned int)-1)
		frob();
	if (*d == -1)
		frob();
	if (*****d == (unsigned int)-1)
		frob();
	return 0;
}
/*
 * check-name: smatch casts pointers
 * check-command: smatch sm_casts2.c
 *
 * check-output-start
sm_casts2.c:12 main() warn: impossible condition '(*a == -1) => (0-255 == u32max)'
sm_casts2.c:22 main() warn: impossible condition '(*****d == -1) => (0-255 == u32max)'
 * check-output-end
 */
