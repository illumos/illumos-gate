#include "check_debug.h"

void memset(void *ptr, char c, int size){}

int copy_to_user(void *dest, void *data, int size){}
int some_func(struct foo *p){}

typedef struct zr364xx_pipeinfo {
	char x;
	int y;
} aa_policy_t;

struct aa_policy {
	int x;
};

struct foo {
	struct aa_policy a;
	int x;
	int y;
};

struct foo *p;
struct foo global_dec;
void *ptr;

int main(void)
{
	struct zr364xx_pipeinfo one;
	struct aa_policy two;
	aa_policy_t three;
	struct foo four;
	struct foo five;
	struct foo six;
	struct foo seven;
	struct foo eight;
	struct foo nine;

	p->a.x = 0;
	global_dec.x = 0;
	memset(&two, 0, sizeof(two));
	four.x = 0;
	six = five;
	some_func(&seven);
	eight.x = (four.x < 5 ? four.x : 5);
	eight.y = !five.y;
	if (some_func()) {
		nine.x = 1;
		nine.y = 2;
	}

	copy_to_user(ptr, &p->a, sizeof(struct aa_policy));
	copy_to_user(ptr, &global_dec, sizeof(global_dec));
	copy_to_user(ptr, &one, sizeof(one));
	copy_to_user(ptr, &two, sizeof(two));
	copy_to_user(ptr, &three, sizeof(three));
	copy_to_user(ptr, &four, sizeof(four));
	copy_to_user(ptr, &five, sizeof(five));
	copy_to_user(ptr, &six, sizeof(six));
	copy_to_user(ptr, &seven, sizeof(seven));
	copy_to_user(ptr, &eight, sizeof(eight));
	copy_to_user(ptr, &nine, sizeof(nine));
	return 0;
}
/*
 * check-name: Rosenberg Leaks
 * check-command: smatch -p=kernel -I.. sm_rosenberg.c
 *
 * check-output-start
sm_rosenberg.c:54 main() warn: check that 'one' doesn't leak information (struct has a hole after 'x')
sm_rosenberg.c:56 main() warn: check that 'three' doesn't leak information (struct has a hole after 'x')
sm_rosenberg.c:57 main() warn: check that 'four.y' doesn't leak information
sm_rosenberg.c:62 main() warn: check that 'nine.x' doesn't leak information
 * check-output-end
 */
