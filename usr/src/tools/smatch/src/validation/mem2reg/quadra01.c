#include "repeat.h"

void use(void *, void *, void *, void *);
void *def(void);

#define BLOCK(n) {				\
	void *label;				\
	use(&&w##n, &&x##n, &&y##n, &&z##n);	\
w##n:	label = def(); goto *label;		\
x##n:	label = def(); goto *label;		\
y##n:	label = def(); goto *label;		\
z##n:	label = def(); goto *label;		\
}

static void foo(void) {
	REPEAT2(5, BLOCK)
}

/*
 * check-name: quadratic @ liveness
 * check-command: test-linearize -I. $file
 * check-timeout:
 *
 * check-output-ignore
 * check-output-excludes: phi\\.
 * check-output-excludes: phisrc\\.
 */
