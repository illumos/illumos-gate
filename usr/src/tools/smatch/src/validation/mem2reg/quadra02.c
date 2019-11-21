#include "repeat.h"

#define	PAT(X)	int a##X = X;
static void foo(void)
{
	REPEAT2(12, PAT)
}

/*
 * check-name: quadratic vars
 * check-command: test-linearize -I. $file
 * check-timeout:
 *
 * check-output-ignore
 * check-output-excludes: phi\\.
 * check-output-excludes: phisrc\\.
 * check-output-excludes: store\\.
 */
