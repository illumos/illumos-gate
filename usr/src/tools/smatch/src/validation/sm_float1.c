#include "check_debug.h"

float frob(float x)
{
	return x;
}

int main(int argc, char *argv[])
{
	__smatch_implied((long long)frob(3.14));
}

/*
 * check-name: smatch floating point #1
 * check-command: smatch -I.. sm_float1.c
 *
 * check-output-start
sm_float1.c:10 main() implied: frob(3.140000e+00) = '3'
 * check-output-end
 */
