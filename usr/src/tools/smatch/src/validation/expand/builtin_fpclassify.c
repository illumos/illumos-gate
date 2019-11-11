enum { FP_NAN, FP_INF, FP_NOR, FP_SUB, FP_ZERO };

#define	classify(X) __builtin_fpclassify(FP_NAN,FP_INF,FP_NOR,FP_SUB,FP_ZERO,X)

int test(void)
{
	if (classify(__builtin_nan("0")) != FP_NAN)
		return 0;
	if (classify(__builtin_inf("0")) != FP_INF)
		return 0;
	if (classify(1.0) != FP_NOR)
		return 0;
	if (classify(0.0) != FP_ZERO)
		return 0;

	return 1;
}

/*
 * check-name: builtin_fpclassify
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$1
 */
