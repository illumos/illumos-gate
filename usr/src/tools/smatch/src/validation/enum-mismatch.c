enum ea { A = 0, };
enum eb { B = 1, };


static enum eb foo(enum ea a)
{
	return a;
}

/*
 * check-name: enum-mismatch
 * check-command: sparse -Wenum-mismatch $file
 *
 * check-error-start
enum-mismatch.c:7:16: warning: mixing different enum types
enum-mismatch.c:7:16:     unsigned int enum ea versus
enum-mismatch.c:7:16:     unsigned int enum eb
 * check-error-end
 */
