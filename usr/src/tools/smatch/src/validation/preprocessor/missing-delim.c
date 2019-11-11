static int  c = 'a;

static char s[] = "abc;
static char t[] = "xyz";

extern void foo(void);

/*
 * check-name: missing-delim
 * check-command: sparse -E $file
 * check-output-ignore
 *
 * check-error-start
preprocessor/missing-delim.c:2:0: warning: missing terminating ' character
preprocessor/missing-delim.c:4:0: warning: missing terminating " character
 * check-error-end
 */
