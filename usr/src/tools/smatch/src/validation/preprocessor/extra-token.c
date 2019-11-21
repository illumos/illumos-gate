#define THIS 0
#ifdef THIS == 1
#endif

/*
 * check-name: preprocessor/extra-token.c
 * check-command: sparse -E $file
 * check-known-to-fail
 *
 * check-error-start
preprocessor/extra-token.c:2:13: warning: extra tokens at end of #ifdef directive
 * check-error-end
 *
 * check-output-ignore
 */
