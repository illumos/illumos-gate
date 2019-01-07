/* one warning for each, please... */
#define 1
#undef 1
/*
 * check-name: Preprocessor #18
 * check-command: sparse -E $file
 *
 * check-output-start


 * check-output-end
 *
 * check-error-start
preprocessor/preprocessor18.c:2:2: error: expected identifier to 'define'
preprocessor/preprocessor18.c:3:2: error: expected identifier to 'undef'
 * check-error-end
 */
