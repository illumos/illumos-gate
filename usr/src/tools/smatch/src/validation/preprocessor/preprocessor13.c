/*
 * GNU kludge, corner case
 */
#define A(x,...) x##,##__VA_ARGS__
A(1)
A(1,2)
A(1,2,3)
/*
 * check-name: Preprocessor #13
 * check-command: sparse -E $file
 *
 * check-output-start

1
1,2
1,2,3
 * check-output-end
 *
 * check-error-start
preprocessor/preprocessor13.c:6:1: error: '##' failed: concatenation is not a valid token
preprocessor/preprocessor13.c:7:1: error: '##' failed: concatenation is not a valid token
 * check-error-end
 */
