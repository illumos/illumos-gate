/*
 * GNU kludge
 */
#define A(x,...) x,##__VA_ARGS__
A(1)
A(1,2)
A(1,2,3)
/*
 * check-name: Preprocessor #12
 * check-command: sparse -E $file
 *
 * check-output-start

1
1,2
1,2,3
 * check-output-end
 */
