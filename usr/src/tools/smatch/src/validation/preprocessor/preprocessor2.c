#define TWO a, b

#define UNARY(x) BINARY(x)
#define BINARY(x, y) x + y

UNARY(TWO)
/*
 * check-name: Preprocessor #2
 * check-command: sparse -E $file
 *
 * check-output-start

a + b
 * check-output-end
 */
