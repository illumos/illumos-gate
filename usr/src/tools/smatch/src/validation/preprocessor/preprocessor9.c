/* Only # in the input stream marks the beginning of preprocessor command,
 * and here we get it from macro expansion.
 */
#define A # define X 1
A
X
/*
 * check-name: Preprocessor #9
 * check-command: sparse -E $file
 *
 * check-output-start

# define X 1
X
 * check-output-end
 */
