/*
 *  Each comment should be treated as if it had been a single space.
 */

/* This should give nothing */
#define X /*
 */ Y

/*
 * check-name: phase3-comments
 * check-command: sparse -E $file
 *
 * check-output-start


 * check-output-end
 */
