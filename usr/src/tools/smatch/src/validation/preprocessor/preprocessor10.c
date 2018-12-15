/* concatenation of 'defi' and 'ned' should result in the same token
 * we would get if we had 'defined' in the input stream.
 */
#define A
#define B defi ## ned
#if B(A)
defined
#else
undefined
#endif
/*
 * check-name: Preprocessor #10
 * check-command: sparse -E $file
 *
 * check-output-start

defined
 * check-output-end
 */
