#if 0
"\l"
#endif

/*
 * check-description:
 *	Following the C standard, escape conversion must be
 *	done in phase 5, just after preprocessing and just
 *	before string concatenation. So we're not supposed
 *	to receive a diagnostic for an unknown escape char
 *	for a token which is excluded by the preprocessor.
 * check-name: early-escape
 * check-command: sparse -E $file
 *
 * check-output-start


 * check-output-end
 *
 * check-error-start
 * check-error-end
 */
