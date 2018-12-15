static char *a = "foobar";	// OK

/*
 * check-name: string literal constness verification.
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
 * check-error-end
 */
