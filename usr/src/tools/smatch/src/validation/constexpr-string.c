static char *a = "foobar";	// OK

/*
 * check-name: constness of string literal
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
 * check-error-end
 */
