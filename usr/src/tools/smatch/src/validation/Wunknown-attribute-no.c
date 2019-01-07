static int foo(void) __attribute__((unknown_attribute));

/*
 * check-name: warn-unknown-attribute-no
 * check-command: sparse -Wno-unknown-attribute $file
 *
 * check-error-start
 * check-error-end
 */
