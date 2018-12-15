static int foo(void) __attribute__((unknown_attribute));

/*
 * check-name: warn-unknown-attribute-yes
 * check-command: sparse -Wunknown-attribute $file
 *
 * check-error-start
Wunknown-attribute-yes.c:1:37: warning: attribute 'unknown_attribute': unknown attribute
 * check-error-end
 */
