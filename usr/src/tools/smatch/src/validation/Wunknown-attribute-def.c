static int foo(void) __attribute__((unknown_attribute));

/*
 * check-name: warn-unknown-attribute
 *
 * check-error-start
Wunknown-attribute-def.c:1:37: warning: attribute 'unknown_attribute': unknown attribute
 * check-error-end
 */
