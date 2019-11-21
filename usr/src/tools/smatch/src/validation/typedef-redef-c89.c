typedef int int_t;
typedef int int_t;

/*
 * check-name: typedef-redef-c89
 * check-command: sparse -std=c89 --pedantic $file
 * check-known-to-fail
 *
 * check-error-start
typedef-redef-c89.c:2:13: warning: redefinition of typedef 'int_t'
typedef-redef-c89.c:1:13: info: originally defined here
 * check-error-end
 */
