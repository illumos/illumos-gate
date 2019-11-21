
extern int myfunction(void);

extern int myfunction(void) { return 0; }

/*
 * check-name: external-function-has-definition
 * check-command: sparse -Wno-external-function-has-definition $file
 *
 * check-error-start
 * check-error-end
 */
