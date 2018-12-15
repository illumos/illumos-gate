
extern void myfunction(void);

extern void
myfunction(void)
{
	return;
}

/*
 * check-name: -Wno-external-function-has-definition works
 * check-command: sparse -Wno-external-function-has-definition
 * check-error-start
 * check-error-end
 */
