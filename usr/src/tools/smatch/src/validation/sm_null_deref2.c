int *ptr;
int x, y, z;
void frob(void) {
	if ((y && !ptr) || z)
		return;
	if (ptr) {
		/* in the current version of smatch this erases
		   the old implications.  Later version should 
		   fix this.  --Dec 2 2009 */
		x = *ptr;
	}
	if (!y && ptr)
		*ptr = 0; // smatch used to print an error here.
	if (!y)
		*ptr = 1;
}
/*
 * check-name: Dereferencing Undefined
 * check-command: smatch sm_null_deref2.c
 *
 * check-output-start
sm_null_deref2.c:15 frob() error: we previously assumed 'ptr' could be null (see line 12)
 * check-output-end
 */
