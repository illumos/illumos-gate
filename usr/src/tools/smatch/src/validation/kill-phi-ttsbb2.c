extern int error(int);

int foo(int perr);
int foo(int perr)
{
	int err = 0;
	int rc = 0;
	int j = 0;
	int i = 1;

	i && j++;

	i-- && j;

	i && j--;

	if (j != 1) {
		err = 1;
		if (perr)
			error(1);
	}

	if (err != 0)
		rc = 1;

	return rc;
}

/*
 * check-name: kill-phi-ttsbb2
 * check-description:
 *	Verify if OP_PHI usage is adjusted after successful try_to_simplify_bb()
 * check-warning: this test is sensitive to details of code generation
 *                with proper bb packing (taking care of phi-nodes) it
 *		  will be optimized away and test nothing. You have been warned.
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: VOID
 */
