int foo(int a, int b)
{
	int x;
	int i;

	switch (a) {
	case  0: i = 0; break;
	case  1: i = 1; break;
	default: i = -1; break;
	}

	x = 0;
	if (b)
		x = i;
	return x;
}

/*
 * check-name: broken-phi03
 * check-description:
 *	This is an indirect test to check correctness of phi-node placement.
 *	The misplaced phi-node for 'i' (not at the meet point but where 'i'
 *	is used) causes a missed select-conversion at later stage.
 *
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 * check-output-contains: select\\.
 */
