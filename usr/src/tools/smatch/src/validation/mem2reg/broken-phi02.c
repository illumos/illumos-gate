int foo(int a, int b)
{
	int x;
	int i;

	if (a)
		i = 0;
	else
		i = 1;

	x = 0;
	if (b)
		x = i;
	return x;
}

/*
 * check-name: broken-phi02
 * check-description:
 *	This is an indirect test to check correctness of phi-node placement.
 *	The misplaced phi-node for 'i' (not at the meet point but where 'i'
 *	is used) causes a missed select-conversion at later stage.
 *
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 * check-output-contains: select\\.
 */
