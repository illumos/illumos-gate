int foo(int **a);
int foo(int **a)
{
	return **a;
}

/*
 * check-name: missing instruction's size
 * check-description:
 *	sparse used to have a problem with *all*
 *	double dereferencing due to missing a
 *	call to examine_symbol_type(). The symptom
 *	here is that the inner deref had no type.
 * check-command: test-linearize $file
 * check-output-ignore
 *
 * check-output-excludes: load\\s
 * check-output-contains: load\\.
 */
