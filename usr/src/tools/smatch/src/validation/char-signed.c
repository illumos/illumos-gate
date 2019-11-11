void foo(void)
{
	_Static_assert((char) -1 == -1, "plain char is not signed");
}

/*
 * check-name: fsigned-char
 * check-command: sparse -fsigned-char -Wno-decl $file
 */
