extern char *strcpy (char *__dest, const char *__src);

static void test_menu_iteminfo( void )
{
		int ansi = 1;
		void *init, *string;
		char initA[]="XYZ";
		char stringA[0x80];
		do {
			if(ansi) {
				string=stringA;
				init = initA;
			}
			if(ansi)
				strcpy( string, init );
		} while( !(ansi = !ansi) );
}
/*
 * check-name: kill-unreachable-phi
 * check-description:
 * 	In wine source tests/menu.c
 * 	Improper killing a phi instruction inside not reachable BB cause
 * 	dead loop on sparse.
 *
 * check-output-ignore
 *
 */
