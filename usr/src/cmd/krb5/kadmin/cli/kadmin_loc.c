/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains kadmin.local specific code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <db.h>
#include <krb5.h>


void
usage(char *whoami)
{
	fprintf(stderr,
	    "%s: %s [-r realm] [-p principal] [-q query] "
	    "[-d dbname] [-e \"enc:salt ...\"] [-m] [-D]\n",
	    gettext("Usage"), whoami);
	exit(1);
}


/*
 * Debugging function
 * Turns on low level debugging in db module
 * Requires that db library be compiled with -DDEBUG_DB flag
 */
/* ARGSUSED */
void
debugEnable(int displayMsgs)
{

#if DEBUG_DB
	debugDisplayDB(displayMsgs);
#endif

#if DEBUG
	/* Solaris Kerberos: not supported */
	/* debugDisplaySS(displayMsgs); */
#endif

}

void
kadmin_getprivs(argc, argv)
int argc;
char *argv[];
{
    static char *privs[] = {"GET", "ADD", "MODIFY", "DELETE", "LIST",
			    "CHANGEPW"};
	krb5_error_code retval;
	int i;
	long plist;

/*  for kadmin.local return all privilages  */

	printf(gettext("current privileges:"));
	for (i = 0; i < sizeof (privs) / 4; i++) {
		printf(" %s", gettext(privs[i]));
	}
	printf("\n");
}
