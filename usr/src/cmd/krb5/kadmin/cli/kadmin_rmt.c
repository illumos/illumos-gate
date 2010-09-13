/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Contains remote client specific code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <k5-int.h>
#include <krb5.h>

extern void *handle;

void
usage(char *whoami)
{
	fprintf(stderr,
	    "%s: %s [-r realm] [-p principal] [-q query] "
	    "[-s admin_server[:port]] [[-c ccache]|[-k [-t keytab]]"
	    "|[-w password]]\n",
	    gettext("Usage"), whoami);
	exit(1);
}


/*
 * Debugging function - for remote admin client
 */
/* ARGSUSED */
void
debugEnable(int displayMsgs)
{

#ifdef DEBUG
	/* Solaris Kerberos: not supported */
	/* debugDisplaySS(displayMsgs); */
#endif
}

void
kadmin_getprivs(argc, argv)
    int argc;
    char *argv[];
{
    static char *privs[] = {"GET", "ADD", "MODIFY", "DELETE", "LIST", "CHANGE"};
    krb5_error_code retval;
    int i;
    long plist;

    if (argc != 1) {
	fprintf(stderr, "%s: get_privs\n", gettext("usage"));
	return;
    }
    retval = kadm5_get_privs(handle, &plist);
    if (retval) {
	com_err("get_privs", retval,
		    gettext("while retrieving privileges"));
	return;
    }
    printf(gettext("current privileges:"));
    for (i = 0; i < sizeof (privs) / sizeof (char *); i++) {
	if (plist & 1 << i)
	    printf(" %s", gettext(privs[i]));
    }
    printf("\n");
}
