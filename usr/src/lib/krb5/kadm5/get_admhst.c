/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING 
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * $Source: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/lib/kadm5/get_admhst.c,v $
 * $Author: marc $
 *
 * Copyright 1985, 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#ifndef lint
static char *rcsid =
"$Header: /cvs/krbdev/krb5/src/lib/kadm5/get_admhst.c,v 1.8 1996/07/22 20:36:00 marc Exp $";
#endif /* lint */

#include <stdio.h>
#include <krb5/osconf.h>
#include <string.h>

/*
 * Given a Kerberos realm, find a host on which the Kerberos database
 * administration server can be found.
 *
 * krb5_get_admhst takes a pointer to be filled in, a pointer to the name
 * of the realm for which a server is desired, and an integer n, and
 * returns (in h) the nth administrative host entry from the configuration
 * file DEFAULT_CONFIG_FILENAME.
 *
 * If the realm is NULL, the default realm is used.
 *
 * On error, get_admhst returns 0. If all goes well, the routine
 * returns 1.
 *
 * This is a temporary hack to allow us to find the nearest system running
 * a Kerberos admin server.  In the long run, this functionality will be
 * provided by a nameserver.
 */
int
krb5_get_admhst(char *h, char *r, int n)
{
    FILE *cnffile;
    char *realm = NULL;
    char tr[BUFSIZ];
    char linebuf[BUFSIZ];
    char scratch[64];
    register int i;
    int	 ret;

    if(r == NULL) {
	if((ret = krb5_get_default_realm(&realm)) != 0)
	    return ret;
	r = realm;
    }
    if ((cnffile = fopen(DEFAULT_CONFIG_FILENAME, "rF")) == NULL) {
            return(0);
    }
    if (fgets(linebuf, BUFSIZ, cnffile) == NULL) {
	/* error reading */
	(void) fclose(cnffile);
	return(0);
    }
    if (!strchr(linebuf, '\n')) {
	/* didn't all fit into buffer, punt */
	(void) fclose(cnffile);
	if(realm)
	    free(realm);
	return(0);
    }
    for (i = 0; i < n; ) {
	/* run through the file, looking for admin host */
	if (fgets(linebuf, BUFSIZ, cnffile) == NULL) {
            (void) fclose(cnffile);
	    if(realm)
		free(realm);
            return(0);
        }
	/* need to scan for a token after 'admin' to make sure that
	   admin matched correctly */
	if (sscanf(linebuf, "%s %s admin %s", tr, h, scratch) != 3)
	    continue;
        if (!strcmp(tr,r))
            i++;
    }
    (void) fclose(cnffile);
    if(realm)
	free(realm);
    return(1);
}
