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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header: /cvs/krbdev/krb5/src/lib/kadm5/srv/adb_free.c,v 1.3 2000/06/01 02:02:03 tritan Exp $
 * 
 * $Log: adb_free.c,v $
 * Revision 1.3  2000/06/01 02:02:03  tritan
 * Check for existance of <memory.h>.
 * (from Nathan Neulinger <nneul@umr.edu>)
 *
 * Revision 1.2  1996/10/18 19:45:49  bjaspan
 * 	* svr_misc_free.c, server_dict.c, adb_policy.c, adb_free.c:
 *  	include stdlib.h instead of malloc.h [krb5-admin/35]
 *
 * Revision 1.1  1996/07/24 22:23:09  tlyu
 * 	* Makefile.in, configure.in: break out server lib into a
 * 		subdirectory
 *
 * Revision 1.8  1996/07/22 20:35:16  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.7.4.1  1996/07/18 03:08:07  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.7.2.1  1996/06/20  02:16:25  marc
 * File added to the repository on a branch
 *
 * Revision 1.7  1996/05/12  06:21:57  marc
 * don't use <absolute paths> for "internal header files"
 *
 * Revision 1.6  1993/12/13  21:15:56  shanzer
 * fixed memory leak
 * .,
 *
 * Revision 1.5  1993/12/06  22:20:37  marc
 * fixup free functions to use xdr to free the underlying struct
 *
 * Revision 1.4  1993/11/15  00:29:46  shanzer
 * check to make sure pointers are somewhat vaid before freeing.
 *
 * Revision 1.3  1993/11/09  04:02:24  shanzer
 * added some includefiles
 * changed bzero to memset
 *
 * Revision 1.2  1993/11/04  01:54:24  shanzer
 * added rcs header ..
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header: /cvs/krbdev/krb5/src/lib/kadm5/srv/adb_free.c,v 1.3 2000/06/01 02:02:03 tritan Exp $";
#endif

#include	"adb.h"
#ifdef HAVE_MEMORY_H
#include	<memory.h>
#endif
#include	<stdlib.h>

void
osa_free_princ_ent(osa_princ_ent_t val)
{
    XDR xdrs;

    xdrmem_create(&xdrs, NULL, 0, XDR_FREE);

    xdr_osa_princ_ent_rec(&xdrs, val);
    free(val);
}

void
osa_free_policy_ent(osa_policy_ent_t val)
{
    XDR xdrs;

    xdrmem_create(&xdrs, NULL, 0, XDR_FREE);

    xdr_osa_policy_ent_rec(&xdrs, val);
    free(val);
}

