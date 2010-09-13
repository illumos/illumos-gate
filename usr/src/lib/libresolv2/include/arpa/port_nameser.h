/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ARPA_PORT_NAMESER_H
#define	_ARPA_PORT_NAMESER_H

/*
 * ISC changed the ns_updrec structure. However, it's a public interface
 * in Solaris, so we rename it here and wrap in sunw_updrec.c
 */
#define	ns_updrec	__ISC_ns_updrec


/*
 * Due to the above, the following functions need to be renamed and
 * wrapped in sunw_updrec.c.
 *
 * For BIND 8.2.2, ISC removed the dynamic update functions, and the
 * definition of the ns_updrec structure, from the public include files
 * (<resolv.h>, <arpa/nameser.h>. However, res_update(), res_mkupdate(),
 * and res_mkupdrec() are in the public libresolv interface in Solaris,
 * so we can't easily remove them. Thus, ISC's new versions of res_mkupdate()
 * etc. can't be exposed under their original names.
 *
 * res_nmkupdate() and res_nupdate are new. We could either change them
 * to accept the <arpa/nameser.h> ns_updrec, or leave them unchanged and
 * undocumented. Since ISC may change ns_updrec again, we pick the latter
 * solution for now.
 */
#define	res_mkupdate	__ISC_res_mkupdate
#define	res_update	__ISC_res_update
#define	res_mkupdrec	__ISC_res_mkupdrec
#define	res_freeupdrec	__ISC_res_freeupdrec
#define	res_nmkupdate	__ISC_res_nmkupdate
#define	res_nupdate	__ISC_res_nupdate


#endif /* _ARPA_PORT_NAMESER_H */
