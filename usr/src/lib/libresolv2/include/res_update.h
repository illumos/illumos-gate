/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1999 by Internet Software Consortium, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *	$Id: res_update.h,v 8.1 1999/10/07 08:24:13 vixie Exp $
 */

#ifndef __RES_UPDATE_H
#define __RES_UPDATE_H

#include <sys/types.h>
#include <sys/bitypes.h>
#include <arpa/nameser.h>
#include <isc/list.h>
#include <resolv.h>

#ifdef	ORIGINAL_ISC_CODE
#else
/*
 * ISC changed the ns_updrec structure. However, it's a public interface
 * in Solaris, so it's time to break out that old #define magic.
 */
#define	ns_updrec	__ISC_ns_updrec
#endif	/* ORIGINAL_ISC_CODE */
/*
 * This RR-like structure is particular to UPDATE.
 */
struct ns_updrec {
	LINK(struct ns_updrec) r_link, r_glink;
	ns_sect		r_section;	/* ZONE/PREREQUISITE/UPDATE */
	char *		r_dname;	/* owner of the RR */
	ns_class	r_class;	/* class number */
	ns_type		r_type;		/* type number */
	u_int32_t	r_ttl;		/* time to live */
	u_char *	r_data;		/* rdata fields as text string */
	u_int		r_size;		/* size of r_data field */
	int		r_opcode;	/* type of operation */
	/* following fields for private use by the resolver/server routines */
	struct databuf *r_dp;		/* databuf to process */
	struct databuf *r_deldp;	/* databuf's deleted/overwritten */
	u_int		r_zone;		/* zone number on server */
};
typedef struct ns_updrec ns_updrec;

typedef	LIST(ns_updrec)	ns_updque;

#ifdef	ORIGINAL_ISC_CODE
#define res_mkupdate		__res_mkupdate
#define res_update		__res_update
#define res_mkupdrec		__res_mkupdrec
#define res_freeupdrec		__res_freeupdrec
#define res_nmkupdate		__res_nmkupdate
#define res_nupdate		__res_nupdate
#else
/*
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
#endif	/* ORIGINAL_ISC_CODE */

int		res_mkupdate __P((ns_updrec *, u_char *, int));
int		res_update __P((ns_updrec *));
ns_updrec *	res_mkupdrec __P((int, const char *, u_int, u_int, u_long));
void		res_freeupdrec __P((ns_updrec *));
int		res_nmkupdate __P((res_state, ns_updrec *, u_char *, int));
int		res_nupdate __P((res_state, ns_updrec *, ns_tsig_key *));

#endif /*__RES_UPDATE_H*/
