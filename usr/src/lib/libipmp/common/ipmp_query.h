/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_QUERY_H
#define	_IPMP_QUERY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>			/* needed by <net/if.h> */
#include <net/if.h>			/* for LIF*NAMSIZ */
#include <ipmp.h>

/*
 * IPMP query interfaces.
 *
 * These interfaces may only be used within ON or after signing a contract
 * with ON.  For documentation, refer to PSARC/2002/615.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Data type describing a list of IPMP groups.
 */
typedef struct ipmp_grouplist {
	uint64_t	gl_sig;
	unsigned int	gl_ngroup;
	char		gl_groups[1][LIFGRNAMSIZ];
} ipmp_grouplist_t;

#define	IPMP_GROUPLIST_MINSIZE	(sizeof (ipmp_grouplist_t) - LIFGRNAMSIZ)
#define	IPMP_GROUPLIST_SIZE(ngr) (IPMP_GROUPLIST_MINSIZE + (ngr) * LIFGRNAMSIZ)

/*
 * Data type describing a list of interfaces.
 */
typedef struct ipmp_iflist {
	unsigned int	il_nif;
	char		il_ifs[1][LIFNAMSIZ];
} ipmp_iflist_t;

#define	IPMP_IFLIST_MINSIZE	(sizeof (ipmp_iflist_t) - LIFNAMSIZ)
#define	IPMP_IFLIST_SIZE(nif)	(IPMP_IFLIST_MINSIZE + (nif) * LIFNAMSIZ)

/*
 * Data type describing the state of an IPMP group.
 */
typedef struct ipmp_groupinfo {
	char			gr_name[LIFGRNAMSIZ];
	uint64_t		gr_sig;
	ipmp_group_state_t	gr_state;
	ipmp_iflist_t		*gr_iflistp;
} ipmp_groupinfo_t;

/*
 * Data type describing the IPMP-related state of an interface.
 */
typedef struct ipmp_ifinfo {
	char		if_name[LIFNAMSIZ];
	char		if_group[LIFGRNAMSIZ];
	ipmp_if_state_t	if_state;
	ipmp_if_type_t	if_type;
} ipmp_ifinfo_t;

typedef enum {
	IPMP_QCONTEXT_LIVE,
	IPMP_QCONTEXT_SNAP
} ipmp_qcontext_t;

extern int  ipmp_setqcontext(ipmp_handle_t, ipmp_qcontext_t);
extern int  ipmp_getgrouplist(ipmp_handle_t, ipmp_grouplist_t **);
extern void ipmp_freegrouplist(ipmp_grouplist_t *);
extern int  ipmp_getgroupinfo(ipmp_handle_t, const char *, ipmp_groupinfo_t **);
extern void ipmp_freegroupinfo(ipmp_groupinfo_t *);
extern int  ipmp_getifinfo(ipmp_handle_t, const char *, ipmp_ifinfo_t **);
extern void ipmp_freeifinfo(ipmp_ifinfo_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_QUERY_H */
