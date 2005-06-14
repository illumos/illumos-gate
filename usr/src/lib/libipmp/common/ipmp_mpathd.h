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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPMP_MPATHD_H
#define	_IPMP_MPATHD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for the messaging protocol between in.mpathd and libipmp.
 * This interface is loosely documented in PSARC/2000/306.
 *
 * PLEASE NOTE: Although this interface is officially consolidation-private,
 * we will be reclassifying it as project-private in the future, and
 * transitioning any existing consumers to use higher-level libipmp routines.
 *
 * Put another way: treat this as if it was project-private!
 */

#include <sys/types.h>
#include <sys/socket.h>		/* needed for <net/if.h> */
#include <net/if.h>		/* needed for LIFNAMSIZ */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MPATHD_PORT	5999
#define	MPATHD_PATH	"/usr/lib/inet/in.mpathd"

/*
 * Supported commands.
 */
enum {
	MI_PING		= 0,	/* sanity test */
	MI_OFFLINE	= 1,	/* offline the interface */
	MI_UNDO_OFFLINE	= 2,	/* undo the offline */
	MI_SETOINDEX	= 3,	/* set original interface index */
	MI_QUERY	= 4,	/* query ipmp-related information */
	MI_NCMD			/* total number of commands */
};

/*
 * Types of information which can be requested and received (except for
 * IPMP_IFLIST, which can only be received).
 */
typedef enum {
	IPMP_GROUPLIST	= 1,
	IPMP_GROUPINFO	= 2,
	IPMP_IFINFO	= 3,
	IPMP_IFLIST	= 4,
	IPMP_SNAP	= 5
} ipmp_infotype_t;

/*
 * Interface offline request; `mio_ifname' is the interface to offline;
 * `mio_min_redundancy' is the minimum amount of usable interfaces after
 * offline that must exist for the operation to succeed.
 */
typedef struct mi_offline {
	uint32_t 	mio_command;
	char		mio_ifname[LIFNAMSIZ];
	char		mio_move_to_if[LIFNAMSIZ]; /* currently unused */
	uint32_t	mio_min_redundancy;
} mi_offline_t;

/*
 * Interface undo-offline request; `miu_uname' is the interface to
 * undo-offline.
 */
typedef struct mi_undo_offline {
	uint32_t	miu_command;
	char		miu_ifname[LIFNAMSIZ];
} mi_undo_offline_t;

/*
 * Set original interface index request: `mis_lifname' is the name of the
 * logical interface that is having its index reset; `mis_new_pifname' is the
 * name of the interface whose index will be associated with `mis_lifname';
 * `mis_iftype' is the interface type.
 */
typedef struct mi_setoindex {
	uint32_t	mis_command;
	char		mis_lifname[LIFNAMSIZ];
	char		mis_new_pifname[LIFNAMSIZ];
	uint32_t	mis_iftype;
} mi_setoindex_t;

/*
 * Retrieve IPMP-related information: `miq_inforeq' is the type of information
 * being request (see above for the list of types).  If the request is for
 * either IPMP_GROUPINFO or IPMP_IFINFO, then either `miq_grname' or
 * `miq_ifname' should be set (respectively) to indicate the name of the
 * group or interface to retrieve the information for.
 */
typedef struct mi_query {
	uint32_t	miq_command;
	ipmp_infotype_t	miq_inforeq;
	union {
		char	miqu_ifname[LIFNAMSIZ];
		char	miqu_grname[LIFGRNAMSIZ];
	} miq_infodata;
} mi_query_t;
#define	miq_ifname	miq_infodata.miqu_ifname
#define	miq_grname	miq_infodata.miqu_grname

/*
 * Union of all commands. Can be used to estimate the maximum buffer size
 * requirement for receiving any command.
 */
union mi_commands {
	uint32_t mi_command;
	mi_offline_t		mi_ocmd;
	mi_undo_offline_t	mi_ucmd;
	mi_setoindex_t 		mi_scmd;
	mi_query_t		mi_qcmd;
};

/*
 * Result structure returned by in.mpathd.
 */
typedef struct mi_result {
	uint32_t me_sys_error;			/* System error (errno.h) */
	uint32_t me_mpathd_error;		/* Mpathd error */
} mi_result_t;

/*
 * Legacy values for me_mpathd_error; the daemon now returns the IPMP
 * error codes defined in <ipmp.h>, which are compatible with these error
 * codes.  These will be removed in the future.
 */
enum {
	MPATHD_SUCCESS		= 0,	/* operation succeeded */
	MPATHD_SYS_ERROR	= 1,	/* check me_sys_error for the errno */
	MPATHD_MIN_RED_ERROR	= 2,	/* minimum redundancy not met */
	MPATHD_FAILBACK_DISABLED = 3,	/* failback administratively disabled */
	MPATHD_FAILBACK_PARTIAL = 4	/* unable to completely failback */
};

extern int ipmp_connect(int *);
extern int ipmp_read(int, void *, size_t, const struct timeval *);
extern int ipmp_write(int, const void *, size_t);
extern int ipmp_writetlv(int, ipmp_infotype_t, size_t, void *);
extern int ipmp_readtlv(int, ipmp_infotype_t *, size_t *, void **,
    const struct timeval *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPMP_MPATHD_H */
