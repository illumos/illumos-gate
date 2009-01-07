/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPMP_MPATHD_H
#define	_IPMP_MPATHD_H

/*
 * Definitions for the messaging protocol between in.mpathd and libipmp.
 * This interface is project-private to the IPMP subsystem.
 */

#include <sys/types.h>
#include <sys/socket.h>		/* needed for <net/if.h> */
#include <net/if.h>		/* needed for LIFNAMSIZ */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MPATHD_PORT	5999
#define	MPATHD_PATH	"/lib/inet/in.mpathd"

/*
 * Supported commands.
 */
enum {
	MI_PING		= 0,	/* ping in.mpathd */
	MI_OFFLINE	= 1,	/* offline the interface */
	MI_UNDO_OFFLINE	= 2,	/* undo the offline */
	MI_QUERY	= 3,	/* query ipmp-related information */
	MI_NCMD			/* total number of commands */
};

/*
 * Types of information which can be requested and received (except for
 * IPMP_IFLIST and IPMP_ADDRLIST, which can only be received).
 */
typedef enum {
	IPMP_GROUPLIST	= 1,
	IPMP_GROUPINFO	= 2,
	IPMP_IFINFO	= 3,
	IPMP_IFLIST	= 4,
	IPMP_SNAP	= 5,
	IPMP_ADDRLIST	= 6,
	IPMP_ADDRINFO	= 7
} ipmp_infotype_t;

/*
 * Daemon ping request.
 */
typedef struct mi_ping {
	uint32_t	mip_command;
} mi_ping_t;

/*
 * Interface offline request; `mio_ifname' is the interface to offline;
 * `mio_min_redundancy' is the minimum amount of usable interfaces after
 * offline that must exist for the operation to succeed.
 */
typedef struct mi_offline {
	uint32_t 	mio_command;
	char		mio_ifname[LIFNAMSIZ];
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
 * Retrieve IPMP-related information: `miq_inforeq' is the type of information
 * being request (see above for the list of types).  If the request type is
 * IPMP_GROUPINFO, then `miq_grname' indicates the group.  If the request type
 * is IPMP_IFINFO, then `miq_ifname' indicates the interface.  If the request
 * type is IPMP_ADDRINFO then `miq_grname' indicates the group and `miq_addr'
 * indicates the address.
 */
typedef struct mi_query {
	uint32_t	miq_command;
	ipmp_infotype_t	miq_inforeq;
	union {
		char	miqu_ifname[LIFNAMSIZ];
		char	miqu_grname[LIFGRNAMSIZ];
	} miq_infodata;
	struct sockaddr_storage	miq_addr;
} mi_query_t;
#define	miq_ifname	miq_infodata.miqu_ifname
#define	miq_grname	miq_infodata.miqu_grname

/*
 * Union of all commands. Can be used to estimate the maximum buffer size
 * requirement for receiving any command.
 */
union mi_commands {
	uint32_t		mi_command;
	mi_ping_t		mi_pcmd;
	mi_offline_t		mi_ocmd;
	mi_undo_offline_t	mi_ucmd;
	mi_query_t		mi_qcmd;
};

/*
 * Result structure returned by in.mpathd.
 */
typedef struct mi_result {
	uint32_t me_sys_error;			/* System error (errno.h) */
	uint32_t me_mpathd_error;		/* Mpathd error */
} mi_result_t;

#define	IPMP_REQTIMEOUT	5			/* seconds */

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
