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
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VNET_H
#define	_VNET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	VNET_SUCCESS		(0)	/* successful return */
#define	VNET_FAILURE		(-1)	/* unsuccessful return */

#define	KMEM_FREE(_p)		kmem_free((_p), sizeof (*(_p)))

#define	VNET_NTXDS		512		/* power of 2 tx descriptors */
#define	VNET_LDCWD_INTERVAL	1000		/* watchdog freq in msec */
#define	VNET_LDCWD_TXTIMEOUT	1000		/* tx timeout in msec */
#define	VNET_LDC_MTU		64		/* ldc mtu */

/*
 * vnet proxy transport layer information. There is one instance of this for
 * every transport being used by a vnet device and a list of these transports
 * is maintained by vnet.
 */
typedef struct vp_tl {
	struct vp_tl		*nextp;			/* next in list */
	mac_register_t		*macp;			/* transport ops */
	char			name[LIFNAMSIZ];	/* device name */
	major_t			major;			/* driver major # */
	uint_t			instance;		/* dev instance */
} vp_tl_t;

/*
 * Forwarding database (FDB) entry, used by vnet to provide switching
 * functionality. Each fdb entry corresponds to a destination vnet device
 * within the ldoms which is directly reachable by invoking a transmit
 * function provided by a vnet proxy transport layer. Currently, the generic
 * transport layer adds/removes/modifies entries in fdb.
 */
typedef struct fdb {
	struct fdb	*nextp;			/* next entry in the list */
	uint8_t		macaddr[ETHERADDRL];	/* destination mac address */
	mac_tx_t	m_tx;			/* transmit function */
	void		*txarg;			/* arg to the transmit func */
} fdb_t;

/* FDB hash queue head */
typedef struct fdbf_s {
	fdb_t		*headp;			/* head of fdb entries */
	krwlock_t	rwlock;			/* protect the list */
} fdb_fanout_t;

#define	VNET_NFDB_HASH		64	/* default no. of hash queues in fdb */
#define	VNET_NFDB_HASH_MAX	128	/* max number of hash queues in fdb */

/* Hash calculation using the mac address */
#define	MACHASH(a, n)	((*(((uchar_t *)(a)) + 0) ^		\
			*(((uchar_t *)(a)) + 1) ^		\
			*(((uchar_t *)(a)) + 2) ^		\
			*(((uchar_t *)(a)) + 3) ^		\
			*(((uchar_t *)(a)) + 4) ^		\
			*(((uchar_t *)(a)) + 5)) % (uint32_t)n)

/* rwlock macros */
#define	READ_ENTER(x)	rw_enter(x, RW_READER)
#define	WRITE_ENTER(x)	rw_enter(x, RW_WRITER)
#define	RW_EXIT(x)	rw_exit(x)

/*
 * vnet instance state information
 */
typedef struct vnet {
	int			instance;	/* instance # */
	dev_info_t		*dip;		/* dev_info */
	struct vnet		*nextp;		/* next in list */
	mac_handle_t 		mh;		/* handle to GLDv3 mac module */
	uchar_t			vendor_addr[ETHERADDRL]; /* orig macadr */
	uchar_t			curr_macaddr[ETHERADDRL]; /* current macadr */
	vp_tl_t			*tlp;		/* list of vp_tl */
	krwlock_t		trwlock;	/* lock for vp_tl list */
	char			vgen_name[MAXNAMELEN];	/* name of generic tl */
	fdb_fanout_t		*fdbhp;		/* fdb hash queues */
	int			nfdb_hash;	/* num fdb hash queues */
} vnet_t;



#ifdef DEBUG
/*
 * debug levels:
 * DBG_LEVEL1:	Function entry/exit tracing
 * DBG_LEVEL2:	Info messages
 * DBG_LEVEL3:	Warning messages
 * DBG_LEVEL4:	Error messages
 */

enum	{ DBG_LEVEL1 = 0x01, DBG_LEVEL2 = 0x02, DBG_WARN = 0x04,
	    DBG_ERR = 0x08 };

#define	DBG1(...)	do {						\
			    if ((vnet_dbglevel & DBG_LEVEL1) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DBG2(...)	do {						\
			    if ((vnet_dbglevel & DBG_LEVEL2) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DWARN(...)	do {						\
			    if ((vnet_dbglevel & DBG_WARN) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#define	DERR(...)	do {						\
			    if ((vnet_dbglevel & DBG_ERR) != 0) {	\
				debug_printf(__func__, __VA_ARGS__);	\
			    }						\
			_NOTE(CONSTCOND) } while (0)

#else

#define	DBG1(...)	if (0)	do { } while (0)
#define	DBG2(...)	if (0)	do { } while (0)
#define	DWARN(...)	if (0)	do { } while (0)
#define	DERR(...)	if (0)	do { } while (0)

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_H */
