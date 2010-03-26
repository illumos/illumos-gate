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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPMGMT_IMPL_H
#define	_IPMGMT_IMPL_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <net/if.h>
#include <libnvpair.h>
#include <libipadm.h>
#include <ipadm_ipmgmt.h>
#include <syslog.h>
#include <pthread.h>

#define	IPMGMT_STRSIZE		256

/* ipmgmt_door.c */
extern void	ipmgmt_handler(void *, char *, size_t, door_desc_t *, uint_t);

/* ipmgmt_util.c */
extern void	ipmgmt_log(int, const char *, ...);

/* ipmgmt_persist.c */

/*
 * following are the list of DB walker callback functions and the callback
 * arguments for each of the callback functions used by the daemon
 */
/* following functions take 'ipmgmt_prop_arg_t' as the callback argument */
extern db_wfunc_t	ipmgmt_db_getprop, ipmgmt_db_resetprop;

/* following functions take ipadm_dbwrite_cbarg_t as callback argument */
extern db_wfunc_t	ipmgmt_db_add, ipmgmt_db_update;

typedef struct {
	char		*cb_ifname;
	ipadm_if_info_t	*cb_ifinfo;
} ipmgmt_getif_cbarg_t;
extern db_wfunc_t	ipmgmt_db_getif;

typedef struct {
	char		*cb_aobjname;
	char		*cb_ifname;
	nvlist_t	*cb_onvl;
	int		cb_ocnt;
} ipmgmt_getaddr_cbarg_t;
extern db_wfunc_t	ipmgmt_db_getaddr;

typedef struct {
	sa_family_t	cb_family;
	char		*cb_ifname;
} ipmgmt_if_cbarg_t;
extern db_wfunc_t	ipmgmt_db_setif, ipmgmt_db_resetif;

typedef struct {
	char		*cb_aobjname;
} ipmgmt_resetaddr_cbarg_t;
extern db_wfunc_t	ipmgmt_db_resetaddr;

typedef struct {
	sa_family_t	cb_family;
	nvlist_t	*cb_invl;
	nvlist_t	*cb_onvl;
	int		cb_ocnt;
} ipmgmt_initif_cbarg_t;
extern db_wfunc_t	ipmgmt_db_initif;

/*
 * A linked list of address object nodes. Each node in the list tracks
 * following information for the address object identified by `am_aobjname'.
 *	- interface on which the address is created
 * 	- logical interface number on which the address is created
 *	- address family
 *	- `am_nextnum' identifies the next number to use to generate user part
 *	  of `aobjname'.
 *	- address type (static, dhcp or addrconf)
 *	- `am_flags' indicates if this addrobj in active and/or persist config
 *	- if `am_atype' is IPADM_ADDR_IPV6_ADDRCONF then `am_ifid' holds the
 *	  interface-id used to configure auto-configured addresses
 */
typedef struct ipmgmt_aobjmap_s {
	struct ipmgmt_aobjmap_s	*am_next;
	char			am_aobjname[IPADM_AOBJSIZ];
	char			am_ifname[LIFNAMSIZ];
	int32_t			am_lnum;
	sa_family_t		am_family;
	ipadm_addr_type_t	am_atype;
	uint32_t		am_nextnum;
	uint32_t		am_flags;
	boolean_t		am_linklocal;
	struct sockaddr_storage	am_ifid;
} ipmgmt_aobjmap_t;

/* linked list of `aobjmap' nodes, protected by RW lock */
typedef struct ipmgmt_aobjmap_list_s {
	ipmgmt_aobjmap_t	*aobjmap_head;
	pthread_rwlock_t	aobjmap_rwlock;
} ipmgmt_aobjmap_list_t;

/* global `aobjmap' defined in ipmgmt_main.c */
extern ipmgmt_aobjmap_list_t aobjmap;

/* operations on the `aobjmap' linked list */
#define	ADDROBJ_ADD		0x00000001
#define	ADDROBJ_DELETE		0x00000002
#define	ADDROBJ_LOOKUPADD	0x00000004

/*
 * A temporary file created in SMF volatile filesystem. This file captures the
 * in-memory copy of list `aobjmap' on disk. This is done to recover from
 * daemon reboot (using svcadm) or crashes.
 */
#define	ADDROBJ_MAPPING_DB_FILE	IPADM_TMPFS_DIR"/aobjmap.conf"

extern int		ipmgmt_db_walk(db_wfunc_t *, void *, ipadm_db_op_t);
extern int		ipmgmt_aobjmap_op(ipmgmt_aobjmap_t *, uint32_t);
extern boolean_t	ipmgmt_aobjmap_init(void *, nvlist_t *, char *,
			    size_t, int *);
extern int 		ipmgmt_persist_aobjmap(ipmgmt_aobjmap_t *,
			    ipadm_db_op_t);

#ifdef  __cplusplus
}
#endif

#endif	/* _IPMGMT_IMPL_H */
