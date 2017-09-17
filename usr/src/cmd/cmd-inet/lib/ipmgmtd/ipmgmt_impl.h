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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
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
#include <libscf.h>

#define	IPMGMT_STRSIZE		256
#define	IPMGMTD_FMRI		"svc:/network/ip-interface-management:default"

/* ipmgmt_door.c */
extern void	ipmgmt_handler(void *, char *, size_t, door_desc_t *, uint_t);

/* ipmgmt_util.c */
extern void	ipmgmt_log(int, const char *, ...);
extern int	ipmgmt_cpfile(const char *, const char *, boolean_t);

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
 *	- other, ipadm_addr_type_t-specific values are cached in
 *	  am_addr_cache (see type ipmgmt_addr_cache_u):
 *	  -	ipv6: ipmgmt_am_linklocal (macro)
 *	  -	ipv6: ipmgmt_am_ifid (macro)
 *	  -	dhcp: ipmgmt_am_reqhost (macro)
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
	ipmgmt_addr_type_cache_u	am_atype_cache;
} ipmgmt_aobjmap_t;

#define	ipmgmt_am_linklocal \
    am_atype_cache.ipmgmt_ipv6_cache_s.ipmgmt_linklocal
#define	ipmgmt_am_ifid \
    am_atype_cache.ipmgmt_ipv6_cache_s.ipmgmt_ifid
#define	ipmgmt_am_reqhost \
    am_atype_cache.ipmgmt_dhcp_cache_s.ipmgmt_reqhost

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
#define	ADDROBJ_SETLIFNUM	0x00000008

/* Permanent data store for ipadm */
#define	IPADM_DB_FILE		"/etc/ipadm/ipadm.conf"
#define	IPADM_FILE_MODE		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/*
 * With the initial integration of the daemon (PSARC 2010/080), the version
 * of the ipadm data-store (/etc/ipadm/ipadm.conf) was 0. A subsequent fix
 * needed an upgrade to the data-store and we bumped the version to 1.
 */
#define	IPADM_DB_VERSION	1

/*
 * A temporary file created in SMF volatile filesystem. This file captures the
 * in-memory copy of list `aobjmap' on disk. This is done to recover from
 * daemon reboot (using svcadm) or crashes.
 */
#define	IPADM_TMPFS_DIR		"/etc/svc/volatile/ipadm"
#define	ADDROBJ_MAPPING_DB_FILE	IPADM_TMPFS_DIR"/aobjmap.conf"

/*
 * A temporary copy of the ipadm configuration file might need
 * to be created if write requests are encountered during boottime
 * and the root filesystem is mounted read-only.
 */
#define	IPADM_VOL_DB_FILE	IPADM_TMPFS_DIR"/ipadm.conf"

/* SCF resources required to interact with svc.configd */
typedef struct scf_resources {
	scf_handle_t		*sr_handle;
	scf_instance_t		*sr_inst;
	scf_propertygroup_t	*sr_pg;
	scf_property_t		*sr_prop;
	scf_value_t		*sr_val;
	scf_transaction_t	*sr_tx;
	scf_transaction_entry_t	*sr_ent;
} scf_resources_t;

extern int		ipmgmt_db_walk(db_wfunc_t *, void *, ipadm_db_op_t);
extern int		ipmgmt_aobjmap_op(ipmgmt_aobjmap_t *, uint32_t);
extern boolean_t	ipmgmt_aobjmap_init(void *, nvlist_t *, char *,
			    size_t, int *);
extern int 		ipmgmt_persist_aobjmap(ipmgmt_aobjmap_t *,
			    ipadm_db_op_t);
extern boolean_t	ipmgmt_ngz_firstboot_postinstall();
extern int		ipmgmt_persist_if(ipmgmt_if_arg_t *);
extern void		ipmgmt_init_prop();
extern boolean_t	ipmgmt_db_upgrade(void *, nvlist_t *, char *,
			    size_t, int *);
extern int		ipmgmt_create_scf_resources(const char *,
			    scf_resources_t *);
extern void		ipmgmt_release_scf_resources(scf_resources_t *);
extern boolean_t	ipmgmt_needs_upgrade(scf_resources_t *);
extern void		ipmgmt_update_dbver(scf_resources_t *);

#ifdef  __cplusplus
}
#endif

#endif	/* _IPMGMT_IMPL_H */
