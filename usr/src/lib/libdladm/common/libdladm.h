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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#include <sys/dls_mgmt.h>
#include <sys/dld.h>
#include <sys/dlpi.h>
#include <libnvpair.h>

/*
 * This file includes structures, macros and common routines shared by all
 * data-link administration, and routines which do not directly administrate
 * links. For example, dladm_status2str().
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	LINKID_STR_WIDTH	10
#define	DLADM_STRSIZE		256

/*
 * option flags taken by the libdladm functions
 *
 *  - DLADM_OPT_ACTIVE:
 *    The function requests to bringup some configuration that only take
 *    effect on active system (not persistent).
 *
 *  - DLADM_OPT_PERSIST:
 *    The function requests to persist some configuration.
 *
 *  - DLADM_OPT_CREATE:
 *    Today, only used by dladm_set_secobj() - requests to create a secobj.
 *
 *  - DLADM_OPT_FORCE:
 *    The function requests to execute a specific operation forcefully.
 *
 *  - DLADM_OPT_PREFIX:
 *    The function requests to generate a link name using the specified prefix.
 *
 *  - DLADM_OPT_VLAN:
 *    Signifies VLAN creation code path
 *
 *  - DLADM_OPT_NOREFRESH:
 *    Do not refresh the daemon after setting parameter (used by STP mcheck).
 *
 *  - DLADM_OPT_BOOT:
 *    Bypass check functions during boot (used by pool property since pools
 *    can come up after link properties are set)
 */
#define	DLADM_OPT_ACTIVE	0x00000001
#define	DLADM_OPT_PERSIST	0x00000002
#define	DLADM_OPT_CREATE	0x00000004
#define	DLADM_OPT_FORCE		0x00000008
#define	DLADM_OPT_PREFIX	0x00000010
#define	DLADM_OPT_ANCHOR	0x00000020
#define	DLADM_OPT_VLAN		0x00000040
#define	DLADM_OPT_NOREFRESH	0x00000080
#define	DLADM_OPT_BOOT		0x00000100

#define	DLADM_WALK_TERMINATE	0
#define	DLADM_WALK_CONTINUE	-1

#define	DLADM_MAX_ARG_CNT	32
#define	DLADM_MAX_ARG_VALS	64

typedef enum {
	DLADM_STATUS_OK = 0,
	DLADM_STATUS_BADARG,
	DLADM_STATUS_FAILED,
	DLADM_STATUS_TOOSMALL,
	DLADM_STATUS_NOTSUP,
	DLADM_STATUS_NOTFOUND,
	DLADM_STATUS_BADVAL,
	DLADM_STATUS_NOMEM,
	DLADM_STATUS_EXIST,
	DLADM_STATUS_LINKINVAL,
	DLADM_STATUS_PROPRDONLY,
	DLADM_STATUS_BADVALCNT,
	DLADM_STATUS_DBNOTFOUND,
	DLADM_STATUS_DENIED,
	DLADM_STATUS_IOERR,
	DLADM_STATUS_TEMPONLY,
	DLADM_STATUS_TIMEDOUT,
	DLADM_STATUS_ISCONN,
	DLADM_STATUS_NOTCONN,
	DLADM_STATUS_REPOSITORYINVAL,
	DLADM_STATUS_MACADDRINVAL,
	DLADM_STATUS_KEYINVAL,
	DLADM_STATUS_INVALIDMACADDRLEN,
	DLADM_STATUS_INVALIDMACADDRTYPE,
	DLADM_STATUS_LINKBUSY,
	DLADM_STATUS_VIDINVAL,
	DLADM_STATUS_NONOTIF,
	DLADM_STATUS_TRYAGAIN,
	DLADM_STATUS_IPTUNTYPE,
	DLADM_STATUS_IPTUNTYPEREQD,
	DLADM_STATUS_BADIPTUNLADDR,
	DLADM_STATUS_BADIPTUNRADDR,
	DLADM_STATUS_ADDRINUSE,
	DLADM_STATUS_BADTIMEVAL,
	DLADM_STATUS_INVALIDMACADDR,
	DLADM_STATUS_INVALIDMACADDRNIC,
	DLADM_STATUS_INVALIDMACADDRINUSE,
	DLADM_STATUS_MACFACTORYSLOTINVALID,
	DLADM_STATUS_MACFACTORYSLOTUSED,
	DLADM_STATUS_MACFACTORYSLOTALLUSED,
	DLADM_STATUS_MACFACTORYNOTSUP,
	DLADM_STATUS_INVALIDMACPREFIX,
	DLADM_STATUS_INVALIDMACPREFIXLEN,
	DLADM_STATUS_BADCPUID,
	DLADM_STATUS_CPUERR,
	DLADM_STATUS_CPUNOTONLINE,
	DLADM_STATUS_BADRANGE,
	DLADM_STATUS_TOOMANYELEMENTS,
	DLADM_STATUS_DB_NOTFOUND,
	DLADM_STATUS_DB_PARSE_ERR,
	DLADM_STATUS_PROP_PARSE_ERR,
	DLADM_STATUS_ATTR_PARSE_ERR,
	DLADM_STATUS_FLOW_DB_ERR,
	DLADM_STATUS_FLOW_DB_OPEN_ERR,
	DLADM_STATUS_FLOW_DB_PARSE_ERR,
	DLADM_STATUS_FLOWPROP_DB_PARSE_ERR,
	DLADM_STATUS_FLOW_ADD_ERR,
	DLADM_STATUS_FLOW_WALK_ERR,
	DLADM_STATUS_FLOW_IDENTICAL,
	DLADM_STATUS_FLOW_INCOMPATIBLE,
	DLADM_STATUS_FLOW_EXISTS,
	DLADM_STATUS_PERSIST_FLOW_EXISTS,
	DLADM_STATUS_INVALID_IP,
	DLADM_STATUS_INVALID_PREFIXLEN,
	DLADM_STATUS_INVALID_PROTOCOL,
	DLADM_STATUS_INVALID_PORT,
	DLADM_STATUS_INVALID_DSF,
	DLADM_STATUS_INVALID_DSFMASK,
	DLADM_STATUS_INVALID_MACMARGIN,
	DLADM_STATUS_NOTDEFINED,
	DLADM_STATUS_BADPROP,
	DLADM_STATUS_MINMAXBW,
	DLADM_STATUS_NO_HWRINGS,
	DLADM_STATUS_PERMONLY,
	DLADM_STATUS_OPTMISSING,
	DLADM_STATUS_POOLCPU,
	DLADM_STATUS_INVALID_PORT_INSTANCE,
	DLADM_STATUS_PORT_IS_DOWN,
	DLADM_STATUS_PKEY_NOT_PRESENT,
	DLADM_STATUS_PARTITION_EXISTS,
	DLADM_STATUS_INVALID_PKEY,
	DLADM_STATUS_NO_IB_HW_RESOURCE,
	DLADM_STATUS_INVALID_PKEY_TBL_SIZE,
	DLADM_STATUS_PORT_NOPROTO,
	DLADM_STATUS_INVALID_MTU
} dladm_status_t;

typedef enum {
	DLADM_TYPE_STR,
	DLADM_TYPE_BOOLEAN,
	DLADM_TYPE_UINT64
} dladm_datatype_t;

typedef struct {
	boolean_t	ds_readonly;
	union {
		int	dsu_confid;
		nvlist_t *dsu_nvl;
	} ds_u;
} dladm_conf_t;

#define	ds_confid	ds_u.dsu_confid
#define	ds_nvl		ds_u.dsu_nvl

#define	DLADM_INVALID_CONF	0

/* opaque dladm handle to libdladm functions */
struct dladm_handle;
typedef struct dladm_handle *dladm_handle_t;

/* open/close handle */
extern dladm_status_t	dladm_open(dladm_handle_t *);
extern void		dladm_close(dladm_handle_t);

/*
 * retrieve the dld file descriptor from handle, only libdladm and
 * dlmgmtd are given access to the door file descriptor.
 */
extern int	dladm_dld_fd(dladm_handle_t);

typedef struct dladm_arg_info {
	const char	*ai_name;
	char		*ai_val[DLADM_MAX_ARG_VALS];
	uint_t		ai_count;
} dladm_arg_info_t;

typedef struct dladm_arg_list {
	dladm_arg_info_t	al_info[DLADM_MAX_ARG_CNT];
	uint_t			al_count;
	char			*al_buf;
} dladm_arg_list_t;

typedef enum {
	DLADM_LOGTYPE_LINK = 1,
	DLADM_LOGTYPE_FLOW
} dladm_logtype_t;

typedef struct dladm_usage {
	char		du_name[MAXLINKNAMELEN];
	uint64_t	du_duration;
	uint64_t	du_stime;
	uint64_t	du_etime;
	uint64_t	du_ipackets;
	uint64_t	du_rbytes;
	uint64_t	du_opackets;
	uint64_t	du_obytes;
	uint64_t	du_bandwidth;
	boolean_t	du_last;
} dladm_usage_t;

extern const char	*dladm_status2str(dladm_status_t, char *);
extern dladm_status_t	dladm_set_rootdir(const char *);
extern const char	*dladm_class2str(datalink_class_t, char *);
extern const char	*dladm_media2str(uint32_t, char *);
extern uint32_t		dladm_str2media(const char *);
extern boolean_t	dladm_valid_linkname(const char *);
extern boolean_t	dladm_str2interval(char *, uint32_t *);
extern dladm_status_t	dladm_str2bw(char *, uint64_t *);
extern const char	*dladm_bw2str(int64_t, char *);
extern dladm_status_t	dladm_str2pri(char *, mac_priority_level_t *);
extern const char	*dladm_pri2str(mac_priority_level_t, char *);
extern dladm_status_t	dladm_str2protect(char *, uint32_t *);
extern const char	*dladm_protect2str(uint32_t, char *);
extern dladm_status_t	dladm_str2ipv4addr(char *, void *);
extern const char	*dladm_ipv4addr2str(void *, char *);
extern dladm_status_t	dladm_str2ipv6addr(char *, void *);
extern const char	*dladm_ipv6addr2str(void *, char *);

extern dladm_status_t	dladm_parse_flow_props(char *, dladm_arg_list_t **,
			    boolean_t);
extern dladm_status_t	dladm_parse_link_props(char *, dladm_arg_list_t **,
			    boolean_t);
extern void		dladm_free_props(dladm_arg_list_t *);
extern dladm_status_t	dladm_parse_flow_attrs(char *, dladm_arg_list_t **,
			    boolean_t);
extern void		dladm_free_attrs(dladm_arg_list_t *);

extern dladm_status_t	dladm_start_usagelog(dladm_handle_t, dladm_logtype_t,
			    uint_t);
extern dladm_status_t	dladm_stop_usagelog(dladm_handle_t, dladm_logtype_t);
extern dladm_status_t	dladm_walk_usage_res(int (*)(dladm_usage_t *, void *),
			    int, char *, char *, char *, char *, void *);
extern dladm_status_t	dladm_walk_usage_time(int (*)(dladm_usage_t *, void *),
			    int, char *, char *, char *, void *);
extern dladm_status_t	dladm_usage_summary(int (*)(dladm_usage_t *, void *),
			    int, char *, void *);
extern dladm_status_t	dladm_usage_dates(int (*)(dladm_usage_t *, void *),
			    int, char *, char *, void *);
extern dladm_status_t	dladm_zone_boot(dladm_handle_t, zoneid_t);
extern dladm_status_t	dladm_zone_halt(dladm_handle_t, zoneid_t);

extern dladm_status_t	dladm_strs2range(char **, uint_t, mac_propval_type_t,
			    mac_propval_range_t **);
extern dladm_status_t	dladm_range2list(mac_propval_range_t *, void*,
			    uint_t *);
extern int		dladm_range2strs(mac_propval_range_t *, char **);
extern dladm_status_t	dladm_list2range(void *, uint_t, mac_propval_type_t,
			    mac_propval_range_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
