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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBVRRPADM_H
#define	_LIBVRRPADM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* in(6)_addr_t */
#include <arpa/inet.h>
#include <net/if.h>		/* LIFNAMSIZ */
#include <limits.h>
#include <netinet/vrrp.h>
#include <syslog.h>
#include <libdladm.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	VRRP_NAME_MAX	32
#define	VRRPD_SOCKET	"/var/run/vrrpd.socket"

/*
 * to store the IP addresses
 */
typedef struct vrrp_addr {
	union {
		struct sockaddr_in	a4;
		struct sockaddr_in6	a6;
	} in;
#define	in4	in.a4
#define	in6	in.a6
} vrrp_addr_t;

/*
 * VRRP instance (configuration information).
 * Passed to vrrp_create(), returned by vrrp_query().
 */
typedef struct vrrp_vr_conf_s {
	char		vvc_name[VRRP_NAME_MAX];	/* VRRP router name */
	char		vvc_link[MAXLINKNAMELEN];	/* data-link name */
	vrid_t		vvc_vrid;			/* VRID */
	int		vvc_af;				/* IPv4/IPv6 */
	int		vvc_pri;
	uint32_t	vvc_adver_int;			/* in ms */
	boolean_t	vvc_preempt;
	boolean_t	vvc_accept;
	boolean_t	vvc_enabled;
} vrrp_vr_conf_t;

/*
 * VRRP state machine
 */
typedef enum {
	VRRP_STATE_NONE = -1,
	VRRP_STATE_INIT,
	VRRP_STATE_MASTER,
	VRRP_STATE_BACKUP
} vrrp_state_t;

/*
 * VRRP status structure
 * Returned by vrrp_query() as part of vrrp_queryinfo_t.
 */
typedef struct vrrp_statusinfo_s {
	vrrp_state_t	vs_state;
	vrrp_state_t	vs_prev_state;
	struct timeval	vs_st_time;	/* timestamp of last state trans */
} vrrp_stateinfo_t;

/*
 * The information obtained from peer's advertisements
 * Returned by vrrp_query() as part of vrrp_queryinfo_t.
 */
typedef struct vrrp_peer_s {
	vrrp_addr_t	vp_addr;	/* source IP addr of the message */
	int		vp_prio;	/* priority in adv message */
	struct timeval	vp_time;	/* timestamp of the adv message */
	int		vp_adver_int;	/* adv interval in adv message */
} vrrp_peer_t;

/*
 * Useful timer information, in ms
 */
typedef struct vrrp_timeinfo_s {
	int	vt_since_last_tran;	/* time since last state transition */
	int	vt_since_last_adv;	/* time since last advertisement */
	int	vt_master_down_intv;	/* timer interval for backup to */
					/* declare master down */
} vrrp_timerinfo_t;

/*
 * Address information
 */
typedef struct vrrp_addrinfo_s {
	char		va_vnic[MAXLINKNAMELEN];
	vrrp_addr_t	va_primary;
	uint32_t	va_vipcnt;
	vrrp_addr_t	va_vips[1];
} vrrp_addrinfo_t;

/*
 * VRRP instance configuration and run-time states information
 * Returned by vrrp_query().
 */
typedef struct vrrp_queryinfo {
	vrrp_vr_conf_t		show_vi;
	vrrp_stateinfo_t	show_vs;
	vrrp_peer_t		show_vp;
	vrrp_timerinfo_t	show_vt;
	vrrp_addrinfo_t		show_va;
} vrrp_queryinfo_t;

/*
 * flags sent with the VRRP_CMD_MODIFY command. Used in vrrp_setprop().
 */
#define	VRRP_CONF_PRIORITY	0x01
#define	VRRP_CONF_INTERVAL	0x02
#define	VRRP_CONF_PREEMPT	0x04
#define	VRRP_CONF_ACCEPT	0x08

/*
 * Errors
 */
typedef enum {
	VRRP_SUCCESS = 0,
	VRRP_EINVAL,		/* invalid parameter */
	VRRP_EINVALVRNAME,	/* invalid router name */
	VRRP_ENOMEM,		/* no memory */
	VRRP_ENOVIRT,		/* no virtual IP addresses */
	VRRP_ENOPRIM,		/* no primary IP address */
	VRRP_ENOVNIC,		/* no vnic created */
	VRRP_ENOLINK,		/* the link does not exist */
	VRRP_EINVALLINK,	/* invalid link */
	VRRP_EINVALADDR,	/* invalid IP address */
	VRRP_EINVALAF,		/* invalid IP address familty */
	VRRP_EDB,		/* configuration error */
	VRRP_EPERM,		/* permission denied */
	VRRP_EBADSTATE,		/* VRRP router in bad state */
	VRRP_EVREXIST,		/* <vrid, intf, af> three-tuple exists */
	VRRP_EINSTEXIST,	/* router name already exists */
	VRRP_EEXIST,		/* already exists */
	VRRP_ENOTFOUND,		/* vrrp router not found */
	VRRP_ETOOSMALL,		/* too small space */
	VRRP_EAGAIN,		/* Try again */
	VRRP_EALREADY,		/* already */
	VRRP_EDLADM,		/* dladm failure */
	VRRP_EIPADM,		/* ipadm failure */
	VRRP_ESYS,		/* system error */
	VRRP_ECMD		/* command request error */
} vrrp_err_t;

/*
 * Internal commands used between vrrpadm and vrrpd.
 */
typedef enum {
	VRRP_CMD_RETURN = 0,
	VRRP_CMD_CREATE,
	VRRP_CMD_DELETE,
	VRRP_CMD_ENABLE,
	VRRP_CMD_DISABLE,
	VRRP_CMD_MODIFY,
	VRRP_CMD_LIST,
	VRRP_CMD_QUERY
} vrrp_cmd_type_t;

#define	addr_len(af) ((af) == AF_INET ? sizeof (in_addr_t): sizeof (in6_addr_t))

#define	VRRPADDR_UNSPECIFIED(af, addr) 					\
	(((af) == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(			\
	    &(addr)->in6.sin6_addr)) || ((af) == AF_INET &&		\
	    ((addr)->in4.sin_addr.s_addr == INADDR_ANY)))

#define	VRRPADDR2STR(af, addr, abuf, size, append) {			\
	char ap[INET6_ADDRSTRLEN];					\
									\
	if (VRRPADDR_UNSPECIFIED(af, addr)) {				\
		(void) strlcpy(ap, "--", INET6_ADDRSTRLEN);		\
	} else if ((af) == AF_INET) {					\
		(void) inet_ntop((af), &(addr)->in4.sin_addr, ap,	\
		    INET6_ADDRSTRLEN);					\
	} else {							\
		(void) inet_ntop((af), &(addr)->in6.sin6_addr, ap,	\
		    INET6_ADDRSTRLEN);					\
	}								\
	if (append)							\
		(void) strlcat(abuf, ap, size);				\
	else								\
		(void) strlcpy(abuf, ap, size);				\
}

typedef struct vrrp_cmd_create_s {
	uint32_t	vcc_cmd;
	vrrp_vr_conf_t	vcc_conf;
} vrrp_cmd_create_t;

typedef struct vrrp_ret_create_s {
	vrrp_err_t	vrc_err;
} vrrp_ret_create_t;

typedef struct vrrp_cmd_delete_s {
	uint32_t	vcd_cmd;
	char		vcd_name[VRRP_NAME_MAX];
} vrrp_cmd_delete_t;

typedef struct vrrp_ret_delete_s {
	vrrp_err_t	vrd_err;
} vrrp_ret_delete_t;

typedef struct vrrp_cmd_enable_s {
	uint32_t	vcs_cmd;
	char		vcs_name[VRRP_NAME_MAX];
} vrrp_cmd_enable_t;

typedef struct vrrp_ret_enable_s {
	vrrp_err_t	vrs_err;
} vrrp_ret_enable_t;

typedef struct vrrp_cmd_disable_s {
	uint32_t	vcx_cmd;
	char		vcx_name[VRRP_NAME_MAX];
} vrrp_cmd_disable_t;

typedef struct vrrp_ret_disable_s {
	vrrp_err_t	vrx_err;
} vrrp_ret_disable_t;

typedef struct vrrp_cmd_modify_s {
	uint32_t	vcm_cmd;
	uint32_t	vcm_mask;
	vrrp_vr_conf_t	vcm_conf;
} vrrp_cmd_modify_t;

typedef struct vrrp_ret_modify_s {
	vrrp_err_t	vrm_err;
} vrrp_ret_modify_t;

typedef struct vrrp_cmd_list_s {
	uint32_t	vcl_cmd;
	vrid_t		vcl_vrid;
	char		vcl_ifname[LIFNAMSIZ];
	int		vcl_af;
} vrrp_cmd_list_t;

typedef struct vrrp_ret_list_s {
	vrrp_err_t	vrl_err;
	uint32_t	vrl_cnt;
	/*
	 * When vrl_cnt is non-zero, the return structure will be followed
	 * by the list of router names, separated by '\0'. Its size will
	 * be vrl_cnt * VRRP_NAME_MAX.
	 */
} vrrp_ret_list_t;

typedef struct vrrp_cmd_query_s {
	uint32_t	vcq_cmd;
	char		vcq_name[VRRP_NAME_MAX];
} vrrp_cmd_query_t;

typedef struct vrrp_ret_query_s {
	vrrp_err_t		vrq_err;
	vrrp_queryinfo_t	vrq_qinfo;
} vrrp_ret_query_t;

/*
 * Union of all VRRP commands
 */
typedef union vrrp_cmd_s {
	uint32_t		vc_cmd;
	vrrp_cmd_create_t	vc_cmd_create;
	vrrp_cmd_delete_t	vc_cmd_delete;
	vrrp_cmd_enable_t	vc_cmd_enable;
	vrrp_cmd_disable_t	vc_cmd_disable;
	vrrp_cmd_modify_t	vc_cmd_modify;
	vrrp_cmd_list_t		vc_cmd_list;
} vrrp_cmd_t;

/*
 * Union of all VRRP replies of the VRRP commands
 */
typedef union vrrp_ret_s {
	vrrp_err_t		vr_err;
	vrrp_ret_create_t	vr_ret_create;
	vrrp_ret_delete_t	vr_ret_delete;
	vrrp_ret_enable_t	vr_ret_enable;
	vrrp_ret_disable_t	vr_ret_disable;
	vrrp_ret_modify_t	vr_ret_modify;
	vrrp_ret_list_t		vr_ret_list;
	vrrp_ret_query_t	vr_ret_query;
} vrrp_ret_t;

/*
 * Public APIs
 */
struct vrrp_handle {
	dladm_handle_t	vh_dh;
};
typedef struct vrrp_handle *vrrp_handle_t;

const char	*vrrp_err2str(vrrp_err_t);
const char	*vrrp_state2str(vrrp_state_t);

vrrp_err_t	vrrp_open(vrrp_handle_t *);
void		vrrp_close(vrrp_handle_t);

boolean_t	vrrp_valid_name(const char *);

vrrp_err_t	vrrp_create(vrrp_handle_t, vrrp_vr_conf_t *);
vrrp_err_t	vrrp_delete(vrrp_handle_t, const char *);

vrrp_err_t	vrrp_enable(vrrp_handle_t, const char *);
vrrp_err_t	vrrp_disable(vrrp_handle_t, const char *);

vrrp_err_t	vrrp_modify(vrrp_handle_t, vrrp_vr_conf_t *, uint32_t);

vrrp_err_t	vrrp_query(vrrp_handle_t, const char *, vrrp_queryinfo_t **);

vrrp_err_t	vrrp_list(vrrp_handle_t, vrid_t, const char *, int,
		    uint32_t *, char *);

boolean_t	vrrp_is_vrrp_vnic(vrrp_handle_t, datalink_id_t,
		    datalink_id_t *, uint16_t *, vrid_t *, int *);

vrrp_err_t	vrrp_get_vnicname(vrrp_handle_t, vrid_t, int, char *,
		    datalink_id_t *, uint16_t *, char *, size_t);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBVRRPADM_H */
