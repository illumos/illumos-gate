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
#ifndef _LIBIPADM_H
#define	_LIBIPADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <libnvpair.h>
#include <netinet/tcp.h>
#include <sys/stropts.h>

#define	IPADM_AOBJ_USTRSIZ	32
#define	IPADM_AOBJSIZ		(LIFNAMSIZ + IPADM_AOBJ_USTRSIZ)
#define	MAXPROPVALLEN		512
#define	LOOPBACK_IF		"lo0"

/* special timeout values for dhcp operations */
#define	IPADM_DHCP_WAIT_DEFAULT	(-1)
#define	IPADM_DHCP_WAIT_FOREVER	(-2)

/*
 * Specifies that the string passed to ipadm_str2nvlist() is a string of comma
 * separated names and that each name does not have values associated with it.
 */
#define	IPADM_NORVAL		0x00000001

/* error codes */
typedef enum {
	IPADM_SUCCESS,		/* No error occurred */
	IPADM_FAILURE,		/* Generic failure */
	IPADM_EAUTH,		/* Insufficient user authorizations */
	IPADM_EPERM,		/* Permission denied */
	IPADM_NO_BUFS,		/* No Buffer space available */
	IPADM_NO_MEMORY,	/* Insufficient memory */
	IPADM_BAD_ADDR,		/* Invalid address */
	IPADM_BAD_PROTOCOL,	/* Wrong protocol family for operation */
	IPADM_DAD_FOUND,	/* Duplicate address detected */
	IPADM_EXISTS,		/* Already exists */
	IPADM_IF_EXISTS,	/* Interface already exists */
	IPADM_ADDROBJ_EXISTS,	/* Address object already exists */
	IPADM_ADDRCONF_EXISTS,	/* Addrconf already in progress */
	IPADM_ENXIO,		/* Interface does not exist */
	IPADM_GRP_NOTEMPTY,	/* IPMP Group non-empty on unplumb */
	IPADM_INVALID_ARG,	/* Invalid argument */
	IPADM_INVALID_NAME,	/* Invalid name */
	IPADM_DLPI_FAILURE,	/* Could not open DLPI link */
	IPADM_DLADM_FAILURE,	/* DLADM error encountered */
	IPADM_PROP_UNKNOWN,	/* Unknown property */
	IPADM_ERANGE,		/* Value is outside the allowed range */
	IPADM_ESRCH,		/* Value does not exist */
	IPADM_EOVERFLOW,	/* Number of values exceed the allowed limit */
	IPADM_NOTFOUND,		/* Object not found */
	IPADM_IF_INUSE,		/* Interface already in use */
	IPADM_ADDR_INUSE,	/* Address alrelady in use */
	IPADM_BAD_HOSTNAME,	/* hostname maps to multiple IP addresses */
	IPADM_ADDR_NOTAVAIL,	/* Can't assign requested address */
	IPADM_ALL_ADDRS_NOT_ENABLED, /* All addresses could not be enabled */
	IPADM_NDPD_NOT_RUNNING,	/* in.ndpd not running */
	IPADM_DHCP_START_ERROR,	/* Cannot start dhcpagent */
	IPADM_DHCP_IPC_ERROR,	/* Cannot communicate with dhcpagent */
	IPADM_DHCP_IPC_TIMEOUT,	/* Communication with dhcpagent timed out */
	IPADM_TEMPORARY_OBJ,	/* Permanent operation on temporary object */
	IPADM_IPC_ERROR,	/* Cannot communicate with ipmgmtd */
	IPADM_OP_DISABLE_OBJ,	/* Operation on disable object */
	IPADM_NOTSUP,		/* Operation not supported */
	IPADM_EBADE,		/* Invalid data exchange with ipmgmtd */
	IPADM_GZ_PERM		/* Operation not permitted on from-gz intf */
} ipadm_status_t;

/*
 * option flags taken by the libipadm functions
 *
 *  - IPADM_OPT_PERSIST:
 *	For all the create/delete/up/down/set/get functions,
 *	requests to persist the configuration so that it can be
 *	re-enabled or re-applied on boot.
 *
 *  - IPADM_OPT_ACTIVE:
 *	Requests to apply configuration without persisting it and
 *	used by show-* subcommands to retrieve current values.
 *
 *  - IPADM_OPT_DEFAULT:
 *	retrieves the default value for a given property
 *
 *  - IPADM_OPT_PERM
 *	retrieves the permission for a given property
 *
 *  - IPADM_OPT_POSSIBLE
 *	retrieves the range of values for a given property
 *
 *  - IPADM_OPT_APPEND
 *	for multi-valued properties, appends a new value.
 *
 *  - IPADM_OPT_REMOVE
 *	for multi-valued properties, removes the specified value
 *
 *  - IPADM_OPT_IPMP
 *	Used in ipadm_create_if() to plumb ipmp interfaces.
 *
 *  - IPADM_OPT_GENPPA
 *	Used in ipadm_create_if() to generate a ppa for the given interface.
 *
 *  - IPADM_OPT_ZEROADDR
 *	return :: or INADDR_ANY
 *
 *  - IPADM_OPT_RELEASE
 *	Used to release the lease on a dhcp address object
 *
 *  - IPADM_OPT_INFORM
 *	Used to perform DHCP_INFORM on a specified static address object
 *
 *  - IPADM_OPT_UP
 *	Used to bring up a static address on creation
 *
 *  - IPADM_OPT_V46
 *	Used to plumb both IPv4 and IPv6 interfaces by ipadm_create_addr()
 *
 *  - IPADM_OPT_SET_PROPS
 *	Used to indicate the update changes the running configuration of
 *	"props" data on the object. The props are cached there on the parent,
 *	but the PROPS_ONLY change does not affect the ACTIVE/PERSIST state of
 *	the parent.
 *
 *  - IPADM_OPT_PERSIST_PROPS
 *	Used when IPADM_OPT_SET_PROPS is active to indicate the update changes
 *  the persistent configuration of the "props" data on the object.
 */
#define	IPADM_OPT_PERSIST	0x00000001
#define	IPADM_OPT_ACTIVE	0x00000002
#define	IPADM_OPT_DEFAULT	0x00000004
#define	IPADM_OPT_PERM		0x00000008
#define	IPADM_OPT_POSSIBLE	0x00000010
#define	IPADM_OPT_APPEND	0x00000020
#define	IPADM_OPT_REMOVE	0x00000040
#define	IPADM_OPT_IPMP		0x00000080
#define	IPADM_OPT_GENPPA	0x00000100
#define	IPADM_OPT_ZEROADDR	0x00000200
#define	IPADM_OPT_RELEASE	0x00000400
#define	IPADM_OPT_INFORM	0x00000800
#define	IPADM_OPT_UP		0x00001000
#define	IPADM_OPT_V46		0x00002000
#define	IPADM_OPT_SET_PROPS	0x00004000
#define	IPADM_OPT_PERSIST_PROPS		0x00008000

/* IPADM property class */
#define	IPADMPROP_CLASS_MODULE	0x00000001	/* on 'protocol' only */
#define	IPADMPROP_CLASS_IF	0x00000002	/* on 'IP interface' only */
#define	IPADMPROP_CLASS_ADDR	0x00000004	/* on 'IP address' only */
/* protocol property that can be applied on interface too */
#define	IPADMPROP_CLASS_MODIF	(IPADMPROP_CLASS_MODULE | IPADMPROP_CLASS_IF)

/* opaque ipadm handle to libipadm functions */
struct ipadm_handle;
typedef struct ipadm_handle	*ipadm_handle_t;

/* ipadm_handle flags */
#define	IPH_VRRP		0x00000001	/* Caller is VRRP */
#define	IPH_LEGACY		0x00000002	/* Caller is legacy app */
#define	IPH_IPMGMTD		0x00000004	/* Caller is ipmgmtd itself */
/*
 * Indicates that the operation being invoked is in 'init' context. This is
 * a library private flag.
 */
#define	IPH_INIT		0x10000000

/* opaque address object structure */
typedef struct ipadm_addrobj_s	*ipadm_addrobj_t;

/* ipadm_if_info_t states */
typedef enum {
	IFIS_OK,		/* Interface is usable */
	IFIS_DOWN,		/* Interface has no UP addresses */
	IFIS_FAILED,		/* Interface has failed. */
	IFIS_OFFLINE,		/* Interface has been offlined */
	IFIS_DISABLED		/* Interface has been disabled. */
} ipadm_if_state_t;

typedef struct ipadm_if_info_s {
	struct ipadm_if_info_s	*ifi_next;
	char			ifi_name[LIFNAMSIZ];	/* interface name */
	ipadm_if_state_t	ifi_state;		/* see above */
	uint_t			ifi_cflags;		/* current flags */
	uint_t			ifi_pflags;		/* persistent flags */
} ipadm_if_info_t;

/* ipadm_if_info_t flags */
#define	IFIF_BROADCAST		0x00000001
#define	IFIF_MULTICAST		0x00000002
#define	IFIF_POINTOPOINT	0x00000004
#define	IFIF_VIRTUAL		0x00000008
#define	IFIF_IPMP		0x00000010
#define	IFIF_STANDBY		0x00000020
#define	IFIF_INACTIVE		0x00000040
#define	IFIF_VRRP		0x00000080
#define	IFIF_NOACCEPT		0x00000100
#define	IFIF_IPV4		0x00000200
#define	IFIF_IPV6		0x00000400
#define	IFIF_L3PROTECT		0x00000800

/* ipadm_addr_info_t state */
typedef enum {
	IFA_DISABLED,		/* Address not in active configuration. */
	IFA_DUPLICATE,		/* DAD failed. */
	IFA_DOWN,		/* Address is not IFF_UP */
	IFA_TENTATIVE,		/* DAD verification initiated */
	IFA_OK,			/* Address is usable */
	IFA_INACCESSIBLE	/* Interface has failed */
} ipadm_addr_state_t;

/* possible address types */
typedef enum  {
	IPADM_ADDR_NONE,
	IPADM_ADDR_STATIC,
	IPADM_ADDR_IPV6_ADDRCONF,
	IPADM_ADDR_DHCP
} ipadm_addr_type_t;

typedef struct ipadm_addr_info_s {
	struct ifaddrs		ia_ifa;		/* list of addresses */
	char			ia_sname[NI_MAXHOST];	/* local hostname */
	char			ia_dname[NI_MAXHOST];	/* remote hostname */
	char			ia_aobjname[IPADM_AOBJSIZ];
	uint_t			ia_cflags;	/* active flags */
	uint_t			ia_pflags;	/* persistent flags */
	ipadm_addr_type_t	ia_atype;	/* see above */
	ipadm_addr_state_t	ia_state;	/* see above */
} ipadm_addr_info_t;
#define	IA_NEXT(ia)		((ipadm_addr_info_t *)(ia->ia_ifa.ifa_next))

/* ipadm_addr_info_t flags */
#define	IA_UP			0x00000001
#define	IA_UNNUMBERED		0x00000002
#define	IA_PRIVATE		0x00000004
#define	IA_TEMPORARY		0x00000008
#define	IA_DEPRECATED		0x00000010

/* open/close libipadm handle */
extern ipadm_status_t	ipadm_open(ipadm_handle_t *, uint32_t);
extern void		ipadm_close(ipadm_handle_t);

/* Check authorization for network configuration */
extern boolean_t	ipadm_check_auth(void);
/*
 * Interface management functions
 */
extern ipadm_status_t	ipadm_create_if(ipadm_handle_t, char *, sa_family_t,
			    uint32_t);
extern ipadm_status_t	ipadm_disable_if(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_enable_if(ipadm_handle_t, const char *, uint32_t);
extern ipadm_status_t	ipadm_if_info(ipadm_handle_t, const char *,
			    ipadm_if_info_t **, uint32_t, int64_t);
extern void		ipadm_free_if_info(ipadm_if_info_t *);
extern ipadm_status_t	ipadm_delete_if(ipadm_handle_t, const char *,
			    sa_family_t, uint32_t);
extern void		ipadm_if_move(ipadm_handle_t, const char *);

/*
 * Address management functions
 */
extern ipadm_status_t	ipadm_create_addr(ipadm_handle_t, ipadm_addrobj_t,
			    uint32_t);
extern ipadm_status_t	ipadm_disable_addr(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_enable_addr(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_addr_info(ipadm_handle_t, const char *,
			    ipadm_addr_info_t **, uint32_t, int64_t);
extern void		ipadm_free_addr_info(ipadm_addr_info_t *);
extern ipadm_status_t	ipadm_up_addr(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_down_addr(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_refresh_addr(ipadm_handle_t, const char *,
			    uint32_t);
extern ipadm_status_t	ipadm_delete_addr(ipadm_handle_t, const char *,
			    uint32_t);

/* Functions related to creating/deleting/modifying opaque address object */
extern ipadm_status_t	ipadm_create_addrobj(ipadm_addr_type_t, const char *,
			    ipadm_addrobj_t *);
extern void		ipadm_destroy_addrobj(ipadm_addrobj_t);
extern ipadm_status_t   ipadm_get_aobjname(const ipadm_addrobj_t, char *,
			    size_t);

/* Functions to set fields in addrobj for static addresses */
extern ipadm_status_t	ipadm_set_addr(ipadm_addrobj_t, const char *,
			    sa_family_t);
extern ipadm_status_t	ipadm_set_dst_addr(ipadm_addrobj_t, const char *,
			    sa_family_t);
extern ipadm_status_t   ipadm_get_addr(const ipadm_addrobj_t,
			    struct sockaddr_storage *);

/* Functions to set fields in addrobj for IPv6 addrconf */
extern ipadm_status_t	ipadm_set_interface_id(ipadm_addrobj_t, const char *);
extern ipadm_status_t	ipadm_set_stateless(ipadm_addrobj_t, boolean_t);
extern ipadm_status_t	ipadm_set_stateful(ipadm_addrobj_t, boolean_t);

/* Functions to set fields in addrobj for DHCP */
extern ipadm_status_t	ipadm_set_primary(ipadm_addrobj_t, boolean_t);
extern ipadm_status_t	ipadm_set_wait_time(ipadm_addrobj_t, int32_t);
extern ipadm_status_t	ipadm_set_reqhost(ipadm_addrobj_t, const char *);

/*
 * Property management functions
 */
/* call back function for the property walker */
typedef boolean_t	ipadm_prop_wfunc_t(void *, const char *, uint_t);
extern ipadm_status_t	ipadm_walk_proptbl(uint_t, uint_t, ipadm_prop_wfunc_t *,
			    void *);
extern ipadm_status_t	ipadm_walk_prop(const char *, uint_t, uint_t,
			    ipadm_prop_wfunc_t *, void *);

/* Interface property management - set, reset and get */
extern ipadm_status_t	ipadm_set_ifprop(ipadm_handle_t, const char *,
			    const char *, const char *, uint_t, uint_t);
extern ipadm_status_t	ipadm_get_ifprop(ipadm_handle_t, const char *,
			    const char *, char *, uint_t *, uint_t, uint_t);

/* Address property management - set, reset and get */
extern ipadm_status_t	ipadm_set_addrprop(ipadm_handle_t, const char *,
			    const char *, const char *, uint_t);
extern ipadm_status_t	ipadm_get_addrprop(ipadm_handle_t, const char *, char *,
			    uint_t *, const char *, uint_t);

/* Protoocl property management - set, reset and get */
extern ipadm_status_t	ipadm_set_prop(ipadm_handle_t, const char *,
			    const char *, uint_t, uint_t);
extern ipadm_status_t	ipadm_get_prop(ipadm_handle_t, const char *, char *,
			    uint_t *, uint_t, uint_t);

/*
 * miscellaneous helper functions.
 */
extern const char 	*ipadm_status2str(ipadm_status_t);
extern int		ipadm_str2nvlist(const char *, nvlist_t **, uint_t);
extern size_t		ipadm_nvlist2str(nvlist_t *, char *, size_t);
extern char		*ipadm_proto2str(uint_t);
extern uint_t		ipadm_str2proto(const char *);
extern ipadm_status_t	ipadm_open_arp_on_udp(const char *, int *);
extern int		ipadm_legacy2new_propname(const char *, char *,
			    uint_t, uint_t *);
extern int		ipadm_new2legacy_propname(const char *, char *,
			    uint_t, uint_t);
extern boolean_t	ipadm_is_valid_hostname(const char *hostname);
extern boolean_t	ipadm_is_nil_hostname(const char *hostname);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPADM_H */
