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

#ifndef	_INETCFG_H
#define	_INETCFG_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* error codes */
typedef enum {
	ICFG_SUCCESS,		/* No error occurred */
	ICFG_FAILURE,		/* Generic failure */
	ICFG_NO_MEMORY,		/* Insufficient memory */
	ICFG_NOT_TUNNEL,	/* Tunnel operation attempted on non-tunnel */
	ICFG_NOT_SET,		/* Could not return non-existent value */
	ICFG_BAD_ADDR,		/* Invalid address */
	ICFG_BAD_PROTOCOL,	/* Wrong protocol family for operation */
	ICFG_DAD_FAILED,	/* Duplicate address detection failure */
	ICFG_DAD_FOUND,		/* Duplicate address detected */
	ICFG_IF_UP,		/* Interface is up */
	ICFG_EXISTS,		/* Interface already exists */
	ICFG_NO_EXIST,		/* Interface does not exist */
	ICFG_INVALID_ARG,	/* Invalid argument */
	ICFG_INVALID_NAME,	/* Invalid name */
	ICFG_DLPI_INVALID_LINK, /* Invalid DLPI link */
	ICFG_DLPI_FAILURE,	/* Generic DLPI failure */
	ICFG_NO_PLUMB_IP,	/* Could not plumb IP stream */
	ICFG_NO_PLUMB_ARP,	/* Could not plumb ARP stream */
	ICFG_NO_UNPLUMB_IP,	/* Could not unplumb IP stream */
	ICFG_NO_UNPLUMB_ARP,	/* Could not unplumb ARP stream */
	ICFG_NO_IP_MUX		/* No IP mux set on the interface */
} icfg_error_t;

/* valid types for icfg_get_if_list() */
#define	ICFG_PLUMBED	0
#define	ICFG_INSTALLED	1

typedef struct icfg_if {
	char if_name[LIFNAMSIZ];	/* name of interface (eg., hme0) */
	sa_family_t if_protocol;	/* IP protocol version */
} icfg_if_t;

typedef struct icfg_handle {
	int ifh_sock;				/* socket to interface */
	icfg_if_t ifh_interface;		/* interface definition */
} *icfg_handle_t;

/* retrieve error string */
extern const char *icfg_errmsg(int);

/* handle functions */
extern int icfg_open(icfg_handle_t *, const icfg_if_t *);
extern void icfg_close(icfg_handle_t);
extern boolean_t icfg_is_logical(icfg_handle_t);

/* get interface name */
extern const char *icfg_if_name(icfg_handle_t);

/* set interface properties */
extern int icfg_set_flags(icfg_handle_t, uint64_t);
extern int icfg_set_metric(icfg_handle_t, int);
extern int icfg_set_mtu(icfg_handle_t, uint_t);
extern int icfg_set_index(icfg_handle_t, int);
extern int icfg_set_netmask(icfg_handle_t, const struct sockaddr_in *);
extern int icfg_set_broadcast(icfg_handle_t, const struct sockaddr_in *);
extern int icfg_set_prefixlen(icfg_handle_t, int);
extern int icfg_set_addr(icfg_handle_t, const struct sockaddr *, socklen_t);
extern int icfg_set_token(icfg_handle_t, const struct sockaddr_in6 *, int);
extern int icfg_set_subnet(icfg_handle_t, const struct sockaddr *, socklen_t,
    int);
extern int icfg_set_dest_addr(icfg_handle_t, const struct sockaddr *,
    socklen_t);

/* get interface properties */
extern int icfg_get_addr(icfg_handle_t, struct sockaddr *, socklen_t *, int *,
    boolean_t);
extern int icfg_get_token(icfg_handle_t, struct sockaddr_in6 *, int *,
    boolean_t);
extern int icfg_get_subnet(icfg_handle_t, struct sockaddr *, socklen_t *,
    int *, boolean_t);
extern int icfg_get_netmask(icfg_handle_t, struct sockaddr_in *);
extern int icfg_get_broadcast(icfg_handle_t, struct sockaddr_in *);
extern int icfg_get_dest_addr(icfg_handle_t, struct sockaddr *, socklen_t *);
extern int icfg_get_groupname(icfg_handle_t, char *, size_t);
extern int icfg_get_flags(icfg_handle_t, uint64_t *);
extern int icfg_get_metric(icfg_handle_t, int *);
extern int icfg_get_mtu(icfg_handle_t, uint_t *);
extern int icfg_get_index(icfg_handle_t, int *);

/* retrieve interface list or iterate over all interface lists */
extern int icfg_get_if_list(icfg_if_t **, int *, int, int);
extern void icfg_free_if_list(icfg_if_t *);
extern int icfg_iterate_if(int, int, void *, int (*)(icfg_if_t *, void *));

extern int icfg_sockaddr_to_str(sa_family_t, const struct sockaddr *,
    char *, size_t);
extern int icfg_str_to_sockaddr(sa_family_t, const char *, struct sockaddr *,
    socklen_t *);

/* plumb or unplumb interfaces, add or remove IP */
extern int icfg_add_addr(icfg_handle_t, icfg_handle_t *,
    const struct sockaddr *, socklen_t);
extern int icfg_remove_addr(icfg_handle_t, const struct sockaddr *, socklen_t);

extern int icfg_plumb(icfg_handle_t);
extern int icfg_unplumb(icfg_handle_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _INETCFG_H */
