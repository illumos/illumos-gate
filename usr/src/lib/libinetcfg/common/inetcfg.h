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

#ifndef	_INETCFG_H
#define	_INETCFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* error codes */
#define	ICFG_SUCCESS	0	/* API was successful */
#define	ICFG_FAILURE	1	/* Generic failure */
#define	ICFG_NOT_TUNNEL	2	/* Tunnel operation attempted on non-tunnel */
#define	ICFG_NOT_SET	3	/* Could not return non-existent value */
#define	ICFG_BAD_ADDR	4	/* Invalid address */
#define	ICFG_BAD_PROT	5	/* Wrong protocol family for operation */
#define	ICFG_DAD_FAILED	6	/* Duplicate address detection failure */
#define	ICFG_DAD_FOUND	7	/* Duplicate address detected */

#define	ICFG_NERR	(ICFG_DAD_FOUND + 1)

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
	struct iftun_req *ifh_tunnel_params;	/* tunnel parameters */
} *icfg_handle_t;

extern const char *icfg_errmsg(int);
extern int icfg_open(icfg_handle_t *, const icfg_if_t *);
extern void icfg_close(icfg_handle_t);
extern int icfg_refresh_tunnel_cache(icfg_handle_t);
extern int icfg_set_tunnel_dest(icfg_handle_t, const struct sockaddr *,
    socklen_t);
extern int icfg_set_tunnel_src(icfg_handle_t, const struct sockaddr *,
    socklen_t);
extern int icfg_set_tunnel_hoplimit(icfg_handle_t, uint8_t);
extern int icfg_set_tunnel_encaplimit(icfg_handle_t, int16_t);
extern int icfg_get_tunnel_dest(icfg_handle_t, struct sockaddr *, socklen_t *);
extern int icfg_get_tunnel_src(icfg_handle_t, struct sockaddr *, socklen_t *);
extern int icfg_get_tunnel_hoplimit(icfg_handle_t, uint8_t *);
extern int icfg_get_tunnel_encaplimit(icfg_handle_t, int16_t *);
extern int icfg_get_tunnel_lower(icfg_handle_t, int *);
extern int icfg_get_tunnel_upper(icfg_handle_t, int *);
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
extern int icfg_get_if_list(icfg_if_t **, int *, int, int);
extern void icfg_free_if_list(icfg_if_t *);
extern int icfg_iterate_if(int, int, void *, int (*)(icfg_if_t *, void *));
extern boolean_t icfg_is_logical(icfg_handle_t);
extern int icfg_get_linkinfo(icfg_handle_t, lif_ifinfo_req_t *);
extern int icfg_sockaddr_to_str(sa_family_t, const struct sockaddr *,
    char *, size_t);
extern int icfg_str_to_sockaddr(sa_family_t, const char *, struct sockaddr *,
    socklen_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _INETCFG_H */
