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
#ifndef _IPADM_NDPD_H
#define	_IPADM_NDPD_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <libipadm.h>

/* File used for the AF_UNIX socket used in communicating with in.ndpd */
#define	IPADM_UDS_PATH	"/var/run/in.ndpd_ipadm"

/* Types of messages sent to in.ndpd */
enum {
	IPADM_DISABLE_AUTOCONF,
	IPADM_ENABLE_AUTOCONF,
	IPADM_CREATE_ADDRS,
	IPADM_DELETE_ADDRS
};

/* Message format sent to in.ndpd */
typedef struct ipadm_ndpd_msg_s {
	uint32_t		inm_cmd;
	char			inm_ifname[LIFNAMSIZ];
	struct sockaddr_in6	inm_intfid;
	int			inm_intfidlen;
	boolean_t		inm_stateless;
	boolean_t		inm_stateful;
	char			inm_aobjname[MAXNAMELEN];
} ipadm_ndpd_msg_t;

/* Functions to send to and receive from in.ndpd */
extern int		ipadm_ndpd_write(int, const void *, size_t);
extern int		ipadm_ndpd_read(int, void *, size_t);

/*
 * Functions used by in.ndpd to add and delete address objects while
 * adding/deleting each stateless/stateful autoconfigured address.
 */
extern ipadm_status_t	ipadm_add_aobjname(ipadm_handle_t, const char *,
			    sa_family_t, const char *, ipadm_addr_type_t, int);
extern ipadm_status_t	ipadm_delete_aobjname(ipadm_handle_t, const char *,
			    sa_family_t, const char *, ipadm_addr_type_t, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPADM_NDPD_H */
