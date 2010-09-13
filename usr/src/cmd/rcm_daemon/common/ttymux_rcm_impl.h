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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_TTYMUX_RCM_IMPL_H
#define	_TTYMUX_RCM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef lint
#define	_(x)    gettext(x)
#else
#define	_(x)    x
#endif

#define	UNKNOWN		1	   /* flags */
#define	PRESENT		2	   /* flags */
#define	REGISTERED	4	   /* flags */
#define	CONNECTED	8	   /* flags */
#define	DISCONNECTED	0x10	   /* flags */

/* RCM operations */
#define	TTYMUX_OFFLINE  1
#define	TTYMUX_ONLINE   2
#define	TTYMUX_REMOVE   3
#define	TTYMUX_SUSPEND  4
#define	TTYMUX_RESUME   5

/*
 * Representation of a resource.
 * All resources are placed in a cache structured as a doubly linked list
 * (ie the next and prev fields).
 * The dependencies list identifies which resources this resource is
 * depending upon.
 */
typedef struct rsrc {
	char		*id;
	dev_t		dev;
	int		flags;
	struct rsrc	*next;
	struct rsrc	*prev;
	struct link	*dependencies;
} rsrc_t;

/*
 * Representation of a pair of resources participating in a
 * dependency relationship
 * The dependency is cast in terms of a resource that is using
 * another resource in order to provide a service.
 * This structure is used to represent a ttymux minor node that
 * has another serial device multiplexed under it. In this
 * case user resource would correspond to the ttymux minor node and the
 * the used resource would correspond to the multiplexed serial device.
 * The linkid field refers to the STREAM's link identifier.
 */
typedef struct link {
	rsrc_t		*user;	/* the using resource */
	rsrc_t		*used;	/* the used resource */
	int		linkid;	/* STREAM's link identifier */
	uint_t		state;
	int		flags;
	int		(*connect)(struct link *);
	int		(*disconnect)(struct link *);
	struct link	*next;
} link_t;

#define	MUXCTLLINK	"/devices/multiplexer@0,0:ctl"
#define	MUXCONLINK	"/devices/multiplexer@0,0:con"

#ifdef	__cplusplus
}
#endif

#endif /* _TTYMUX_RCM_IMPL_H */
