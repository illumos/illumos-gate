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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_VNI_IMPL_H
#define	_INET_VNI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/modctl.h>
#include <sys/stream.h>

typedef struct vni_str {
	struct vni_str	*st_next;	/* next in list */
	t_uscalar_t	st_state;	/* DLPI state */
	minor_t		st_minor;	/* corresponding minor */
	uint32_t	st_ppa;		/* physical point of attachment */
} vni_str_t;

#define	DL_MAXPRIM	DL_GET_STATISTICS_ACK
#define	VNIIDNUM	0x2a84
#define	VNINAME		"vni"
#define	VNIFLAGS	(D_MP|D_MTPERMOD)
#define	VNIHIWAT	1024
#define	VNILOWAT	512
#define	VNIMINPSZ	0
#define	VNIMAXPSZ	INFPSZ

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_VNI_IMPL_H */
