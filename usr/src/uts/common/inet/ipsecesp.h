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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_IPSECESP_H
#define	_INET_IPSECESP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* Named Dispatch Parameter Management Structure */
typedef struct ipsecesppparam_s {
	uint_t	ipsecesp_param_min;
	uint_t	ipsecesp_param_max;
	uint_t	ipsecesp_param_value;
	char	*ipsecesp_param_name;
} ipsecespparam_t;

#endif	/* _KERNEL */

/*
 * For now, only provide "aligned" version of header.
 * If aligned version is needed, we'll go with the naming conventions then.
 */

typedef struct esph {
	uint32_t esph_spi;
	uint32_t esph_replay;
} esph_t;

/* No need for "old" ESP, just point a uint32_t *. */

#ifdef	__cplusplus
}
#endif

#endif /* _INET_IPSECESP_H */
