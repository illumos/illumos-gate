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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DHCP_STABLE_H
#define	_DHCP_STABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module reads and writes the stable identifier values, DUID and IAID.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

extern uchar_t	*read_stable_duid(size_t *);
extern int	write_stable_duid(const uchar_t *, size_t);
extern uchar_t	*make_stable_duid(const char *, size_t *);

extern uint32_t	read_stable_iaid(const char *);
extern int	write_stable_iaid(const char *, uint32_t);
extern uint32_t	make_stable_iaid(const char *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _DHCP_STABLE_H */
