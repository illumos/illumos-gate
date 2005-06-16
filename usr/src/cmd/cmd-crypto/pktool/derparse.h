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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKTOOL_DERPARSE_H
#define	_PKTOOL_DERPARSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	LBER_OID
#define	LBER_OID		0x06
#endif

#ifndef	LBER_PRINTABLE_STRING
#define	LBER_PRINTABLE_STRING	0x13
#endif

#ifndef	LBER_IA5STRING
#define	LBER_IA5STRING		0x16
#endif

extern void	rdnseq_to_str(uchar_t *from, size_t from_sz, char *to,
		    size_t to_sz);

#ifdef	__cplusplus
}
#endif

#endif /* _PKTOOL_DERPARSE_H */
