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
 * Copyright (c) 1989 by Sun Microsystem, Inc.
 */

#ifndef	_UDFS_H
#define	_UDFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Tag structure errors
 */
#define	TAGERR_CKSUM	1	/* Invalid checksum on tag */
#define	TAGERR_ID	2	/* Unknown tag id */
#define	TAGERR_VERSION	3	/* Version > ecma_version */
#define	TAGERR_TOOBIG	4	/* CRC length is too large */
#define	TAGERR_CRC	5	/* Bad CRC */
#define	TAGERR_LOC	6	/* Location does not match tag location */

#ifdef	__cplusplus
}
#endif

#endif	/* _UDFS_H */
