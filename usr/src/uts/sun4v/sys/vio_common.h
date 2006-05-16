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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VIO_COMMON_H
#define	_SYS_VIO_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


/*
 *  Common header for VIO descriptor ring entries
 */
typedef struct vio_dring_entry_hdr {
	uint8_t		dstate;		/* Current state of Dring entry */
	uint8_t		ack:1;		/* 1 => receiver must ACK when DONE */

	/*
	 * Padding.
	 */
	uint16_t	resv[3];
} vio_dring_entry_hdr_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_VIO_COMMON_H */
