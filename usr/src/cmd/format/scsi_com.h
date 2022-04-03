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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 */

#ifndef	_SCSI_COM_H
#define	_SCSI_COM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common definitions for SCSI routines.
 */

/*
 * Possible error levels.
 */
#define	ERRLVL_COR	1	/* corrected error */
#define	ERRLVL_RETRY	2	/* retryable error */
#define	ERRLVL_FAULT	3	/* drive faulted */
#define	ERRLVL_FATAL	4	/* fatal error */

#ifdef	__cplusplus
}
#endif

#endif	/* _SCSI_COM_H */
