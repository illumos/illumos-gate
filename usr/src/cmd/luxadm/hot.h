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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PHOTON CONFIGURATION MANAGER
 * Common definitions
 */

/*
 * I18N message number ranges
 *  This file: 13000 - 13499
 *  Shared common messages: 1 - 1999
 */

#ifndef	_HOT_H
#define	_HOT_H




/*
 * Include any headers you depend on.
 */

#ifdef	__cplusplus
extern "C" {
#endif


#define	NODE_CREATION_TIME	60	/* # seconds */
/*
 * Version 0.16 of the SES firmware powers up disks in front/back pairs.
 * However, the first disk inserted is usually spun up by itself, so
 * we need to calculate a timeout for 22/2 + 1 = 12 disks.
 *
 * Measured times are about 40s/disk for a total of 40*12=8 min total
 * The timeout assumes 10s/iteration or 4*12*10=8 min
 */
#define	PHOTON_SPINUP_TIMEOUT	(4*12)
#define	PHOTON_SPINUP_DELAY	10

#define	QLC_LIP_DELAY		17

#define		TARGET_ID(box_id, f_r, slot)    \
		((box_id | ((f_r == 'f' ? 0 : 1) << 4)) | (slot + 2))

#define		NEWER(time1, time2) 	(time1.tv_sec > time2.tv_sec)

extern	int	Options;


#ifdef	__cplusplus
}
#endif

#endif	/* _HOT_H */
