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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__MMS_DM_MSG_H
#define	__MMS_DM_MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	DM_MSG
#define	DM_MSG(n, s)
#endif

/* DM Messages 6000-6999 */

#define	DM_6500_MSG 6500
DM_MSG(DM_6500_MSG, gettext("$dm$: syntax error: $error$"))

#define	DM_6501_MSG 6501
DM_MSG(DM_6501_MSG, gettext("$dm$: activate $type$ failed: $error$"))

#define	DM_6502_MSG 6502
DM_MSG(DM_6502_MSG,
	gettext("$dm$: reserved. Preempt reservation? reply yes/no/retry."))

#define	DM_6504_MSG 6504
DM_MSG(DM_6504_MSG, gettext("$dm$: USCSICMD error: $error$"))

#define	DM_6505_MSG 6505
DM_MSG(DM_6505_MSG, gettext("$dm$: no matching command: $error$"))

#define	DM_6506_MSG 6506
DM_MSG(DM_6506_MSG, gettext("$dm$: internal error: $error$"))

#define	DM_6507_MSG 6507
DM_MSG(DM_6507_MSG, gettext("$dm$: unknown capability: $error$"))

#define	DM_6508_MSG 6508
DM_MSG(DM_6508_MSG, gettext("$dm$: attach error: $error$"))

#define	DM_6510_MSG 6510
DM_MSG(DM_6510_MSG, gettext("$dm$: identify error: $error$"))

#define	DM_6511_MSG 6511
DM_MSG(DM_6511_MSG, gettext("$dm$: detach error: $error$"))

#define	DM_6513_MSG 6513
DM_MSG(DM_6513_MSG, gettext("$dm$: set blocksize error: $error$"))

#define	DM_6514_MSG 6514
DM_MSG(DM_6514_MSG, gettext("$dm$: get blocksize error: $error$"))

#define	DM_6515_MSG 6515
DM_MSG(DM_6515_MSG, gettext("$dm$: unsupported MTIOCTOP function: $error$"))

#define	DM_6516_MSG 6516
DM_MSG(DM_6516_MSG, gettext("$dm$: open error: $error$"))

#define	DM_6517_MSG 6517
DM_MSG(DM_6517_MSG, gettext("$dm$: load command error: $error$"))

#define	DM_6518_MSG 6518
DM_MSG(DM_6518_MSG, gettext("$dm$: overwrite data on $pcl$? reply yes/no."))

#define	DM_6519_MSG 6519
DM_MSG(DM_6519_MSG, gettext("$dm$: switch label from $from$ to $to$ on " \
	"$pcl$? reply yes/no."))

#define	DM_6520_MSG 6520
DM_MSG(DM_6520_MSG, gettext("$dm$: switch label from $from$ to $to$ and " \
	"writeover data on $pcl$? reply yes/no."))

#define	DM_6521_MSG 6521
DM_MSG(DM_6521_MSG, gettext("$dm$: $drive$ is still opened by pid $pid$"))

#define	DM_6522_MSG 6522
DM_MSG(DM_6522_MSG, gettext("$dm$: MTSEEK error: $error$"))

#define	DM_6523_MSG 6523
DM_MSG(DM_6523_MSG, gettext("$dm$: MTTELL error: $error$"))

#define	DM_6524_MSG 6524
DM_MSG(DM_6524_MSG,
	gettext("$dm$: DM restarting because of attach error: $error$"))

#define	DM_6525_MSG 6525
DM_MSG(DM_6525_MSG, gettext("$dm$: DM initialization error: $error$"))

#define	DM_6526_MSG 6526
DM_MSG(DM_6526_MSG, gettext("$dm$: DM restarting: $error$"))

#define	DM_6527_MSG 6527
DM_MSG(DM_6527_MSG, gettext("$dm$: mount command error: $error$"))

#define	DM_6529_MSG 6529
DM_MSG(DM_6529_MSG, gettext("$dm$: make handle directory error: $error$"))


#ifdef	__cplusplus
}
#endif

#endif	/* __MMS_DM_MSG_H */
