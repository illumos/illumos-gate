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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * !!! IMPORTANT !!!
 * Please DO NOT overwrite existing Fastboot Not Support msgids.
 * New fastboot_nosup_msg() have to be added to the end of the list,
 * just BEFORE fastboot_nosup_msg_end().
 */

#ifndef	_SYS_FASTBOOT_MSG_H
#define	_SYS_FASTBOOT_MSG_H
#endif	/* _SYS_FASTBOOT_MSG_H */

#ifndef	fastboot_nosup_msg
#define	fastboot_nosup_msg(id, str)
#endif	/* fastboot_nosup_msg */

#ifndef	fastboot_nosup_msg_end
#define	fastboot_nosup_msg_end(id)
#endif	/* fastboot_nosup_msg_end */

fastboot_nosup_msg(FBNS_DEFAULT, "")
fastboot_nosup_msg(FBNS_SUSPEND, " after suspend/resume")
fastboot_nosup_msg(FBNS_FMAHWERR, " due to FMA recovery from hardware error")
fastboot_nosup_msg(FBNS_HOTPLUG, " after DR operations")
fastboot_nosup_msg(FBNS_BOOTMOD, " due to presence of boot-time modules")

/*
 * Should ALWAYS be the last one.
 * No fastboot_nosup_msg() after that line.
 */
fastboot_nosup_msg_end(FBNS_END)

#undef	fastboot_nosup_msg
#undef	fastboot_nosup_msg_end

#undef	_SYS_FASTBOOT_MSG_H
