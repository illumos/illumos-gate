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

#ifndef	_SYS_FASTBOOT_IMPL_H
#define	_SYS_FASTBOOT_IMPL_H


#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/fastboot.h>

/*
 * Fast Reboot NOT SUPPORTED message IDs.
 */
enum {
#define	fastboot_nosup_msg(id, str)	id,
#define	fastboot_nosup_msg_end(id)	id
#include "fastboot_msg.h"
};

extern void fastreboot_disable(uint32_t);
extern void fastreboot_disable_highpil(void);

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FASTBOOT_IMPL_H */
