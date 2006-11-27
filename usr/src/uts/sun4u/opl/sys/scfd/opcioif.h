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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef	_SYS_OPCIOIF_H
#define	_SYS_OPCIOIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/*
 * ioctl
 *
 * Note:  The ioctl definitions are split between opcio.h (closed) and
 * opcioif.h (open).  All definitions required for the exported scfd
 * interface should be in opcioif.h (open).
 */
#define	SCFIOC			'p'<<8

#define	SCFIOCGETDISKLED	(SCFIOC|101|0x80040000)
#define	SCFIOCSETDISKLED	(SCFIOC|102|0x80040000)
#define	SCFIOCSETPHPINFO	(SCFIOC|1|0xe0000000)

#define	SCF_DISK_LED_PATH_MAX	512

/* for led field */
#define	SCF_DISK_LED_ON		0x01
#define	SCF_DISK_LED_BLINK	0x02
#define	SCF_DISK_LED_OFF	0x04

typedef struct scfiocgetdiskled {
	unsigned char	path[SCF_DISK_LED_PATH_MAX];
	unsigned char	led;
} scfiocgetdiskled_t;

typedef struct scfsetphpinfo {
	unsigned char	buf[65536];
	unsigned int	size;
} scfsetphpinfo_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_OPCIOIF_H */
