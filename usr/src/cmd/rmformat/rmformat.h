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

#ifndef	_RMFORMAT_H
#define	_RMFORMAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contents the definitions for rmformat utility
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <strings.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <unistd.h>
#include <limits.h>
#include <volmgt.h>
#include <sys/vtoc.h>
#include <locale.h>
#include <libintl.h>
#include <dirent.h>
#include <sys/dkio.h>
#include <sys/dktp/fdisk.h>
#include <sys/smedia.h>
#include <sys/efi_partition.h>

#ifdef	DEBUG
#define	DPRINTF(str)			(void) printf(str)
#define	DPRINTF1(str, a)		(void) printf(str, a)
#define	DPRINTF2(str, a, b)		(void) printf(str, a, b)
#define	DPRINTF3(str, a, b, c)		(void) printf(str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)	(void) printf(str, a, b, c, d)
#else
#define	DPRINTF(str)
#define	DPRINTF1(str, a)
#define	DPRINTF2(str, a, b)
#define	DPRINTF3(str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)
#endif

#define	PERROR(string)	my_perror(gettext(string))

/* Little endian and big endian */
#ifdef sparc
#define	les(val)	((((val)&0xFF)<<8)|(((val)>>8)&0xFF))
#define	lel(val)	(((unsigned)(les((val)&0x0000FFFF))<<16) | \
			(les((unsigned)((val)&0xffff0000)>>16)))
#else	/* !sparc */
#define	les(val)	(val)
#define	lel(val)	(val)
#endif /* sparc */

/* To avoid misalign access in sparc */
#ifdef sparc
#define	GET_32(addr)       \
	((*((uint8_t *)((char *)addr)) << 24) | \
	(*((uint8_t *)(((char *)addr)+1)) << 16) |\
	(*((uint8_t *)(((char *)addr)+2)) << 8) | \
	(*((uint8_t *)(((char *)addr)+3))))

#else
#define	GET_32(addr) (*(uint32_t *)addr)
#endif

#define	VERIFY_READ 1
#define	VERIFY_WRITE 2

/* w_flag and others */
#define	WP_MSG_0 "Medium is already write protected\n"
#define	WP_MSG_1 "Medium is password protected : use -W option.\n"
#define	WP_MSG_2 "Medium is Read Write protected : use -R option.\n"
#define	WP_MSG_3 "Medium is not Write protected\n"

/* W_flag */
#define	WP_MSG_4 "Medium is Read Write protected.\n"
#define	WP_MSG_5 "Changing to write protect with password.\n"
#define	WP_MSG_6 "Medium is already password protected\n"
#define	WP_MSG_7 "Medium is not password protected\n"

/* R_flag */

/* Misc */
#define	WP_MSG_8 "Medium is password write protected\n"
#define	WP_MSG_9 "Changing to Read Write protected\n"
#define	WP_MSG_10 "Wrong password or access denied\n"
#define	WP_UNKNOWN "Error, can not determine the state of the medium\n"
#define	WP_ERROR   "Error, write protect operation failed\n"

/*
 * Condition to be checked for a device
 */
#define	CHECK_TYPE_NOT_CDROM		1
#define	CHECK_DEVICE_NOT_READY		2
#define	CHECK_DEVICE_NOT_WRITABLE	4
#define	CHECK_NO_MEDIA			8
#define	CHECK_MEDIA_IS_NOT_WRITABLE	0x10
#define	CHECK_MEDIA_IS_NOT_BLANK	0x20
#define	CHECK_MEDIA_IS_NOT_ERASABLE	0x40
#define	CHECK_DEVICE_IS_CD_WRITABLE	0x100
#define	CHECK_DEVICE_IS_DVD_WRITABLE	0x200
#define	CHECK_DEVICE_IS_DVD_READABLE	0x400

#define	INQUIRY_DATA_LENGTH		96
#define	DVD_CONFIG_SIZE			0x20

int uscsi_error;	/* used for debugging failed uscsi */

/* fdisk related structures */

struct fdisk_part {
	uint8_t    bootid;   /* Bootable? (Active/Inactive) */
	uint8_t    systid; /* OS type */
	uint32_t   relsect; /* Beginning of partition */
	uint32_t   numsect;
};

struct fdisk_info {
	struct fdisk_part part[FD_NUMPART];
};

typedef struct device {
	char		*d_node;
	char		*d_name;
	int		d_fd;
	uchar_t		*d_inq;
} device_t;

#ifdef __cplusplus
}
#endif

#endif /* _RMFORMAT_H */
