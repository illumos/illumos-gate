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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_INSTALLBOOT_H
#define	_INSTALLBOOT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/multiboot.h>
#include <sys/types.h>

enum ib_fs_types {
	TARGET_IS_UFS = 0,
	TARGET_IS_HSFS,
	TARGET_IS_ZFS
};

typedef struct _ib_device {
	char	*path;
	int	fd;
	uint8_t	type;
} ib_device_t;

typedef struct _ib_bootblock {
	char			*buf;
	char			*file;
	char			*extra;
	multiboot_header_t	*mboot;
	uint32_t		mboot_off;
	uint32_t		buf_size;
	uint32_t		file_size;
	uint32_t		extra_size;
} ib_bootblock_t;

typedef struct _ib_data {
	ib_device_t	device;
	ib_bootblock_t	bootblock;
} ib_data_t;

#define	is_zfs(type)	(type == TARGET_IS_ZFS)

#define	BBLK_DATA_RSVD_SIZE	(15 * SECTOR_SIZE)
#define	BBLK_ZFS_EXTRA_OFF	(SECTOR_SIZE * 1024)

#ifdef	__cplusplus
}
#endif

#endif /* _INSTALLBOOT_H */
