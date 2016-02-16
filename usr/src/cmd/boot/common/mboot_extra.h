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

#ifndef	_MBOOT_EXTRA_H
#define	_MBOOT_EXTRA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <sys/types.h>
#include "bblk_einfo.h"

/* multiboot header needs to be located in the first 32KB. */
#define	MBOOT_SCAN_SIZE		(32 * 1024)

/* multiboot header AOUT_KLUDGE flag. */
#define	BB_MBOOT_AOUT_FLAG	(0x00010000)

/* Extra header preceeding the payloads at the end of the bootblock. */
typedef struct _bb_extra_header {
	uint32_t	size;
	uint32_t	checksum;
} bb_header_ext_t;

uint32_t compute_checksum(char *, uint32_t);
bblk_einfo_t *find_einfo(char *, uint32_t);
int find_multiboot(char *, uint32_t, uint32_t *);
void add_einfo(char *, char *, bblk_hs_t *, uint32_t);
int compare_bootblocks(char *, char *, char **);

#ifdef	__cplusplus
}
#endif

#endif /* _MBOOT_EXTRA_H */
