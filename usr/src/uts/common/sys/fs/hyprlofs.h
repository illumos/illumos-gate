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
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 */

#ifndef	_SYS_FS_HYPRLOFS_H
#define	_SYS_FS_HYPRLOFS_H

#include <sys/param.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * hyprlofs ioctl numbers.
 */
#define	HYPRLOFS_IOC	('H' << 8)

#define	HYPRLOFS_ADD_ENTRIES	(HYPRLOFS_IOC | 1)
#define	HYPRLOFS_RM_ENTRIES	(HYPRLOFS_IOC | 2)
#define	HYPRLOFS_RM_ALL		(HYPRLOFS_IOC | 3)

#ifdef _KERNEL
typedef struct {
	caddr32_t	hle_path;
	uint_t		hle_plen;
	caddr32_t	hle_name;
	uint_t		hle_nlen;
} hyprlofs_entry32_t;

typedef struct {
	caddr32_t	hle_entries;
	uint_t		hle_len;
} hyprlofs_entries32_t;

#endif /* _KERNEL */

typedef struct {
	const char	*hle_path;
	uint_t		hle_plen;
	const char	*hle_name;
	uint_t		hle_nlen;
} hyprlofs_entry_t;

typedef struct {
	hyprlofs_entry_t	*hle_entries;
	uint_t			hle_len;
} hyprlofs_entries_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HYPRLOFS_H */
