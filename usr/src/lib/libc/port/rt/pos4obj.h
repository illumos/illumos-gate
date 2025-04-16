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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 MNX Cloud, Inc.
 */

#ifndef	_POS4OBJ_H
#define	_POS4OBJ_H

/*
 * pos4obj.h - Header file for POSIX.4 related object names
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* flags used to indicate current state of open */
#define	DFILE_CREATE	0x01
#define	DFILE_OPEN	0x02
/* ALLOC_MEM 0x4 is deprecated, reuse this first */
#define	DFILE_MMAP	0x08
#define	PFILE_CREATE	0x10
#define	NFILE_CREATE	0x20
#define	MQDNP_MMAP	0x40

/* semaphore object types - used in constructing file name */
#define	SEM_DATA_TYPE	".SEMD"
#define	SEM_LOCK_TYPE	".SEML"

/* message queue object types - used in constructing file name */
#define	MQ_DATA_TYPE	".MQD"
#define	MQ_PERM_TYPE	".MQP"
#define	MQ_DSCN_TYPE	".MQN"
#define	MQ_LOCK_TYPE	".MQL"

/* shared memory object types - used in constructing file name */
#define	SHM_DATA_TYPE	".SHMD"
#define	SHM_LOCK_TYPE	".SHML"

/* functions defined related to object names in POSIX.4 */
extern	int	__pos4obj_lock(const char *, const char *);
extern	int	__pos4obj_unlock(const char *, const char *);
extern	int	__pos4obj_unlink(const char *, const char *);
extern	int	__pos4obj_open(const char *, char *, int, mode_t, int *);
extern	int	__pos4obj_check(const char *);

/* non-cancelable file operations */
int	__open_nc(const char *, int, mode_t);
int	__close_nc(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _POS4OBJ_H */
