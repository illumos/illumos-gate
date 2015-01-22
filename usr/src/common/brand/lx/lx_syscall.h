/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#ifndef	_LX_SYSCALL_H
#define	_LX_SYSCALL_H

#include <sys/lx_brand.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The br_scall_args field of lx_lwp_data is going to be populated with
 * pointers to structs. The types of these structs should be defined in this
 * header file.  These are Linux specific arguments to system calls that don't
 * exist in illumos. Each section should be labelled with which system call it
 * belongs to.
 */

/* arguments for waitpid(2) */
/* see comments in usr/src/lib/brand/lx/lx_brand/common/wait.c */
#define	LX_WNOTHREAD	0x20000000 /* Do not wait on siblings' children */
#define	LX_WALL		0x40000000 /* Wait on all children */
#define	LX_WCLONE	0x80000000 /* Wait only on clone children */
typedef struct lx_waitid_args {
	int waitid_flags;
} lx_waitid_args_t;

/* For arch_prctl(2) */
#define	LX_ARCH_SET_GS	0x1001
#define	LX_ARCH_SET_FS	0x1002
#define	LX_ARCH_GET_FS	0x1003
#define	LX_ARCH_GET_GS	0x1004


#ifdef	__cplusplus
}
#endif

#endif	/* _LX_SYSCALL_H */
