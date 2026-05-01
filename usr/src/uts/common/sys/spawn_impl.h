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
 * Copyright (c) 2011 by Delphix. All rights reserved.
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _SYS_SPAWN_IMPL_H
#define	_SYS_SPAWN_IMPL_H

/*
 * Private interface between libc and the kernel for the spawn(2) system
 * call that implements the posix_spawn(3C) family. libc marshals an entire
 * spawn - the attributes, file actions, argv and envp - into the structures
 * defined here, and the kernel parses them back out. None of it is a
 * committed interface and it is not packaged, so both sides can change in
 * lockstep. The public, application-visible posix_spawn definitions live in
 * <sys/spawn.h>.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/stdbool.h>
#include <sys/stdalign.h>
#include <sys/priocntl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ALL_POSIX_SPAWN_FLAGS			\
		(POSIX_SPAWN_RESETIDS |		\
		POSIX_SPAWN_SETPGROUP |		\
		POSIX_SPAWN_SETSIGDEF |		\
		POSIX_SPAWN_SETSIGMASK |	\
		POSIX_SPAWN_SETSCHEDPARAM |	\
		POSIX_SPAWN_SETSCHEDULER |	\
		POSIX_SPAWN_SETSID |		\
		POSIX_SPAWN_SETSIGIGN_NP |	\
		POSIX_SPAWN_NOSIGCHLD_NP |	\
		POSIX_SPAWN_WAITPID_NP |	\
		POSIX_SPAWN_NOEXECERR_NP)

/*
 * The exit status of a spawned child whose exec failed while
 * POSIX_SPAWN_NOEXECERR_NP was in effect, following the shell convention
 * for a command that was found but could not be executed.
 */
#define	SPAWN_NOEXECERR_STATUS	127

/*
 * Ensure that this struct retains the same layout in both 32- and 64-bit
 * binaries. It is passed to the kernel via spawn(2).
 */
typedef struct {
	int		sa_psflags;	/* POSIX_SPAWN_* flags */
	int		sa_priority;
	int		sa_schedpolicy;
	pid_t		sa_pgroup;
	sigset_t	sa_sigdefault;
	sigset_t	sa_sigignore;
	sigset_t	sa_sigmask;
} spawn_attr_t;
CTASSERT(sizeof (spawn_attr_t) == 64);
CTASSERT(alignof (spawn_attr_t) <= sizeof (uint32_t));

typedef enum file_action {
	FA_OPEN,
	FA_CLOSE,
	FA_DUP2,
	FA_CLOSEFROM,
	FA_CHDIR,
	FA_FCHDIR
} file_action_t;

/*
 * The scheduling attributes, as resolved by libc into the form that the
 * kernel child applies directly to itself. This struct has the same layout
 * in both 32- and 64-bit code.
 */
typedef enum kspawn_sched_op {
	KSCHED_PARMS = 1,
	KSCHED_PRIO
} kspawn_sched_op_t;

typedef struct kspawn_sched {
	kspawn_sched_op_t	ksched_op;
	union {
		pcparms_t	u_parms;
		pcprio_t	u_prio;
	} ksched_u;
} kspawn_sched_t;
CTASSERT(sizeof (kspawn_sched_t) == 40);
CTASSERT(alignof (kspawn_sched_t) <= sizeof (uint32_t));

#define	ksched_parms	ksched_u.u_parms
#define	ksched_prio	ksched_u.u_prio

typedef struct file_attr {
	struct file_attr *fa_next;	/* circular list of file actions */
	struct file_attr *fa_prev;
	file_action_t	fa_type;	/* type of action */
	char		*fa_path;	/* copied pathname for open() */
	uint_t		fa_pathsize;	/* size of fa_path[] array */
	int		fa_oflag;	/* oflag for open() */
	mode_t		fa_mode;	/* mode for open() */
	int		fa_filedes;	/* file descriptor for open()/close() */
	int		fa_newfiledes;	/* new file descriptor for dup2() */
} file_attr_t;

/*
 * We need to marshal all of the data that spawn(2) needs. We could pass
 * the spawn_attr_t directly but the set of file actions needs to be packed
 * into something that the kernel can quickly copy in and parse. There are
 * additional data items too such as the shell and PATH to use for
 * posix_spawnp(). We therefore pack everything into a new structure -
 * spawn_param_t. The following structures have the same layout in both 32-
 * and 64-bit code. Every *_off field is a byte offset measured from the start
 * of the trailing sp_data[]/sa_data[] array.
 */
typedef struct kfile_attr {
	uint32_t	kfa_len;	/* size of this record */
	file_action_t	kfa_type;	/* type of action */
	uint32_t	kfa_pathsize;	/* size of fa_path[] array (can be 0) */
	uint32_t	kfa_oflag;	/* oflag for open() */
	uint32_t	kfa_mode;	/* mode for open() */
	int32_t		kfa_filedes;	/* file descriptor for open()/close() */
	int32_t		kfa_newfiledes;	/* new file descriptor for dup2() */
	char		kfa_path[];	/* pathname for open()/chdir() */
} kfile_attr_t;
CTASSERT(sizeof (kfile_attr_t) == 28);
CTASSERT(alignof (kfile_attr_t) <= sizeof (uint32_t));

typedef struct spawn_param {
	uint32_t	sp_size;
	uint32_t	sp_datalen;
	uint32_t	sp_attr_off;	/* Offset of spawn_attr_t */
	uint32_t	sp_attr_len;	/* Length of spawn_attr_t */
	uint32_t	sp_fattr_off;	/* Offset of the first file attribute */
	uint32_t	sp_fattr_cnt;	/* Number of file attributes */
	uint32_t	sp_shell_off;	/* Offset of the shell */
	uint32_t	sp_shell_len;	/* Length of the shell */
	uint32_t	sp_path_off;	/* Offset of the PATH */
	uint32_t	sp_path_len;	/* Length of the PATH */
	uint32_t	sp_sched_off;	/* Offset of kspawn_sched_t */
	uint32_t	sp_sched_len;	/* Length of kspawn_sched_t */
	uint8_t		sp_data[];
} spawn_param_t;
CTASSERT(sizeof (spawn_param_t) == 48);

typedef struct spawn_args {
	uint32_t	sa_size;
	uint32_t	sa_datalen;
	uint32_t	sa_arg_off;	/* Offset of first argument */
	uint32_t	sa_arg_cnt;	/* Number of arguments */
	uint32_t	sa_env_off;	/* Offset of first environment entry */
	uint32_t	sa_env_cnt;	/* Number of environment entries */
	uint8_t		sa_data[];
} spawn_args_t;
CTASSERT(sizeof (spawn_args_t) == 24);

#ifdef _KERNEL

#include <sys/model.h>
#include <sys/vnode.h>

typedef struct kspawn_param {
	/*
	 * The parent/child handshake. The child sets ksp_complete (with
	 * ksp_error) under ksp_lock once it has applied the spawn and tried
	 * the exec, then signals ksp_cv to wake the waiting parent.
	 */
	bool		ksp_complete;
	int		ksp_error;
	kmutex_t	ksp_lock;
	kcondvar_t	ksp_cv;
	/*
	 * On entry, the program path copied in from the caller. On success,
	 * the path the child actually exec'd, which for posix_spawnp() or the
	 * shell fallback may differ. Audited by the parent.
	 */
	char		ksp_path[MAXPATHLEN];
	/*
	 * Whether to gather the audit detail below. The parent sets it from
	 * its own audit state before the child runs. The child cannot test
	 * its own, since exec resets the per-thread audit flag.
	 */
	bool		ksp_audit;
	/*
	 * Attributes of the exec'd file, for the audit attribute token.
	 */
	struct vattr	ksp_vattr;
	bool		ksp_have_vattr;
	/*
	 * When non-NULL, the exact vector the child exec'd, as ksp_argc
	 * NUL-terminated strings; audited in place of the caller's argv,
	 * which it matches except for the shell fallback. The parent frees it.
	 */
	char		*ksp_argv;
	uint_t		ksp_argc;
	size_t		ksp_argvsz;
	/*
	 * Marshalled spawn attributes and file actions to apply.
	 */
	spawn_param_t	*ksp_param;
	/*
	 * Marshalled argument and environment vectors for exec.
	 */
	spawn_args_t	*ksp_args;
	/*
	 * Data model of the parent, used to read the marshalled data.
	 */
	model_t		ksp_parent_model;
	/*
	 * Lowest fd named by a closefrom() action, or INT_MAX if none. Set
	 * rom pre-scanning the file actions. The child copies the parent's fd
	 * table only below this.
	 */
	int		ksp_closefrom;
	/*
	 * Source fds of dup2/fchdir actions which must survive the fd-table
	 * copy even when they lie at or above ksp_closefrom.
	 */
	int		*ksp_reffds;
	uint_t		ksp_nreffds;
} kspawn_param_t;

extern void spawn_main(void *);
extern void spawn_complete(kspawn_param_t *, int);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPAWN_IMPL_H */
