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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Header file to support the signalfd facility. Note that this facility
 * is designed to be binary compatible with the Linux signalfd facility, modulo
 * the signals themselves; values for constants here should therefore exactly
 * match those found in Linux, and this facility shouldn't be extended
 * independently of Linux.
 */

#ifndef _SYS_SIGNALFD_H
#define	_SYS_SIGNALFD_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * To assure binary compatibility with Linux, these values are fixed at their
 * Linux equivalents, not their native ones.
 */
#define	SFD_CLOEXEC		02000000		/* LX_O_CLOEXEC */
#define	SFD_NONBLOCK		04000			/* LX_O_NONBLOCK */

/*
 * These ioctl values are specific to the native implementation; applications
 * shouldn't be using them directly, and they should therefore be safe to
 * change without breaking apps.
 */
#define	SIGNALFDIOC		(('s' << 24) | ('f' << 16) | ('d' << 8))
#define	SIGNALFDIOC_MASK	(SIGNALFDIOC | 1)	/* set mask */

typedef struct signalfd_siginfo {
	uint32_t ssi_signo;	/* signal from signal.h */
	int32_t  ssi_errno;	/* error from errno.h */
	int32_t  ssi_code;	/* signal code */
	uint32_t ssi_pid;	/* PID of sender */
	uint32_t ssi_uid;	/* real UID of sender */
	int32_t  ssi_fd;	/* File descriptor (SIGIO) */
	uint32_t ssi_tid;	/* unused */
	uint32_t ssi_band;	/* band event (SIGIO) */
	uint32_t ssi_overrun;	/* unused */
	uint32_t ssi_trapno;	/* trap number that caused signal */
	int32_t  ssi_status;	/* exit status or signal (SIGCHLD) */
	int32_t  ssi_int;	/* unused */
	uint64_t ssi_ptr;	/* unused */
	uint64_t ssi_utime;	/* user CPU time consumed (SIGCHLD) */
	uint64_t ssi_stime;	/* system CPU time consumed (SIGCHLD) */
	uint64_t ssi_addr;	/* address that generated signal */
	uint8_t  ssi_pad[48];	/* Pad size to 128 bytes to allow for */
				/* additional fields in the future. */
} signalfd_siginfo_t;

#ifndef _KERNEL

extern int signalfd(int, const sigset_t *, int);

#else

#define	SIGNALFDMNRN_SIGNALFD	0
#define	SIGNALFDMNRN_CLONE	1

/*
 * This holds the proc_t state for a process which is using signalfd.
 * Its presence and contents are protected by p_lock.
 */
typedef struct sigfd_proc_state {
	void (*sigfd_pollwake_cb)(void *, int);
	list_t sigfd_list;
} sigfd_proc_state_t;


extern void (*sigfd_exit_helper)();

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SIGNALFD_H */
