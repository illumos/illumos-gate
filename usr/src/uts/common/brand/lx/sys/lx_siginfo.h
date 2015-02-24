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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _LX_SIGINFO_H
#define	_LX_SIGINFO_H

#include <sys/lx_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * lx_siginfo_t lsi_code values
 *
 *	LX_SI_ASYNCNL:	Sent by asynch name lookup completion
 *	LX_SI_DETHREAD:	Sent by execve() killing subsidiary threads
 *	LX_SI_SIGIO:	Sent by queued SIGIO
 *	LX_SI_ASYNCIO:	Sent by asynchronous I/O completion
 *	LX_SI_MESGQ:	Sent by real time message queue state change
 *	LX_SI_TIMER:	Sent by timer expiration
 *	LX_SI_QUEUE:	Sent by sigqueue
 *	LX_SI_USER:	Sent by kill, sigsend, raise, etc.
 *	LX_SI_KERNEL:	Sent by kernel
 *	LX_SI_CODE_NOT_EXIST: Error code. When translating from Linux to
 *	    illumos errors, if there is no translation available, this value
 *	    should be used. This value should have no meaning as an si_code in
 *	    illumos or Linux.
 *
 * At present, LX_SI_ASYNCNL, LX_SI_DETHREAD, and LX_SI_SIGIO are unused by
 * BrandZ.
 */
#define	LX_SI_CODE_NOT_EXIST	(-61)
#define	LX_SI_ASYNCNL		(-60)
#define	LX_SI_DETHREAD		(-7)
#define	LX_SI_TKILL		(-6)
#define	LX_SI_SIGIO		(-5)
#define	LX_SI_ASYNCIO		(-4)
#define	LX_SI_MESGQ		(-3)
#define	LX_SI_TIMER		(-2)
#define	LX_SI_QUEUE		(-1)
#define	LX_SI_USER		(0)
#define	LX_SI_KERNEL		(0x80)

#define	LX_SI_MAX_SIZE		128
#define	LX_SI_PAD_SIZE_32	((LX_SI_MAX_SIZE / sizeof (int)) - 3)
#define	LX_SI_PAD_SIZE_64	((LX_SI_MAX_SIZE / sizeof (int)) - 4)

#if defined(_LP64)
/*
 * Because of the odd number (3) of ints before the union, we need to account
 * for the smaller padding needed on x64 due to the union being offset to an 8
 * byte boundary.
 */
#define	LX_SI_PAD_SIZE		LX_SI_PAD_SIZE_64
#else
#define	LX_SI_PAD_SIZE		LX_SI_PAD_SIZE_32
#endif

typedef struct lx_siginfo {
	int lsi_signo;
	int lsi_errno;
	int lsi_code;
	union {
		int _pad[LX_SI_PAD_SIZE];

		struct {
			pid_t _pid;
			lx_uid16_t _uid;
		} _kill;

		struct {
			uint_t _timer1;
			uint_t _timer2;
		} _timer;

		struct {
			pid_t _pid;
			lx_uid16_t _uid;
			union sigval _sigval;
		} _rt;

		struct {
			pid_t _pid;
			lx_uid16_t _uid;
			int _status;
			clock_t _utime;
			clock_t _stime;
		} _sigchld;

		struct {
			void *_addr;
		} _sigfault;

		struct {
			int _band;
			int _fd;
		} _sigpoll;
	} _sifields;
} lx_siginfo_t;

#if defined(_KERNEL) && defined(_SYSCALL32_IMPL)
/*
 * 64-bit kernel view of the 32-bit "lx_siginfo_t" object.
 */
#pragma pack(4)
typedef struct lx_siginfo32 {
	int lsi_signo;
	int lsi_errno;
	int lsi_code;
	union {
		int _pad[LX_SI_PAD_SIZE_32];

		struct {
			pid32_t _pid;
			lx_uid16_t _uid;
		} _kill;

		struct {
			uint_t _timer1;
			uint_t _timer2;
		} _timer;

		struct {
			pid32_t _pid;
			lx_uid16_t _uid;
			union sigval32 _sigval;
		} _rt;

		struct {
			pid32_t _pid;
			lx_uid16_t _uid;
			int _status;
			clock32_t _utime;
			clock32_t _stime;
		} _sigchld;

		struct {
			caddr32_t _addr;
		} _sigfault;

		struct {
			int _band;
			int _fd;
		} _sigpoll;
	} _sifields;
} lx_siginfo32_t;
#pragma pack()
#endif /* defined(_KERNEL) && defined(_SYSCALL32_IMPL) */

#define	lsi_pid		_sifields._kill._pid
#define	lsi_uid		_sifields._kill._uid
#define	lsi_status	_sifields._sigchld._status
#define	lsi_utime	_sifields._sigchld._utime
#define	lsi_stime	_sifields._sigchld._stime
#define	lsi_value	_sifields._rt._sigval
#define	lsi_int		_sifields._rt._sigval.sivalx_int
#define	lsi_ptr		_sifields._rt._sigval.sivalx_ptr
#define	lsi_addr	_sifields._sigfault._addr
#define	lsi_band	_sifields._sigpoll._band
#define	lsi_fd		_sifields._sigpoll._fd

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_SIGINFO_H */
