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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_STROPTS_H
#define	_SYS_STROPTS_H

#include <sys/feature_tests.h>
#include <sys/types.h>
/*
 * For FMNAMESZ define.
 */
#include <sys/conf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Write options
 */
#define	SNDZERO		0x001		/* send a zero length message */
#define	SNDPIPE		0x002		/* send SIGPIPE on write and */
					/* putmsg if sd_werror is set */

/*
 * Read options
 */
#define	RNORM		0x000		/* read msg norm */
#define	RMSGD		0x001		/* read msg discard */
#define	RMSGN		0x002		/* read msg no discard */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	RMODEMASK	0x003		/* all above bits */
#endif

/*
 * These next three read options are added for the sake of
 * user-level transparency.  RPROTDAT will cause the stream head
 * to treat the contents of M_PROTO and M_PCPROTO message blocks
 * as data.  RPROTDIS will prevent the stream head from failing
 * a read with EBADMSG if an M_PROTO or M_PCPROTO message is on
 * the front of the stream head read queue.  Rather, the protocol
 * blocks will be silently discarded and the data associated with
 * the message (in linked M_DATA blocks), if any, will be delivered
 * to the user.  RPROTNORM sets the default behavior, where read
 * will fail with EBADMSG if an M_PROTO or M_PCPROTO are at the
 * stream head.
 */
#define	RPROTDAT	0x004		/* read protocol messages as data */
#define	RPROTDIS	0x008		/* discard protocol messages, but */
					/* read data portion */
#define	RPROTNORM	0x010

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	RPROTMASK	0x01c		/* all RPROT bits */

/*
 * The next read option is used so that a TPI aware module can tell the
 * stream head to not flush M_PCPROTO messages when processing a read side
 * flush. This will avoid problems where a flush removes a T_OK_ACK.
 */
#define	RFLUSHMASK	0x020		/* all RFLUSH bits */

#define	RFLUSHPCPROT	0x020		/* do not flush PCPROTOs */

#endif

/*
 * Error options
 */

/*
 * Error options to adjust the stream head error behavior with respect
 * to M_ERROR message for read and write side errors respectively.
 * The normal case is that the read/write side error is
 * persistent and these options allow the application or streams module/driver
 * to specify that errors are nonpersistent. In this case the error is cleared
 * after having been returned to read(), getmsg(), ioctl(), write(), putmsg(),
 * etc.
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	RERRNORM	0x001		/* Normal, persistent read errors */
#define	RERRNONPERSIST	0x002		/* Nonpersistent read errors */

#define	RERRMASK	(RERRNORM|RERRNONPERSIST)

#define	WERRNORM	0x004		/* Normal, persistent write errors */
#define	WERRNONPERSIST	0x008		/* Nonpersistent write errors */

#define	WERRMASK	(WERRNORM|WERRNONPERSIST)
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Flush options
 */

#define	FLUSHR		0x01		/* flush read queue */
#define	FLUSHW		0x02		/* flush write queue */
#define	FLUSHRW		0x03		/* flush both queues */
#define	FLUSHBAND	0x04		/* flush only band specified */
					/* in next byte */
/*
 * Copy options for M_SETOPS/SO_COPYOPT
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	ZCVMSAFE	0x01		/* safe to borrow file (segmapped) */
					/* pages instead of bcopy */
#define	ZCVMUNSAFE	0x02		/* unsafe to borrow file pages */
#define	COPYCACHED	0x04		/* copy should NOT bypass cache */
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * Events for which the SIGPOLL signal is to be sent.
 */
#define	S_INPUT		0x0001		/* any msg but hipri on read Q */
#define	S_HIPRI		0x0002		/* high priority msg on read Q */
#define	S_OUTPUT	0x0004		/* write Q no longer full */
#define	S_MSG		0x0008		/* signal msg at front of read Q */
#define	S_ERROR		0x0010		/* error msg arrived at stream head */
#define	S_HANGUP	0x0020		/* hangup msg arrived at stream head */
#define	S_RDNORM	0x0040		/* normal msg on read Q */
#define	S_WRNORM	S_OUTPUT
#define	S_RDBAND	0x0080		/* out of band msg on read Q */
#define	S_WRBAND	0x0100		/* can write out of band */
#define	S_BANDURG	0x0200		/* modifier to S_RDBAND, to generate */
					/* SIGURG instead of SIGPOLL */

/*
 * Flags for getmsg() and putmsg() syscall arguments.
 * "RS" stands for recv/send.  The system calls were originally called
 * recv() and send(), but were renamed to avoid confusion with the BSD
 * calls of the same name.  A value of zero will cause getmsg() to return
 * the first message on the stream head read queue and putmsg() to send
 * a normal priority message.
 *
 * Flags for strmakemsg() arguments (should define strmakemsg() flags).
 * Used to determine the message type of the control part of a message,
 * if RS_HIPRI, M_PCPROTO, else M_PROTO.
 */

#define	RS_HIPRI	0x01		/* send/recv high priority message */
#define	STRUIO_POSTPONE	0x08		/* postpone copyin() for struio() */

/*
 * Flags for getpmsg() and putpmsg() syscall arguments.
 */

/*
 * These are settable by the user and will be set on return
 * to indicate the priority of message received.
 */
#define	MSG_HIPRI	0x01		/* send/recv high priority message */
#define	MSG_ANY		0x02		/* recv any messages */
#define	MSG_BAND	0x04		/* recv messages from specified band */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * This is a private flag passed by libc to kernel to
 * identify that it is a XPG4_2 application. No
 * applications need to know about this flag.
 */
#define	MSG_XPG4	0x08
#endif

#ifdef _KERNEL

/*
 * Additional private flags for kstrgetmsg and kstrputmsg.
 * These must be bit-wise distinct from the above MSG flags.
 */
#define	MSG_IPEEK	0x10		/* Peek - don't remove the message */
#define	MSG_DISCARDTAIL	0x20		/* Discard tail if it doesn't fit */
#define	MSG_HOLDSIG	0x40		/* Ignore signals. */
#define	MSG_IGNERROR	0x80		/* Ignore stream head errors */
#define	MSG_DELAYERROR	0x100		/* Delay error check until we sleep */
#define	MSG_IGNFLOW	0x200		/* Ignore flow control */
#define	MSG_NOMARK	0x400		/* Do not read if message is marked */

#endif /* _KERNEL */

/*
 * Flags returned as value of getmsg() and getpmsg() syscall.
 */
#define	MORECTL		1		/* more ctl info is left in message */
#define	MOREDATA	2		/* more data is left in message */

/*
 * Define to indicate that all multiplexors beneath a stream should
 * be unlinked.
 */
#define	MUXID_ALL	(-1)

/*
 * Flag definitions for the I_ATMARK ioctl.
 */
#define	ANYMARK		0x01
#define	LASTMARK	0x02

/*
 *  Stream Ioctl defines
 */
#define	STR		('S'<<8)
/* (STR|000) in use */
#define	I_NREAD		(STR|01)
#define	I_PUSH		(STR|02)
#define	I_POP		(STR|03)
#define	I_LOOK		(STR|04)
#define	I_FLUSH		(STR|05)
#define	I_SRDOPT	(STR|06)
#define	I_GRDOPT	(STR|07)
#define	I_STR		(STR|010)
#define	I_SETSIG	(STR|011)
#define	I_GETSIG	(STR|012)
#define	I_FIND		(STR|013)
#define	I_LINK		(STR|014)
#define	I_UNLINK	(STR|015)
/* (STR|016) in use */
#define	I_PEEK		(STR|017)
#define	I_FDINSERT	(STR|020)
#define	I_SENDFD	(STR|021)

#if defined(_KERNEL)
#define	I_RECVFD	(STR|022)
#define	I_E_RECVFD	(STR|016)
#else	/* user level definition */
#define	I_RECVFD	(STR|016)	/* maps to kernel I_E_RECVFD */
#endif /* defined(_KERNEL) */

#define	I_SWROPT	(STR|023)
#define	I_GWROPT	(STR|024)
#define	I_LIST		(STR|025)
#define	I_PLINK		(STR|026)
#define	I_PUNLINK	(STR|027)
#define	I_ANCHOR	(STR|030)
#define	I_FLUSHBAND	(STR|034)
#define	I_CKBAND	(STR|035)
#define	I_GETBAND	(STR|036)
#define	I_ATMARK	(STR|037)
#define	I_SETCLTIME	(STR|040)
#define	I_GETCLTIME	(STR|041)
#define	I_CANPUT	(STR|042)
#define	I_SERROPT	(STR|043)
#define	I_GERROPT	(STR|044)
#define	I_ESETSIG	(STR|045)
#define	I_EGETSIG	(STR|046)

#define	__I_PUSH_NOCTTY	(STR|047)	/* push module, no cntrl tty */

/*
 * IOCTLs (STR|050) - (STR|055) are available for use.
 */

#define	_I_MUXID2FD	(STR|056)	/* Private: get a fd from a muxid */
#define	_I_INSERT	(STR|057)	/* Private: insert a module */
#define	_I_REMOVE	(STR|060)	/* Private: remove a module */
#define	_I_GETPEERCRED	(STR|061)	/* Private: get peer cred */
#define	_I_PLINK_LH	(STR|062)	/* Private: Layered Driver ioctl */
#define	_I_CMD		(STR|063) 	/* Private: send ioctl via M_CMD */

/*
 * User level ioctl format for ioctls that go downstream (I_STR)
 */
struct strioctl {
	int 	ic_cmd;			/* command */
	int	ic_timout;		/* timeout value */
	int	ic_len;			/* length of data */
	char	*ic_dp;			/* pointer to data */
};

#if defined(_SYSCALL32)

struct strioctl32 {
	int32_t 	ic_cmd;			/* command */
	int32_t		ic_timout;		/* timeout value */
	int32_t		ic_len;			/* length of data */
	caddr32_t	ic_dp;			/* pointer to data */
};

#endif /* _SYSCALL32 */

/*
 * Value for timeouts (ioctl, select) that denotes infinity
 */
#define	_INFTIM		-1
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	INFTIM		_INFTIM
#endif

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
/*
 * For _I_CMD: similar to strioctl, but with included buffer (to avoid copyin/
 * copyout from another address space).  NOTE: the size of this structure must
 * be less than libproc.h`MAXARGL for pr_ioctl() to handle it.
 */
#define	STRCMDBUFSIZE			2048
typedef struct strcmd {
	int 	sc_cmd;			/* ioctl command */
	int	sc_timeout;		/* timeout value (in seconds) */
	int	sc_len;			/* length of data */
	int	sc_pad;
	char	sc_buf[STRCMDBUFSIZE];	/* data buffer */
} strcmd_t;
#endif

/*
 * Stream buffer structure for putmsg and getmsg system calls
 */
struct strbuf {
	int	maxlen;		/* no. of bytes in buffer */
	int	len;		/* no. of bytes returned */
	caddr_t	buf;		/* pointer to data */
};

#if defined(_SYSCALL32)

struct strbuf32 {
	int32_t	maxlen;		/* no. of bytes in buffer */
	int32_t	len;		/* no. of bytes returned */
	caddr32_t buf;		/* pointer to data */
};
#endif /* _SYSCALL32 */

/*
 * Stream I_PEEK ioctl format
 */
struct strpeek {
	struct strbuf	ctlbuf;
	struct strbuf	databuf;
	t_uscalar_t	flags;
};

#if defined(_SYSCALL32)

struct strpeek32 {
	struct strbuf32	ctlbuf;
	struct strbuf32	databuf;
	uint32_t	flags;
};

#endif /* _SYSCALL32 */

/*
 * Stream I_FDINSERT ioctl format
 */
struct strfdinsert {
	struct strbuf	ctlbuf;
	struct strbuf	databuf;
	t_uscalar_t	flags;
	int		fildes;
	int		offset;
};

#if defined(_SYSCALL32)

struct strfdinsert32 {
	struct strbuf32	ctlbuf;
	struct strbuf32	databuf;
	uint32_t	flags;
	int32_t		fildes;
	int32_t		offset;
};

#endif /* _SYSCALL32 */

/*
 * Receive file descriptor structure
 */
#if defined(_KERNEL)

struct o_strrecvfd {	/* SVR3 syscall structure */
	int fd;
	o_uid_t uid;		/* always ushort */
	o_gid_t gid;
	char fill[8];
};

/*
 * Although EFT is enabled in the kernel we kept the following definition
 * to support an EFT application on a 4.0 non-EFT system.
 */
struct k_strrecvfd {	/* SVR4 expanded syscall interface structure */
	struct file *fp;
	uid_t uid;
	gid_t gid;
	char fill[8];
};

/*
 * Private _I_GETPEERCRED data.
 */

typedef struct k_peercred {
	cred_t	*pc_cr;
	pid_t	pc_cpid;
} k_peercred_t;

#endif	/* defined(_KERNEL) */

struct strrecvfd {
	int fd;
	uid_t uid;
	gid_t gid;
#if defined(_XPG4_2)
	char __fill[8];
#else
	char fill[8];
#endif
};


/*
 * For I_LIST ioctl.
 */
struct str_mlist {
	char l_name[FMNAMESZ+1];
};

struct str_list {
	int sl_nmods;
	struct str_mlist *sl_modlist;
};

#if defined(_SYSCALL32)

struct str_list32 {
	int32_t 	sl_nmods;
	caddr32_t 	sl_modlist;
};

#endif /* _SYSCALL32 */

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Private, for _I_INSERT/_I_REMOVE ioctl.
 */
struct strmodconf {
	int	pos;			/* Position to be inserted/removed. */
	caddr_t	mod_name;		/* Name of module. */
};

#if defined(_SYSCALL32)

struct strmodconf32 {
	int32_t		pos;
	caddr32_t	mod_name;
};

#endif /* _SYSCALL32 */
#endif /* (_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * For I_FLUSHBAND ioctl.  Describes the priority
 * band for which the operation applies.
 */
struct bandinfo {
	unsigned char	bi_pri;
	int		bi_flag;
};


/*
 * The argument for I_ESETSIG and I_EGETSIG ioctls.
 */
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
struct strsigset {
	pid_t		ss_pid;		/* pgrp if negative */
	int		ss_events;	/* S_ events */
};
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#ifdef	_XPG4_2
#ifdef	__PRAGMA_REDEFINE_EXTNAME

#pragma	redefine_extname putmsg		__xpg4_putmsg
#pragma	redefine_extname putpmsg	__xpg4_putpmsg

#else	/* __PRAGMA_REDEFINE_EXTNAME */

#define	putmsg	__xpg4_putmsg
#define	putpmsg	__xpg4_putpmsg

#endif	/* __PRAGMA_REDEFINE_EXTNAME */
#endif	/* _XPG4_2 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STROPTS_H */
