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

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _sys_stropts_h
#define	_sys_stropts_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Read options
 */
#define RNORM	0			/* read msg norm */
#define RMSGD	1			/* read msg discard */
#define RMSGN	2			/* read msg no discard */

/*
 * Flush options
 */

#define FLUSHR	1			/* flush read queue */
#define FLUSHW	2			/* flush write queue */
#define FLUSHRW	3			/* flush both queues */

/*
 * Events for which to be sent SIGPOLL signal
 */
#define S_INPUT		001		/* regular priority msg on read Q */
#define S_HIPRI		002		/* high priority msg on read Q */
#define S_OUTPUT	004		/* write Q no longer full */
#define S_MSG		010		/* signal msg at front of read Q */

/*
 * Flags for recv() and send() syscall arguments
 */
#define RS_HIPRI	1		/* send/recv high priority message */

/*
 * Flags returned as value of recv() syscall
 */
#define MORECTL		1		/* more ctl info is left in message */
#define MOREDATA	2		/* more data is left in message */

#ifndef FMNAMESZ
#define	FMNAMESZ	8
#endif

#include <sys/ioccom.h>

/*
 *  Stream Ioctl defines
 */
#define I_NREAD		_IOR('S',01,int)
#define I_PUSH		_IOWN('S',02,FMNAMESZ+1)
#define I_POP		_IO('S',03)
#define I_LOOK		_IORN('S',04,FMNAMESZ+1)
#define I_FLUSH		_IO('S',05)
#define I_SRDOPT	_IO('S',06)
#define I_GRDOPT	_IOR('S',07,int)
#define I_STR		_IOWR('S',010,struct strioctl)
#define I_SETSIG	_IO('S',011)
#define I_GETSIG	_IOR('S',012,int)
#define I_FIND		_IOWN('S',013,FMNAMESZ+1)
#define I_LINK		_IO('S',014)
#define I_UNLINK	_IO('S',015)
#define I_PEEK		_IOWR('S',017,struct strpeek)
#define I_FDINSERT	_IOW('S',020,struct strfdinsert)
#define I_SENDFD	_IO('S',021)
#define I_RECVFD	_IOR('S',022,struct strrecvfd)
#define I_PLINK		_IO('S',023)
#define I_PUNLINK	_IO('S',024)


/*
 * User level ioctl format for ioctl that go downstream I_STR 
 */
struct strioctl {
	int 	ic_cmd;			/* command */
	int	ic_timout;		/* timeout value */
	int	ic_len;			/* length of data */
	char	*ic_dp;			/* pointer to data */
};


/*
 * Value for timeouts (ioctl, select) that denotes infinity
 */
#define INFTIM		-1


/*
 * Stream buffer structure for send and recv system calls
 */
struct strbuf {
	int	maxlen;			/* no. of bytes in buffer */
	int	len;			/* no. of bytes returned */
	char	*buf;			/* pointer to data */
};


/* 
 * stream I_PEEK ioctl format
 */

struct strpeek {
	struct strbuf ctlbuf;
	struct strbuf databuf;
	long	      flags;
};

/*
 * stream I_FDINSERT ioctl format
 */
struct strfdinsert {
	struct strbuf ctlbuf;
	struct strbuf databuf;
	long	      flags;
	int	      fildes;
	int	      offset;
};


/*
 * receive file descriptor structure
 */
struct strrecvfd {
	int fd;
	unsigned short uid;
	unsigned short gid;
	char fill[8];
};

#endif /* !_sys_stropts_h */
