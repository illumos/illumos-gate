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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MQUEUE_H
#define	_MQUEUE_H

#include <sys/feature_tests.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef void	*mqd_t;		/* opaque message queue descriptor */

struct mq_attr {
	long	mq_flags;	/* message queue flags */
	long	mq_maxmsg;	/* maximum number of messages */
	long	mq_msgsize;	/* maximum message size */
	long	mq_curmsgs;	/* number of messages currently queued */
	int	mq_pad[12];
};

/*
 * function prototypes
 */
#if	(_POSIX_C_SOURCE - 0 > 0) && (_POSIX_C_SOURCE - 0 <= 2)
#error	"POSIX Message Passing is not supported in POSIX.1-1990"
#endif
#include <sys/siginfo.h>
mqd_t	mq_open(const char *, int, ...);
int	mq_close(mqd_t);
int	mq_unlink(const char *);
int	mq_send(mqd_t, const char *, size_t, unsigned int);
int	mq_timedsend(mqd_t, const char *, size_t, unsigned int,
		const struct timespec *);
int	mq_reltimedsend_np(mqd_t, const char *, size_t, unsigned int,
		const struct timespec *);
ssize_t	mq_receive(mqd_t, char *, size_t, unsigned int *);
ssize_t	mq_timedreceive(mqd_t, char *_RESTRICT_KYWD, size_t,
		unsigned int *_RESTRICT_KYWD,
		const struct timespec *_RESTRICT_KYWD);
ssize_t	mq_reltimedreceive_np(mqd_t, char *_RESTRICT_KYWD, size_t,
		unsigned int *_RESTRICT_KYWD,
		const struct timespec *_RESTRICT_KYWD);
int	mq_notify(mqd_t, const struct sigevent *);
int	mq_getattr(mqd_t, struct mq_attr *);
int	mq_setattr(mqd_t, const struct mq_attr *_RESTRICT_KYWD,
		struct mq_attr *_RESTRICT_KYWD);

#ifdef	__cplusplus
}
#endif

#endif	/* _MQUEUE_H */
