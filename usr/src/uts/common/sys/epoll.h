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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_EPOLL_H
#define	_SYS_EPOLL_H

#include <sys/types.h>
#include <sys/poll.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef union epoll_data {
	void		*ptr;
	int		fd;
	uint32_t	u32;
	uint64_t	u64;
} epoll_data_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct epoll_event {
	uint32_t	events;		/* events */
	epoll_data_t	data;		/* user-specified data */
} epoll_event_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * Define the EPOLL* constants in terms of their poll(2)/poll(7) equivalents.
 * Note that the values match the equivalents in Linux to allow for any binary
 * compatibility layers to not need to translate them.
 */
#define	EPOLLIN		0x0001
#define	EPOLLPRI	0x0002
#define	EPOLLOUT	0x0004
#define	EPOLLRDNORM	0x0040
#define	EPOLLRDBAND	0x0080
#define	EPOLLWRNORM	0x0100
#define	EPOLLWRBAND	0x0200
#define	EPOLLMSG	0x0400		/* not used */
#define	EPOLLERR	0x0008
#define	EPOLLHUP	0x0010
#define	EPOLLRDHUP	0x2000

#define	EPOLLWAKEUP	(1UL << 29)	/* no meaning; silently ignored */
#define	EPOLLONESHOT	(1UL << 30)	/* translated to POLLONESHOT */
#define	EPOLLET		(1UL << 31)	/* translated to POLLET */

#define	EPOLL_CTL_ADD	1
#define	EPOLL_CTL_DEL	2
#define	EPOLL_CTL_MOD	3

#define	EPOLL_CLOEXEC	02000000

#if !defined(_KERNEL)

extern int epoll_create(int size);
extern int epoll_create1(int flags);
extern int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
extern int epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout);
extern int epoll_pwait(int epfd, struct epoll_event *events,
    int maxevents, int timeout, const sigset_t *sigmask);

#endif /* !_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EPOLL_H */
