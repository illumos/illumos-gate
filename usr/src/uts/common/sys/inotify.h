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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Header file to support for the inotify facility.  Note that this facility
 * is designed to be binary compatible with the Linux inotify facility; values
 * for constants here should therefore exactly match those found in Linux, and
 * this facility shouldn't be extended independently of Linux.
 */

#ifndef _SYS_INOTIFY_H
#define	_SYS_INOTIFY_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Events that can be explicitly requested on any inotify watch.
 */
#define	IN_ACCESS		0x00000001
#define	IN_MODIFY		0x00000002
#define	IN_ATTRIB		0x00000004
#define	IN_CLOSE_WRITE		0x00000008
#define	IN_CLOSE_NOWRITE	0x00000010
#define	IN_OPEN			0x00000020
#define	IN_MOVED_FROM		0x00000040
#define	IN_MOVED_TO		0x00000080
#define	IN_CREATE		0x00000100
#define	IN_DELETE		0x00000200
#define	IN_DELETE_SELF		0x00000400
#define	IN_MOVE_SELF		0x00000800

/*
 * Events that can be sent to an inotify watch -- requested or not.
 */
#define	IN_UNMOUNT		0x00002000
#define	IN_Q_OVERFLOW		0x00004000
#define	IN_IGNORED		0x00008000

/*
 * Flags that can modify an inotify event.
 */
#define	IN_ONLYDIR		0x01000000
#define	IN_DONT_FOLLOW		0x02000000
#define	IN_EXCL_UNLINK		0x04000000
#define	IN_MASK_ADD		0x20000000
#define	IN_ISDIR		0x40000000
#define	IN_ONESHOT		0x80000000

/*
 * Helpful constants.
 */
#define	IN_CLOSE		(IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
#define	IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO)
#define	IN_ALL_EVENTS		\
	(IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
	IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | \
	IN_DELETE | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF)

#define	IN_CHILD_EVENTS		\
	(IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
	IN_CLOSE_NOWRITE | IN_MODIFY | IN_OPEN)

/*
 * To assure binary compatibility with Linux, these values are fixed at their
 * Linux equivalents, not their native ones.
 */
#define	IN_CLOEXEC		02000000		/* LX_O_CLOEXEC */
#define	IN_NONBLOCK		04000			/* LX_O_NONBLOCK */

struct inotify_event {
	int32_t		wd;		/* watch descriptor */
	uint32_t	mask;		/* mask of events */
	uint32_t	cookie;		/* event association cookie, if any */
	uint32_t	len;		/* size of name field */
	char		name[];		/* optional NUL-terminated name */
};

/*
 * These ioctl values are specific to the native implementation; applications
 * shouldn't be using them directly, and they should therefore be safe to
 * change without breaking apps.
 */
#define	INOTIFYIOC		(('i' << 24) | ('n' << 16) | ('y' << 8))
#define	INOTIFYIOC_ADD_WATCH	(INOTIFYIOC | 1)	/* add watch */
#define	INOTIFYIOC_RM_WATCH	(INOTIFYIOC | 2)	/* remove watch */
#define	INOTIFYIOC_ADD_CHILD	(INOTIFYIOC | 3)	/* add child watch */
#define	INOTIFYIOC_ACTIVATE	(INOTIFYIOC | 4)	/* activate watch */

#ifndef _LP64
#ifndef _LITTLE_ENDIAN
#define	INOTIFY_PTR(type, name)	uint32_t name##pad; type *name
#else
#define	INOTIFY_PTR(type, name)	type *name; uint32_t name##pad
#endif
#else
#define	INOTIFY_PTR(type, name)	type *name
#endif

typedef struct inotify_addwatch {
	int inaw_fd;			/* open fd for object */
	uint32_t inaw_mask;		/* desired mask */
} inotify_addwatch_t;

typedef struct inotify_addchild {
	INOTIFY_PTR(char, inac_name);	/* pointer to name */
	int inac_fd;			/* open fd for parent */
} inotify_addchild_t;

#ifndef _KERNEL

extern int inotify_init(void);
extern int inotify_init1(int);
extern int inotify_add_watch(int, const char *, uint32_t);
extern int inotify_rm_watch(int, int);

#else

#define	IN_UNMASKABLE \
	(IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED | IN_ISDIR)

#define	IN_MODIFIERS \
	(IN_EXCL_UNLINK | IN_ONESHOT)

#define	IN_FLAGS \
	(IN_ONLYDIR | IN_DONT_FOLLOW | IN_MASK_ADD)

#define	IN_REMOVAL		(1ULL << 32)
#define	INOTIFYMNRN_INOTIFY	0
#define	INOTIFYMNRN_CLONE	1

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INOTIFY_H */
