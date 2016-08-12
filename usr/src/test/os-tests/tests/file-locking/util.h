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

#ifndef FLOCK_TEST_UTIL_H
#define	FLOCK_TEST_UTIL_H

#include <fcntl.h>
#include <sys/types.h>

#define	BAD_ARGS_MESSAGE	"Expected to receive 3 arguments, but found %d."
#define	BAD_MODE_MESSAGE	"Lock mode must be one of " \
	"\"shared\" or \"exclusive\""
#define	BAD_LOCK_MESSAGE	"Lock style must be one of " \
	"\"posix\", \"ofd\", or \"exclusive\""

typedef enum lock_style {
	LSTYLE_POSIX,
	LSTYLE_OFD,
	LSTYLE_FLOCK,
	LSTYLE_LAST
} lock_style_t;

extern boolean_t	LOG;

extern boolean_t	flock_nodata(int);

extern void	flock_block(int);
extern void	flock_alert(int);
extern void	flock_log(const char *, ...);
extern void	flock_reinit(struct flock *, int);

extern char		*flock_cmdname(int);
extern char		*flock_stylename(lock_style_t);
extern char		*flock_stylestr(lock_style_t);
extern lock_style_t	flock_styleenum(char *);

#endif /* FLOCK_TEST_UTIL_H */
