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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _PR_TARGET_H
#define	_PR_TARGET_H

/*
 * Common defintiions for the pr_target.h test.
 */

#include <sys/file.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Our expectation is that the file descriptors will end up with the following
 * values.
 */
#define	PRT_NULL_FD		3
#define	PRT_NULL_OFLAG		O_RDWR
#define	PRT_NULL_GETFD		0

#define	PRT_CLOSE_FD		4

#define	PRT_ZERO_FD		5
#define	PRT_ZERO_OFLAG		O_WRONLY
#define	PRT_ZERO_GETFD		0

#define	PRT_DUP_FD		6
#define	PRT_DUP_OFLAG		PRT_NULL_OFLAG
#define	PRT_DUP_GETFD		PRT_NULL_GETFD

#define	PRT_CLOFORK_FD		7
#define	PRT_CLOFORK_OFLAG	PRT_NULL_OFLAG
#define	PRT_CLOFORK_GETFD	FD_CLOFORK

#define	PRT_DUP3_FD		8
#define	PRT_DUP3_OFLAG		PRT_ZERO_OFLAG
#define	PRT_DUP3_GETFD		(FD_CLOFORK | FD_CLOEXEC)

#ifdef __cplusplus
}
#endif

#endif /* _PR_TARGET_H */
