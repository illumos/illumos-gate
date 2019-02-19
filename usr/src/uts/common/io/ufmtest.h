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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _UFMTEST_H
#define	_UFMTEST_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/nvpair.h>
#include <sys/param.h>
#else
#include <sys/nvpair.h>
#include <sys/param.h>
#include <sys/types.h>
#endif /* _KERNEL */

#define	DDI_UFMTEST_DEV			"/dev/ufmtest"

#define	UFMTEST_IOC			('u' << 24) | ('f' << 16) | ('t' << 8)
#define	UFMTEST_IOC_SET_FW		(UFMTEST_IOC | 1)
#define	UFMTEST_IOC_TOGGLE_FAILS	(UFMTEST_IOC | 2)
#define	UFMTEST_IOC_DO_UPDATE		(UFMTEST_IOC | 3)

typedef struct ufmtest_ioc_setfw {
	size_t	utsw_bufsz;
	caddr_t	utsw_buf;
} ufmtest_ioc_setfw_t;

#ifdef _KERNEL
typedef struct ufmtest_ioc_setfw32 {
	size32_t	utsw_bufsz;
	caddr32_t	utsw_buf;
} ufmtest_ioc_setfw32_t;
#endif /* _KERNEL */

/*
 * The argument for the UFMTEST_IOC_TOGGLE_FAILS ioctl is a bitfield
 * indicating which of the UFM entry points we want to simulate a failure on.
 */
typedef enum {
	UFMTEST_FAIL_GETCAPS	= 1 << 0,
	UFMTEST_FAIL_NIMAGES	= 1 << 1,
	UFMTEST_FAIL_FILLIMAGE	= 1 << 2,
	UFMTEST_FAIL_FILLSLOT	= 1 << 3
} ufmtest_failflags_t;

#define	UFMTEST_MAX_FAILFLAGS	(UFMTEST_FAIL_GETCAPS | UFMTEST_FAIL_NIMAGES | \
				UFMTEST_FAIL_FILLIMAGE | UFMTEST_FAIL_FILLSLOT)

typedef struct ufmtest_ioc_fails {
	ufmtest_failflags_t	utfa_flags;
} ufmtest_ioc_fails_t;

#ifdef __cplusplus
}
#endif

#endif	/* _UFMTEST_H */
