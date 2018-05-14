/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _LIBPPT_H
#define	_LIBPPT_H

#include <sys/types.h>

#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int ppt_devpath_to_dev(const char *, char *, size_t);

extern nvlist_t *ppt_list_assigned(void);

extern nvlist_t *ppt_list(void);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPPT_H */
