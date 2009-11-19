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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FMEV_IMPL_H
#define	_FMEV_IMPL_H

/*
 * libfmevent - private implementation
 *
 * Note: The contents of this file are private to the implementation of
 * libfmevent and are subject to change at any time without notice.
 * This file is not delivered into /usr/include.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <errno.h>
#include <libuutil.h>
#include <libsysevent.h>
#include <fm/libfmevent.h>

#ifdef DEBUG
#define	ASSERT(x) (assert(x))
#else
#define	ASSERT(x)
#endif

struct fmev_hdl_cmn {
	uint32_t hc_magic;
	uint32_t hc_api_vers;
	void *(*hc_alloc)(size_t);
	void *(*hc_zalloc)(size_t);
	void (*hc_free)(void *, size_t);
};

struct fmev_hdl_cmn *fmev_shdl_cmn(fmev_shdl_t);

extern int fmev_api_init(struct fmev_hdl_cmn *);
extern int fmev_api_enter(struct fmev_hdl_cmn *, uint32_t);
extern void fmev_api_freetsd(void);
extern fmev_err_t fmev_seterr(fmev_err_t);
extern int fmev_shdl_valid(fmev_shdl_t);
extern fmev_t fmev_sysev2fmev(fmev_shdl_t, sysevent_t *sep, char **,
    nvlist_t **);

#ifdef __cplusplus
}
#endif

#endif /* _FMEV_IMPL_H */
