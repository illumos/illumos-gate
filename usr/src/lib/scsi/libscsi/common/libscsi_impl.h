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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSCSI_IMPL_H
#define	_LIBSCSI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libscsi.h>

#define	LIBSCSI_ENGINE_EXT	".so"

#define	LIBSCSI_ERRMSGLEN	512

typedef struct libscsi_engine_impl {
	const libscsi_engine_t *lsei_engine;
	void *lsei_dl_hdl;
	struct libscsi_engine_impl *lsei_next;
} libscsi_engine_impl_t;

typedef struct libscsi_action_impl {
	libscsi_hdl_t *lsai_hdl;
	uint_t lsai_flags;
	uint32_t lsai_timeout;
	uint8_t *lsai_cdb;
	size_t lsai_cdb_len;
	size_t lsai_data_len;
	size_t lsai_data_alloc;
	uint8_t *lsai_data;
	sam4_status_t lsai_status;
	size_t lsai_sense_len;
	uint8_t *lsai_sense_data;
	uint8_t lsai_buf[1];
} libscsi_action_impl_t;

struct libscsi_hdl {
	uint_t lsh_version;
	libscsi_errno_t lsh_errno;
	char lsh_errmsg[LIBSCSI_ERRMSGLEN];
	libscsi_engine_impl_t *lsh_engines;
	uint_t lsh_targets;
};

struct libscsi_target {
	const libscsi_engine_t *lst_engine;
	char *lst_vendor;
	char *lst_product;
	char *lst_revision;
	void *lst_priv;
	uint_t lst_mtbf_cdb;
	uint_t lst_mtbf_read;
	uint_t lst_mtbf_write;
	struct libscsi_hdl *lst_hdl;
};

#define	VERIFY(x)	((void)((x) || libscsi_assert(#x, __FILE__, __LINE__)))

#ifdef DEBUG
#define	ASSERT(x)	VERIFY(x)
#else
#define	ASSERT(x)
#endif

#define	LXOR(l, r)	(((l) != 0) ^ ((r) != 0))

extern int libscsi_assert(const char *, const char *, int);
extern int libscsi_get_inquiry(struct libscsi_hdl *, struct libscsi_target *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCSI_IMPL_H */
