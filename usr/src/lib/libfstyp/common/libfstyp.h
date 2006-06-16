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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBFSTYP_H
#define	_LIBFSTYP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * libfstyp: filesystem identification library
 */
#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libnvpair.h>

typedef struct fstyp_handle *fstyp_handle_t;

enum {
	FSTYP_ERR_OK = 0,
	FSTYP_ERR_NO_MATCH,		/* no matches */
	FSTYP_ERR_MULT_MATCH,		/* multiple matches */
	FSTYP_ERR_HANDLE,		/* invalid handle */
	FSTYP_ERR_OFFSET,		/* invalid or unsupported offset */
	FSTYP_ERR_NO_PARTITION,		/* partition not found */
	FSTYP_ERR_NOP,			/* no such operation */
	FSTYP_ERR_DEV_OPEN,		/* cannot open device */
	FSTYP_ERR_IO,			/* I/O error */
	FSTYP_ERR_NOMEM,		/* out of memory */
	FSTYP_ERR_MOD_NOT_FOUND,	/* requested fs module not found */
	FSTYP_ERR_MOD_DIR_OPEN,		/* cannot open directory */
	FSTYP_ERR_MOD_OPEN,		/* cannot open module */
	FSTYP_ERR_MOD_VERSION,		/* invalid module version */
	FSTYP_ERR_MOD_INVALID,		/* invalid module */
	FSTYP_ERR_NAME_TOO_LONG		/* fs name exceeds FSTYPSZ */
};

/*
 * generic attribute names
 *
 * gen_clean (DATA_TYPE_BOOLEAN_VALUE)
 * gen_guid (DATA_TYPE_STRING)
 * gen_version (DATA_TYPE_STRING)
 * gen_volume_label (DATA_TYPE_STRING)
 */

int fstyp_init(int fd, off64_t offset, char *module_dir,
    fstyp_handle_t *handle);
void fstyp_fini(fstyp_handle_t handle);
int fstyp_ident(fstyp_handle_t handle, const char *fsname,
    const char **ident);
int fstyp_get_attr(fstyp_handle_t handle, nvlist_t **attr);
int fstyp_dump(fstyp_handle_t handle, FILE *fout, FILE *ferr);
const char *fstyp_strerror(fstyp_handle_t handle, int error);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFSTYP_H */
