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

#ifndef	_FMD_MSG_H
#define	_FMD_MSG_H

#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fault Management Daemon msg File Interfaces
 *
 * Note: The contents of this file are private to the implementation of the
 * Solaris system and FMD subsystem and are subject to change at any time
 * without notice.  Applications and drivers using these interfaces will fail
 * to run on future releases.  These interfaces should not be used for any
 * purpose until they are publicly documented for use outside of Sun.
 */

#define	FMD_MSG_VERSION	1	/* libary ABI interface version */

typedef struct fmd_msg_hdl fmd_msg_hdl_t;

typedef enum {
	FMD_MSG_ITEM_TYPE,
	FMD_MSG_ITEM_SEVERITY,
	FMD_MSG_ITEM_DESC,
	FMD_MSG_ITEM_RESPONSE,
	FMD_MSG_ITEM_IMPACT,
	FMD_MSG_ITEM_ACTION,
	FMD_MSG_ITEM_URL,
	FMD_MSG_ITEM_MAX
} fmd_msg_item_t;

extern void fmd_msg_lock(void);
extern void fmd_msg_unlock(void);

fmd_msg_hdl_t *fmd_msg_init(const char *, int);
void fmd_msg_fini(fmd_msg_hdl_t *);

extern int fmd_msg_locale_set(fmd_msg_hdl_t *, const char *);
extern const char *fmd_msg_locale_get(fmd_msg_hdl_t *);

extern int fmd_msg_url_set(fmd_msg_hdl_t *, const char *);
extern const char *fmd_msg_url_get(fmd_msg_hdl_t *);

extern char *fmd_msg_gettext_nv(fmd_msg_hdl_t *, const char *, nvlist_t *);
extern char *fmd_msg_gettext_id(fmd_msg_hdl_t *, const char *, const char *);

extern char *fmd_msg_getitem_nv(fmd_msg_hdl_t *,
    const char *, nvlist_t *, fmd_msg_item_t);

extern char *fmd_msg_getitem_id(fmd_msg_hdl_t *,
    const char *, const char *, fmd_msg_item_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_MSG_H */
