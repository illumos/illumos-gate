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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _FS_REPARSE_H
#define	_FS_REPARSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/time.h>
#include <sys/nvpair.h>
#else
#include <libnvpair.h>
#endif

#define	FS_REPARSE_TAG_STR		"@{REPARSE"
#define	FS_REPARSE_TAG_END_CHAR		'}'
#define	FS_REPARSE_TAG_END_STR		"}"
#define	FS_TOKEN_START_STR		"@{"
#define	FS_TOKEN_END_STR		"}"

#define	REPARSED			"svc:/system/filesystem/reparse:default"
#define	MAXREPARSELEN			MAXPATHLEN
#define	REPARSED_DOOR			"/var/run/reparsed_door"
#define	REPARSED_DOORCALL_MAX_RETRY	4

/*
 * This structure is shared between kernel code and user reparsed daemon.
 * The 'res_len' must be defined as int, and not size_t, for 32-bit reparsed
 * binary and 64-bit kernel code to work together.
 */
typedef struct reparsed_door_res {
	int	res_status;
	int	res_len;
	char	res_data[1];
} reparsed_door_res_t;

extern nvlist_t *reparse_init(void);
extern void reparse_free(nvlist_t *nvl);
extern int reparse_parse(const char *reparse_data, nvlist_t *nvl);
extern int reparse_validate(const char *reparse_data);

#ifdef _KERNEL
extern int reparse_kderef(const char *svc_type, const char *svc_data,
			char *buf, size_t *bufsz);
extern int reparse_vnode_parse(vnode_t *vp, nvlist_t *nvl);
#else
extern int reparse_add(nvlist_t *nvl, const char *svc_type,
			const char *svc_data);
extern int reparse_remove(nvlist_t *nvl, const char *svc_type);
extern int reparse_unparse(nvlist_t *nvl, char **stringp);
extern int reparse_create(const char *path, const char *data);
extern int reparse_delete(const char *path);
extern int reparse_deref(const char *svc_type, const char *svc_data,
			char *buf, size_t *bufsz);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _FS_REPARSE_H */
