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

#ifndef	_SYS_DEVCACHE_H
#define	_SYS_DEVCACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>

#ifdef	_KERNEL

/*
 * Handle reference to a registered file
 */
typedef struct __nvf_handle *nvf_handle_t;

/*
 * Registration descriptor for a cache file within /etc/devices
 *
 * path			- cache file path path
 * unpack_list		- when reading, called to unpack nvlist
 * pack_list		- when writing, called to pack nvlist
 * list_free		- free data contained within list
 * write_complete	- called when write is completed
 */
typedef struct nvf_ops {
	char		*nvfr_cache_path;
	int		(*nvfr_unpack_nvlist)(nvf_handle_t, nvlist_t *, char *);
	int		(*nvfr_pack_list)(nvf_handle_t, nvlist_t **);
	void		(*nvfr_list_free)(nvf_handle_t);
	void		(*nvfr_write_complete)(nvf_handle_t);
} nvf_ops_t;

/*
 * Client interfaces
 */

nvf_handle_t	nvf_register_file(nvf_ops_t *);
int		nvf_read_file(nvf_handle_t);
void		nvf_wake_daemon(void);
void		nvf_error(const char *, ...);
char		*nvf_cache_name(nvf_handle_t);
krwlock_t	*nvf_lock(nvf_handle_t);
list_t		*nvf_list(nvf_handle_t);
void		nvf_mark_dirty(nvf_handle_t);
int		nvf_is_dirty(nvf_handle_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVCACHE_H */
