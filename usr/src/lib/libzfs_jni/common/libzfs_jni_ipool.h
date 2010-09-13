/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef _LIBZFS_JNI_IPOOL_H
#define	_LIBZFS_JNI_IPOOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types
 */

/* Callback function for importable pool iteration */
typedef int (*zjni_ipool_iter_f)(nvlist_t *config, void *data);

/*
 * Function prototypes
 */

extern int zjni_ipool_iter(
    int argc, char **argv, zjni_ipool_iter_f func, void *data);
extern char *zjni_vdev_state_to_str(vdev_state_t state);
extern char *zjni_vdev_aux_to_str(vdev_aux_t aux);
extern char *zjni_pool_state_to_str(pool_state_t state);
extern char *zjni_pool_status_to_str(zpool_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_IPOOL_H */
