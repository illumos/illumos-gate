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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBZFS_JNI_PROPERTY_H
#define	_LIBZFS_JNI_PROPERTY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function prototypes
 */

#include <jni.h>
#include <libzfs.h>

jobject zjni_get_default_property(JNIEnv *, zfs_prop_t);
jobject zjni_get_lineage(JNIEnv *, zfs_source_t);
jobjectArray zjni_get_Dataset_properties(JNIEnv *, zfs_handle_t *);
zfs_prop_t zjni_get_property_from_name(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_PROPERTY_H */
