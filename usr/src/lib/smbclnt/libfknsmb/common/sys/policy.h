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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent, Inc. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_POLICY_H
#define	_SYS_POLICY_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>

#ifdef	__cplusplus
extern "C" {
#endif

int secpolicy_fs_allowed_mount(const char *);
int secpolicy_vnode_owner(const cred_t *, uid_t);
int secpolicy_vnode_access2(const cred_t *, vnode_t *, uid_t, mode_t, mode_t);
int secpolicy_vnode_setattr(cred_t *, struct vnode *, struct vattr *,
    const struct vattr *, int, int (void *, int, cred_t *), void *);
int secpolicy_vnode_setdac(const cred_t *, uid_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_POLICY_H */
