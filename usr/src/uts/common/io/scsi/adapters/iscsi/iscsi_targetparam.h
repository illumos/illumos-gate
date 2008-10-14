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

#ifndef _ISCSI_TARGETPARAM_H
#define	_ISCSI_TARGETPARAM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iscsi_targetparam_entry {
	uint32_t target_oid;
	uchar_t	 target_name[ISCSI_MAX_NAME_LEN];
	struct iscsi_targetparam_entry *next;
} iscsi_targetparam_entry_t;

typedef struct iscsi_targetparams {
	krwlock_t target_list_lock;
	iscsi_targetparam_entry_t *target_list;
} iscsi_targetparams_t;


void iscsi_targetparam_init();
void iscsi_targetparam_cleanup();
iscsi_targetparam_entry_t *iscsi_targetparam_get_next_entry(
    iscsi_targetparam_entry_t *ref_entry);
uint32_t iscsi_targetparam_get_oid(uchar_t *name);
uchar_t *iscsi_targetparam_get_name(uint32_t oid);
int	iscsi_targetparam_remove_target(uint32_t oid);
void iscsi_targetparam_list_dump();
void iscsi_targetparam_lock_list(krw_t type);
void iscsi_targetparam_unlock_list();

#ifdef __cplusplus
}
#endif

#endif /* _ISCSI_TARGETPARAM_H */
