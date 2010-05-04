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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/ib/ibtl/ibti_common.h>

kmutex_t	ibtl_part_attr_mutex;
ibt_status_t	(*ibtl_get_part_attr_cb)(datalink_id_t, ibt_part_attr_t *);
ibt_status_t	(*ibtl_get_all_part_attr_cb)(ibt_part_attr_t **, int *);

void
ibt_register_part_attr_cb(
    ibt_status_t (*get_part_attr)(datalink_id_t, ibt_part_attr_t *),
    ibt_status_t (*get_all_part_attr)(ibt_part_attr_t **, int *))
{
	mutex_enter(&ibtl_part_attr_mutex);
	ibtl_get_part_attr_cb = get_part_attr;
	ibtl_get_all_part_attr_cb = get_all_part_attr;
	mutex_exit(&ibtl_part_attr_mutex);
}

void
ibt_unregister_part_attr_cb(void)
{
	mutex_enter(&ibtl_part_attr_mutex);
	ibtl_get_part_attr_cb = NULL;
	ibtl_get_all_part_attr_cb = NULL;
	mutex_exit(&ibtl_part_attr_mutex);
}

ibt_status_t
ibt_get_part_attr(datalink_id_t linkid, ibt_part_attr_t *attr)
{
	ibt_status_t	status;

	mutex_enter(&ibtl_part_attr_mutex);
	if (ibtl_get_part_attr_cb != NULL)
		status = (*ibtl_get_part_attr_cb) (linkid, attr);
	else
		status = IBT_NO_SUCH_OBJECT;
	mutex_exit(&ibtl_part_attr_mutex);

	return (status);
}

ibt_status_t
ibt_get_all_part_attr(ibt_part_attr_t **attr, int *nparts)
{
	ibt_status_t	status;

	mutex_enter(&ibtl_part_attr_mutex);
	if (ibtl_get_all_part_attr_cb != NULL)
		status = (*ibtl_get_all_part_attr_cb) (attr, nparts);
	else {
		*attr = NULL;
		*nparts = 0;
		status = IBT_SUCCESS;
	}
	mutex_exit(&ibtl_part_attr_mutex);

	return (status);
}

ibt_status_t
ibt_free_part_attr(ibt_part_attr_t *attr, int nparts)
{
	if (nparts > 0)
		kmem_free(attr, sizeof (ibt_part_attr_t) * nparts);
	return (IBT_SUCCESS);
}
