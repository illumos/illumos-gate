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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Methods for ZFS to notify the iSCSI Target about which ZVOLs
 * need to be made available.
 */

#include <libiscsitgt.h>
#include <strings.h>
#include <errno.h>
#include <libscf.h>
#include <errcode.h>

#include "iscsitgt_impl.h"

/*
 * iscsitgt_zfs_share -- share a ZFS volume as an iSCSI target
 */
int
iscsitgt_zfs_share(const char *dataset)
{
	char		*str	= NULL;
	tgt_node_t	*n;
	int		code;

	tgt_buf_add_tag(&str, "create", Tag_Start);
	tgt_buf_add_tag(&str, "zfs", Tag_Start);
	tgt_buf_add(&str, "name", dataset);
	tgt_buf_add_tag(&str, "zfs", Tag_End);
	tgt_buf_add_tag(&str, "create", Tag_End);

	if ((n = tgt_door_call(str, SMF_TEMPORARY)) == NULL) {
		if (iscsitgt_svc_online() != 0) {
			errno = EPERM;
		} else {
			errno = EINVAL;
		}
		free(str);
		return (-1);
	}

	if (strcmp(n->x_name, XML_ELEMENT_ERROR) == 0 &&
	    tgt_find_value_int(n, XML_ELEMENT_CODE, &code) == True) {
		if (code == 1000) {
			free(str);
			tgt_node_free(n);
			return (0);
		} else {
			errno = (code == ERR_NO_PERMISSION) ? EPERM : EINVAL;
		}
	} else {
		errno = EINVAL;
	}
	free(str);
	tgt_node_free(n);
	return (-1);
}

/*
 * iscsitgt_zfs_unshare -- unshare a ZFS volume
 */
int
iscsitgt_zfs_unshare(const char *dataset)
{
	char		*str	= NULL;
	tgt_node_t	*n;
	int		code;

	tgt_buf_add_tag(&str, "delete", Tag_Start);
	tgt_buf_add_tag(&str, "zfs", Tag_Start);
	tgt_buf_add(&str, "name", dataset);
	tgt_buf_add_tag(&str, "zfs", Tag_End);
	tgt_buf_add_tag(&str, "delete", Tag_End);

	if ((n = tgt_door_call(str, SMF_TEMPORARY)) == NULL) {
		errno = EINVAL;
		free(str);
		return (-1);
	}

	if (strcmp(n->x_name, XML_ELEMENT_ERROR) == 0 &&
	    tgt_find_value_int(n, XML_ELEMENT_CODE, &code) == True) {
		if (code == 1000) {
			free(str);
			tgt_node_free(n);
			return (0);
		} else {
			errno = (code == ERR_NO_PERMISSION) ? EPERM : EINVAL;
		}
	} else {
		errno = EINVAL;
	}

	free(str);
	tgt_node_free(n);
	return (-1);
}

int
iscsitgt_zfs_is_shared(const char *dataset)
{
	char		*str	= NULL;
	tgt_node_t	*n;
	int		code;

	tgt_buf_add_tag(&str, "modify", Tag_Start);
	tgt_buf_add_tag(&str, "zfs", Tag_Start);
	tgt_buf_add(&str, "name", dataset);
	tgt_buf_add(&str, XML_ELEMENT_VALIDATE, XML_VALUE_TRUE);
	tgt_buf_add_tag(&str, "zfs", Tag_End);
	tgt_buf_add_tag(&str, "modify", Tag_End);

	if ((n = tgt_door_call(str, SMF_TEMPORARY)) == NULL) {
		errno = EINVAL;
		free(str);
		return (-1);
	}
	if (strcmp(n->x_name, XML_ELEMENT_ERROR) == 0 &&
	    tgt_find_value_int(n, XML_ELEMENT_CODE, &code) == True &&
	    code == 1000) {
		free(str);
		tgt_node_free(n);
		return (1);
	}

	free(str);
	tgt_node_free(n);
	return (0);
}
