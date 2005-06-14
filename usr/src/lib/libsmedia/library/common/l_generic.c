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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * l_generic.c :
 *      This file contains all defined interfaces for libsm.so
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/smedia.h>
#include "../inc/rmedia.h"
#include "l_defines.h"

extern int32_t call_function(
			rmedia_handle_t *handle,  void *ip, char *func_name);
extern smedia_handle_t get_handle(int fd);
extern smedia_handle_t get_handle_from_path(const char *, int32_t, int32_t);
extern smedia_handle_t get_handle_from_fd(int32_t fd);
extern int32_t release_handle(rmedia_handle_t *);

int32_t
smedia_get_device_info(smedia_handle_t handle, struct smdevice_info *dev_info)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		dev_info, "_m_get_device_info");
	DPRINTF1("1....%s\n", dev_info->sm_product_name);
	dev_info->sm_version = SMDEVICE_INFO_V_1;

	return (ret_val);
}

int32_t
smedia_free_device_info(smedia_handle_t handle, struct smdevice_info *dev_info)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		dev_info, "_m_free_device_info");
	DPRINTF1("1....%s\n", dev_info->sm_product_name);
	dev_info->sm_version = SMDEVICE_INFO_V_1;

	return (ret_val);
}

int32_t
smedia_get_medium_property(smedia_handle_t handle, smmedium_prop_t *med_info)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		med_info, "_m_get_media_info");
	med_info->sm_version = SMMEDIA_PROP_V_1;

	return (ret_val);
}

int32_t
smedia_set_protection_status(smedia_handle_t handle, struct smwp_state *wp)
{
	int32_t ret_val;

	if (wp->sm_version != SMWP_STATE_V_1) {
		errno = ENOTSUP;
		return (-1);
	}
	ret_val = call_function((rmedia_handle_t *)handle,
		wp, "_m_set_media_status");
	return (ret_val);
}

int32_t
smedia_get_protection_status(smedia_handle_t handle, struct smwp_state *wp)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		wp, "_m_get_media_status");
	return (ret_val);
}

int32_t
smedia_format(smedia_handle_t handle, uint32_t flavor, uint32_t mode)
{
	struct format_flags ffl;
	int32_t ret_val;

	ffl.flavor = flavor;
	ffl.mode   = mode;
	ret_val = call_function((rmedia_handle_t *)handle,
		&ffl, "_m_media_format");
	return (ret_val);
}

size_t
smedia_raw_read(smedia_handle_t handle,
		diskaddr_t offset, caddr_t buffer, size_t size)
{

	struct raw_params r_p;
	int32_t ret_val;

	r_p.offset = (uint32_t)offset;
	r_p.buffer = buffer;
	r_p.size = size;

	ret_val = call_function((rmedia_handle_t *)handle, &r_p, "_m_raw_read");
	return (ret_val);
}

size_t
smedia_raw_write(smedia_handle_t handle,
		diskaddr_t offset, caddr_t buffer, size_t size)
{

	struct raw_params r_p;
	int32_t ret_val;

	r_p.offset = (uint32_t)offset;
	r_p.buffer = buffer;
	r_p.size = (uint32_t)size;

	ret_val = call_function((rmedia_handle_t *)handle,
		&r_p, "_m_raw_write");

	return (ret_val);
}

int32_t
smedia_check_format_status(smedia_handle_t handle)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		NULL, "_m_check_format_status");

	return (ret_val);
}

int32_t
smedia_reassign_block(smedia_handle_t handle, diskaddr_t block)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
		&block, "_m_reassign_block");
	return (ret_val);
}

int32_t
smedia_eject(smedia_handle_t handle)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle, NULL, "_m_eject");
	return (ret_val);
}

int32_t
smedia_format_track(smedia_handle_t handle, uint32_t trackno, uint32_t head,
						uint32_t density)
{
	int32_t ret_val;
	struct format_track ft;

	ft.track_no = (int32_t)trackno;
	ft.head = (int32_t)head;
	ft.flag = density;
	ret_val = call_function((rmedia_handle_t *)handle,
		&ft, "_m_media_format_track");
	return (ret_val);
}

smedia_handle_t
smedia_get_handle(int32_t fd)
{
	return (get_handle_from_fd(fd));
}

int32_t
smedia_release_handle(smedia_handle_t handle)
{
	return (release_handle((rmedia_handle_t *)handle));
}

int32_t
smedia_uscsi_cmd(smedia_handle_t handle, struct uscsi_cmd *cmd)
{
	int32_t ret_val;

	ret_val = call_function((rmedia_handle_t *)handle,
			cmd, "_m_uscsi_cmd");
	return (ret_val);
}
