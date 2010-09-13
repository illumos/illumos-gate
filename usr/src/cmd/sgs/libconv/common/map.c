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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * String conversion routines for mapfile related items.
 * These items are not ELF constructs. However, we have a need
 * to display them.
 */
#include	<stdio.h>
#include	<_conv.h>
#include	<map_msg.h>

const char *
conv_mapfile_version(Word version, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	static const Msg	versions[] = {
		MSG_VER_NONE,	MSG_VER_SYSV,	MSG_VER_SOLARIS
	};
#if MFV_NUM != (MFV_SOLARIS + 1)
#error "NT_NUM has grown. Update mapfile versions[]"
#endif
	static const conv_ds_msg_t ds_versions = {
	    CONV_DS_MSG_INIT(MFV_NONE, versions) };
	static const conv_ds_t	*ds[] = { CONV_DS_ADDR(ds_versions), NULL };

	return (conv_map_ds(ELFOSABI_NONE, EM_NONE, version, ds, fmt_flags,
	    inv_buf));
}
