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
#ifndef _MMP_DEFS_H
#define	_MMP_DEFS_H


/*
 * mmp_def.h - private header file
 * This header contains the definitions used in the MMP protocol. The MMS
 * client will communicate with the MM using the MMP
 */

#include <stdio.h>
#include <sys/nvpair.h>

#include "mms.h"
#include "mgmt_util.h"
#include "mgmt_library.h"
#include "mgmt_media.h"

/*
 * All requests to the MM, including access to media, device management
 * functions, routine operational functions and MMS administration are done
 * using the MMP protocol.
 *
 * The MMP is made up of command type, object type and its attributes. MMP
 * supports a rich range of commands which fall into several different
 * categories such as attribute, cancel, create, deallocate, delete, goodbye,
 * locale, privilege, rename, show, accept, begin-end, cpattribute, cpscan,
 * cpshow, cpreset, eject, inject, mount, move, release, respond, shutdown
 * and unmount. The build_mmp() function only supports the attribute, create,
 * delete and show commands at this time.
 *
 * The MMS defines more than 40 types of objects that make up a media
 * environment. However this management library is only interested in the
 * following objects:-
 * drive, dm, drivegroup, drivegroupapplication, slottype, cartridge,
 * cartridgegroup, and cartridgegroupapplication
 */

int mms_client_handle_rsp(void *rsp);

void mmp_parse_lib_attr(mms_par_node_t *node, mms_acslib_t *lib);
void mmp_parse_lm_attr(mms_par_node_t *node, mms_lm_t *lm);
void mmp_parse_drive_attr(mms_par_node_t *node, mms_drive_t *drive);
void mmp_parse_dm_attr(mms_par_node_t *node, mms_dm_t *dm);

int mmp_parse_library_rsp(void *rsp, mms_list_t *list);
int mmp_parse_lm_rsp(void *rsp, mms_list_t *list);
int mmp_parse_drive_rsp(void *rsp, mms_list_t *list);
int mmp_parse_dm_rsp(void *rsp, mms_list_t *list);

int mmp_parse_app_rsp(void *rsp, mms_list_t *list);
int mmp_parse_rsp(void *resp, mms_list_t *list);

#endif /* _MMP_DEFS_H */
