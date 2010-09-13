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

#ifndef	_VOLD_H
#define	_VOLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libhal.h>

typedef enum {
	EJECT,
	INSERT,
	REMOUNT,
	UNMOUNT,
	CLEAR_MOUNTS,
	CLOSETRAY
} action_t;

struct action_arg {
	action_t aa_action;	/* VOLUME_ACTION */
	char	*aa_symdev;	/* VOLUME_SYMDEV */
	char	*aa_name;	/* VOLUME_NAME */
	char	*aa_path;	/* special device in question (block) */
	char	*aa_rawpath;	/* special device in question (character) */
	char	*aa_type;	/* file system type */
	char	*aa_media;	/* type of media */
	char	*aa_partname;	/* iff a partition, partition name */
	char	*aa_mountpoint;	/* path this file system mounted on */
};

extern int rmm_debug;
extern boolean_t rmm_vold_actions_enabled;
extern boolean_t rmm_vold_mountpoints_enabled;

void vold_init(int argc, char **argv);
int vold_postprocess(LibHalContext *hal_ctx, const char *udi,
    struct action_arg *aap);
int vold_rmmount(int argc, char **argv);
int volrmmount(int argc, char **argv);
int volcheck(int argc, char **argv);

#ifdef	__cplusplus
}
#endif

#endif	/* _VOLD_H */
