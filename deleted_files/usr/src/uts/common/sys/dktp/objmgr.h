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
 * Copyright (c) 1992 Sun Microsystems, Inc.  All Rights Reserved.
 */

#ifndef _SYS_DKTP_OBJMGR_H
#define	_SYS_DKTP_OBJMGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int	objmgr_load_obj(char *);
extern void	objmgr_unload_obj(char *);
extern opaque_t objmgr_create_obj(char *);
extern int	objmgr_destroy_obj(char *);
extern int	objmgr_ins_entry(char *, opaque_t, char *);
extern int	objmgr_del_entry(char *);

#define	OBJNAMELEN	64
struct obj_entry {
	struct obj_entry *o_forw;
	struct obj_entry *o_back;
	char		*o_keyp;
	opaque_t	(*o_cfunc)();
	int		o_refcnt;
	int		o_modid;
	char		*o_modgrp;
};

#define	OBJ_MODGRP_SNGL	NULL

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_OBJMGR_H */
