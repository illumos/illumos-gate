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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FORTH_H
#define	_FORTH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "ctfstabs.h"

/*
 * The macros emitted for structs/unions and enums differ, but their
 * formatting in the input file and construction method is roughly the same.
 * If any of the ops return -1, the remainder of the type being processed is
 * skipped, and an error is signaled to the main portion of ctfstabs.
 */
typedef struct fth_type_ops {
	/*
	 * Called to start a definition.
	 */
	int (*fto_header)(ctf_id_t);

	/*
	 * When a specific-member request for a struct or union type is
	 * encountered, this op will be invoked for each requested member.
	 */
	int (*fto_members)(char *, char *);

	/*
	 * Invoked when the current open definition is to be finished.
	 */
	int (*fto_trailer)(void);
} fth_type_ops_t;

/* forth.c */
extern char *fth_curtype;

/* fth_struct.c */
extern fth_type_ops_t fth_enum_ops;
extern fth_type_ops_t fth_struct_ops;

#ifdef __cplusplus
}
#endif

#endif /* _FORTH_H */
