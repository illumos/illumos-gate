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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_MDB_H
#define	_EMLXS_MDB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/mdb_modapi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	DRIVER_NAME		"emlxs"
#define	MAX_FC_BRDS		256	/* Maximum # boards per system */

void emlxs_msgbuf_help();

int emlxs_msgbuf(uintptr_t base_addr, uint_t flags, int argc,
				const mdb_arg_t *argv);

#ifdef	__cplusplus
}
#endif

#endif /* _EMLXS_MDB_H */
