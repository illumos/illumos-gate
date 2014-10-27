/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_MDB_H
#define	_EMLXS_MDB_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRIVER_NAME		"emlxs"

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/mdb_modapi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	MAX_FC_BRDS		256	/* Maximum # boards per system */

void emlxs_msgbuf_help();

int emlxs_msgbuf(uintptr_t base_addr, uint_t flags, int argc,
				const mdb_arg_t *argv);

void emlxs_dump_help();

int emlxs_dump(uintptr_t base_addr, uint_t flags, int argc,
				const mdb_arg_t *argv);

#ifdef	__cplusplus
}
#endif

#endif /* _EMLXS_MDB_H */
