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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_MDB_SHELL_H
#define	_MDB_SHELL_H

#include <mdb/mdb_io.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

struct mdb_cmd;

extern void mdb_shell_exec(char *);
extern void mdb_shell_pipe(char *);
extern void mdb_shell_source(char *);
extern void mdb_shell_pipe_source(char *);
extern void mdb_shell_source_run(void);
extern void mdb_shell_source_discard(void);
extern int mdb_shell_filter(const char *);
extern void mdb_shell_filter_pump(int, mdb_iob_t *);
extern void mdb_shell_filter_close(int);
extern void mdb_shell_producer(struct mdb_cmd *);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_SHELL_H */
