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

#ifndef	_MDB_CMDBUF_H
#define	_MDB_CMDBUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_cmdbuf {
	char **cmd_history;	/* Circular array of history buffers */
	char *cmd_linebuf;	/* Temporary history for current buffer */
	char *cmd_buf;		/* Current line buffer */
	size_t cmd_linelen;	/* Maximum line length */
	size_t cmd_histlen;	/* Maximum history entries */
	size_t cmd_halloc;	/* Number of allocated history entries */
	size_t cmd_buflen;	/* Number of bytes in current line buffer */
	size_t cmd_bufidx;	/* Byte position in current line buffer */
	ssize_t cmd_hold;	/* Oldest history entry index */
	ssize_t cmd_hnew;	/* Newest history entry index */
	ssize_t cmd_hcur;	/* Current history entry index */
	ssize_t cmd_hlen;	/* Number of valid history buffers */
} mdb_cmdbuf_t;

#ifdef _MDB

extern void mdb_cmdbuf_create(mdb_cmdbuf_t *);
extern void mdb_cmdbuf_destroy(mdb_cmdbuf_t *);

extern const char *mdb_cmdbuf_accept(mdb_cmdbuf_t *);

extern int mdb_cmdbuf_caninsert(mdb_cmdbuf_t *, size_t);
extern int mdb_cmdbuf_atstart(mdb_cmdbuf_t *);
extern int mdb_cmdbuf_atend(mdb_cmdbuf_t *);

extern int mdb_cmdbuf_insert(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_backspace(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_delchar(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_fwdchar(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_backchar(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_transpose(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_home(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_end(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_fwdword(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_backword(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_killfwdword(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_killbackword(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_kill(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_reset(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_prevhist(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_nexthist(mdb_cmdbuf_t *, int);
extern int mdb_cmdbuf_findhist(mdb_cmdbuf_t *, int);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_CMDBUF_H */
