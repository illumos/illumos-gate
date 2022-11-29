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

#ifndef	_SMB_SQLITE_H
#define	_SMB_SQLITE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sqlite-sys/sqlite.h>

#ifdef _LP64
/*
 * We cannot make 64-bit version of libsqlite because the code
 * has some problems.
 */

sqlite *
sqlite_open(const char *filename __unused, int mode __unused,
    char **errmsg __unused)
{
	return (NULL);
}

void
sqlite_close(sqlite *db __unused)
{
}

char *
sqlite_mprintf(const char *fmt __unused, ...)
{
	return (NULL);
}

void
sqlite_freemem(void *p __unused)
{
}

int
sqlite_compile(sqlite *db __unused, const char *zSql __unused,
    const char **pzTail __unused, sqlite_vm **ppVm __unused,
    char **pzErrmsg __unused)
{
	return (SQLITE_ERROR);
}

void
sqlite_free_table(char **res __unused)
{
}

int
sqlite_last_insert_rowid(sqlite *db __unused)
{
	return (-1);
}

void
sqlite_busy_timeout(sqlite *db __unused, int ms __unused)
{
}

int
sqlite_get_table(sqlite *db __unused, const char *zSql __unused,
    char ***pazResult __unused, int *pnRow __unused,
    int *pnColumn __unused, char **pzErrMsg __unused)
{
	return (SQLITE_ERROR);
}

int
sqlite_step(sqlite_vm *pVm __unused, int *pN __unused,
    const char ***pazValue __unused, const char ***pazColName __unused)
{
	return (SQLITE_ERROR);
}

int
sqlite_exec(sqlite *db __unused, const char *zSql __unused,
    sqlite_callback xCallback __unused, void *pArg __unused,
    char **pzErrMsg __unused)
{
	return (SQLITE_ERROR);
}

int
sqlite_finalize(sqlite_vm *pVm __unused, char **pzErrMsg __unused)
{
	return (SQLITE_ERROR);
}
#endif /* _LP64 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SMB_SQLITE_H */
