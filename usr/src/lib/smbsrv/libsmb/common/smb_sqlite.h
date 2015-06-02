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

/*ARGSUSED*/
sqlite *
sqlite_open(const char *filename, int mode, char **errmsg)
{
	return (NULL);
}

/*ARGSUSED*/
void
sqlite_close(sqlite *db)
{
}

/*ARGSUSED*/
char *
sqlite_mprintf(const char *fmt, ...)
{
	return (NULL);
}

/*ARGSUSED*/
void
sqlite_freemem(void *p)
{
}

/*ARGSUSED*/
int
sqlite_compile(sqlite *db, const char *zSql, const char **pzTail,
    sqlite_vm **ppVm, char **pzErrmsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
void
sqlite_free_table(char **res)
{
}

/*ARGSUSED*/
int
sqlite_last_insert_rowid(sqlite *db)
{
	return (-1);
}

/*ARGSUSED*/
void
sqlite_busy_timeout(sqlite *db, int ms)
{
}

/*ARGSUSED*/
int
sqlite_get_table(sqlite *db, const char *zSql, char ***pazResult, int *pnRow,
    int *pnColumn, char **pzErrMsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_step(sqlite_vm *pVm, int *pN, const char ***pazValue,
    const char ***pazColName)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_exec(sqlite *db, const char *zSql, sqlite_callback xCallback, void *pArg,
    char **pzErrMsg)
{
	return (SQLITE_ERROR);
}

/*ARGSUSED*/
int
sqlite_finalize(sqlite_vm *pVm, char **pzErrMsg)
{
	return (SQLITE_ERROR);
}
#endif /* _LP64 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SMB_SQLITE_H */
