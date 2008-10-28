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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _MM_DB_H
#define	_MM_DB_H

#include <limits.h>
#include <sys/types.h>
#include <libpq-fe.h>

typedef struct mm_db_cfg mm_db_cfg_t;	/* database configuration */
struct mm_db_cfg {
	char		*mm_db_host;
	int		mm_db_port;
	char		*mm_db_user;
	char		*mm_db_name;
	char		*mm_db_passwd;
	int		mm_db_bool_oid;
	int		mm_db_timestamp_oid;
};

typedef struct mm_db mm_db_t;		/* database */
struct mm_db {
	PGconn		*mm_db_conn;	/* connection */
	PGresult	*mm_db_results;	/* query results */
	int		 mm_db_rval;	/* database return value */
	int		 mm_db_oid;	/* row oid, invalid if more than 1 */
	int		 mm_db_count;	/* number of rows changed */
	int		 mm_db_txn_blk; /* transaction block flag */
	mm_db_cfg_t	*mm_db_cfg;	/* database config */
	int		mm_db_fd;	/* database socket file descriptor */
	mms_list_t	mm_db_cmds;	/* linked list of all text sql */
					/* commands for this db's txn block */
	int		mm_db_has_list;
	int		mm_db_resending;
};

typedef enum mm_db_rval mm_db_rval_t;	/* database function return codes */
enum mm_db_rval {
	MM_DB_OK = 0,		/* operation successful */
	MM_DB_DATA,		/* data (tuples) rows */
	MM_DB_ERROR,		/* operation failed */
	MM_DB_DROPPED		/* database item dropped */
};

extern mm_db_rval_t mm_db_init(mm_db_t *);
extern mm_db_rval_t mm_db_connect(mm_db_t *);
extern mm_db_rval_t mm_db_reconnect(mm_db_t *);
extern boolean_t mm_db_connected(mm_db_t *);
extern void mm_db_disconnect(mm_db_t *);
extern mm_db_rval_t mm_db_exec_si(char *file, int line, mm_db_t *, char *, ...);
extern mm_db_rval_t mm_db_exec(char *file, int line, mm_db_t *, char *, ...);
extern mm_db_rval_t mm_db_txn_begin(mm_db_t *);
extern mm_db_rval_t mm_db_txn_rollback(mm_db_t *);
extern mm_db_rval_t mm_db_txn_savepoint_rollback(mm_db_t *, char *);
extern mm_db_rval_t mm_db_txn_savepoint(mm_db_t *, char *);
extern mm_db_rval_t mm_db_txn_release_savepoint(mm_db_t *, char *);
extern mm_db_rval_t mm_db_txn_commit(mm_db_t *);
extern mm_db_rval_t mm_db_create_attribute(mm_db_t *, char *, char *);
extern mm_db_rval_t mm_db_create_attribute2(mm_db_t *, char *, char *, char **);
extern mm_db_rval_t mm_db_delete_attribute(mm_db_t *, char *, char *);
extern mm_db_rval_t mm_db_upgrade(mm_db_t *db, int dbcurver, int dbnewver);
extern mm_db_rval_t mm_db_downgrade(mm_db_t *db, int dbcurver, int dbnewver);
extern int db_version_check(char *dbfile);
extern char *mm_db_sql_err_rsp(int, char *, char *, char *);
extern char *mm_db_escape_string(char *from);

#endif /* _MM_DB_H */
