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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <syslog.h>
#include <unistd.h>
#include <libpq-fe.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <msg_sub.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include "mm_commands.h"
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_db_version.h"
#include <mms_cfg.h>

static char *_SrcFile = __FILE__;
static mm_db_rval_t db_connect(mm_db_t *db, char *database_name);
static mm_db_rval_t mm_db_oid_init(mm_db_t *db);
static void notice_receiver(void *, const PGresult *);
static char *mm_db_get_sql_cmd(char *fmt, va_list args);
static mm_db_rval_t mm_db_do_exec(char *file, int line, mm_db_t *db, int flag,
    char *fmt, va_list args);

/*
 * Initialize database, called once at startup.
 *
 * The MMS installation process must up-grade or down-grade the
 * postgres database to the same version as mm is expecting.
 */
mm_db_rval_t
mm_db_init(mm_db_t *db)
{
	int		exists;
	int		rows;
	int		row;
	int		try = 0;
	const int	retrys = 10;
	char		*initialized;
	int		db_version;


	mms_trace(MMS_DEVP, "inspecting database");

try_again:
	if (try >= retrys) {
		mms_trace(MMS_ERR, "unable to initialize, retries exceed");
		mms_trace(MMS_INFO,
		    "HINT: make sure mms:db is configured and running");
		return (MM_DB_ERROR);
	} else if (try > 1) {
		mms_trace(MMS_DEVP, "trying to initialize again %d", try);
	}
	try++;

	if (db_connect(db, "template1") != MM_DB_OK) {
		mms_trace(MMS_INFO, "can't connect to built-in database");
		sleep(2);
		goto try_again;
	}
	if (mm_db_exec(HERE, db, "SELECT datname FROM pg_database "
	    "WHERE datname = '%s';", db->mm_db_cfg->mm_db_name) != MM_DB_DATA) {
		mm_db_disconnect(db);
		mms_trace(MMS_ERR, "can't query for database");
		return (MM_DB_ERROR);
	}
	rows = PQntuples(db->mm_db_results);
	for (row = 0, exists = 0; row < rows && exists == 0; row++) {
		if (strcmp(PQgetvalue(db->mm_db_results, row, 0),
		    db->mm_db_cfg->mm_db_name) == 0) {
			mms_trace(MMS_DEVP, "found database %s",
			    db->mm_db_cfg->mm_db_name);
			exists = 1;
			break;
		}
	}
	mm_clear_db(&db->mm_db_results);
	if (exists == 0) {
		mms_trace(MMS_ERR, "database %s not found",
		    db->mm_db_cfg->mm_db_name);
		mms_trace(MMS_INFO, "HINT: run `mms.ksh data`");
		return (MM_DB_ERROR);
	}
	mm_db_disconnect(db);

	if (db_connect(db, db->mm_db_cfg->mm_db_name) != MM_DB_OK) {
		mms_trace(MMS_ERR, "can't connect to database %s",
		    db->mm_db_cfg->mm_db_name);
		mms_trace(MMS_INFO, "HINT: run `mms.ksh start`");
		return (MM_DB_ERROR);
	}
	if (mm_db_exec(HERE, db, "SELECT \"DBInitialized\",\"DBVersion\" "
	    "FROM \"MM\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR, "can't query internal mm object");
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		mms_trace(MMS_ERR, "database not completely initialized");
		mms_trace(MMS_INFO, "HINT: run `mms.ksh clean; mms.ksh data`");
		return (MM_DB_ERROR);
	}
	initialized = PQgetvalue(db->mm_db_results, 0, 0);
	if (strcmp(initialized, "true") != 0 &&
	    strcmp(initialized, "t") != 0) {
		mms_trace(MMS_ERR, "database not initialized");
		mms_trace(MMS_INFO, "HINT: run `mms.ksh clean; mms.ksh data`");
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	db_version = atoi(PQgetvalue(db->mm_db_results, 0, 1));
	if (db_version != MM_DB_VERSION) {
		if (db_version > MM_DB_VERSION) {
			mms_trace(MMS_ERR,
			    "down-grade database version from %d to %d",
			    db_version, MM_DB_VERSION);
		} else {
			mms_trace(MMS_ERR,
			    "up-grade database version from %d to %d",
			    db_version, MM_DB_VERSION);
		}
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	mms_trace(MMS_INFO, "mm and database version %d", MM_DB_VERSION);
	mm_clear_db(&db->mm_db_results);

	if (mm_db_oid_init(db) != MM_DB_OK) {
		mms_trace(MMS_ERR, "failed to read database OIDs");
		return (MM_DB_ERROR);
	}

	mm_db_disconnect(db);
	mms_trace(MMS_DEVP, "Initialization status - ok");
	return (MM_DB_OK);
}

/* Connect to the database. */
static mm_db_rval_t
db_connect(mm_db_t *db, char *database_name)
{
	mm_db_rval_t	rval;
	char		*sql_cmd;
	mm_db_cfg_t	*db_cfg = db->mm_db_cfg;

	sql_cmd = mms_strnew("host=%s port=%d dbname=%s user=%s",
	    db->mm_db_cfg->mm_db_host,
	    db->mm_db_cfg->mm_db_port,
	    database_name,
	    db->mm_db_cfg->mm_db_user);
	mms_trace(MMS_DEBUG, "connect command - %s", sql_cmd);
	if (db_cfg->mm_db_passwd) {
		mms_trace(MMS_DEBUG, "adding password");
		sql_cmd = mms_strapp(sql_cmd, " password=%s",
		    db_cfg->mm_db_passwd);
	}
	if (sql_cmd == NULL) {
		mms_trace(MMS_ERR, "Connect - unable to build command");
		return (MM_DB_ERROR);
	}
	db->mm_db_rval = PQstatus(db->mm_db_conn = PQconnectdb(sql_cmd));
	switch (db->mm_db_rval) {
	case CONNECTION_OK:
		if ((db->mm_db_fd = PQsocket(db->mm_db_conn)) < 0) {
			(void) mm_db_disconnect(db);
			rval = MM_DB_ERROR;
			mms_trace(MMS_DEVP,
			    "connect command status, no sockfd");
		} else {
			rval = MM_DB_OK;
			PQsetNoticeReceiver(db->mm_db_conn, notice_receiver,
			    NULL);
			mms_trace(MMS_DEVP, "connect command status - ok");
		}
		break;
	default:
		rval = MM_DB_ERROR;
		mms_trace(MMS_DEVP, "connect command status - %d, %s",
		    db->mm_db_rval, PQerrorMessage(db->mm_db_conn));
	}
	free(sql_cmd);
	return (rval);
}

/* Disconnect from the database. */
void
mm_db_disconnect(mm_db_t *db)
{
	if (db != NULL && db->mm_db_conn != NULL) {
		PQfinish(db->mm_db_conn);
		db->mm_db_conn = NULL;
		db->mm_db_fd = -1;
		mms_trace(MMS_DEVP, "disconnect");
	}
}

mm_db_rval_t
mm_db_resend(mm_db_t *db, char *sql_cmd) {
	int num_retry = 0;
	int rc;

	mm_char_list_t *node;
	mm_char_list_t *next;

	int		max_retry = 10;
	int		timeout = 3;

	char		*buf = NULL;

	/* MM has disconnected from the db */
	/* attempt to reconnect and resend all commands */
	/* in the currect transaction block for this db connection */

	if ((buf = mms_cfg_alloc_getvar(MMS_CFG_DB_RETRY, NULL)) == NULL) {
		/* report service configuration repoistory scf_error() */
		mms_trace(MMS_ERR, "using default-path, ssi path cfg error");
		max_retry = 50;
	} else {
		max_retry = atoi(buf);
		free(buf);
		buf = NULL;
	}
	if ((buf = mms_cfg_alloc_getvar(MMS_CFG_DB_TIMEOUT, NULL)) == NULL) {
		/* report service configuration repoistory scf_error() */
		mms_trace(MMS_ERR, "using default-path, ssi path cfg error");
		timeout = 3;
	} else {
		timeout = atoi(buf);
		free(buf);
		buf = NULL;
	}

	mms_trace(MMS_DEVP,
	    "mm_db_resend: "
	    "connection to db lost fd - %d, "
	    "attempt to reconnect, max retry = %d, timeout = %d",
	    db->mm_db_fd,
	    max_retry,
	    timeout);

	while (mm_db_reconnect(db) == MM_DB_ERROR) {
		num_retry ++;
		if (num_retry > max_retry) {
			mms_trace(MMS_ERR,
			    "mm_db_resend: "
			    "reconnect for db fd - %d failed "
			    "to many times %d, MM exiting",
			    db->mm_db_fd,
			    max_retry);
			exit(1);
		}
		mms_trace(MMS_ERR,
		    "mm_db_resend: "
		    "error reconnecting to db fd - %d"
		    ", retry %d",
		    db->mm_db_fd,
		    num_retry);
		sleep(timeout);
	}
	mms_trace(MMS_DEVP,
	    "mm_db_resend: "
	    "reconnect successful db fd -%d, "
	    "try to resend commands",
	    db->mm_db_fd);
	db->mm_db_resending = 1;
	if ((db->mm_db_txn_blk == 1) &&
	    (db->mm_db_has_list)) {
		mms_trace(MMS_ERR,
		    "mm_db_resend: "
		    "commands in list");
		/* have commands in list */
		for (node = mms_list_head(&db->mm_db_cmds);
		    node != NULL;
		    node = next) {
			next = mms_list_next(&db->mm_db_cmds, node);
			rc = mm_db_exec(HERE, db, node->text);
		}

	} else {
		mms_trace(MMS_ERR,
		    "mm_db_resend: "
		    "single command");
		/* don't have commands in list */
		/* resend sql_cmd */
		rc = mm_db_exec(HERE, db, sql_cmd);
	}
	mms_trace(MMS_DEVP,
	    "mm_db_resend: "
	    "reconnect successful db fd - %d, "
	    "commands sent",
	    db->mm_db_fd);
	db->mm_db_resending = 0;
	return (rc);

}

/*
 * Execute sql command with sensitive information.
 */
mm_db_rval_t
mm_db_exec_si(char *file, int line, mm_db_t *db, char *fmt, ...)
{
	va_list		args;
	int		rval;

	va_start(args, fmt);
	rval = mm_db_do_exec(file, line, db, 0, fmt, args);
	va_end(args);

	return (rval);
}

/*
 * Execute sql command.
 */
mm_db_rval_t
mm_db_exec(char *file, int line, mm_db_t *db, char *fmt, ...)
{
	va_list		args;
	int		rval;

	va_start(args, fmt);
	rval = mm_db_do_exec(file, line, db, 1, fmt, args);
	va_end(args);

	return (rval);
}

/*
 * Add sql command terminator if needed.
 */
static char *
mm_db_get_sql_cmd(char *fmt, va_list args)
{
	int		i;
	char		*sql_cmd;

	if ((sql_cmd = mms_vstrapp(NULL, fmt, args)) != NULL) {
		/* add sql command terminator if needed */
		for (i = strlen(sql_cmd) - 1; i >= 0; i--) {
			if (sql_cmd[i] == ';') {
				break;
			}
			if (isspace(sql_cmd[i]) == 0) {
				sql_cmd = mms_strapp(sql_cmd, ";");
				break;
			}
		}
	}
	return (sql_cmd);
}

/*
 * Execute synchronous sql command in auto-commit mode, no txn needed.
 * Multiple commands can be wrapped in transaction block.
 */
static mm_db_rval_t
mm_db_do_exec(char *file, int line, mm_db_t *db, int flag,
    char *fmt, va_list args)
{
	int		rval;
	char		*count;
	char		*sql_cmd;

	if ((sql_cmd = mm_db_get_sql_cmd(fmt, args)) == NULL) {
		mms_trace(MMS_ERR, "Exec %s:%d fd %d - unable to build command",
		    file, line, db->mm_db_fd);
		return (MM_DB_ERROR);
	}
	/* add this cmd to this db's cmd list */
	if (db->mm_db_has_list &&
	    db->mm_db_txn_blk &&
	    (db->mm_db_resending == 0)) {
		(void) mm_add_char(sql_cmd, &db->mm_db_cmds);
	}
	db->mm_db_results = PQexec(db->mm_db_conn, sql_cmd);
	if (flag) {
		mms_trace(MMS_DEVP, "Exec %s:%d fd %d - \n\n%s\n", file, line,
		    db->mm_db_fd, sql_cmd);
	} else {
		mms_trace(MMS_DEVP, "Exec %s:%d fd %d", file, line,
		    db->mm_db_fd);
	}
	db->mm_db_rval = PQresultStatus(db->mm_db_results);
	db->mm_db_oid = PQoidValue(db->mm_db_results);
	count = PQcmdTuples(db->mm_db_results);
	db->mm_db_count = count ? atoi(count) : 0;
	switch (db->mm_db_rval) {
	case PGRES_COMMAND_OK:
		rval = MM_DB_OK;
		mms_trace(MMS_DEVP, "Exec %s:%d fd %d status - ok (%d %d)",
		    file, line, db->mm_db_fd, db->mm_db_oid,
		    db->mm_db_count);
		mm_clear_db(&db->mm_db_results);
		break;
	case PGRES_TUPLES_OK:
		rval = MM_DB_DATA;
		mms_trace(MMS_DEVP,
		    "Exec %s:%d fd %d status - ok, data (%d %d)",
		    file, line, db->mm_db_fd, db->mm_db_oid,
		    db->mm_db_count);
		break;
	default:
		rval = MM_DB_ERROR;
		mms_trace(MMS_ERR, "Exec %s:%d fd %d status - %d, %s",
		    file, line, db->mm_db_fd, db->mm_db_rval,
		    PQerrorMessage(db->mm_db_conn));

		if ((db->mm_db_rval == 7) &&
		    ((strstr(PQerrorMessage(db->mm_db_conn),
		    "no connection to the server") != NULL) ||
		    (strstr(PQerrorMessage(db->mm_db_conn),
		    "terminating connection due "
		    "to administrator command") != NULL) ||
		    (strstr(PQerrorMessage(db->mm_db_conn),
		    "server closed the connection unexpectedly") != NULL))) {
			/* DB has disconnected, attempt to reconnect */
			/* and resend the entire transaction block */
			/* associated with this db fd */
			mm_clear_db(&db->mm_db_results);
			rval = mm_db_resend(db, sql_cmd);
			free(sql_cmd);
			return (rval);

		}
	}
	free(sql_cmd);
	return (rval);
}

/* Trace query execution notice and warning messages. */
static void
/* LINTED: void *arg is required arg in PQsetNoticeReceiver */
notice_receiver(void *arg, const PGresult *res)
{
	int		rval;

	rval = PQresultStatus(res);
	if (rval != 6) {
		mms_trace(MMS_DEVP, "Notice Receiver - %d, %s",
		    rval, PQresultErrorMessage(res));
	}
}


/* Get database oids for mms string conversions. */
static mm_db_rval_t
mm_db_oid_init(mm_db_t *db)
{
	char		*value;

	if (mm_db_exec(HERE, db, "SELECT OID FROM pg_type "
	    "WHERE typname = 'bool';") != MM_DB_DATA) {
		mms_trace(MMS_ERR, "boolean oid not found");
		return (MM_DB_ERROR);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR, "missing boolean oid");
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	value = PQgetvalue(db->mm_db_results, 0, 0);
	db->mm_db_cfg->mm_db_bool_oid = atoi(value);
	mm_clear_db(&db->mm_db_results);

	if (mm_db_exec(HERE, db, "SELECT OID FROM pg_type "
	    "WHERE typname = 'timestamp';") != MM_DB_DATA) {
		mms_trace(MMS_ERR, "timestamp oid not found");
		return (MM_DB_ERROR);
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mms_trace(MMS_ERR, "missing timestamp oid");
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	value = PQgetvalue(db->mm_db_results, 0, 0);
	db->mm_db_cfg->mm_db_timestamp_oid = atoi(value);
	mm_clear_db(&db->mm_db_results);
	return (MM_DB_OK);
}


/* Connect to database. */
mm_db_rval_t
mm_db_connect(mm_db_t *db)
{
	mms_trace(MMS_DEVP, "Connection");
	if (db_connect(db, db->mm_db_cfg->mm_db_name) != MM_DB_OK) {
		mms_trace(MMS_DEVP, "Connection status - failed to connect");
		return (MM_DB_ERROR);
	}
	mms_trace(MMS_DEVP, "Connection status - ok");

	return (MM_DB_OK);
}

/* Reconnect to the database. */
mm_db_rval_t
mm_db_reconnect(mm_db_t *db)
{
	if (db->mm_db_conn != NULL) {
		PQreset(db->mm_db_conn);
	} else if (mm_db_connect(db) != MM_DB_OK) {
		mms_trace(MMS_DEVP, "reconnect init failed");
		return (MM_DB_ERROR);
	}
	if (mm_db_connected(db) == B_TRUE) {
		return (MM_DB_OK);
	}
	mms_trace(MMS_DEVP, "reconnect failed");
	return (MM_DB_ERROR);
}

/* Determine if database connection exists. */
boolean_t
mm_db_connected(mm_db_t *db)
{
	if (db->mm_db_conn != NULL &&
	    PQstatus(db->mm_db_conn) == CONNECTION_OK) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/* Database transaction begin. */
mm_db_rval_t
mm_db_txn_begin(mm_db_t *db)
{
	int	rc;

	mms_trace(MMS_DEVP, "TXN begin");
	/* clear this db's cmd list */
	if (db->mm_db_has_list)
		mm_free_list(&db->mm_db_cmds);
	if ((rc = mm_db_exec(HERE, db, "BEGIN;")) == MM_DB_OK) {
		db->mm_db_txn_blk = 1;
		(void) mm_add_char("BEGIN;",
		    &db->mm_db_cmds);
	} else {
		db->mm_db_txn_blk = 0;
	}
	return (rc);
}

/* Database transaction rollback. */
mm_db_rval_t
mm_db_txn_rollback(mm_db_t *db)
{
	int	rc;
	mms_trace(MMS_DEVP, "TXN rollback");
	db->mm_db_txn_blk = 0;
	rc = mm_db_exec(HERE, db, "ROLLBACK;");
	/* clear this db's cmd list */
	if (db->mm_db_has_list)
		mm_free_list(&db->mm_db_cmds);
	return (rc);
}

/* Database transaction savepoint rollback. */
mm_db_rval_t
mm_db_txn_savepoint_rollback(mm_db_t *db, char *savepoint)
{
	if (db->mm_db_txn_blk) {
		mms_trace(MMS_DEVP, "TXN rollback to %s", savepoint);
		return (mm_db_exec(HERE, db, "ROLLBACK TO %s;", savepoint));
	}
	return (MM_DB_OK);
}

/* Database transaction savepoint. */
mm_db_rval_t
mm_db_txn_savepoint(mm_db_t *db, char *savepoint)
{
	if (db->mm_db_txn_blk) {
		mms_trace(MMS_DEVP, "TXN savepoint %s", savepoint);
		return (mm_db_exec(HERE, db, "SAVEPOINT %s;", savepoint));
	}
	return (MM_DB_OK);
}

/* Database transaction release savepoint. */
mm_db_rval_t
mm_db_txn_release_savepoint(mm_db_t *db, char *savepoint)
{
	int		rc;

	if (db->mm_db_txn_blk) {
		mms_trace(MMS_DEVP, "TXN release savepoint %s", savepoint);
		rc = mm_db_exec(HERE, db, "RELEASE SAVEPOINT %s;", savepoint);
		return (rc);
	}
	return (MM_DB_OK);
}

/* Database transaction commit. */
mm_db_rval_t
mm_db_txn_commit(mm_db_t *db)
{
	int		rc;
	mms_trace(MMS_DEVP, "TXN commit");
	db->mm_db_txn_blk = 0;
	rc = mm_db_exec(HERE, db, "COMMIT;");
	/* clear this db's cmd list */
	if (db->mm_db_has_list)
		mm_free_list(&db->mm_db_cmds);
	return (rc);
}

/* Add attribute (column) to object (table). */
mm_db_rval_t
mm_db_create_attribute(mm_db_t *db, char *objname, char *attribute)
{
	int		col;
	int		cols;
	int		rows;
	int		found;

	mms_trace(MMS_DEBUG, "mm_db_create_attribute");

	/* does this object allow user-defined attributes? */
	if (mm_db_exec(HERE, db, "SELECT * FROM \"SYSTEM_DEFINED\" "
	    "WHERE objname = '%s'", objname) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	rows = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);
	if (rows == 0) {
		/* user-defined attributes not allowed */
		return (MM_DB_OK);
	}
	/* does attribute already exist? */
	if (mm_db_exec(HERE, db,
	    "SELECT * FROM \"%s\"", objname) != MM_DB_DATA) {
		return (MM_DB_ERROR);
	}
	found = 0;
	cols = PQnfields(db->mm_db_results);
	for (col = 0; !found && col < cols; col++) {
		if (strcmp(PQfname(db->mm_db_results, col), attribute) == 0) {
			found = 1;
		}
	}
	mm_clear_db(&db->mm_db_results);
	if (found) {
		/* user-defined attributes already exists */
		return (MM_DB_OK);
	}
	/* add user-defined table column */
	if (mm_db_exec(HERE, db, "ALTER TABLE \"%s\" ADD \"%s\" text",
	    objname, attribute) != MM_DB_OK) {
		return (MM_DB_ERROR);
	}
	/* user-defined table column added */
	return (MM_DB_OK);
}

mm_db_rval_t
mm_db_create_attribute2(mm_db_t *db, char *objname,
    char *attribute, char **send_buf)
{
	int		col;
	int		cols;
	int		rows;
	int		found;

	/* does this object allow user-defined attributes? */
	if (mm_db_exec(HERE, db, "SELECT * FROM \"SYSTEM_DEFINED\" "
	    "WHERE objname = '%s'", objname) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	rows = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);
	if (rows == 0) {
		/* user-defined attributes not allowed */
		return (MM_DB_OK);
	}
	/* does attribute already exist? */
	if (mm_db_exec(HERE, db,
	    "SELECT * FROM \"%s\"", objname) != MM_DB_DATA) {
		return (MM_DB_ERROR);
	}
	found = 0;
	cols = PQnfields(db->mm_db_results);
	for (col = 0; !found && col < cols; col++) {
		if (strcmp(PQfname(db->mm_db_results, col), attribute) == 0) {
			found = 1;
		}
	}
	mm_clear_db(&db->mm_db_results);
	if (found) {
		/* user-defined attributes already exists */
		return (MM_DB_OK);
	}
	/* add user-defined table column */
	*send_buf = mms_strapp(*send_buf, "ALTER TABLE \"%s\" ADD \"%s\" text;",
	    objname, attribute);

	/* user-defined table column added */
	return (MM_DB_OK);
}

/* Delete attribute (column) from object (table). */
mm_db_rval_t
mm_db_delete_attribute(mm_db_t *db, char *objname, char *attribute)
{
	int		row;
	int		rows;
	int		col;
	int		cols;
	int		found;


	mms_trace(MMS_INFO, "mm_db_delete_attribute");

	/* does object allow user-defined attributes? */
	if (mm_db_exec(HERE, db, "SELECT * FROM \"SYSTEM_DEFINED\" "
	    "WHERE objname = '%s'", objname) != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return (MM_DB_ERROR);
	}
	rows = PQntuples(db->mm_db_results);
	mm_clear_db(&db->mm_db_results);
	if (rows == 0) {
		/* user-defined attributes not allowed */
		return (MM_DB_OK);
	}
	/* does object attribute exists? */
	if (mm_db_exec(HERE, db,
	    "SELECT * FROM \"%s\"", objname) != MM_DB_DATA) {
		return (MM_DB_ERROR);
	}
	found = 0;
	cols = PQnfields(db->mm_db_results);
	for (col = 0; !found && col < cols; col++) {
		if (strcmp(PQfname(db->mm_db_results, col), attribute) == 0) {
			found = 1;
		}
	}
	mm_clear_db(&db->mm_db_results);
	if (!found) {
		/* user-defined attribute not found */
		return (MM_DB_OK);
	}
	/* is attribute part of base data model? */
	if (mm_db_exec(HERE, db, "SELECT attribute FROM \"SYSTEM_DEFINED\" "
	    "WHERE attribute = '%s'", attribute) != MM_DB_DATA) {
		return (MM_DB_ERROR);
	}
	found = 0;
	rows = PQntuples(db->mm_db_results);
	for (row = 0; !found && row < rows; row++) {
		if (strcmp(PQgetvalue(db->mm_db_results, row, 0),
		    attribute) == 0) {
			found = 1;
		}
	}
	mm_clear_db(&db->mm_db_results);
	if (found) {
		/* attribute is part of base data model */
		return (MM_DB_OK);
	}
	/* remove user-defined object attribute */
	if (mm_db_exec(HERE, db, "ALTER TABLE \"%s\" DROP \"%s\"",
	    objname, attribute) != MM_DB_OK) {
		return (MM_DB_ERROR);
	}
	/* user-defined object attribute removed */
	return (MM_DB_DROPPED);
}

/*
 * This is hard coded without database access because we are probably in a
 * database transaction block that has failed and thus an additional database
 * message catalog lookup would fail.
 */
char *
mm_db_sql_err_rsp(int mm_db_status, char *mm_db_error_message,
    char *lang, char *taskid)
{
	char		*dberrmsg;
	char		*response;
	char		args[100];
	char		*p;


	/*
	 * Replace ', ", ... with multi-character mms_escape sequences not
	 * processed by the parser.
	 */
	if ((dberrmsg = mms_strpar_escape_sequence(mm_db_error_message))
	    == NULL) {
		return (NULL);
	}
	/*
	 * Remove last new line from database error message(s). Leave new
	 * lines in-between multiline database error messages.
	 */
	if (p = strrchr(dberrmsg, '\n')) {
		*p = '\0';
	}
	/*
	 * Build command error response with loctext.
	 */
	snprintf(args, sizeof (args), "\"status\" \"%d\"", mm_db_status);
	if (taskid && lang) {
		response = mms_strnew(RESPONSE_ERROR_TEXT, taskid,
		    ECLASS_INTERNAL,
		    EDATABASE, MESS_MANUFACTURER, MESS_MODEL, 5001,
		    args, lang, dberrmsg);
	} else {
		response = mms_strnew(RESPONSE_UNACCEPTABLE);
	}
	free(dberrmsg);

	return (response);
}

char *
mm_db_escape_string(char *from)
{
	char		*to;
	int		len;

	len = strlen(from);
	if ((to = (char *)malloc((len * 2) + 1)) == NULL) {
		mms_trace(MMS_ERR, "mms_escape string out of memory");
		return (NULL);
	}
	PQescapeString(to, from, len);
	if (strcmp(from, to) != 0) {
		mms_trace(MMS_DEVP,
		    "mms_escape string\nfrom - %s\nto - %s", from, to);
	}
	return (to);
}
