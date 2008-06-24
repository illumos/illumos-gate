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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Database related utility routines
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <sys/sid.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <assert.h>
#include <sys/u8_textprep.h>

#include "idmapd.h"
#include "adutils.h"
#include "string.h"
#include "idmap_priv.h"
#include "schema.h"
#include "nldaputils.h"


static idmap_retcode sql_compile_n_step_once(sqlite *, char *,
		sqlite_vm **, int *, int, const char ***);
static idmap_retcode ad_lookup_one(lookup_state_t *, idmap_mapping *,
		idmap_id_res *);
static idmap_retcode lookup_localsid2pid(idmap_mapping *, idmap_id_res *);
static idmap_retcode lookup_cache_name2sid(sqlite *, const char *,
		const char *, char **, char **, idmap_rid_t *, int *);


#define	EMPTY_NAME(name)	(*name == 0 || strcmp(name, "\"\"") == 0)

#define	DO_NOT_ALLOC_NEW_ID_MAPPING(req)\
		(req->flag & IDMAP_REQ_FLG_NO_NEW_ID_ALLOC)

#define	AVOID_NAMESERVICE(req)\
		(req->flag & IDMAP_REQ_FLG_NO_NAMESERVICE)

#define	IS_EPHEMERAL(pid)	(pid > INT32_MAX && pid != SENTINEL_PID)

#define	LOCALRID_MIN	1000


typedef enum init_db_option {
	FAIL_IF_CORRUPT = 0,
	REMOVE_IF_CORRUPT = 1
} init_db_option_t;

/*
 * Data structure to store well-known SIDs and
 * associated mappings (if any)
 */
typedef struct wksids_table {
	const char	*sidprefix;
	uint32_t	rid;
	const char	*winname;
	int		is_wuser;
	uid_t		pid;
	int		is_user;
	int		direction;
} wksids_table_t;

/*
 * Thread specfic data to hold the database handles so that the
 * databaes are not opened and closed for every request. It also
 * contains the sqlite busy handler structure.
 */

struct idmap_busy {
	const char *name;
	const int *delays;
	int delay_size;
	int total;
	int sec;
};


typedef struct idmap_tsd {
	sqlite *db_db;
	sqlite *cache_db;
	struct idmap_busy cache_busy;
	struct idmap_busy db_busy;
} idmap_tsd_t;



static const int cache_delay_table[] =
		{ 1, 2, 5, 10, 15, 20, 25, 30,  35,  40,
		50,  50, 60, 70, 80, 90, 100};

static const int db_delay_table[] =
		{ 5, 10, 15, 20, 30,  40,  55,  70, 100};


static pthread_key_t	idmap_tsd_key;

void
idmap_tsd_destroy(void *key)
{

	idmap_tsd_t	*tsd = (idmap_tsd_t *)key;
	if (tsd) {
		if (tsd->db_db)
			(void) sqlite_close(tsd->db_db);
		if (tsd->cache_db)
			(void) sqlite_close(tsd->cache_db);
		free(tsd);
	}
}

int
idmap_init_tsd_key(void)
{
	return (pthread_key_create(&idmap_tsd_key, idmap_tsd_destroy));
}



idmap_tsd_t *
idmap_get_tsd(void)
{
	idmap_tsd_t	*tsd;

	if ((tsd = pthread_getspecific(idmap_tsd_key)) == NULL) {
		/* No thread specific data so create it */
		if ((tsd = malloc(sizeof (*tsd))) != NULL) {
			/* Initialize thread specific data */
			(void) memset(tsd, 0, sizeof (*tsd));
			/* save the trhread specific data */
			if (pthread_setspecific(idmap_tsd_key, tsd) != 0) {
				/* Can't store key */
				free(tsd);
				tsd = NULL;
			}
		} else {
			tsd = NULL;
		}
	}

	return (tsd);
}

/*
 * A simple wrapper around u8_textprep_str() that returns the Unicode
 * lower-case version of some string.  The result must be freed.
 */
char *
tolower_u8(const char *s)
{
	char *res = NULL;
	char *outs;
	size_t inlen, outlen, inbytesleft, outbytesleft;
	int rc, err;

	/*
	 * u8_textprep_str() does not allocate memory.  The input and
	 * output buffers may differ in size (though that would be more
	 * likely when normalization is done).  We have to loop over it...
	 *
	 * To improve the chances that we can avoid looping we add 10
	 * bytes of output buffer room the first go around.
	 */
	inlen = inbytesleft = strlen(s);
	outlen = outbytesleft = inlen + 10;
	if ((res = malloc(outlen)) == NULL)
		return (NULL);
	outs = res;

	while ((rc = u8_textprep_str((char *)s, &inbytesleft, outs,
	    &outbytesleft, U8_TEXTPREP_TOLOWER, U8_UNICODE_LATEST, &err)) < 0 &&
	    err == E2BIG) {
		if ((res = realloc(res, outlen + inbytesleft)) == NULL)
			return (NULL);
		/* adjust input/output buffer pointers */
		s += (inlen - inbytesleft);
		outs = res + outlen - outbytesleft;
		/* adjust outbytesleft and outlen */
		outlen += inbytesleft;
		outbytesleft += inbytesleft;
	}

	if (rc < 0) {
		free(res);
		res = NULL;
		return (NULL);
	}

	res[outlen - outbytesleft] = '\0';

	return (res);
}

static int sql_exec_tran_no_cb(sqlite *db, char *sql, const char *dbname,
	const char *while_doing);


/*
 * Initialize 'dbname' using 'sql'
 */
static
int
init_db_instance(const char *dbname, int version,
	const char *detect_version_sql, char * const *sql,
	init_db_option_t opt, int *created, int *upgraded)
{
	int rc, curr_version;
	int tries = 1;
	int prio = LOG_NOTICE;
	sqlite *db = NULL;
	char *errmsg = NULL;

	*created = 0;
	*upgraded = 0;

	if (opt == REMOVE_IF_CORRUPT)
		tries = 3;

rinse_repeat:
	if (tries == 0) {
		idmapdlog(LOG_ERR, "Failed to initialize db %s", dbname);
		return (-1);
	}
	if (tries-- == 1)
		/* Last try, log errors */
		prio = LOG_ERR;

	db = sqlite_open(dbname, 0600, &errmsg);
	if (db == NULL) {
		idmapdlog(prio, "Error creating database %s (%s)",
		    dbname, CHECK_NULL(errmsg));
		sqlite_freemem(errmsg);
		if (opt == REMOVE_IF_CORRUPT)
			(void) unlink(dbname);
		goto rinse_repeat;
	}

	sqlite_busy_timeout(db, 3000);

	/* Detect current version of schema in the db, if any */
	curr_version = 0;
	if (detect_version_sql != NULL) {
		char *end, **results;
		int nrow;

#ifdef	IDMAPD_DEBUG
		(void) fprintf(stderr, "Schema version detection SQL: %s\n",
		    detect_version_sql);
#endif	/* IDMAPD_DEBUG */
		rc = sqlite_get_table(db, detect_version_sql, &results,
		    &nrow, NULL, &errmsg);
		if (rc != SQLITE_OK) {
			idmapdlog(prio,
			    "Error detecting schema version of db %s (%s)",
			    dbname, errmsg);
			sqlite_freemem(errmsg);
			sqlite_free_table(results);
			sqlite_close(db);
			return (-1);
		}
		if (nrow != 1) {
			idmapdlog(prio,
			    "Error detecting schema version of db %s", dbname);
			sqlite_close(db);
			sqlite_free_table(results);
			return (-1);
		}
		curr_version = strtol(results[1], &end, 10);
		sqlite_free_table(results);
	}

	if (curr_version < 0) {
		if (opt == REMOVE_IF_CORRUPT)
			(void) unlink(dbname);
		goto rinse_repeat;
	}

	if (curr_version == version)
		goto done;

	/* Install or upgrade schema */
#ifdef	IDMAPD_DEBUG
	(void) fprintf(stderr, "Schema init/upgrade SQL: %s\n",
	    sql[curr_version]);
#endif	/* IDMAPD_DEBUG */
	rc = sql_exec_tran_no_cb(db, sql[curr_version], dbname,
	    (curr_version == 0) ? "installing schema" : "upgrading schema");
	if (rc != 0) {
		idmapdlog(prio, "Error %s schema for db %s", dbname,
		    (curr_version == 0) ? "installing schema" :
		    "upgrading schema");
		if (opt == REMOVE_IF_CORRUPT)
			(void) unlink(dbname);
		goto rinse_repeat;
	}

	*upgraded = (curr_version > 0);
	*created = (curr_version == 0);

done:
	(void) sqlite_close(db);
	return (0);
}


/*
 * This is the SQLite database busy handler that retries the SQL
 * operation until it is successful.
 */
int
/* LINTED E_FUNC_ARG_UNUSED */
idmap_sqlite_busy_handler(void *arg, const char *table_name, int count)
{
	struct idmap_busy	*busy = arg;
	int			delay;
	struct timespec		rqtp;

	if (count == 1)  {
		busy->total = 0;
		busy->sec = 2;
	}
	if (busy->total > 1000 * busy->sec) {
		idmapdlog(LOG_DEBUG,
		    "Thread %d waited %d sec for the %s database",
		    pthread_self(), busy->sec, busy->name);
		busy->sec++;
	}

	if (count <= busy->delay_size) {
		delay = busy->delays[count-1];
	} else {
		delay = busy->delays[busy->delay_size - 1];
	}
	busy->total += delay;
	rqtp.tv_sec = 0;
	rqtp.tv_nsec = delay * (NANOSEC / MILLISEC);
	(void) nanosleep(&rqtp, NULL);
	return (1);
}


/*
 * Get the database handle
 */
idmap_retcode
get_db_handle(sqlite **db)
{
	char		*errmsg;
	idmap_tsd_t	*tsd;

	/*
	 * Retrieve the db handle from thread-specific storage
	 * If none exists, open and store in thread-specific storage.
	 */
	if ((tsd = idmap_get_tsd()) == NULL) {
		idmapdlog(LOG_ERR,
		    "Error getting thread specific data for %s", IDMAP_DBNAME);
		return (IDMAP_ERR_MEMORY);
	}

	if (tsd->db_db == NULL) {
		tsd->db_db = sqlite_open(IDMAP_DBNAME, 0, &errmsg);
		if (tsd->db_db == NULL) {
			idmapdlog(LOG_ERR, "Error opening database %s (%s)",
			    IDMAP_DBNAME, CHECK_NULL(errmsg));
			sqlite_freemem(errmsg);
			return (IDMAP_ERR_DB);
		}

		tsd->db_busy.name = IDMAP_DBNAME;
		tsd->db_busy.delays = db_delay_table;
		tsd->db_busy.delay_size = sizeof (db_delay_table) /
		    sizeof (int);
		sqlite_busy_handler(tsd->db_db, idmap_sqlite_busy_handler,
		    &tsd->db_busy);
	}
	*db = tsd->db_db;
	return (IDMAP_SUCCESS);
}

/*
 * Get the cache handle
 */
idmap_retcode
get_cache_handle(sqlite **cache)
{
	char		*errmsg;
	idmap_tsd_t	*tsd;

	/*
	 * Retrieve the db handle from thread-specific storage
	 * If none exists, open and store in thread-specific storage.
	 */
	if ((tsd = idmap_get_tsd()) == NULL) {
		idmapdlog(LOG_ERR, "Error getting thread specific data for %s",
		    IDMAP_DBNAME);
		return (IDMAP_ERR_MEMORY);
	}

	if (tsd->cache_db == NULL) {
		tsd->cache_db = sqlite_open(IDMAP_CACHENAME, 0, &errmsg);
		if (tsd->cache_db == NULL) {
			idmapdlog(LOG_ERR, "Error opening database %s (%s)",
			    IDMAP_CACHENAME, CHECK_NULL(errmsg));
			sqlite_freemem(errmsg);
			return (IDMAP_ERR_DB);
		}

		tsd->cache_busy.name = IDMAP_CACHENAME;
		tsd->cache_busy.delays = cache_delay_table;
		tsd->cache_busy.delay_size = sizeof (cache_delay_table) /
		    sizeof (int);
		sqlite_busy_handler(tsd->cache_db, idmap_sqlite_busy_handler,
		    &tsd->cache_busy);
	}
	*cache = tsd->cache_db;
	return (IDMAP_SUCCESS);
}

/*
 * Initialize cache and db
 */
int
init_dbs()
{
	char *sql[4];
	int created, upgraded;

	/* name-based mappings; probably OK to blow away in a pinch(?) */
	sql[0] = DB_INSTALL_SQL;
	sql[1] = DB_UPGRADE_FROM_v1_SQL;
	sql[2] = NULL;

	if (init_db_instance(IDMAP_DBNAME, DB_VERSION, DB_VERSION_SQL, sql,
	    FAIL_IF_CORRUPT, &created, &upgraded) < 0)
		return (-1);

	/* mappings, name/SID lookup cache + ephemeral IDs; OK to blow away */
	sql[0] = CACHE_INSTALL_SQL;
	sql[1] = CACHE_UPGRADE_FROM_v1_SQL;
	sql[2] = CACHE_UPGRADE_FROM_v2_SQL;
	sql[3] = NULL;

	if (init_db_instance(IDMAP_CACHENAME, CACHE_VERSION, CACHE_VERSION_SQL,
	    sql, REMOVE_IF_CORRUPT, &created, &upgraded) < 0)
		return (-1);

	_idmapdstate.new_eph_db = (created || upgraded) ? 1 : 0;

	return (0);
}

/*
 * Finalize databases
 */
void
fini_dbs()
{
}

/*
 * This table is a listing of status codes that will be returned to the
 * client when a SQL command fails with the corresponding error message.
 */
static msg_table_t sqlmsgtable[] = {
	{IDMAP_ERR_U2W_NAMERULE_CONFLICT,
	"columns unixname, is_user, u2w_order are not unique"},
	{IDMAP_ERR_W2U_NAMERULE_CONFLICT,
	"columns winname, windomain, is_user, is_wuser, w2u_order are not"
	" unique"},
	{IDMAP_ERR_W2U_NAMERULE_CONFLICT, "Conflicting w2u namerules"},
	{-1, NULL}
};

/*
 * idmapd's version of string2stat to map SQLite messages to
 * status codes
 */
idmap_retcode
idmapd_string2stat(const char *msg)
{
	int i;
	for (i = 0; sqlmsgtable[i].msg; i++) {
		if (strcasecmp(sqlmsgtable[i].msg, msg) == 0)
			return (sqlmsgtable[i].retcode);
	}
	return (IDMAP_ERR_OTHER);
}

/*
 * Executes some SQL in a transaction.
 *
 * Returns 0 on success, -1 if it failed but the rollback succeeded, -2
 * if the rollback failed.
 */
static
int
sql_exec_tran_no_cb(sqlite *db, char *sql, const char *dbname,
	const char *while_doing)
{
	char		*errmsg = NULL;
	int		rc;

	rc = sqlite_exec(db, "BEGIN TRANSACTION;", NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		idmapdlog(LOG_ERR, "Begin transaction failed (%s) "
		    "while %s (%s)", errmsg, while_doing, dbname);
		sqlite_freemem(errmsg);
		return (-1);
	}

	rc = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		idmapdlog(LOG_ERR, "Database error (%s) while %s (%s)", errmsg,
		    while_doing, dbname);
		sqlite_freemem(errmsg);
		errmsg = NULL;
		goto rollback;
	}

	rc = sqlite_exec(db, "COMMIT TRANSACTION", NULL, NULL, &errmsg);
	if (rc == SQLITE_OK) {
		sqlite_freemem(errmsg);
		return (0);
	}

	idmapdlog(LOG_ERR, "Database commit error (%s) while s (%s)",
	    errmsg, while_doing, dbname);
	sqlite_freemem(errmsg);
	errmsg = NULL;

rollback:
	rc = sqlite_exec(db, "ROLLBACK TRANSACTION", NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		idmapdlog(LOG_ERR, "Rollback failed (%s) while %s (%s)",
		    errmsg, while_doing, dbname);
		sqlite_freemem(errmsg);
		return (-2);
	}
	sqlite_freemem(errmsg);

	return (-1);
}

/*
 * Execute the given SQL statment without using any callbacks
 */
idmap_retcode
sql_exec_no_cb(sqlite *db, const char *dbname, char *sql)
{
	char		*errmsg = NULL;
	int		r;
	idmap_retcode	retcode;

	r = sqlite_exec(db, sql, NULL, NULL, &errmsg);
	assert(r != SQLITE_LOCKED && r != SQLITE_BUSY);

	if (r != SQLITE_OK) {
		idmapdlog(LOG_ERR, "Database error on %s while executing %s "
		    "(%s)", dbname, sql, CHECK_NULL(errmsg));
		retcode = idmapd_string2stat(errmsg);
		if (errmsg != NULL)
			sqlite_freemem(errmsg);
		return (retcode);
	}

	return (IDMAP_SUCCESS);
}

/*
 * Generate expression that can be used in WHERE statements.
 * Examples:
 * <prefix> <col>      <op> <value>   <suffix>
 * ""       "unixuser" "="  "foo" "AND"
 */
idmap_retcode
gen_sql_expr_from_rule(idmap_namerule *rule, char **out)
{
	char	*s_windomain = NULL, *s_winname = NULL;
	char	*s_unixname = NULL;
	char	*lower_winname;
	int	retcode = IDMAP_SUCCESS;

	if (out == NULL)
		return (IDMAP_ERR_ARG);


	if (!EMPTY_STRING(rule->windomain)) {
		s_windomain =  sqlite_mprintf("AND windomain = %Q ",
		    rule->windomain);
		if (s_windomain == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto out;
		}
	}

	if (!EMPTY_STRING(rule->winname)) {
		if ((lower_winname = tolower_u8(rule->winname)) == NULL)
			lower_winname = rule->winname;
		s_winname = sqlite_mprintf(
		    "AND winname = %Q AND is_wuser = %d ",
		    lower_winname, rule->is_wuser ? 1 : 0);
		if (lower_winname != rule->winname)
			free(lower_winname);
		if (s_winname == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto out;
		}
	}

	if (!EMPTY_STRING(rule->unixname)) {
		s_unixname = sqlite_mprintf(
		    "AND unixname = %Q AND is_user = %d ",
		    rule->unixname, rule->is_user ? 1 : 0);
		if (s_unixname == NULL) {
			retcode = IDMAP_ERR_MEMORY;
			goto out;
		}
	}

	*out = sqlite_mprintf("%s %s %s",
	    s_windomain ? s_windomain : "",
	    s_winname ? s_winname : "",
	    s_unixname ? s_unixname : "");

	if (*out == NULL) {
		retcode = IDMAP_ERR_MEMORY;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

out:
	if (s_windomain != NULL)
		sqlite_freemem(s_windomain);
	if (s_winname != NULL)
		sqlite_freemem(s_winname);
	if (s_unixname != NULL)
		sqlite_freemem(s_unixname);

	return (retcode);
}



/*
 * Generate and execute SQL statement for LIST RPC calls
 */
idmap_retcode
process_list_svc_sql(sqlite *db, const char *dbname, char *sql, uint64_t limit,
		int flag, list_svc_cb cb, void *result)
{
	list_cb_data_t	cb_data;
	char		*errmsg = NULL;
	int		r;
	idmap_retcode	retcode = IDMAP_ERR_INTERNAL;

	(void) memset(&cb_data, 0, sizeof (cb_data));
	cb_data.result = result;
	cb_data.limit = limit;
	cb_data.flag = flag;


	r = sqlite_exec(db, sql, cb, &cb_data, &errmsg);
	assert(r != SQLITE_LOCKED && r != SQLITE_BUSY);
	switch (r) {
	case SQLITE_OK:
		retcode = IDMAP_SUCCESS;
		break;

	default:
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Database error on %s while executing "
		    "%s (%s)", dbname, sql, CHECK_NULL(errmsg));
		break;
	}
	if (errmsg != NULL)
		sqlite_freemem(errmsg);
	return (retcode);
}

/*
 * This routine is called by callbacks that process the results of
 * LIST RPC calls to validate data and to allocate memory for
 * the result array.
 */
idmap_retcode
validate_list_cb_data(list_cb_data_t *cb_data, int argc, char **argv,
		int ncol, uchar_t **list, size_t valsize)
{
	size_t	nsize;
	void	*tmplist;

	if (cb_data->limit > 0 && cb_data->next == cb_data->limit)
		return (IDMAP_NEXT);

	if (argc < ncol || argv == NULL) {
		idmapdlog(LOG_ERR, "Invalid data");
		return (IDMAP_ERR_INTERNAL);
	}

	/* alloc in bulk to reduce number of reallocs */
	if (cb_data->next >= cb_data->len) {
		nsize = (cb_data->len + SIZE_INCR) * valsize;
		tmplist = realloc(*list, nsize);
		if (tmplist == NULL) {
			idmapdlog(LOG_ERR, "Out of memory");
			return (IDMAP_ERR_MEMORY);
		}
		*list = tmplist;
		(void) memset(*list + (cb_data->len * valsize), 0,
		    SIZE_INCR * valsize);
		cb_data->len += SIZE_INCR;
	}
	return (IDMAP_SUCCESS);
}

static
idmap_retcode
get_namerule_order(char *winname, char *windomain, char *unixname,
	int direction, int is_diagonal, int *w2u_order, int *u2w_order)
{
	*w2u_order = 0;
	*u2w_order = 0;

	/*
	 * Windows to UNIX lookup order:
	 *  1. winname@domain (or winname) to ""
	 *  2. winname@domain (or winname) to unixname
	 *  3. winname@* to ""
	 *  4. winname@* to unixname
	 *  5. *@domain (or *) to *
	 *  6. *@domain (or *) to ""
	 *  7. *@domain (or *) to unixname
	 *  8. *@* to *
	 *  9. *@* to ""
	 * 10. *@* to unixname
	 *
	 * winname is a special case of winname@domain when domain is the
	 * default domain. Similarly * is a special case of *@domain when
	 * domain is the default domain.
	 *
	 * Note that "" has priority over specific names because "" inhibits
	 * mappings and traditionally deny rules always had higher priority.
	 */
	if (direction != IDMAP_DIRECTION_U2W) {
		/* bi-directional or from windows to unix */
		if (winname == NULL)
			return (IDMAP_ERR_W2U_NAMERULE);
		else if (unixname == NULL)
			return (IDMAP_ERR_W2U_NAMERULE);
		else if (EMPTY_NAME(winname))
			return (IDMAP_ERR_W2U_NAMERULE);
		else if (*winname == '*' && windomain && *windomain == '*') {
			if (*unixname == '*')
				*w2u_order = 8;
			else if (EMPTY_NAME(unixname))
				*w2u_order = 9;
			else /* unixname == name */
				*w2u_order = 10;
		} else if (*winname == '*') {
			if (*unixname == '*')
				*w2u_order = 5;
			else if (EMPTY_NAME(unixname))
				*w2u_order = 6;
			else /* name */
				*w2u_order = 7;
		} else if (windomain != NULL && *windomain == '*') {
			/* winname == name */
			if (*unixname == '*')
				return (IDMAP_ERR_W2U_NAMERULE);
			else if (EMPTY_NAME(unixname))
				*w2u_order = 3;
			else /* name */
				*w2u_order = 4;
		} else  {
			/* winname == name && windomain == null or name */
			if (*unixname == '*')
				return (IDMAP_ERR_W2U_NAMERULE);
			else if (EMPTY_NAME(unixname))
				*w2u_order = 1;
			else /* name */
				*w2u_order = 2;
		}

	}

	/*
	 * 1. unixname to "", non-diagonal
	 * 2. unixname to winname@domain (or winname), non-diagonal
	 * 3. unixname to "", diagonal
	 * 4. unixname to winname@domain (or winname), diagonal
	 * 5. * to *@domain (or *), non-diagonal
	 * 5. * to *@domain (or *), diagonal
	 * 7. * to ""
	 * 8. * to winname@domain (or winname)
	 * 9. * to "", non-diagonal
	 * 10. * to winname@domain (or winname), diagonal
	 */
	if (direction != IDMAP_DIRECTION_W2U) {
		int diagonal = is_diagonal ? 1 : 0;

		/* bi-directional or from unix to windows */
		if (unixname == NULL || EMPTY_NAME(unixname))
			return (IDMAP_ERR_U2W_NAMERULE);
		else if (winname == NULL)
			return (IDMAP_ERR_U2W_NAMERULE);
		else if (windomain != NULL && *windomain == '*')
			return (IDMAP_ERR_U2W_NAMERULE);
		else if (*unixname == '*') {
			if (*winname == '*')
				*u2w_order = 5 + diagonal;
			else if (EMPTY_NAME(winname))
				*u2w_order = 7 + 2 * diagonal;
			else
				*u2w_order = 8 + 2 * diagonal;
		} else {
			if (*winname == '*')
				return (IDMAP_ERR_U2W_NAMERULE);
			else if (EMPTY_NAME(winname))
				*u2w_order = 1 + 2 * diagonal;
			else
				*u2w_order = 2 + 2 * diagonal;
		}
	}
	return (IDMAP_SUCCESS);
}

/*
 * Generate and execute SQL statement to add name-based mapping rule
 */
idmap_retcode
add_namerule(sqlite *db, idmap_namerule *rule)
{
	char		*sql = NULL;
	idmap_stat	retcode;
	char		*dom = NULL;
	int		w2u_order, u2w_order;
	char		w2ubuf[11], u2wbuf[11];

	retcode = get_namerule_order(rule->winname, rule->windomain,
	    rule->unixname, rule->direction,
	    rule->is_user == rule->is_wuser ? 0 : 1, &w2u_order, &u2w_order);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	if (w2u_order)
		(void) snprintf(w2ubuf, sizeof (w2ubuf), "%d", w2u_order);
	if (u2w_order)
		(void) snprintf(u2wbuf, sizeof (u2wbuf), "%d", u2w_order);

	/*
	 * For the triggers on namerules table to work correctly:
	 * 1) Use NULL instead of 0 for w2u_order and u2w_order
	 * 2) Use "" instead of NULL for "no domain"
	 */

	if (!EMPTY_STRING(rule->windomain))
		dom = rule->windomain;
	else if (lookup_wksids_name2sid(rule->winname, NULL, NULL, NULL, NULL)
	    == IDMAP_SUCCESS) {
		/* well-known SIDs don't need domain */
		dom = "";
	}

	RDLOCK_CONFIG();
	if (dom == NULL) {
		if (_idmapdstate.cfg->pgcfg.default_domain)
			dom = _idmapdstate.cfg->pgcfg.default_domain;
		else
			dom = "";
	}
	sql = sqlite_mprintf("INSERT into namerules "
	    "(is_user, is_wuser, windomain, winname_display, is_nt4, "
	    "unixname, w2u_order, u2w_order) "
	    "VALUES(%d, %d, %Q, %Q, %d, %Q, %q, %q);",
	    rule->is_user ? 1 : 0, rule->is_wuser ? 1 : 0, dom,
	    rule->winname, rule->is_nt4 ? 1 : 0, rule->unixname,
	    w2u_order ? w2ubuf : NULL, u2w_order ? u2wbuf : NULL);
	UNLOCK_CONFIG();

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	retcode = sql_exec_no_cb(db, IDMAP_DBNAME, sql);

	if (retcode == IDMAP_ERR_OTHER)
		retcode = IDMAP_ERR_CFG;

out:
	if (sql != NULL)
		sqlite_freemem(sql);
	return (retcode);
}

/*
 * Flush name-based mapping rules
 */
idmap_retcode
flush_namerules(sqlite *db)
{
	idmap_stat	retcode;

	retcode = sql_exec_no_cb(db, IDMAP_DBNAME, "DELETE FROM namerules;");

	return (retcode);
}

/*
 * Generate and execute SQL statement to remove a name-based mapping rule
 */
idmap_retcode
rm_namerule(sqlite *db, idmap_namerule *rule)
{
	char		*sql = NULL;
	idmap_stat	retcode;
	char		buf[80];
	char		*expr = NULL;

	if (rule->direction < 0 && EMPTY_STRING(rule->windomain) &&
	    EMPTY_STRING(rule->winname) && EMPTY_STRING(rule->unixname))
		return (IDMAP_SUCCESS);

	buf[0] = 0;

	if (rule->direction == IDMAP_DIRECTION_BI)
		(void) snprintf(buf, sizeof (buf), "AND w2u_order > 0"
		    " AND u2w_order > 0");
	else if (rule->direction == IDMAP_DIRECTION_W2U)
		(void) snprintf(buf, sizeof (buf), "AND w2u_order > 0"
		    " AND (u2w_order = 0 OR u2w_order ISNULL)");
	else if (rule->direction == IDMAP_DIRECTION_U2W)
		(void) snprintf(buf, sizeof (buf), "AND u2w_order > 0"
		    " AND (w2u_order = 0 OR w2u_order ISNULL)");

	retcode = gen_sql_expr_from_rule(rule, &expr);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	sql = sqlite_mprintf("DELETE FROM namerules WHERE 1 %s %s;", expr,
	    buf);

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}


	retcode = sql_exec_no_cb(db, IDMAP_DBNAME, sql);

out:
	if (expr != NULL)
		sqlite_freemem(expr);
	if (sql != NULL)
		sqlite_freemem(sql);
	return (retcode);
}

/*
 * Compile the given SQL query and step just once.
 *
 * Input:
 * db  - db handle
 * sql - SQL statement
 *
 * Output:
 * vm     -  virtual SQL machine
 * ncol   - number of columns in the result
 * values - column values
 *
 * Return values:
 * IDMAP_SUCCESS
 * IDMAP_ERR_NOTFOUND
 * IDMAP_ERR_INTERNAL
 */

static
idmap_retcode
sql_compile_n_step_once(sqlite *db, char *sql, sqlite_vm **vm, int *ncol,
		int reqcol, const char ***values)
{
	char		*errmsg = NULL;
	int		r;

	if ((r = sqlite_compile(db, sql, NULL, vm, &errmsg)) != SQLITE_OK) {
		idmapdlog(LOG_ERR, "Database error during %s (%s)", sql,
		    CHECK_NULL(errmsg));
		sqlite_freemem(errmsg);
		return (IDMAP_ERR_INTERNAL);
	}

	r = sqlite_step(*vm, ncol, values, NULL);
	assert(r != SQLITE_LOCKED && r != SQLITE_BUSY);

	if (r == SQLITE_ROW) {
		if (ncol != NULL && *ncol < reqcol) {
			(void) sqlite_finalize(*vm, NULL);
			*vm = NULL;
			return (IDMAP_ERR_INTERNAL);
		}
		/* Caller will call finalize after using the results */
		return (IDMAP_SUCCESS);
	} else if (r == SQLITE_DONE) {
		(void) sqlite_finalize(*vm, NULL);
		*vm = NULL;
		return (IDMAP_ERR_NOTFOUND);
	}

	(void) sqlite_finalize(*vm, &errmsg);
	*vm = NULL;
	idmapdlog(LOG_ERR, "Database error during %s (%s)", sql,
	    CHECK_NULL(errmsg));
	sqlite_freemem(errmsg);
	return (IDMAP_ERR_INTERNAL);
}

/*
 * Load config in the state.
 *
 * nm_siduid and nm_sidgid fields:
 * state->nm_siduid represents mode used by sid2uid and uid2sid
 * requests for directory-based name mappings. Similarly,
 * state->nm_sidgid represents mode used by sid2gid and gid2sid
 * requests.
 *
 * sid2uid/uid2sid:
 * none       -> ds_name_mapping_enabled != true
 * AD-mode    -> !nldap_winname_attr && ad_unixuser_attr
 * nldap-mode -> nldap_winname_attr && !ad_unixuser_attr
 * mixed-mode -> nldap_winname_attr && ad_unixuser_attr
 *
 * sid2gid/gid2sid:
 * none       -> ds_name_mapping_enabled != true
 * AD-mode    -> !nldap_winname_attr && ad_unixgroup_attr
 * nldap-mode -> nldap_winname_attr && !ad_unixgroup_attr
 * mixed-mode -> nldap_winname_attr && ad_unixgroup_attr
 */
idmap_retcode
load_cfg_in_state(lookup_state_t *state)
{
	state->nm_siduid = IDMAP_NM_NONE;
	state->nm_sidgid = IDMAP_NM_NONE;
	RDLOCK_CONFIG();

	if (_idmapdstate.cfg->pgcfg.default_domain != NULL) {
		state->defdom =
		    strdup(_idmapdstate.cfg->pgcfg.default_domain);
		if (state->defdom == NULL) {
			UNLOCK_CONFIG();
			return (IDMAP_ERR_MEMORY);
		}
	} else {
		UNLOCK_CONFIG();
		return (IDMAP_SUCCESS);
	}
	if (_idmapdstate.cfg->pgcfg.ds_name_mapping_enabled == FALSE) {
		UNLOCK_CONFIG();
		return (IDMAP_SUCCESS);
	}
	if (_idmapdstate.cfg->pgcfg.nldap_winname_attr != NULL) {
		state->nm_siduid =
		    (_idmapdstate.cfg->pgcfg.ad_unixuser_attr != NULL)
		    ? IDMAP_NM_MIXED : IDMAP_NM_NLDAP;
		state->nm_sidgid =
		    (_idmapdstate.cfg->pgcfg.ad_unixgroup_attr != NULL)
		    ? IDMAP_NM_MIXED : IDMAP_NM_NLDAP;
	} else {
		state->nm_siduid =
		    (_idmapdstate.cfg->pgcfg.ad_unixuser_attr != NULL)
		    ? IDMAP_NM_AD : IDMAP_NM_NONE;
		state->nm_sidgid =
		    (_idmapdstate.cfg->pgcfg.ad_unixgroup_attr != NULL)
		    ? IDMAP_NM_AD : IDMAP_NM_NONE;
	}
	if (_idmapdstate.cfg->pgcfg.ad_unixuser_attr != NULL) {
		state->ad_unixuser_attr =
		    strdup(_idmapdstate.cfg->pgcfg.ad_unixuser_attr);
		if (state->ad_unixuser_attr == NULL) {
			UNLOCK_CONFIG();
			return (IDMAP_ERR_MEMORY);
		}
	}
	if (_idmapdstate.cfg->pgcfg.ad_unixgroup_attr != NULL) {
		state->ad_unixgroup_attr =
		    strdup(_idmapdstate.cfg->pgcfg.ad_unixgroup_attr);
		if (state->ad_unixgroup_attr == NULL) {
			UNLOCK_CONFIG();
			return (IDMAP_ERR_MEMORY);
		}
	}
	if (_idmapdstate.cfg->pgcfg.nldap_winname_attr != NULL) {
		state->nldap_winname_attr =
		    strdup(_idmapdstate.cfg->pgcfg.nldap_winname_attr);
		if (state->nldap_winname_attr == NULL) {
			UNLOCK_CONFIG();
			return (IDMAP_ERR_MEMORY);
		}
	}
	UNLOCK_CONFIG();
	return (IDMAP_SUCCESS);
}

/*
 * Set the rule with sepecified values.
 * All the strings are copied.
 */
static void
idmap_namerule_set(idmap_namerule *rule, const char *windomain,
		const char *winname, const char *unixname, boolean_t is_user,
		boolean_t is_wuser, boolean_t is_nt4, int direction)
{
	/*
	 * Only update if they differ because we have to free
	 * and duplicate the strings
	 */
	if (rule->windomain == NULL || windomain == NULL ||
	    strcmp(rule->windomain, windomain) != 0) {
		if (rule->windomain != NULL) {
			free(rule->windomain);
			rule->windomain = NULL;
		}
		if (windomain != NULL)
			rule->windomain = strdup(windomain);
	}

	if (rule->winname == NULL || winname == NULL ||
	    strcmp(rule->winname, winname) != 0) {
		if (rule->winname != NULL) {
			free(rule->winname);
			rule->winname = NULL;
		}
		if (winname != NULL)
			rule->winname = strdup(winname);
	}

	if (rule->unixname == NULL || unixname == NULL ||
	    strcmp(rule->unixname, unixname) != 0) {
		if (rule->unixname != NULL) {
			free(rule->unixname);
			rule->unixname = NULL;
		}
		if (unixname != NULL)
			rule->unixname = strdup(unixname);
	}

	rule->is_user = is_user;
	rule->is_wuser = is_wuser;
	rule->is_nt4 = is_nt4;
	rule->direction = direction;
}


/*
 * Table for well-known SIDs.
 *
 * Background:
 *
 * Some of the well-known principals are stored under:
 * cn=WellKnown Security Principals, cn=Configuration, dc=<forestRootDomain>
 * They belong to objectClass "foreignSecurityPrincipal". They don't have
 * "samAccountName" nor "userPrincipalName" attributes. Their names are
 * available in "cn" and "name" attributes. Some of these principals have a
 * second entry under CN=ForeignSecurityPrincipals,dc=<forestRootDomain> and
 * these duplicate entries have the stringified SID in the "name" and "cn"
 * attributes instead of the actual name.
 *
 * Those of the form S-1-5-32-X are Builtin groups and are stored in the
 * cn=builtin container (except, Power Users which is not stored in AD)
 *
 * These principals are and will remain constant. Therefore doing AD lookups
 * provides no benefit. Also, using hard-coded table (and thus avoiding AD
 * lookup) improves performance and avoids additional complexity in the
 * adutils.c code. Moreover these SIDs can be used when no Active Directory
 * is available (such as the CIFS server's "workgroup" mode).
 *
 * Notes:
 * 1. Currently we don't support localization of well-known SID names,
 * unlike Windows.
 *
 * 2. Other well-known SIDs i.e. S-1-5-<domain>-<w-k RID> are not stored
 * here. AD does have normal user/group objects for these objects and
 * can be looked up using the existing AD lookup code.
 *
 * 3. See comments above lookup_wksids_sid2pid() for more information
 * on how we lookup the wksids table.
 */
static wksids_table_t wksids[] = {
	{"S-1-0", 0, "Nobody", 0, SENTINEL_PID, -1, 1},
	{"S-1-1", 0, "Everyone", 0, SENTINEL_PID, -1, -1},
	{"S-1-3", 0, "Creator Owner", 1, IDMAP_WK_CREATOR_OWNER_UID, 1, 0},
	{"S-1-3", 1, "Creator Group", 0, IDMAP_WK_CREATOR_GROUP_GID, 0, 0},
	{"S-1-3", 2, "Creator Owner Server", 1, SENTINEL_PID, -1, -1},
	{"S-1-3", 3, "Creator Group Server", 0, SENTINEL_PID, -1, 1},
	{"S-1-3", 4, "Owner Rights", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 1, "Dialup", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 2, "Network", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 3, "Batch", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 4, "Interactive", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 6, "Service", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 7, "Anonymous Logon", 0, GID_NOBODY, 0, 0},
	{"S-1-5", 7, "Anonymous Logon", 0, UID_NOBODY, 1, 0},
	{"S-1-5", 8, "Proxy", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 9, "Enterprise Domain Controllers", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 10, "Self", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 11, "Authenticated Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 12, "Restricted Code", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 13, "Terminal Server User", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 14, "Remote Interactive Logon", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 15, "This Organization", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 17, "IUSR", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 18, "Local System", 0, IDMAP_WK_LOCAL_SYSTEM_GID, 0, 0},
	{"S-1-5", 19, "Local Service", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 20, "Network Service", 0, SENTINEL_PID, -1, -1},
	{"S-1-5", 1000, "Other Organization", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 544, "Administrators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 545, "Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 546, "Guests", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 547, "Power Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 548, "Account Operators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 549, "Server Operators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 550, "Print Operators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 551, "Backup Operators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 552, "Replicator", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 554, "Pre-Windows 2000 Compatible Access", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 555, "Remote Desktop Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 556, "Network Configuration Operators", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 557, "Incoming Forest Trust Builders", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 558, "Performance Monitor Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 559, "Performance Log Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 560, "Windows Authorization Access Group", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 561, "Terminal Server License Servers", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-32", 561, "Distributed COM Users", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 568, "IIS_IUSRS", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 569, "Cryptographic Operators", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 573, "Event Log Readers", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-32", 574, "Certificate Service DCOM Access", 0,
	    SENTINEL_PID, -1, -1},
	{"S-1-5-64", 21, "Digest Authentication", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-64", 10, "NTLM Authentication", 0, SENTINEL_PID, -1, -1},
	{"S-1-5-64", 14, "SChannel Authentication", 0, SENTINEL_PID, -1, -1},
	{NULL, UINT32_MAX, NULL, -1, SENTINEL_PID, -1, -1}
};

/*
 * Lookup well-known SIDs table either by winname or by SID.
 * If the given winname or SID is a well-known SID then we set wksid
 * variable and then proceed to see if the SID has a hard mapping to
 * a particular UID/GID (Ex: Creator Owner/Creator Group mapped to
 * fixed ephemeral ids). If we find such mapping then we return
 * success otherwise notfound. If a well-known SID is mapped to
 * SENTINEL_PID and the direction field is set (bi-directional or
 * win2unix) then we treat it as inhibited mapping and return no
 * mapping (Ex. S-1-0-0).
 */
static
idmap_retcode
lookup_wksids_sid2pid(idmap_mapping *req, idmap_id_res *res, int *wksid)
{
	int i;

	*wksid = 0;

	for (i = 0; wksids[i].sidprefix != NULL; i++) {
		if (req->id1.idmap_id_u.sid.prefix != NULL) {
			if ((strcasecmp(wksids[i].sidprefix,
			    req->id1.idmap_id_u.sid.prefix) != 0) ||
			    wksids[i].rid != req->id1.idmap_id_u.sid.rid)
				/* this is not our SID */
				continue;
			if (req->id1name == NULL) {
				req->id1name = strdup(wksids[i].winname);
				if (req->id1name == NULL)
					return (IDMAP_ERR_MEMORY);
			}
		} else if (req->id1name != NULL) {
			if (strcasecmp(wksids[i].winname, req->id1name) != 0)
				/* this is not our winname */
				continue;
			req->id1.idmap_id_u.sid.prefix =
			    strdup(wksids[i].sidprefix);
			if (req->id1.idmap_id_u.sid.prefix == NULL)
				return (IDMAP_ERR_MEMORY);
			req->id1.idmap_id_u.sid.rid = wksids[i].rid;
		}

		*wksid = 1;
		req->direction |= _IDMAP_F_DONT_UPDATE_NAMECACHE;

		req->id1.idtype = (wksids[i].is_wuser) ?
		    IDMAP_USID : IDMAP_GSID;

		if (wksids[i].pid == SENTINEL_PID) {
			if (wksids[i].direction == IDMAP_DIRECTION_BI ||
			    wksids[i].direction == IDMAP_DIRECTION_W2U)
				/* Inhibited */
				return (IDMAP_ERR_NOMAPPING);
			/* Not mapped */
			if (res->id.idtype == IDMAP_POSIXID) {
				res->id.idtype =
				    (wksids[i].is_wuser) ?
				    IDMAP_UID : IDMAP_GID;
			}
			return (IDMAP_ERR_NOTFOUND);
		} else if (wksids[i].direction == IDMAP_DIRECTION_U2W)
			continue;

		switch (res->id.idtype) {
		case IDMAP_UID:
			if (wksids[i].is_user == 0)
				continue;
			res->id.idmap_id_u.uid = wksids[i].pid;
			res->direction = wksids[i].direction;
			if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
				res->info.how.map_type =
				    IDMAP_MAP_TYPE_KNOWN_SID;
				res->info.src = IDMAP_MAP_SRC_HARD_CODED;
			}
			return (IDMAP_SUCCESS);
		case IDMAP_GID:
			if (wksids[i].is_user == 1)
				continue;
			res->id.idmap_id_u.gid = wksids[i].pid;
			res->direction = wksids[i].direction;
			if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
				res->info.how.map_type =
				    IDMAP_MAP_TYPE_KNOWN_SID;
				res->info.src = IDMAP_MAP_SRC_HARD_CODED;
			}
			return (IDMAP_SUCCESS);
		case IDMAP_POSIXID:
			res->id.idmap_id_u.uid = wksids[i].pid;
			res->id.idtype = (!wksids[i].is_user) ?
			    IDMAP_GID : IDMAP_UID;
			res->direction = wksids[i].direction;
			if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
				res->info.how.map_type =
				    IDMAP_MAP_TYPE_KNOWN_SID;
				res->info.src = IDMAP_MAP_SRC_HARD_CODED;
			}
			return (IDMAP_SUCCESS);
		default:
			return (IDMAP_ERR_NOTSUPPORTED);
		}
	}
	return (IDMAP_ERR_NOTFOUND);
}


static
idmap_retcode
lookup_wksids_pid2sid(idmap_mapping *req, idmap_id_res *res, int is_user)
{
	int i;
	if (req->id1.idmap_id_u.uid == SENTINEL_PID)
		return (IDMAP_ERR_NOTFOUND);
	for (i = 0; wksids[i].sidprefix != NULL; i++) {
		if (wksids[i].pid == req->id1.idmap_id_u.uid &&
		    wksids[i].is_user == is_user &&
		    wksids[i].direction != IDMAP_DIRECTION_W2U) {
			if (res->id.idtype == IDMAP_SID) {
				res->id.idtype = (wksids[i].is_wuser) ?
				    IDMAP_USID : IDMAP_GSID;
			}
			res->id.idmap_id_u.sid.rid = wksids[i].rid;
			res->id.idmap_id_u.sid.prefix =
			    strdup(wksids[i].sidprefix);
			if (res->id.idmap_id_u.sid.prefix == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				return (IDMAP_ERR_MEMORY);
			}
			res->direction = wksids[i].direction;
			if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
				res->info.how.map_type =
				    IDMAP_MAP_TYPE_KNOWN_SID;
				res->info.src = IDMAP_MAP_SRC_HARD_CODED;
			}
			return (IDMAP_SUCCESS);
		}
	}
	return (IDMAP_ERR_NOTFOUND);
}

idmap_retcode
lookup_wksids_name2sid(const char *name, char **canonname, char **sidprefix,
	idmap_rid_t *rid, int *type)
{
	int	i;

	if ((strncasecmp(name, "BUILTIN\\", 8) == 0) ||
	    (strncasecmp(name, "BUILTIN/", 8) == 0))
		name += 8;

	for (i = 0; wksids[i].sidprefix != NULL; i++) {
		if (strcasecmp(wksids[i].winname, name) != 0)
			continue;
		if (sidprefix != NULL &&
		    (*sidprefix = strdup(wksids[i].sidprefix)) == NULL) {
			idmapdlog(LOG_ERR, "Out of memory");
			return (IDMAP_ERR_MEMORY);
		}
		if (canonname != NULL &&
		    (*canonname = strdup(wksids[i].winname)) == NULL) {
			idmapdlog(LOG_ERR, "Out of memory");
			if (sidprefix != NULL) {
				free(*sidprefix);
				*sidprefix = NULL;
			}
			return (IDMAP_ERR_MEMORY);
		}
		if (type != NULL)
			*type = (wksids[i].is_wuser) ?
			    _IDMAP_T_USER : _IDMAP_T_GROUP;
		if (rid != NULL)
			*rid = wksids[i].rid;
		return (IDMAP_SUCCESS);
	}
	return (IDMAP_ERR_NOTFOUND);
}

static
idmap_retcode
lookup_cache_sid2pid(sqlite *cache, idmap_mapping *req, idmap_id_res *res)
{
	char		*end;
	char		*sql = NULL;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol, is_user;
	uid_t		pid;
	time_t		curtime, exp;
	idmap_retcode	retcode;
	char		*is_user_string, *lower_name;

	/* Current time */
	errno = 0;
	if ((curtime = time(NULL)) == (time_t)-1) {
		idmapdlog(LOG_ERR, "Failed to get current time (%s)",
		    strerror(errno));
		retcode = IDMAP_ERR_INTERNAL;
		goto out;
	}

	switch (res->id.idtype) {
	case IDMAP_UID:
		is_user_string = "1";
		break;
	case IDMAP_GID:
		is_user_string = "0";
		break;
	case IDMAP_POSIXID:
		/* the non-diagonal mapping */
		is_user_string = "is_wuser";
		break;
	default:
		retcode = IDMAP_ERR_NOTSUPPORTED;
		goto out;
	}

	/* SQL to lookup the cache */

	if (req->id1.idmap_id_u.sid.prefix != NULL) {
		sql = sqlite_mprintf("SELECT pid, is_user, expiration, "
		    "unixname, u2w, is_wuser, "
		    "map_type, map_dn, map_attr, map_value, "
		    "map_windomain, map_winname, map_unixname, map_is_nt4 "
		    "FROM idmap_cache WHERE is_user = %s AND "
		    "sidprefix = %Q AND rid = %u AND w2u = 1 AND "
		    "(pid >= 2147483648 OR "
		    "(expiration = 0 OR expiration ISNULL OR "
		    "expiration > %d));",
		    is_user_string, req->id1.idmap_id_u.sid.prefix,
		    req->id1.idmap_id_u.sid.rid, curtime);
	} else if (req->id1name != NULL) {
		if ((lower_name = tolower_u8(req->id1name)) == NULL)
			lower_name = req->id1name;
		sql = sqlite_mprintf("SELECT pid, is_user, expiration, "
		    "unixname, u2w, is_wuser, "
		    "map_type, map_dn, map_attr, map_value, "
		    "map_windomain, map_winname, map_unixname, map_is_nt4 "
		    "FROM idmap_cache WHERE is_user = %s AND "
		    "winname = %Q AND windomain = %Q AND w2u = 1 AND "
		    "(pid >= 2147483648 OR "
		    "(expiration = 0 OR expiration ISNULL OR "
		    "expiration > %d));",
		    is_user_string, lower_name, req->id1domain,
		    curtime);
		if (lower_name != req->id1name)
			free(lower_name);
	} else {
		retcode = IDMAP_ERR_ARG;
		goto out;
	}
	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	retcode = sql_compile_n_step_once(cache, sql, &vm, &ncol,
	    14, &values);
	sqlite_freemem(sql);

	if (retcode == IDMAP_ERR_NOTFOUND) {
		goto out;
	} else if (retcode == IDMAP_SUCCESS) {
		/* sanity checks */
		if (values[0] == NULL || values[1] == NULL) {
			retcode = IDMAP_ERR_CACHE;
			goto out;
		}

		pid = strtoul(values[0], &end, 10);
		is_user = strncmp(values[1], "0", 2) ? 1 : 0;

		if (is_user) {
			res->id.idtype = IDMAP_UID;
			res->id.idmap_id_u.uid = pid;
		} else {
			res->id.idtype = IDMAP_GID;
			res->id.idmap_id_u.gid = pid;
		}

		/*
		 * We may have an expired ephemeral mapping. Consider
		 * the expired entry as valid if we are not going to
		 * perform name-based mapping. But do not renew the
		 * expiration.
		 * If we will be doing name-based mapping then store the
		 * ephemeral pid in the result so that we can use it
		 * if we end up doing dynamic mapping again.
		 */
		if (!DO_NOT_ALLOC_NEW_ID_MAPPING(req) &&
		    !AVOID_NAMESERVICE(req) &&
		    IS_EPHEMERAL(pid) && values[2] != NULL) {
			exp = strtoll(values[2], &end, 10);
			if (exp && exp <= curtime) {
				/* Store the ephemeral pid */
				res->direction = IDMAP_DIRECTION_BI;
				req->direction |= is_user
				    ? _IDMAP_F_EXP_EPH_UID
				    : _IDMAP_F_EXP_EPH_GID;
				retcode = IDMAP_ERR_NOTFOUND;
			}
		}
	}

out:
	if (retcode == IDMAP_SUCCESS) {
		if (values[4] != NULL)
			res->direction =
			    (strtol(values[4], &end, 10) == 0)?
			    IDMAP_DIRECTION_W2U:IDMAP_DIRECTION_BI;
		else
			res->direction = IDMAP_DIRECTION_W2U;

		if (values[3] != NULL) {
			if (req->id2name != NULL)
				free(req->id2name);
			req->id2name = strdup(values[3]);
			if (req->id2name == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
			}
		}

		req->id1.idtype = strncmp(values[5], "0", 2) ?
		    IDMAP_USID : IDMAP_GSID;

		if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
			res->info.src = IDMAP_MAP_SRC_CACHE;
			res->info.how.map_type = strtoul(values[6], &end, 10);
			switch (res->info.how.map_type) {
			case IDMAP_MAP_TYPE_DS_AD:
				res->info.how.idmap_how_u.ad.dn =
				    strdup(values[7]);
				res->info.how.idmap_how_u.ad.attr =
				    strdup(values[8]);
				res->info.how.idmap_how_u.ad.value =
				    strdup(values[9]);
				break;

			case IDMAP_MAP_TYPE_DS_NLDAP:
				res->info.how.idmap_how_u.nldap.dn =
				    strdup(values[7]);
				res->info.how.idmap_how_u.nldap.attr =
				    strdup(values[8]);
				res->info.how.idmap_how_u.nldap.value =
				    strdup(values[9]);
				break;

			case IDMAP_MAP_TYPE_RULE_BASED:
				res->info.how.idmap_how_u.rule.windomain =
				    strdup(values[10]);
				res->info.how.idmap_how_u.rule.winname =
				    strdup(values[11]);
				res->info.how.idmap_how_u.rule.unixname =
				    strdup(values[12]);
				res->info.how.idmap_how_u.rule.is_nt4 =
				    strtoul(values[13], &end, 1);
				res->info.how.idmap_how_u.rule.is_user =
				    is_user;
				res->info.how.idmap_how_u.rule.is_wuser =
				    strtoul(values[5], &end, 1);
				break;

			case IDMAP_MAP_TYPE_EPHEMERAL:
				break;

			case IDMAP_MAP_TYPE_LOCAL_SID:
				break;

			case IDMAP_MAP_TYPE_KNOWN_SID:
				break;

			default:
				/* Unknow mapping type */
				assert(FALSE);
			}
		}
	}
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

static
idmap_retcode
lookup_cache_sid2name(sqlite *cache, const char *sidprefix, idmap_rid_t rid,
		char **name, char **domain, int *type)
{
	char		*end;
	char		*sql = NULL;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol;
	time_t		curtime;
	idmap_retcode	retcode = IDMAP_SUCCESS;

	/* Get current time */
	errno = 0;
	if ((curtime = time(NULL)) == (time_t)-1) {
		idmapdlog(LOG_ERR, "Failed to get current time (%s)",
		    strerror(errno));
		retcode = IDMAP_ERR_INTERNAL;
		goto out;
	}

	/* SQL to lookup the cache */
	sql = sqlite_mprintf("SELECT canon_name, domain, type "
	    "FROM name_cache WHERE "
	    "sidprefix = %Q AND rid = %u AND "
	    "(expiration = 0 OR expiration ISNULL OR "
	    "expiration > %d);",
	    sidprefix, rid, curtime);
	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	retcode = sql_compile_n_step_once(cache, sql, &vm, &ncol, 3, &values);
	sqlite_freemem(sql);

	if (retcode == IDMAP_SUCCESS) {
		if (type != NULL) {
			if (values[2] == NULL) {
				retcode = IDMAP_ERR_CACHE;
				goto out;
			}
			*type = strtol(values[2], &end, 10);
		}

		if (name != NULL && values[0] != NULL) {
			if ((*name = strdup(values[0])) == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}
		}

		if (domain != NULL && values[1] != NULL) {
			if ((*domain = strdup(values[1])) == NULL) {
				if (name != NULL && *name) {
					free(*name);
					*name = NULL;
				}
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}
		}
	}

out:
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

/*
 * Given SID, find winname using name_cache OR
 * Given winname, find SID using name_cache.
 * Used when mapping win to unix i.e. req->id1 is windows id and
 * req->id2 is unix id
 */
static
idmap_retcode
lookup_name_cache(sqlite *cache, idmap_mapping *req, idmap_id_res *res)
{
	int		type = -1;
	idmap_retcode	retcode;
	char		*sidprefix = NULL;
	idmap_rid_t	rid;
	char		*name = NULL, *domain = NULL;

	/* Done if we've both sid and winname */
	if (req->id1.idmap_id_u.sid.prefix != NULL && req->id1name != NULL)
		return (IDMAP_SUCCESS);

	/* Lookup sid to winname */
	if (req->id1.idmap_id_u.sid.prefix != NULL) {
		retcode = lookup_cache_sid2name(cache,
		    req->id1.idmap_id_u.sid.prefix,
		    req->id1.idmap_id_u.sid.rid, &name, &domain, &type);
		goto out;
	}

	/* Lookup winame to sid */
	retcode = lookup_cache_name2sid(cache, req->id1name, req->id1domain,
	    &name, &sidprefix, &rid, &type);

out:
	if (retcode != IDMAP_SUCCESS) {
		free(name);
		free(domain);
		free(sidprefix);
		return (retcode);
	}

	if (res->id.idtype == IDMAP_POSIXID) {
		res->id.idtype = (type == _IDMAP_T_USER) ?
		    IDMAP_UID : IDMAP_GID;
	}
	req->id1.idtype = (type == _IDMAP_T_USER) ?
	    IDMAP_USID : IDMAP_GSID;

	req->direction |= _IDMAP_F_DONT_UPDATE_NAMECACHE;
	if (name != NULL) {
		free(req->id1name);	/* Free existing winname */
		req->id1name = name;	/* and use canonical name instead */
	}
	if (req->id1domain == NULL)
		req->id1domain = domain;
	if (req->id1.idmap_id_u.sid.prefix == NULL) {
		req->id1.idmap_id_u.sid.prefix = sidprefix;
		req->id1.idmap_id_u.sid.rid = rid;
	}
	return (retcode);
}

/*
 * Batch AD lookups
 */
idmap_retcode
ad_lookup_batch(lookup_state_t *state, idmap_mapping_batch *batch,
		idmap_ids_res *result)
{
	idmap_retcode	retcode;
	int		i, add, type, is_wuser, is_user;
	int		retries = 0, eunixtype;
	char		**unixname;
	idmap_mapping	*req;
	idmap_id_res	*res;
	idmap_query_state_t	*qs = NULL;
	idmap_how	*how;
	char		**dn, **attr, **value;

	/*
	 * Since req->id2.idtype is unused, we will use it here
	 * to retrieve the value of sid_type. But it needs to be
	 * reset to IDMAP_NONE before we return to prevent xdr
	 * from mis-interpreting req->id2 when it tries to free
	 * the input argument. Other option is to allocate an
	 * array of integers and use it instead for the batched
	 * call. But why un-necessarily allocate memory. That may
	 * be an option if req->id2.idtype cannot be re-used in
	 * future.
	 */

	if (state->ad_nqueries == 0)
		return (IDMAP_SUCCESS);

retry:
	retcode = idmap_lookup_batch_start(_idmapdstate.ad, state->ad_nqueries,
	    &qs);
	if (retcode != IDMAP_SUCCESS) {
		if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR && retries++ < 2)
			goto retry;
		degrade_svc(1, "failed to create batch for AD lookup");
		goto out;
	}

	restore_svc();

	idmap_lookup_batch_set_unixattr(qs, state->ad_unixuser_attr,
	    state->ad_unixgroup_attr);

	for (i = 0, add = 0; i < batch->idmap_mapping_batch_len; i++) {
		req = &batch->idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		how = &res->info.how;

		retcode = IDMAP_SUCCESS;
		req->id2.idtype = IDMAP_NONE;

		/* Skip if not marked for AD lookup */
		if (!(req->direction & _IDMAP_F_LOOKUP_AD))
			continue;

		if (retries == 0)
			res->retcode = IDMAP_ERR_RETRIABLE_NET_ERR;
		else if (res->retcode != IDMAP_ERR_RETRIABLE_NET_ERR)
			continue;

		if (IS_REQUEST_SID(*req, 1)) {

			/* win2unix request: */

			unixname = dn = attr = value = NULL;
			eunixtype = _IDMAP_T_UNDEF;
			if (req->id2name == NULL) {
				if (res->id.idtype == IDMAP_UID &&
				    AD_OR_MIXED(state->nm_siduid)) {
					eunixtype = _IDMAP_T_USER;
					unixname = &req->id2name;
				} else if (res->id.idtype == IDMAP_GID &&
				    AD_OR_MIXED(state->nm_sidgid)) {
					eunixtype = _IDMAP_T_GROUP;
					unixname = &req->id2name;
				} else if (AD_OR_MIXED(state->nm_siduid) ||
				    AD_OR_MIXED(state->nm_sidgid)) {
					unixname = &req->id2name;
				}
			}
			add = 1;
			if (unixname != NULL) {
				/*
				 * Get how info for DS-based name
				 * mapping only if AD or MIXED
				 * mode is enabled.
				 */
				idmap_info_free(&res->info);
				res->info.src = IDMAP_MAP_SRC_NEW;
				how->map_type = IDMAP_MAP_TYPE_DS_AD;
				dn = &how->idmap_how_u.ad.dn;
				attr = &how->idmap_how_u.ad.attr;
				value = &how->idmap_how_u.ad.value;
			}
			if (req->id1.idmap_id_u.sid.prefix != NULL) {
				/* Lookup AD by SID */
				retcode = idmap_sid2name_batch_add1(
				    qs, req->id1.idmap_id_u.sid.prefix,
				    &req->id1.idmap_id_u.sid.rid, eunixtype,
				    dn, attr, value,
				    (req->id1name == NULL) ?
				    &req->id1name : NULL,
				    (req->id1domain == NULL) ?
				    &req->id1domain : NULL,
				    (int *)&req->id2.idtype, unixname,
				    &res->retcode);
			} else {
				/* Lookup AD by winname */
				assert(req->id1name != NULL);
				retcode = idmap_name2sid_batch_add1(
				    qs, req->id1name, req->id1domain,
				    eunixtype,
				    dn, attr, value,
				    &req->id1name,
				    &req->id1.idmap_id_u.sid.prefix,
				    &req->id1.idmap_id_u.sid.rid,
				    (int *)&req->id2.idtype, unixname,
				    &res->retcode);
			}

		} else if (IS_REQUEST_UID(*req) || IS_REQUEST_GID(*req)) {

			/* unix2win request: */

			if (res->id.idmap_id_u.sid.prefix != NULL &&
			    req->id2name != NULL) {
				/* Already have SID and winname -- done */
				res->retcode = IDMAP_SUCCESS;
				continue;
			}

			if (res->id.idmap_id_u.sid.prefix != NULL) {
				/*
				 * SID but no winname -- lookup AD by
				 * SID to get winname.
				 * how info is not needed here because
				 * we are not retrieving unixname from
				 * AD.
				 */
				add = 1;
				retcode = idmap_sid2name_batch_add1(
				    qs, res->id.idmap_id_u.sid.prefix,
				    &res->id.idmap_id_u.sid.rid,
				    _IDMAP_T_UNDEF,
				    NULL, NULL, NULL,
				    &req->id2name,
				    &req->id2domain, (int *)&req->id2.idtype,
				    NULL, &res->retcode);
			} else if (req->id2name != NULL) {
				/*
				 * winname but no SID -- lookup AD by
				 * winname to get SID.
				 * how info is not needed here because
				 * we are not retrieving unixname from
				 * AD.
				 */
				add = 1;
				retcode = idmap_name2sid_batch_add1(
				    qs, req->id2name, req->id2domain,
				    _IDMAP_T_UNDEF,
				    NULL, NULL, NULL, NULL,
				    &res->id.idmap_id_u.sid.prefix,
				    &res->id.idmap_id_u.sid.rid,
				    (int *)&req->id2.idtype, NULL,
				    &res->retcode);
			} else if (req->id1name != NULL) {
				/*
				 * No SID and no winname but we've unixname --
				 * lookup AD by unixname to get SID.
				 */
				is_user = (IS_REQUEST_UID(*req)) ? 1 : 0;
				if (res->id.idtype == IDMAP_USID)
					is_wuser = 1;
				else if (res->id.idtype == IDMAP_GSID)
					is_wuser = 0;
				else
					is_wuser = is_user;
				add = 1;
				idmap_info_free(&res->info);
				res->info.src = IDMAP_MAP_SRC_NEW;
				how->map_type = IDMAP_MAP_TYPE_DS_AD;
				retcode = idmap_unixname2sid_batch_add1(
				    qs, req->id1name, is_user, is_wuser,
				    &how->idmap_how_u.ad.dn,
				    &how->idmap_how_u.ad.attr,
				    &how->idmap_how_u.ad.value,
				    &res->id.idmap_id_u.sid.prefix,
				    &res->id.idmap_id_u.sid.rid,
				    &req->id2name, &req->id2domain,
				    (int *)&req->id2.idtype, &res->retcode);
			}
		}
		if (retcode != IDMAP_SUCCESS) {
			idmap_lookup_release_batch(&qs);
			break;
		}
	}

	if (retcode == IDMAP_SUCCESS && add)
		retcode = idmap_lookup_batch_end(&qs);

	if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR && retries++ < 2)
		goto retry;
	else if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR)
		degrade_svc(1, "some AD lookups timed out repeatedly");

	if (retcode != IDMAP_SUCCESS)
		idmapdlog(LOG_NOTICE, "Failed to batch AD lookup requests");

out:
	/*
	 * This loop does the following:
	 * 1. Reset _IDMAP_F_LOOKUP_AD flag from the request.
	 * 2. Reset req->id2.idtype to IDMAP_NONE
	 * 3. If batch_start or batch_add failed then set the status
	 *    of each request marked for AD lookup to that error.
	 * 4. Evaluate the type of the AD object (i.e. user or group) and
	 *    update the idtype in request.
	 */
	for (i = 0; i < batch->idmap_mapping_batch_len; i++) {
		req = &batch->idmap_mapping_batch_val[i];
		type = req->id2.idtype;
		req->id2.idtype = IDMAP_NONE;
		res = &result->ids.ids_val[i];
		how = &res->info.how;
		if (!(req->direction & _IDMAP_F_LOOKUP_AD))
			continue;

		/* Reset AD lookup flag */
		req->direction &= ~(_IDMAP_F_LOOKUP_AD);

		/*
		 * If batch_start or batch_add failed then set the status
		 * of each request marked for AD lookup to that error.
		 */
		if (retcode != IDMAP_SUCCESS) {
			res->retcode = retcode;
			continue;
		}

		if (!add)
			continue;

		if (res->retcode == IDMAP_ERR_NOTFOUND) {
			/* Nothing found - remove the preset info */
			idmap_info_free(&res->info);
		}

		if (IS_REQUEST_SID(*req, 1)) {
			if (res->retcode != IDMAP_SUCCESS)
				continue;
			/* Evaluate result type */
			switch (type) {
			case _IDMAP_T_USER:
				if (res->id.idtype == IDMAP_POSIXID)
					res->id.idtype = IDMAP_UID;
				req->id1.idtype = IDMAP_USID;
				break;
			case _IDMAP_T_GROUP:
				if (res->id.idtype == IDMAP_POSIXID)
					res->id.idtype = IDMAP_GID;
				req->id1.idtype = IDMAP_GSID;
				break;
			default:
				res->retcode = IDMAP_ERR_SID;
				break;
			}
			if (res->retcode == IDMAP_SUCCESS &&
			    req->id1name != NULL &&
			    (req->id2name == NULL ||
			    res->id.idmap_id_u.uid == SENTINEL_PID) &&
			    NLDAP_MODE(res->id.idtype, state)) {
				req->direction |= _IDMAP_F_LOOKUP_NLDAP;
				state->nldap_nqueries++;
			}
		} else if (IS_REQUEST_UID(*req) || IS_REQUEST_GID(*req)) {
			if (res->retcode != IDMAP_SUCCESS) {
				if ((!(IDMAP_FATAL_ERROR(res->retcode))) &&
				    res->id.idmap_id_u.sid.prefix == NULL &&
				    req->id2name == NULL && /* no winname */
				    req->id1name != NULL) /* unixname */
					/*
					 * If AD lookup by unixname failed
					 * with non fatal error then clear
					 * the error (i.e set res->retcode
					 * to success). This allows the next
					 * pass to process other mapping
					 * mechanisms for this request.
					 */
					res->retcode = IDMAP_SUCCESS;
				continue;
			}
			/* Evaluate result type */
			switch (type) {
			case _IDMAP_T_USER:
				if (res->id.idtype == IDMAP_SID)
					res->id.idtype = IDMAP_USID;
				break;
			case _IDMAP_T_GROUP:
				if (res->id.idtype == IDMAP_SID)
					res->id.idtype = IDMAP_GSID;
				break;
			default:
				res->retcode = IDMAP_ERR_SID;
				break;
			}
		}
	}

	/* AD lookups done. Reset state->ad_nqueries and return */
	state->ad_nqueries = 0;
	return (retcode);
}

/*
 * Convention when processing win2unix requests:
 *
 * Windows identity:
 * req->id1name =
 *              winname if given otherwise winname found will be placed
 *              here.
 * req->id1domain =
 *              windomain if given otherwise windomain found will be
 *              placed here.
 * req->id1.idtype =
 *              Either IDMAP_SID/USID/GSID. If this is IDMAP_SID then it'll
 *              be set to IDMAP_USID/GSID depending upon whether the
 *              given SID is user or group respectively. The user/group-ness
 *              is determined either when looking up well-known SIDs table OR
 *              if the SID is found in namecache OR by ad_lookup_one() OR by
 *              ad_lookup_batch().
 * req->id1..sid.[prefix, rid] =
 *              SID if given otherwise SID found will be placed here.
 *
 * Unix identity:
 * req->id2name =
 *              unixname found will be placed here.
 * req->id2domain =
 *              NOT USED
 * res->id.idtype =
 *              Target type initialized from req->id2.idtype. If
 *              it is IDMAP_POSIXID then actual type (IDMAP_UID/GID) found
 *              will be placed here.
 * res->id..[uid or gid] =
 *              UID/GID found will be placed here.
 *
 * Others:
 * res->retcode =
 *              Return status for this request will be placed here.
 * res->direction =
 *              Direction found will be placed here. Direction
 *              meaning whether the resultant mapping is valid
 *              only from win2unix or bi-directional.
 * req->direction =
 *              INTERNAL USE. Used by idmapd to set various
 *              flags (_IDMAP_F_xxxx) to aid in processing
 *              of the request.
 * req->id2.idtype =
 *              INTERNAL USE. Initially this is the requested target
 *              type and is used to initialize res->id.idtype.
 *              ad_lookup_batch() uses this field temporarily to store
 *              sid_type obtained by the batched AD lookups and after
 *              use resets it to IDMAP_NONE to prevent xdr from
 *              mis-interpreting the contents of req->id2.
 * req->id2..[uid or gid or sid] =
 *              NOT USED
 */

/*
 * This function does the following:
 * 1. Lookup well-known SIDs table.
 * 2. Check if the given SID is a local-SID and if so extract UID/GID from it.
 * 3. Lookup cache.
 * 4. Check if the client does not want new mapping to be allocated
 *    in which case this pass is the final pass.
 * 5. Set AD lookup flag if it determines that the next stage needs
 *    to do AD lookup.
 */
idmap_retcode
sid2pid_first_pass(lookup_state_t *state, idmap_mapping *req,
		idmap_id_res *res)
{
	idmap_retcode	retcode;
	int		wksid;

	/* Initialize result */
	res->id.idtype = req->id2.idtype;
	res->id.idmap_id_u.uid = SENTINEL_PID;
	res->direction = IDMAP_DIRECTION_UNDEF;
	wksid = 0;

	if (EMPTY_STRING(req->id1.idmap_id_u.sid.prefix)) {
		if (req->id1name == NULL) {
			retcode = IDMAP_ERR_ARG;
			goto out;
		}
		/* sanitize sidprefix */
		free(req->id1.idmap_id_u.sid.prefix);
		req->id1.idmap_id_u.sid.prefix = NULL;
	}

	/* Lookup well-known SIDs table */
	retcode = lookup_wksids_sid2pid(req, res, &wksid);
	if (retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	/* Check if this is a localsid */
	if (!wksid) {
		retcode = lookup_localsid2pid(req, res);
		if (retcode != IDMAP_ERR_NOTFOUND)
			goto out;
	}

	/* Lookup cache */
	retcode = lookup_cache_sid2pid(state->cache, req, res);
	if (retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	if (DO_NOT_ALLOC_NEW_ID_MAPPING(req) || AVOID_NAMESERVICE(req)) {
		retcode = IDMAP_ERR_NONEGENERATED;
		goto out;
	}

	/*
	 * Failed to find non-expired entry in cache. Next step is
	 * to determine if this request needs to be batched for AD lookup.
	 *
	 * At this point we have either sid or winname or both. If we don't
	 * have both then lookup name_cache for the sid or winname
	 * whichever is missing. If not found then this request will be
	 * batched for AD lookup.
	 */
	retcode = lookup_name_cache(state->cache, req, res);
	if (retcode != IDMAP_SUCCESS && retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	/*
	 * Set the flag to indicate that we are not done yet so that
	 * subsequent passes considers this request for name-based
	 * mapping and ephemeral mapping.
	 */
	state->sid2pid_done = FALSE;
	req->direction |= _IDMAP_F_NOTDONE;

	/*
	 * Even if we have both sid and winname, we still may need to batch
	 * this request for AD lookup if we don't have unixname and
	 * directory-based name mapping (AD or mixed) is enabled.
	 * We avoid AD lookup for well-known SIDs because they don't have
	 * regular AD objects.
	 */
	if (retcode != IDMAP_SUCCESS ||
	    (!wksid && req->id2name == NULL &&
	    AD_OR_MIXED_MODE(res->id.idtype, state))) {
		retcode = IDMAP_SUCCESS;
		req->direction |= _IDMAP_F_LOOKUP_AD;
		state->ad_nqueries++;
	} else if (NLDAP_MODE(res->id.idtype, state)) {
		req->direction |= _IDMAP_F_LOOKUP_NLDAP;
		state->nldap_nqueries++;
	}


out:
	res->retcode = idmap_stat4prot(retcode);
	/*
	 * If we are done and there was an error then set fallback pid
	 * in the result.
	 */
	if (ARE_WE_DONE(req->direction) && res->retcode != IDMAP_SUCCESS)
		res->id.idmap_id_u.uid = UID_NOBODY;
	return (retcode);
}

/*
 * Generate SID using the following convention
 * 	<machine-sid-prefix>-<1000 + uid>
 * 	<machine-sid-prefix>-<2^31 + gid>
 */
static
idmap_retcode
generate_localsid(idmap_mapping *req, idmap_id_res *res, int is_user,
		int fallback)
{
	free(res->id.idmap_id_u.sid.prefix);
	res->id.idmap_id_u.sid.prefix = NULL;

	/*
	 * Diagonal mapping for localSIDs not supported because of the
	 * way we generate localSIDs.
	 */
	if (is_user && res->id.idtype == IDMAP_GSID)
		return (IDMAP_ERR_NOMAPPING);
	if (!is_user && res->id.idtype == IDMAP_USID)
		return (IDMAP_ERR_NOMAPPING);

	/* Skip 1000 UIDs */
	if (is_user && req->id1.idmap_id_u.uid >
	    (INT32_MAX - LOCALRID_MIN))
		return (IDMAP_ERR_NOMAPPING);

	RDLOCK_CONFIG();
	/*
	 * machine_sid is never NULL because if it is we won't be here.
	 * No need to assert because stdrup(NULL) will core anyways.
	 */
	res->id.idmap_id_u.sid.prefix =
	    strdup(_idmapdstate.cfg->pgcfg.machine_sid);
	if (res->id.idmap_id_u.sid.prefix == NULL) {
		UNLOCK_CONFIG();
		idmapdlog(LOG_ERR, "Out of memory");
		return (IDMAP_ERR_MEMORY);
	}
	UNLOCK_CONFIG();
	res->id.idmap_id_u.sid.rid =
	    (is_user) ? req->id1.idmap_id_u.uid + LOCALRID_MIN :
	    req->id1.idmap_id_u.gid + INT32_MAX + 1;
	res->direction = IDMAP_DIRECTION_BI;
	if (res->id.idtype == IDMAP_SID)
		res->id.idtype = is_user ? IDMAP_USID : IDMAP_GSID;

	if (!fallback && req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
		res->info.how.map_type = IDMAP_MAP_TYPE_LOCAL_SID;
		res->info.src = IDMAP_MAP_SRC_ALGORITHMIC;
	}

	/*
	 * Don't update name_cache because local sids don't have
	 * valid windows names.
	 */
	req->direction |= _IDMAP_F_DONT_UPDATE_NAMECACHE;
	return (IDMAP_SUCCESS);
}

static
idmap_retcode
lookup_localsid2pid(idmap_mapping *req, idmap_id_res *res)
{
	char		*sidprefix;
	uint32_t	rid;
	int		s;

	/*
	 * If the sidprefix == localsid then UID = last RID - 1000 or
	 * GID = last RID - 2^31.
	 */
	if ((sidprefix = req->id1.idmap_id_u.sid.prefix) == NULL)
		/* This means we are looking up by winname */
		return (IDMAP_ERR_NOTFOUND);
	rid = req->id1.idmap_id_u.sid.rid;

	RDLOCK_CONFIG();
	s = (_idmapdstate.cfg->pgcfg.machine_sid) ?
	    strcasecmp(sidprefix, _idmapdstate.cfg->pgcfg.machine_sid) : 1;
	UNLOCK_CONFIG();

	/*
	 * If the given sidprefix does not match machine_sid then this is
	 * not a local SID.
	 */
	if (s != 0)
		return (IDMAP_ERR_NOTFOUND);

	switch (res->id.idtype) {
	case IDMAP_UID:
		if (rid > INT32_MAX || rid < LOCALRID_MIN)
			return (IDMAP_ERR_ARG);
		res->id.idmap_id_u.uid = rid - LOCALRID_MIN;
		break;
	case IDMAP_GID:
		if (rid <= INT32_MAX)
			return (IDMAP_ERR_ARG);
		res->id.idmap_id_u.gid = rid - INT32_MAX - 1;
		break;
	case IDMAP_POSIXID:
		if (rid > INT32_MAX) {
			res->id.idmap_id_u.gid = rid - INT32_MAX - 1;
			res->id.idtype = IDMAP_GID;
		} else if (rid < LOCALRID_MIN) {
			return (IDMAP_ERR_ARG);
		} else {
			res->id.idmap_id_u.uid = rid - LOCALRID_MIN;
			res->id.idtype = IDMAP_UID;
		}
		break;
	default:
		return (IDMAP_ERR_NOTSUPPORTED);
	}
	if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
		res->info.how.map_type = IDMAP_MAP_TYPE_LOCAL_SID;
		res->info.src = IDMAP_MAP_SRC_ALGORITHMIC;
	}
	return (IDMAP_SUCCESS);
}

/*
 * Name service lookup by unixname to get pid
 */
static
idmap_retcode
ns_lookup_byname(const char *name, const char *lower_name, idmap_id *id)
{
	struct passwd	pwd, *pwdp;
	struct group	grp, *grpp;
	char		buf[1024];
	int		errnum;
	const char	*me = "ns_lookup_byname";

	switch (id->idtype) {
	case IDMAP_UID:
		pwdp = getpwnam_r(name, &pwd, buf, sizeof (buf));
		if (pwdp == NULL && errno == 0 && lower_name != NULL &&
		    name != lower_name && strcmp(name, lower_name) != 0)
			pwdp = getpwnam_r(lower_name, &pwd, buf, sizeof (buf));
		if (pwdp == NULL) {
			errnum = errno;
			idmapdlog(LOG_WARNING,
			    "%s: getpwnam_r(%s) failed (%s).",
			    me, name, errnum ? strerror(errnum) : "not found");
			if (errnum == 0)
				return (IDMAP_ERR_NOTFOUND);
			else
				return (IDMAP_ERR_INTERNAL);
		}
		id->idmap_id_u.uid = pwd.pw_uid;
		break;
	case IDMAP_GID:
		grpp = getgrnam_r(name, &grp, buf, sizeof (buf));
		if (grpp == NULL && errno == 0 && lower_name != NULL &&
		    name != lower_name && strcmp(name, lower_name) != 0)
			grpp = getgrnam_r(lower_name, &grp, buf, sizeof (buf));
		if (grpp == NULL) {
			errnum = errno;
			idmapdlog(LOG_WARNING,
			    "%s: getgrnam_r(%s) failed (%s).",
			    me, name, errnum ? strerror(errnum) : "not found");
			if (errnum == 0)
				return (IDMAP_ERR_NOTFOUND);
			else
				return (IDMAP_ERR_INTERNAL);
		}
		id->idmap_id_u.gid = grp.gr_gid;
		break;
	default:
		return (IDMAP_ERR_ARG);
	}
	return (IDMAP_SUCCESS);
}


/*
 * Name service lookup by pid to get unixname
 */
static
idmap_retcode
ns_lookup_bypid(uid_t pid, int is_user, char **unixname)
{
	struct passwd	pwd;
	struct group	grp;
	char		buf[1024];
	int		errnum;
	const char	*me = "ns_lookup_bypid";

	if (is_user) {
		errno = 0;
		if (getpwuid_r(pid, &pwd, buf, sizeof (buf)) == NULL) {
			errnum = errno;
			idmapdlog(LOG_WARNING,
			    "%s: getpwuid_r(%u) failed (%s).",
			    me, pid, errnum ? strerror(errnum) : "not found");
			if (errnum == 0)
				return (IDMAP_ERR_NOTFOUND);
			else
				return (IDMAP_ERR_INTERNAL);
		}
		*unixname = strdup(pwd.pw_name);
	} else {
		errno = 0;
		if (getgrgid_r(pid, &grp, buf, sizeof (buf)) == NULL) {
			errnum = errno;
			idmapdlog(LOG_WARNING,
			    "%s: getgrgid_r(%u) failed (%s).",
			    me, pid, errnum ? strerror(errnum) : "not found");
			if (errnum == 0)
				return (IDMAP_ERR_NOTFOUND);
			else
				return (IDMAP_ERR_INTERNAL);
		}
		*unixname = strdup(grp.gr_name);
	}
	if (*unixname == NULL)
		return (IDMAP_ERR_MEMORY);
	return (IDMAP_SUCCESS);
}

/*
 * Name-based mapping
 *
 * Case 1: If no rule matches do ephemeral
 *
 * Case 2: If rule matches and unixname is "" then return no mapping.
 *
 * Case 3: If rule matches and unixname is specified then lookup name
 *  service using the unixname. If unixname not found then return no mapping.
 *
 * Case 4: If rule matches and unixname is * then lookup name service
 *  using winname as the unixname. If unixname not found then process
 *  other rules using the lookup order. If no other rule matches then do
 *  ephemeral. Otherwise, based on the matched rule do Case 2 or 3 or 4.
 *  This allows us to specify a fallback unixname per _domain_ or no mapping
 *  instead of the default behaviour of doing ephemeral mapping.
 *
 * Example 1:
 * *@sfbay == *
 * If looking up windows users foo@sfbay and foo does not exists in
 * the name service then foo@sfbay will be mapped to an ephemeral id.
 *
 * Example 2:
 * *@sfbay == *
 * *@sfbay => guest
 * If looking up windows users foo@sfbay and foo does not exists in
 * the name service then foo@sfbay will be mapped to guest.
 *
 * Example 3:
 * *@sfbay == *
 * *@sfbay => ""
 * If looking up windows users foo@sfbay and foo does not exists in
 * the name service then we will return no mapping for foo@sfbay.
 *
 */
static
idmap_retcode
name_based_mapping_sid2pid(lookup_state_t *state,
		idmap_mapping *req, idmap_id_res *res)
{
	const char	*unixname, *windomain;
	char		*sql = NULL, *errmsg = NULL, *lower_winname = NULL;
	idmap_retcode	retcode;
	char		*end, *lower_unixname, *winname;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol, r, i, is_user, is_wuser;
	idmap_namerule	*rule = &res->info.how.idmap_how_u.rule;
	int		direction;
	const char	*me = "name_based_mapping_sid2pid";

	assert(req->id1name != NULL); /* We have winname */
	assert(req->id2name == NULL); /* We don't have unixname */

	winname = req->id1name;
	windomain = req->id1domain;

	switch (req->id1.idtype) {
	case IDMAP_USID:
		is_wuser = 1;
		break;
	case IDMAP_GSID:
		is_wuser = 0;
		break;
	default:
		idmapdlog(LOG_ERR, "%s: Unable to determine if the "
		    "given Windows id is user or group.", me);
		return (IDMAP_ERR_INTERNAL);
	}

	switch (res->id.idtype) {
	case IDMAP_UID:
		is_user = 1;
		break;
	case IDMAP_GID:
		is_user = 0;
		break;
	case IDMAP_POSIXID:
		is_user = is_wuser;
		res->id.idtype = is_user ? IDMAP_UID : IDMAP_GID;
		break;
	}

	i = 0;
	if (windomain == NULL)
		windomain = "";
	else if (state->defdom != NULL &&
	    strcasecmp(state->defdom, windomain) == 0)
		i = 1;

	if ((lower_winname = tolower_u8(winname)) == NULL)
		lower_winname = winname;    /* hope for the best */
	sql = sqlite_mprintf(
	    "SELECT unixname, u2w_order, winname_display, windomain, is_nt4 "
	    "FROM namerules WHERE "
	    "w2u_order > 0 AND is_user = %d AND is_wuser = %d AND "
	    "(winname = %Q OR winname = '*') AND "
	    "(windomain = %Q OR windomain = '*' %s) "
	    "ORDER BY w2u_order ASC;",
	    is_user, is_wuser, lower_winname, windomain,
	    i ? "OR windomain ISNULL OR windomain = ''" : "");
	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}

	if (sqlite_compile(state->db, sql, NULL, &vm, &errmsg) != SQLITE_OK) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "%s: database error (%s)", me,
		    CHECK_NULL(errmsg));
		sqlite_freemem(errmsg);
		goto out;
	}

	for (;;) {
		r = sqlite_step(vm, &ncol, &values, NULL);
		assert(r != SQLITE_LOCKED && r != SQLITE_BUSY);

		if (r == SQLITE_ROW) {
			if (ncol < 5) {
				retcode = IDMAP_ERR_INTERNAL;
				goto out;
			}
			if (values[0] == NULL) {
				retcode = IDMAP_ERR_INTERNAL;
				goto out;
			}

			if (values[1] != NULL)
				direction =
				    (strtol(values[1], &end, 10) == 0)?
				    IDMAP_DIRECTION_W2U:IDMAP_DIRECTION_BI;
			else
				direction = IDMAP_DIRECTION_W2U;

			if (EMPTY_NAME(values[0])) {
				idmap_namerule_set(rule, values[3], values[2],
				    values[0], is_wuser, is_user,
				    strtol(values[4], &end, 10),
				    direction);
				retcode = IDMAP_ERR_NOMAPPING;
				goto out;
			}

			if (values[0][0] == '*') {
				unixname = winname;
				lower_unixname = lower_winname;
			} else {
				unixname = values[0];
				lower_unixname = NULL;
			}

			retcode = ns_lookup_byname(unixname, lower_unixname,
			    &res->id);
			if (retcode == IDMAP_ERR_NOTFOUND) {
				if (values[0][0] == '*')
					/* Case 4 */
					continue;
				else {
					/* Case 3 */
					idmap_namerule_set(rule, values[3],
					    values[2], values[0], is_wuser,
					    is_user,
					    strtol(values[4], &end, 10),
					    direction);
					retcode = IDMAP_ERR_NOMAPPING;
				}
			}
			goto out;
		} else if (r == SQLITE_DONE) {
			retcode = IDMAP_ERR_NOTFOUND;
			goto out;
		} else {
			(void) sqlite_finalize(vm, &errmsg);
			vm = NULL;
			idmapdlog(LOG_ERR, "%s: database error (%s)", me,
			    CHECK_NULL(errmsg));
			sqlite_freemem(errmsg);
			retcode = IDMAP_ERR_INTERNAL;
			goto out;
		}
	}

out:
	if (sql != NULL)
		sqlite_freemem(sql);
	res->info.how.map_type = IDMAP_MAP_TYPE_RULE_BASED;
	if (retcode == IDMAP_SUCCESS) {
		if (values[1] != NULL)
			res->direction =
			    (strtol(values[1], &end, 10) == 0)?
			    IDMAP_DIRECTION_W2U:IDMAP_DIRECTION_BI;
		else
			res->direction = IDMAP_DIRECTION_W2U;

		req->id2name = strdup(unixname);
		if (req->id2name == NULL) {
			retcode = IDMAP_ERR_MEMORY;
		}
	}

	if (retcode == IDMAP_SUCCESS) {
		idmap_namerule_set(rule, values[3], values[2],
		    values[0], is_wuser, is_user, strtol(values[4], &end, 10),
		    res->direction);
		res->info.src = IDMAP_MAP_SRC_NEW;
	}

	if (lower_winname != NULL && lower_winname != winname)
		free(lower_winname);
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

static
int
get_next_eph_uid(uid_t *next_uid)
{
	uid_t uid;
	gid_t gid;
	int err;

	*next_uid = (uid_t)-1;
	uid = _idmapdstate.next_uid++;
	if (uid >= _idmapdstate.limit_uid) {
		if ((err = allocids(0, 8192, &uid, 0, &gid)) != 0)
			return (err);

		_idmapdstate.limit_uid = uid + 8192;
		_idmapdstate.next_uid = uid;
	}
	*next_uid = uid;

	return (0);
}

static
int
get_next_eph_gid(gid_t *next_gid)
{
	uid_t uid;
	gid_t gid;
	int err;

	*next_gid = (uid_t)-1;
	gid = _idmapdstate.next_gid++;
	if (gid >= _idmapdstate.limit_gid) {
		if ((err = allocids(0, 0, &uid, 8192, &gid)) != 0)
			return (err);

		_idmapdstate.limit_gid = gid + 8192;
		_idmapdstate.next_gid = gid;
	}
	*next_gid = gid;

	return (0);
}

static
int
gethash(const char *str, uint32_t num, uint_t htsize)
{
	uint_t  hval, i, len;

	if (str == NULL)
		return (0);
	for (len = strlen(str), hval = 0, i = 0; i < len; i++) {
		hval += str[i];
		hval += (hval << 10);
		hval ^= (hval >> 6);
	}
	for (str = (const char *)&num, i = 0; i < sizeof (num); i++) {
		hval += str[i];
		hval += (hval << 10);
		hval ^= (hval >> 6);
	}
	hval += (hval << 3);
	hval ^= (hval >> 11);
	hval += (hval << 15);
	return (hval % htsize);
}

static
int
get_from_sid_history(lookup_state_t *state, const char *prefix, uint32_t rid,
		uid_t *pid)
{
	uint_t		next, key;
	uint_t		htsize = state->sid_history_size;
	idmap_sid	*sid;

	next = gethash(prefix, rid, htsize);
	while (next != htsize) {
		key = state->sid_history[next].key;
		if (key == htsize)
			return (0);
		sid = &state->batch->idmap_mapping_batch_val[key].id1.
		    idmap_id_u.sid;
		if (sid->rid == rid && strcmp(sid->prefix, prefix) == 0) {
			*pid = state->result->ids.ids_val[key].id.
			    idmap_id_u.uid;
			return (1);
		}
		next = state->sid_history[next].next;
	}
	return (0);
}

static
void
add_to_sid_history(lookup_state_t *state, const char *prefix, uint32_t rid)
{
	uint_t		hash, next;
	uint_t		htsize = state->sid_history_size;

	hash = next = gethash(prefix, rid, htsize);
	while (state->sid_history[next].key != htsize) {
		next++;
		next %= htsize;
	}
	state->sid_history[next].key = state->curpos;
	if (hash == next)
		return;
	state->sid_history[next].next = state->sid_history[hash].next;
	state->sid_history[hash].next = next;
}

void
cleanup_lookup_state(lookup_state_t *state)
{
	free(state->sid_history);
	free(state->ad_unixuser_attr);
	free(state->ad_unixgroup_attr);
	free(state->nldap_winname_attr);
	free(state->defdom);
}

/* ARGSUSED */
static
idmap_retcode
dynamic_ephemeral_mapping(lookup_state_t *state,
		idmap_mapping *req, idmap_id_res *res)
{

	uid_t		next_pid;

	res->direction = IDMAP_DIRECTION_BI;

	if (IS_EPHEMERAL(res->id.idmap_id_u.uid)) {
		res->info.how.map_type = IDMAP_MAP_TYPE_EPHEMERAL;
		res->info.src = IDMAP_MAP_SRC_CACHE;
		return (IDMAP_SUCCESS);
	}

	if (state->sid_history != NULL &&
	    get_from_sid_history(state, req->id1.idmap_id_u.sid.prefix,
	    req->id1.idmap_id_u.sid.rid, &next_pid)) {
		res->id.idmap_id_u.uid = next_pid;
		res->info.how.map_type = IDMAP_MAP_TYPE_EPHEMERAL;
		res->info.src = IDMAP_MAP_SRC_NEW;
		return (IDMAP_SUCCESS);
	}

	if (res->id.idtype == IDMAP_UID) {
		if (get_next_eph_uid(&next_pid) != 0)
			return (IDMAP_ERR_INTERNAL);
		res->id.idmap_id_u.uid = next_pid;
	} else {
		if (get_next_eph_gid(&next_pid) != 0)
			return (IDMAP_ERR_INTERNAL);
		res->id.idmap_id_u.gid = next_pid;
	}

	res->info.how.map_type = IDMAP_MAP_TYPE_EPHEMERAL;
	res->info.src = IDMAP_MAP_SRC_NEW;
	if (state->sid_history != NULL)
		add_to_sid_history(state, req->id1.idmap_id_u.sid.prefix,
		    req->id1.idmap_id_u.sid.rid);

	return (IDMAP_SUCCESS);
}

idmap_retcode
sid2pid_second_pass(lookup_state_t *state,
		idmap_mapping *req, idmap_id_res *res)
{
	idmap_retcode	retcode;

	/* Check if second pass is needed */
	if (ARE_WE_DONE(req->direction))
		return (res->retcode);

	/* Get status from previous pass */
	retcode = res->retcode;
	if (retcode != IDMAP_SUCCESS)
		goto out;

	/*
	 * If directory-based name mapping is enabled then the unixname
	 * may already have been retrieved from the AD object (AD-mode or
	 * mixed-mode) or from native LDAP object (nldap-mode) -- done.
	 */
	if (req->id2name != NULL) {
		assert(res->id.idtype != IDMAP_POSIXID);
		if (AD_MODE(res->id.idtype, state))
			res->direction = IDMAP_DIRECTION_BI;
		else if (NLDAP_MODE(res->id.idtype, state))
			res->direction = IDMAP_DIRECTION_BI;
		else if (MIXED_MODE(res->id.idtype, state))
			res->direction = IDMAP_DIRECTION_W2U;

		/*
		 * Special case: (1) If the ad_unixuser_attr and
		 * ad_unixgroup_attr uses the same attribute
		 * name and (2) if this is a diagonal mapping
		 * request and (3) the unixname has been retrieved
		 * from the AD object -- then we ignore it and fallback
		 * to name-based mapping rules and ephemeral mapping
		 *
		 * Example:
		 *  Properties:
		 *    config/ad_unixuser_attr = "unixname"
		 *    config/ad_unixgroup_attr = "unixname"
		 *  AD user object:
		 *    dn: cn=bob ...
		 *    objectclass: user
		 *    sam: bob
		 *    unixname: bob1234
		 *  AD group object:
		 *    dn: cn=winadmins ...
		 *    objectclass: group
		 *    sam: winadmins
		 *    unixname: unixadmins
		 *
		 *  In this example whether "unixname" refers to a unixuser
		 *  or unixgroup depends upon the AD object.
		 *
		 * $idmap show -c winname:bob gid
		 *    AD lookup by "samAccountName=bob" for
		 *    "ad_unixgroup_attr (i.e unixname)" for directory-based
		 *    mapping would get "bob1234" which is not what we want.
		 *    Now why not getgrnam_r("bob1234") and use it if it
		 *    is indeed a unixgroup? That's because Unix can have
		 *    users and groups with the same name and we clearly
		 *    don't know the intention of the admin here.
		 *    Therefore we ignore this and fallback to name-based
		 *    mapping rules or ephemeral mapping.
		 */
		if ((AD_MODE(res->id.idtype, state) ||
		    MIXED_MODE(res->id.idtype, state)) &&
		    state->ad_unixuser_attr != NULL &&
		    state->ad_unixgroup_attr != NULL &&
		    strcasecmp(state->ad_unixuser_attr,
		    state->ad_unixgroup_attr) == 0 &&
		    ((req->id1.idtype == IDMAP_USID &&
		    res->id.idtype == IDMAP_GID) ||
		    (req->id1.idtype == IDMAP_GSID &&
		    res->id.idtype == IDMAP_UID))) {
			free(req->id2name);
			req->id2name = NULL;
			res->id.idmap_id_u.uid = SENTINEL_PID;
			/* fallback */
		} else {
			if (res->id.idmap_id_u.uid == SENTINEL_PID)
				retcode = ns_lookup_byname(req->id2name,
				    NULL, &res->id);
			/*
			 * If ns_lookup_byname() fails that means the
			 * unixname (req->id2name), which was obtained
			 * from the AD object by directory-based mapping,
			 * is not a valid Unix user/group and therefore
			 * we return the error to the client instead of
			 * doing rule-based mapping or ephemeral mapping.
			 * This way the client can detect the issue.
			 */
			goto out;
		}
	}

	/* Free any mapping info from Directory based mapping */
	if (res->info.how.map_type != IDMAP_MAP_TYPE_UNKNOWN)
		idmap_info_free(&res->info);

	/*
	 * If we don't have unixname then evaluate local name-based
	 * mapping rules.
	 */
	retcode = name_based_mapping_sid2pid(state, req, res);
	if (retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	/* If not found, do ephemeral mapping */
	retcode = dynamic_ephemeral_mapping(state, req, res);

out:
	res->retcode = idmap_stat4prot(retcode);
	if (res->retcode != IDMAP_SUCCESS) {
		req->direction = _IDMAP_F_DONE;
		res->id.idmap_id_u.uid = UID_NOBODY;
	}
	if (!ARE_WE_DONE(req->direction))
		state->sid2pid_done = FALSE;
	return (retcode);
}

idmap_retcode
update_cache_pid2sid(lookup_state_t *state,
		idmap_mapping *req, idmap_id_res *res)
{
	char		*sql = NULL;
	idmap_retcode	retcode;
	char		*map_dn = NULL;
	char		*map_attr = NULL;
	char		*map_value = NULL;
	char 		*map_windomain = NULL;
	char		*map_winname = NULL;
	char		*map_unixname = NULL;
	int		map_is_nt4 = FALSE;

	/* Check if we need to cache anything */
	if (ARE_WE_DONE(req->direction))
		return (IDMAP_SUCCESS);

	/* We don't cache negative entries */
	if (res->retcode != IDMAP_SUCCESS)
		return (IDMAP_SUCCESS);

	assert(res->direction != IDMAP_DIRECTION_UNDEF);
	assert(req->id1.idmap_id_u.uid != SENTINEL_PID);
	assert(res->id.idtype != IDMAP_SID);

	assert(res->info.how.map_type != IDMAP_MAP_TYPE_UNKNOWN);
	switch (res->info.how.map_type) {
	case IDMAP_MAP_TYPE_DS_AD:
		map_dn = res->info.how.idmap_how_u.ad.dn;
		map_attr = res->info.how.idmap_how_u.ad.attr;
		map_value = res->info.how.idmap_how_u.ad.value;
		break;

	case IDMAP_MAP_TYPE_DS_NLDAP:
		map_dn = res->info.how.idmap_how_u.nldap.dn;
		map_attr = res->info.how.idmap_how_u.nldap.attr;
		map_value = res->info.how.idmap_how_u.nldap.value;
		break;

	case IDMAP_MAP_TYPE_RULE_BASED:
		map_windomain = res->info.how.idmap_how_u.rule.windomain;
		map_winname = res->info.how.idmap_how_u.rule.winname;
		map_unixname = res->info.how.idmap_how_u.rule.unixname;
		map_is_nt4 = res->info.how.idmap_how_u.rule.is_nt4;
		break;

	case IDMAP_MAP_TYPE_EPHEMERAL:
		break;

	case IDMAP_MAP_TYPE_LOCAL_SID:
		break;

	default:
		/* Dont cache other mapping types */
		assert(FALSE);
	}

	/*
	 * Using NULL for u2w instead of 0 so that our trigger allows
	 * the same pid to be the destination in multiple entries
	 */
	sql = sqlite_mprintf("INSERT OR REPLACE into idmap_cache "
	    "(sidprefix, rid, windomain, canon_winname, pid, unixname, "
	    "is_user, is_wuser, expiration, w2u, u2w, "
	    "map_type, map_dn, map_attr, map_value, map_windomain, "
	    "map_winname, map_unixname, map_is_nt4) "
	    "VALUES(%Q, %u, %Q, %Q, %u, %Q, %d, %d, "
	    "strftime('%%s','now') + 600, %q, 1, "
	    "%d, %Q, %Q, %Q, %Q, %Q, %Q, %d); ",
	    res->id.idmap_id_u.sid.prefix, res->id.idmap_id_u.sid.rid,
	    req->id2domain, req->id2name, req->id1.idmap_id_u.uid,
	    req->id1name, (req->id1.idtype == IDMAP_UID) ? 1 : 0,
	    (res->id.idtype == IDMAP_USID) ? 1 : 0,
	    (res->direction == 0) ? "1" : NULL,
	    res->info.how.map_type, map_dn, map_attr, map_value,
	    map_windomain, map_winname, map_unixname, map_is_nt4);

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	retcode = sql_exec_no_cb(state->cache, IDMAP_CACHENAME, sql);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	state->pid2sid_done = FALSE;
	sqlite_freemem(sql);
	sql = NULL;

	/* Check if we need to update namecache */
	if (req->direction & _IDMAP_F_DONT_UPDATE_NAMECACHE)
		goto out;

	if (req->id2name == NULL)
		goto out;

	sql = sqlite_mprintf("INSERT OR REPLACE into name_cache "
	    "(sidprefix, rid, canon_name, domain, type, expiration) "
	    "VALUES(%Q, %u, %Q, %Q, %d, strftime('%%s','now') + 3600); ",
	    res->id.idmap_id_u.sid.prefix, res->id.idmap_id_u.sid.rid,
	    req->id2name, req->id2domain,
	    (res->id.idtype == IDMAP_USID) ? _IDMAP_T_USER : _IDMAP_T_GROUP);

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	retcode = sql_exec_no_cb(state->cache, IDMAP_CACHENAME, sql);

out:
	if (!(req->flag & IDMAP_REQ_FLG_MAPPING_INFO))
		idmap_info_free(&res->info);
	if (sql != NULL)
		sqlite_freemem(sql);
	return (retcode);
}

idmap_retcode
update_cache_sid2pid(lookup_state_t *state,
		idmap_mapping *req, idmap_id_res *res)
{
	char		*sql = NULL;
	idmap_retcode	retcode;
	int		is_eph_user;
	char		*map_dn = NULL;
	char		*map_attr = NULL;
	char		*map_value = NULL;
	char 		*map_windomain = NULL;
	char		*map_winname = NULL;
	char		*map_unixname = NULL;
	int		map_is_nt4 = FALSE;

	/* Check if we need to cache anything */
	if (ARE_WE_DONE(req->direction))
		return (IDMAP_SUCCESS);

	/* We don't cache negative entries */
	if (res->retcode != IDMAP_SUCCESS)
		return (IDMAP_SUCCESS);

	if (req->direction & _IDMAP_F_EXP_EPH_UID)
		is_eph_user = 1;
	else if (req->direction & _IDMAP_F_EXP_EPH_GID)
		is_eph_user = 0;
	else
		is_eph_user = -1;

	if (is_eph_user >= 0 && !IS_EPHEMERAL(res->id.idmap_id_u.uid)) {
		sql = sqlite_mprintf("UPDATE idmap_cache "
		    "SET w2u = 0 WHERE "
		    "sidprefix = %Q AND rid = %u AND w2u = 1 AND "
		    "pid >= 2147483648 AND is_user = %d;",
		    req->id1.idmap_id_u.sid.prefix,
		    req->id1.idmap_id_u.sid.rid,
		    is_eph_user);
		if (sql == NULL) {
			retcode = IDMAP_ERR_INTERNAL;
			idmapdlog(LOG_ERR, "Out of memory");
			goto out;
		}

		retcode = sql_exec_no_cb(state->cache, IDMAP_CACHENAME, sql);
		if (retcode != IDMAP_SUCCESS)
			goto out;

		sqlite_freemem(sql);
		sql = NULL;
	}

	assert(res->direction != IDMAP_DIRECTION_UNDEF);
	assert(res->id.idmap_id_u.uid != SENTINEL_PID);

	switch (res->info.how.map_type) {
	case IDMAP_MAP_TYPE_DS_AD:
		map_dn = res->info.how.idmap_how_u.ad.dn;
		map_attr = res->info.how.idmap_how_u.ad.attr;
		map_value = res->info.how.idmap_how_u.ad.value;
		break;

	case IDMAP_MAP_TYPE_DS_NLDAP:
		map_dn = res->info.how.idmap_how_u.nldap.dn;
		map_attr = res->info.how.idmap_how_u.ad.attr;
		map_value = res->info.how.idmap_how_u.nldap.value;
		break;

	case IDMAP_MAP_TYPE_RULE_BASED:
		map_windomain = res->info.how.idmap_how_u.rule.windomain;
		map_winname = res->info.how.idmap_how_u.rule.winname;
		map_unixname = res->info.how.idmap_how_u.rule.unixname;
		map_is_nt4 = res->info.how.idmap_how_u.rule.is_nt4;
		break;

	case IDMAP_MAP_TYPE_EPHEMERAL:
		break;

	default:
		/* Dont cache other mapping types */
		assert(FALSE);
	}

	sql = sqlite_mprintf("INSERT OR REPLACE into idmap_cache "
	    "(sidprefix, rid, windomain, canon_winname, pid, unixname, "
	    "is_user, is_wuser, expiration, w2u, u2w, "
	    "map_type, map_dn, map_attr, map_value, map_windomain, "
	    "map_winname, map_unixname, map_is_nt4) "
	    "VALUES(%Q, %u, %Q, %Q, %u, %Q, %d, %d, "
	    "strftime('%%s','now') + 600, 1, %q, "
	    "%d, %Q, %Q, %Q, %Q, %Q, %Q, %d);",
	    req->id1.idmap_id_u.sid.prefix, req->id1.idmap_id_u.sid.rid,
	    (req->id1domain != NULL) ? req->id1domain : "", req->id1name,
	    res->id.idmap_id_u.uid, req->id2name,
	    (res->id.idtype == IDMAP_UID) ? 1 : 0,
	    (req->id1.idtype == IDMAP_USID) ? 1 : 0,
	    (res->direction == 0) ? "1" : NULL,
	    res->info.how.map_type, map_dn, map_attr, map_value,
	    map_windomain, map_winname, map_unixname, map_is_nt4);

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	retcode = sql_exec_no_cb(state->cache, IDMAP_CACHENAME, sql);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	state->sid2pid_done = FALSE;
	sqlite_freemem(sql);
	sql = NULL;

	/* Check if we need to update namecache */
	if (req->direction & _IDMAP_F_DONT_UPDATE_NAMECACHE)
		goto out;

	if (EMPTY_STRING(req->id1name))
		goto out;

	sql = sqlite_mprintf("INSERT OR REPLACE into name_cache "
	    "(sidprefix, rid, canon_name, domain, type, expiration) "
	    "VALUES(%Q, %u, %Q, %Q, %d, strftime('%%s','now') + 3600); ",
	    req->id1.idmap_id_u.sid.prefix, req->id1.idmap_id_u.sid.rid,
	    req->id1name, req->id1domain,
	    (req->id1.idtype == IDMAP_USID) ? _IDMAP_T_USER : _IDMAP_T_GROUP);

	if (sql == NULL) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "Out of memory");
		goto out;
	}

	retcode = sql_exec_no_cb(state->cache, IDMAP_CACHENAME, sql);

out:
	if (!(req->flag & IDMAP_REQ_FLG_MAPPING_INFO))
		idmap_info_free(&res->info);

	if (sql != NULL)
		sqlite_freemem(sql);
	return (retcode);
}

static
idmap_retcode
lookup_cache_pid2sid(sqlite *cache, idmap_mapping *req, idmap_id_res *res,
		int is_user, int getname)
{
	char		*end;
	char		*sql = NULL;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol;
	idmap_retcode	retcode = IDMAP_SUCCESS;
	time_t		curtime;
	idmap_id_type	idtype;

	/* Current time */
	errno = 0;
	if ((curtime = time(NULL)) == (time_t)-1) {
		idmapdlog(LOG_ERR, "Failed to get current time (%s)",
		    strerror(errno));
		retcode = IDMAP_ERR_INTERNAL;
		goto out;
	}

	/* SQL to lookup the cache by pid or by unixname */
	if (req->id1.idmap_id_u.uid != SENTINEL_PID) {
		sql = sqlite_mprintf("SELECT sidprefix, rid, "
		    "canon_winname, windomain, w2u, is_wuser, "
		    "map_type, map_dn, map_attr, map_value, map_windomain, "
		    "map_winname, map_unixname, map_is_nt4 "
		    "FROM idmap_cache WHERE "
		    "pid = %u AND u2w = 1 AND is_user = %d AND "
		    "(pid >= 2147483648 OR "
		    "(expiration = 0 OR expiration ISNULL OR "
		    "expiration > %d));",
		    req->id1.idmap_id_u.uid, is_user, curtime);
	} else if (req->id1name != NULL) {
		sql = sqlite_mprintf("SELECT sidprefix, rid, "
		    "canon_winname, windomain, w2u, is_wuser, "
		    "map_type, map_dn, map_attr, map_value, map_windomain, "
		    "map_winname, map_unixname, map_is_nt4 "
		    "FROM idmap_cache WHERE "
		    "unixname = %Q AND u2w = 1 AND is_user = %d AND "
		    "(pid >= 2147483648 OR "
		    "(expiration = 0 OR expiration ISNULL OR "
		    "expiration > %d));",
		    req->id1name, is_user, curtime);
	} else {
		retcode = IDMAP_ERR_ARG;
		goto out;
	}

	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	retcode = sql_compile_n_step_once(
	    cache, sql, &vm, &ncol, 14, &values);
	sqlite_freemem(sql);

	if (retcode == IDMAP_ERR_NOTFOUND)
		goto out;
	else if (retcode == IDMAP_SUCCESS) {
		/* sanity checks */
		if (values[0] == NULL || values[1] == NULL) {
			retcode = IDMAP_ERR_CACHE;
			goto out;
		}

		switch (res->id.idtype) {
		case IDMAP_SID:
		case IDMAP_USID:
		case IDMAP_GSID:
			idtype = strtol(values[5], &end, 10) == 1
			    ? IDMAP_USID : IDMAP_GSID;

			if (res->id.idtype == IDMAP_USID &&
			    idtype != IDMAP_USID) {
				retcode = IDMAP_ERR_NOTUSER;
				goto out;
			} else if (res->id.idtype == IDMAP_GSID &&
			    idtype != IDMAP_GSID) {
				retcode = IDMAP_ERR_NOTGROUP;
				goto out;
			}
			res->id.idtype = idtype;

			res->id.idmap_id_u.sid.rid =
			    strtoul(values[1], &end, 10);
			res->id.idmap_id_u.sid.prefix = strdup(values[0]);
			if (res->id.idmap_id_u.sid.prefix == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}

			if (values[4] != NULL)
				res->direction =
				    (strtol(values[4], &end, 10) == 0)?
				    IDMAP_DIRECTION_U2W:IDMAP_DIRECTION_BI;
			else
				res->direction = IDMAP_DIRECTION_U2W;

			if (getname == 0 || values[2] == NULL)
				break;
			req->id2name = strdup(values[2]);
			if (req->id2name == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}

			if (values[3] == NULL)
				break;
			req->id2domain = strdup(values[3]);
			if (req->id2domain == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}

			break;
		default:
			retcode = IDMAP_ERR_NOTSUPPORTED;
			break;
		}
		if (req->flag & IDMAP_REQ_FLG_MAPPING_INFO) {
			res->info.src = IDMAP_MAP_SRC_CACHE;
			res->info.how.map_type = strtoul(values[6], &end, 10);
			switch (res->info.how.map_type) {
			case IDMAP_MAP_TYPE_DS_AD:
				res->info.how.idmap_how_u.ad.dn =
				    strdup(values[7]);
				res->info.how.idmap_how_u.ad.attr =
				    strdup(values[8]);
				res->info.how.idmap_how_u.ad.value =
				    strdup(values[9]);
				break;

			case IDMAP_MAP_TYPE_DS_NLDAP:
				res->info.how.idmap_how_u.nldap.dn =
				    strdup(values[7]);
				res->info.how.idmap_how_u.nldap.attr =
				    strdup(values[8]);
				res->info.how.idmap_how_u.nldap.value =
				    strdup(values[9]);
				break;

			case IDMAP_MAP_TYPE_RULE_BASED:
				res->info.how.idmap_how_u.rule.windomain =
				    strdup(values[10]);
				res->info.how.idmap_how_u.rule.winname =
				    strdup(values[11]);
				res->info.how.idmap_how_u.rule.unixname =
				    strdup(values[12]);
				res->info.how.idmap_how_u.rule.is_nt4 =
				    strtoul(values[13], &end, 10);
				res->info.how.idmap_how_u.rule.is_user =
				    is_user;
				res->info.how.idmap_how_u.rule.is_wuser =
				    strtol(values[5], &end, 10);
				break;

			case IDMAP_MAP_TYPE_EPHEMERAL:
				break;

			case IDMAP_MAP_TYPE_LOCAL_SID:
				break;

			case IDMAP_MAP_TYPE_KNOWN_SID:
				break;

			default:
				/* Unknow mapping type */
				assert(FALSE);
			}
		}
	}

out:
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

static
idmap_retcode
lookup_cache_name2sid(sqlite *cache, const char *name, const char *domain,
	char **canonname, char **sidprefix, idmap_rid_t *rid, int *type)
{
	char		*end, *lower_name;
	char		*sql = NULL;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol;
	time_t		curtime;
	idmap_retcode	retcode = IDMAP_SUCCESS;

	/* Get current time */
	errno = 0;
	if ((curtime = time(NULL)) == (time_t)-1) {
		idmapdlog(LOG_ERR, "Failed to get current time (%s)",
		    strerror(errno));
		retcode = IDMAP_ERR_INTERNAL;
		goto out;
	}

	/* SQL to lookup the cache */
	if ((lower_name = tolower_u8(name)) == NULL)
		lower_name = (char *)name;
	sql = sqlite_mprintf("SELECT sidprefix, rid, type, canon_name "
	    "FROM name_cache WHERE name = %Q AND domain = %Q AND "
	    "(expiration = 0 OR expiration ISNULL OR "
	    "expiration > %d);", lower_name, domain, curtime);
	if (lower_name != name)
		free(lower_name);
	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}
	retcode = sql_compile_n_step_once(cache, sql, &vm, &ncol, 4, &values);
	sqlite_freemem(sql);

	if (retcode == IDMAP_SUCCESS) {
		if (type != NULL) {
			if (values[2] == NULL) {
				retcode = IDMAP_ERR_CACHE;
				goto out;
			}
			*type = strtol(values[2], &end, 10);
		}

		if (values[0] == NULL || values[1] == NULL) {
			retcode = IDMAP_ERR_CACHE;
			goto out;
		}

		if (canonname != NULL) {
			assert(values[3] != NULL);
			if ((*canonname = strdup(values[3])) == NULL) {
				idmapdlog(LOG_ERR, "Out of memory");
				retcode = IDMAP_ERR_MEMORY;
				goto out;
			}
		}

		if ((*sidprefix = strdup(values[0])) == NULL) {
			idmapdlog(LOG_ERR, "Out of memory");
			retcode = IDMAP_ERR_MEMORY;
			if (canonname != NULL) {
				free(*canonname);
				*canonname = NULL;
			}
			goto out;
		}
		*rid = strtoul(values[1], &end, 10);
	}

out:
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

static
idmap_retcode
ad_lookup_by_winname(lookup_state_t *state,
		const char *name, const char *domain, int eunixtype,
		char **dn, char **attr, char **value, char **canonname,
		char **sidprefix, idmap_rid_t *rid, int *wintype,
		char **unixname)
{
	int			retries = 0;
	idmap_query_state_t	*qs = NULL;
	idmap_retcode		rc, retcode;

retry:
	retcode = idmap_lookup_batch_start(_idmapdstate.ad, 1, &qs);
	if (retcode != IDMAP_SUCCESS) {
		if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR && retries++ < 2)
			goto retry;
		degrade_svc(1, "failed to create request for AD lookup "
		    "by winname");
		return (retcode);
	}

	restore_svc();

	if (state != NULL)
		idmap_lookup_batch_set_unixattr(qs, state->ad_unixuser_attr,
		    state->ad_unixgroup_attr);

	retcode = idmap_name2sid_batch_add1(qs, name, domain, eunixtype,
	    dn, attr, value, canonname, sidprefix, rid, wintype, unixname, &rc);

	if (retcode != IDMAP_SUCCESS)
		idmap_lookup_release_batch(&qs);
	else
		retcode = idmap_lookup_batch_end(&qs);

	if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR && retries++ < 2)
		goto retry;
	else if (retcode == IDMAP_ERR_RETRIABLE_NET_ERR)
		degrade_svc(1, "some AD lookups timed out repeatedly");

	if (retcode != IDMAP_SUCCESS) {
		idmapdlog(LOG_NOTICE, "AD lookup by winname failed");
		return (retcode);
	}
	return (rc);
}

idmap_retcode
lookup_name2sid(sqlite *cache, const char *name, const char *domain,
		int *is_wuser, char **canonname, char **sidprefix,
		idmap_rid_t *rid, idmap_mapping *req, int local_only)
{
	int		type;
	idmap_retcode	retcode;

	*sidprefix = NULL;
	if (canonname != NULL)
		*canonname = NULL;

	/* Lookup well-known SIDs table */
	retcode = lookup_wksids_name2sid(name, canonname, sidprefix, rid,
	    &type);
	if (retcode == IDMAP_SUCCESS) {
		req->direction |= _IDMAP_F_DONT_UPDATE_NAMECACHE;
		goto out;
	} else if (retcode != IDMAP_ERR_NOTFOUND) {
		return (retcode);
	}

	/* Lookup cache */
	retcode = lookup_cache_name2sid(cache, name, domain, canonname,
	    sidprefix, rid, &type);
	if (retcode == IDMAP_SUCCESS) {
		req->direction |= _IDMAP_F_DONT_UPDATE_NAMECACHE;
		goto out;
	} else if (retcode != IDMAP_ERR_NOTFOUND) {
		return (retcode);
	}

	/*
	 * The caller may be using this function to determine if this
	 * request needs to be marked for AD lookup or not
	 * (i.e. _IDMAP_F_LOOKUP_AD) and therefore may not want this
	 * function to AD lookup now.
	 */
	if (local_only)
		return (retcode);

	/* Lookup AD */
	retcode = ad_lookup_by_winname(NULL, name, domain, _IDMAP_T_UNDEF,
	    NULL, NULL, NULL, canonname, sidprefix, rid, &type, NULL);
	if (retcode != IDMAP_SUCCESS)
		return (retcode);

out:
	/*
	 * Entry found (cache or Windows lookup)
	 * is_wuser is both input as well as output parameter
	 */
	if (*is_wuser == 1 && type != _IDMAP_T_USER)
		retcode = IDMAP_ERR_NOTUSER;
	else if (*is_wuser == 0 && type != _IDMAP_T_GROUP)
		retcode = IDMAP_ERR_NOTGROUP;
	else if (*is_wuser == -1) {
		/* Caller wants to know if its user or group */
		if (type == _IDMAP_T_USER)
			*is_wuser = 1;
		else if (type == _IDMAP_T_GROUP)
			*is_wuser = 0;
		else
			retcode = IDMAP_ERR_SID;
	}

	if (retcode != IDMAP_SUCCESS) {
		free(*sidprefix);
		*sidprefix = NULL;
		if (canonname != NULL) {
			free(*canonname);
			*canonname = NULL;
		}
	}
	return (retcode);
}

static
idmap_retcode
name_based_mapping_pid2sid(lookup_state_t *state, const char *unixname,
		int is_user, idmap_mapping *req, idmap_id_res *res)
{
	const char	*winname, *windomain;
	char		*canonname;
	char		*sql = NULL, *errmsg = NULL;
	idmap_retcode	retcode;
	char		*end;
	const char	**values;
	sqlite_vm	*vm = NULL;
	int		ncol, r;
	int		is_wuser;
	const char	*me = "name_based_mapping_pid2sid";
	int 		non_wild_match = FALSE;
	idmap_namerule	*rule = &res->info.how.idmap_how_u.rule;
	int direction;

	assert(unixname != NULL); /* We have unixname */
	assert(req->id2name == NULL); /* We don't have winname */
	assert(res->id.idmap_id_u.sid.prefix == NULL); /* No SID either */

	sql = sqlite_mprintf(
	    "SELECT winname_display, windomain, w2u_order, "
	    "is_wuser, unixname, is_nt4 "
	    "FROM namerules WHERE "
	    "u2w_order > 0 AND is_user = %d AND "
	    "(unixname = %Q OR unixname = '*') "
	    "ORDER BY u2w_order ASC;", is_user, unixname);
	if (sql == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}

	if (sqlite_compile(state->db, sql, NULL, &vm, &errmsg) != SQLITE_OK) {
		retcode = IDMAP_ERR_INTERNAL;
		idmapdlog(LOG_ERR, "%s: database error (%s)", me,
		    CHECK_NULL(errmsg));
		sqlite_freemem(errmsg);
		goto out;
	}

	for (;;) {
		r = sqlite_step(vm, &ncol, &values, NULL);
		assert(r != SQLITE_LOCKED && r != SQLITE_BUSY);
		if (r == SQLITE_ROW) {
			if (ncol < 6) {
				retcode = IDMAP_ERR_INTERNAL;
				goto out;
			}
			if (values[0] == NULL) {
				/* values [1] and [2] can be null */
				retcode = IDMAP_ERR_INTERNAL;
				goto out;
			}

			if (values[2] != NULL)
				direction =
				    (strtol(values[2], &end, 10) == 0)?
				    IDMAP_DIRECTION_U2W:IDMAP_DIRECTION_BI;
			else
				direction = IDMAP_DIRECTION_U2W;

			if (EMPTY_NAME(values[0])) {
				idmap_namerule_set(rule, values[1], values[0],
				    values[4], is_user,
				    strtol(values[3], &end, 10),
				    strtol(values[5], &end, 10),
				    direction);
				retcode = IDMAP_ERR_NOMAPPING;
				goto out;
			}

			if (values[0][0] == '*') {
				winname = unixname;
				if (non_wild_match) {
					/*
					 * There were non-wildcard rules
					 * where the Windows identity doesn't
					 * exist. Return no mapping.
					 */
					retcode = IDMAP_ERR_NOMAPPING;
					goto out;
				}
			} else {
				/* Save first non-wild match rule */
				if (!non_wild_match) {
					idmap_namerule_set(rule, values[1],
					    values[0], values[4],
					    is_user,
					    strtol(values[3], &end, 10),
					    strtol(values[5], &end, 10),
					    direction);
					non_wild_match = TRUE;
				}
				winname = values[0];
			}
			is_wuser = res->id.idtype == IDMAP_USID ? 1
			    : res->id.idtype == IDMAP_GSID ? 0
			    : -1;
			if (values[1] != NULL)
				windomain = values[1];
			else if (state->defdom != NULL)
				windomain = state->defdom;
			else {
				idmapdlog(LOG_ERR, "%s: no domain", me);
				retcode = IDMAP_ERR_DOMAIN_NOTFOUND;
				goto out;
			}

			retcode = lookup_name2sid(state->cache,
			    winname, windomain,
			    &is_wuser, &canonname,
			    &res->id.idmap_id_u.sid.prefix,
			    &res->id.idmap_id_u.sid.rid, req, 0);

			if (retcode == IDMAP_ERR_NOTFOUND) {
				continue;
			}
			goto out;

		} else if (r == SQLITE_DONE) {
			/*
			 * If there were non-wildcard rules where
			 * Windows identity doesn't exist
			 * return no mapping.
			 */
			if (non_wild_match)
				retcode = IDMAP_ERR_NOMAPPING;
			else
				retcode = IDMAP_ERR_NOTFOUND;
			goto out;
		} else {
			(void) sqlite_finalize(vm, &errmsg);
			vm = NULL;
			idmapdlog(LOG_ERR, "%s: database error (%s)", me,
			    CHECK_NULL(errmsg));
			sqlite_freemem(errmsg);
			retcode = IDMAP_ERR_INTERNAL;
			goto out;
		}
	}

out:
	if (sql != NULL)
		sqlite_freemem(sql);
	res->info.how.map_type = IDMAP_MAP_TYPE_RULE_BASED;
	if (retcode == IDMAP_SUCCESS) {
		res->id.idtype = is_wuser ? IDMAP_USID : IDMAP_GSID;

		if (values[2] != NULL)
			res->direction =
			    (strtol(values[2], &end, 10) == 0)?
			    IDMAP_DIRECTION_U2W:IDMAP_DIRECTION_BI;
		else
			res->direction = IDMAP_DIRECTION_U2W;

		req->id2name = canonname;
		if (req->id2name != NULL) {
			req->id2domain = strdup(windomain);
			if (req->id2domain == NULL)
				retcode = IDMAP_ERR_MEMORY;
		}
	}

	if (retcode == IDMAP_SUCCESS) {
		idmap_namerule_set(rule, values[1], values[0], values[4],
		    is_user, strtol(values[3], &end, 10),
		    strtol(values[5], &end, 10),
		    rule->direction);
		res->info.src = IDMAP_MAP_SRC_NEW;
	}
	if (vm != NULL)
		(void) sqlite_finalize(vm, NULL);
	return (retcode);
}

/*
 * Convention when processing unix2win requests:
 *
 * Unix identity:
 * req->id1name =
 *              unixname if given otherwise unixname found will be placed
 *              here.
 * req->id1domain =
 *              NOT USED
 * req->id1.idtype =
 *              Given type (IDMAP_UID or IDMAP_GID)
 * req->id1..[uid or gid] =
 *              UID/GID if given otherwise UID/GID found will be placed here.
 *
 * Windows identity:
 * req->id2name =
 *              winname found will be placed here.
 * req->id2domain =
 *              windomain found will be placed here.
 * res->id.idtype =
 *              Target type initialized from req->id2.idtype. If
 *              it is IDMAP_SID then actual type (IDMAP_USID/GSID) found
 *              will be placed here.
 * req->id..sid.[prefix, rid] =
 *              SID found will be placed here.
 *
 * Others:
 * res->retcode =
 *              Return status for this request will be placed here.
 * res->direction =
 *              Direction found will be placed here. Direction
 *              meaning whether the resultant mapping is valid
 *              only from unix2win or bi-directional.
 * req->direction =
 *              INTERNAL USE. Used by idmapd to set various
 *              flags (_IDMAP_F_xxxx) to aid in processing
 *              of the request.
 * req->id2.idtype =
 *              INTERNAL USE. Initially this is the requested target
 *              type and is used to initialize res->id.idtype.
 *              ad_lookup_batch() uses this field temporarily to store
 *              sid_type obtained by the batched AD lookups and after
 *              use resets it to IDMAP_NONE to prevent xdr from
 *              mis-interpreting the contents of req->id2.
 * req->id2..[uid or gid or sid] =
 *              NOT USED
 */

/*
 * This function does the following:
 * 1. Lookup well-known SIDs table.
 * 2. Lookup cache.
 * 3. Check if the client does not want new mapping to be allocated
 *    in which case this pass is the final pass.
 * 4. Set AD/NLDAP lookup flags if it determines that the next stage needs
 *    to do AD/NLDAP lookup.
 */
idmap_retcode
pid2sid_first_pass(lookup_state_t *state, idmap_mapping *req,
		idmap_id_res *res, int is_user, int getname)
{
	idmap_retcode	retcode;
	bool_t		gen_localsid_on_err = FALSE;

	/* Initialize result */
	res->id.idtype = req->id2.idtype;
	res->direction = IDMAP_DIRECTION_UNDEF;

	if (req->id2.idmap_id_u.sid.prefix != NULL) {
		/* sanitize sidprefix */
		free(req->id2.idmap_id_u.sid.prefix);
		req->id2.idmap_id_u.sid.prefix = NULL;
	}

	/* Find pid */
	if (req->id1.idmap_id_u.uid == SENTINEL_PID) {
		if (ns_lookup_byname(req->id1name, NULL, &req->id1)
		    != IDMAP_SUCCESS) {
			retcode = IDMAP_ERR_NOMAPPING;
			goto out;
		}
	}

	/* Lookup well-known SIDs table */
	retcode = lookup_wksids_pid2sid(req, res, is_user);
	if (retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	/* Lookup cache */
	retcode = lookup_cache_pid2sid(state->cache, req, res, is_user,
	    getname);
	if (retcode != IDMAP_ERR_NOTFOUND)
		goto out;

	/* Ephemeral ids cannot be allocated during pid2sid */
	if (IS_EPHEMERAL(req->id1.idmap_id_u.uid)) {
		retcode = IDMAP_ERR_NOMAPPING;
		goto out;
	}

	if (DO_NOT_ALLOC_NEW_ID_MAPPING(req)) {
		retcode = IDMAP_ERR_NONEGENERATED;
		goto out;
	}

	if (AVOID_NAMESERVICE(req)) {
		gen_localsid_on_err = TRUE;
		retcode = IDMAP_ERR_NOMAPPING;
		goto out;
	}

	/* Set flags for the next stage */
	if (AD_MODE(req->id1.idtype, state)) {
		/*
		 * If AD-based name mapping is enabled then the next stage
		 * will need to lookup AD using unixname to get the
		 * corresponding winname.
		 */
		if (req->id1name == NULL) {
			/* Get unixname if only pid is given. */
			retcode = ns_lookup_bypid(req->id1.idmap_id_u.uid,
			    is_user, &req->id1name);
			if (retcode != IDMAP_SUCCESS) {
				gen_localsid_on_err = TRUE;
				goto out;
			}
		}
		req->direction |= _IDMAP_F_LOOKUP_AD;
		state->ad_nqueries++;
	} else if (NLDAP_OR_MIXED_MODE(req->id1.idtype, state)) {
		/*
		 * If native LDAP or mixed mode is enabled for name mapping
		 * then the next stage will need to lookup native LDAP using
		 * unixname/pid to get the corresponding winname.
		 */
		req->direction |= _IDMAP_F_LOOKUP_NLDAP;
		state->nldap_nqueries++;
	}

	/*
	 * Failed to find non-expired entry in cache. Set the flag to
	 * indicate that we are not done yet.
	 */
	state->pid2sid_done = FALSE;
	req->direction |= _IDMAP_F_NOTDONE;
	retcode = IDMAP_SUCCESS;

out:
	res->retcode = idmap_stat4prot(retcode);
	if (ARE_WE_DONE(req->direction) && res->retcode != IDMAP_SUCCESS)
		if (gen_localsid_on_err == TRUE)
			(void) generate_localsid(req, res, is_user, TRUE);
	return (retcode);
}

idmap_retcode
pid2sid_second_pass(lookup_state_t *state, idmap_mapping *req,
	idmap_id_res *res, int is_user)
{
	bool_t		gen_localsid_on_err = TRUE;
	idmap_retcode	retcode = IDMAP_SUCCESS;

	/* Check if second pass is needed */
	if (ARE_WE_DONE(req->direction))
		return (res->retcode);

	/* Get status from previous pass */
	retcode = res->retcode;
	if (retcode != IDMAP_SUCCESS)
		goto out;

	/*
	 * If directory-based name mapping is enabled then the winname
	 * may already have been retrieved from the AD object (AD-mode)
	 * or from native LDAP object (nldap-mode or mixed-mode).
	 * Note that if we have winname but no SID then it's an error
	 * because this implies that the Native LDAP entry contains
	 * winname which does not exist and it's better that we return
	 * an error instead of doing rule-based mapping so that the user
	 * can detect the issue and take appropriate action.
	 */
	if (req->id2name != NULL) {
		/* Return notfound if we've winname but no SID. */
		if (res->id.idmap_id_u.sid.prefix == NULL) {
			retcode = IDMAP_ERR_NOTFOUND;
			goto out;
		}
		if (AD_MODE(req->id1.idtype, state))
			res->direction = IDMAP_DIRECTION_BI;
		else if (NLDAP_MODE(req->id1.idtype, state))
			res->direction = IDMAP_DIRECTION_BI;
		else if (MIXED_MODE(req->id1.idtype, state))
			res->direction = IDMAP_DIRECTION_W2U;
		goto out;
	} else if (res->id.idmap_id_u.sid.prefix != NULL) {
		/*
		 * We've SID but no winname. This is fine because
		 * the caller may have only requested SID.
		 */
		goto out;
	}

	/* Free any mapping info from Directory based mapping */
	if (res->info.how.map_type != IDMAP_MAP_TYPE_UNKNOWN)
		idmap_info_free(&res->info);

	if (req->id1name == NULL) {
		/* Get unixname from name service */
		retcode = ns_lookup_bypid(req->id1.idmap_id_u.uid, is_user,
		    &req->id1name);
		if (retcode != IDMAP_SUCCESS)
			goto out;
	} else if (req->id1.idmap_id_u.uid == SENTINEL_PID) {
		/* Get pid from name service */
		retcode = ns_lookup_byname(req->id1name, NULL, &req->id1);
		if (retcode != IDMAP_SUCCESS) {
			gen_localsid_on_err = FALSE;
			goto out;
		}
	}

	/* Use unixname to evaluate local name-based mapping rules */
	retcode = name_based_mapping_pid2sid(state, req->id1name, is_user,
	    req, res);
	if (retcode == IDMAP_ERR_NOTFOUND) {
		retcode = generate_localsid(req, res, is_user, FALSE);
		gen_localsid_on_err = FALSE;
	}

out:
	res->retcode = idmap_stat4prot(retcode);
	if (res->retcode != IDMAP_SUCCESS) {
		req->direction = _IDMAP_F_DONE;
		free(req->id2name);
		req->id2name = NULL;
		free(req->id2domain);
		req->id2domain = NULL;
		if (gen_localsid_on_err == TRUE)
			(void) generate_localsid(req, res, is_user, TRUE);
		else
			res->id.idtype = is_user ? IDMAP_USID : IDMAP_GSID;
	}
	if (!ARE_WE_DONE(req->direction))
		state->pid2sid_done = FALSE;
	return (retcode);
}

static
int
copy_mapping_request(idmap_mapping *mapping, idmap_mapping *request)
{
	(void) memset(mapping, 0, sizeof (*mapping));

	mapping->flag = request->flag;
	mapping->direction = _IDMAP_F_DONE;
	mapping->id2.idtype = request->id2.idtype;

	mapping->id1.idtype = request->id1.idtype;
	if (IS_REQUEST_SID(*request, 1)) {
		mapping->id1.idmap_id_u.sid.rid =
		    request->id1.idmap_id_u.sid.rid;
		if (!EMPTY_STRING(request->id1.idmap_id_u.sid.prefix)) {
			mapping->id1.idmap_id_u.sid.prefix =
			    strdup(request->id1.idmap_id_u.sid.prefix);
			if (mapping->id1.idmap_id_u.sid.prefix == NULL)
				goto errout;
		}
	} else {
		mapping->id1.idmap_id_u.uid = request->id1.idmap_id_u.uid;
	}

	if (!EMPTY_STRING(request->id1domain)) {
		mapping->id1domain = strdup(request->id1domain);
		if (mapping->id1domain == NULL)
			goto errout;
	}

	if (!EMPTY_STRING(request->id1name)) {
		mapping->id1name = strdup(request->id1name);
		if (mapping->id1name == NULL)
			goto errout;
	}

	/* We don't need the rest of the request i.e request->id2 */
	return (0);

errout:
	if (mapping->id1.idmap_id_u.sid.prefix != NULL)
		free(mapping->id1.idmap_id_u.sid.prefix);
	if (mapping->id1domain != NULL)
		free(mapping->id1domain);
	if (mapping->id1name != NULL)
		free(mapping->id1name);

	(void) memset(mapping, 0, sizeof (*mapping));
	return (-1);
}


idmap_retcode
get_w2u_mapping(sqlite *cache, sqlite *db, idmap_mapping *request,
		idmap_mapping *mapping)
{
	idmap_id_res	idres;
	lookup_state_t	state;
	char		*cp;
	idmap_retcode	retcode;
	const char	*winname, *windomain;

	(void) memset(&idres, 0, sizeof (idres));
	(void) memset(&state, 0, sizeof (state));
	state.cache = cache;
	state.db = db;

	/* Get directory-based name mapping info */
	retcode = load_cfg_in_state(&state);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	/*
	 * Copy data from "request" to "mapping". Note that
	 * empty strings are not copied from "request" to
	 * "mapping" and therefore the coresponding strings in
	 * "mapping" will be NULL. This eliminates having to
	 * check for empty strings henceforth.
	 */
	if (copy_mapping_request(mapping, request) < 0) {
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}

	winname = mapping->id1name;
	windomain = mapping->id1domain;

	if (winname == NULL && windomain != NULL) {
		retcode = IDMAP_ERR_ARG;
		goto out;
	}

	/* Need atleast winname or sid to proceed */
	if (winname == NULL && mapping->id1.idmap_id_u.sid.prefix == NULL) {
		retcode = IDMAP_ERR_ARG;
		goto out;
	}

	/*
	 * If domainname is not given but we have a fully qualified
	 * winname then extract the domainname from the winname,
	 * otherwise use the default_domain from the config
	 */
	if (winname != NULL && windomain == NULL) {
		retcode = IDMAP_SUCCESS;
		if ((cp = strchr(winname, '@')) != NULL) {
			*cp = '\0';
			mapping->id1domain = strdup(cp + 1);
			if (mapping->id1domain == NULL)
				retcode = IDMAP_ERR_MEMORY;
		} else if (lookup_wksids_name2sid(winname, NULL, NULL, NULL,
		    NULL) != IDMAP_SUCCESS) {
			if (state.defdom == NULL) {
				/*
				 * We have a non-qualified winname which is
				 * neither the name of a well-known SID nor
				 * there is a default domain with which we can
				 * qualify it.
				 */
				retcode = IDMAP_ERR_DOMAIN_NOTFOUND;
			} else {
				mapping->id1domain = strdup(state.defdom);
				if (mapping->id1domain == NULL)
					retcode = IDMAP_ERR_MEMORY;
			}
		}
		if (retcode != IDMAP_SUCCESS)
			goto out;
	}

	/*
	 * First pass looks up the well-known SIDs table and cache
	 * and handles localSIDs
	 */
	state.sid2pid_done = TRUE;
	retcode = sid2pid_first_pass(&state, mapping, &idres);
	if (IDMAP_ERROR(retcode) || state.sid2pid_done == TRUE)
		goto out;

	/* AD lookup */
	if (state.ad_nqueries > 0) {
		retcode = ad_lookup_one(&state, mapping, &idres);
		if (IDMAP_ERROR(retcode))
			goto out;
	}

	/* nldap lookup */
	if (state.nldap_nqueries > 0) {
		retcode = nldap_lookup_one(&state, mapping, &idres);
		if (IDMAP_FATAL_ERROR(retcode))
			goto out;
	}

	/* Next pass performs name-based mapping and ephemeral mapping. */
	state.sid2pid_done = TRUE;
	retcode = sid2pid_second_pass(&state, mapping, &idres);
	if (IDMAP_ERROR(retcode) || state.sid2pid_done == TRUE)
		goto out;

	/* Update cache */
	(void) update_cache_sid2pid(&state, mapping, &idres);

out:
	/*
	 * Note that "mapping" is returned to the client. Therefore
	 * copy whatever we have in "idres" to mapping->id2 and
	 * free idres.
	 */
	mapping->direction = idres.direction;
	mapping->id2 = idres.id;
	if (mapping->flag & IDMAP_REQ_FLG_MAPPING_INFO ||
	    retcode != IDMAP_SUCCESS)
		(void) idmap_info_mov(&mapping->info, &idres.info);
	else
		idmap_info_free(&idres.info);
	(void) memset(&idres, 0, sizeof (idres));
	if (retcode != IDMAP_SUCCESS)
		mapping->id2.idmap_id_u.uid = UID_NOBODY;
	xdr_free(xdr_idmap_id_res, (caddr_t)&idres);
	cleanup_lookup_state(&state);
	return (retcode);
}

idmap_retcode
get_u2w_mapping(sqlite *cache, sqlite *db, idmap_mapping *request,
		idmap_mapping *mapping, int is_user)
{
	idmap_id_res	idres;
	lookup_state_t	state;
	idmap_retcode	retcode;

	/*
	 * In order to re-use the pid2sid code, we convert
	 * our input data into structs that are expected by
	 * pid2sid_first_pass.
	 */

	(void) memset(&idres, 0, sizeof (idres));
	(void) memset(&state, 0, sizeof (state));
	state.cache = cache;
	state.db = db;

	/* Get directory-based name mapping info */
	retcode = load_cfg_in_state(&state);
	if (retcode != IDMAP_SUCCESS)
		goto out;

	/*
	 * Copy data from "request" to "mapping". Note that
	 * empty strings are not copied from "request" to
	 * "mapping" and therefore the coresponding strings in
	 * "mapping" will be NULL. This eliminates having to
	 * check for empty strings henceforth.
	 */
	if (copy_mapping_request(mapping, request) < 0) {
		retcode = IDMAP_ERR_MEMORY;
		goto out;
	}

	/*
	 * For unix to windows mapping request, we need atleast a
	 * unixname or uid/gid to proceed
	 */
	if (mapping->id1name == NULL &&
	    mapping->id1.idmap_id_u.uid == SENTINEL_PID) {
		retcode = IDMAP_ERR_ARG;
		goto out;
	}

	/* First pass looks up cache and well-known SIDs */
	state.pid2sid_done = TRUE;
	retcode = pid2sid_first_pass(&state, mapping, &idres, is_user, 1);
	if (IDMAP_ERROR(retcode) || state.pid2sid_done == TRUE)
		goto out;

	/* nldap lookup */
	if (state.nldap_nqueries > 0) {
		retcode = nldap_lookup_one(&state, mapping, &idres);
		if (IDMAP_FATAL_ERROR(retcode))
			goto out;
	}

	/* AD lookup */
	if (state.ad_nqueries > 0) {
		retcode = ad_lookup_one(&state, mapping, &idres);
		if (IDMAP_FATAL_ERROR(retcode))
			goto out;
	}

	/*
	 * Next pass processes the result of the preceding passes/lookups.
	 * It returns if there's nothing more to be done otherwise it
	 * evaluates local name-based mapping rules
	 */
	state.pid2sid_done = TRUE;
	retcode = pid2sid_second_pass(&state, mapping, &idres, is_user);
	if (IDMAP_ERROR(retcode) || state.pid2sid_done == TRUE)
		goto out;

	/* Update cache */
	(void) update_cache_pid2sid(&state, mapping, &idres);

out:
	/*
	 * Note that "mapping" is returned to the client. Therefore
	 * copy whatever we have in "idres" to mapping->id2 and
	 * free idres.
	 */
	mapping->direction = idres.direction;
	mapping->id2 = idres.id;
	if (mapping->flag & IDMAP_REQ_FLG_MAPPING_INFO ||
	    retcode != IDMAP_SUCCESS)
		(void) idmap_info_mov(&mapping->info, &idres.info);
	else
		idmap_info_free(&idres.info);
	(void) memset(&idres, 0, sizeof (idres));
	xdr_free(xdr_idmap_id_res, (caddr_t)&idres);
	cleanup_lookup_state(&state);
	return (retcode);
}

/*ARGSUSED*/
static
idmap_retcode
ad_lookup_one(lookup_state_t *state, idmap_mapping *req, idmap_id_res *res)
{
	idmap_mapping_batch	batch;
	idmap_ids_res		result;

	batch.idmap_mapping_batch_len = 1;
	batch.idmap_mapping_batch_val = req;
	result.ids.ids_len = 1;
	result.ids.ids_val = res;
	return (ad_lookup_batch(state, &batch, &result));
}
