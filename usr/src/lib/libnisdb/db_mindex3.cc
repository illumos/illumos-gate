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
 * Copyright 2015 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 RackTop Systems.
 */

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <lber.h>
#include <ldap.h>
#include <signal.h>
#include <pthread.h>
#include "db_headers.h"
#include "db.h"
#include "db_mindex.h"
#include "db_dictionary.h"
#include "nisdb_mt.h"
#include "ldap_map.h"
#include "ldap_glob.h"
#include "ldap_util.h"


extern db_dictionary	*InUseDictionary;


extern "C" {

typedef struct {
	db_mindex		*mindex;
	__nis_table_mapping_t	*t;
	db_query		*qin;
	db_query		*q;
	char			*dbId;
	nis_object		*dirObj;
	int			isDeferred;
	char			*tableName;
} __entries_from_ldap_arg_t;

static void	*entriesFromLDAPthread(void *);

}

int		entriesFromLDAPreal(__entries_from_ldap_arg_t *);

#ifdef	SET_ENTRY_FLAGS
static uint_t
entryFlagsFromTable(uint_t tf) {
	uint_t	ef = 0;

	if ((tf & TA_BINARY) != 0)
		ef |= EN_BINARY;
	if ((tf & TA_CRYPT) != 0)
		ef |= EN_CRYPT;
	if ((tf & TA_XDR) != 0)
		ef |= EN_XDR;
	if ((tf & TA_ASN1) != 0)
		ef |= EN_ASN1;

	return (ef);
}
#endif	/* SET_ENTRY_FLAGS */

static void                    setOid(nis_object *obj);

/*
 * Retrieve container entries from LDAP per 't' and 'qin'/'q'.
 * This is a helper function for db_mindex::queryLDAP(); see
 * that function for details of the parameters (except doAsynch).
 *
 * If 'doAsynch' is set, and the retrieval is an enumeration
 * (qin == NULL), the retrieval is performed in a detached
 * thread. In this case, the return code just reflects the
 * setup and launch of the detached thread. Retrieval will
 * complete asynchronously.
 */
int
db_mindex::entriesFromLDAP(__nis_table_mapping_t *t, db_query *qin, db_query *q,
			char *dbId, nis_object *dirObj, int doAsynch) {
	__entries_from_ldap_arg_t	*arg;
	int				stat;
	db_status			dstat;
	const char			*myself = "db_mindex::entriesFromLDAP";

	arg = (__entries_from_ldap_arg_t *)am(myself, sizeof (*arg));
	if (arg == 0) {
		freeQuery(q);
		if (dirObj != 0)
			nis_destroy_object(dirObj);
		return (LDAP_NO_MEMORY);
	}

	arg->mindex = this;
	arg->t = t;
	arg->qin = qin;
	arg->q = q;
	arg->dbId = dbId;
	arg->dirObj = dirObj;
	arg->tableName = t->objName;

	/*
	 * Check if an enumeration thread is running; if so, then regardless
	 * of whether or not the current operation is an enumeration, we
	 * just return success, and let our caller get the data from the
	 * existing (deferred) DB.
	 */
	(void) mutex_lock(&table->mapping.enumLock);
	if (table->mapping.enumTid != 0) {
		int	doReturn = 0;

		stat = pthread_kill(table->mapping.enumTid, 0);
		if (stat == ESRCH) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
	"%s: Enumeration thread %d not found for \"%s\"; exit status = %d (%s)",
				myself, table->mapping.enumTid,
				NIL(t->objName), table->mapping.enumStat,
				ldap_err2string(table->mapping.enumStat));
			/* Reflect the fact that no enum thread is running */
			table->mapping.enumTid = 0;
			table->mapping.enumStat = -1;
			/* Cleanup deferred mode */
			if (table->mapping.enumDeferred) {
				dstat = InUseDictionary->commit(t->objPath);
				if (dstat == DB_SUCCESS) {
					table->mapping.enumDeferred = 0;
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: DB error %d committing \"%s\"",
						myself, dstat, NIL(t->objName));
				}
			}
		} else if (stat == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: Enumeration thread %d already running for \"%s\"",
				myself, table->mapping.enumTid,
				NIL(t->objName));
			stat = LDAP_SUCCESS;
			doReturn = 1;
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
		"%s: Error %d looking for enumeration thread %d for \"%s\"",
				myself, stat, table->mapping.enumTid,
				NIL(t->objName));
			doReturn = 1;
			stat = LDAP_OPERATIONS_ERROR;
		}
		if (doReturn) {
			(void) mutex_unlock(&table->mapping.enumLock);
			sfree(arg);
			freeQuery(q);
			if (dirObj != 0)
				nis_destroy_object(dirObj);
			return (stat);
		}
	}

	/*
	 * If we're enumerating (and hence expect that retrieving all data,
	 * and updating the local DB, might take a while), create a deferred-
	 * update table that clients can use while we are updating the real
	 * one.
	 */
	if (doAsynch && qin == 0) {
		if ((dstat = InUseDictionary->defer(t->objPath)) ==
				DB_SUCCESS) {
			arg->isDeferred = 1;
			table->mapping.enumDeferred = 1;
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unable to defer updates for \"%s\" (status=%d);"
					" updating in place",
				myself, NIL(t->objName), dstat);
			arg->isDeferred = 0;
			table->mapping.enumDeferred = 0;
		}
	} else {
		arg->isDeferred = 0;
		table->mapping.enumDeferred = 0;
	}

	/* If enumerating, perform the operation in a separate thread */
	if (doAsynch && qin == 0) {
		pthread_t	tid;
		pthread_attr_t	attr;

		(void) pthread_attr_init(&attr);
#ifdef	FORCE_SYNCHRONOUS
#else
		(void) pthread_attr_setdetachstate(&attr,
						PTHREAD_CREATE_DETACHED);
#endif	/* FORCE_SYNCHRONOUS */
		stat = pthread_create(&tid, &attr, entriesFromLDAPthread, arg);
		if (stat != 0) {
			(void) mutex_unlock(&table->mapping.enumLock);
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Error %d creating new thread; using current one",
				myself, stat);
			stat = entriesFromLDAPreal(arg);
			return (stat);
		}

		table->mapping.enumTid = tid;
		table->mapping.enumStat = -1;

		/*
		 * We're now returning to the caller, who will get data
		 * from:
		 *
		 *	The deferred DB, if an enumeration thread already
		 *	was running, and deferred mode was on, or
		 *
		 *	The original DB, if we just started an enumeration
		 *	thread. In this case, our caller (several levels up)
		 *	is holding a lock on the db_mindex/db_table, which
		 *	means that the enum thread will have to wait for
		 *	our caller once it's done the LDAP retrieval, and
		 *	wants to update the DB.
		 */
		(void) mutex_unlock(&table->mapping.enumLock);
		stat = LDAP_SUCCESS;
#ifdef	FORCE_SYNCHRONOUS
		{
			int	tstat;

			stat = pthread_join(tid, (void **)&tstat);
			if (stat == 0) {
				stat = tstat;
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: thread %d => %d",
					myself, tid, tstat);
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: pthread_join(%d) => %d",
					myself, tid, stat);
				stat = LDAP_OPERATIONS_ERROR;
			}
		}
#endif	/* FORCE_SYNCHRONOUS */
	} else {
		(void) mutex_unlock(&table->mapping.enumLock);
		stat = entriesFromLDAPreal(arg);
	}

	return (stat);
}

extern "C" {

/*
 * We use this 'extern "C"' function in order to make sure that
 * pthread_create() doesn't have any problems trying to invoke a
 * C++ function.
 */
static void *
entriesFromLDAPthread(void *voidarg) {
	__entries_from_ldap_arg_t	*arg;
	db				*dbase;
	db_table_desc			*tbl = 0;
	char				*tableName;

	arg = (__entries_from_ldap_arg_t *)voidarg;

	/* Lock to prevent removal */
	(void) __nis_lock_db_table(arg->tableName, 1, 0,
					"entriesFromLDAPthread");

	/*
	 * It's possible that the db_mindex for the table has changed,
	 * or disappeared, between now and the time when our parent
	 * thread released its lock on the table. Hence, we search the
	 * dictionary to re-acquire the 'db', and the db_mindex.
	 */
	tableName = internalTableName(arg->tableName);
	if (tableName != 0) {
#ifdef	NISDB_LDAP_DEBUG
		db_mindex	*oldMindex = arg->mindex;
#endif	/* NISDB_LDAP_DEBUG */

		dbase = InUseDictionary->find_table(tableName, &tbl, FALSE);
		if (dbase != 0)
			arg->mindex = dbase->mindex();
		else
			arg->mindex = 0;
#ifdef	NISDB_LDAP_DEBUG
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"entriesFromLDAPthread: %s -> %s -> 0x%x (0x%x)",
			NIL(arg->tableName), NIL(tableName),
			arg->mindex, oldMindex);
#endif	/* NISDB_LDAP_DEBUG */
		sfree(tableName);
		tableName = 0;
	}

	(void) entriesFromLDAPreal(arg);

	(void) __nis_ulock_db_table(arg->tableName, 1, 0,
					"entriesFromLDAPthread");

	freeQuery(arg->q);
	if (arg->dirObj != 0)
		nis_destroy_object(arg->dirObj);
	sfree(arg);
	return (NULL);
}

}

int
entriesFromLDAPreal(__entries_from_ldap_arg_t *arg) {
	db_mindex			*mindex;
	db_table			*table;
	__nis_table_mapping_t		*t;
	db_query			*q, *qin;
	char				*dbId;
	nis_object			*dirObj;
	int				i, na, nau, nq = 0, xid = 0;
	int				ret, stat = LDAP_SUCCESS, stat2, stat3;
	int				lstat;
	__nis_obj_attr_t		**oa = 0;
	db_query			**res;
	entry_object			**ea;
	long				numEa;
	bool_t				doEnum;
	db_status			dstat;
	struct timeval			start;
	const char			*myself =
					"db_mindex::entriesFromLDAPreal";

	if (arg == 0)
		return (LDAP_PARAM_ERROR);
	mindex = arg->mindex;
	t = arg->t;
	q = arg->q;
	qin = arg->qin;
	dbId = arg->dbId;
	dirObj = arg->dirObj;

	table = (mindex != 0) ? mindex->getTable() : 0;

	if (mindex == 0 || t == 0 || table == 0) {
		/* We haven't done anything, so rollback should be OK */
		if (arg->isDeferred && t != 0) {
			dstat = InUseDictionary->rollback(t->objPath);
			if (dstat != DB_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: DB error %d rolling back \"%s\"",
					myself, dstat, NIL(t->objName));
				/*
				 * Had rollback succeeded, the 'table'
				 * would have disappeared. However, since
				 * rollback failed, we need to update the
				 * table->mapping.enum* fields.
				 */
				if (table != 0) {
					(void) mutex_lock(&table->
							mapping.enumLock);
					table->mapping.enumStat =
							LDAP_PARAM_ERROR;
					table->mapping.enumTime = 0;
					table->mapping.enumEntries = 0;
					table->mapping.enumTid = 0;
					(void) mutex_unlock(&table->
							mapping.enumLock);
				}
			}
		}
		return (LDAP_PARAM_ERROR);
	}

	if (qin == 0)
		logmsg(MSG_NOTIMECHECK, LOG_INFO, "%s: enumerating \"%s%s%s\"",
			myself, dbId ? dbId : "", dbId ? ":" : "",
			NIL(t->objName));

	(void) gettimeofday(&start, 0);

	/* Getting table entries */
	res = mapFromLDAP(t, q, &nq, dbId, &stat, &oa);
#ifdef	NISDB_LDAP_DEBUG
	logmsg(MSG_ALWAYS, LOG_INFO,
		"%s: mapFromLDAP() => 0x%x, status=%d %s; nq = %d",
		myself, res, stat, stat == LDAP_SUCCESS ? "" :
		ldap_err2string(stat), nq);
#endif	/* NISDB_LDAP_DEBUG */

	/*
	 * Keep track of the number of NIS+ entries we got back;
	 * note that the number of LDAP entries may have been
	 * smaller or larger.
	 */
	(void) mutex_lock(&table->mapping.enumLock);
	table->mapping.enumEntries = nq;
	(void) mutex_unlock(&table->mapping.enumLock);

	/*
	 * If we get LDAP_NO_SUCH_OBJECT, we need to delete the entries
	 * in the table, so we can't just return.
	 */
	if (res == 0 && stat != LDAP_NO_SUCH_OBJECT) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: mapFromLDAP() => 0x0, status=%d (%s)",
			myself, stat, ldap_err2string(stat));
		if (arg->isDeferred) {
			dstat = InUseDictionary->rollback(t->objPath);
			if (dstat != DB_SUCCESS) {
				struct timeval	end;

				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: DB error %d rolling back \"%s\"",
					myself, dstat, NIL(t->objName));
				/*
				 * Had rollback succeeded, the 'table'
				 * would have disappeared. However, since
				 * rollback failed, we need to update the
				 * table->mapping.enum* fields.
				 */
				(void) mutex_lock(&table->mapping.enumLock);
				table->mapping.enumStat = stat;
				(void) gettimeofday(&end, 0);
				end.tv_sec -= start.tv_sec;
				end.tv_usec -= start.tv_usec;
				if (end.tv_usec < 0) {
					end.tv_usec += 1000000;
					end.tv_sec -= 1;
				}
				table->mapping.enumTime =
					1000000*end.tv_sec + end.tv_usec;
				table->mapping.enumTid = 0;
				(void) mutex_unlock(&table->mapping.enumLock);
			}
		}
		return (stat);
	}

	/*
	 * Need to disable write-through to LDAP, for which we need a lock
	 * on our db_mindex ('mindex'); we're also updating the table, so
	 * we need a write lock on that as well. However, before locking the
	 * mindex, we need to maintain lock integrity by acquiring the
	 * trans log lock. Note that actually beginning a transaction is
	 * expensive, so we defer that until we know that we really need
	 * to update.
	 */
	lstat = lockTransLog(myself, 1, 1);
	if (lstat != 0) {
		if (lstat == EBUSY)
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
		"%s: transaction log busy; no LDAP update for \"%s\"",
				myself, NIL(t->objName));
		else
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error %d locking transaction log; no LDAP update for \"%s\"",
				myself, lstat, NIL(t->objName));
		if (arg->isDeferred) {
			dstat = InUseDictionary->rollback(t->objPath);
			if (dstat != DB_SUCCESS) {
				struct timeval	end;

				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: DB error %d rolling back \"%s\"",
					myself, dstat, NIL(t->objName));
				/*
				 * Had rollback succeeded, the 'table'
				 * would have disappeared. However, since
				 * rollback failed, we need to update the
				 * table->mapping.enum* fields.
				 */
				(void) mutex_lock(&table->mapping.enumLock);
				table->mapping.enumStat = LDAP_OPERATIONS_ERROR;
				(void) gettimeofday(&end, 0);
				end.tv_sec -= start.tv_sec;
				end.tv_usec -= start.tv_usec;
				if (end.tv_usec < 0) {
					end.tv_usec += 1000000;
					end.tv_sec -= 1;
				}
				table->mapping.enumTime = 1000000*end.tv_sec +
					end.tv_usec;
				table->mapping.enumTid = 0;
				(void) mutex_unlock(&table->mapping.enumLock);
			}
		}
		return (LDAP_OPERATIONS_ERROR);
	}

	/*
	 * If we have any updates, we'll call db::sync_log, which write-
	 * locks the 'db' instance. In order to avoid a dead-lock with
	 * threads performing a DB lookup (which will lock the 'db' and
	 * then the 'db_mindex'), we need hence need to lock in the
	 * following order:
	 *
	 *	trans.log	(already holding that one)
	 *	db
	 *	db_mindex
	 *	db_table
	 */
	TRYWRITELOCK(((db *)mindex->getDbPtr()), stat,
		"w db db_mindex::entriesFromLDAPreal");
	if (stat == 0) {
		TRYWRITELOCK(mindex, stat2, "w db_mindex::entriesFromLDAPreal");
		if (stat2 == 0) {
			TRYWRITELOCK(table, stat3,
				"table w db_mindex::entriesFromLDAPreal");
		}
	}

	if (stat != 0 || stat2 != 0 || stat3 != 0) {
		if (stat != 0) {
			if (stat == EBUSY)
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: 'db' busy; no LDAP update for \"%s\"",
					myself, NIL(t->objName));
			else
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: 'db' lock error %d; no LDAP update for \"%s\"",
					myself, stat, NIL(t->objName));
		} else if (stat2 != 0) {
			if (stat2 == EBUSY)
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: 'db_mindex' busy; no LDAP update for \"%s\"",
					myself, NIL(t->objName));
			else
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s: 'db_mindex' lock error %d; no LDAP update for \"%s\"",
					myself, stat2, NIL(t->objName));
		} else {
			if (stat3 == EBUSY)
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: 'db_table' busy; no LDAP update for \"%s\"",
					myself, NIL(t->objName));
			else
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s: 'db_table' lock error %d; no LDAP update for \"%s\"",
					myself, stat3, NIL(t->objName));
		}
		freeQueries(res, nq);
		if (arg->isDeferred) {
			dstat = InUseDictionary->rollback(t->objPath);
			if (dstat != DB_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: DB error %d rolling back \"%s\"",
					myself, dstat, NIL(t->objName));
				/*
				 * Had rollback succeeded, the 'table'
				 * would have disappeared. However, since
				 * rollback failed, we need to update the
				 * table->mapping.enum* fields.
				 */
				(void) mutex_lock(&table->mapping.enumLock);
				table->mapping.enumStat = LDAP_OPERATIONS_ERROR;
				table->mapping.enumTid = 0;
				(void) mutex_unlock(&table->mapping.enumLock);
			}
		}
		if (stat == 0) {
			if (stat2 == 0) {
				WRITEUNLOCK2(mindex, ((db *)mindex->getDbPtr()),
					LDAP_OPERATIONS_ERROR,
					LDAP_OPERATIONS_ERROR,
					"db_mindex::entriesFromLDAPreal wu",
					"db_mindex::entriesFromLDAPreal wu db");
			} else {
				WRITEUNLOCK(((db *)mindex->getDbPtr()),
					LDAP_OPERATIONS_ERROR,
					"db_mindex::entriesFromLDAPreal wu db");
			}
		}
		unlockTransLog(myself, 1);
		return (LDAP_OPERATIONS_ERROR);
	}

	stat = LDAP_SUCCESS;
	mindex->setNoWriteThrough();
	mindex->setNoLDAPquery();
	if (qin == 0) {
		table->setEnumMode(0);
		doEnum = TRUE;

		/*
		 * If there is no non-indexed table mapping, we must filter
		 * the enum mode (i.e., deletion candidates) array to only
		 * contain those entries that match the indexes.
		 */
		if (haveIndexedMapping(t)) {
			entry_object	**tea = table->gettab();
			long		i, ntea = table->getsize();


			/*
			 * Walk through the entry array, and remove any enum
			 * array entry that _doesn't_ match the index(es).
			 */
			for (i = 0; i < ntea; i++) {
				db_query		*q;
				__nis_table_mapping_t	**tp;
				int			numMatches;

				if (tea[i] == 0)
					continue;

				q = pseudoEntryObj2Query(tea[i], 0, 0);
				if (q == 0)
					continue;

				tp = selectTableMapping(t, q, 0, 0, dbId,
							&numMatches);
				if (tp == 0 || numMatches <= 0)
					table->enumTouch(i);

				sfree(tp);

				freeQuery(q);
			}
		}

		logmsg(MSG_NOTIMECHECK, LOG_INFO, "%s: %d entries from LDAP",
			myself, nq);
	} else {
		db_index_entry	*dbie;
		long		i, count;
		bool_t		valid;

		/*
		 * Find the entries in the DB that currently match the
		 * query, and add them to the enum array. Those that
		 * remain untouched when we've processed the LDAP data
		 * don't currently exist in LDAP, and should be deleted
		 * from the DB.
		 */
		dbie = mindex->satisfy_query_dbonly(qin, &count, FALSE, &valid);
		if (dbie != 0 && valid && count > 0) {
			table->setEnumMode(count);
			doEnum = TRUE;
			for (i = 0; i < count; i++) {
				table->enumSetup(dbie->getlocation(), i);
				dbie = dbie->getnextresult();
				if (dbie == 0)
					break;
			}
		} else {
			doEnum = FALSE;
		}
	}

	entry_col	ec[NIS_MAXCOLUMNS+1];
	for (i = 0, na = 0; i < nq; i++) {
		entry_object	eo, *e;
		table_col	*tc;
		nis_object	o, *to;
		int		j, nc;
		db_qcomp	*qc;

		if (res[i] == 0)
			continue;

#ifdef	NISDB_LDAP_DEBUG
		printQuery(res[i], t);
		printObjAttr(oa[i]);
#endif	/* NISDB_LDAP_DEBUG */

		/* Assemble an object from the query and attributes */
		(void) memset(&o, 0, sizeof (o));
		if (oa[i] != 0) {
			o.zo_owner = oa[i]->zo_owner;
			o.zo_group = oa[i]->zo_group;
			o.zo_domain = oa[i]->zo_domain;
			o.zo_access = oa[i]->zo_access;
			o.zo_ttl = oa[i]->zo_ttl;
		}
		if ((to = t->obj) != 0) {
			o.zo_name = to->zo_name;
			o.zo_data.objdata_u.en_data.en_type =
				to->zo_data.objdata_u.ta_data.ta_type;
			tc = to->zo_data.objdata_u.ta_data.ta_cols.ta_cols_val;
			if (to->zo_data.objdata_u.ta_data.ta_cols.ta_cols_len
					!= t->numColumns)
				tc = 0;
			if (o.zo_owner == 0)
				o.zo_owner = to->zo_owner;
			if (o.zo_group == 0)
				o.zo_group = to->zo_group;
			if (o.zo_domain == 0)
				o.zo_domain = to->zo_domain;
			if (o.zo_access == 0)
				o.zo_access = to->zo_access;
			if (o.zo_ttl == 0)
				o.zo_ttl = to->zo_ttl;
		} else {
			tc = 0;
			o.zo_owner = (nis_name)"";
			o.zo_group = (nis_name)"";
			o.zo_domain = (nis_name)"";
		}

		o.zo_data.zo_type = NIS_ENTRY_OBJ;
		o.zo_data.objdata_u.en_data.en_cols.en_cols_len =
			t->numColumns + 1;
		o.zo_data.objdata_u.en_data.en_cols.en_cols_val = ec;

		(void) memset(&ec, 0, sizeof (ec));
		nc = res[i]->size();
		qc = res[i]->queryloc();
		if (qc == 0) {
			freeQuery(res[i]);
			continue;
		}
		for (j = 0; j < nc; j++) {
			int	ic = 1+ qc[j].which_index;
			if (ic < 1 || ic > t->numColumns)
				continue;
#ifdef	SET_ENTRY_FLAGS
			if (tc != 0)
				ec[ic].ec_flags =
					entryFlagsFromTable(tc[ic-1].tc_flags);
#else
			/*
			 * In theory, the entry flags should be derived
			 * from the table flags. However, that doesn't
			 * seem to be the way that the DB code has done
			 * things so far, so leave the entry flags unset.
			 */
#endif	/* SET_ENTRY_FLAGS */
			qc[j].index_value->get_value(
					&ec[ic].ec_value.ec_value_val,
					(int *)&ec[ic].ec_value.ec_value_len);
		}

		setOid(&o);
		e = makePseudoEntryObj(&o, &eo, t->obj);
		if (e == 0) {
			freeQuery(res[i]);
			continue;
		}

		/*
		 * 'o' is currently a pseudo-object of type entry, with
		 * column zero used for an XDR:ed version of the entry_obj,
		 * column one the real column zero of the entry, etc.
		 * We now need a real NIS_ENTRY_OBJ object, so move the
		 * entry_col array one step left.
		 */
		o.zo_data.objdata_u.en_data.en_cols.en_cols_len = t->numColumns;
		o.zo_data.objdata_u.en_data.en_cols.en_cols_val = &ec[1];

		stat = mindex->updateTableEntry(e, 1, t->objName, &o, t->obj,
						o.zo_oid.mtime, &xid);
		/*
		 * LDAP_SUCCESS =>	Entry added or modified
		 * LDAP_COMPARE_TRUE =>	Entry same as existing one
		 * other =>		Error
		 */
		if (stat == LDAP_SUCCESS) {
			na++;
		} else if (stat == LDAP_COMPARE_TRUE) {
			stat = LDAP_SUCCESS;
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Error adding entry to \"%s\": %s",
				myself, NIL(t->objName),
				ldap_err2string(stat));
		}

		if (e->en_cols.en_cols_val != 0)
			sfree(e->en_cols.en_cols_val[0].ec_value.ec_value_val);

		freeQuery(res[i]);
	}

	sfree(res);

	/* Take care of deletes if we enumerated the table */
	if (doEnum) {
		ea = table->endEnumMode(&numEa);
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: %d entries added/updated", myself, na);
		nau = na;
	} else
		ea = 0;
	if (ea != 0) {
		uint32_t	nowt = time(0);

		for (i = 0; i < numEa; i++) {
			int	st;

			if (ea[i] == 0)
				continue;

			st = mindex->updateTableEntry(ea[i], 0, t->objName, 0,
						t->obj, nowt, &xid);
			if (st == LDAP_SUCCESS) {
				na++;
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Error removing directory entry for \"%s\": %s",
					myself, NIL(t->objName),
					ldap_err2string(st));
				if (stat == LDAP_SUCCESS)
					stat = st;
			}
		}
		if (stat == LDAP_SUCCESS) {
			struct timeval	now;
			(void) gettimeofday(&now, 0);
			table->mapping.enumExpire = now.tv_sec +
				table->mapping.ttl;
		}
		if (doEnum)
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: %d entries deleted", myself, na-nau);
	}

	sfree(ea);

	/* If we called log_action() successfully, we need to sync the log */
	if (na > 0)
		(void) ((db *)mindex->getDbPtr())->sync_log();

	if (xid != 0 && na > 0 && stat == LDAP_SUCCESS)
		ret = endTransaction(xid, dirObj);
	else if (xid != 0)
		ret = abort_transaction(xid);
	else
		ret = 0;
	if (ret != 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Error %s transaction for \"%s\"",
			myself, (na > 0 && stat == LDAP_SUCCESS) ?
					"ending" : "aborting",
			NIL(t->objName));
		stat = LDAP_OPERATIONS_ERROR;
	}

	mindex->clearNoLDAPquery();
	mindex->clearNoWriteThrough();
	freeObjAttr(oa, nq);

#ifdef	NISDB_LDAP_DEBUG
	printbuf();
#endif	/* NISDB_LDAP_DEBUG */

	if (doEnum)
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: enumeration \"%s\" done", myself, NIL(t->objName));

	if (arg->isDeferred) {
		/*
		 * Rollback doesn't recover data written to disk, so
		 * we should commit even if we're returning failure.
		 */
		dstat = InUseDictionary->commit(t->objPath);
		if (dstat != DB_SUCCESS) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: DB error %d committing \"%s\"",
				myself, dstat, NIL(t->objName));
		}
	}
	(void) mutex_lock(&table->mapping.enumLock);
	if (arg->isDeferred && dstat == DB_SUCCESS)
		table->mapping.enumDeferred = 0;
	table->mapping.enumStat = stat;
	{
		struct timeval	end;

		(void) gettimeofday(&end, 0);
		end.tv_sec -= start.tv_sec;
		end.tv_usec -= start.tv_usec;
		if (end.tv_usec < 0) {
			end.tv_usec += 1000000;
			end.tv_sec -= 1;
		}
		table->mapping.enumTime = 1000000*end.tv_sec + end.tv_usec;
		logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
			"%s: %d entries in %ld usec => %ld usec/entry",
			NIL(t->objName), table->mapping.enumEntries,
			table->mapping.enumTime,
			table->mapping.enumTime/
			(table->mapping.enumEntries != 0 ?
				table->mapping.enumEntries : 1));
	}
	table->mapping.enumTid = 0;
	(void) mutex_unlock(&table->mapping.enumLock);

	WRITEUNLOCKNR(table, stat3, "table wu db_mindex::entriesFromLDAPreal");
	WRITEUNLOCKNR(mindex, stat2, "db_mindex::entriesFromLDAPreal wu");
	WRITEUNLOCKNR(((db *)mindex->getDbPtr()), lstat,
		"db db_mindex::entriesFromLDAPreal wu");
	unlockTransLog(myself, 1);
	if (stat3 != 0)
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Error %d unlocking db_table", myself, stat3);
	if (stat2 != 0)
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Error %d unlocking db_mindex", myself, stat2);
	if (lstat != 0)
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Error %d unlocking db", myself, lstat);

	return (stat);
}
/*
 * Sets the oid (i.e., the creation and modification times) for the
 * specified object. In order to avoid retrieving the old incarnation
 * (if any) from the DB first, we're punting and setting both mtime
 * and ctime to the current time.
 */
static void
setOid(nis_object *obj) {
        if (obj != 0) {
                obj->zo_oid.ctime = obj->zo_oid.mtime = time(0);
        }
}
