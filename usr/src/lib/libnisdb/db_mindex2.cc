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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>

#include <malloc.h>
#include <strings.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <time.h>
#include "db_headers.h"
#include "db.h"
#include "db_mindex.h"
#include "db_pickle.h"
#include "nisdb_mt.h"
#include "nisdb_ldap.h"
#include "ldap_nisdbquery.h"
#include "ldap_map.h"
#include "ldap_ruleval.h"
#include "ldap_scheme.h"
#include "ldap_parse.h"
#include "nis_hashitem.h"
#include "nis_db.h"
#include "ldap_glob.h"

/* Pass through configuration information to the table */
bool_t
db_mindex::configure(char *tablePath) {
	if (tablePath == NULL)
		return (FALSE);

	if (objPath.ptr != 0)
		free(objPath.ptr);
	objPath.ptr = strdup(tablePath);

	if (table != NULL) {
		return (table->configure(tablePath));
	} else {
		/* Defer table config until we have a table instance */
		return (objPath.ptr != NULL);
	}
}

/*
 * The noWriteThrough flag is used to prevent modifies/updates to LDAP
 * while we're incorporating log data into the in-memory tables.
 */
void
db_mindex::setNoWriteThrough(void) {
	ASSERTWHELD(this->mindex);
	noWriteThrough.flag++;
}

void
db_mindex::clearNoWriteThrough(void) {
	ASSERTWHELD(this->mindex);
	if (noWriteThrough.flag > 0)
		noWriteThrough.flag--;
#ifdef	NISDB_LDAP_DEBUG
	else
		abort();
#endif	/* NISDB_LDAP_DEBUG */
}

/*
 * The noLDAPquery flag is used to prevent recursive LDAP queries when
 * satisfy_query() is re-entered as we add an entry from queryLDAP().
 */
void
db_mindex::setNoLDAPquery(void) {
	ASSERTWHELD(this->mindex);
	noLDAPquery.flag++;
}

void
db_mindex::clearNoLDAPquery(void) {
	ASSERTWHELD(this->mindex);
	if (noLDAPquery.flag > 0)
		noLDAPquery.flag--;
#ifdef	NISDB_LDAP_DEBUG
	else
		abort();
#endif	/* NISDB_LDAP_DEBUG */
}

/*
 * The initialLoad flag tells us if an add or remove is done as part of
 * the initial load of data, in which case we should use the initial TTLs.
 */
void
db_mindex::setInitialLoad(void) {
	ASSERTWHELD(this->mindex);
	initialLoad.flag++;
}

void
db_mindex::clearInitialLoad(void) {
	ASSERTWHELD(this->mindex);
	if (initialLoad.flag > 0)
		initialLoad.flag--;
#ifdef	NISDB_LDAP_DEBUG
	else
		abort();
#endif	/* NISDB_LDAP_DEBUG */
}

void
db_mindex::setDbPtr(void *ptr) {
	dbptr.ptr = ptr;
}

void *
db_mindex::getDbPtr(void) {
	return (dbptr.ptr);
}

db_table *
db_mindex::getTable(void) {
	return (table);
}

static void                    setOid(nis_object *obj);

extern void	db_free_result(db_result *);

zotypes
updateMappingObj(__nis_table_mapping_t *t, char **objNameP,
		bool_t *isMasterP) {
	zotypes         type = NIS_BOGUS_OBJ;
	char            *objName = 0;
	const char	*myself = "updateMappingObj";

	if (t != 0)
		objName = t->objName;
	else if (objNameP != 0)
		objName = *objNameP;
	else
		return (NIS_BOGUS_OBJ);

	if (objName != 0) {
		db_status	stat;
		int		lstat = LDAP_SUCCESS;
		nis_object	*o = dbFindObject(objName, &stat);

		/* If not found in the local DB, try LDAP */
		if (o == 0) {
			if (stat != DB_NOTFOUND) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: DB err %d for \"%s\"",
					myself, stat, NIL(objName));
			}
			o = ldapFindObj(t, objName, &lstat);
			/* If found, refresh/create the local copy */
			if (o != 0) {
				db_status	rstat;
				rstat = dbRefreshObj(objName, o);
				if (rstat != DB_SUCCESS)
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: DB error %d refreshing \"%s\"",
					myself, rstat, NIL(objName));
			}
		}

		if (o != 0) {
			type = o->zo_data.zo_type;
			if (objNameP != 0) {
				*objNameP = sdup(myself, T, objName);
				if (*objNameP == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Unable to copy object name (\"%s\")",
						myself, NIL(objName));
				}
			}
			if (t != 0) {
				if (!setMappingObjTypeEtc(t, o))
					nis_destroy_object(o);

			} else {
				nis_destroy_object(o);
			}
		} else if (lstat != LDAP_SUCCESS) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: LDAP err %d for \"%s\"",
				myself, lstat, NIL(objName));
		}
	}

	return (type);
}

static __nis_table_mapping_t *
mappingFromObj(nis_object *obj, int *statP) {
	__nis_table_mapping_t	*t;
	__nis_buffer_t		b = {0, 0};
	char			*objPath;
	const char		*myself = "mappingFromObj";

	if (obj == 0 || obj->zo_data.zo_type == NIS_ENTRY_OBJ)
		return (0);

	/*
	 * Convert full object name to the db table path used as
	 * key for the mapping hash list.
	 */
	bp2buf(myself, &b, "%s.%s",
		NIL(obj->zo_name), NIL(obj->zo_domain));
	objPath = internalTableName(b.buf);
	sfree(b.buf);
	if (slen(objPath) <= 0) {
		if (statP != 0)
			*statP = LDAP_OPERATIONS_ERROR;
		sfree(objPath);
		return (0);
	}

	t = (__nis_table_mapping_t *)__nis_find_item_mt(objPath,
						&ldapMappingList, 0, 0);

	sfree(objPath);

	return (t);
}

static __nis_table_mapping_t *
selectMapping(db_table *table, nis_object *obj, db_query *qin,
		bool_t wantWrite, bool_t *asObjP, int *statP) {
	__nis_table_mapping_t	*t;
	__nis_buffer_t		b = {0, 0};
	bool_t			doLDAP, asObj;
	int			stat = LDAP_SUCCESS;
	char			*objPath = 0, buf[MAXPATHLEN+NIS_MAXNAMELEN+1];
	const char		*myself = "db_mindex::selectMapping";

	/*
	 * If 'table' is NULL, we try to find a mapping for 'obj'.
	 * We expect this to happen when our caller wants to write
	 * the object from a directory entry to LDAP.
	 */
	if (table == 0) {
		if (asObjP != 0)
			*asObjP = TRUE;
		if (statP != 0)
			*statP = LDAP_SUCCESS;

		t = mappingFromObj(obj, statP);

		if (t == 0)
			return (0);

		/*
		 * Should the object type in the mapping be NIS_BOGUS_OBJ,
		 * we need to determine what kind of object this is.
		 */
		if (t->objType == NIS_BOGUS_OBJ) {
			t->objType = updateMappingObj(t, 0, 0);
			if (t->objType == NIS_BOGUS_OBJ) {
				if (statP != 0)
					*statP = LDAP_OPERATIONS_ERROR;
				return (0);
			}
		}

		/*
		 * If caller wants a mapping suitable for writing,
		 * check that we're the master for this object.
		 */

		return (t);
	}

	/*
	 * If the object type for the mapping is NIS_BOGUS_OBJ, then
	 * we haven't yet been able to determine what kind of object this
	 * is. Try to fix that now.
	 */
	if (table->mapping.objType == NIS_BOGUS_OBJ) {
		table->mapping.objType = updateMappingObj(table->mapping.tm,
						&table->mapping.objName,
						&table->mapping.isMaster);
		table->mapping.expireType = table->mapping.objType;
	}

	/*
	 * Depending on the object type (table->mapping.objType):
	 *
	 *	table		Use table->mapping.tm to query LDAP
	 *			for entries per 'qin'.
	 *
	 *	directory	Use 'qin' and table->mapping.objName
	 *			to retrieve a mapping entry, and then
	 *			query LDAP for the corresponding object.
	 *			'qin' == NULL means reading/writing the
	 *			entire directory object, plus the names
	 *			of the directory entries.
	 *
	 *	bogus		Not mapping this object. However, we may
	 *			still be mapping the object 'obj'.
	 *
	 *	other		Shouldn't happen; illegal.
	 */
	switch (table->mapping.objType) {
	case NIS_TABLE_OBJ:
		t = table->mapping.tm;
		if (wantWrite)
			doLDAP = table->mapping.isMaster &&
					table->mapping.toLDAP;
		else
			doLDAP = table->mapping.fromLDAP;
		asObj = FALSE;
		break;
	case NIS_DIRECTORY_OBJ: {
		char		*sub = 0;
		int		nqc, len = 0;
		db_qcomp	*qc;

		t = 0;
		doLDAP = FALSE;
		asObj = TRUE;

		/*
		 * We expect the query to have one component, containing
		 * the directory entry name. If there's no query, we want
		 * an enumeration of the entries in the directory. They're
		 * stored with the XDR:ed directory object in LDAP, so
		 * asObj should be TRUE.
		 */
		if (qin == 0) {
			t = table->mapping.tm;
			if (wantWrite)
				doLDAP = table->mapping.isMaster &&
					table->mapping.toLDAP;
			else
				doLDAP = table->mapping.fromLDAP;
			asObj = TRUE;
			break;
		}

		nqc = qin->size();
		if (nqc != 1 || (qc = qin->queryloc()) == 0 ||
				qc[0].index_value == 0) {
			stat = LDAP_PARAM_ERROR;
			break;
		}
		qc[0].index_value->get_value(&sub, &len);
		if (sub == 0 || len <= 0) {
			stat = LDAP_PARAM_ERROR;
			break;
		}

		/* Append directory name to dir entry name */
		sbc2buf(myself, sub, len, &b);
		bp2buf(myself, &b, ".%s", table->mapping.objName);

		/* Convert to the DB internal name */
		objPath = internal_table_name(b.buf, buf);
		sfree(b.buf);
		if (slen(objPath) <= 0) {
			stat = LDAP_OPERATIONS_ERROR;
			break;
		}

		/* Look for the corresponding table mapping */
		t = (__nis_table_mapping_t *)__nis_find_item_mt(
					objPath, &ldapMappingList, 0, 0);

		if (t == 0)
			break;

		/* Update object mapping information */
		if (t->objType == NIS_BOGUS_OBJ)
			(void) updateMappingObj(t, 0, 0);

		/*
		 * Should check the objectDN's in 't', but leave that to
		 * underlying functions.
		 */
		if (wantWrite)
			doLDAP = t->isMaster;
		else
			doLDAP = TRUE;

		break;
	}
	case NIS_BOGUS_OBJ:
		t = mappingFromObj(obj, statP);
		doLDAP = TRUE;
		asObj = TRUE;
		break;
	default:
		t = 0;
		doLDAP = FALSE;
		asObj = TRUE;
		break;
	}

	if (!doLDAP)
		t = 0;

	if (asObjP != 0)
		*asObjP = asObj;

	if (statP != 0)
		*statP = stat;

	return (t);
}

/*
 * Replace or remove the table entry identified by 'e'. 'tableName' is
 * the name of the table (which could be a directory) in which the entry
 * resides. 'obj' is an un-XDR:ed copy of the object in 'e', optionally
 * supplied to save re-doing unpacking of the entry object. 'tobj' is
 * a pointer to the table object; needed for table entries, but not
 * for directory entries.
 *
 * 'ttime' contains the current time, to be supplied for the trans log
 * entry.
 *
 * Returns LDAP_SUCCESS when entry successfully added/modified/deleted,
 * LDAP_COMPARE_TRUE if an entry to be added/modified was the same as
 * an already existing one, and a suitable error otherwise.
 */
int
db_mindex::updateTableEntry(entry_object *e, int replace, char *tableName,
		nis_object *obj, nis_object *tobj, uint32_t ttime,
		int *xid) {
	int			stat, freeObj = 0;
	db_index_entry		*dbie;
	long			count = 0;
	bool_t			valid = TRUE;
	db_result		*dbres;
	db_query		*qi;
	nis_object		*oldObj = 0;
	const char		*myself = "db_mindex::updateTableEntry";

	if (table == 0 || e == 0)
		return (LDAP_PARAM_ERROR);

	qi = extract_index_values_from_object(e);
	if (qi == 0) {
		logmsg(MSG_NOMEM, LOG_ERR,
				"%s: Out of memory for query index",
				myself);
		return (LDAP_NO_MEMORY);
	}

	dbie = satisfy_query(qi, &count, &valid, FALSE);
	if (dbie != 0 && (count != 1 || !valid)) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: count=%d, valid=%s",
			myself, count, valid ? "TRUE" : "FALSE");
		delete qi;
		return (LDAP_OPERATIONS_ERROR);
	}

	/*
	 * Need a copy of the old object in order to log a removal
	 * (this is true even if we're modifying an existing entry).
	 */
	if (dbie != 0) {
		oldObj = unmakePseudoEntryObj(
				table->get_entry(dbie->getlocation()), tobj);
		if (oldObj == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error getting object from old pseudo-entry for \"%s\" in \"%s\"",
					myself, NIL(obj->zo_name),
					NIL(tableName));
			delete qi;
			return (LDAP_OPERATIONS_ERROR);
		}
	}

	if (replace) {
		/* Need the object from the entry */
		if (dbie != 0 && obj == 0) {
			obj = unmakePseudoEntryObj(e, tobj);
			if (obj == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error getting object from pseudo-entry for \"%s\" in \"%s\"",
					myself, NIL(obj->zo_name),
					NIL(tableName));
				delete qi;
				nis_destroy_object(oldObj);
				return (LDAP_OPERATIONS_ERROR);
			}
			freeObj = 1;
		}

		/* Is the new object a dup of the old ? */
		if (dbie != 0 && sameNisPlusObj(oldObj, obj)) {
			/* Yes, it's a dup, so just update the timestamp */
			table->touchEntry(dbie->getlocation());
			delete qi;
			if (freeObj)
				nis_destroy_object(obj);
			nis_destroy_object(oldObj);
			return (LDAP_COMPARE_TRUE);
		} else {
			/*
			 * Not a dup, so go ahead and add it. Provided
			 * that 'qi' isn't NULL (which we've already
			 * checked), DB_ADD(_NOSYNC) does the right
			 * thing even if matching entries already
			 * exist.
			 */
			dbres = ((db *)dbptr.ptr)->log_action(DB_ADD_NOSYNC,
								qi, e);
			if (dbres == 0)
				stat = LDAP_OPERATIONS_ERROR;
			else if (dbres->status == DB_SUCCESS)
				stat = LDAP_SUCCESS;
			else
				stat = LDAP_OPERATIONS_ERROR;
			db_free_result(dbres);
		}
	} else {	/* Removing */
		/* If the object doesn't exist, we're done */
		if (dbie == 0) {
			delete qi;
			return (LDAP_SUCCESS);
		}

		dbres = ((db *)dbptr.ptr)->log_action(DB_REMOVE_NOSYNC, qi, 0);
		if (dbres == 0)
			stat = LDAP_OPERATIONS_ERROR;
		else if (dbres->status == DB_SUCCESS)
			stat = LDAP_SUCCESS;
		else
			stat = LDAP_OPERATIONS_ERROR;
		db_free_result(dbres);
	}

	/* Log the operation */
	if (stat == LDAP_SUCCESS) {
		int		ret, numAttrs;
		nis_attr	*attr, attrbuf[NIS_MAXCOLUMNS];

		/* If we haven't begun the transaction yet, do so now */
		if (*xid == 0) {
			*xid = beginTransaction();
			if (*xid == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error starting transaction for \"%s\"",
					myself, NIL(tableName));
				delete qi;
				if (oldObj != 0)
					nis_destroy_object(oldObj);
				return (LDAP_OPERATIONS_ERROR);
			}
		}

		if (replace && obj == 0) {
			obj = unmakePseudoEntryObj(e, tobj);
			if (obj == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error getting object from pseudo-entry for \"%s\" in \"%s\"",
					myself, NIL(obj->zo_name),
					NIL(tableName));
				delete qi;
				if (oldObj != 0)
					nis_destroy_object(oldObj);
				return (LDAP_OPERATIONS_ERROR);
			}
			freeObj = 1;
		}

		/*
		 * The log stores nis_attr information, so we need to
		 * convert the scheme-query to a nis_attr array.
		 */
		attr = schemeQuery2nisAttr(qi, attrbuf, scheme,
				table->mapping.tm, &numAttrs);
		if (attr == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error converting index query to nis_attr for \"%s\" in \"%s\"",
				myself, NIL(obj->zo_name), NIL(tableName));
			if (freeObj)
				nis_destroy_object(obj);
			if (oldObj != 0)
				nis_destroy_object(oldObj);
			delete qi;
			return (LDAP_OPERATIONS_ERROR);
		}

		if (replace) {
			/*
			 * While the DB can handle a modify (replace)
			 * operation, the trans log stores this as a
			 * remove followed by an add (which allows
			 * backing out the change by removing the new
			 * object incarnation, and adding the old one).
			 */
			if (oldObj != 0)
				ret = addUpdate(REM_IBASE, tableName,
					numAttrs, attr, oldObj, 0, ttime);
			else
				ret = 0;
			if (ret == 0)
				ret = addUpdate(ADD_IBASE, tableName,
					numAttrs, attr, obj, 0, ttime);
		} else {	/* Removal */
			ret = addUpdate(REM_IBASE, tableName, numAttrs, attr,
					oldObj, 0, ttime);
		}
		if (ret != 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s: Error adding trans log entry for \"%s\" in \"%s\"",
				myself, NIL(obj->zo_name), NIL(tableName));
			stat = LDAP_OPERATIONS_ERROR;
		}
	}

	delete qi;

	if (oldObj != 0)
		nis_destroy_object(oldObj);
	if (freeObj)
		nis_destroy_object(obj);

	return (stat);
}

bool_t
db_mindex::touchEntry(entry_object *e) {
	db_query		*qi;
	bool_t			ret;

	if (table == 0 || e == 0)
		return (FALSE);

	qi = extract_index_values_from_object(e);
	if (qi == 0)
		return (FALSE);

	ret = touchEntry(qi);

	delete qi;

	return (ret);
}

bool_t
db_mindex::touchEntry(db_query *q) {
	db_index_entry		*dbie;
	long			count;
	bool_t			valid;

	dbie = satisfy_query(q, &count, &valid, FALSE);
	if (dbie != 0 && count == 1 && valid)
		table->touchEntry(dbie->getlocation());
	else
		return (FALSE);

	return (TRUE);
}

/*
 * Compose an object name from column zero of 'e' and 't->objName',
 * and return the mapping for that object, if any. Also set '*name'
 * to point to the dir entry name in 'e'. Note that this is a pointer
 * to existing data, and shouldn't be freed other than as part of
 * freeing 'e'.
 */
static __nis_table_mapping_t *
findDirEntryMapping(__nis_table_mapping_t *t, entry_object *e, char **name) {
	__nis_table_mapping_t	*x;
	char			*entryName;
	const char			*myself = "findDirEntryMapping";
	__nis_buffer_t		b = {0, 0};

	if (e == 0 || e->en_cols.en_cols_len != 2 ||
			e->en_cols.en_cols_val == 0)
		return (0);

	entryName = e->en_cols.en_cols_val[1].ec_value.ec_value_val;
	if (name != 0)
		*name = entryName;

	if (t == 0 || entryName == 0 || t->objName == 0)
		return (0);

	bp2buf(myself, &b, "%s.%s", entryName, t->objName);
	if (b.len == 0 || b.buf == 0)
		return (0);

	x = (__nis_table_mapping_t *)__nis_find_item_mt(b.buf,
						&ldapMappingList, 0, 0);

	sfree(b.buf);

	return (x);
}

/*
 * Query LDAP per the supplied (scheme-) query 'qin'. If 'doAsynch' is
 * set, and the query is an enumeration (qin == 0), the query will be
 * performed in a detached thread, and complete asynchronously. In this
 * case, the return status reflects the setup and launch of the
 * detached thread; the query will complete asynchronously.
 *
 * Returns an appropriate LDAP status code.
 */
int
db_mindex::queryLDAP(db_query *qin, char *dbId, int doAsynch) {
	__nis_table_mapping_t	*t;
	int			i, na, nq = 0, stat, stat2, numAttrs, ret;
	int			xid = 0;
	long			numEa;
	bool_t			asObj, doEnum;
	db_query		*q;
	entry_object		**ea;
	nis_attr		attr;
	nis_object		*dirObj;
	db_status		dstat;
	const char		*myself = "db_mindex::queryLDAP";

	if (!useLDAPrespository || table == 0)
		return (LDAP_SUCCESS);

	/*
	 * Instances from the deferred dictionary shouldn't change,
	 * there's no point in querying LDAP.
	 */
	if (table->mapping.isDeferredTable)
		return (LDAP_SUCCESS);

	t = selectMapping(table, 0, qin, FALSE, &asObj, &stat);

	if (t == 0)
		return (stat);

#ifdef	NISDB_LDAP_DEBUG
	printf("%s: %s (%s)\n",
		myself, NIL(t->objName), (asObj ? "object" : "entry"));
#endif	/* NISDB_LDAP_DEBUG */

	if (qin != NULL) {
		q = schemeQuery2Query(qin, scheme);
		if (q == 0)
			return (LDAP_PARAM_ERROR);
#ifdef	NISDB_LDAP_DEBUG
		q->print();
#endif	/* NISDB_LDAP_DEBUG */
	} else {
		q = 0;
#ifdef	NISDB_LDAP_DEBUG
		printf("\tenumerating %s%s%s\n",
			dbId ? dbId : "", dbId ? ":" : "", NIL(t->objName));
#endif	/* NISDB_LDAP_DEBUG */
	}

	/*
	 * Do we have any active mappings for this particular query and
	 * dbId ?  If not, we're done.
	 *
	 * Note that we don't care about the return value from
	 * selectTableMapping(), just wheter or not there are
	 * any valid mappings.
	 */
	i = 0;
	sfree(selectTableMapping(t, q, 0, asObj, dbId, &i));
	if (i <= 0) {
		freeQuery(q);
		return (LDAP_SUCCESS);
	}

	/* Is the object a directory ? */
	if (asObj) {
		nis_object	*o;
		entry_object	*e, eo;
		entry_col	ec[2];
		int		nea;

		stat = objFromLDAP(t, &o, &ea, &nea);
		numEa = nea;

		if (stat == LDAP_NO_SUCH_OBJECT) {
			/* Positive failure; remove the object */
			dstat = dbDeleteObj(t->objName);
			if (dstat == DB_SUCCESS || dstat == DB_NOTFOUND) {
				stat = LDAP_SUCCESS;
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: DB error %d deleting \"%s\"",
					myself, dstat, NIL(t->objName));
				stat = LDAP_OPERATIONS_ERROR;
			}

			freeQuery(q);

			return (stat);
		} else if (stat != LDAP_SUCCESS) {
			freeQuery(q);
			return (stat);
		} else if (o == 0) {
			/* OK; this entry just isn't mapped */
			freeQuery(q);
			return (LDAP_SUCCESS);
		}

		if (q != 0) {
			/*
			 * We're updating one particular entry (described
			 * by 't') in the directory 'table->mapping.tm'.
			 */

			setOid(o);
			dstat = dbRefreshObj(t->objName, o);
			if (dstat == DB_SUCCESS) {
				stat = LDAP_SUCCESS;
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: DB error %d updating \"%s\" in \"%s\"",
					myself, NIL(t->objName),
					NIL(table->mapping.tm->objName));
				stat = LDAP_OPERATIONS_ERROR;
			}

			freeEntryObjArray(ea, numEa);
			freeQuery(q);
			nis_destroy_object(o);

			return (stat);
		}

		dirObj = o;

		/*
		 * q == 0, so we're enumerating. Update the list of
		 * directory entries.
		 */

		/*
		 * Need to disable write-through to LDAP, for which we need
		 * a lock on our db_mindex ('this'); we're also updating the
		 * table, so we need a write lock on that as well.
		 */
		WRITELOCKNR(this, stat, "w db_mindex::queryLDAP");
		if (stat == 0) {
			WRITELOCKNR(table, stat2,
				"table w db_mindex::queryLDAP");
		}
		if (stat != 0 || stat2 != 0) {
			nis_destroy_object(dirObj);
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: lock error %d", myself,
				stat != 0 ? stat : stat2);
			return (LDAP_OPERATIONS_ERROR);
		}

		setNoWriteThrough();
		setNoLDAPquery();
		table->setEnumMode(0);

		for (i = 0, na = 0; i < numEa; i++) {
			int			st;
			__nis_table_mapping_t	*x;
			char			*name = 0;
			entry_obj		*e;

			if (ea[i] == 0)
				continue;

			/*
			 * We've got a list of dir entries. In the general,
			 * case, some are new, and some already exist.
			 * We definitely want to add the new ones, and to
			 * that end, we need a copy of the object for the
			 * entry. By definition, if an entry is new, we
			 * don't yet have a copy of the object for it, so
			 * it's LDAP or nothing.
			 *
			 * If the entry already exists, try to update the
			 * entry object. In this case, we again only need
			 * to look in LDAP for the object; if there already
			 * is one in the DB, it's in the dir entry which we
			 * want to update.
			 *
			 * So, whether adding or replacing, try to get the
			 * object from LDAP.
			 *
			 * If we can't get a copy of the object, there's not
			 * much point in adding or updating (since a dir
			 * entry just consists of the entry object and name),
			 * so we continue to the next entry.
			 *
			 * However, in that case, we do need to touch the
			 * dir entry; otherwise, it will be removed later
			 * on.
			 */

			x = findDirEntryMapping(t, ea[i], &name);
			o = 0;
			if (x == 0 || (st = objFromLDAP(x, &o, 0, 0)) !=
					LDAP_SUCCESS) {
				if (x != 0)
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unable to obtain object for \"%s\" in \"%s\": %s",
					myself, NIL(name), NIL(t->objName),
						ldap_err2string(st));
				if (o != 0)
					nis_destroy_object(o);
				if (!touchEntry(ea[i])) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Inconsistency: LDAP-derived directory \"%s\" "
			"contains entry \"%s\", which is unknown locally, "
			"and has no LDAP mapping",
						myself, NIL(t->objName),
						NIL(name));
				}
				continue;
			}

			if (ea[i]->en_cols.en_cols_len != 2 ||
				ea[i]->en_cols.en_cols_val == 0 ||
				ea[i]->en_cols.en_cols_val[0].
					ec_value.ec_value_val != 0 ||
				ea[i]->en_cols.en_cols_val[0].
					ec_value.ec_value_len != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Illegal entry_obj col 0 for \"%s\" in \"%s\"",
					myself, NIL(name), NIL(t->objName));
				nis_destroy_object(o);
				touchEntry(ea[i]);
				continue;
			}

			setOid(o);
			e = makePseudoEntryObj(o, ea[i], 0);
			if (e == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
	"%s: Unable to create pseudo entry object for \"%s\" in \"%s\"",
					myself, NIL(name), NIL(t->objName));
				nis_destroy_object(o);
				touchEntry(ea[i]);
				continue;
			}

			st = updateTableEntry(e, 1, t->objName, o, 0,
						o->zo_oid.mtime, &xid);
			if (st == LDAP_SUCCESS) {
				na++;
			} else if (st == LDAP_COMPARE_TRUE) {
				/* OK, same as existing entry */
				st = LDAP_SUCCESS;
			} else {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: Error updating directory entry for \"%s\" in \"%s\": %s",
					myself, NIL(name), NIL(t->objName),
					ldap_err2string(st));
				if (stat == LDAP_SUCCESS)
					stat = st;
			}

			/* Free the XDR buffer */
			sfree(e->en_cols.en_cols_val[0].
					ec_value.ec_value_val);
			/* Restore ea[i] */
			ea[i]->en_cols.en_cols_val[0].
					ec_value.ec_value_val = 0;
			ea[i]->en_cols.en_cols_val[0].
					ec_value.ec_value_len = 0;
			nis_destroy_object(o);
		}

		freeEntryObjArray(ea, numEa);

		/* Get list of entries to remove */
		ea = table->endEnumMode(&numEa);
		if (ea != 0) {
			uint32_t	nowt = time(0);

			for (i = 0; i < numEa; i++) {
				int	st;

				if (ea[i] == 0)
					continue;

				st = updateTableEntry(ea[i], 0, t->objName, 0,
							0, nowt, &xid);
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
		}

		if (stat == LDAP_SUCCESS) {
			struct timeval	now;
			(void) gettimeofday(&now, 0);
			table->mapping.enumExpire = now.tv_sec +
				table->mapping.ttl;
		}

		if (na > 0)
			(void) ((db *)dbptr.ptr)->sync_log();

		if (xid != 0 && na > 0 && stat == LDAP_SUCCESS) {
			ret = endTransaction(xid, dirObj);
			if (ret != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error ending transaction for \"%s\"",
					myself, NIL(t->objName));
				stat = LDAP_OPERATIONS_ERROR;
			}
		} else if (xid != 0) {
			ret = abort_transaction(xid);
			if (ret != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error aborting transaction for \"%s\"",
					myself, NIL(t->objName));
			}
		}
		nis_destroy_object(dirObj);

		sfree(ea);

		clearNoLDAPquery();
		clearNoWriteThrough();

		WRITEUNLOCK2(table, this,
			stat, stat,
			"table wu db_mindex::queryLDAP",
			"wu db_mindex::queryLDAP");

		return (stat);
	}

	/*
	 * In order to ping replicas, if any, we need to find the
	 * directory containing the table to be updated. If we
	 * can't find the directory object, we're sunk, so let's
	 * start with that.
	 */
	if (t->isMaster) {
		dirObj = findObj(t->obj->zo_domain, &dstat, &stat);
		if (dirObj == 0) {
			if (stat == LDAP_SUCCESS)
				stat = LDAP_OPERATIONS_ERROR;
			return (stat);
		}
	} else {
		dirObj = 0;
	}

	stat = entriesFromLDAP(t, qin, q, dbId, dirObj, doAsynch);

	return (stat);
}

extern db	*tableDB(char *);

/*
 * Remove the LDAP entry/entries corresponding to 'qin'/'obj'.
 */
int
db_mindex::removeLDAP(db_query *qin, nis_object *obj) {
	__nis_table_mapping_t	*t;
	db_query		*q;
	bool_t			asObj;
	int			stat;

	if (!useLDAPrespository || table == 0)
		return (LDAP_SUCCESS);

	/* Instances from the deferred dictionary should not update LDAP */
	if (table->mapping.isDeferredTable)
		return (LDAP_SUCCESS);

	t = selectMapping(table, 0, qin, TRUE, &asObj, &stat);
	if (t == 0 && stat != LDAP_SUCCESS)
		return (stat);

#ifdef	NISDB_LDAP_DEBUG
	if (t != 0)
		printf("removeLDAP: %s\n", NIL(t->objName));
#endif	/* NISDB_LDAP_DEBUG */

	if (qin != NULL) {
		if (asObj) {
			/*
			 * selectMapping() gave us the mapping for the
			 * directory entry. However, if 't' is NULL, this
			 * could be due to the directory itself not being
			 * mapped, in which case we must obtain the mapping
			 * info from 'obj'.
			 */
			if (t == 0) {
				t = selectMapping(0, obj, 0, TRUE, &asObj,
						&stat);
				if (t == 0 && stat != LDAP_SUCCESS)
					return (stat);
			}

			if (t != 0) {
				stat = deleteLDAPobj(t);
				/*
				 * If we were successful, update the object
				 * stored with the mapping.
				 */
				if (stat == LDAP_SUCCESS)
					(void) replaceMappingObj(t, 0);
				else
					return (stat);
			}

			/*
			 * Since it's a directory entry we've removed, we also
			 * need to update the directory object itself.
			 */
			stat = storeLDAP(0, 0, 0, 0, 0);
		} else {
			q = schemeQuery2Query(qin, scheme);
			if (q == 0)
				return (LDAP_PARAM_ERROR);
#ifdef	NISDB_LDAP_DEBUG
			q->print();
#endif	/* NISDB_LDAP_DEBUG */
			stat = mapToLDAP(t, 1, &q, 0, 0, 0, 0);
			freeQuery(q);
		}
	} else {
		/*
		 * This isn't the way to remove the LDAP entries
		 * corresponding to the entire table.
		 */
#ifdef	NISDB_LDAP_DEBUG
		abort();
#endif	/* NISDB_LDAP_DEBUG */
		stat = LDAP_PARAM_ERROR;
	}

	return (stat);
}

/*
 * Helper function for storeLDAP() which handles updates for objects
 * other than table entries.
 */
int
db_mindex::storeObjLDAP(__nis_table_mapping_t *t, nis_object *o) {
	int		stat, assigned = 0;
	entry_object	**ea;
	int		numEa, doUnlock = 0;
	db		*dbase = 0;
	db_mindex	*dbm = 0;
	const char	*myself = "db_mindex::storeObjLDAP";

	if (t == 0 || o == 0)
		return (LDAP_SUCCESS);

	/*
	 * If the object to be stored is anything other than a
	 * directory, we can just go ahead and write it to LDAP.
	 * A directory object, however, also needs a directory
	 * entry list, so we should to get hold of the db_table
	 * that goes with the directory.
	 */
	if (o->zo_data.zo_type == NIS_DIRECTORY_OBJ) {
		dbase = tableDB(t->objName);
		if (dbase != 0)
			dbm = dbase->mindex();
		if (dbase == 0 || dbm == 0 || dbm->table == 0) {
			/* By definition, no dir entries */
			ea = 0;
			numEa = 0;
			dbase = 0;
		} else {
			entry_object	**tea;
			long		i, ntea;

			/*
			 * Read-lock the table so that 'tab'
			 * doesn't change while we're using it.
			 */
			READLOCK(dbm->table, LDAP_OPERATIONS_ERROR,
					"r table db_mindex::storeLDAP");
			doUnlock = 1;

			tea = dbm->table->gettab();
			ntea = dbm->table->getsize();

			/*
			 * There may be empty slots in the table 'tab'
			 * array, so get rid of those.
			 */
			if (tea != 0 && ntea > 0) {
				ea = (entry_object **)am(myself,
						ntea * sizeof (ea[0]));
				if (ea == 0) {
					READUNLOCK(dbm->table, LDAP_NO_MEMORY,
					"ru table db_mindex::storeLDAP");
					return (LDAP_NO_MEMORY);
				}
				for (i = 0, numEa = 0; i < ntea; i++) {
					if (tea[i] != 0) {
						ea[numEa] = tea[i];
						numEa++;
					}
				}
				if (numEa == 0) {
					/* No non-empty slots */
					sfree(ea);
					ea = 0;
					READUNLOCK(dbm->table,
						LDAP_OPERATIONS_ERROR,
					"ru table db_mindex::storeLDAP");
					doUnlock = 0;
				}
			} else {
				ea = 0;
				numEa = 0;
				READUNLOCK(dbm->table,
					LDAP_OPERATIONS_ERROR,
					"ru table db_mindex::storeLDAP");
				doUnlock = 0;
			}
		}
	} else {
		ea = 0;
		numEa = 0;
	}

	stat = objToLDAP(t, o, ea, numEa);

	if (ea != 0)
		sfree(ea);
	if (doUnlock) {
		READUNLOCK(dbm->table, stat,
				"ru table db_mindex::storeLDAP");
	}

	return (stat);
}


/*
 * Store data specified by the index-query 'qin' to LDAP. If 'obj' is
 * non-null, it's a pointer to the pseudo-entry object corresponding to
 * 'qin'. As a short-cut/convenience, the caller can instead supply
 * the actual nis_object 'o'; if 'o' is NULL, it's derived from 'obj'.
 *
 * 'oldObj' is used for table entries if the store operation is
 * an update, and the corresponding NIS+ operation was a delete followed
 * by an add. In this case, oldObj contains the pre-delete incarnation of
 * the entry object to be modified.
 *
 * The 'dbId' string is used to select one dbId for mapping chains
 * that contain more than one.
 *
 * Returns an LDAP status code.
 */
int
db_mindex::storeLDAP(db_query *qin, entry_object *obj, nis_object *o,
			entry_obj *oldObj, char *dbId) {
	__nis_table_mapping_t	*t;
	bool_t			asObj;
	db_query		*q, *qo, **qa;
	__nis_rule_value_t	*rv = 0;
	int			stat;
	const char		*myself = "db_mindex::storeLDAP";

	if (!useLDAPrespository || table == 0)
		return (LDAP_SUCCESS);

	/* Instances from the deferred dictionary should not update LDAP */
	if (table->mapping.isDeferredTable)
		return (LDAP_SUCCESS);

	t = selectMapping(table, 0, qin, TRUE, &asObj, &stat);
	if (t == 0 && stat != LDAP_SUCCESS)
		return (stat);

#ifdef	NISDB_LDAP_DEBUG
	if (t != 0)
		printf("storeLDAP: %s%s%s\n",
			dbId ? dbId : "", dbId ? ":" : "", NIL(t->objName));
#endif	/* NISDB_LDAP_DEBUG */

	/*
	 * selectMapping() didn't have the object to look at, so we
	 * must check if this is a directory entry or not.
	 */
	if (asObj) {
		if (o != 0) {
			if (o->zo_data.zo_type == NIS_ENTRY_OBJ)
				asObj = FALSE;
		} else if (obj != 0) {
			if (obj->en_type == 0 ||
				strcmp(obj->en_type, "IN_DIRECTORY") != 0)
				asObj = FALSE;
		}
	}

	if (asObj) {
		bool_t		freeO = FALSE;

		/*
		 * If we don't have a mapping, that's probably because
		 * the directory (represented by 'this') isn't mapped.
		 * Try to get a mapping from 'o' or 'obj'.
		 */
		if (t == 0) {
			if (o == 0 && obj != 0) {
				o = unmakePseudoEntryObj(obj, 0);
				if (o == 0)
					return (LDAP_OPERATIONS_ERROR);
				freeO = TRUE;
			}
			if (o != 0) {
				t = selectMapping(0, o, 0, TRUE, &asObj, &stat);
				if (t == 0) {
					if (freeO)
						nis_destroy_object(o);
					return (stat);
				}
			}
		}

		/*
		 * If we found a mapping for the 'table' in this db_mindex,
		 * store the object.
		 */
		if (t != 0) {
			if (o == 0) {
				if (obj != 0) {
					o = unmakePseudoEntryObj(obj, 0);
					freeO = TRUE;
				} else {
					db_status	dstat;

					o = dbFindObject(t->objName, &dstat);
					if (o == 0)
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: DB error %d finding \"%s\"",
							myself,
							NIL(t->objName));
					freeO = TRUE;
				}
			}
			if (o == 0)
				return (LDAP_OPERATIONS_ERROR);

			stat = storeObjLDAP(t, o);

			/*
			 * Store the object with the mapping. If 'o' was
			 * supplied by the caller, we first need to make
			 * a copy.
			 */
			if (!freeO) {
				o = nis_clone_object(o, 0);
				if (o == 0)
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unable to refresh mapping object for \"%s\"",
						myself, NIL(t->objName));
			}
			if (o != 0) {
				if (!replaceMappingObj(t, o))
					nis_destroy_object(o);
			}

			/*
			 * Object now either destroyed or stored in 't'.
			 * Set pointer to NULL in order to avoid freeing
			 * it below.
			 */
			o = 0;

			if (stat != LDAP_SUCCESS)
				return (stat);
		}

		if (freeO && o != 0) {
			nis_destroy_object(o);
			o = 0;
		}

		/*
		 * If the entry object 'obj' has the type "IN_DIRECTORY",
		 * then it's a directory entry, and we should check if
		 * the directory is mapped to LDAP, and update the dir
		 * entry list accordingly.
		 */
		if (obj == 0 || obj->en_type == 0 ||
				strcmp(obj->en_type, "IN_DIRECTORY") != 0)
			return (LDAP_SUCCESS);

		/* Does it have a mapping  ? */
		t = selectMapping(table, 0, 0, TRUE, &asObj, &stat);
		if (t == 0)
			return (stat);

		stat = storeObjLDAP(t, t->obj);

		return (stat);
	}

	/* Store table entries. If we don't have a mapping, we're done. */
	if (t == 0)
		return (LDAP_SUCCESS);

	if (qin != NULL && obj != NULL) {
		db_index_entry	*dbie;
		int		i, size, nq = 0;
		long		l, count;
		bool_t		valid;
		db_query	qbuf, **qold;

		rv = (__nis_rule_value_t *)am(myself, sizeof (*rv));
		qa = (db_query **)am(myself, sizeof (qa[0]));
		if (oldObj != 0) {
			/*
			 * Note that only qold[0] is a unique query pointer.
			 * All the other qold[i]'s are copies of qa[i].
			 * Hence, we only free qold[0], as well as qold
			 * itself.
			 */
			qold = (db_query **)am(myself, sizeof (qold[0]));
		} else {
			qold = 0;
		}
		if (rv == 0 || qa == 0 || (oldObj != 0 && qold == 0)) {
			sfree(rv);
			sfree(qa);
			sfree(qold);
			return (LDAP_NO_MEMORY);
		}

		q = schemeQuery2Query(qin, scheme);
		if (q == 0) {
			sfree(rv);
			sfree(qa);
			return (LDAP_PARAM_ERROR);
		}

		qa[0] = pseudoEntryObj2Query(obj, t->obj, &rv[0]);
		if (qa[0] == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
"%s: Unable to obtain query representation of new entry object for \"%s\"",
				myself, NIL(t->dbId));
			freeQuery(q);
			sfree(rv);
			sfree(qa);
			sfree(qold);
			return (LDAP_OPERATIONS_ERROR);
		}
		if (oldObj != 0) {
			qold[0] = pseudoEntryObj2Query(oldObj, t->obj, 0);
			if (qold[0] == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
"%s: Unable to obtain query representation of old entry object for \"%s\"",
					myself, NIL(t->dbId));
				freeQueries(qa, 1);
				freeQuery(q);
				sfree(rv);
				sfree(qa);
				sfree(qold);
				return (LDAP_OPERATIONS_ERROR);
			}
		}

		nq++;

		/*
		 * In order to support many-to-one NIS+ to LDAP mapping,
		 * we need to find all possible matches in the NIS+ DB,
		 * and then merge to produce a single update. mapToLDAP()
		 * takes care of the merging, so our job is to collect
		 * the matches. Worst case is that we need to search
		 * individually for each component in 'qin', so that's
		 * what we'll do.
		 *
		 * mapToLDAP() has a mode that only performs an update
		 * for the first DN, and that's what we want. In order
		 * to make sure that it's the correct DN, we leave the
		 * original query as the first one passed to mapToLDAP().
		 */

		size = qin->size();

		/* For each component of 'qin' */
		for (i = 0; i < size; i++) {
			db_query		*qc, **qat, **qoldt;
			long			j;
			__nis_rule_value_t	*rvt;

			qc = queryFromComponent(qin, i, &qbuf);
			if (qc == 0)
				continue;

			dbie = satisfy_query_dbonly(qc, &count, FALSE, &valid);
			if (dbie == 0 || !valid || count <= 0)
				continue;

			rvt = (__nis_rule_value_t *)realloc(rv,
						(nq+count) * sizeof (rv[0]));
			qat = (db_query **)realloc(qa,
						(nq+count) * sizeof (qa[0]));
			if (qold != 0)
				qoldt = (db_query **)realloc(qold,
						(nq+count) * sizeof (qold[0]));
			if (rvt == 0 || qat == 0 || (qold != 0 && qoldt == 0)) {
				if (qat == 0)
					freeQueries(qa, nq);
				else
					freeQueries(qat, nq);
				if (rvt == 0)
					freeRuleValue(rv, nq);
				else
					freeRuleValue(rvt, nq);
				if (qold != 0) {
					if (qoldt == 0)
						freeQueries(qold, 1);
					else
						freeQueries(qoldt, 1);
				}
				freeQuery(q);
				(void) memset(&qbuf, 0, sizeof (qbuf));
				logmsg(MSG_NOMEM, LOG_ERR,
					"%s: realloc(%d) failed",
					myself, (nq+count) * sizeof (void *));
				return (LDAP_NO_MEMORY);
			}

			rv = rvt;
			qa = qat;

			(void) memset(&rv[nq], 0, count * sizeof (rv[0]));
			(void) memset(&qa[nq], 0, count * sizeof (qa[0]));
			if (qold != 0) {
				qold = qoldt;
				(void) memset(&qold[nq], 0,
						count * sizeof (qold[0]));
			}

			for (j = 0; j < count; j++) {
				qa[nq] = pseudoEntryObj2Query(
					table->get_entry(dbie->getlocation()),
							t->obj, &rv[nq]);
				if (qa[nq] == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Could not create query from entry obj for \"%s\"",
						myself, NIL(t->objName));
					freeQueries(qa, nq);
					freeQueries(qold, 1);
					freeRuleValue(rv, nq);
					freeQuery(q);
					(void) memset(&qbuf, 0, sizeof (qbuf));
					return (LDAP_PARAM_ERROR);
				}
				if (qold != 0)
					qold[nq] = qa[nq];
				nq++;
				dbie = dbie->getnextresult();
				if (dbie == 0)
					break;
			}
		}

		stat = mapToLDAP(t, nq, (qold != 0 ? qold : qa), qa, rv, 1,
				dbId);

		freeQueries(qa, nq);
		freeRuleValue(rv, nq);
		freeQuery(q);
		freeQueries(qold, 1);
		(void) memset(&qbuf, 0, sizeof (qbuf));

	} else if (qin == 0 && obj == 0 && t->objType == NIS_TABLE_OBJ) {
		long			i, j, ntab;
		entry_object		**tab;

		READLOCK(table, LDAP_OPERATIONS_ERROR,
				"r table db_mindex::storeLDAP");

		tab = table->gettab();
		ntab = table->getsize();
		if (tab == 0 || ntab <= 0) {
			READUNLOCK(table, LDAP_OPERATIONS_ERROR,
					"ru table db_mindex::storeLDAP");
			return (LDAP_SUCCESS);
		}

		qa = (db_query **)am(myself, ntab * sizeof (qa[0]));
		rv = (__nis_rule_value_t *)am(myself, ntab * sizeof (rv[0]));
		if (qa == 0 || rv == 0) {
			sfree(qa);
			sfree(rv);
			READUNLOCK(table, LDAP_OPERATIONS_ERROR,
					"ru table db_mindex::storeLDAP");
			return (LDAP_NO_MEMORY);
		}

		for (i = 0; i < ntab; i++) {
			if (tab[i] == 0)
				continue;

			qa[i] = pseudoEntryObj2Query(tab[i], t->obj, &rv[i]);
			if (qa[i] == 0) {
				freeQueries(qa, i);
				freeRuleValue(rv, i);
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Could not create query from entry for \"%s\"",
					myself, NIL(t->objName));
				READUNLOCK(table, LDAP_OPERATIONS_ERROR,
					"ru table db_mindex::storeLDAP");
				return (LDAP_OPERATIONS_ERROR);
			}
		}

		stat = mapToLDAP(t, ntab, qa, qa, rv, 0, dbId);

		freeQueries(qa, ntab);
		freeRuleValue(rv, ntab);

		if (stat == LDAP_SUCCESS) {
			struct timeval  now;
			int		lstat, lck = 1;
			/*
			 * Since we've just successfully uploaded everthing
			 * in this table, we now consider our local copy
			 * up-to-date as well.
			 */

			(void) gettimeofday(&now, 0);
			WRITELOCKNR(table, lstat,
				"w table db_mindex::storeLDAP");
			if (lstat == 0) {
				table->mapping.enumExpire = now.tv_sec +
					table->mapping.ttl;
				lck = 0;
				WRITEUNLOCKNR(table, lstat,
					"wu table db_mindex::storeLDAP");
			}
			if (lstat != 0) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: %sock error %d for \"%s\"%s",
					myself, lck?"L":"Unl", lstat,
					NIL(t->objName),
					lck ?
				"; unable to update enumeration expiration":
				"");
			}
		}

		READUNLOCK(table, stat,
				"ru table db_mindex::storeLDAP");
	}

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
