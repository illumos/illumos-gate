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
 *	nis_db.cc
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 RackTop Systems.
 */


#include <sys/param.h>
#include <strings.h>
#include <syslog.h>
#include "nisdb_mt.h"
#include "db_headers.h"
#include "db_entry.h"
#include "db.h"
#include "db_dictionary.h"
#include "db_pickle.h"
#include "nis_db.h"
#include "nis_ldap.h"
#include "ldap_util.h"
#include "ldap_parse.h"
#include "ldap_glob.h"
#include "ldap_xdr.h"
#include "ldap_glob.h"

db_dictionary	curdict;
db_dictionary	tempdict; /* a temporary one */

db_dictionary *InUseDictionary = &curdict;
db_dictionary *FreeDictionary = &tempdict;

extern "C" {
static db_result	*db_add_entry_x(char *tab, int numattrs,
					nis_attr *attrname, entry_obj * newobj,
					int skiplog, int nosync);
db_status		db_table_exists(char *table_name);

/*
 * (Imported from rpc.nisd/nis_xx_proc.c)
 *
 * 'tbl_prototype' is used to create a table that holds a directory.
 */
static table_col cols[2] = {
	{(char *)"object", TA_BINARY+TA_XDR, 0},
	{(char *)"name", TA_CASE+TA_SEARCHABLE, 0}
};

table_obj tbl_prototype = { (char *)"DIRECTORY", 2, ' ', {2, &cols[0]}, NULL };
}

/*
 * Free resources associated with a db_result structure
 */
void
db_free_result(db_result *dr)
{
	int	i;

	if (dr == 0)
		return;

	/* Can't have valid objects */
	if (dr->status != DB_SUCCESS) {
		free(dr);
		return;
	}

	for (i = 0; i < dr->objects.objects_len; i++)
		free_entry(dr->objects.objects_val[i]);
	free(dr->objects.objects_val);
	free(dr);
}


/* Return an empty db_result structure with its status field set to 's'. */
db_result*
empty_result(db_status s)
{
	db_result * res = new db_result;
	if (res != NULL)  {
		res->status = s;
		res->nextinfo.db_next_desc_len = 0;
		res->nextinfo.db_next_desc_val = NULL;
		res->objects.objects_len = 0;
		res->objects.objects_val = NULL;
	} else {
		WARNING("nis_db::empty_result: cannot allocate space");
	}
	return (res);
}

static db_result*
set_result(db_result* res, db_status s)
{
	if (res != NULL)  {
		res->status = s;
	}
	return (res);
}

/*
 * Given a FQ object name for a table or directory, return the (db *)
 * corresponding to the object.
 */
db *
tableDB(char *tableName) {
	db_table_desc	*tbl = 0;
	char		*intName;
	db		*dbase;

	intName = internalTableName(tableName);
	if (intName == 0)
		return (0);

	dbase = InUseDictionary->find_table(intName, &tbl);

	sfree(intName);

	return (dbase);
}

extern "C" {

bool_t
db_in_dict_file(char *name)
{
	return (InUseDictionary->find_table_desc(name) != NULL);

}

const char
*db_perror(db_status dbstat)
{
	const char *str = NULL;

	switch (dbstat) {
		case DB_SUCCESS:
			str = "Success";
			break;
		case DB_NOTFOUND:
			str = "Not Found";
			break;
		case DB_BADTABLE:
			str = "Bad Table";
			break;
		case DB_BADQUERY:
			str = "Bad Query";
			break;
		case DB_BADOBJECT:
			str = "Bad Object";
			break;
		case DB_MEMORY_LIMIT:
			str = "Memory limit exceeded";
			break;
		case DB_STORAGE_LIMIT:
			str = "Database storage limit exceeded";
			break;
		case DB_INTERNAL_ERROR:
			str = "Database internal error";
			break;
		case DB_SYNC_FAILED:
			str = "Sync of log file failed";
			break;
		default:
			str = "Unknown Error";
			break;
	}
	return (str);
}

bool_t
db_extract_dict_entries(char *newdict, char **fs, int fscnt)
{
	/*
	 * Use the "FreeDictionary" ptr for the backup
	 * dictionary.
	 */
	if (!FreeDictionary->inittemp(newdict, *InUseDictionary))
		return (FALSE);
	return (InUseDictionary->extract_entries (*FreeDictionary,
		fs, fscnt));
}

bool_t
db_copy_file(char *infile, char *outfile)
{
	return (InUseDictionary->copyfile(infile, outfile));

}


/*
 * The tok and repl parameters will allow us to merge two dictionaries
 * that reference tables from different domains (master/replica in live
 * in different domains). If set to NULL, then the dictionary merge is
 * done as normal (no name changing).
 */
db_status
db_begin_merge_dict(char *newdict, char *tok, char *repl)
{
	db_status dbstat;

	/*
	 * It is assumed that InUseDictionary has already been initialized.
	 */
	dbstat = InUseDictionary->checkpoint();
	if (dbstat != DB_SUCCESS)
		return (dbstat);

	/*
	 * Use the "FreeDictionary" ptr for the backup
	 * dictionary.
	 */
	if (!FreeDictionary->init(newdict))
		return (DB_INTERNAL_ERROR);

	return (InUseDictionary->merge_dict(*FreeDictionary,
		tok, repl));
}


db_status
db_end_merge_dict()
{
	db_status	dbstat;

	dbstat = InUseDictionary->checkpoint();
	if (dbstat != DB_SUCCESS) {
		return (dbstat);
	}
	dbstat = InUseDictionary->db_shutdown();
	if (dbstat != DB_SUCCESS) {
		return (dbstat);
	}
	dbstat = FreeDictionary->db_shutdown();
	if (dbstat != DB_SUCCESS) {
		return (dbstat);
	}
	return (dbstat);
}



db_status
db_abort_merge_dict()
{
	db_status	dbstat;

	dbstat = InUseDictionary->db_shutdown();
	if (dbstat != DB_SUCCESS)
		return (dbstat);
	dbstat = FreeDictionary->db_shutdown();
	if (dbstat != DB_SUCCESS)
		return (dbstat);
}


/*
 * Initialize system (dictionary) using file 'filename'.  If system cannot
 * be read from file, it is initialized to be empty. Returns TRUE if
 * initialization succeeds, FALSE otherwise.
 * This function must be called before any other.
*/
bool_t
db_initialize(char * filename)
{
	return (InUseDictionary->init(filename));
}


/*
 * Massage the dictionary file by replacing the specified token with the
 * the replacement string. This function is needed to provide backwards
 * compatibility for providing a transportable dictionary file. The idea
 * is that rpc.nisd will call this function when it wants to change the
 * /var/nis/<hostname> strings with something like /var/nis/data.
 *
 */
db_status
db_massage_dict(char *newdictname, char *tok, char *repl)
{
	return (InUseDictionary->massage_dict(newdictname, tok, repl));
}



/*
 * Create new table using given table name and table descriptor.
 * Returns DB_SUCCESS if successful; appropriate error code otherwise.
*/
db_status
db_create_table(char * table_name, table_obj * table_desc)
{
	return (InUseDictionary->add_table(table_name, table_desc));
}

/*
 * Destroys table named by 'table_name.'  Returns DB_SUCCESS if successful,
 * error code otherwise.  Note that currently, the removed table is no
 * longer accessible from this interface and all files associated with it
 * are removed from stable storage.
*/
db_status
db_destroy_table(char * table_name)
{
	return (InUseDictionary->delete_table(table_name));
}


/*
* Return a copy of the first entry in the specified table, that satisfies
* the given attributes.  The returned structure 'db_result' contains the status,
* the  copy of the object, and a 'db_next_desc' to be used for the 'next'
* operation.
 */
db_result *
db_first_entry(char * table_name, int numattrs, nis_attr * attrname)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db_table_desc * tbl = NULL;
	db * dbase = InUseDictionary->find_table(table_name, &tbl);

	if (tbl == NULL || dbase == NULL)
		return (set_result(safety, DB_BADTABLE));
	else {
		db_result * res = NULL;
		db_query *query = NULL;

		if (numattrs != 0) {
			query = InUseDictionary->translate_to_query(tbl,
					numattrs, attrname);
			if (query == NULL)
				return (set_result(safety,
						DB_BADQUERY));
		}
		res = dbase->execute(DB_FIRST, query, NULL, NULL);
		if (query) delete query;
		if (safety) delete safety;
		return (res);
	}
}

/*
 * Return a copy of the next entry in the specified table as specified by
 * the 'next_desc'.  The returned structure 'db_result' contains the status,
 * a copy of the object, and a db_next_desc to be used for a subsequent
 * 'next' operation.
*/
db_result *
db_next_entry(char * table_name, db_next_desc * next_desc)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase != NULL) {
		if (safety) delete safety;
		return (dbase->execute(DB_NEXT, NULL, NULL, next_desc));
	} else
		return (set_result(safety, DB_BADTABLE));
}

/*
 * Indicate to the system that you are no longer interested in the rest of the
 * results identified by [next_desc].  After executing this operation, the
 * [next_desc] is no longer valid (cannot  be used as an argument for next).
*/

db_result *
db_reset_next_entry(char * table_name, db_next_desc * next_desc)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase != NULL) {
		if (safety) delete safety;
		return (dbase->execute(DB_RESET_NEXT,
					NULL, NULL, next_desc));
	} else
		return (set_result(safety, DB_BADTABLE));
}

/*
 * Returns copies of entries that satisfy the given attributes from table.
 * Returns the status and entries in a db_result structure.
 * If no attributes are specified, DB_BADQUERY is returned.
*/
db_result *
__db_list_entries(char * table_name, int numattrs, nis_attr * attrname,
			bool_t useDeferred)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db_table_desc * tbl = NULL;
	db * dbase = InUseDictionary->find_table(table_name, &tbl,
							useDeferred);

	if (tbl == NULL || dbase == NULL)
		return (set_result(safety, DB_BADTABLE));
	else {
		db_result * res = NULL;
		if (numattrs != 0) {
			db_query *query;
			query = InUseDictionary->translate_to_query(tbl,
						    numattrs, attrname);
			if (query == NULL)
				return (set_result(safety,
							DB_BADQUERY));
			res = dbase->execute(DB_LOOKUP, query,
							NULL, NULL);
			delete query;
		} else {
			res = dbase->execute(DB_ALL, NULL, NULL, NULL);
		}
		if (safety) delete safety;
		return (res);
	}
}

db_result *
db_list_entries(char *table_name, int numattrs, nis_attr *attrname) {
	return (__db_list_entries(table_name, numattrs, attrname, TRUE));
}

/*
 * Input:	A fully qualified object name (example: "x.y.z").
 * Output:	Returns the first level of the object name ("x").
 *		If 'tableP' is non-NULL, '*tableP' will contain
 *		the internal table name for "y.z".
 *
 * Both the return value and '*tableP' must be freed by the caller.
 */
char *
entryName(const char *msg, char *objName, char **tableP) {
	char		*name, *table, *dir;
	const char	*myself = "entryName";

	if (msg == 0)
		msg = myself;

	name = sdup(msg, T, objName);
	if (name == 0)
		return (0);

	dir = strchr(name, '.');
	if (dir == 0) {
		sfree(name);
		return (0);
	}
	*(dir++) = '\0';

	if (tableP == 0)
		return (name);

	table = internalTableName(dir);
	if (table == 0) {
		sfree(name);
		return (0);
	}

	*tableP = table;

	return (name);
}

#define	RETSTAT(obj, status) \
	{ \
		if (statP != 0) \
			*statP = status; \
		return (obj); \
	}

/*
 * Given a fully qualified object name, retrive a copy of the object,
 * using the NIS+ DB only (i.e., no LDAP). Avoids using nis_leaf_of()
 * etc., since they aren't re-entrant.
 */
nis_object *
dbFindObject(char *objName, db_status *statP) {
	char		buf[MAXPATHLEN+NIS_MAXNAMELEN+1];
	char		*name, *table = 0;
	nis_attr	attr;
	db		*dbase;
	db_result	*res;
	db_table_desc	*tbl = 0;
	db_query	*query;
	db_mindex	*mindex;
	nis_object	*o;
	int		lstat;
	const char	*myself = "dbFindObject";

	if (objName == 0)
		RETSTAT(0, DB_BADQUERY);

	/* The root dir is treated specially */
	table = internalTableName(objName);
	if (table == 0)
		RETSTAT(0, DB_BADQUERY);
	if (strcmp(ROOTDIRFILE, table) == 0) {
		sfree(table);

		o = get_root_object();
		if (o == 0)
			RETSTAT(0, DB_NOTFOUND);

		RETSTAT(o, DB_SUCCESS);
	}

	/* If not the root dir, find the directory where the entry lives */

	sfree(table);
	name = entryName(myself, objName, &table);
	if (name == 0 || table == 0) {
		sfree(name);
		RETSTAT(0, DB_MEMORY_LIMIT);
	}

	dbase = InUseDictionary->find_table_noLDAP(table, &tbl, TRUE, TRUE);
	sfree(table);
	if (dbase != 0)
		mindex = dbase->mindex();
	if (dbase == 0 || tbl == 0 || mindex == 0) {
		sfree(name);
		RETSTAT(0, DB_BADTABLE);
	}

	WRITELOCKNR(mindex, lstat, "mindex w dbFindObject");
	if (lstat != 0) {
		sfree(name);
		RETSTAT(0, DB_LOCK_ERROR);
	}

	attr.zattr_ndx = (char *)"name";
	attr.zattr_val.zattr_val_val = name;
	attr.zattr_val.zattr_val_len = slen(name) + 1;

	query = InUseDictionary->translate_to_query(tbl, 1, &attr);
	if (query == 0) {
		sfree(name);
		WRITEUNLOCKNR(mindex, lstat, "mindex wu dbFindObject");
		RETSTAT(0, DB_BADQUERY);
	}

	/* Only want to look in the local DB */
	mindex->setNoLDAPquery();

	res = dbase->execute(DB_LOOKUP, query, 0, 0);

	mindex->clearNoLDAPquery();

	delete query;

	sfree(name);

	WRITEUNLOCKNR(mindex, lstat, "mindex wu dbFindObject");
	if (lstat != 0) {
		db_free_result(res);
		RETSTAT(0, DB_LOCK_ERROR);
	}

	if (res == 0)
		RETSTAT(0, DB_MEMORY_LIMIT);

	if (res->status != DB_SUCCESS) {
		db_status	st = res->status;

		db_free_result(res);
		RETSTAT(0, st);
	}

	if (res->objects.objects_len != 1 || res->objects.objects_val == 0 ||
			res->objects.objects_val[0] == 0) {
		db_free_result(res);
		RETSTAT(0, DB_BADOBJECT);
	}

	o = unmakePseudoEntryObj(res->objects.objects_val[0], 0);

	db_free_result(res);

	if (o == 0) {
		RETSTAT(0, DB_BADOBJECT);
	}

	RETSTAT(o, DB_SUCCESS);
}

/*
 * Return the object specified by 't' or 'objName' from LDAP. Set
 * the LDAP status in '*statP'.
 */
nis_object *
ldapFindObj(__nis_table_mapping_t *t, char *objName, int *statP) {
	nis_object	*o;
	int		stat;
	const char	*myself = "ldapFindObj";

	if (t == 0) {
		char	*table, tbuf[MAXPATHLEN + NIS_MAXNAMELEN + 1];

		if (objName == 0) {
			if (statP != 0)
				*statP = LDAP_PARAM_ERROR;
			return (0);
		}

		/* Look for mapping */
		table = internal_table_name(objName, tbuf);
		if (table == 0) {
			if (statP != 0)
				*statP = LDAP_PARAM_ERROR;
			return (0);
		}

		t = (__nis_table_mapping_t *)__nis_find_item_mt(table,
						&ldapMappingList, 0, 0);
		if (t == 0) {
			/* Not really an error; just not mapped */
			*statP = LDAP_SUCCESS;
			return (0);
		}
	}

	o = 0;
	stat = objFromLDAP(t, &o, 0, 0);

	if (statP != 0)
		*statP = stat;

	return (o);
}

/*
 * Look for the specified object, first locally, then in LDAP.
 */
nis_object *
findObj(char *name, db_status *statP, int *lstatP) {
	nis_object	*o;
	db_status	stat = DB_SUCCESS;
	int		lstat = LDAP_SUCCESS;
	const char	*myself = "findObj";

	o = dbFindObject(name, &stat);

	if (o == 0) {
		if (stat != DB_NOTFOUND)
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: DB error %d looking for \"%s\"",
				myself, stat, NIL(name));

		o = ldapFindObj(0, name, &lstat);
		if (o == 0) {
			if (lstat != LDAP_SUCCESS &&
					lstat != LDAP_NO_SUCH_OBJECT)
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: LDAP error looking for \"%s\": %s",
					myself, NIL(name),
					ldap_err2string(lstat));
		}
	}

	if (statP != 0)
		*statP = stat;
	if (lstatP != 0)
		*lstatP = lstat;

	return (o);
}

/*
 * Delete the specified object from the local DB.
 */
db_status
dbDeleteObj(char *objName) {
	nisdb_tsd_t	*tsd = __nisdb_get_tsd();
	nis_object	*o;
	db_status	stat;
	nisdb_obj_del_t	*nod, *tmp;
	int		xid;
	const char	*myself = "dbDeleteObj";

	if (objName == 0)
		return (DB_SUCCESS);

	/*
	 * Since in-structure locks can't completely protect
	 * during structure deletion, we just note that the
	 * object should be deleted, and leave that for a
	 * (slightly) later time in rpc.nisd, where we can
	 * use the rpc.nisd's table/directory locks for
	 * protection.
	 */

	if (tsd == 0)
		return (DB_INTERNAL_ERROR);

	o = dbFindObject(objName, &stat);
	if (o == 0) {
		if (stat == DB_NOTFOUND)
			return (DB_SUCCESS);
		else
			return (stat);
	}

	/*
	 * In order to prevent a chicken-and-egg problem (if the
	 * object doesn't exist in LDAP, is that because we just
	 * haven't written it to LDAP yet, or because it's been
	 * removed), we only allow object deletion if we're the
	 * master for it.
	 */

	nod = (nisdb_obj_del_t *)am(myself, sizeof (*nod));
	if (nod == 0) {
		nis_destroy_object(o);
		return (DB_MEMORY_LIMIT);
	}

	nod->objType = o->zo_data.zo_type;
	nis_destroy_object(o);

	nod->objName = sdup(myself, T, objName);
	if (nod->objName == 0) {
		sfree(nod);
		return (DB_MEMORY_LIMIT);
	}

	/* Check for a dup */
	for (tmp = tsd->objDelList; tmp != 0;
			tmp = (nisdb_obj_del_t *)tmp->next) {
		if (strcmp(nod->objName, tmp->objName) == 0) {
			sfree(nod->objName);
			sfree(nod);
			return (DB_SUCCESS);
		}
	}

	/* Insert at start of list */
	nod->next = tsd->objDelList;
	tsd->objDelList = nod;

	return (DB_SUCCESS);
}

/*
 * Touch (i.e., update the expiration time for) the specified object.
 */
db_status
dbTouchObj(char *objName) {
	char		*ent, *table;
	db		*dbase;
	db_table_desc	*tbl = 0;
	db_mindex	*mindex;
	nis_attr	attr;
	db_query	*query;
	db_status	stat;
	const char	*myself = "dbTouchObj";

	table = internalTableName(objName);
	if (table == 0)
		return (DB_BADQUERY);

	if (strcmp(ROOTDIRFILE, table) == 0) {
		sfree(table);

		if (touchRootDir() == 0)
			return (DB_SUCCESS);
		else
			return (DB_INTERNAL_ERROR);
	}

	sfree(table);
	table = 0;
	ent = entryName(myself, objName, &table);
	if (ent == 0 || table == 0) {
		sfree(ent);
		return (DB_MEMORY_LIMIT);
	}

	dbase = InUseDictionary->find_table(table, &tbl, TRUE);
	if (dbase != 0)
		mindex = dbase->mindex();
	if (dbase == 0 || tbl == 0 || mindex == 0) {
		sfree(ent);
		sfree(table);
		return (DB_BADTABLE);
	}

	attr.zattr_ndx = (char *)"name";
	attr.zattr_val.zattr_val_val = ent;
	attr.zattr_val.zattr_val_len = slen(ent) + 1;

	query = InUseDictionary->translate_to_query(tbl, 1, &attr);
	if (query == 0) {
		sfree(ent);
		sfree(table);
		return (DB_BADQUERY);
	}

	mindex->touchEntry(query);

	sfree(ent);
	sfree(table);
	delete query;

	return (DB_SUCCESS);
}

/*
 * Create a NIS_TABLE_OBJ.
 * Borrows heavily from rpc.nisd/nis_db.c:__create_table().
 */
db_status
dbCreateTable(char *intName, nis_object *obj) {
	table_col	tc[NIS_MAXCOLUMNS+1];
	table_obj	tobj, *t;
	int		i;
	const char	*myself = "dbCreateTable";

	if (intName == 0 || obj == 0)
		return (DB_BADTABLE);

	t = &(obj->TA_data);

	/* Make sure there are searchable columns */
	for (i = 0; i < t->ta_cols.ta_cols_len; i++) {
		if (t->ta_cols.ta_cols_val[i].tc_flags & TA_SEARCHABLE)
			break;
	}
	if (i >= t->ta_cols.ta_cols_len) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: No searchable columns in \"%s\" (\"%s\")",
			myself, NIL(obj->zo_name), NIL(intName));
		return (DB_BADTABLE);
	}

	tobj = *t;
	/* Shift columns one step right */
	for (i = 0; i < tobj.ta_cols.ta_cols_len; i++) {
		tc[i+1] = tobj.ta_cols.ta_cols_val[i];
	}
	tc[0].tc_name = 0;
	tc[0].tc_flags = TA_XDR | TA_BINARY;
	tc[0].tc_rights = 0;
	tobj.ta_cols.ta_cols_len += 1;
	tobj.ta_cols.ta_cols_val = tc;

	return (db_create_table(intName, &tobj));
}

#define	TABLE_COL(o, n)	o->TA_data.ta_cols.ta_cols_val[n]

/*
 * Refresh (if necessary, create), the specified object in the local DB.
 */
db_status
dbRefreshObj(char *name, nis_object *o) {
	char		*objName;
	__nis_buffer_t	b = {0, 0};
	nis_object	*curObj;
	db_status	stat;
	char		*ent, *table, *objTable;
	int		rstat, isDir = 0, isTable = 0;
	const char	*myself = "refreshObj";

	if (o == 0)
		/* Delete it */
		return (dbDeleteObj(name));

	/* We don't work on entry objects */
	if (o->zo_data.zo_type == NIS_ENTRY_OBJ)
		return (DB_BADOBJECT);

	if (name != 0)
		objName = name;
	else {
		bp2buf(myself, &b, "%s.%s", NIL(o->zo_name), NIL(o->zo_domain));
		objName = b.buf;
	}

	curObj = dbFindObject(objName, &stat);
	if (curObj == 0 && stat != DB_NOTFOUND) {
		sfree(b.buf);
		return (stat);
	}

	/*
	 * If the object doesn't change, just touch it to update the
	 * expiration time.
	 */
	if (curObj != 0) {
		if (sameNisPlusObj(o, curObj)) {
			sfree(b.buf);
			nis_destroy_object(curObj);
			return (dbTouchObj(objName));
		}

		/* Otherwise, check that the name and type is the same */
		if (o->zo_data.zo_type != curObj->zo_data.zo_type ||
			o->zo_name == 0 || curObj->zo_name == 0 ||
			o->zo_domain == 0 || curObj->zo_domain == 0 ||
			strcmp(o->zo_name, curObj->zo_name) != 0 ||
			strcmp(o->zo_domain, curObj->zo_domain) != 0) {
			sfree(b.buf);
			nis_destroy_object(curObj);
			return (DB_BADOBJECT);
		}

		/*
		 * If the object is a table, we can't allow the scheme
		 * to change.
		 */
		if (o->zo_data.zo_type == NIS_TABLE_OBJ) {
			int	i;

			if (o->TA_data.ta_maxcol !=
					curObj->TA_data.ta_maxcol) {
				sfree(b.buf);
				nis_destroy_object(curObj);
				return (DB_BADOBJECT);
			}

			for (i = 0; i < o->TA_data.ta_maxcol; i++) {
				if ((TABLE_COL(o, i).tc_flags &
						TA_SEARCHABLE) !=
					(TABLE_COL(curObj, i).tc_flags &
						TA_SEARCHABLE)) {
					sfree(b.buf);
					nis_destroy_object(curObj);
					return (DB_BADOBJECT);
				}
			}
		}
	} else {
		/*
		 * If we're creating a directory object, make a note
		 * so that we can add it to the serving list and create
		 * the disk file. Similarly, if creating a table, we
		 * also need to create the disk file.
		 */
		if (o->zo_data.zo_type == NIS_DIRECTORY_OBJ)
			isDir = 1;
		else if (o->zo_data.zo_type == NIS_TABLE_OBJ)
			isTable = 1;
	}

	objTable = internalTableName(objName);
	if (objTable == 0) {
		sfree(b.buf);
		if (curObj != 0)
			nis_destroy_object(curObj);
		return (DB_BADQUERY);
	}

	if (strcmp(ROOTDIRFILE, objTable) == 0) {
		sfree(objTable);

		rstat = update_root_object((nis_name)ROOTOBJFILE, o);
		if (rstat == 1)
			stat = DB_SUCCESS;
		else
			stat = DB_INTERNAL_ERROR;
	} else {
		nis_attr	attr;
		entry_object	*e, eo;
		entry_col	ec[2];
		db		*dbase;
		db_table_desc	*tbl = 0;
		db_mindex	*mindex;
		db_result	*dbres;
		int		lstat;

		/* Find parent */
		ent = entryName(myself, objName, &table);
		if (ent == 0 || table == 0) {
			sfree(b.buf);
			sfree(objTable);
			sfree(ent);
			if (curObj != 0)
				nis_destroy_object(curObj);
			return (DB_MEMORY_LIMIT);
		}

		/*
		 * Calling vanilla find_table() here (which might go to
		 * LDAP and recurse back to ourselves) so that it should
		 * work to create a hierarchy of directories.
		 */
		dbase = InUseDictionary->find_table(table, &tbl, TRUE);
		if (dbase != 0)
			mindex = dbase->mindex();
		if (dbase == 0 || tbl == 0 || mindex == 0) {
			sfree(b.buf);
			sfree(objTable);
			sfree(ent);
			sfree(table);
			if (curObj != 0)
				nis_destroy_object(curObj);
			return (DB_BADTABLE);
		}

		/* Construct suitable nis_attr and entry_object */
		attr.zattr_ndx = (char *)"name";
		attr.zattr_val.zattr_val_val = ent;
		attr.zattr_val.zattr_val_len = slen(ent) + 1;

		ec[1].ec_flags = 0;
		ec[1].ec_value.ec_value_val = ent;
		ec[1].ec_value.ec_value_len = attr.zattr_val.zattr_val_len;

		eo.en_type = (char *)"IN_DIRECTORY";
		eo.en_cols.en_cols_val = ec;
		eo.en_cols.en_cols_len = 2;

		e = makePseudoEntryObj(o, &eo, 0);
		if (e == 0) {
			sfree(objTable);
			sfree(table);
			sfree(ent);
			if (curObj != 0)
				nis_destroy_object(curObj);
			return (DB_INTERNAL_ERROR);
		}

		/* Only want to update the local DB */

		WRITELOCKNR(mindex, lstat, "mindex w dbRefreshObj");
		if (lstat != 0) {
			sfree(objTable);
			sfree(table);
			sfree(ent);
			if (curObj != 0)
				nis_destroy_object(curObj);
			return (DB_LOCK_ERROR);
		}
		mindex->setNoWriteThrough();
		mindex->setNoLDAPquery();

		dbres = db_add_entry_x(table, 1, &attr, e, 0, 0);

		mindex->clearNoLDAPquery();
		mindex->clearNoWriteThrough();
		WRITEUNLOCKNR(mindex, lstat, "mindex wu dbRefreshObj");
		if (lstat != 0) {
			sfree(objTable);
			sfree(table);
			sfree(ent);
			if (curObj != 0)
				nis_destroy_object(curObj);
			db_free_result(dbres);
			return (DB_LOCK_ERROR);
		}

		sfree(ent);
		sfree(table);

		if (dbres == 0)
			stat = DB_MEMORY_LIMIT;
		else
			stat = dbres->status;

		db_free_result(dbres);

		/*
		 * If successful so far, add the transaction.
		 */
		if (stat == DB_SUCCESS) {
			int		xid, st;
			db_status	ds;
			nis_object	*dirObj;

			/* Find the directory where this is added */
			dirObj = dbFindObject(o->zo_domain, &ds);
			if (dirObj == 0) {
				sfree(objTable);
				if (curObj != 0)
					nis_destroy_object(curObj);
				return (ds);
			}

			xid = beginTransaction();
			if (xid == 0) {
				sfree(objTable);
				if (curObj != 0)
					nis_destroy_object(curObj);
				nis_destroy_object(dirObj);
				return (DB_INTERNAL_ERROR);
			}

			st = addUpdate((curObj == 0) ? ADD_NAME : MOD_NAME_NEW,
					objName, 0, 0, o, curObj, 0);
			if (st != 0) {
				(void) abort_transaction(xid);
				sfree(objTable);
				if (curObj != 0)
					nis_destroy_object(curObj);
				nis_destroy_object(dirObj);
				return (DB_INTERNAL_ERROR);
			}

			st = endTransaction(xid, dirObj);
			if (st != 0)
				stat = DB_INTERNAL_ERROR;

			if (curObj != 0)
				nis_destroy_object(curObj);
			nis_destroy_object(dirObj);
		}

		/*
		 * If it's a table or directory, create the DB file.
		 * If a directory, also add it to the serving list.
		 */
		if (stat == DB_SUCCESS &&(isDir || isTable)) {
			if (isDir) {
				stat = db_create_table(objTable,
							&tbl_prototype);
			} else {
				stat = dbCreateTable(objTable, o);
			}
		}
		sfree(objTable);
	}

	sfree(b.buf);

	return (stat);
}

/*
 * Replace the object stored with the mapping 't'. Return TRUE if
 * at least one object was replaced, FALSE otherwise.
 */
bool_t
replaceMappingObj(__nis_table_mapping_t *t, nis_object *n) {
	__nis_table_mapping_t	*x;
	nis_object		*old = 0;
	int			assigned = 0;

	/*
	 * The alternate mappings are usually mostly copies
	 * of the original, so we try to make sure that we
	 * don't free the same nis_object twice.
	 */
	for (x = t; x != 0; x = (__nis_table_mapping_t *)x->next) {
		if (old == 0) {
			old = x->obj;
			if (x->obj != 0)
				nis_destroy_object(x->obj);
		} else {
			if (x->obj != old && x->obj != 0)
				nis_destroy_object(x->obj);
		}
		x->obj = n;
		assigned++;
	}

	return (assigned > 0);
}

/*
 * Set object type, column info, and obj for the specified
 * mapping 't' from the object 'o'. Returns zero if 'o' was unused,
 * and should be freed by the caller, larger than zero otherwise.
 */
int
setMappingObjTypeEtc(__nis_table_mapping_t *t, nis_object *o) {
	__nis_table_mapping_t	*x;
	int			ls, ret;
	int	                i;

	if (t == 0 || o == 0)
		return (0);

	t->objType = o->zo_data.zo_type;
	for (x = t; x != 0; x = (__nis_table_mapping_t *)x->next) {
		if (x != t) {
			x->objType = t->objType;
		}
		if (x->objType == NIS_TABLE_OBJ) {
			/*
			 * If we have rules, this mapping is for table entries,
			 * and we need the column names. Otherwise, remove the
			 * column names (if any).
			 */

                        for (i = 0; i < x->numColumns; i++)
			sfree(x->column[i]);
		        sfree(x->column);
			x->column = 0;
			x->numColumns = 0;
		}
	}
	ret = replaceMappingObj(t, o);

	return (ret);
}

/*
 * Retrieve the specified object (internal DB name) from LDAP, and
 * refresh/create as appropriate.
 */
db_status
dbCreateFromLDAP(char *intName, int *ldapStat) {
	__nis_table_mapping_t	*t;
	int			lstat, doDestroy;
	nis_object		*obj = 0;
	db_status		dstat;
	const char		*myself = "dbCreateFromLDAP";

	if (!useLDAPrespository) {
		if (ldapStat != 0)
			*ldapStat = LDAP_SUCCESS;
		return (DB_SUCCESS);
	}

	t = (__nis_table_mapping_t *)__nis_find_item_mt(intName,
							&ldapMappingList,
							0, 0);

	/* No mapping isn't a failure */
	if (t == 0) {
		if (ldapStat != 0)
			*ldapStat = LDAP_SUCCESS;
		return (DB_NOTFOUND);
	}

	lstat = objFromLDAP(t, &obj, 0, 0);
	if (ldapStat != 0)
		*ldapStat = lstat;
	if (lstat != LDAP_SUCCESS)
		return (DB_NOTFOUND);

	/*
	 * If the LDAP operation was successful, but 'obj' is NULL,
	 * there's no mapping for this object, and we're done.
	 */
	if (obj == 0)
		return (DB_SUCCESS);

	/* Update the mapping with object info */
	doDestroy = setMappingObjTypeEtc(t, obj) == 0;

	dstat = dbRefreshObj(t->objName, obj);

	if (doDestroy)
		nis_destroy_object(obj);

	return (dstat);
}

/*
 * Up- (fromLDAP==0) or down- (fromLDAP==1) load all LDAP mapped data.
 * Returns an LDAP error status.
 */
int
loadAllLDAP(int fromLDAP, void *cookie, db_status *dstatP) {
	__nis_table_mapping_t	*t, *start;
	int			stat = LDAP_SUCCESS;
	db_status		dstat = DB_SUCCESS;
	db			*dbase;
	db_table_desc		*tbl = 0;
	db_mindex		*mindex;
	const char		*myself = "loadAllLDAP";

	/*
	 * If the 'cookie' and '*cookie' are non-NULL, start scanning
	 * the mappings from '*cookie'. When we return with an error,
	 * we set '*cookie' to point to the mapping being processed.
	 * This enables our caller to react appropriately, and retry
	 * if desired.
	 *
	 * The cookie is opaque to our caller, who's only allowed to
	 * initialize *cookie to NULL.
	 */
	if (cookie != 0) {
		start = *((__nis_table_mapping_t **)cookie);
		if (start == 0)
			start = ldapMappingSeq;
	} else {
		start = ldapMappingSeq;
	}

	for (t = start; t != 0; t = (__nis_table_mapping_t *)t->seqNext) {
		__nis_table_mapping_t	**tp;
		int			nm;

		if (fromLDAP) {
			/* Are there any mappings for the object proper ? */
			tp = selectTableMapping(t, 0, 0, 1, t->dbId, &nm);
			if (tp != 0 && nm > 0) {
				dstat = dbCreateFromLDAP(t->objPath, &stat);
				if (dstat != DB_SUCCESS) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: DB error %d creating \"%s\": %s",
						myself, dstat, NIL(t->objName),
						ldap_err2string(stat));
					if (cookie != 0)
						*((__nis_table_mapping_t **)
							cookie) = t;
					if (dstatP != 0)
						*dstatP = dstat;
					else if (stat == LDAP_SUCCESS)
						stat = LDAP_OPERATIONS_ERROR;
					sfree(tp);
					return (stat);
				}
			}
			sfree(tp);

			/* Any mappings for table entries ? */
			tp = selectTableMapping(t, 0, 0, 0, t->dbId, &nm);
			if (tp == 0 || nm <= 0) {
				sfree(tp);
				continue;
			}
			sfree(tp);

			/*
			 * The object itself must exist in the local
			 * DB by now. Get the db_mindex and let
			 * db_mindex::queryLDAP() do the work; if
			 * the object isn't a table, queryLDAP()
			 * will do nothing and return success.
			 */
			dbase = InUseDictionary->find_table(t->objPath,
							&tbl, TRUE);
			if (dbase != 0)
				mindex = dbase->mindex();
			if (dbase == 0 || tbl == 0 || mindex == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: No local DB entry for \"%s\" (%s:%s)",
					myself, NIL(t->objPath),
					NIL(t->dbId), NIL(t->objName));
				if (cookie != 0)
					*((__nis_table_mapping_t **)cookie) =
						t;
				if (dstatP != 0)
					*dstatP = DB_BADTABLE;
				return ((dstatP != 0) ?
					LDAP_SUCCESS : LDAP_OPERATIONS_ERROR);
			}
			mindex->setInitialLoad();
			stat = mindex->queryLDAP(0, t->dbId, 0);
			mindex->clearInitialLoad();
			if (stat != LDAP_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: LDAP error retrieving entries for %s:%s: %s",
					myself, NIL(t->dbId), NIL(t->objName),
					ldap_err2string(stat));
				if (cookie != 0)
					*((__nis_table_mapping_t **)cookie) =
						t;
				if (dstatP != 0)
					*dstatP = DB_SUCCESS;
				return (stat);
			}
		} else {
			nis_object	*obj;
			char		*ent, *objPath;
			int		freeObjPath = 0;

			/*
			 * Up-loading to LDAP, so the object must
			 * already exist in the local DB.
			 */
			obj = dbFindObject(t->objName, &dstat);
			if (obj == 0) {
				if (dstat == DB_NOTFOUND)
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: No local DB object for \"%s\" (%s:%s); skipping up-load",
						myself, NIL(t->objPath),
						NIL(t->dbId),
						NIL(t->objName));
				else
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: DB error %d for \"%s\" (%s:%s); skipping up-load",
						myself, dstat,
						NIL(t->objPath),
						NIL(t->dbId),
						NIL(t->objName));
				continue;
			}

			/*
			 * If it's a table or directory, there will be
			 * a dictionary entry for the object itself.
			 * Otherwise, we need the dictionary entry for
			 * the parent directory.
			 *
			 * For a table, we need the db_mindex for both the
			 * table object itself, as well as for the parent
			 * directory (in order to store table entries).
			 * We start with the latter.
			 */
			if (obj->zo_data.zo_type == NIS_DIRECTORY_OBJ) {
				objPath = t->objPath;
				ent = 0;
			} else {
				objPath = 0;
				ent = entryName(myself, t->objName,
				    &objPath);
				if (ent == 0 || objPath == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: Error deriving entry/DB-table names for %s:%s; skipping up-load",
						myself, NIL(t->dbId),
						NIL(t->objName));
					sfree(ent);
					sfree(objPath);
					nis_destroy_object(obj);
					obj = 0;
					continue;
				}
				freeObjPath = 1;
			}

			dbase = InUseDictionary->find_table(objPath,
							&tbl, TRUE);
			if (dbase != 0)
				mindex = dbase->mindex();
			if (dbase == 0 || tbl == 0 || mindex == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: No local DB entry for \"%s\" (%s:%s); skipping up-load",
					myself, objPath,
					NIL(t->dbId), NIL(t->objName));
				sfree(ent);
				if (freeObjPath)
					sfree(objPath);
				nis_destroy_object(obj);
				obj = 0;
				continue;
			}

			/*
			 * Our next action(s) depend on the object type:
			 *
			 *	directory	Store dir object
			 *
			 *	table		Store table obj, as well
			 *			as any entries in the
			 *			table
			 *
			 *	other		Store object; we need to
			 *			build a db_query specifying
			 *			the first-level name of the
			 *			object.
			 *
			 * storeLDAP() will just do nothing and return
			 * success if we try to, say, store a table object
			 * when only the table entries are mapped. Hence,
			 * we don't have to worry about those distinctions
			 * here.
			 */
			if (obj->zo_data.zo_type == NIS_DIRECTORY_OBJ) {
				stat = mindex->storeLDAP(0, 0, obj, 0, t->dbId);
			} else {
				nis_attr	attr;
				db_query	*q;

				attr.zattr_ndx = (char *)"name";
				attr.zattr_val.zattr_val_val = ent;
				attr.zattr_val.zattr_val_len = slen(ent) + 1;

				q = new db_query(mindex->getScheme(), 1, &attr);
				if (q == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: error creating db_query for \"%s\" in \"%s\"; skipping up-load",
						myself, ent, objPath);
					sfree(ent);
					if (freeObjPath)
						sfree(objPath);
					nis_destroy_object(obj);
					obj = 0;
					continue;
				}

				stat = mindex->storeLDAP(q, 0, obj, 0, t->dbId);

				delete q;

			}

			sfree(ent);
			if (freeObjPath)
				sfree(objPath);

			if (stat != LDAP_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Error storing %s:%s to LDAP: %s",
					myself, NIL(t->dbId), NIL(t->objName),
					ldap_err2string(stat));
				nis_destroy_object(obj);
				obj = 0;
				if (cookie != 0)
					*((__nis_table_mapping_t **)
						cookie) = t;
				if (dstatP != 0)
					*dstatP = DB_SUCCESS;
				return (stat);
			}

			/* Any mappings for table entries ? */
			tp = selectTableMapping(t, 0, 0, 0, t->dbId, &nm);
			if (tp == 0 || nm <= 0) {
				sfree(tp);
				nis_destroy_object(obj);
				obj = 0;
				continue;
			}
			sfree(tp);

			/*
			 * If it's a table, we also need to store the table
			 * entries.
			 */
			if (obj->zo_data.zo_type == NIS_TABLE_OBJ) {
				tbl = 0;
				dbase = InUseDictionary->find_table(t->objPath,
								&tbl, TRUE);
				if (dbase != 0)
				mindex = dbase->mindex();
				if (dbase == 0 || tbl == 0 || mindex == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
	"%s: No local DB entry for \"%s\" (%s:%s); skipping entry up-load",
						myself, NIL(t->objPath),
						NIL(t->dbId), NIL(t->objName));
					nis_destroy_object(obj);
					obj = 0;
					continue;
				}

				stat = mindex->storeLDAP(0, 0, obj, 0, t->dbId);

				if (stat != LDAP_SUCCESS) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error storing %s:%s entries to LDAP: %s",
						myself, NIL(t->dbId),
						NIL(t->objName),
						ldap_err2string(stat));
					nis_destroy_object(obj);
					obj = 0;
					if (cookie != 0)
						*((__nis_table_mapping_t **)
							cookie) = t;
					if (dstatP != 0)
						*dstatP = DB_SUCCESS;
					return (stat);
				}
			}
			nis_destroy_object(obj);
			obj = 0;
		}
	}

	if (dstatP != 0)
		*dstatP = dstat;
	return (stat);
}

/*
 * Object identified by given attribute name is added to specified table.
 * If object already exists, it is replaced.  If more than one object
 * matches the given attribute name, DB_NOTUNIQUE is returned.
 */
static
db_result *
db_add_entry_x(char * tab, int numattrs, nis_attr * attrname,
		entry_obj * newobj, int skiplog, int nosync)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db_table_desc * tbl = NULL;
	db * dbase = InUseDictionary->find_table(tab, &tbl, FALSE);

	if (tbl == NULL || dbase == NULL) {
		return (set_result(safety, DB_BADTABLE));
	} else if (skiplog) {
		db_result * res;
		res = dbase->execute(DB_ADD_NOLOG, NULL,
			    (entry_object *) newobj, NULL);
		if (safety) delete safety;
		return (res);
	} else {
		db_result *res;
		db_query *
		query = InUseDictionary->translate_to_query(tbl,
						numattrs, attrname);
		if (query == NULL)
			return (set_result(safety, DB_BADQUERY));
		if (nosync)
			res = dbase->execute(DB_ADD_NOSYNC,
				query, (entry_object *) newobj, NULL);
		else
			res = dbase->execute(DB_ADD, query,
				(entry_object *) newobj, NULL);
		delete query;
		if (safety) delete safety;
		return (res);
	}
}

db_result *
db_add_entry(char * tab, int numattrs, nis_attr * attrname,
		entry_obj * newobj)
{
	return (db_add_entry_x(tab, numattrs, attrname, newobj, 0, 0));
}

db_result *
__db_add_entry_nolog(char * tab, int numattrs, nis_attr * attrname,
		entry_obj * newobj)
{
	return (db_add_entry_x(tab, numattrs, attrname, newobj, 1, 0));
}

db_result *
__db_add_entry_nosync(char * tab, int numattrs, nis_attr * attrname,
			entry_obj * newobj)
{
	return (db_add_entry_x(tab, numattrs, attrname, newobj, 0, 1));
}

/*
 * Remove object identified by given attributes from specified table.
 * If no attribute is supplied, all entries in table are removed.
 * If attributes identify more than one object, all objects are removed.
*/

db_result *
db_remove_entry_x(char * table_name, int num_attrs, nis_attr * attrname,
			int nosync)
{
	db_result * safety = empty_result(DB_SUCCESS);
	db_table_desc * tbl = NULL;
	db * dbase = InUseDictionary->find_table(table_name, &tbl, FALSE);
	db_result * res;

	if (tbl == NULL || dbase == NULL)
		return (set_result(safety, DB_BADTABLE));
	else {
		if (num_attrs != 0) {
			db_query *query;
			query = InUseDictionary->translate_to_query(tbl,
					num_attrs, attrname);
			if (query == NULL)
				return (set_result(safety,
						DB_BADQUERY));
			if (nosync)
				res = dbase->execute(DB_REMOVE_NOSYNC,
						query, NULL, NULL);
			else
				res = dbase->execute(DB_REMOVE, query,
						NULL, NULL);
			delete query;
		} else {
			if (nosync)
				res = dbase->execute(DB_REMOVE_NOSYNC,
					NULL, NULL, NULL);
			else
				res = dbase->execute(DB_REMOVE,
					NULL, NULL, NULL);
		}
		if (safety) delete safety;
		return (res);
	}
}

db_result *
db_remove_entry(char * table_name, int num_attrs, nis_attr * attrname)
{
	return (db_remove_entry_x(table_name, num_attrs, attrname, 0));
}

db_result *
__db_remove_entry_nosync(char * table_name, int num_attrs, nis_attr * attrname)
{
	return (db_remove_entry_x(table_name, num_attrs, attrname, 1));
}

/* Return a copy of the version of specified table. */
vers *
db_version(char * table_name)
{
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase == NULL)
		return (NULL);
	vers* v = new vers(dbase->get_version());
	if (v == NULL)
		WARNING("nis_db::db_version: cannot allocate space");
	return (v);
}

/* Return log entries since (later than) given version 'v' of table. */
db_log_list *
db_log_entries_since(char * table_name, vers * v)
{
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase == NULL)
		return (NULL);
	return (dbase->get_log_entries_since(v));
}

db_status
db_sync_log(char *table_name) {

	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase == NULL)
		return (DB_BADTABLE);
	return (dbase->sync_log());
}

/*
 * Apply the given update specified in 'entry' to the specified table.
 * Returns DB_SUCCESS if update was executed.
 * Returns DB_NOTFOUND if update occurs too early to be applied.
*/
db_status
db_apply_log_entry(char * table_name, db_log_entry * entry)
{
	db * dbase = InUseDictionary->find_table(table_name, NULL, FALSE);

	if (dbase == NULL)
		return (DB_BADTABLE);
	if (dbase->execute_log_entry(entry))
		return (DB_SUCCESS);   /* got executed */
	else
		return (DB_NOTFOUND);  /* not executed */
}

/*
 * Checkpoint specified table (i.e. incorporate logged updates to main
 * database file).  If table_name is NULL, checkpoint all tables that
 * needs it.
*/
db_status
db_checkpoint(char * table_name)
{
	return (InUseDictionary->db_checkpoint(table_name));
}

/* Print names of tables in system. */
void
db_print_table_names()
{
	int i;
	db_table_names * answer = InUseDictionary->get_table_names();

	if (answer != NULL) {
		for (i = 0; i < answer->db_table_names_len; i++) {
			printf("%s\n", answer->db_table_names_val[i]);
			delete answer->db_table_names_val[i];
		}
		delete answer->db_table_names_val;
		delete answer;
	}
}

/* Print statistics of specified table to stdout. */
db_status
db_stats(char * table_name)
{
	db_table_desc * tbl = NULL;
	db *dbase = InUseDictionary->find_table(table_name, &tbl);

	if (tbl == NULL || dbase == NULL || tbl->scheme == NULL)
		return (DB_BADTABLE);

	dbase->print();
	tbl->scheme->print();
	return (DB_SUCCESS);
}


/* Print statistics of indices of specified table to stdout. */
db_status
db_print_all_indices(char * table_name)
{
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase == NULL)
		return (DB_BADTABLE);
	dbase->print_all_indices();
	return (DB_SUCCESS);
}

/* Print specified index of table to stdout. */
db_status
db_print_index(char * table_name, int which)
{
	db * dbase = InUseDictionary->find_table(table_name);

	if (dbase == NULL)
		return (DB_BADTABLE);
	dbase->print_index(which);
	return (DB_SUCCESS);
}

/* close open files */
db_status
db_standby(char * table_name)
{
	return (InUseDictionary->db_standby(table_name));
}

/* Returns DB_SUCCESS if table exists; DB_BADTABLE if table does not exist. */
db_status
db_table_exists(char * table_name)
{
	db_table_desc *dbtab = InUseDictionary->find_table_desc(table_name);

	if (dbtab == NULL)
		return (DB_BADTABLE);
	return (DB_SUCCESS);
}

/*
 * Returns DB_SUCCESS if table exists; DB_BADTABLE if table does not exist.
 *  If table already loaded, unload it.
*/
db_status
db_unload_table(char * table_name)
{
	db_table_desc *
	dbtab = InUseDictionary->find_table_desc(table_name);
	if (dbtab == NULL)
		return (DB_BADTABLE);
	// unload
	if (dbtab->database != NULL) {
		delete dbtab->database;
		dbtab->database = NULL;
	}
	return (DB_SUCCESS);
}

/*
 * Put the specified table in deferred mode, which means that updates go
 * to the original table, but reads are satisfied out of a copy (which we
 * make here). Thus, "defer" refers to the table as seen by read requests,
 * since for them, changes are deferred.
 */
db_status
__db_defer(char *table_name) {
	db_status	stat;

	stat = InUseDictionary->defer(table_name);
	return (stat);
}

/*
 * Commit deferred changes for the specified table. I.e., make visible
 * any updates made since the table was deferred.
 */
db_status
__db_commit(char *table_name) {
	db_status	stat;

	stat = InUseDictionary->commit(table_name);
	return (stat);
}

/*
 * Rollback, i.e., return to the state before we entered deferred mode.
 */
db_status
__db_rollback(char *table_name) {
	db_status	stat;

	stat = InUseDictionary->rollback(table_name);
	return (stat);
}

db_status
__db_configure(char *table_name) {
	db_status	stat;
	char		tablePath[MAXPATHLEN + NIS_MAXNAMELEN + 1];
	db		*dbase = InUseDictionary->find_table(table_name, NULL);

	if (dbase == NULL || table_name == 0)
		return (DB_BADTABLE);

	if (strlen(table_name) >= sizeof (tablePath))
		return (DB_BADQUERY);

	if (internal_table_name(table_name, tablePath) == 0)
		return (DB_STORAGE_LIMIT);

	if (dbase->configure(tablePath))
		stat = DB_SUCCESS;
	else
		stat = DB_INTERNAL_ERROR;

	return (stat);
}

/*
 * During some rpc.nisd operations (such as when recovering the trans.log),
 * we don't want to use the LDAP repository, so we provide a main switch.
 * Note that we expect this to be used only when rpc.nisd is single-threaded,
 * so there is no need for synchronization when reading or modifying the
 * value of the main switch.
 */
int	useLDAPrespository = 1;

void
__db_disallowLDAP(void) {
	useLDAPrespository = 0;
}

void
__db_allowLDAP(void) {
	useLDAPrespository = 1;
}

}  /* extern "C" */
