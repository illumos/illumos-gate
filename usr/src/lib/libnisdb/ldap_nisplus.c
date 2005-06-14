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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <lber.h>
#include <ldap.h>
#include <strings.h>

#include "ldap_nisplus.h"
#include "ldap_util.h"
#include "ldap_val.h"
#include "ldap_attr.h"
#include "ldap_glob.h"


static void
freeColNames(char **name, int numCols) {
	int	i;

	if (name == 0)
		return;

	for (i = 0; i < numCols; i++) {
		sfree(name[i]);
	}
	sfree(name);
}

/*
 * Convert the object attributes (zo_owner, etc.) fields of 'o' to
 * the corresponding char **'s and __nis_value_t's. The 'name' and
 * 'val' arrays are each assumed to have (at least) 'numVals' elements,
 * and 'numVals' must be at least five.
 *
 * Returns zero if successful, non-zero otherwise. Whether successful
 * or not, the caller must clean up 'name' and 'val', which may be
 * partially allocated even after a failure.
 */
static int
objAttr2Value(nis_object *o, char **name, __nis_value_t *val, int numVals) {
	int	i, err;
	char	*myself = "objAttr2Value";

	if (o == 0 || name == 0 || val == 0 || numVals < 5)
		return (-1);

	name[0] = sdup(myself, T, "zo_owner");
	name[1] = sdup(myself, T, "zo_group");
	name[2] = sdup(myself, T, "zo_domain");
	name[3] = sdup(myself, T, "zo_access");
	name[4] = sdup(myself, T, "zo_ttl");

	for (err = 0, i = 0; i < 5; i++) {
		if (name[i] == 0)
			err++;
		val[i].val = am(myself, sizeof (val[i].val[0]));
		if (val[i].val == 0)
			err++;
		val[i].type = vt_string;
	}
	if (err > 0) {
		for (i = 0; i < 5; i++) {
			sfree(name[i]);
			name[i] = 0;
			sfree(val[i].val);
			val[i].val = 0;
		}
		return (-2);
	}

	val[0].val[0].value = sdup(myself, T, o->zo_owner);
	val[1].val[0].value = sdup(myself, T, o->zo_group);
	val[2].val[0].value = sdup(myself, T, o->zo_domain);
	val[3].val[0].value = am(myself, 2 * sizeof (o->zo_access) + 1);
	val[4].val[0].value = am(myself, 2 * sizeof (o->zo_ttl) + 1);

	for (err = 0, i = 0; i < 5; i++) {
		if (val[i].val[0].value == 0)
			err++;
		val[i].numVals = 1;
	}
	if (err > 0) {
		for (i = 0; i < 5; i++) {
			sfree(name[i]);
			name[i] = 0;
			sfree(val[i].val[0].value);
			val[i].val[0].value = 0;
			sfree(val[i].val);
			val[i].val = 0;
		}
		return (-3);
	}

	sprintf(val[3].val[0].value, "%x", o->zo_access);
	sprintf(val[4].val[0].value, "%x", o->zo_ttl);

	val[0].val[0].length = slen(o->zo_owner);
	val[1].val[0].length = slen(o->zo_group);
	val[2].val[0].length = slen(o->zo_domain);
	val[3].val[0].length = 2 * sizeof (o->zo_access);
	val[4].val[0].length = 2 * sizeof (o->zo_ttl);

	return (0);
}

/*
 * Convert a __nis_index_t to a string, using the supplied rule-value
 * to evaluate any expressions in the index components.
 *
 * The 'table' is used only to produce a more meaningful error message.
 */
static char *
index2string(char *msg, __nis_index_t *index, __nis_rule_value_t *rvIn,
		char *table) {
	__nis_buffer_t	b = {0, 0};
	int		i, frv = 0;
	char		*myself = "index2string";

	if (index == 0)
		return (0);

	if (rvIn == 0) {
		rvIn = initRuleValue(1, 0);
		if (rvIn == 0)
			return (0);
		frv = 1;
	}

	if (msg == 0)
		msg = myself;

	bp2buf(msg, &b, "[");
	for (i = 0; i < index->numIndexes; i++) {
		char	*fmt;
		__nis_value_t	*tmpval;

		if (slen(index->name[i]) <= 0 ||
				index->value[i] == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: index spec error for component \"%s\"%s",
				msg, NIL(index->name[i]),
					(index->value[i] == 0) ?
						", <nil> value" : "");
			sfree(b.buf);
			if (frv)
				freeRuleValue(rvIn, 1);
			return (0);
		}

		/* Derive a value for this index */
		tmpval = getMappingFormatArray(index->value[i], rvIn,
						fa_item, 0, 0);
		if (tmpval == 0 || tmpval->numVals <= 0) {
			char	*ival;

			freeValue(tmpval, 1);
			tmpval = getMappingFormatArray(index->value[i],
					0, fa_item, 0, 0);
			if (tmpval == 0)
				ival = "<unknown>";
			else if (tmpval->type != vt_string)
				ival = "<non-string>";
			else if (tmpval->numVals != 1)
				ival = "<# val error>";
			else
				ival = tmpval->val[0].value;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: No value for index \"%s = %s\" (table = \"%s\")",
				msg, index->name[i], ival,
				NIL(table));
			freeValue(tmpval, 1);
			sfree(b.buf);
			if (frv)
				freeRuleValue(rvIn, 1);
			return (0);
		}

		/*
		 * There should only be one value, so we ignore
		 * any excess values.
		 */
		if (tmpval->type == vt_string) {
			if (i == 0)
				fmt = "%s=%s";
			else
				fmt = ",%s=%s";
			bp2buf(msg, &b, fmt,
				index->name[i], tmpval->val[0].value);
		} else {
			bc2buf(msg, tmpval->val[0].value,
				tmpval->val[0].length, &b);
		}
		freeValue(tmpval, 1);
	}
	bp2buf(msg, &b, "]");

	if (frv)
		freeRuleValue(rvIn, 1);

	return (b.buf);
}

/*
 * Return the rule-value representation of the the entry (or entries)
 * specified by 'index' and 'table'.
 *
 * If 'index' is non-NULL, we evaluate the index->value format using
 * the supplied 'rvIn'; should 'index' be NULL, 'rvIn' is unused. In either
 * case, 'rvIn' isn't modified.
 */
__nis_rule_value_t *
getNisPlusEntry(__nis_index_t *index, char *table, __nis_rule_value_t *rvIn,
		int *numVals) {
	__nis_buffer_t		b = {0, 0};
	__nis_rule_value_t	*rv;
	char			*myself = "getNisPlusEntry";

	if (table == 0)
		return (0);

	if (index != 0 && index->numIndexes > 0) {
		b.buf = index2string(myself, index, rvIn, table);
		b.len = slen(b.buf);

		bp2buf(myself, &b, "%s", table, 0);

		rv = getNisPlusEntrySimple(b.buf, numVals);

		sfree(b.buf);
	} else {
		/* Special case: want the zo_* attributes for the 'table' */
		nis_result	*res = 0;
		int		stat;

		stat = getNisPlusObj(table, 0, &res);
		if (stat != LDAP_SUCCESS)
			return (0);

		rv = initRuleValue(1, 0);
		if (rv == 0) {
			nis_freeresult(res);
			return (0);
		}

		/* Allocate space for the object attributes */
		rv->colName = am(myself, 5 * sizeof (rv->colName[0]));
		rv->colVal = am(myself, 5 * sizeof (rv->colVal[0]));
		if (rv->colName == 0 || rv->colVal == 0) {
			freeRuleValue(rv, 1);
			nis_freeresult(res);
			return (0);
		}

		if (objAttr2Value(NIS_RES_OBJECT(res), rv->colName,
				rv->colVal, 5) == 0) {
			rv->numColumns = 5;
			if (numVals != 0)
				*numVals = 1;
		} else {
			freeRuleValue(rv, 1);
			rv = 0;
		}

		nis_freeresult(res);
	}

	return (rv);
}

/*
 * Simple NIS+ entry lookup routine, which accepts an indexed name, and
 * returns the corresponding rule-value array, and number of elements in
 * said array.
 */
__nis_rule_value_t *
getNisPlusEntrySimple(char *name, int *numVals) {
	char			*table;
	__nis_rule_value_t	*rv;
	nis_result		*res;
	int			i, nobj, nv, nc = 0;
	nis_object		*o;
	char			**col = 0;
	zotypes			ttype;
	char			*myself = "getNisPlusEntrySimple";

	if (name == 0)
		return (0);

	/* Find the table name proper */
	table = strrchr(name, ']');
	if (table != 0) {
		/* Point to the start of the table name */
		table++;
	} else {
		/*
		 * Presumably no indices; this implies enumeration, and
		 * that's not the intended use of this function, so return
		 * failure.
		 */
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s: un-indexed name \"%s\" used for table entry lookup",
			myself, name);
		return (0);
	}

	if (LDAP_SUCCESS != initializeColumnNames(table, &col, &nc, &ttype,
			0)) {
		freeColNames(col, nc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: unable to get column names for \"%s\"",
			myself, table);
		return (0);
	}

	if (ttype != NIS_TABLE_OBJ) {
		freeColNames(col, nc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: \"%s\" is object type %d, not a table",
			myself, table, ttype);
		return (0);
	}

	if (col == 0 || nc <= 0) {
		/* col!=0 and nc==0 is possible, so free the column array */
		freeColNames(col, nc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: %s for \"%s\"",
			myself, (col == 0) ? "<nil> column name array" :
					"no column name elements",
			table);
		return (0);
	}

	res = nis_list(name, 0, 0, 0);
	if (res == 0) {
		freeColNames(col, nc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: NIS+ lookup error (no result) for \"%s\"",
			myself, name);
		return (0);
	}
	if (res->status == NIS_NOTFOUND) {
		/*
		 * Not really an error from the POV of this function; we
		 * have no way of knowing if the entry should exist or not.
		 */
		freeColNames(col, nc);
		nis_freeresult(res);
		return (0);
	} else if (res->status != NIS_SUCCESS && res->status != NIS_S_SUCCESS) {
		freeColNames(col, nc);
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: NIS+ lookup error (%d) for \"%s\"",
			myself, res->status, name);
		nis_freeresult(res);
		return (0);
	}

	nobj = res->objects.objects_len;

	/* One rule-value element for each entry object */
	rv = initRuleValue(nobj, 0);
	if (rv == 0) {
		freeColNames(col, nc);
		nis_freeresult(res);
		return (0);
	}

	for (i = 0, nv = 0; i < nobj; i++) {
		unsigned int		nec;
		entry_col		*ec;
		int			j;

		o = &res->objects.objects_val[i];
		if (o->zo_data.zo_type != NIS_ENTRY_OBJ)
			continue;

		nec = o->zo_data.objdata_u.en_data.en_cols.en_cols_len;
		if (nec == 0)
			continue;

		if (nec != nc)
			continue;

		/*
		 * 'nec+5' to account for the object attributes
		 * (zo_owner. etc), of which there are five.
		 */
		rv[nv].colName = am(myself,
				(nec+5) * sizeof (rv[nv].colName[0]));
		rv[nv].colVal = am(myself,
				(nec+5) * sizeof (rv[nv].colVal[0]));
		if (rv[nv].colName == 0 || rv[nv].colVal == 0) {
			freeRuleValue(rv, nv+1);
			freeColNames(col, nc);
			nis_freeresult(res);
			return (0);
		}
		rv[nv].numColumns = nec + 5;

		ec = o->zo_data.objdata_u.en_data.en_cols.en_cols_val;

		for (j = 0; j < nec; j++) {
			int	len;

			rv[nv].colName[j] = sdup(myself, T, col[j]);
			if (rv[nv].colName[j] == 0) {
				freeRuleValue(rv, nv+1);
				freeColNames(col, nc);
				nis_freeresult(res);
				return (0);
			}

			/* What's the type of column value ? */
			if ((ec[j].ec_flags & TA_BINARY) != 0 ||
					(ec[j].ec_flags & TA_XDR) != 0 ||
					(ec[j].ec_flags & TA_ASN1) != 0)
				rv[nv].colVal[j].type = vt_ber;
			else
				rv[nv].colVal[j].type = vt_string;

			rv[nv].colVal[j].val = am(myself,
					sizeof (rv[nv].colVal[j].val[0]));
			if (rv[nv].colVal[j].val == 0) {
				freeRuleValue(rv, nv+1);
				freeColNames(col, nc);
				nis_freeresult(res);
				return (0);
			}
			rv[nv].colVal[j].numVals = 1;

			len = ec[j].ec_value.ec_value_len;
			if (len > 0 &&
				ec[j].ec_value.ec_value_val[len-1] == '\0') {
				/* Don't count NUL in the value length */
				len -= 1;
			}

			/*
			 * Always allocate memory so that there's a NUL at
			 * the end.
			 */
			rv[nv].colVal[j].val[0].value = am(myself, len+1);
			rv[nv].colVal[j].val[0].length = len;

			if (rv[nv].colVal[j].val[0].value == 0) {
				freeRuleValue(rv, nv+1);
				freeColNames(col, nc);
				nis_freeresult(res);
				return (0);
			}

			(void) memcpy(rv[nv].colVal[j].val[0].value,
				ec[j].ec_value.ec_value_val, len);
		}

		/* Now the object attributes */
		if (objAttr2Value(o, &rv[nv].colName[nec], &rv[nv].colVal[nec],
				5) != 0) {
			freeRuleValue(rv, nv+1);
			freeColNames(col, nc);
			nis_freeresult(res);
			return (0);
		}

		nv++;
	}

	freeColNames(col, nc);
	nis_freeresult(res);

	if (numVals != 0)
		*numVals = nv;

	return (rv);
}

/*
 * Retrieve a copy of the specified NIS+ object. Upon successful return,
 * the return value is LDAP_SUCCESS, *outRes contains the nis_result
 * pointer, and there's at least one object in the result.
 *
 * On error, return a status other than LDAP_SUCCESS.
 */
int
getNisPlusObj(char *name, char *msg, nis_result **outRes) {
	nis_result	*res;
	char		*objName;
	char		*myself = "getNisPlusObj";

	objName = fullObjName(F, name);
	if (objName == 0) {
		return ((name == 0) ? LDAP_PARAM_ERROR : LDAP_NO_MEMORY);
	}

	if (msg == 0)
		msg = myself;

	res = nis_lookup(objName, 0);

	if (res == 0) {
		sfree(objName);
		return (LDAP_NO_MEMORY);
	}

	if (res->status != NIS_SUCCESS && res->status != NIS_S_SUCCESS) {
		int	msgtype = MSG_NOTIMECHECK;

		if (res->status == NIS_COLDSTART_ERR)
			msgtype = MSG_NONPCOLDSTART;

		logmsg(msgtype, LOG_ERR,
			"%s: nis_lookup(\"%s\", 0) => %d (%s)",
			msg, objName, res->status, nis_sperrno(res->status));
		sfree(objName);
		nis_freeresult(res);
		return (LDAP_OPERATIONS_ERROR);
	}

	if (res->objects.objects_len <= 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: nis_lookup(\"%s\", 0) => no objects",
			msg, objName);
		sfree(objName);
		nis_freeresult(res);
		return (LDAP_OPERATIONS_ERROR);
	}

	if (res->objects.objects_len > 1) {
		if (verbose)
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Ignoring excess objects (%d) for \"%s\"",
				msg, res->objects.objects_len - 1, objName);
	}

	sfree(objName);

	if (outRes != 0) {
		*outRes = res;
	} else {
		nis_freeresult(res);
		return (LDAP_PARAM_ERROR);
	}

	return (LDAP_SUCCESS);
}

__nis_value_t *
lookupNisPlus(__nis_obj_spec_t *obj, char *col, __nis_rule_value_t *rvIn) {
	char			*objname;
	__nis_rule_value_t	*rv;
	int			i, nv;
	__nis_value_t		*val;
	char			*myself = "lookupNisPlus";

	if (obj == 0 || col == 0)
		return (0);

	objname = fullObjName(F, obj->name);
	if (objname == 0)
		return (0);

	rv = getNisPlusEntry(&obj->index, objname, rvIn, &nv);
	sfree(objname);
	if (rv == 0)
		return (0);

	val = am(myself, sizeof (*val));
	if (val == 0) {
		freeRuleValue(rv, nv);
		return (0);
	}

	for (i = 0, val->numVals = 0; i < nv; i++) {
		int		j;
		__nis_value_t	*oldval;

		for (j = 0; j < rv[i].numColumns; j++) {
			if (strcmp(col, rv[i].colName[j]) == 0)
				break;
		}
		if (j >= rv[i].numColumns)
			continue;

		oldval = val;
		val = concatenateValues(val, &rv[i].colVal[j]);
		freeValue(oldval, 1);
		if (val == 0) {
			freeRuleValue(rv, nv);
			return (0);
		}
	}

	freeRuleValue(rv, nv);

	if (val->numVals == 0) {
		freeValue(val, 1);
		val = 0;
	}

	return (val);
}

/*
 * Store the specified NIS+ colname/value in the indicated entry.
 * The 'table' is used if the 'item->searchSpec.obj.name' is
 * unspecified. If the 'item' doesn't contain an index spec (and
 * hence indication of the exact NIS+ entry to update), an index
 * spec is constructed from 'rv'.
 */
nis_error
storeNisPlus(__nis_mapping_item_t *item, int index, int numItems,
		__nis_rule_value_t *rv, char *table, __nis_value_t *val) {
	__nis_buffer_t	b = {0, 0};
	nis_result	*res, *mres;
	char		**col = 0;
	int		i, err, nc = 0, ic;
	zotypes		ttype;
	nis_object	*o;
	entry_obj	*e;
	uint_t		orgEcFlg;
	uint_t		orgEcLen;
	char		*orgEcVal;
	char		*myself = "storeNisPlus";

	if (item == 0 || val == 0 || val->numVals != 1 || index < 0 ||
			index >= numItems ||
			item->type != mit_nisplus || item->name == 0 ||
			item->searchSpec.obj.name == 0)
		return (NIS_BADREQUEST);

	/* Check that the table has column with the desired name */
	if (slen(item->searchSpec.obj.name) > 0)
		table = item->searchSpec.obj.name;
	table = fullObjName(F, table);
	if (slen(table) <= 0)
		return (NIS_NOMEMORY);
	if (LDAP_SUCCESS != initializeColumnNames(table, &col, &nc, &ttype,
			0) || ttype != NIS_TABLE_OBJ) {
		freeColNames(col, nc);
		sfree(table);
		return (NIS_NOSUCHTABLE);
	}

	for (ic = 0; ic < nc; ic++) {
		if (strcmp(item->name, col[ic]) == 0)
			break;
	}
	freeColNames(col, nc);
	if (ic >= nc) {
		sfree(table);
		return (NIS_BADATTRIBUTE);
	}

	/* Construct the index entry object name */
	if (item->searchSpec.obj.index.numIndexes > 0) {
		b.buf = index2string(myself, &item->searchSpec.obj.index, 0,
					table);
		b.len = slen(b.buf);
		if (b.buf == 0 || b.len <= 0) {
			sfree(b.buf);
			sfree(table);
			return (NIS_NOMEMORY);
		}
	} else if (rv != 0 && rv->numColumns > 0) {
		/* Construct index value from rule-value */
		bp2buf(myself, &b, "[");
		for (i = 0; i < rv->numColumns; i++) {
			if (slen(rv->colName[i]) <= 0 ||
					rv->colVal[i].type != vt_string ||
					rv->colVal[i].numVals != 1 ||
					slen(rv->colVal[i].val[0].value) <= 0)
				continue;
			if (i == 0)
				bp2buf(myself, &b, "%s=%s", rv->colName[i],
					rv->colVal[i].val[0].value);
			else
				bp2buf(myself, &b, ",s=%s", rv->colName[i],
					rv->colVal[i].val[0].value);
		}
		bp2buf(myself, &b, "]");
	} else {
		/* Can't identify entry to modify */
		sfree(table);
		return (NIS_NOTFOUND);
	}
	if (strcmp("[]", b.buf) == 0) {
		sfree(b.buf);
		sfree(table);
		return (NIS_NOTFOUND);
	}
	bp2buf(myself, &b, "%s", table);
	sfree(table);

	/* Look it up */
	res = nis_list(b.buf, 0, 0, 0);
	if (res == 0) {
		sfree(b.buf);
		return (NIS_NOMEMORY);	/* Likely guess */
	} else if (res->status != NIS_SUCCESS &&
			res->status != NIS_S_SUCCESS) {
		err = res->status;
		sfree(b.buf);
		nis_freeresult(res);
		return (err);
	}

	/* We only want one object, and it must be an entry */
	if (res->objects.objects_len != 1 ||
			(o = res->objects.objects_val) == 0 ||
			o->zo_data.zo_type != NIS_ENTRY_OBJ) {
		sfree(b.buf);
		nis_freeresult(res);
		return (NIS_BADOBJECT);
	}

	/* Verify that the column index 'ic' is in range */
	e = &o->zo_data.objdata_u.en_data;
	if (ic >= e->en_cols.en_cols_len) {
		sfree(b.buf);
		nis_freeresult(res);
		return (NIS_TYPEMISMATCH);
	}

	/*
	 * Replace the indicated column value, and set the EN_MODIFIED flag.
	 * We keep track of the original value, so that we can restore it
	 * before destroying 'res'.
	 */
	orgEcFlg = e->en_cols.en_cols_val[ic].ec_flags;
	orgEcLen = e->en_cols.en_cols_val[ic].ec_value.ec_value_len;
	orgEcVal = e->en_cols.en_cols_val[ic].ec_value.ec_value_val;
	/*
	 * We always make sure that the val->val[].value's have a NUL
	 * at the end. However, the 'length' usually doesn't include
	 * the NUL. Since NIS+ wants the NUL counted, we increase the
	 * length by one if:
	 *	(a) the val->type is vt_string, and
	 *	(b) val->val[].value[val->val[].length-1] isn't already
	 *	    NUL, and
	 *	(c) val->val[].value[val->val[].length] is NUL.
	 */
	if (val->type == vt_string && val->val[0].length > 0 &&
		((char *)val->val[0].value)[val->val[0].length-1] != '\0' &&
		((char *)val->val[0].value)[val->val[0].length] == '\0')
		val->val[0].length++;
	e->en_cols.en_cols_val[ic].ec_flags |= EN_MODIFIED;
	e->en_cols.en_cols_val[ic].ec_value.ec_value_len = val->val[0].length;
	e->en_cols.en_cols_val[ic].ec_value.ec_value_val = val->val[0].value;

	mres = nis_modify_entry(b.buf, o, MOD_SAMEOBJ);

	/* Restore 'res', and destroy it */
	e->en_cols.en_cols_val[ic].ec_flags = orgEcFlg;
	e->en_cols.en_cols_val[ic].ec_value.ec_value_len = orgEcLen;
	e->en_cols.en_cols_val[ic].ec_value.ec_value_val = orgEcVal;
	nis_freeresult(res);

	/* Don't need the indexed name anymore */
	sfree(b.buf);

	/* Set the return status, and destroy the modification result */
	if (mres != 0) {
		err = mres->status;
		nis_freeresult(mres);
	} else {
		err = NIS_NOMEMORY;
	}

	return (err);
}

int
copyColumnNames(nis_object *o, char ***column, int *numColumns) {
	int		i, nc, stat;
	char		**name;
	char		*myself = "copyColumnNames";

	if (o == 0 || column == 0 || numColumns == 0)
		return (LDAP_PARAM_ERROR);

	if (*column == 0 && *numColumns < 0) {
		/*
		 * This table mapping is used to map the table object
		 * itself. Since that's indicated by t->column == 0 and
		 * t->numColumns == -1, we definitely don't want to set
		 * the column names.
		 */
		return (LDAP_SUCCESS);
	}

	freeColNames(*column, *numColumns);
	*column = 0;
	*numColumns = 0;

	if (o->zo_data.zo_type != NIS_TABLE_OBJ) {
		/*
		 * Since we can map non-table objects, this isn't really
		 * an error, but we return a special value to tell our
		 * caller that this isn't a table (as opposed to a table
		 * with zero columns).
		 */
		return (LDAP_OBJECT_CLASS_VIOLATION);
	}

	nc = o->zo_data.objdata_u.ta_data.ta_cols.ta_cols_len;
	if (nc < 0) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: negative column count (%d) for \"%s.%s\"",
			myself, nc, NIL(o->zo_name), NIL(o->zo_domain));
		return (LDAP_DECODING_ERROR);
	}

	if (nc == 0 || o->zo_data.objdata_u.ta_data.ta_cols.ta_cols_val == 0) {
		return (LDAP_SUCCESS);
	}

	name = am(myself, nc * sizeof (name[0]));
	if (name == 0) {
		return (LDAP_NO_MEMORY);
	}

	for (i = 0; i < nc; i++) {
		if (o->zo_data.objdata_u.ta_data.ta_cols.
				ta_cols_val[i].tc_name == 0)
			continue;
		name[i] = sdup(myself, T, o->zo_data.objdata_u.ta_data.ta_cols.
						ta_cols_val[i].tc_name);
		if (name[i] == 0) {
			for (--i; i >= 0; i--)
				sfree(name[i]);
			free(name);
			return (LDAP_NO_MEMORY);
		}
	}

	*column = name;
	*numColumns = nc;

	return (LDAP_SUCCESS);
}

/*
 * Initialize the column name list for the specified table name
 * (which must be fully qualified).
 *
 * Returns an LDAP error status
 */
int
initializeColumnNames(char *table, char ***column, int *numColumns,
			zotypes *type, nis_object **obj) {
	nis_result	*res = 0;
	int		stat;
	char		*myself = "initializeColumnNames";

	if (table == 0 || column == 0 || numColumns == 0 || type == 0)
		return (LDAP_PARAM_ERROR);

	stat = getNisPlusObj(table, myself, &res);
	if (stat != LDAP_SUCCESS)
		return (stat);

	*type = res->objects.objects_val->zo_data.zo_type;
	*column = 0;
	*numColumns = 0;

	stat = copyColumnNames(res->objects.objects_val, column, numColumns);

	nis_freeresult(res);

	return (stat);
}

/*
 * Sets the oid (i.e., the creation and modification times) for the
 * specified object. In order to avoid retrieving the old incarnation
 * (if any) from the DB first, we're punting and setting both mtime
 * and ctime to the current time.
 */
void
setOid(nis_object *obj) {
	if (obj != 0) {
		obj->zo_oid.ctime = obj->zo_oid.mtime = time(0);
	}
}
