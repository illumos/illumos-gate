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
 */

#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <rpcsvc/nis.h>
#include <rpc/xdr.h>

#include "ldap_util.h"
#include "ldap_attr.h"
#include "ldap_ruleval.h"
#include "ldap_op.h"
#include "ldap_map.h"
#include "ldap_glob.h"
#include "ldap_xdr.h"
#include "ldap_val.h"

/* From yptol/dit_access_utils.h */
#define	N2LKEY		"rf_key"
#define	N2LIPKEY	"rf_ipkey"

__nis_hash_table_mt	ldapMappingList = NIS_HASH_TABLE_MT_INIT;
extern	int yp2ldap;


int
setColumnNames(__nis_table_mapping_t *t) {
	int	i, j, nic, noc;
	char	**col;
	char	*myself = "setColumnNames";

	if (t == 0)
		return (0);

	col = t->column;
	nic = (col != 0) ? t->numColumns : -1;

	t->objType = NIS_BOGUS_OBJ;
	t->obj = 0;

	/*
	 * If it's a table object, but there are no translation rules,
	 * this mapping is for the table object itself. In that case,
	 * we throw away the column names (if any).
	 */
	if (t->objType == NIS_TABLE_OBJ && t->numRulesFromLDAP == 0 &&
			t->numRulesToLDAP == 0) {
		for (i = 0; i < t->numColumns; i++)
			sfree(t->column[i]);
		sfree(t->column);
		t->column = 0;
		t->numColumns = 0;
		noc = 0;
	}

	/*
	 * Verify that all column names found by the parser
	 * are present in the actual column list.
	 */
	if (verbose) {
		for (i = 0, noc = 0; i < nic; i++) {
			int	found = 0;

			if (col[i] == 0)
				continue;
			/* Skip the 'zo_*' special column names */
			if (isObjAttrString(col[i]))
				continue;
			for (j = 0; j < t->numColumns; j++) {
				if (strcmp(col[i], t->column[j]) == 0) {
					noc++;
					found = 1;
					break;
				}
			}
			if (!found) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: No column \"%s\" in \"%s\"",
					myself, NIL(col[i]), NIL(t->objName));
			}
		}
	}

	/* Remove any setup by the parser */
	for (i = 0; i < nic; i++) {
		sfree(col[i]);
	}
	sfree(col);

	return (0);
}

void
freeSingleObjAttr(__nis_obj_attr_t *attr) {
	if (attr == 0)
		return;

	sfree(attr->zo_owner);
	sfree(attr->zo_group);
	sfree(attr->zo_domain);
	sfree(attr);
}

void
freeObjAttr(__nis_obj_attr_t **attr, int numAttr) {
	int	i;

	if (attr == 0)
		return;

	for (i = 0; i < numAttr; i++) {
		freeSingleObjAttr(attr[i]);
	}

	sfree(attr);
}

__nis_obj_attr_t *
cloneObjAttr(__nis_obj_attr_t *old) {
	__nis_obj_attr_t	*new;
	char			*myself = "cloneObjAttr";

	if (old == 0)
		return (0);

	new = am(myself, sizeof (*new));
	if (new == 0)
		return (0);

	new->zo_owner = sdup(myself, T, old->zo_owner);
	if (new->zo_owner == 0 && old->zo_owner != 0)
		goto cleanup;

	new->zo_group = sdup(myself, T, old->zo_group);
	if (new->zo_group == 0 && old->zo_group != 0)
		goto cleanup;

	new->zo_domain = sdup(myself, T, old->zo_domain);
	if (new->zo_domain == 0 && old->zo_domain != 0)
		goto cleanup;

	new->zo_access = old->zo_access;
	new->zo_ttl = old->zo_ttl;

	return (new);

cleanup:
	freeSingleObjAttr(new);

	return (0);
}


/*
 * Obtain NIS+ entries (in the form of db_query's) from the supplied table
 * mapping and db_query.
 *
 * If 'qin' is NULL, enumeration is desired.
 *
 * On exit, '*numQueries' contains the number of (db_query *)'s in the
 * return array, '*ldapStat' the LDAP operation status, and '*objAttr'
 * a pointer to an array (of '*numQueries elements) of object attributes
 * (zo_owner, etc.). If no object attributes were retrieved, '*objAttr'
 * is NULL; any and all of the (*objAttr)[i]'s may be NULL.
 */
db_query **
mapFromLDAP(__nis_table_mapping_t *t, db_query *qin, int *numQueries,
		char *dbId, int *ldapStat, __nis_obj_attr_t ***objAttr) {
	__nis_table_mapping_t	**tp;
	db_query		**q;
	__nis_rule_value_t	*rv;
	__nis_ldap_search_t	*ls;
	int			n, numVals, numMatches = 0;
	int			stat;
	__nis_obj_attr_t	**attr;
	char			*myself = "mapFromLDAP";

	if (ldapStat == 0)
		ldapStat = &stat;

	if (t == 0 || numQueries == 0) {
		*ldapStat = LDAP_PARAM_ERROR;
		return (0);
	}

	/* Select the correct table mapping(s) */
	tp = selectTableMapping(t, qin, 0, 0, dbId, &numMatches);
	if (tp == 0 || numMatches <= 0) {
		/*
		 * Not really an error; just no matching mapping
		 * for the query.
		 */
		*ldapStat = LDAP_SUCCESS;
		return (0);
	}

	q = 0;
	attr = 0;

	/* For each mapping */
	for (numVals = 0, n = 0; n < numMatches; n++) {
		db_query		**qt;
		int			i, nqt = 0, filterOnQin, res = 0;

		t = tp[n];

		if (qin != 0) {
			rv = buildNisPlusRuleValue(t, qin, 0);
			if (rv != 0) {
				/*
				 * Depending on the value of res, we shall
				 * proceed to next table mapping.
				 */
				ls = createLdapRequest(t, rv, 0, 1, &res, NULL);
			}
			else
				ls = 0;
		} else {
			/* Build enumeration request */
			rv = 0;
			ls = createLdapRequest(t, 0, 0, 1, NULL, NULL);
		}

		freeRuleValue(rv, 1);

		if (ls == 0) {
			/*
			 * if the res is NP_LDAP_RULES_NO_VALUE, that means we
			 * have enough NIS+ columns for the rules to produce
			 * values, but none of them did, so continue to the
			 * next table mapping. Otherwise do cleanup and return
			 * error.
			 */
			if (res == NP_LDAP_RULES_NO_VALUE)
				continue;
			for (i = 0; i < numVals; i++)
				freeQuery(q[i]);
			sfree(q);
			free(tp);
			*ldapStat = LDAP_OPERATIONS_ERROR;
			return (0);
		}

		/* Query LDAP */
		nqt = (ls->isDN || qin != 0) ? 0 : -1;
		rv = ldapSearch(ls, &nqt, 0, ldapStat);

		/*
		 * If qin != 0, then we need to make sure that the
		 * LDAP search is filtered so that only entries that
		 * are compatible with 'qin' are retained. This will
		 * happen automatically if we do a DN search (in which
		 * case, no need to filter on 'qin').
		 */
		if (ls->isDN || qin == 0)
			filterOnQin = 0;
		else
			filterOnQin = 1;

		freeLdapSearch(ls);

		/* Convert rule-values to db_query's */
		if (rv != 0 && nqt > 0) {
			int			nrv = nqt;
			__nis_obj_attr_t	**at = 0;

			qt = ruleValue2Query(t, rv,
				(filterOnQin) ? qin : 0, &at, &nqt);
			freeRuleValue(rv, nrv);

			if (qt != 0 && q == 0) {
				q = qt;
				attr = at;
				numVals = nqt;
			} else if (qt != 0) {
				db_query		**tmp;
				__nis_obj_attr_t	**atmp;

				/* Extend the 'q' array */
				tmp = realloc(q,
					(numVals+nqt) * sizeof (q[0]));
				/* ... and the 'attr' array */
				atmp = realloc(attr,
					(numVals+nqt) * sizeof (attr[0]));
				if (tmp == 0 || atmp == 0) {
					logmsg(MSG_NOMEM, LOG_ERR,
						"%s: realloc(%d) => NULL",
						myself,
						(numVals+nqt) * sizeof (q[0]));
					for (i = 0; i < numVals; i++)
						freeQuery(q[i]);
					for (i = 0; i < nqt; i++)
						freeQuery(qt[i]);
					sfree(tmp);
					sfree(atmp);
					sfree(q);
					sfree(qt);
					sfree(tp);
					freeObjAttr(at, nqt);
					freeObjAttr(attr, numVals);
					*ldapStat = LDAP_NO_MEMORY;
					return (0);
				}
				q = tmp;
				attr = atmp;
				/* Add the results for this 't' */
				(void) memcpy(&q[numVals], qt,
						nqt * sizeof (qt[0]));
				(void) memcpy(&attr[numVals], at,
						nqt * sizeof (at[0]));
				numVals += nqt;

				sfree(qt);
				sfree(at);
			}
		}
	}

	*numQueries = numVals;
	if (objAttr != 0)
		*objAttr = attr;
	else
		freeObjAttr(attr, numVals);
	sfree(tp);

	return (q);
}

/*
 * Add the object attributes (zo_owner, etc.) to the rule-value 'rv'.
 * Returns a pointer to the (possibly newly allocated) rule-value,
 * or NULL in case of failure. If not returning 'rvIn', the latter
 * will have been freed.
 */
__nis_rule_value_t *
addObjAttr2RuleValue(nis_object *obj, __nis_rule_value_t *rvIn) {
	__nis_rule_value_t	*rv;
	char			abuf[2 * sizeof (obj->zo_access) + 1];
	char			tbuf[2 * sizeof (obj->zo_ttl) + 1];

	if (obj == 0)
		return (0);

	if (rvIn != 0) {
		rv = rvIn;
	} else {
		rv = initRuleValue(1, 0);
		if (rv == 0)
			return (0);
	}

	if (obj->zo_owner != 0) {
		if (addSCol2RuleValue("zo_owner", obj->zo_owner, rv) != 0) {
			freeRuleValue(rv, 1);
			return (0);
		}
	}

	if (obj->zo_group != 0) {
		if (addSCol2RuleValue("zo_group", obj->zo_group, rv) != 0) {
			freeRuleValue(rv, 1);
			return (0);
		}
	}

	if (obj->zo_domain != 0) {
		if (addSCol2RuleValue("zo_domain", obj->zo_domain, rv) != 0) {
			freeRuleValue(rv, 1);
			return (0);
		}
	}

	(void) memset(abuf, 0, sizeof (abuf));
	(void) memset(tbuf, 0, sizeof (tbuf));

	sprintf(abuf, "%x", obj->zo_access);
	sprintf(tbuf, "%x", obj->zo_ttl);

	if (addSCol2RuleValue("zo_access", abuf, rv) != 0) {
		freeRuleValue(rv, 1);
		return (0);
	}
	if (addSCol2RuleValue("zo_ttl", tbuf, rv) != 0) {
		freeRuleValue(rv, 1);
		return (0);
	}

	return (rv);
}

/*
 * Returns a pointer to (NOT a copy of) the value for the specified
 * column 'col' in the rule-value 'rv'.
 */
__nis_value_t *
findColValue(char *col, __nis_rule_value_t *rv) {
	int		i;

	if (col == 0 || rv == 0 || rv->numColumns <= 0)
		return (0);

	for (i = 0; i < rv->numColumns; i++) {
		if (strcmp(col, rv->colName[i]) == 0)
			return (&rv->colVal[i]);
	}

	return (0);
}

/*
 * Return the NIS+ object attributes (if any) in the rule-value 'rv'.
 */
__nis_obj_attr_t *
ruleValue2ObjAttr(__nis_rule_value_t *rv) {
	__nis_obj_attr_t	*attr;
	__nis_value_t		*val;
	char			*myself = "ruleValue2ObjAttr";

	if (rv == 0 || rv->numColumns <= 0)
		return (0);

	attr = am(myself, sizeof (*attr));

	if ((val = findColValue("zo_owner", rv)) != 0 &&
			val->type == vt_string && val->numVals == 1 &&
			val->val[0].value != 0) {
		attr->zo_owner = sdup(myself, T, val->val[0].value);
		if (attr->zo_owner == 0) {
			freeSingleObjAttr(attr);
			return (0);
		}
	}

	if ((val = findColValue("zo_group", rv)) != 0 &&
			val->type == vt_string && val->numVals == 1 &&
			val->val[0].value != 0) {
		attr->zo_group = sdup(myself, T, val->val[0].value);
		if (attr->zo_group == 0) {
			freeSingleObjAttr(attr);
			return (0);
		}
	}

	if ((val = findColValue("zo_domain", rv)) != 0 &&
			val->type == vt_string && val->numVals == 1 &&
			val->val[0].value != 0) {
		attr->zo_domain = sdup(myself, T, val->val[0].value);
		if (attr->zo_domain == 0) {
			freeSingleObjAttr(attr);
			return (0);
		}
	}

	if ((val = findColValue("zo_access", rv)) != 0 &&
			val->type == vt_string && val->numVals == 1 &&
			val->val[0].value != 0) {
		if (sscanf(val->val[0].value, "%x", &attr->zo_access) != 1) {
			freeSingleObjAttr(attr);
			return (0);
		}
	}

	if ((val = findColValue("zo_ttl", rv)) != 0 &&
			val->type == vt_string && val->numVals == 1 &&
			val->val[0].value != 0) {
		if (sscanf(val->val[0].value, "%x", &attr->zo_ttl) != 1) {
			freeSingleObjAttr(attr);
			return (0);
		}
	}

	return (attr);
}

/*
 * If the supplied string is one of the object attributes, return one.
 * Otherwise, return zero.
 */
int
isObjAttrString(char *str) {
	if (str == 0)
		return (0);

	if (strcmp("zo_owner", str) == 0 ||
		strcmp("zo_group", str) == 0 ||
		strcmp("zo_domain", str) == 0 ||
		strcmp("zo_access", str) == 0 ||
		strcmp("zo_ttl", str) == 0)
		return (1);
	else
		return (0);
}


/*
 * If the supplied value is one of the object attribute strings, return
 * a pointer to the string. Otherwise, return NULL.
 */
char *
isObjAttr(__nis_single_value_t *val) {
	if (val == 0 || val->length <= 0 || val->value == 0)
		return (0);

	if (isObjAttrString(val->value))
		return (val->value);
	else
		return (0);
}

int
setObjAttrField(char *attrName, __nis_single_value_t *val,
		__nis_obj_attr_t **objAttr) {
	__nis_obj_attr_t	*attr;
	char			*myself = "setObjAttrField";

	if (attrName == 0 || val == 0 || objAttr == 0 ||
			val->value == 0 || val->length <= 0)
		return (-1);

	if (*objAttr != 0) {
		attr = *objAttr;
	} else {
		attr = am(myself, sizeof (*attr));
		if (attr == 0)
			return (-2);
		*objAttr = attr;
	}

	if (strcmp("zo_owner", attrName) == 0) {
		if (attr->zo_owner == 0) {
			attr->zo_owner = sdup(myself, T, val->value);
			if (attr->zo_owner == 0)
				return (-11);
		}
	} else if (strcmp("zo_group", attrName) == 0) {
		if (attr->zo_group == 0) {
			attr->zo_group = sdup(myself, T, val->value);
			if (attr->zo_group == 0)
				return (-12);
		}
	} else if (strcmp("zo_domain", attrName) == 0) {
		if (attr->zo_domain == 0) {
			attr->zo_domain = sdup(myself, T, val->value);
			if (attr->zo_domain == 0)
				return (-13);
		}
	} else if (strcmp("zo_access", attrName) == 0) {
		if (attr->zo_access == 0) {
			if (sscanf(val->value, "%x", &attr->zo_access) != 1)
				return (-14);
		}
	} else if (strcmp("zo_ttl", attrName) == 0) {
		if (attr->zo_ttl == 0) {
			if (sscanf(val->value, "%x", &attr->zo_ttl) != 1)
				return (-15);
		}
	}

	return (0);
}

/*
 * Return a DN and rule-value for the supplied mapping, db_query's, and
 * input rule-value. This function only works on a single mapping. See
 * mapToLDAP() below for a description of the action depending on the
 * values of 'old' and 'new'.
 *
 * If both 'old' and 'new' are supplied, and the modify would result
 * in a change to the DN, '*oldDN' will contain the old DN. Otherwise
 * (and normally), '*oldDN' will be NULL.
 */
char *
map1qToLDAP(__nis_table_mapping_t *t, db_query *old, db_query *new,
		__nis_rule_value_t *rvIn, __nis_rule_value_t **rvOutP,
		char **oldDnP) {

	__nis_rule_value_t	*rv, *rvt;
	__nis_ldap_search_t	*ls;
	char			*dn = 0, *oldDn = 0;
	__nis_table_mapping_t	del;
	char			*myself = "map1qToLDAP";

	if (t == 0 || (old == 0 && new == 0) || rvOutP == 0)
		return (0);

	/*
	 * If entry should be deleted, we look at the delete
	 * policy in the table mapping. Should it specify a
	 * rule set, we use that rule set to build a rule-
	 * value, and the delete actually becomes a modify
	 * operation.
	 */
	if (old != 0 && new == 0) {
		if (t->objectDN->delDisp == dd_perDbId) {
			/*
			 * The functions that build a rule-value from a
			 * rule set expect a __nis_table_mapping_t, but the
			 * rule set in the __nis_object_dn_t isn't of that
			 * form. So, build a pseudo-__nis_table_mapping_t that
			 * borrows heavily from 't'.
			 */
			del = *t;

			del.numRulesToLDAP = del.objectDN->numDbIds;
			del.ruleToLDAP = del.objectDN->dbId;

			/*
			 * Do a modify with the pseudo-table
			 * mapping, and the 'old' db_query
			 * supplying input to the delete rule
			 * set.
			 */
			t = &del;
			new = old;
		} else if (t->objectDN->delDisp == dd_always) {

			/* Nothing to do here; all handled below */

		} else if (t->objectDN->delDisp == dd_never) {

			return (0);

		} else {

			logmsg(MSG_INVALIDDELDISP, LOG_WARNING,
				"%s: Invalid delete disposition %d for \"%s\"",
				myself, t->objectDN->delDisp,
				NIL(t->dbId));
			return (0);

		}
	}

	/* Make a copy of the input rule-value */
	if (rvIn != 0) {
		rv = initRuleValue(1, rvIn);
		if (rv == 0)
			return (0);
	} else {
		rv = 0;
	}

	/* First get a rule-value from the supplied NIS+ entry. */
	rvt = rv;
	rv = buildNisPlusRuleValue(t, ((old != 0) ? old : new), rvt);
	freeRuleValue(rvt, 1);
	if (rv == 0) {
		logmsg(MSG_NORULEVALUE, LOG_WARNING,
			"%s: No in-query rule-value derived for \"%s\"",
			myself, NIL(t->dbId));
		return (0);
	}

	/*
	 * Create a request (really only care about the DN) from the
	 * supplied NIS+ entry data.
	 */
	ls = createLdapRequest(t, rv, &dn, 0, NULL, NULL);
	if (ls == 0 || dn == 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to create LDAP request for %s: %s",
			myself, NIL(t->dbId),
			(dn != 0) ? dn : rvId(rv, mit_nisplus));
		sfree(dn);
		freeLdapSearch(ls);
		freeRuleValue(rv, 1);
		return (0);
	}

	freeLdapSearch(ls);

	if (new != 0) {
		/*
		 * Create a rule-value from the new NIS+ entry.
		 * Don't want to mix in the rule-value derived
		 * from 'old', so delete it. However, we still
		 * want the owner, group, etc., from 'rvIn'.
		 */
		if (old != 0) {
			freeRuleValue(rv, 1);
			if (rvIn != 0) {
				rv = initRuleValue(1, rvIn);
				if (rv == 0) {
					sfree(dn);
					return (0);
				}
			} else {
				rv = 0;
			}
		}
		rvt = rv;
		rv = buildNisPlusRuleValue(t, new, rvt);
		freeRuleValue(rvt, 1);
		if (rv == 0) {
			logmsg(MSG_NORULEVALUE, LOG_WARNING,
				"%s: No new rule-value derived for \"%s: %s\"",
				myself, NIL(t->dbId), dn);
			sfree(dn);
			return (0);
		}
		/*
		 * Check if the proposed modification would result in a
		 * a change to the DN.
		 */
		if (old != 0) {
			oldDn = dn;
			dn = 0;
			ls = createLdapRequest(t, rv, &dn, 0, NULL, NULL);
			if (ls == 0 || dn == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to create new DN for \"%s: %s\"",
					myself, NIL(t->dbId), oldDn);
				sfree(oldDn);
				freeLdapSearch(ls);
				freeRuleValue(rv, 1);
				return (0);
			}
			freeLdapSearch(ls);
			if (strcasecmp(oldDn, dn) == 0) {
				sfree(oldDn);
				oldDn = 0;
			}
		}
	}


	*rvOutP = rv;
	if (oldDnP != 0)
		*oldDnP = oldDn;

	return (dn);
}

/*
 * Since the DN hash list is an automatic variable, there's no need for
 * locking, and we remove the locking overhead by using the libnsl
 * hash functions.
 */
#undef  NIS_HASH_ITEM
#undef  NIS_HASH_TABLE

typedef struct {
	NIS_HASH_ITEM	item;
	int		index;
	char		*oldDn;
} __dn_item_t;

/*
 * Update LDAP per the supplied table mapping and db_query's.
 *
 * 'nq' is the number of elements in the 'old', 'new', and 'rvIn'
 * arrays. mapToLDAP() generally performs one update for each
 * element; however, if one or more of the individual queries
 * produce the same DN, they're merged into a single update.
 *
 * There are four cases, depending on the values of 'old[iq]' and
 * 'new[iq]':
 *
 * (1)	old[iq] == 0 && new[iq] == 0
 *	No action; skip to next query
 *
 * (2)	old[iq] == 0 && new[iq] != 0
 *	Attempt to use the 'new' db_query to get a DN, and try to create
 *	the corresponding LDAP entry.
 *
 * (3)	old[iq] != 0 && new[iq] == 0
 *	Use the 'old' db_query to get a DN, and try to delete the LDAP
 *	entry per the table mapping.
 *
 * (4)	old[iq] != 0 && new[iq] != 0
 *	Use the 'old' db_query to get a DN, and update (possibly create)
 *	the corresponding LDAP entry per the 'new' db_query.
 *
 * If 'rvIn' is non-NULL, it is expected to contain the object attributes
 * (zo_owner, etc.) to be written to LDAP. 'rvIn' is an array with 'nq'
 * elements.
 *
 * If 'firstOnly' is set, only the first old[iq]/new[iq] pair is used
 * to perform the actual update. Any additional queries specified will
 * have their values folded in, but are not used to derive update targets.
 * This mode is inteded to support the case where multiple NIS+ entries
 * map to one and the same LDAP entry. Note that 'rvIn' must still be
 * an array of 'nq' elements, though if 'firstOnly' is set, it should be
 * OK to leave all but 'rvIn[0]' empty.
 *
 * 'dbId' is used to further narow down the selection of mapping candidates
 * to those matching the 'dbId' value.
 */
int
mapToLDAP(__nis_table_mapping_t *tm, int nq, db_query **old, db_query **new,
		__nis_rule_value_t *rvIn, int firstOnly, char *dbId) {
	__nis_table_mapping_t	**tp, **tpa;
	int			i, n, rnq, iq, r, ret = LDAP_SUCCESS;
	int			maxMatches, numMatches = 0;
	__nis_ldap_search_t	*ls;
	char			**dn = 0, **odn = 0;
	__nis_rule_value_t	**rv;
	__dn_item_t		*dni;
	char			*myself = "mapToLDAP";


	if (tm == 0 || (old == 0 && new == 0) || nq <= 0)
		return (LDAP_PARAM_ERROR);

	/* Determine maximum number of table mapping matches */
	if (nq == 1) {
		tp = selectTableMapping(tm,
			(old != 0 && old[0] != 0) ? old[0] : new[0], 1, 0,
				dbId, &maxMatches);
		numMatches = maxMatches;
	} else {
		tp = selectTableMapping(tm, 0, 1, 0, dbId, &maxMatches);
	}

	/*
	 * If no matching mapping, we're not mapping to LDAP in this
	 * particular case.
	 */
	if (tp == 0 || maxMatches == 0) {
		sfree(tp);
		return (LDAP_SUCCESS);
	}

	/*
	 * Allocate the 'rv', 'dn', and 'tpa' arrays. Worst case is that
	 * we need nq * maxMatches elements in each array. However, if
	 * 'firstOnly' is set, we only need one element per matching
	 * mapping in each.
	 */
	dn = am(myself, (firstOnly ? 1 : nq) * maxMatches * sizeof (dn[0]));
	odn = am(myself, (firstOnly ? 1 : nq) * maxMatches * sizeof (odn[0]));
	rv = am(myself, (firstOnly ? 1 : nq) * maxMatches * sizeof (rv[0]));
	tpa = am(myself, (firstOnly ? 1 : nq) * maxMatches * sizeof (tpa[0]));
	if (dn == 0 || odn == 0 || rv == 0 || tpa == 0) {
		sfree(tp);
		sfree(dn);
		sfree(odn);
		sfree(rv);
		sfree(tpa);
		return (LDAP_NO_MEMORY);
	}

	/* Unless nq == 1, we don't need the 'tp' value */
	if (nq != 1)
		sfree(tp);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s: %d * %d potential updates",
		myself, NIL(tm->objName), nq, maxMatches);

	/*
	 * Create DNs, column and attribute values, and merge duplicate DNs.
	 */
	for (iq = 0, rnq = 0; iq < nq; iq++) {
		int	idx;

		if ((old == 0 || old[iq] == 0) &&
				(new == 0 || new[iq] == 0))
			continue;

		/*
		 * Select matching table mappings; if nq == 1, we've already
		 * got the 'tp' array from above. We expect this to be the
		 * most common case, so it's worth special treatment.
		 */
		if (nq != 1)
			tp = selectTableMapping(tm,
			(old != 0 && old[iq] != 0) ? old[iq] : new[iq], 1, 0,
					dbId, &numMatches);
		if (tp == 0)
			continue;
		else if (numMatches <= 0) {
			sfree(tp);
			continue;
		}

		idx = iq * maxMatches;

		if (idx == 0 || !firstOnly)
			(void) memcpy(&tpa[idx], tp,
					numMatches * sizeof (tpa[idx]));

		for (n = 0; n < numMatches; n++) {
			char			*dnt, *odnt;
			__nis_rule_value_t	*rvt = 0;

			if (tp[n] == 0)
				continue;

			dnt = map1qToLDAP(tp[n],
					(old != 0) ? old[iq] : 0,
					(new != 0) ? new[iq] : 0,
					(rvIn != 0) ? &rvIn[iq] : 0,
					&rvt, &odnt);

			if (dnt == 0)
				continue;
			if (rvt == 0) {
#ifdef  NISDB_LDAP_DEBUG
				abort();
#else
				sfree(dnt);
				sfree(odnt);
				continue;
#endif	/* NISDB_LDAP_DEBUG */
			}

			/*
			 * Create a request to get a rule-value with
			 * NIS+ data translated to LDAP equivalents.
			 */
			ls = createLdapRequest(tp[n], rvt, 0, 0, NULL, NULL);
			if (ls == 0) {
				if (ret == LDAP_SUCCESS)
					ret = LDAP_OPERATIONS_ERROR;
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Unable to map to LDAP attrs for %s:dn=%s",
				myself, NIL(tp[n]->dbId), dnt);
				sfree(dnt);
				freeRuleValue(rvt, 1);
				continue;
			}
			freeLdapSearch(ls);

			/*
			 * If the DN is the same as one we already know
			 * about, merge the rule-values.
			 */

			if ((iq == 0 || !firstOnly) && dnt != 0) {
				dni = am(myself, sizeof (*dni));
				if (dni != 0) {
					dni->item.name = dnt;
					dni->index = idx + n;
					dni->oldDn = odnt;
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: Skipping update for dn=\"%s\"",
						myself, dnt);
					sfree(dnt);
					dnt = 0;
				}
				if (dnt != 0) {
					dn[idx+n] = dnt;
					odn[idx+n] = odnt;
					rv[idx+n] = rvt;
					rnq++;
				} else {
					freeRuleValue(rvt, 1);
					rvt = 0;
				}
			} else if (dnt != 0) {
				sfree(dnt);
				sfree(odnt);
				freeRuleValue(rvt, 1);
			}
		}
		sfree(tp);
	}

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s: %d update%s requested",
		myself, NIL(tm->objName), rnq, rnq != 1 ? "s" : "");

	/* Perform the updates */
	for (i = rnq = 0; i < (firstOnly ? maxMatches : nq*maxMatches); i++) {
		int	delPerDbId;

		if (dn[i] == 0)
			continue;

#ifdef	NISDB_LDAP_DEBUG
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: %s %s:dn=%s",
			myself,
			(new != 0 && new[i/maxMatches] != 0) ?
				"modify" : "delete",
			NIL(tpa[i]->dbId), dn[i]);
#endif	/* NISDB_LDAP_DEBUG */

		delPerDbId = (tpa[i]->objectDN->delDisp == dd_perDbId);
		if ((new != 0 && new[i/maxMatches] != 0) || delPerDbId) {
			/*
			 * Try to modify/create the specified DN. First,
			 * however, if the update changes the DN, make
			 * that change.
			 */
			if (odn[i] == 0 || (r = ldapChangeDN(odn[i], dn[i])) ==
					LDAP_SUCCESS) {
				int	addFirst;

				addFirst = (new != 0 &&
						new[i/maxMatches] != 0 &&
						!delPerDbId);
				r = ldapModify(dn[i], rv[i],
					tpa[i]->objectDN->write.attrs,
						addFirst);
			}
		} else {
			/* Try to delete the specified DN */
			r = ldapModify(dn[i], 0,
					tpa[i]->objectDN->write.attrs, 0);
		}

		if (r == LDAP_SUCCESS) {
			rnq++;
		} else {
			if (ret == LDAP_SUCCESS)
				ret = r;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: LDAP %s request error %d for %s:dn=%s",
				myself,
				(new != 0 && new[i/maxMatches] != 0) ?
					"modify" : "delete",
				r, NIL(tpa[i]->dbId), dn[i]);
		}

		sfree(dn[i]);
		dn[i] = 0;
		freeRuleValue(rv[i], 1);
		rv[i] = 0;
	}

	sfree(dn);
	sfree(odn);
	sfree(rv);
	sfree(tpa);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s: %d update%s performed",
		myself, NIL(tm->objName), rnq, rnq != 1 ? "s" : "");

	return (ret);
}

/*
 * In nis+2ldap, check if the query 'q' matches the selector index 'x->index'.
 *
 * In nis2ldap, if 'name' is provided then check if its value in 'val'
 * matches the selector index. If 'name' is NULL, then check if rule-value 'rv'
 * matches the index.
 * To match the selector index, all fieldspecs in the indexlist should match
 * (AND). In nis2ldap, an exception is, if there are multiple fieldspecs with
 * the same fieldname then only one of them needs to match (OR).
 * Example:
 *	Indexlist = [host="H*", host="I*", user="U*", domain="D*"]
 * Then,
 *	host = "H1", user="U1", domain="D1" ==> pass
 *	host = "I1", user="U1", domain="D1" ==> pass
 *	host = "X1", user="U1", domain="D1" ==> fail
 *	host = "H1", user="X1", domain="D1" ==> fail
 *	host = "H1", user="U1" ==> fail
 *
 * Return 1 in case of a match, 0 otherwise.
 */
int
verifyIndexMatch(__nis_table_mapping_t *x, db_query *q,
		__nis_rule_value_t *rv, char *name, char *val) {
	int	i, j, k, match = 1;
	char	*myself = "verifyIndexMatch";

	/*
	 * The pass and fail arrays are used by N2L to keep track of
	 * index matches. This saves us from having matches in a
	 * nested loop to decide OR or AND.
	 */
	int	ppos, fpos;
	char	**pass, **fail;

	if (x == 0)
		return (0);

	/* Trivial match */
	if (x->index.numIndexes <= 0 || (!yp2ldap && q == 0))
		return (1);

	if (yp2ldap) {
		if (!(pass = am(myself, x->index.numIndexes * sizeof (char *))))
			return (0);
		if (!(fail = am(myself,
				x->index.numIndexes * sizeof (char *)))) {
			sfree(pass);
			return (0);
		}
		ppos = fpos = 0;
	}

	/* Check each index */
	for (i = 0; i < x->index.numIndexes; i++) {
		char	*value = 0;

		/* Skip NULL index names */
		if (x->index.name[i] == 0)
			continue;

		/* Check N2L values */
		if (yp2ldap) {
			if (name) {
				if (strcasecmp(x->index.name[i], name) == 0)
					value = val;
				else
					continue;
			} else if (rv) {
				if (strcasecmp(x->index.name[i], N2LKEY) == 0 ||
					strcasecmp(x->index.name[i], N2LIPKEY)
							== 0)
					continue;
				value = findVal(x->index.name[i], rv,
							mit_nisplus);
			}

			if (value && verifyMappingMatch(x->index.value[i],
									value))
				pass[ppos++] = x->index.name[i];
			else
				fail[fpos++] = x->index.name[i];
			continue;
		}

		/* If here, means nis+2ldap */

		/* Is the index name a known column ? */
		for (j = 0; j < x->numColumns; j++) {
			if (strcmp(x->index.name[i], x->column[j]) == 0) {
				/*
				 * Do we have a value for the column ?
				 */
				for (k = 0; k < q->components.components_len;
						k++) {
					if (q->components.components_val[k].
							which_index == j) {
						value = q->components.
							components_val[k].
							index_value->
							itemvalue.
							itemvalue_val;
						break;
					}
				}
				if (value != 0)
					break;
			}
		}

		/*
		 * If we found a value, check if it matches the
		 * format. If no value found or no match, this
		 * mapping is _not_ an alternative. Otherwise,
		 * we continue checking any other indexes.
		 */
		if (value == 0 ||
			!verifyMappingMatch(x->index.value[i],
				value)) {
			match = 0;
			break;
		}
	}

	if (yp2ldap) {
		for (--fpos; fpos >= 0; fpos--) {
			for (i = 0; i < ppos; i++) {
				if (strcmp(pass[i], fail[fpos]) == 0)
					break;
			}
			if (i == ppos) {
				match = 0;
				break;
			}
		}
		sfree(pass);
		sfree(fail);
	}

	return (match);
}

/*
 * Return all table mappings that match the column values in 'q'.
 * If there's no match, return those alternative mappings that don't
 * have an index; if no such mapping exists, return NULL.
 *
 * If 'wantWrite' is set, we want mappings for writing (i.e., data
 * to LDAP); otherwise, we want mappings for reading.
 *
 * If 'wantObj' is set, we want object mappings only (i.e., _not_
 * those used to map entries in tables).
 *
 * If 'dbId' is non-NULL, we select mappings with a matching dbId field.
 */
__nis_table_mapping_t **
selectTableMapping(__nis_table_mapping_t *t, db_query *q,
			int wantWrite, int wantObj, char *dbId,
			int *numMatches) {
	__nis_table_mapping_t	*x, **tp;
	int			i, nm, numap;
	char			*myself = "selectTableMapping";

	if (numMatches == 0)
		numMatches = &nm;

	/*
	 * Count the number of possible mappings, so that we can
	 * allocate the 'tp' array up front.
	 */
	for (numap = 0, x = t; x != 0; numap++, x = x->next);

	if (numap == 0) {
		*numMatches = 0;
		return (0);
	}

	tp = am(myself, numap * sizeof (tp[0]));
	if (tp == 0) {
		*numMatches = -1;
		return (0);
	}

	/*
	 * Special cases:
	 *
	 *	q == 0 trivially matches any 't' of the correct object type
	 *
	 *	wantObj != 0 means we ignore 'q'
	 */
	if (q == 0 || wantObj) {
		for (i = 0, x = t, nm = 0; i < numap; i++, x = x->next) {
			if (x->objectDN == 0)
				continue;
			if (wantWrite) {
				if (x->objectDN->write.scope ==
						LDAP_SCOPE_UNKNOWN)
					continue;
			} else {
				if (x->objectDN->read.scope ==
						LDAP_SCOPE_UNKNOWN)
					continue;
			}
			if (wantObj) {
				if (x->numColumns > 0)
					continue;
			} else {
				if (x->numColumns <= 0)
					continue;
			}
			if (dbId != 0 && x->dbId != 0 &&
					strcmp(dbId, x->dbId) != 0)
				continue;
			tp[nm] = x;
			nm++;
		}
		*numMatches = nm;
		if (nm == 0) {
			sfree(tp);
			tp = 0;
		}
		return (tp);
	}

	/* Scan all mappings, and collect candidates */
	for (nm = 0, x = t; x != 0; x = x->next) {
		if (x->objectDN == 0)
			continue;
		if (wantWrite) {
			if (x->objectDN->write.scope == LDAP_SCOPE_UNKNOWN)
				continue;
		} else {
			if (x->objectDN->read.scope == LDAP_SCOPE_UNKNOWN)
				continue;
		}
		/* Only want table/entry mappings */
		if (x->numColumns <= 0)
			continue;
		if (dbId != 0 && x->dbId != 0 &&
				strcmp(dbId, x->dbId) != 0)
			continue;
		/*
		 * It's a match if: there are no indexes, or we actually
		 * match the query with the indexes.
		 */
		if (x->index.numIndexes <= 0 ||
					verifyIndexMatch(x, q, 0, 0, 0)) {
			tp[nm] = x;
			nm++;
		}
	}

	if (nm == 0) {
		free(tp);
		tp = 0;
	}

	*numMatches = nm;

	return (tp);
}

/*
 * Return 1 if there's an indexed mapping, 0 otherwise.
 */
int
haveIndexedMapping(__nis_table_mapping_t *t) {
	__nis_table_mapping_t	*x;

	for (x = t; x != 0; x = x->next) {
		if (x->index.numIndexes > 0)
			return (1);
	}

	return (0);
}

/*
 * Given an input string 'attrs' of the form "attr1=val1,attr2=val2,...",
 * or a filter, return the value associated with the attribute 'attrName'.
 * If no instance of 'attrName' is found, return 'default'. In all cases,
 * the return value is a copy, and must be freed by the caller.
 *
 * Of course, return NULL in case of failure.
 */
static char *
attrVal(char *msg, char *attrName, char *def, char *attrs) {
	char	*val, *filter, **fc = 0;
	int	i, nfc;
	char	*myself = "attrVal";

	if (attrName == 0 || attrs == 0)
		return (0);

	if (msg == 0)
		msg = myself;

	val = def;

	filter = makeFilter(attrs);
	if (filter != 0 && (fc = makeFilterComp(filter, &nfc)) != 0 &&
			nfc > 0) {
		for (i = 0; i < nfc; i++) {
			char	*name, *value;

			name = fc[i];
			/* Skip if not of attr=value form */
			if ((value = strchr(name, '=')) == 0)
				continue;

			*value = '\0';
			value++;

			if (strcasecmp(attrName, name) == 0) {
				val = value;
				break;
			}
		}
	}

	if (val != 0)
		val = sdup(msg, T, val);

	sfree(filter);
	freeFilterComp(fc, nfc);

	return (val);
}

extern bool_t	xdr_nis_object(register XDR *xdrs, nis_object *objp);

/*
 * Copy an XDR:ed version of the NIS+ object 'o' (or the one indicated
 * by 't->objName' if 'o' is NULL) to the place indicated by
 * 't->objectDN->write'. Return an appropriate LDAP status code.
 */
int
objToLDAP(__nis_table_mapping_t *t, nis_object *o, entry_obj **ea, int numEa) {
	__nis_table_mapping_t	**tp;
	int			stat, osize, n, numMatches = 0;
	void			*buf;
	__nis_rule_value_t	*rv;
	__nis_value_t		*val;
	__nis_single_value_t	*sv;
	char			**attrName, *dn;
	char			*myself = "objToLDAP";

	if (t == 0)
		return (LDAP_PARAM_ERROR);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s", myself, NIL(t->objName));

	tp = selectTableMapping(t, 0, 1, 1, 0, &numMatches);
	if (tp == 0 || numMatches <= 0) {
		sfree(tp);
		logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
			"%s: %s (no mapping)", myself, NIL(t->objName));
		return (LDAP_SUCCESS);
	}

	for (n = 0; n < numMatches; n++) {

		t = tp[n];

		if (o == 0) {
			sfree(tp);
			return (LDAP_OPERATIONS_ERROR);
		}

		buf = (char *)xdrNisObject(o, ea, numEa, &osize);
		if (buf == 0) {
			sfree(tp);
			return (LDAP_OPERATIONS_ERROR);
		}

		/*
		 * Prepare to build a rule-value containing the XDR:ed
		 * object
		 */
		rv = am(myself, sizeof (*rv));
		sv = am(myself, sizeof (*sv));
		val = am(myself, sizeof (*val));
		attrName = am(myself, sizeof (attrName[0]));
		if (attrName != 0)
			attrName[0] = attrVal(myself, "nisplusObject",
						"nisplusObject",
						t->objectDN->write.attrs);
		if (rv == 0 || sv == 0 || val == 0 || attrName == 0 ||
				attrName[0] == 0) {
			sfree(tp);
			sfree(buf);
			sfree(rv);
			sfree(sv);
			sfree(val);
			sfree(attrName);
			return (LDAP_NO_MEMORY);
		}

		sv->length = osize;
		sv->value = buf;

		/* 'vt_ber' just means "not a NUL-terminated string" */
		val->type = vt_ber;
		val->repeat = 0;
		val->numVals = 1;
		val->val = sv;

		rv->numAttrs = 1;
		rv->attrName = attrName;
		rv->attrVal = val;

		/*
		 * The 'write.base' is the actual DN of the entry (and the
		 * scope had better be 'base', but we don't check that).
		 */
		dn = t->objectDN->write.base;

		stat = ldapModify(dn, rv, t->objectDN->write.attrs, 1);

		freeRuleValue(rv, 1);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s (%s)", myself, NIL(t->objName), ldap_err2string(stat));

		if (stat != LDAP_SUCCESS)
			break;

	}

	sfree(tp);

	return (stat);
}

/*
 * Retrieve a copy of the 't->objName' object from LDAP, where it's
 * stored in XDR:ed form in the place indicated by 't->objectDN->read'.
 * Un-XDR the object, and return a pointer to it in '*obj'; it's the
 * responsibility of the caller to free the object when it's no
 * longer needed.
 *
 * Returns an appropriate LDAP status.
 */
int
objFromLDAP(__nis_table_mapping_t *t, nis_object **obj,
		entry_obj ***eaP, int *numEaP) {
	__nis_table_mapping_t	**tp;
	nis_object		*o;
	__nis_rule_value_t	*rv;
	__nis_ldap_search_t	*ls;
	char			*attrs[2], *filter, **fc = 0;
	void			*buf;
	int			i, j, nfc, nrv, blen, stat = LDAP_SUCCESS;
	int			n, numMatches;
	char			*myself = "objFromLDAP";

	if (t == 0)
		return (LDAP_PARAM_ERROR);

	/*
	 * If there's nowhere to store the result, we might as
	 * well pretend all went well, and return right away.
	 */
	if (obj == 0)
		return (LDAP_SUCCESS);

	/* Prepare for the worst */
	*obj = 0;

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s", myself, NIL(t->objName));

	tp = selectTableMapping(t, 0, 0, 1, 0, &numMatches);
	if (tp == 0 || numMatches <= 0) {
		sfree(tp);
		logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
			"%s: %s (no mapping)", myself, NIL(t->objName));
		return (LDAP_SUCCESS);
	}

	for (n = 0; n < numMatches; n++) {

		t = tp[n];

		filter = makeFilter(t->objectDN->read.attrs);
		if (filter == 0 || (fc = makeFilterComp(filter, &nfc)) == 0 ||
				nfc <= 0) {
			sfree(tp);
			sfree(filter);
			freeFilterComp(fc, nfc);
			return ((t->objectDN->read.attrs != 0) ?
				LDAP_NO_MEMORY : LDAP_PARAM_ERROR);
		}
		/* Don't need the filter, just the components */
		sfree(filter);

		/*
		 * Look for a "nisplusObject" attribute, and (if found) copy
		 * the value to attrs[0]. Also remove the "nisplusObject"
		 * attribute and value from the filter components.
		 */
		attrs[0] = sdup(myself, T, "nisplusObject");
		if (attrs[0] == 0) {
			sfree(tp);
			freeFilterComp(fc, nfc);
			return (LDAP_NO_MEMORY);
		}
		attrs[1] = 0;
		for (i = 0; i < nfc; i++) {
			char	*name, *value;
			int	compare;

			name = fc[i];
			/* Skip if not of attr=value form */
			if ((value = strchr(name, '=')) == 0)
				continue;

			/* Temporarily overWrite the '=' with a '\0' */
			*value = '\0';

			/* Compare with our target attribute name */
			compare = strcasecmp("nisplusObject", name);

			/* Put back the '=' */
			*value = '=';

			/* Is it the name we're looking for ? */
			if (compare == 0) {
				sfree(attrs[0]);
				attrs[0] = sdup(myself, T, value+1);
				if (attrs[0] == 0) {
					sfree(tp);
					freeFilterComp(fc, nfc);
					return (LDAP_NO_MEMORY);
				}
				sfree(fc[i]);
				if (i < nfc-1)
					(void) memmove(&fc[i], &fc[i+1],
						(nfc-1-i) * sizeof (fc[i]));
				nfc--;
				break;
			}
		}

		ls = buildLdapSearch(t->objectDN->read.base,
					t->objectDN->read.scope,
					nfc, fc, 0, attrs, 0, 1);
		sfree(attrs[0]);
		freeFilterComp(fc, nfc);
		if (ls == 0) {
			sfree(tp);
			return (LDAP_OPERATIONS_ERROR);
		}

		nrv = 0;
		rv = ldapSearch(ls, &nrv, 0, &stat);
		if (rv == 0) {
			sfree(tp);
			freeLdapSearch(ls);
			return (stat);
		}

		for (i = 0, buf = 0; i < nrv && buf == 0; i++) {
			for (j = 0; j < rv[i].numAttrs; j++) {
				if (strcasecmp(ls->attrs[0],
					rv[i].attrName[j]) == 0) {
					if (rv[i].attrVal[j].numVals <= 0)
						continue;
					buf = rv[i].attrVal[j].val[0].value;
					blen = rv[i].attrVal[j].val[0].length;
					break;
				}
			}
		}

		if (buf != 0) {
			o = unXdrNisObject(buf, blen, eaP, numEaP);
			if (o == 0) {
				sfree(tp);
				freeLdapSearch(ls);
				freeRuleValue(rv, nrv);
				return (LDAP_OPERATIONS_ERROR);
			}
			stat = LDAP_SUCCESS;
			*obj = o;
		} else {
			stat = LDAP_NO_SUCH_OBJECT;
		}

		freeLdapSearch(ls);
		freeRuleValue(rv, nrv);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s (%s)", myself, NIL(t->objName), ldap_err2string(stat));

		if (stat != LDAP_SUCCESS)
			break;

	}

	sfree(tp);

	return (stat);
}

int
deleteLDAPobj(__nis_table_mapping_t *t) {
	__nis_table_mapping_t	**tp;
	int		n, stat, numMatches = 0;
	char		*myself = "deleteLDAPobj";

	if (t == 0)
		return (LDAP_PARAM_ERROR);

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s", myself, NIL(t->objName));

	tp = selectTableMapping(t, 0, 1, 1, 0, &numMatches);
	if (tp == 0 || numMatches <= 0) {
		sfree(tp);
		logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
			LOG_WARNING,
#else
			LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
			"%s: %s (no mapping)", myself, NIL(t->objName));
		return (LDAP_SUCCESS);
	}

	for (n = 0; n < numMatches; n++) {

		t = tp[n];

		if (t->objectDN->delDisp == dd_always) {
			/* Delete entire entry */
			stat = ldapModify(t->objectDN->write.base, 0,
					t->objectDN->write.attrs, 1);
		} else if (t->objectDN->delDisp == dd_perDbId) {
			/*
			 * Delete the attribute holding the object.
			 * First, determine what that attribute is called.
			 */
			char			*attrName =
						attrVal(myself,
							"nisplusObject",
							"nisplusObject",
						t->objectDN->write.attrs);
			__nis_rule_value_t	rv;
			__nis_value_t		val;

			if (attrName == 0) {
				sfree(tp);
				return (LDAP_NO_MEMORY);
			}

			/*
			 * Build a __nis_value_t with 'numVals' < 0 to
			 * indicate deletion.
			 */
			val.type = vt_ber;
			val.numVals = -1;
			val.val = 0;

			/*
			 * Build a rule-value with the name we determined
			 * above, and the deletion value.
			 */
			(void) memset(&rv, 0, sizeof (rv));
			rv.numAttrs = 1;
			rv.attrName = &attrName;
			rv.attrVal = &val;

			stat = ldapModify(t->objectDN->write.base, &rv,
						t->objectDN->write.attrs, 0);

			sfree(attrName);
		} else if (t->objectDN->delDisp == dd_never) {
			/* Nothing to do, so we're trivially successful */
			stat = LDAP_SUCCESS;
		} else {
			stat = LDAP_PARAM_ERROR;
		}

	logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
		LOG_WARNING,
#else
		LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
		"%s: %s (%s)", myself, NIL(t->objName), ldap_err2string(stat));

		/* If there were no such object, we've trivially succeeded */
		if (stat == LDAP_NO_SUCH_OBJECT)
			stat = LDAP_SUCCESS;

		if (stat != LDAP_SUCCESS)
			break;

	}

	sfree(tp);

	return (stat);
}
