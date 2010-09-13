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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <lber.h>
#include <ldap.h>
#include <string.h>

#include "ldap_util.h"
#include "ldap_op.h"
#include "ldap_attr.h"
#include "ldap_ldap.h"


static __nis_value_t *
evalMappingElement(__nis_mapping_element_t *e, __nis_rule_value_t *rvIn) {
	__nis_rule_value_t	*rv = rvIn;
	int			freeRv = 0;
	__nis_value_t		*val;

	if (rv == 0) {
		rv = initRuleValue(1, 0);
		if (rv == 0)
			return (0);
		freeRv = 1;
	}

	val = getMappingElement(e, mit_any, rv, NULL);

	if (freeRv)
		freeRuleValue(rv, 1);

	return (val);
}

__nis_value_t *
lookupLDAP(__nis_search_triple_t *t, char *attrName, __nis_rule_value_t *rv,
		__nis_object_dn_t *def, int *np_ldap_stat) {
	__nis_value_t		*val, *eVal = 0;
	char			*base, *filter;
	__nis_ldap_search_t	*ls;
	char			*attrs[2];
	int			scope, i, stat, nrv = 0, freeBase = 0;
	char			*myself = "lookupLDAP";

	if (t == 0 || slen(attrName) <= 0)
		return (0);

	if (t->element != 0) {
		/* Evaluate t->element to get the t->attrs value */

		eVal = evalMappingElement(t->element, rv);

		if (eVal == 0)
			return (0);

		if (eVal->type != vt_string || eVal->numVals <= 0) {
			freeValue(eVal, 1);
			{
				char	*ename = "<unknown>";

				eVal = evalMappingElement(t->element, 0);
				if (eVal != 0 && eVal->type == vt_string &&
					eVal->numVals == 1 &&
					eVal->val[0].length > 0 &&
					eVal->val[0].value != 0)
					ename = eVal->val[0].value;
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: %s: unable to evaluate filter expression \"%s\"",
					myself, attrName, ename);
				freeValue(eVal, 1);
			}
			return (0);
		}

		filter = eVal->val[0].value;
	} else {
		filter = t->attrs;
	}

	if (slen(t->base) > 0) {
		base = appendBase(t->base, (def != 0) ? def->read.base : 0,
					&stat, 0);
		if (stat != 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: %s: error appending \"%s\" to \"%s\"",
				myself, attrName, NIL(def->read.base),
				NIL(t->base));
			return (0);
		}
		freeBase = 1;
	} else {
		if (def == 0 || def->read.scope == LDAP_SCOPE_UNKNOWN ||
				slen(def->read.base) <= 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: %s: no supplied or default search base",
				myself, attrName);
			freeValue(eVal, 1);
			return (0);
		}
		base = def->read.base;
	}

	if (slen(filter) > 0)
		scope = t->scope;
	else
		scope = LDAP_SCOPE_BASE;

	attrs[0] = attrName;
	attrs[1] = 0;

	ls = buildLdapSearch(base, scope, 0, 0, filter, attrs, 0, 0);
	if (ls == 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"%s: %s: error building LDAP search information for \"%s?%s?%s\"",
			myself, attrName, NIL(base), getScope(scope),
			NIL(filter));
		freeValue(eVal, 1);
		if (freeBase)
			sfree(base);
		return (0);
	}

	rv = ldapSearch(ls, &nrv, 0, &stat);
	freeLdapSearch(ls);

	/*
	 * If ldapSearch returns LDAP_NO_SUCH_OBJECT, then entry that
	 * looked for is not there in LDAP, so return NP_LDAP_NO_VALUE
	 * in np_ldap_stat.
	 */

	if (np_ldap_stat != NULL && stat == LDAP_NO_SUCH_OBJECT)
		*np_ldap_stat = NP_LDAP_NO_VALUE;

	if (rv == 0) {
		logmsg(MSG_NOTIMECHECK,
			(stat == LDAP_NO_SUCH_OBJECT)?LOG_DEBUG:LOG_ERR,
			"%s: %s: LDAP error %d (%s) for \"%s?%s?%s\"",
			myself, attrName, stat, ldap_err2string(stat),
			NIL(base), getScope(scope), NIL(filter));
		if (freeBase)
			sfree(base);
		freeValue(eVal, 1);
		return (0);
	}

	if (freeBase)
		sfree(base);
	freeValue(eVal, 1);
	eVal = 0;

	for (i = 0, val = 0; i < nrv; i++) {
		int	j;
		for (j = 0; j < rv[i].numAttrs; j++) {
			if (strcasecmp(attrName, rv[i].attrName[j]) == 0) {
				eVal = concatenateValues(val,
							&rv[i].attrVal[j]);
				freeValue(val, 1);
				if (eVal == 0) {
					freeRuleValue(rv, nrv);
					return (0);
				}
				val = eVal;
				break;
			}
		}
	}

	freeRuleValue(rv, nrv);
	return (val);
}

/*
 * Store 'val' at the LDAP location indicated by 'item'. As usual,
 * val->numVals == -1 indicates deletion.
 *
 * The 'index' and 'numIndexes' parameters are used as follows:
 *
 *	index < 0 || index >= numIndexes
 *		Illegal
 *
 *	index >= val->numVals
 *		Store val->val[val->numVals-1]
 *
 *	item->repeat == 0 || index < numIndexes
 *		Store val->val[index]
 *
 *	Else (repeat != 0 && index == numIndexes-1)
 *		Store val->val[index...val->numVals-1]
 *
 * 'defDN' should be the default object DN specification, primarily
 * used when the item search triple is invalid. Also, the defDN->write.base
 * value is appended to the item search base if the latter is empty, or ends
 * in a comma.
 *
 * If the item search triple is invalid, 'dn' must contain the DN(s)
 * of the LDAP entry to be modified. If the search triple is valid,
 * the DN(s) is(are) either:
 *	Derived via an LDAP search on the search triple 'attrs' or
 *      'element' fields, or (if neither of those fields is set)
 *	assumed to be the search triple base.
 *
 * Returns LDAP_SUCCESS when successful, or an appropriate LDAP
 * error status otherwise.
 */
int
storeLDAP(__nis_mapping_item_t *item, int index, int numIndexes,
		__nis_value_t *val, __nis_object_dn_t *defDN,
		char **dn, int numDN) {
	__nis_ldap_search_t	ls;
	int			stat, i, ix, six, nix;
	int			freeDN = 0;
	char			*locDN[1];
	__nis_rule_value_t	*rv;
	char			*defBase = 0;
	char			*myself = "storeLDAP";

	if (item == 0 || item->type != mit_ldap || item->name == 0 ||
			index < 0 || index >= numIndexes ||
			val == 0 || val->numVals < -1 || val->numVals == 0)
		return (LDAP_PARAM_ERROR);

	if (defDN != 0 && slen(defDN->write.base) > 0)
		defBase = defDN->write.base;

	ls.numFilterComps = 0;
	ls.filterComp = 0;
	ls.numAttrs = 0;
	ls.attrs = 0;
	ls.isDN = 0;

	if (item->searchSpec.triple.scope == LDAP_SCOPE_UNKNOWN) {
		/* If 'defDN' is NULL, we don't know where to write */
		if (defDN == 0)
			return (LDAP_PARAM_ERROR);
		/*
		 * Check if we're supposed to write. Since we want the
		 * admin to be able to use the nisplusLDAPobjectDN attribute
		 * as an on/off switch, we don't flag failure as an error.
		 */
		if (defDN != 0 && defDN->write.scope == LDAP_SCOPE_UNKNOWN) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: write not enabled for \"%s\"",
				myself, NIL(item->name));
			return (LDAP_SUCCESS);
		}
	} else {
		/*
		 * Attempt to get a DN from the search triple.
		 */

		if (slen(item->searchSpec.triple.base) > 0)
			ls.base = item->searchSpec.triple.base;
		else
			ls.base = defBase;
		ls.base = appendBase(ls.base, defBase, &stat, 0);
		if (stat != 0)
			return (0);
		ls.scope = item->searchSpec.triple.scope;

		/*
		 * If the search triple specifies a filter, we use the
		 * base, scope and filter to get an entry to supply the
		 * DN. Otherwise, the triple.base is assumed to be the DN.
		 */
		if (slen(item->searchSpec.triple.attrs) > 0 ||
				item->searchSpec.triple.element != 0) {
			__nis_value_t		*eVal = 0;
			__nis_rule_value_t	*rvDN;
			int			nv = 0;

			if (item->searchSpec.triple.element != 0) {
				eVal = evalMappingElement(
					item->searchSpec.triple.element, 0);

				if (eVal == 0) {
					sfree(ls.base);
					return (0);
				}

				if (eVal->type != vt_string ||
						eVal->numVals <= 0) {
					sfree(ls.base);
					freeValue(eVal, 1);
					return (0);
				}

				ls.filter = eVal->val[0].value;
			} else {
				ls.filter = item->searchSpec.triple.attrs;
			}

			rvDN = ldapSearch(&ls, &nv, 0, &stat);
			sfree(ls.base);
			freeValue(eVal, 1);
			if (rvDN == 0 || nv <= 0)
				return (stat);

			/* Look for DNs */
			dn = findDNs(myself, rvDN, nv, 0, &numDN);
			freeRuleValue(rvDN, nv);
			if (dn == 0 || numDN <= 0) {
				freeDNs(dn, numDN);
				return (LDAP_NO_MEMORY);
			}
			freeDN = 1;
		} else if (slen(item->searchSpec.triple.base) > 0) {
			locDN[0] = item->searchSpec.triple.base;
			dn = locDN;
			numDN = 1;
		}
	}

	/* We must have at least one DN to continue */
	if (dn == 0 || numDN < 1) {
		if (freeDN)
			freeDNs(dn, numDN);
		return (LDAP_PARAM_ERROR);
	}

	if (val->numVals > 0) {
		/* Make a rule-value describing the modification */
		rv = am(myself, sizeof (*rv));
		if (rv == 0)
			return (LDAP_NO_MEMORY);
		rv->attrName = am(myself, sizeof (rv->attrName[0]));
		rv->attrVal = am(myself, sizeof (rv->attrVal[0]));
		if (rv->attrName == 0 || rv->attrVal == 0) {
			if (freeDN)
				freeDNs(dn, numDN);
			freeRuleValue(rv, 1);
			return (LDAP_NO_MEMORY);
		}

		/*
		 * What's the start index in val->val[], and how many elements
		 * should we copy ?
		 */
		if (index < val->numVals)
			six = index;
		else
			six = val->numVals - 1;
		if (item->repeat && index == (numIndexes - 1))
			nix = 1 + (six - (val->numVals - 1));
		else
			nix = 1;

		rv->attrName[0] = sdup(myself, T, item->name);
		rv->attrVal[0].val = am(myself,
				nix * sizeof (rv->attrVal[0].val[0]));
		if (rv->attrName[0] == 0 || rv->attrVal[0].val == 0) {
			if (freeDN)
				freeDNs(dn, numDN);
			freeRuleValue(rv, 1);
			return (LDAP_NO_MEMORY);
		}
		rv->numAttrs = 1;
		for (ix = six; ix < nix; ix++) {
			rv->attrVal[0].numVals++;
			rv->attrVal[0].val[ix-six].value =
					am(myself, val->val[ix].length);
			if (rv->attrVal[0].val[ix-six].value == 0 &&
					val->val[ix].value != 0) {
				if (freeDN)
					freeDNs(dn, numDN);
				freeRuleValue(rv, 1);
				return (LDAP_NO_MEMORY);
			}
			rv->attrVal[0].val[ix-six].length =
				val->val[ix].length;
			if (rv->attrVal[0].val[ix-six].length > 0) {
				(void) memcpy(rv->attrVal[0].val[ix-six].value,
					val->val[ix].value,
					rv->attrVal[0].val[ix-six].length);
			}
		}
		rv->attrVal[0].type = val->type;
	} else {
		/*
		 * We already rejected val->numvals < -1 and val->numVals == 0
		 * in the initial sanity check, so it must be -1. This means
		 * deletion, which we indicate to ldapModify() by supplying
		 * a NULL rule-value pointer.
		 */
		rv = 0;
	}

	/* For each DN */
	for (i = 0; i < numDN; i++) {
		stat = ldapModify(dn[i], rv, item->searchSpec.triple.attrs, 0);
		if (stat != LDAP_SUCCESS)
			break;
	}

	if (freeDN)
		freeDNs(dn, numDN);
	freeRuleValue(rv, 1);

	return (stat);
}
