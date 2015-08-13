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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * DESCRIPTION:	Contains dit_access interface support functions.
 */
#include <sys/systeminfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <ndbm.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include "../ldap_util.h"
#include "../ldap_map.h"
#include "../ldap_parse.h"
#include "../ldap_structs.h"
#include "../ldap_val.h"
#include "../ldap_ruleval.h"
#include "../ldap_op.h"
#include "../ldap_attr.h"
#include "../ldap_nisdbquery.h"
#include "../nisdb_mt.h"
#include "shim.h"
#include "yptol.h"
#include "dit_access_utils.h"

#define	YPMULTI		"YP_MULTI_"
#define	YPMULTISZ	9		/* == strlen(YPMULTI) */

/*
 * Returns 'map,domain.'
 */
char *
getFullMapName(char *map, char *domain) {
	char	*myself = "getFullMapName";
	char	*objPath;
	if (map == 0 || domain == 0) {
		return (0);
	}
	objPath =  scat(myself, T, scat(myself, F, map, ","),
		scat(myself, F, domain, "."));

	return (objPath);
}

/*
 * Convert string to __nis_value_t
 */
__nis_value_t *stringToValue(char *dptr, int dsize) {
	char		*myself = "stringToValue";
	char		*emptystr = "";
	__nis_value_t	*val;

	if ((val = am(myself, sizeof (*val))) == 0) {
		return (0);
	}

	val->type = vt_string;
	val->repeat = 0;
	val->numVals = 1;
	if ((val->val = am(myself, sizeof (val->val[0]))) == 0) {
		sfree(val);
		return (0);
	}

	/*
	 * Null strings or strings with length 0 are treated
	 * as empty strings with length 1
	 */
	if (dptr == 0 || dsize <= 0) {
		dptr = emptystr;
		dsize = 1;
	}

	val->val->length = dsize;
	if (dptr[dsize - 1] != '\0') {
		val->val->length = dsize + 1;
	}

	val->val->value = am(myself, val->val->length);
	if (val->val->value == 0) {
		freeValue(val, 1);
		return (0);
	}
	(void) memcpy(val->val->value, dptr, dsize);

	return (val);
}

/*
 * Returns an array of rule-values corresponding to the
 * splitfields.
 */
__nis_rule_value_t *
processSplitField(__nis_table_mapping_t *sf, __nis_value_t *inVal,
			int *nv, int *statP) {

	char			*sepset;
	__nis_rule_value_t	*rvq;
	__nis_value_t		**valA, *tempVal;
	int			i, j, res, numVals, oldlen, count;
	char			*str, *oldstr;

	/* sf will be non NULL */

	if (inVal == 0 || inVal->type != vt_string) {
		*statP =  MAP_PARAM_ERROR;
		return (0);
	}

	/* Get the separator list */
	sepset = sf->separatorStr;

	/* Initialize rule-value */
	rvq = 0;
	count = 0;

	if ((tempVal = stringToValue(inVal->val->value,
			inVal->val->length)) == 0) {
		*statP = MAP_NO_MEMORY;
		return (0);
	}

	str = oldstr = tempVal->val->value;
	oldlen = tempVal->val->length;

	while (str) {
		tempVal->val->value = str;
		tempVal->val->length = strlen(str) + 1;

		/* Loop to check which format matches str */
		for (i = 0; i <= sf->numSplits; i++) {
			valA = matchMappingItem(sf->e[i].element.match.fmt,
				tempVal, &numVals, sepset, &str);
			if (valA == 0) {
				/* The format didn't match. Try the next one */
				continue;
			}

			/*
			 * If we are here means we had a match.
			 * Each new set of values obtained from the match is
			 * added to a new rule-value. This is to preserve the
			 * the distinction between each set.
			 */
			rvq = growRuleValue(count, count + 1, rvq, 0);
			if (rvq == 0) {
				*statP = MAP_INTERNAL_ERROR;
				for (j = 0; j < numVals; j++)
					freeValue(valA[j], 1);
				sfree(valA);
				tempVal->val->value = oldstr;
				tempVal->val->length = oldlen;
				freeValue(tempVal, 1);
				return (0);
			}
			count++;

			for (j = 0; j < numVals; j++) {
				res = addCol2RuleValue(vt_string,
					sf->e[i].element.match.item[j].name,
					valA[j]->val->value,
					valA[j]->val->length,
					&rvq[count - 1]);
				if (res == -1) {
					*statP = MAP_INTERNAL_ERROR;
					for (; j < numVals; j++)
						freeValue(valA[j], 1);
					sfree(valA);
					tempVal->val->value = oldstr;
					tempVal->val->length = oldlen;
					freeValue(tempVal, 1);
					freeRuleValue(rvq, count);
					return (0);
				}
				freeValue(valA[j], 1);
			}
			sfree(valA);

			/*
			 * Since we had a match, break out of this loop
			 * to parse remainder of str
			 */
			break;
		}

		/* Didn't find any match, so get out of the loop */
		if (i > sf->numSplits) {
			str = 0;
			break;
		}

		/* Skip the separators before looping back */
		if (str) {
			str = str + strspn(str, sepset);
			if (*str == '\0')
				break;
		}
	}

	tempVal->val->value = oldstr;
	tempVal->val->length = oldlen;
	freeValue(tempVal, 1);

	if (str == 0) {
		freeRuleValue(rvq, count);
		return (0);
	}

	if (nv != 0)
		*nv = count;

	return (rvq);
}

/*
 * Convert the datum to an array of RuleValues
 */
__nis_rule_value_t *
datumToRuleValue(datum *key, datum *value, __nis_table_mapping_t *t,
			int *nv, char *domain, bool_t readonly, int *statP) {

	__nis_rule_value_t	*rvq, *subrvq, *newrvq;
	__nis_value_t		*val;
	__nis_value_t		**valA;
	__nis_table_mapping_t	*sf;
	int			valueLen, comLen, numVals, nr, count = 1;
	int			i, j, k, l;
	char			*ipaddr, *ipvalue;

	/*  At this point, 't' is always non NULL */

	/* Initialize rule-value */
	if ((rvq = initRuleValue(1, 0)) == 0) {
		*statP = MAP_INTERNAL_ERROR;
		return (0);
	}

	/* Add domainname to rule-value */
	if (addCol2RuleValue(vt_string, N2LDOMAIN, domain, strlen(domain),
						rvq)) {
		freeRuleValue(rvq, 1);
		*statP = MAP_INTERNAL_ERROR;
		return (0);
	}

	/* Handle key */
	if (key != 0) {
		/* Add field=value pair for N2LKEY */
		i = addCol2RuleValue(vt_string, N2LKEY, key->dptr, key->dsize,
						rvq);

		/* For readonly, add field=value pair for N2LSEARCHKEY */
		if (readonly == TRUE && i == 0) {
			i = addCol2RuleValue(vt_string, N2LSEARCHKEY, key->dptr,
						key->dsize, rvq);
		}
		if (i) {
			freeRuleValue(rvq, 1);
			*statP = MAP_INTERNAL_ERROR;
			return (0);
		}

		/* Add field=value pairs for IP addresses */
		if (checkIPaddress(key->dptr, key->dsize, &ipaddr) > 0) {
			/* If key is IPaddress, use preferred format */
			ipvalue = ipaddr;
			valueLen = strlen(ipaddr);
			i = addCol2RuleValue(vt_string, N2LIPKEY, ipvalue,
						valueLen, rvq);
		} else {
			/* If not, use original value for N2LSEARCHIPKEY */
			ipaddr = 0;
			ipvalue = key->dptr;
			valueLen = key->dsize;
			i = 0;
		}

		if (readonly == TRUE && i == 0) {
			i = addCol2RuleValue(vt_string, N2LSEARCHIPKEY, ipvalue,
								valueLen, rvq);
		}
		sfree(ipaddr);
		if (i) {
			freeRuleValue(rvq, 1);
			*statP = MAP_INTERNAL_ERROR;
			return (0);
		}
	}

	/* Handle datum value */
	if (value != 0 && t->e) {
		valueLen = value->dsize;
		/*
		 * Extract the comment, if any, and add it to
		 * the rule-value.
		 */
		if (t->commentChar != '\0') {
			/*
			 * We loop on value->dsize because value->dptr
			 * may not be NULL-terminated.
			 */
			for (i = 0; i < value->dsize; i++) {
				if (value->dptr[i] == t->commentChar) {
					valueLen = i;
					comLen = value->dsize - i - 1;
					if (comLen == 0)
						break;
					if (addCol2RuleValue(vt_string,
						N2LCOMMENT, value->dptr + i + 1,
						comLen, rvq)) {
						freeRuleValue(rvq, 1);
						*statP = MAP_INTERNAL_ERROR;
						return (0);
					}
					break;
				}
			}
		}

		/* Skip trailing whitespaces */
		for (; valueLen > 0 && (value->dptr[valueLen - 1] == ' ' ||
			value->dptr[valueLen - 1] == '\t'); valueLen--);

		/*
		 * At this point valueLen is the effective length of
		 * the data. Convert value into __nis_value_t so that
		 * we can use the matchMappingItem function to break it
		 * into fields.
		 */
		if ((val = stringToValue(value->dptr, valueLen)) == 0) {
			freeRuleValue(rvq, 1);
			*statP = MAP_NO_MEMORY;
			return (0);
		}

		/* Perform namefield match */
		valA = matchMappingItem(t->e->element.match.fmt, val,
							&numVals, 0, 0);
		if (valA == 0) {
			freeValue(val, 1);
			freeRuleValue(rvq, 1);
			*statP = MAP_NAMEFIELD_MATCH_ERROR;
			return (0);
		}

		/* We don't need val anymore, so free it */
		freeValue(val, 1);

		/*
		 * Since matchMappingItem only returns us an array of
		 * __nis_value_t's, we need to associate each value
		 * in the array with the corresponding item name.
		 * This code assumes that numVals will be less than or
		 * equal to the number of item names associated with
		 * the format.
		 * These name=value pairs are added to rvq.
		 */
		for (i = 0, *statP = SUCCESS; i < numVals; i++) {
			for (j = 0; j < count; j++) {
				if (addCol2RuleValue(vt_string,
					t->e->element.match.item[i].name,
					valA[i]->val->value,
					valA[i]->val->length, &rvq[j])) {
					*statP = MAP_INTERNAL_ERROR;
					break;
				}
			}
			if (*statP == MAP_INTERNAL_ERROR)
				break;

			/*
			 * Check if splitField exists for the field.
			 * Since splitfields are also stored as mapping
			 * structures, we need to get the hash table entry
			 * corresponding to the splitfield name
			 */
			sf = mappingFromMap(t->e->element.match.item[i].name,
					domain, statP);
			if (*statP == MAP_NO_MEMORY)
				break;
			*statP = SUCCESS;
			if (sf == 0)
				continue;

			/*
			 * Process and add splitFields to rule-value rvq
			 */
			subrvq = processSplitField(sf, valA[i], &nr, statP);

			if (subrvq == 0) {
				/* statP would have been set */
				break;
			}

			/*
			 * We merge 'count' rule-values in rvq with 'nr'
			 * rule-values from subrvq to give us a whopping
			 * 'count * nr' rule-values
			 */

			/* Initialize the new rule-value array */
			if ((newrvq = initRuleValue(count * nr, 0)) == 0) {
				*statP = MAP_INTERNAL_ERROR;
				freeRuleValue(subrvq, nr);
				break;
			}

			for (j = 0, l = 0; j < nr; j++) {
				for (k = 0; k < count; k++, l++) {
					if ((mergeRuleValue(&newrvq[l],
							&rvq[k]) == -1) ||
							(mergeRuleValue(
							&newrvq[l],
							&subrvq[j]) == -1)) {
						*statP = MAP_INTERNAL_ERROR;
						for (i = 0; i < numVals; i++)
							freeValue(valA[i], 1);
						sfree(valA);
						freeRuleValue(rvq, count);
						freeRuleValue(newrvq,
								count * nr);
						freeRuleValue(subrvq, nr);
						return (0);
					}
				}
			}

			freeRuleValue(rvq, count);
			rvq = newrvq;
			count = l;
			freeRuleValue(subrvq, nr);

		}

		/* We don't need valA anymore, so free it */
		for (i = 0; i < numVals; i++)
			freeValue(valA[i], 1);
		sfree(valA);

		if (*statP != SUCCESS) {
			freeRuleValue(rvq, count);
			return (0);
		}

	} /* if value */

	if (nv != 0)
		*nv = count;
	return (rvq);

}

/*
 * Generate name=values pairs for splitfield names
 *
 * Consider Example:
 *	nisLDAPnameFields club:
 *			("%s %s %s", name, code, members)
 *	nisLDAPsplitField members:
 *			("(%s,%s,%s)", host, user, domain),
 *			("%s", group)
 * On entry,
 * - rv is an array of numVals rule-values each containing
 * name=value pairs for names occuring in nisLDAPsplitField.
 * (i.e host, user, domain, group)
 * - trv contains name=value pairs for names occuring in
 * nisLDAPnameFields. (i.e name, code but not members)
 *
 * For every name in nisLDAPnamefields that is a splitfield,
 * this function applies the data in rv to the corresponding
 * splitfield formats (accessed thru t), to generate a single
 * string value for the corresponding splitfield (members).
 * This new name=value pair is then added to trv.
 * Besides, any uninitialized namefield names are set to empty strings.
 */
suc_code
addSplitFieldValues(__nis_table_mapping_t *t, __nis_rule_value_t *rv,
			__nis_rule_value_t *trv, int numVals, char *domain) {
	__nis_table_mapping_t	*sf;
	__nis_value_t		*val;
	int			i, j, k, nitems, res, statP;
	char			*str, *tempstr;
	char			delim[2] = {0, 0};
	char			*emptystr = "";
	char			*myself = "addSplitFieldValues";

	if (trv == 0)
		return (MAP_INTERNAL_ERROR);

	if (t->e == 0)
		return (SUCCESS);

	nitems = t->e->element.match.numItems;

	/*
	 * Procedure:
	 * - Check each name in nisLDAPnamefield
	 * - if it's a splifield, construct its value and add it to trv
	 * - if not, check if it has a value
	 * - if not, add empty string
	 */
	for (i = 0, sf = 0; i < nitems; i++) {
		if (rv) {
			/*
			 * str will eventually contain the single string
			 * value for the corresponding  splitfield.
			 * No point initializing str if rv == 0 because
			 * splitfield cannot be constructed without rv.
			 * So, only initialized here.
			 */
			str = 0;

			/* Check if it's a splitfield name */
			sf = mappingFromMap(t->e->element.match.item[i].name,
				domain, &statP);

			/*
			 * Return only incase of memory allocation failure.
			 * The other error case (MAP_NO_MAPPING_EXISTS),
			 * indicates that the item name is not a splitfieldname
			 * i.e it's a namefieldname. This case is handled by
			 * the following if (sf == 0)
			 */
			if (statP == MAP_NO_MEMORY)
				return (statP);
		}

		if (sf == 0) {
			/*
			 * Not a splitfield name. Verify if it has a value
			 */
			if (findVal(t->e->element.match.item[i].name,
				trv, mit_nisplus) == 0) {
				/* if not, use empty string */
				res = addCol2RuleValue(vt_string,
					t->e->element.match.item[i].name,
					emptystr, 0, trv);
				if (res == -1) {
					return (MAP_INTERNAL_ERROR);
				}
			}
			/*
			 * If rv == 0 then sf == 0 so we will continue here
			 * i.e. does not matter that str is not yet set up.
			 */
			continue;
		}

		/* Code to construct a single value */

		/* Use the first separator character as the delimiter */
		delim[0] = sf->separatorStr[0];

		for (j = 0; j < numVals; j++) {
			/* sf->numSplits is zero-based */
			for (k = 0; k <= sf->numSplits; k++) {
				val = getMappingFormatArray(
					sf->e[k].element.match.fmt, &rv[j],
					fa_item,
					sf->e[k].element.match.numItems,
					sf->e[k].element.match.item);
				if (val == 0)
					continue;
				if (val->numVals > 0) {
					if (str) {
						tempstr = scat(myself,
							0, str, delim);
						sfree(str);
						if (tempstr)
							str = tempstr;
						else {
							freeValue(val, 1);
							return (MAP_NO_MEMORY);
						}
					}
					tempstr = scat(myself, 0, str,
						val->val->value);
					sfree(str);
					if (tempstr)
						str = tempstr;
					else {
						freeValue(val, 1);
						return (MAP_NO_MEMORY);
					}
				}
				freeValue(val, 1);
			}
		}
		if (str == 0)
			str = emptystr;

		res = addCol2RuleValue(vt_string,
				t->e->element.match.item[i].name,
				str, strlen(str), trv);

		if (str != emptystr)
			sfree(str);

		if (res == -1) {
			return (MAP_INTERNAL_ERROR);
		}
	}

	return (SUCCESS);
}

/*
 * Updates 'rv' with NIS name=value pairs suitable to
 * construct datum from namefield information.
 * Some part based on createNisPlusEntry (from ldap_nisdbquery.c)
 * This code assumes that from a given LDAP entry, applying the
 * mapping rules, would give us one or more NIS entries, differing
 * only in key.
 */
suc_code
buildNISRuleValue(__nis_table_mapping_t *t, __nis_rule_value_t *rv,
					char *domain) {
	int			r, i, j, k, l, nrq, res, len;
	int			numItems, splitname, count, statP;
	__nis_value_t		*rval;
	__nis_mapping_item_t	*litem;
	__nis_mapping_rule_t	*rl;
	__nis_rule_value_t	*rvq;
	char			*value, *emptystr = "";

	statP = SUCCESS;

	/* Initialize default base */
	__nisdb_get_tsd()->searchBase = t->objectDN->read.base;

	/* Initialize rule-value rvq */
	rvq = 0;
	count = 0;

	/* Add domainname to rule-value */
	if (addCol2RuleValue(vt_string, N2LDOMAIN, domain, strlen(domain),
						rv)) {
		return (MAP_INTERNAL_ERROR);
	}

	for (r = 0; r < t->numRulesFromLDAP; r++) {
		rl = t->ruleFromLDAP[r];

		/* Set escapeFlag if RHS is "dn" to remove escape chars */
		if (rl->rhs.numElements == 1 &&
			rl->rhs.element->type == me_item &&
			rl->rhs.element->element.item.type == mit_ldap &&
			strcasecmp(rl->rhs.element->element.item.name, "dn")
									== 0) {
				__nisdb_get_tsd()->escapeFlag = '2';
		}

		rval = buildRvalue(&rl->rhs, mit_ldap, rv, NULL);

		/* Reset escapeFlag */
		__nisdb_get_tsd()->escapeFlag = '\0';

		if (rval == 0) {
			continue;
		}

		if (rval->numVals <= 0) {
			/* Treat as invalid */
			freeValue(rval, 1);
			continue;
		}

		litem = buildLvalue(&rl->lhs, &rval, &numItems);
		if (litem == 0) {
			/* This will take care of numItems == 0 */
			freeValue(rval, 1);
			continue;
		}

		if (rval->numVals > 1) {
			if (numItems == 1 && litem->repeat)
				nrq = rval->numVals;
			else if (numItems > 1 && rval->repeat)
				nrq = 1 + ((rval->numVals-1)/numItems);
			else
				nrq = 1;
		} else
			nrq = 1;

		/* Set splitname if splitfield names are specified */
		for (i = 0; i < numItems; i++) {
			if (strcasecmp(litem[i].name, N2LKEY) == 0 ||
				strcasecmp(litem[i].name, N2LIPKEY) == 0 ||
				strcasecmp(litem[i].name, N2LCOMMENT) == 0)
				continue;
			for (j = 0; j < t->numColumns; j++) {
				if (strcmp(litem[i].name, t->column[j]) == 0)
					break;
			}
			if (j == t->numColumns)
				break;
		}

		splitname = (i < numItems)?1:0;

		for (j = 0; j < nrq; j++) {
			if (splitname == 1) {
				/*
				 * Put every value of splitfieldname in a new
				 * rule-value. Helps generating splitfields.
				 */
				rvq = growRuleValue(count, count + 1, rvq, 0);
				if (rvq == 0) {
					freeRuleValue(rvq, count);
					freeValue(rval, 1);
					freeMappingItem(litem, numItems);
					return (MAP_INTERNAL_ERROR);
				}
				count++;
			}

			for (k = j % nrq, l = 0; l < numItems; k += nrq, l++) {
				/* If we run out of values, use empty strings */
				if (k >= rval->numVals) {
					value = emptystr;
					len = 0;
				} else {
					value = rval->val[k].value;
					len = rval->val[k].length;
				}
				res = (splitname == 1)?addCol2RuleValue(
					vt_string, litem[l].name, value,
					len, &rvq[count - 1]):0;
				if (res != -1)
					res = addCol2RuleValue(vt_string,
						litem[l].name, value, len, rv);
				if (res == -1) {
					freeRuleValue(rvq, count);
					freeValue(rval, 1);
					freeMappingItem(litem, numItems);
					return (MAP_INTERNAL_ERROR);
				}
			}
		}
		freeValue(rval, 1);
		rval = 0;
		freeMappingItem(litem, numItems);
		litem = 0;
		numItems = 0;
	} /* for r < t->numRulesFromLDAP */

	statP = addSplitFieldValues(t, rvq, rv, count, domain);

	if (rvq)
		freeRuleValue(rvq, count);

	if (verifyIndexMatch(t, 0, rv, 0, 0) == 0)
		return (MAP_INDEXLIST_ERROR);
	return (statP);

} /* end of buildNISRuleValue */

/*
 * Convert rule-value to datum using namefield information
 */
datum *
ruleValueToDatum(__nis_table_mapping_t *t, __nis_rule_value_t *rv, int *statP) {
	__nis_value_t	*val;
	datum		*value;
	char		*str, *cstr, commentSep[3] = {' ', 0, 0};
	char		*myself = "ruleValueToDatum";

	/* No error yet */
	*statP = 0;

	/* Return empty datum if no namefield information available */
	if (t->e == 0) {
		if ((value = am(myself, sizeof (*value))) == 0)
			*statP = MAP_NO_MEMORY;
		return (value);
	}

	val = getMappingFormatArray(t->e->element.match.fmt, rv,
				fa_item, t->e->element.match.numItems,
				t->e->element.match.item);

	if (val && val->val && val->val->value) {
		if ((value = am(myself, sizeof (*value))) == 0) {
			*statP = MAP_NO_MEMORY;
			freeValue(val, 1);
			return (0);
		}

		/* Strip trailing whitespaces */
		cstr = (char *)val->val->value + val->val->length;
		for (; cstr >= (char *)val->val->value &&
			(*cstr == ' ' || *cstr == '\t'); *cstr-- = '\0');

		if (t->commentChar != '\0' &&
		    (str = findVal(N2LCOMMENT, rv, mit_nisplus)) != 0 &&
		    *str != '\0') {
			commentSep[1] = t->commentChar;
			cstr = scat(myself, F, commentSep, str);
			if (cstr) {
				value->dptr = scat(myself, F,
						val->val->value, cstr);
				sfree(cstr);
			}
		} else {
			value->dptr = sdup(myself, T, val->val->value);
		}
		freeValue(val, 1);
		if (value->dptr) {
			value->dsize = strlen(value->dptr);
			return (value);
		} else {
			*statP = MAP_NO_MEMORY;
			sfree(value);
			return (0);
		}
	}

	*statP = MAP_NAMEFIELD_MATCH_ERROR;
	return (0);
}

datum *
getKeyFromRuleValue(__nis_table_mapping_t *t, __nis_rule_value_t *rv, int *nv,
    int *statP, bool_t xlate_to_lcase)
{
	int	i, j, k;
	datum	*key = 0;
	char	*str;
	char	*myself = "getKeyFromRuleValue";

	/* No error yet */
	*statP = 0;

	if (rv == 0 || nv == 0)
		return (0);

	for (i = 0; i < rv->numColumns; i++) {
		if (rv->colName[i] == 0)
			continue;
		if (strcasecmp(N2LKEY, rv->colName[i]) == 0 ||
		    strcasecmp(N2LIPKEY, rv->colName[i]) == 0) {
			if ((*nv = rv->colVal[i].numVals) == 0)
				return (0);
			if ((key = am(myself, sizeof (key[0]) * *nv)) == 0) {
				*statP = MAP_NO_MEMORY;
				return (0);
			}
			for (j = 0; j < *nv; j++) {
				if ((str = rv->colVal[i].val[j].value) == 0) {
					key[j].dsize = 0;
					key[j].dptr = 0;
				} else {
					if (verifyIndexMatch(t, 0, 0,
					    rv->colName[i], str) == 0) {
						key[j].dsize = 0;
						key[j].dptr = 0;
						continue;
					}

					key[j].dsize = strlen(str);
					key[j].dptr = am(myself,
					    key[j].dsize + 1);
					if (key[j].dptr == 0) {
						*statP = MAP_NO_MEMORY;
						for (--j; j >= 0; j--)
							sfree(key[j].dptr);
						sfree(key);
						return (0);
					}

					/* transliterate key to lowercase */
					if (xlate_to_lcase == TRUE) {

						/*
						 * For multi-homed
						 * entries, skip over
						 * "YP_MULTI_" prefix.
						 */
						k = 0;
						if (strncmp(YPMULTI, str,
						    YPMULTISZ) == 0) {
							k = YPMULTISZ;
							bcopy(str, key[j].dptr,
							    YPMULTISZ);
						}
						while (k < key[j].dsize) {
							key[j].dptr[k] =
							    (char)tolower(
							    (int)(uchar_t)
							    str[k]);
							k++;
						}
					} else {
						bcopy(str, key[j].dptr,
						    key[j].dsize);
					}
				}
			}
			return (key);
		}
	}
	return (0);
}

/*
 * Get the mapping structure corresponding to `map,domain.'
 */
__nis_table_mapping_t *
mappingFromMap(char *map, char *domain, int *statP) {
	char			*mapPath;
	__nis_table_mapping_t	*t;

	/* No error yet */
	*statP = 0;

	/* Construct map,domain. */
	if ((mapPath = getFullMapName(map, domain)) == 0) {
		*statP = MAP_NO_MEMORY;
		return (0);
	}

	/* Get the hash table entry for the mapPath */
	if ((t = __nis_find_item_mt(mapPath, &ldapMappingList, 1, 0))
			== 0) {
		*statP = MAP_NO_MAPPING_EXISTS;
	}
	sfree(mapPath);
	return (t);
}

/*
 * Verify at least one key value obtained from DIT matches the search key
 * RETURNS:	 1	MATCH
 *		 0	NO MATCH
 *		-1	NO KEY FOUND
 */
static int
verifyKey(char *key, __nis_rule_value_t *rv) {
	int	i, j;
	char	*sipkey, *str;

	for (i = 0; i < rv->numColumns; i++) {
		if (rv->colName[i] == 0)
			continue;
		if (strcasecmp(N2LKEY, rv->colName[i]) == 0) {
			if (rv->colVal[i].val == 0)
				return (0);
			for (j = 0; j < rv->colVal[i].numVals; j++) {
				str = (char *)rv->colVal[i].val[j].value;
				if (str && strcmp(str, key) == 0)
					return (1);
			}
			return (0);
		} else if (strcasecmp(N2LIPKEY, rv->colName[i]) == 0) {
			if (checkIPaddress(key, strlen(key), &sipkey) > 0) {
				if (rv->colVal[i].val == 0)
					return (0);
				for (j = 0; j < rv->colVal[i].numVals; j++) {
					str = rv->colVal[i].val[j].value;
					if (str && strcmp(str, sipkey) == 0) {
						sfree(sipkey);
						return (1);
					}
				}
				sfree(sipkey);
			}
			return (0);
		}
	}
	return (-1);
}

/*
 * Read (i.e get and map) a single NIS entry from the LDAP DIT
 */
bool_t
singleReadFromDIT(char *map, char *domain, datum *key, datum *value,
							int *statP) {
	__nis_table_mapping_t	*t;
	__nis_rule_value_t	*rv_request = 0, *rv_result = 0;
	__nis_ldap_search_t	*ls;
	__nis_object_dn_t	*objectDN = NULL;
	int			i, rc, nr = 0;
	datum			*datval = 0;
	char			*skey, *str;
	char			*myself = "singleReadFromDIT";

	*statP = SUCCESS;

	if (!map || !domain || !key || !value) {
		*statP = MAP_PARAM_ERROR;
		return (FALSE);
	}


	/* Get the mapping information for the map */
	if ((t = mappingFromMap(map, domain, statP)) == 0) {
		/*
		 * No problem. We don't handle this map and domain. Maybe it's
		 * handled by a service other than NIS.
		 */
		return (FALSE);
	}

	/* NULL-terminated version of datum key for logging */
	if ((skey = am(myself, key->dsize + 1)) == 0) {
		*statP = MAP_NO_MEMORY;
		return (FALSE);
	}
	(void) memcpy(skey, key->dptr, key->dsize);

	if ((str = getFullMapName(map, domain)) == 0) {
		*statP = MAP_NO_MEMORY;
		return (FALSE);
	}

	/* For each alternate mapping */
	for (; t != 0; t = t->next) {
		/* Verify objName */
		if (strcmp(str, t->objName) != 0) {
			continue;
		}

		/* Verify if key matches the index */
		if (verifyIndexMatch(t, 0, 0, N2LKEY, skey) == 0 ||
			verifyIndexMatch(t, 0, 0, N2LIPKEY, skey) == 0)
			continue;

		/* Check if rulesFromLDAP are provided */
		if (t->numRulesFromLDAP == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: No rulesFromLDAP information available "
				"for %s (%s)", myself, t->dbId, map);
			continue;
		}

		/* Convert key into rule-value */
		if ((rv_request = datumToRuleValue(key, 0, t, 0, domain, TRUE,
								statP)) == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Conversion error %d (NIS to name=value "
				"pairs) for NIS key (%s) for %s (%s)",
				myself, *statP, skey, t->dbId, map);
			continue;
		}
		/* Convert rule-value into ldap request */
		for (objectDN = t->objectDN; objectDN &&
				objectDN->read.base;
				objectDN = objectDN->next) {
			ls = createLdapRequest(t, rv_request, 0, 1, NULL,
								objectDN);
			if (ls == 0) {
				*statP = MAP_CREATE_LDAP_REQUEST_ERROR;
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Failed to create ldapSearch "
					"request for "
					"NIS key (%s) for %s (%s) "
					"for base %s",
					myself, skey, t->dbId, map,
					objectDN->read.base);
				continue;
			}
			ls->timeout.tv_sec = SINGLE_ACCESS_TIMEOUT_SEC;
			ls->timeout.tv_usec = SINGLE_ACCESS_TIMEOUT_USEC;
			/* Query LDAP */
			nr = (ls->isDN)?0:-1;
			rv_result = ldapSearch(ls, &nr, 0, statP);
			freeLdapSearch(ls);
			if (rv_result == 0) {
				if (*statP == LDAP_NO_SUCH_OBJECT) {
					/* Entry does not exist in */
					/* the ldap server */
				}
				continue;
			}
			freeRuleValue(rv_request, 1);
			rv_request = 0;

			/* if result > 1, first match will be returned */
			if (nr > 1) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: %d ldapSearch results "
					"for NIS key (%s) "
					"for %s (%s) for base %s. "
					"First match will be returned ",
					myself, nr, skey, t->dbId, map,
					objectDN->read.base);
			}

			for (i = 0; i < nr; i++) {
				/* Convert LDAP data to NIS equivalents */
				*statP = buildNISRuleValue(t, &rv_result[i],
								domain);
				if (*statP == MAP_INDEXLIST_ERROR)
					continue;

				if (*statP != SUCCESS) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: Conversion error %d (LDAP to "
					"name=value pairs) for NIS key (%s) "
					"for %s (%s) for base %s", myself,
					*statP, skey,
					t->dbId, map, objectDN->read.base);
					continue;
				}

			/*
			 * Check if 'key' from the ldap result matches the key
			 * provided by our caller
			 */
				if ((rc = verifyKey(skey, &rv_result[i]))
						== -1) {
					logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: Cannot verify key from ldap "
					"result for NIS key (%s) for %s (%s) "
					"for base %s",
					myself, skey, t->dbId, map,
					objectDN->read.base);
					continue;
				}

				if (rc == 1) {
					datval = ruleValueToDatum(t,
							&rv_result[i], statP);
					if (datval == 0) {
						logmsg(MSG_NOTIMECHECK,
						LOG_WARNING,
						"%s: Conversion error %d "
						"(name=value pairs to NIS) "
						"for NIS key (%s) for %s (%s)"
						" for base %s",
						myself,
						*statP, skey, t->dbId, map,
						objectDN->read.base);
						continue;
					}
					if (value) {
						value->dptr = datval->dptr;
						value->dsize = datval->dsize;
					}
					sfree(datval);
					sfree(skey);
					freeRuleValue(rv_result, nr);
					rv_result = 0;
					*statP = SUCCESS;

					/* Free full map name */
					sfree(str);

					return (TRUE);
				}
			}
			freeRuleValue(rv_result, nr);
			rv_result = 0;
		}   /* end of for over objectDN */

		if (rv_request != 0) {
			freeRuleValue(rv_request, 1);
			rv_request = 0;
		}
		if (rv_result != 0) {
			freeRuleValue(rv_result, nr);
			rv_result = 0;
		}
	}
	sfree(skey);
	*statP = MAP_NO_MATCHING_KEY;

	/* Free full map name */
	sfree(str);

	return (FALSE);
}


/*
 * Maps and writes a single NIS entry to the LDAP DIT
 */
int
singleWriteToDIT(char *map, char *domain, datum *key, datum *value,
						bool_t replace) {
	__nis_table_mapping_t	*t;
	__nis_rule_value_t	*rv, *frv;
	__nis_ldap_search_t	*ls;
	int			statP = SUCCESS, flag;
	int			nv, nr, i, rc, collapse;
	char			*dn = 0, *skey, *svalue, *str;
	char			*myself = "singleWriteToDIT";

	if (!map || !domain || !key || !value) {
		return (MAP_PARAM_ERROR);
	}

	/* Return SUCCESS for empty or whitespace key */
	for (i = 0; i < key->dsize && (key->dptr[i] == 0 ||
		key->dptr[i] == ' ' || key->dptr[i] == '\t'); i++);
	if (i >= key->dsize)
		return (SUCCESS);

	/* Get the mapping information for the map */
	if ((t = mappingFromMap(map, domain, &statP)) == 0) {
		/*
		 * No problem. We don't handle this map and domain. Maybe it's
		 * handled by a service other than NIS.
		 */
		return (statP);
	}

	/* NULL-terminated version of key and value for logging */
	if ((skey = am(myself, key->dsize + 1)) == 0)
		return (MAP_NO_MEMORY);
	(void) memcpy(skey, key->dptr, key->dsize);

	if ((svalue = am(myself, value->dsize + 1)) == 0) {
		sfree(skey);
		return (MAP_NO_MEMORY);
	}
	(void) memcpy(svalue, value->dptr, value->dsize);

	if ((str = getFullMapName(map, domain)) == 0) {
		sfree(skey);
		sfree(svalue);
		return (MAP_NO_MEMORY);
	}

	/* For each alternate mapping */
	for (flag = 0; t != 0; t = t->next) {
		/* Verify objName */
		if (strcmp(str, t->objName) != 0) {
			continue;
		}

		/* Verify if key matches the index */
		if (verifyIndexMatch(t, 0, 0, N2LKEY, skey) == 0 ||
			verifyIndexMatch(t, 0, 0, N2LIPKEY, skey) == 0)
			continue;

		/* Check the writespecs */
		if (t->objectDN->write.base == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: No baseDN in writespec. Write disabled "
				"for %s (%s)", myself, t->dbId, map);
			continue;
		}

		/* Check if rulesToLDAP are provided */
		if (t->numRulesToLDAP == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: No rulesToLDAP. Write disabled for "
				"%s (%s)", myself, t->dbId, map);
			continue;
		}

		/* Set flag to indicate write is enabled */
		flag = 1;

		/* Convert key  and value into an array of rule-values */
		if ((rv = datumToRuleValue(key, value, t, &nv, domain, FALSE,
								&statP)) == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Conversion error %d (NIS to name=value "
				"pairs) for NIS data (key=%s, value=%s) "
				"for %s (%s)",
				myself, statP, skey, svalue, t->dbId, map);
			sfree(skey);
			sfree(svalue);

			/* Free full map name */
			sfree(str);

			return (statP);
		}

		/* Convert NIS data to LDAP equivalents for each rule-value */
		for (i = 0; i < nv; i++) {
			/* Verify indexlist with name=value pairs */
			if (verifyIndexMatch(t, 0, &rv[i], 0, 0) == 0)
				break;

			/* Create LDAP request and LDAP name=value pairs */
			if ((ls = createLdapRequest(t, &rv[i],
			    0, 0, NULL, NULL)) == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Conversion error (name=value pairs"
					" to LDAP) for NIS data "
					"(key=%s, value=%s) for %s (%s)",
					myself, skey, svalue, t->dbId, map);
				freeRuleValue(rv, nv);
				sfree(skey);
				sfree(svalue);

				/* Free full map name */
				sfree(str);

				return (MAP_CREATE_LDAP_REQUEST_ERROR);
			}
			freeLdapSearch(ls);
			/* printRuleValue(&rv[i]); */
		}

		/* If i < nv then this alternate mapping isn't the one */
		if (i < nv)
			continue;

		/*
		 * Merge rule-values with the same DN so that we have
		 * one ldap write request for each DN
		 */
		nr = nv;
		frv = mergeRuleValueWithSameDN(rv, &nr);
		freeRuleValue(rv, nv);
		if (frv == 0) {
			if (nr == -1) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Unable to merge LDAP write "
					"requests to same DN for NIS data "
					"(key=%s, value=%s) for %s (%s)",
					myself, skey, svalue, t->dbId, map);
				statP = MAP_INTERNAL_ERROR;
			} else if (nr == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_WARNING,
					"%s: Cannot generate write DN due to "
					"missing information for NIS data "
					"(key=%s, value=%s) for %s (%s)",
					myself, skey, svalue, t->dbId, map);
				statP = MAP_NO_DN;
			}
			sfree(skey);
			sfree(svalue);

			/* Free full map name */
			sfree(str);

			return (statP);
		}

		/* Write to the LDAP server */
		for (collapse = 0, i = 0; i < nr; i++) {
			if ((dn = findVal("dn", &frv[i], mit_ldap)) != 0) {
				if (replace == FALSE) {
					/* ldap add */
					rc = ldapAdd(dn, &frv[i],
						t->objectDN->write.attrs, 0);
				} else {
					/* ldap modify with addFirst set */
					rc = ldapModify(dn, &frv[i],
						t->objectDN->write.attrs, 1);
				}

				/* if we get err=20, collapse and try again */
				if (!collapse &&
					(rc == LDAP_TYPE_OR_VALUE_EXISTS) &&
					(collapseRuleValue(&frv[i]) == 1)) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s: Ignoring values differing "
						"in case from NIS data (key=%s,"
						" value=%s) for (dn: %s) for "
						"%s (%s)", myself, skey,
						svalue, dn, t->dbId, map);
					collapse = 1;
					i--;
					continue;
				}

				collapse = 0;
				if (rc != LDAP_SUCCESS) {
					/* Log error */
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"%s: %s error %d (%s) for "
						"(dn: %s) for NIS data "
						"(key=%s, value=%s) "
						"for %s (%s)",
						myself, (replace == TRUE) ?
						"ldapModify" : "ldapAdd", rc,
						ldap_err2string(rc), dn, skey,
						svalue, t->dbId, map);

					/* Dumping failed call may be useful */
					/* printRuleValue(&frv[i]); */

					/*
					 * Return the error code and let wrapper
					 * sort out if mapping should continue
					 * or abort.
					 */
					statP = rc;
					sfree(skey);
					sfree(svalue);
					freeRuleValue(frv, nr);

					/* Free full map name */
					sfree(str);

					return (statP);
				}
			}
		}

		freeRuleValue(frv, nr);
	}

	sfree(skey);
	sfree(svalue);

	/* Free full map name */
	sfree(str);

	return ((flag)?SUCCESS:MAP_WRITE_DISABLED);
}

suc_code
collapseRuleValue(__nis_rule_value_t *rv) {
	int		i, j, k, flag;

	/* Using 'val' to appease cstyle's 80 chars/line limit */
	__nis_value_t	*val;

	for (i = 0, flag = 0; i < rv->numAttrs; i++) {
		val = &rv->attrVal[i];
		for (j = 1; j < val->numVals; j++) {
			for (k = 0; k < j; k++) {
				if (val->val[j].length != val->val[k].length)
					continue;
				if (val->val[k].length == 0)
					continue;
				if (strncasecmp(val->val[j].value,
						val->val[k].value,
						val->val[j].length) != 0)
					continue;
				flag = 1;
				sfree(val->val[j].value);

#ifdef	ORDER_NOT_IMPORTANT
				val->val[j--] = val->val[--val->numVals];
#else
				/* Order needs to be maintained */
				for (k = j + 1; k < val->numVals; k++)
					val->val[k - 1] = val->val[k];
				j--;
				val->numVals--;
#endif
				break;
			}
		}
	}
	return (flag);
}

/* ObjectClass lookup table */
static struct {
	const char *attrType;
	const char *objectClass;
} oc_lookup[] = {
	{ "o",				"objectclass=organization"},
	{ "organizationname",		"objectclass=organization"},
	{ "2.5.4.10",			"objectclass=organization"},
	{ "ou",				"objectclass=organizationalunit"},
	{ "organizationalunitname",	"objectclass=organizationalunit"},
	{ "2.5.4.11",			"objectclass=organizationalunit"},
	{ "c",				"objectclass=country"},
	{ "countryname",		"objectclass=country"},
	{ "2.5.4.6",			"objectclass=country"},
	{ "dc",				"objectclass=domain"},
	{ "domaincomponent",		"objectclass=domain"},
	{ "0.9.2342.19200300.100.1.25",	"objectclass=domain"},
	{ "nismapname",			"objectclass=nismap"},
	{ "1.3.6.1.1.1.1.26",		"objectclass=nismap"},
	{ "automountmapname",		"objectclass=automountmap"},
	{ "1.3.6.1.1.1.1.31",		"objectclass=automountmap"},
	{ 0,				0}
};

/*
 * Returns the name of the objectclass to which the object
 * represented by the given 'rdn' will most likely belong to.
 * The return value is in static memory so it should not be
 * freed
 */
const char *
getObjectClass(char *rdn) {

	char *attrtype, *p;
	int len, i;

	/* Skip leading whitespaces */
	for (p = rdn; *p == ' ' || *p == '\t'; p++);
	if (*p == '\0')
		return (0);
	attrtype = p;

	/* Find '=' */
	if ((p = strchr(attrtype, '=')) == 0 || p == attrtype ||
						*(p - 1) == '\\')
		return (0);

	/*
	 * Skip trailing whitespaces in attrtype
	 * Don't worry, p won't decrease beyond attrtype
	 */
	for (--p; *p == ' ' || *p == '\t'; p--);
	len = p - attrtype + 1;

	for (i = 0; oc_lookup[i].attrType; i++)
		if (!strncasecmp(oc_lookup[i].attrType, attrtype, len))
			/* Check length is right */
			if (len == strlen(oc_lookup[i].attrType))
				return (oc_lookup[i].objectClass);

	return (0);
}

/*
 * Split 'dn' into rdn and parentdn based on the first
 * occurrence of unescaped 'comma' or 'semicolon'. rdn
 * lies on the LHS while parentdn lies on the RHS of the
 * split. If none found, then an empty string ("") is
 * assigned to parentdn
 */
int
splitDN(char *dn, char **rdn, char **parentdn) {
	char	*value, *name;
	char	*myself = "splitDN";

	if ((name = sdup(myself, T, dn)) == 0)
		return (-1);

	for (value = name; *value != '\0'; value++) {
		if (*value == ',' || *value == ';')
			if (value == name || *(value - 1) != '\\')
				break;
	}

	if (*value != '\0') {
		*value = '\0';
		value++;
	} else
		value = 0;

	if (parentdn) {
		if ((*parentdn = sdup(myself, T, value)) == 0) {
			sfree(name);
			return (-1);
		}
	}
	if (rdn)
		*rdn = name;
	else
		sfree(name);

	return (1);
}

/*
 * FUNCTION :	makeNISObject()
 *
 * DESCRIPTION: Sets up a nis Object in the DIT.
 *
 * GIVEN :
 *		Case 1: Both 'domain' and 'dn' are non-NULL
 *			Create nisDomainObject with the given information
 *		Case 2: Only 'domain' is  non-NULL
 *			Obtain the 'dn' from the nisLDAPdomainContext list
 *			Create nisDomainObject with the above information
 *		Case 3: Only 'dn' is  non-NULL
 *			Create an object with the 'dn'
 *			Here we guess the objectclass attribute, based on
 *			oc_lookup table
 *		Case 4: Both 'domain' and 'dn' are NULL
 *			Error
 *
 * RETURNS :	SUCCESS = It worked
 *		FAILURE = There was a problem.
 */
suc_code
makeNISObject(char *domain, char *dn) {
	__nis_rule_value_t	*rv;
	__nis_ldap_search_t	*ls;
	int			i, rc, nr, add_rc;
	char			*val;
	char			*myself = "makeNISObject";

	if (!dn && !domain)
		return (FAILURE);

	/*
	 * If only 'domain' name is provided, then
	 * try to find dn from the nisLDAPdomainContext
	 * list generated by the parser
	 */
	if (!dn) {
		for (i = 0; i < ypDomains.numDomains; i++) {
			if (ypDomains.domainLabels[i] == 0)
				continue;
			if (strcasecmp(domain, ypDomains.domainLabels[i])
								== 0) {
				dn = ypDomains.domains[i];
				break;
			}
		}
		if (!dn)
			return (FAILURE);
	}

	/*
	 * If only 'dn' is given, then it means that the
	 * caller simply wants to a create an entry for
	 * that 'dn'.
	 *
	 * If 'domain' is given, then check if the 'dn'
	 * has already been set up as a nis domain object.
	 * If not, see if we can make it become one.
	 */
	if (domain) {
		/*
		 * Check to see if the nis domain object has
		 * already been set up
		 */
		ls = buildLdapSearch(dn, LDAP_SCOPE_BASE, 0, 0,
			"objectclass=*", 0, 0, 0);
		if (ls == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to create ldapSearch "
				"request for dn: %s", myself, dn);
			return (FAILURE);
		}
		nr = -1;
		rv = ldapSearch(ls, &nr, 0, &rc);
		freeLdapSearch(ls);
		if (rc == LDAP_SUCCESS) {
			val = findVal("nisDomain", rv, mit_ldap);
			if (val != NULL) {
				/*
				 * Yes, nis domain object found. Check
				 * to see if the domain names match.
				 * If so, we are done. If not, log
				 * a warning message, and return SUCCESS.
				 */
				if (strcasecmp(val, domain) == 0) {
					freeRuleValue(rv, nr);
					return (SUCCESS);
				} else {
					logmsg(MSG_NOTIMECHECK,
						LOG_WARNING,
						"%s: Entry (dn: %s) already "
						"contains a nis domain name "
						"(%s). The domain name (%s) "
						"is not added.",
						myself, dn, val, domain);
					freeRuleValue(rv, nr);
					return (SUCCESS);
				}
			} else {
				freeRuleValue(rv, nr);
				/*
				 * Entry for the 'dn' exists, but it
				 * is not a nis domain object yet.
				 * Add the nisDoamin attribute and
				 * the nisDomainObject objectclass to
				 * the entry.
				 */
				if ((rv = initRuleValue(1, 0)) == 0)
					return (FAILURE);

				if (addSAttr2RuleValue("nisDomain",
						domain, rv) == -1) {
					freeRuleValue(rv, 1);
					return (FAILURE);
				}
				rc = ldapModify(dn, rv,
					"objectclass=nisDomainObject",
					0);
				freeRuleValue(rv, 1);
				if (rc == LDAP_SUCCESS) {
					logmsg(MSG_NOTIMECHECK,
						LOG_INFO,
						"%s: entry (dn: %s) "
						"modified to be an "
						"nis domain object",
						myself, dn);
					return (SUCCESS);
				} else {
					logmsg(MSG_NOTIMECHECK,
						LOG_ERR,
						"%s: unable to modify "
						"entry (dn: %s) to be "
						"a nis domain object: "
						"ldapModify error %d (%s)",
						myself, dn, rc,
						ldap_err2string(rc));
					return (FAILURE);
				}
			}
		} else { /* search for 'dn' failed */
			freeRuleValue(rv, nr);

			/*
			 * It is OK if no such object, otherwise
			 * log an error.
			 */
			if (rc != LDAP_NO_SUCH_OBJECT) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: unable to retrieve "
					"entry (dn: %s): "
					"ldapSearch error %d (%s)",
					myself, dn, rc,
					ldap_err2string(rc));
				return (FAILURE);
			}
		}

		/*
		 * If the 'dn' is actually the naming context of
		 * the DIT, we should be able to make it a nis domain
		 * object without worrying about missing parent
		 * entries. If unable to add the entry for the 'dn'
		 * due to missing parent entries, fall through
		 * to create them and then add the nis domain object.
		 */
		if (addNISObject(domain, dn, &add_rc) == SUCCESS)
			return (SUCCESS);
		else if (add_rc != LDAP_NO_SUCH_OBJECT)
			return (FAILURE);
	}

	/* Create parent */
	if (addParent(dn, NULL) == FAILURE)
		return (FAILURE);

	if (addNISObject(domain, dn, NULL) == FAILURE)
		return (FAILURE);

	return (SUCCESS);
}

suc_code
addParent(char *dn, char **attr) {
	__nis_rule_value_t	*rv;
	__nis_ldap_search_t	*ls;
	int			rc, nr;
	char			*parentdn = 0, *rdn = 0;
	char			*myself = "addParent";

	/* Obtain parentdn */
	if (splitDN(dn, &rdn, &parentdn) == -1)
		return (FAILURE);
	if (!parentdn) {
		sfree(rdn);
		return (FAILURE);
	}

	/* Check if parentdn exists */
	ls = buildLdapSearch(parentdn, LDAP_SCOPE_BASE, 0, 0,
					"objectclass=*", 0, 0, 0);
	if (ls == 0) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to create ldapSearch request for "
			"parent (dn: %s) of (dn: %s)",
			myself, parentdn, dn);
		sfree(parentdn);
		sfree(rdn);
		return (FAILURE);
	}
	nr = -1;
	rv = ldapSearch(ls, &nr, 0, &rc);
	freeLdapSearch(ls);
	freeRuleValue(rv, nr);

	/* Create parent if it doesn't exists */
	if (rc == LDAP_NO_SUCH_OBJECT) {
		if (makeNISObject(0, parentdn) == FAILURE) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to create parent (dn: %s) of "
				"(dn: %s) in the DIT", myself, parentdn, dn);
			sfree(parentdn);
			sfree(rdn);
			return (FAILURE);
		}
	}
	sfree(parentdn);

	if (attr && rdn)
		*attr = (char *)getObjectClass(rdn);
	sfree(rdn);

	return (SUCCESS);
}



/*
 * FUNCTION :	is_fatal_error()
 *
 * DESCRIPTION:	Works out if a failed mapping operation should be retried.
 *
 * INPUTS :	Result code from operation
 *
 * OUTPUTS :	TRUE = Fatal error, don't retry.
 *		FALSE = Temporary error, retry.
 */
bool_t
is_fatal_error(int res)
{

	if (0 > res)
		/* An internal mapping error. Not going to go away. */
		return (TRUE);

	switch (res) {
		case (LDAP_PROTOCOL_ERROR):
		case (LDAP_TIMELIMIT_EXCEEDED):
		case (LDAP_PARTIAL_RESULTS):
		case (LDAP_BUSY):
		case (LDAP_UNAVAILABLE):
		case (LDAP_UNWILLING_TO_PERFORM):
		case (LDAP_OTHER):
		case (LDAP_SERVER_DOWN):
		case (LDAP_LOCAL_ERROR):
		case (LDAP_TIMEOUT):
		case (LDAP_NO_MEMORY):
			/* Probably worth a retry */
			return (FALSE);

		default:
			return (TRUE);
	}
}

/*
 * FUNCTION :	addNISObject()
 *
 * DESCRIPTION: Add a nis Object in the DIT.
 *
 * GIVEN :
 *		Case 1: 'dn' is NULL
 *			Error
 *		Case 2: 'domain' is non-NULL
 *			Create nisDomainObject with the given information
 *		Case 3: 'domain' is NULL
 *			Create an object with the 'dn'
 *			Here we guess the objectclass attribute, based on
 *			oc_lookup table
 *
 * RETURNS :	SUCCESS = It worked
 *		FAILURE = There was a problem. If the ldap add
 *                        operation failed, ldap_rc will be set
 *			  to the ldap error code.
 */
suc_code
addNISObject(char *domain, char *dn, int *ldap_rc) {
	__nis_rule_value_t	*rv;
	int			rc;
	char			*objClassAttrs = NULL, *attrs;
	char			*value, *svalue, *rdn = NULL;
	char			*myself = "addNISObject";

	if (!dn)
		return (FAILURE);

	if ((rv = initRuleValue(1, 0)) == 0)
		return (FAILURE);

	if (ldap_rc)
		*ldap_rc = -1;

	/*
	 * Add name=value pairs from RDN. Although this is not required
	 * for SunOne Directory Server, during openldap interoperabilty
	 * tests, it was found out that openldap server returned object
	 * class violation errors if MUST attributes were not specified
	 * explicitly.
	 */
	if (splitDN(dn, &rdn, 0) == -1)
		return (FAILURE);
	if (rdn != NULL) {
		objClassAttrs = (char *)getObjectClass(rdn);
		if (objClassAttrs == NULL) {
			sfree(rdn);
			return (FAILURE);
		}

		/*
		 * RDN can be composed of multiple name=value pairs
		 * concatenated by '+'. Hence, we need to determine each
		 * pair and add it to 'rv'
		 */
		for (value = rdn, svalue = NULL; *value != '\0'; value++) {
			if (*value == '+') {
				/* Make sure it's not escaped */
				if (value == rdn || *(value - 1) != '\\') {
					/*
					 * We are at the start of the new
					 * pair. 'svalue' now contains the
					 * value for the previous pair. Add
					 * the previous pair to 'rv'
					 */
					*value = '\0';
					if (svalue &&
					addSAttr2RuleValue(rdn, svalue, rv)
									== -1) {
						sfree(rdn);
						freeRuleValue(rv, 1);
						return (FAILURE);
					}
					svalue = NULL;
					rdn = value + 1;
					continue;
				}
			}

			if (*value == '=') {
				if (value == rdn || *(value - 1) != '\\') {
					/*
					 * 'rdn' now contains the name.
					 * Whatever follows till the next
					 * unescaped '+' or '\0' is the
					 * value for this pair.
					 */
					*value = '\0';
					svalue = value + 1;
					continue;
				}
			}
		}

		/*
		 * End of String. Add the previous name=value pair to 'rv'
		 */
		if (svalue && addSAttr2RuleValue(rdn, svalue, rv) == -1) {
			sfree(rdn);
			freeRuleValue(rv, 1);
			return (FAILURE);
		}
		sfree(rdn);
	} else /* rdn  == NULL */
		return (FAILURE);

	/* Create the entry */
	if (domain) {
		if (addSAttr2RuleValue("nisDomain", domain, rv) == -1) {
			freeRuleValue(rv, 1);
			return (FAILURE);
		}
		attrs = scat(myself, F, "objectclass=nisdomainobject,",
					objClassAttrs);
		if (!attrs) {
			freeRuleValue(rv, 1);
			return (FAILURE);
		}
		rc = ldapAdd(dn, rv, attrs, 0);
		sfree(attrs);
	} else {
		rc = ldapAdd(dn, rv, objClassAttrs, 0);
	}

	if (rc == LDAP_SUCCESS)
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Entry (dn: %s) added to DIT",
				myself, dn);
	else if (rc == LDAP_ALREADY_EXISTS)
		/* Treat this as success */
		rc = LDAP_SUCCESS;
	else
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: ldapAdd error %d (%s) for (dn: %s)",
				myself, rc, ldap_err2string(rc), dn);

	freeRuleValue(rv, 1);
	if (ldap_rc)
		*ldap_rc = rc;
	return ((rc == LDAP_SUCCESS)?SUCCESS:FAILURE);
}
