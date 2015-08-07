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


#include <lber.h>
#include <ldap.h>
#include <strings.h>

#include "nisdb_mt.h"

#include "ldap_util.h"
#include "ldap_val.h"
#include "ldap_attr.h"
#include "ldap_ldap.h"
#include "ldap_ruleval.h"


/*
 * Free an array of 'count' rule-value elements.
 */
void
freeRuleValue(__nis_rule_value_t *rv, int count) {
	int	n, i, j;

	if (rv == 0)
		return;

	for (n = 0; n < count; n++) {

		if (rv[n].colName != 0) {
			for (i = 0; i < rv[n].numColumns; i++) {
				sfree(rv[n].colName[i]);
			}
			free(rv[n].colName);
		}
		if (rv[n].colVal != 0) {
			for (i = 0; i < rv[n].numColumns; i++) {
				for (j = 0; j < rv[n].colVal[i].numVals; j++) {
					sfree(rv[n].colVal[i].val[j].value);
				}
				if (rv[n].colVal[i].numVals > 0)
					sfree(rv[n].colVal[i].val);
			}
			free(rv[n].colVal);
		}

		if (rv[n].attrName != 0) {
			for (i = 0; i < rv[n].numAttrs; i++) {
				sfree(rv[n].attrName[i]);
			}
			free(rv[n].attrName);
		}
		if (rv[n].attrVal != 0) {
			for (i = 0; i < rv[n].numAttrs; i++) {
				for (j = 0; j < rv[n].attrVal[i].numVals;
						j++) {
					sfree(rv[n].attrVal[i].val[j].value);
				}
				if (rv[n].attrVal[i].numVals > 0)
					sfree(rv[n].attrVal[i].val);
			}
			free(rv[n].attrVal);
		}

	}
	sfree(rv);
}

/*
 * Return an array of 'count' __nis_rule_value_t elements, initialized
 * to be copies of 'rvIn' if supplied; empty otherwise.
 */
__nis_rule_value_t *
initRuleValue(int count, __nis_rule_value_t *rvIn) {
	return (growRuleValue(0, count, 0, rvIn));
}

static const __nis_rule_value_t	rvZero = {0};

/*
 * Grow 'old' from 'oldCount' to 'newCount' elements, initialize the
 * new portion to 'rvIn' (empty if not supplied), and return a pointer
 * to the result. Following a call to this function, the caller must
 * refer only to the returned array, not to 'old'.
 */
__nis_rule_value_t *
growRuleValue(int oldCount, int newCount, __nis_rule_value_t *old,
		__nis_rule_value_t *rvIn) {
	__nis_rule_value_t	*rv;
	int			i;
	char			*myself = "growRuleValue";

	if (newCount <= 0 || newCount <= oldCount)
		return (old);

	if (oldCount <= 0) {
		oldCount = 0;
		old = 0;
	}

	if (rvIn == 0)
		rvIn = (__nis_rule_value_t *)&rvZero;

	rv = realloc(old, newCount * sizeof (rv[0]));
	if (rv == 0) {
		logmsg(MSG_NOMEM, LOG_ERR,
			"%s: realloc(%d ((%d+%d)*%d)) => 0",
			myself, (oldCount+newCount) * sizeof (rv[0]),
			oldCount, newCount, sizeof (rv[0]));
		freeRuleValue(old, oldCount);
		return (0);
	}

	(void) memset(&rv[oldCount], 0, (newCount-oldCount)*sizeof (rv[0]));

	for (i = oldCount; i < newCount; i++) {
		rv[i].numColumns = rvIn->numColumns;
		if (rv[i].numColumns > 0) {
			rv[i].colName = cloneName(rvIn->colName,
					rv[i].numColumns);
			rv[i].colVal = cloneValue(rvIn->colVal,
					rv[i].numColumns);
		}
		if (rv[i].numColumns > 0 &&
				(rv[i].colName == 0 || rv[i].colVal == 0)) {
			freeRuleValue(rv, i);
			return (0);
		}
		rv[i].numAttrs = rvIn->numAttrs;
		rv[i].attrName = cloneName(rvIn->attrName, rv[i].numAttrs);
		rv[i].attrVal = cloneValue(rvIn->attrVal, rv[i].numAttrs);
		if (rv[i].numAttrs > 0 &&
			(rv[i].attrName == 0 || rv[i].attrVal == 0)) {
			freeRuleValue(rv, i);
			return (0);
		}
	}

	return (rv);
}

/*
 * Merge the source rule-value 's' into the target rule-value 't'.
 * If successful, unless 's' is a sub-set of 't', 't' will be changed
 * on exit, and will contain the values from 's' as well.
 */
int
mergeRuleValue(__nis_rule_value_t *t, __nis_rule_value_t *s) {
	int	i, j;

	if (s == 0)
		return (0);
	else if (t == 0)
		return (-1);

	for (i = 0; i < s->numColumns; i++) {
		for (j = 0; j < s->colVal[i].numVals; j++) {
			if (addCol2RuleValue(s->colVal[i].type, s->colName[i],
					s->colVal[i].val[j].value,
					s->colVal[i].val[j].length,
					t))
				return (-1);
		}
	}

	for (i = 0; i < s->numAttrs; i++) {
		for (j = 0; j < s->attrVal[i].numVals; j++) {
			if (addAttr2RuleValue(s->attrVal[i].type,
					s->attrName[i],
					s->attrVal[i].val[j].value,
					s->attrVal[i].val[j].length,
					t))
				return (-1);
		}
	}

	return (0);
}

static int
addVal2RuleValue(char *msg, int caseSens, int snipNul, __nis_value_type_t type,
		char *name, void *value, int valueLen,
		int *numP, char ***inNameP, __nis_value_t **inValP) {
	int			i, j, copyLen = valueLen;
	__nis_single_value_t	*v;
	char			**inName = *inNameP;
	__nis_value_t		*inVal = *inValP;
	int			num = *numP;
	int			(*comp)(const char *s1, const char *s2);
	char			*myself = "addVal2RuleValue";

	/* Internal function, so assume arguments OK */

	if (msg == 0)
		msg = myself;

	/* Should we match the 'inName' value case sensitive or not ? */
	if (caseSens)
		comp = strcmp;
	else
		comp = strcasecmp;

	/*
	 * String-valued NIS+ entries count the concluding NUL in the
	 * length, while LDAP entries don't. In order to support this,
	 * we implement the following for vt_string value types:
	 *
	 * If the last byte of the value isn't a NUL, add one to the
	 * allocated length, so that there always is a NUL after the
	 * value, making it safe to pass to strcmp() etc.
	 *
	 * If 'snipNul' is set (presumably meaning we're inserting a
	 * value derived from a NIS+ entry), and the last byte of the
	 * value already is a NUL, decrement the length to be copied by
	 * one. This (a) doesn't count the NUL in the value length, but
	 * (b) still leaves a NUL following the value.
	 *
	 * In N2L, for all cases we set 'copyLen' to the number of non-0
	 * characters in 'value'.
	 */
	if (type == vt_string && valueLen > 0) {
		char	*charval = value;

		if (charval[valueLen-1] != '\0')
			valueLen += 1;
		else if (yp2ldap || snipNul)
			copyLen -= 1;
	} else if (valueLen == 0) {
		/*
		 * If the 'value' pointer is non-NULL, we create a zero-
		 * length value with one byte allocated. This takes care
		 * of empty strings.
		 */
		valueLen += 1;
	}

	/* If we already have values for this attribute, add another one */
	for (i = 0; i < num; i++) {
		if ((*comp)(inName[i], name) == 0) {

			/*
			 * Our caller often doesn't know the type of the
			 * value; this happens because the type (vt_string
			 * or vt_ber) is determined by the format in the
			 * rule sets, and we may be invoked as a preparation
			 * for evaluating the rules. Hence, we only use the
			 * supplied 'type' if we need to create a value.
			 * Otherwise, we accept mixed types.
			 *
			 * Strings are OK in any case, since we always make
			 * sure to have a zero byte at the end of any value,
			 * whatever the type.
			 */

			if (inVal[i].numVals < 0) {
				/*
				 * Used to indicate deletion of attribute,
				 * so we honor that and don't add a value.
				 */
				return (0);
			}

			/*
			 * If 'value' is NULL, we should delete, so
			 * remove any existing values, and set the
			 * 'numVals' field to -1.
			 */
			if (value == 0) {
				for (j = 0; j < inVal[i].numVals; j++) {
					sfree(inVal[i].val[j].value);
				}
				sfree(inVal[i].val);
				inVal[i].val = 0;
				inVal[i].numVals = -1;
				return (0);
			}

			/* Is the value a duplicate ? */
			for (j = 0; j < inVal[i].numVals; j++) {
				if (copyLen == inVal[i].val[j].length &&
					memcmp(value, inVal[i].val[j].value,
						copyLen) == 0) {
					break;
				}
			}
			if (j < inVal[i].numVals)
				return (0);

			/* Not a duplicate, so add the name/value pair */
			v = realloc(inVal[i].val,
					(inVal[i].numVals+1) *
					sizeof (inVal[i].val[0]));
			if (v == 0)
				return (-1);
			inVal[i].val = v;
			v[inVal[i].numVals].length = copyLen;
			v[inVal[i].numVals].value = am(msg, valueLen);
			if (v[inVal[i].numVals].value == 0 &&
					value != 0) {
				sfree(v);
				return (-1);
			}
			memcpy(v[inVal[i].numVals].value, value, copyLen);
			inVal[i].numVals++;

			return (0);
		}
	}

	/* No previous value for this attribute */

	/*
	 * value == 0 means deletion, in which case we create a
	 * __nis_value_t with the numVals field set to -1.
	 */
	if (value != 0) {
		if ((v = am(msg, sizeof (*v))) == 0)
			return (-1);
		v->length = copyLen;
		v->value = am(msg, valueLen);
		if (v->value == 0 && value != 0) {
			sfree(v);
			return (-1);
		}
		memcpy(v->value, value, copyLen);
	}

	inVal = realloc(inVal, (num+1)*sizeof (inVal[0]));
	if (inVal == 0) {
		if (value != 0) {
			sfree(v->value);
			sfree(v);
		}
		return (-1);
	}
	*inValP = inVal;

	inName = realloc(inName,
		(num+1)*sizeof (inName[0]));
	if (inName == 0 || (inName[num] =
			sdup(msg, T, name)) == 0) {
		sfree(v->value);
		sfree(v);
		return (-1);
	}
	*inNameP = inName;

	inVal[num].type = type;
	inVal[num].repeat = 0;
	if (value != 0) {
		inVal[num].numVals = 1;
		inVal[num].val = v;
	} else {
		inVal[num].numVals = -1;
		inVal[num].val = 0;
	}

	*numP += 1;

	return (0);
}

int
addAttr2RuleValue(__nis_value_type_t type, char *name, void *value,
		int valueLen, __nis_rule_value_t *rv) {
	char			*myself = "addAttr2RuleValue";

	if (name == 0 || rv == 0)
		return (-1);

	return (addVal2RuleValue(myself, 0, 0, type, name, value, valueLen,
				&rv->numAttrs, &rv->attrName, &rv->attrVal));
}

int
addSAttr2RuleValue(char *name, char *value, __nis_rule_value_t *rv) {
	return (addAttr2RuleValue(vt_string, name, value, slen(value), rv));
}

int
addCol2RuleValue(__nis_value_type_t type, char *name, void *value,
		int valueLen, __nis_rule_value_t *rv) {
	char *myself = "addCol2RuleValue";

	if (name == 0 || rv == 0)
		return (-1);

	return (addVal2RuleValue(myself, 1, 1, type, name, value, valueLen,
				&rv->numColumns, &rv->colName, &rv->colVal));
}

int
addSCol2RuleValue(char *name, char *value, __nis_rule_value_t *rv) {
	return (addCol2RuleValue(vt_string, name, value, slen(value), rv));
}

/*
 * Given a table mapping, a NIS+ DB query, and (optionally) an existing
 * and compatible __nis_rule_value_t, return a new __nis_rule_value_t
 * with the values from the query added.
 */
__nis_rule_value_t *
buildNisPlusRuleValue(__nis_table_mapping_t *t, db_query *q,
			__nis_rule_value_t *rv) {
	int			i;

	if (t == 0 || q == 0)
		return (0);

	rv = initRuleValue(1, rv);
	if (rv == 0)
		return (0);

	for (i = 0; i < q->components.components_len; i++) {

		/* Ignore out-of-range column index */
		if (q->components.components_val[i].which_index >=
				t->numColumns)
			continue;

		/*
		 * Add the query value. A NULL value indicates deletion,
		 * but addCol2RuleValue() takes care of that for us.
		 */
		if (addCol2RuleValue(vt_string,
				t->column[q->components.components_val[i].
						which_index],
				q->components.components_val[i].index_value->
					itemvalue.itemvalue_val,
				q->components.components_val[i].index_value->
					itemvalue.itemvalue_len, rv) != 0) {
			freeRuleValue(rv, 1);
			rv = 0;
			break;
		}
	}

	return (rv);
}


/*
 * Given a LHS rule 'rl', return an array containing the item names,
 * and the number of elements in the array in '*numItems'.
 *
 * If there are 'me_match' __nis_mapping_element_t's, we use the
 * supplied '*rval' (if any) to derive values for the items in
 * the 'me_match', and add the values thus derived to '*rval' (in
 * which case the '*rval' pointer will change; the old '*rval'
 * is deleted).
 */
__nis_mapping_item_t *
buildLvalue(__nis_mapping_rlhs_t *rl, __nis_value_t **rval, int *numItems) {
	__nis_value_t		*val, *r;
	__nis_mapping_item_t	*item = 0;
	int			i, n, ni = 0, nv = 0;
	int			repeat = 0;

	if (rl == 0)
		return (0);

	if (rval != 0) {
		r = *rval;
		repeat = r->repeat;
	} else
		r = 0;

	/* If there is more than one element, we concatenate the items */
	for (i = 0; i < rl->numElements; i++) {
		__nis_mapping_element_t	*e = &rl->element[i];
		__nis_mapping_item_t	*olditem, *tmpitem = 0;
		__nis_value_t		**tmp;

		switch (e->type) {
		case me_item:
			tmpitem = cloneItem(&e->element.item);
			break;
		case me_match:
			/*
			 * Obtain values for the items in the 'me_match'
			 * element.
			 */
			tmp = matchMappingItem(e->element.match.fmt, r, &nv,
				0, 0);
			if (tmp != 0) {
				freeValue(r, 1);
				val = 0;
				for (n = 0; n < nv; n++) {
					r = concatenateValues(val, tmp[n]);
					freeValue(val, 1);
					freeValue(tmp[n], 1);
					val = r;
					if (val == 0) {
						for (n++; n < nv; n++) {
							freeValue(tmp[n], 1);
						}
						break;
					}
				}
				free(tmp);
				if (rval != 0) {
					if (repeat && val != 0)
						val->repeat = repeat;
					*rval = val;
				}
				for (n = 0; n < e->element.match.numItems;
						n++) {
					olditem = item;
					item = concatenateMappingItem(item, ni,
						&e->element.match.item[n]);
					freeMappingItem(olditem, ni);
					if (item == 0) {
						ni = 0;
						break;
					}
					ni++;
				}
			}
			break;
		case me_print:
		case me_split:
		case me_extract:
		default:
			/* These shouldn't show up on the LHS; ignore */
			break;
		}

		if (tmpitem != 0) {
			olditem = item;
			item = concatenateMappingItem(item, ni, tmpitem);
			freeMappingItem(olditem, ni);
			freeMappingItem(tmpitem, 1);
			ni++;
			if (item == 0) {
				ni = 0;
				break;
			}
		}
	}

	if (numItems != 0)
		*numItems = ni;

	return (item);
}

__nis_value_t *
buildRvalue(__nis_mapping_rlhs_t *rl, __nis_mapping_item_type_t native,
		__nis_rule_value_t *rv, int *stat) {
	__nis_value_t	*val, *vold = 0, *vnew;
	int		i;
	char		*myself = "buildRvalue";

	if (rl == 0 || rl->numElements <= 0) {
		/*
		 * No RHS indicates deletion, as does a __nis_value_t
		 * with numVals == -1, so we return such a creature.
		 */
		val = am(myself, sizeof (*val));
		if (val != 0) {
			val->type = vt_string;
			val->numVals = -1;
		}
		return (val);
	}

	/* If there is more than one element, we concatenate the values */
	for (i = 0; i < rl->numElements; i++) {
		vnew = getMappingElement(&rl->element[i], native, rv, stat);
		val = concatenateValues(vold, vnew);
		freeValue(vnew, 1);
		freeValue(vold, 1);
		vold = val;
	}
	return (val);
}

/*
 * Derive values for the LDAP attributes specified by the rule 'r',
 * and add them to the rule-value 'rv'.
 *
 * If 'doAssign' is set, out-of-context assignments are performed,
 * otherwise not.
 */
__nis_rule_value_t *
addLdapRuleValue(__nis_table_mapping_t *t,
			__nis_mapping_rule_t *r,
			__nis_mapping_item_type_t lnative,
			__nis_mapping_item_type_t rnative,
			__nis_rule_value_t *rv,
			int doAssign, int *stat) {
	int			i, j;
	__nis_value_t		*rval, *lval;
	__nis_mapping_item_t	*litem;
	int			numItems;
	char			**dn = 0;
	int			numDN = 0;
	char			*myself = "addLdapRuleValue";


	/* Do we have the required values ? */
	if (rv == 0)
		return (0);

	/*
	 * Establish appropriate search base. For rnative == mit_nisplus,
	 * we're deriving LDAP attribute values from NIS+ columns; in other
	 * words, we're writing to LDAP, and should use the write.base value.
	 */
	__nisdb_get_tsd()->searchBase = (rnative == mit_nisplus) ?
		t->objectDN->write.base : t->objectDN->read.base;

	/* Set escapeFlag if LHS is "dn" to escape special chars */
	if (yp2ldap && r->lhs.numElements == 1 &&
		r->lhs.element->type == me_item &&
		r->lhs.element->element.item.type == mit_ldap &&
		strcasecmp(r->lhs.element->element.item.name, "dn") == 0) {
			__nisdb_get_tsd()->escapeFlag = '1';
	}

	/* Build the RHS value */
	rval = buildRvalue(&r->rhs, rnative, rv, stat);

	/* Reset escapeFlag */
	__nisdb_get_tsd()->escapeFlag = '\0';

	if (rval == 0)
		return (rv);

	/*
	 * Special case: If we got no value for the RHS (presumably because
	 * we're missing one or more item values), we don't produce an lval.
	 * Note that this isn't the same thing as an empty value, which we
	 * faithfully try to transmit to LDAP.
	 */
	if (rval->numVals == 1 && rval->val[0].value == 0) {
		freeValue(rval, 1);
		return (rv);
	}

	/* Obtain the LHS item names */
	litem = buildLvalue(&r->lhs, &rval, &numItems);
	if (litem == 0) {
		freeValue(rval, 1);
		return (rv);
	}

	/* Get string representations of the LHS item names */
	lval = 0;
	for (i = 0; i < numItems; i++) {
		__nis_value_t	*tmpval, *old;

		tmpval = getMappingItem(&litem[i], lnative, 0, 0, NULL);

		/*
		 * If the LHS item is out-of-context, we do the
		 * assignment right here.
		 */
		if (doAssign && litem[i].type == mit_ldap &&
				litem[i].searchSpec.triple.scope !=
					LDAP_SCOPE_UNKNOWN &&
				slen(litem[i].searchSpec.triple.base) > 0 &&
				(slen(litem[i].searchSpec.triple.attrs) > 0 ||
				litem[i].searchSpec.triple.element != 0)) {
			int	stat;

			if (dn == 0)
				dn = findDNs(myself, rv, 1,
					t->objectDN->write.base,
					&numDN);

			stat = storeLDAP(&litem[i], i, numItems, rval,
				t->objectDN, dn, numDN);
			if (stat != LDAP_SUCCESS) {
				char	*iname = "<unknown>";

				if (tmpval != 0 &&
						tmpval->numVals == 1)
					iname = tmpval->val[0].value;
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: LDAP store \"%s\": %s",
					myself, iname,
					ldap_err2string(stat));
			}

			freeValue(tmpval, 1);
			continue;
		}

		old = lval;
		lval = concatenateValues(old, tmpval);
		freeValue(tmpval, 1);
		freeValue(old, 1);
	}

	/* Don't need the LHS items themselves anymore */
	freeMappingItem(litem, numItems);

	/*
	 * If we don't have an 'lval' (probably because all litem[i]:s
	 * were out-of-context assignments), we're done.
	 */
	if (lval == 0 || lval->numVals <= 0) {
		freeValue(lval, 1);
		freeValue(rval, 1);
		return (rv);
	}

	for (i = 0, j = 0; i < lval->numVals; i++) {
		/* Special case: rval->numVals < 0 means deletion */
		if (rval->numVals < 0) {
			(void) addAttr2RuleValue(rval->type,
				lval->val[i].value, 0, 0, rv);
			continue;
		}
		/* If we're out of values, repeat the last one */
		if (j >= rval->numVals)
			j = (rval->numVals > 0) ? rval->numVals-1 : 0;
		for (; j < rval->numVals; j++) {
			/*
			 * If this is the 'dn', and the value ends in a
			 * comma, append the appropriate search base.
			 */
			if (strcasecmp("dn", lval->val[i].value) == 0 &&
					lastChar(&rval->val[j]) == ',' &&
					t->objectDN->write.scope !=
						LDAP_SCOPE_UNKNOWN) {
				void	*nval;
				int	nlen = -1;

				nval = appendString2SingleVal(
					t->objectDN->write.base, &rval->val[j],
					&nlen);
				if (nval != 0 && nlen >= 0) {
					sfree(rval->val[j].value);
					rval->val[j].value = nval;
					rval->val[j].length = nlen;
				}
			}
			(void) addAttr2RuleValue(rval->type,
				lval->val[i].value, rval->val[j].value,
				rval->val[j].length, rv);
			/*
			 * If the lval is multi-valued, go on to the
			 * other values; otherwise, quit (but increment
			 * the 'rval' value index).
			 */
			if (!lval->repeat) {
				j++;
				break;
			}
		}
	}

	/* Clean up */
	freeValue(lval, 1);
	freeValue(rval, 1);

	return (rv);
}

/*
 * Remove the indicated attribute, and any values for it, from the
 * rule-value.
 */
void
delAttrFromRuleValue(__nis_rule_value_t *rv, char *attrName) {
	int	i;

	if (rv == 0 || attrName == 0)
		return;

	for (i = 0; i < rv->numAttrs; i++) {
		if (strcasecmp(attrName, rv->attrName[i]) == 0) {
			int	j;

			for (j = 0; j < rv->attrVal[i].numVals; j++)
				sfree(rv->attrVal[i].val[j].value);
			if (rv->attrVal[i].numVals > 0)
				sfree(rv->attrVal[i].val);

			sfree(rv->attrName[i]);

			/* Move up the rest of the attribute names/values */
			for (j = i+1; j < rv->numAttrs; j++) {
				rv->attrName[j-1] = rv->attrName[j];
				rv->attrVal[j-1] = rv->attrVal[j];
			}

			rv->numAttrs -= 1;

			break;
		}
	}
}

/*
 * Remove the indicated column, and any values for it, from the
 * rule-value.
 */
void
delColFromRuleValue(__nis_rule_value_t *rv, char *colName) {
	int	i;

	if (rv == 0 || colName == 0)
		return;

	for (i = 0; i < rv->numColumns; i++) {
		if (strcmp(colName, rv->colName[i]) == 0) {
			int	j;

			for (j = 0; j < rv->colVal[i].numVals; j++)
				sfree(rv->colVal[i].val[j].value);
			if (rv->colVal[i].numVals > 0)
				sfree(rv->colVal[i].val);

			sfree(rv->colName[i]);

			/* Move up the rest of the column names/values */
			for (j = i+1; j < rv->numColumns; j++) {
				rv->colName[j-1] = rv->colName[j];
				rv->colVal[j-1] = rv->colVal[j];
			}

			rv->numColumns -= 1;

			break;
		}
	}
}

/*
 * Add the write-mode object classes specified by 'objClassAttrs' to the
 * rule-value 'rv'.
 * If there's an error, 'rv' is deleted, and NULL returned.
 */
__nis_rule_value_t *
addObjectClasses(__nis_rule_value_t *rv, char *objClassAttrs) {
	char	*filter = 0, **fc = 0;
	int	i, nfc = 0;

	/*
	 * Expect to only use this for existing rule-values, so rv == 0 is
	 * an error.
	 */
	if (rv == 0)
		return (0);

	/*
	 * If 'objClassAttrs' is NULL, we trivially have nothing to do.
	 * Assume the caller knows what it's doing, and return success.
	 */
	if (objClassAttrs == 0)
		return (rv);

	/*
	 * Make an AND-filter of the object classes, and split into
	 * components. (Yes, this is a bit round-about, but leverages
	 * existing functions.)
	 */
	filter = makeFilter(objClassAttrs);
	if (filter == 0) {
		freeRuleValue(rv, 1);
		return (0);
	}

	fc = makeFilterComp(filter, &nfc);
	if (fc == 0 || nfc <= 0) {
		free(filter);
		freeRuleValue(rv, 1);
		return (0);
	}

	/* Add the objectClass attributes to the rule-value */
	for (i = 0; i < nfc; i++) {
		char	*name, *value;

		name = fc[i];
		/* Skip if not of the "name=value" form */
		if ((value = strchr(name, '=')) == 0)
			continue;

		*value = '\0';
		value++;

		/* Skip if the attribute name isn't "objectClass" */
		if (strcasecmp("objectClass", name) != 0)
			continue;

		if (addSAttr2RuleValue(name, value, rv) != 0) {
			free(filter);
			freeFilterComp(fc, nfc);
			freeRuleValue(rv, 1);
			return (0);
		}
	}

	free(filter);
	freeFilterComp(fc, nfc);

	return (rv);
}


static char *
valString(__nis_value_t *val) {
	int	i;

	if (val == 0 || val->type != vt_string)
		return (0);

	for (i = 0; i < val->numVals; i++) {
		/* Look for a non-NULL, non-zero length value */
		if (val->val[i].value != 0 && val->val[i].length > 0) {
			char	*v = val->val[i].value;

			/*
			 * Check that there's a NUL at the end. True,
			 * if there isn't, we may be looking beyond
			 * allocated memory. However, we would have done
			 * so in any case when the supposed string was
			 * traversed (printed, etc.), very possibly by
			 * a lot more than one byte. So, it's better to
			 * take a small risk here than a large one later.
			 */
			if (v[val->val[i].length-1] == '\0' ||
					v[val->val[i].length] == '\0')
				return (v);
		}
	}

	return (0);
}

char *
findVal(char *name, __nis_rule_value_t *rv, __nis_mapping_item_type_t type) {
	int	i;

	if (type == mit_nisplus) {
		for (i = 0; i < rv->numColumns; i++) {
			if (rv->colName[i] == 0)
				continue;
			if (strcmp(name, rv->colName[i]) == 0) {
				return (valString(&rv->colVal[i]));
			}
		}
	} else if (type == mit_ldap) {
		for (i = 0; i < rv->numAttrs; i++) {
			if (rv->attrName[i] == 0)
				continue;
			if (strcasecmp(name, rv->attrName[i]) == 0) {
				return (valString(&rv->attrVal[i]));
			}
		}
	}

	return (0);
}

static char	*norv = "<NIL>";
static char	*unknown = "<unknown>";

/*
 * Attempt to derive a string identifying the rule-value 'rv'. The
 * returned string is a pointer, either into 'rv', or to static
 * storage, and must not be freed.
 */
char *
rvId(__nis_rule_value_t *rv, __nis_mapping_item_type_t type) {
	char	*v;

	if (rv == 0)
		return (norv);

	if (rv->numColumns > 0 && type == mit_nisplus) {
		/*
		 * Look for a column called "cname" or "name".
		 * If that fails, try "key" or "alias".
		 */
		if ((v = findVal("cname", rv, type)) != 0)
			return (v);
		else if ((v = findVal("name", rv, type)) != 0)
			return (v);
		else if ((v = findVal("key", rv, type)) != 0)
			return (v);
		else if ((v = findVal("alias", rv, type)) != 0)
			return (v);
	} else if (rv->numAttrs > 0 && type == mit_ldap) {
		/*
		 * Look for "dn", or "cn".
		 */
		if ((v = findVal("dn", rv, type)) != 0)
			return (v);
		else if ((v = findVal("cn", rv, type)) != 0)
			return (v);
	}

	return (unknown);
}

/*
 * Merge the rule-values with the same DN into one. Each rule-value
 * in the returned array will have unique 'dn'. On entry, *numVals
 * contains the number of rule-values in 'rv'. On exit, it contains
 * the number of rule-values in the returned array or -1 on error.
 */
__nis_rule_value_t *
mergeRuleValueWithSameDN(__nis_rule_value_t *rv, int *numVals) {
	__nis_rule_value_t	*rvq = 0;
	char			*dn, *odn;
	int			count = 0;
	int			i, j;

	if (numVals == 0)
		return (0);

	for (i = 0; i < *numVals; i++) {
		if ((dn = findVal("dn", &rv[i], mit_ldap)) != 0) {
			for (j = 0; j < count; j++) {
				if ((odn = findVal("dn", &rvq[j],
						mit_ldap)) != 0) {
					/* case sensitive compare */
					if (strcmp(dn, odn) != 0)
						continue;
					if (mergeRuleValue(&rvq[j],
							&rv[i]) == -1) {
						freeRuleValue(rvq, count);
						*numVals = -1;
						return (0);
					}
					break;
				} else {
					freeRuleValue(rvq, count);
					*numVals = -1;
					return (0);
				}
			}
			/* if no match, then add it to the rulevalue array */
			if (j == count) {
				rvq = growRuleValue(count, count + 1, rvq,
									&rv[i]);
				if (rvq == 0) {
					*numVals = -1;
					return (0);
				}
				count++;
			}
		}
	}

	*numVals = count;
	return (rvq);
}
