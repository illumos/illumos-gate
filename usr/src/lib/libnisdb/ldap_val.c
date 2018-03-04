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
#include <errno.h>

#include "nisdb_mt.h"

#include "ldap_util.h"
#include "ldap_op.h"
#include "ldap_ruleval.h"
#include "ldap_attr.h"
#include "ldap_val.h"
#include "ldap_ldap.h"

extern int yp2ldap;


__nis_mapping_format_t *
cloneMappingFormat(__nis_mapping_format_t *m) {
	__nis_mapping_format_t	*new;
	int			i, nf, err;
	char			*myself = "cloneMappingFormat";

	if (m == 0)
		return (0);

	for (nf = 0; m[nf].type != mmt_end; nf++);
	nf++;

	new = am(myself, nf * sizeof (new[0]));
	if (new == 0)
		return (0);

	/* Copy the whole array */
	memcpy(new, m, nf * sizeof (new[0]));

	/* Make copies of allocated stuff */
	for (i = 0, err = 0; i < nf; i++) {
		switch (m[i].type) {
		case mmt_string:
			new[i].match.string = sdup(myself, T,
							m[i].match.string);
			if (new[i].match.string == 0 && m[i].match.string != 0)
				err++;
			break;
		case mmt_single:
			new[i].match.single.lo =
				am(myself, m[i].match.single.numRange *
					sizeof (new[i].match.single.lo[0]));
			new[i].match.single.hi =
				am(myself, m[i].match.single.numRange *
					sizeof (new[i].match.single.hi[0]));
			if (new[i].match.single.lo != 0)
				memcpy(new[i].match.single.lo,
					m[i].match.single.lo,
					m[i].match.single.numRange);
			else if (m[i].match.single.lo != 0)
				err++;
			if (new[i].match.single.hi != 0)
				memcpy(new[i].match.single.hi,
					m[i].match.single.hi,
					m[i].match.single.numRange);
			else if (m[i].match.single.hi != 0)
				err++;
			break;
		case mmt_berstring:
			new[i].match.berString = sdup(myself, T,
							m[i].match.berString);
			if (new[i].match.berString == 0 &&
					m[i].match.berString != 0)
				err++;
			break;
		case mmt_item:
		case mmt_limit:
		case mmt_any:
		case mmt_begin:
		case mmt_end:
		default:
			break;
		}
	}

	/* If there were memory allocation errors, free the copy */
	if (err > 0) {
		freeMappingFormat(new);
		new = 0;
	}

	return (new);
}

void
freeMappingFormat(__nis_mapping_format_t *m) {
	int	i;

	if (m == 0)
		return;

	for (i = 0; m[i].type != mmt_end; i++) {
		switch (m[i].type) {
		case mmt_string:
			sfree(m[i].match.string);
			break;
		case mmt_single:
			sfree(m[i].match.single.lo);
			sfree(m[i].match.single.hi);
			break;
		case mmt_berstring:
			sfree(m[i].match.berString);
			break;
		case mmt_item:
		case mmt_limit:
		case mmt_any:
		case mmt_begin:
		case mmt_end:
		default:
			break;
		}
	}

	free(m);
}


void
copyIndex(__nis_index_t *old, __nis_index_t *new, int *err) {
	int	i;
	char	*myself = "copyIndex";

	if (old == 0 || new == 0) {
		*err = EINVAL;
		return;
	}

	for (i = 0; i < old->numIndexes; i++) {
		new->name[i] = sdup(myself, T, old->name[i]);
		if (new->name[i] == 0 && old->name[i] != 0) {
			*err = ENOMEM;
			return;
		}
		new->value[i] = cloneMappingFormat(old->value[i]);
		if (new->value[i] == 0 && old->value[i] != 0) {
			*err = ENOMEM;
			return;
		}
	}

	new->numIndexes = old->numIndexes;
}

__nis_index_t *
cloneIndex(__nis_index_t *old) {
	char		*myself = "cloneIndex";
	int		err = 0;
	__nis_index_t	*new = am(myself, sizeof (*new));

	if (old == 0)
		return (0);

	if (new != 0) {
		copyIndex(old, new, &err);
		if (err != 0) {
			freeIndex(new, 1);
			new = 0;
		}
	}

	return (new);
}

void
freeIndex(__nis_index_t *old, bool_t doFree) {
	int	i;

	if (old == 0)
		return;

	for (i = 0; i < old->numIndexes; i++) {
		sfree(old->name[i]);
		freeMappingFormat(old->value[i]);
	}

	if (doFree)
		free(old);
}

char **
cloneName(char **name, int numNames) {
	char	**new;
	int	i;
	char	*myself = "cloneName";

	if (name == 0 || numNames <= 0)
		return (0);

	new = am(myself, numNames * sizeof (new[0]));
	if (new == 0)
		return (0);

	for (i = 0; i < numNames; i++) {
		if (name[i] != 0) {
			new[i] = sdup(myself, T, name[i]);
			if (new[i] == 0) {
				for (i--; i >= 0; i--) {
					sfree(new[i]);
				}
				sfree(new);
				return (0);
			}
		} else {
			new[i] = 0;
		}
	}

	return (new);
}

void
freeValue(__nis_value_t *val, int count) {
	int	c, i;

	if (val == 0)
		return;

	for (c = 0; c < count; c++) {
		if (val[c].val != 0) {
			for (i = 0; i < val[c].numVals; i++) {
				sfree(val[c].val[i].value);
			}
			free(val[c].val);
		}
	}

	free(val);
}

__nis_value_t *
cloneValue(__nis_value_t *val, int count) {
	__nis_value_t	*n;
	int		c, i;
	char		*myself = "cloneValue";

	if (count <= 0 || val == 0)
		return (0);

	n = am(myself, count * sizeof (*n));
	if (n == 0)
		return (0);

	for (c = 0; c < count; c++) {
		n[c].type = val[c].type;
		n[c].repeat = val[c].repeat;
		n[c].numVals = val[c].numVals;
		if (n[c].numVals > 0) {
			n[c].val = am(myself, n[c].numVals *
						sizeof (n[c].val[0]));
			if (n[c].val == 0) {
				freeValue(n, c);
				return (0);
			}
		} else {
			n[c].val = 0;
		}
		for (i = 0; i < n[c].numVals; i++) {
			int	amlen = val[c].val[i].length;

			/*
			 * The functions that create string values try to
			 * make sure that there's a NUL at the end. However,
			 * both NIS+ and LDAP have a tendency to store strings
			 * without a NUL, so the value length may not include
			 * the NUL (even though it's there). In order to
			 * preserve that NUL, we add a byte to the length if
			 * the type is vt_string, and there isn't already a
			 * NUL at the end. The memory allocation function
			 * (am()) will take care of actually putting the NUL
			 * in place, since it allocates zero-initialized
			 * memory.
			 */
			n[c].val[i].length = val[c].val[i].length;
			if (n[c].type == vt_string && amlen > 0 &&
				((char *)val[c].val[i].value)[amlen-1] !=
					'\0') {
				amlen++;
			}
			n[c].val[i].value = am(myself, amlen);
			if (amlen > 0 && n[c].val[i].value == 0) {
				freeValue(n, c);
				return (0);
			}
			memcpy(n[c].val[i].value, val[c].val[i].value,
				n[c].val[i].length);
		}
	}

	return (n);
}

/* Define LBER_USE_DER per ber_decode(3LDAP) */
#ifndef	LBER_USE_DER
#define	LBER_USE_DER	0x01
#endif	/* LBER_USE_DER */

/*
 * Return a copy of 'valIn' where each value has been replaced by the
 * BER encoded equivalent specified by 'berstring'. 'valIn' is unchanged.
 */
__nis_value_t *
berEncode(__nis_value_t *valIn, char *berstring) {
	char		*myself = "berEncode";
	__nis_value_t	*val;
	int		i;

	if (valIn == 0 || berstring == 0)
		return (0);

	val = cloneValue(valIn, 1);
	if (val == 0)
		return (0);

	for (i = 0; i < val->numVals; i++) {
		BerElement	*ber = ber_alloc();
		struct berval	*bv = 0;
		int		ret;

		if (ber == 0) {
			logmsg(MSG_NOMEM, LOG_ERR, "%s: ber_alloc() => NULL",
				myself);
			freeValue(val, 1);
			return (0);
		}

		if ((strcmp("b", berstring) == 0 ||
				strcmp("i", berstring) == 0)) {
			if (val->val[i].length >= sizeof (int)) {
				ret = ber_printf(ber, berstring,
					*((int *)(val->val[i].value)));
			} else {
				ret = -1;
			}
		} else if (strcmp("B", berstring) == 0) {
			ret = ber_printf(ber, berstring,
				val->val[i].value,
				val->val[i].length * 8);
		} else if (strcmp("n", berstring) == 0) {
			ret = ber_printf(ber, berstring);
		} else if (strcmp("o", berstring) == 0) {
			ret = ber_printf(ber, berstring,
				val->val[i].value, val->val[i].length);
		} else if (strcmp("s", berstring) == 0) {
			char	*str = am(myself, val->val[i].length + 1);

			if (str != 0) {
				ret = ber_printf(ber, berstring, str);
				free(str);
			} else {
				ret = -1;
			}
		} else {
			ret = -1;
		}

		if (ret == -1) {
			reportError(NPL_BERENCODE, "%s: BER encoding error",
					myself);
			ber_free(ber, 1);
			freeValue(val, 1);
			return (0);
		}

		if (ber_flatten(ber, &bv) != 0 || bv == 0) {
			reportError(NPL_BERENCODE, "%s: ber_flatten() error",
					myself);
			ber_free(ber, 1);
			freeValue(val, 1);
			return (0);
		}

		sfree(val->val[i].value);
		val->val[i].length = bv->bv_len;
		val->val[i].value = bv->bv_val;

		ber_free(ber, 1);
	}

	val->type = vt_ber;

	return (val);
}

__nis_value_t *
berDecode(__nis_value_t *valIn, char *berstring) {
	__nis_value_t	*val;
	int		i;
	char		*myself = "berDecode";

	if (valIn == 0 || berstring == 0)
		return (0);

	val = cloneValue(valIn, 1);
	if (val == 0)
		return (0);

	for (i = 0; i < val->numVals; i++) {
		void		*v = 0;
		int		ret, len = 0;
		struct berval	bv;
		BerElement	*ber;

		if (val->val[i].value == 0 || val->val[i].length <= 0)
			continue;

		bv.bv_val = val->val[i].value;
		bv.bv_len = val->val[i].length;
		ber = ber_init(&bv);
		if (ber == 0) {
			reportError(NPL_BERDECODE, "%s: ber_init() error",
				myself);
			freeValue(val, 1);
			return (0);
		}

		if ((strcmp("b", berstring) == 0 ||
				strcmp("i", berstring) == 0)) {
			len = sizeof (int);
			v = am(myself, len);
			if (v != 0) {
				ret = ber_scanf(ber, berstring, v);
			} else {
				ret = -1;
			}
		} else if (strcmp("B", berstring) == 0) {
			long	llen;

			ret = ber_scanf(ber, berstring, &v, &llen);
			if (ret != -1) {
				len = llen/8;
			}
		} else if (strcmp("n", berstring) == 0) {
			ret = 0;
		} else if (strcmp("o", berstring) == 0) {
			struct berval	*bv = am(myself, sizeof (*bv));

			if (bv != 0) {
				ret = ber_scanf(ber, "O", &bv);
				if (ret != -1 && bv != 0) {
					v = bv->bv_val;
					len = bv->bv_len;
				} else {
					ret = -1;
				}
				/* Only free 'bv' itself */
				free(bv);
			} else {
				ret = -1;
			}
		} else if (strcmp("s", berstring) == 0) {
			ret = ber_scanf(ber, "a", &v);
			if (ret != -1) {
				len = slen(v);
			}
		} else {
			ret = -1;
		}

		if (ret == -1) {
			reportError(NPL_BERDECODE, "%s: BER decoding error",
					myself);
			freeValue(val, 1);
			return (0);
		}

		/* Free the old value, and replace it with the decoded one */
		sfree(val->val[i].value);
		val->val[i].value = v;
		val->val[i].length = len;
	}

	return (val);
}

/*
 * Return the value of the specified item.
 */
__nis_value_t *
getMappingItemVal(__nis_mapping_item_t *item, __nis_mapping_item_type_t native,
		__nis_rule_value_t *rv, char *berstring, int *np_ldap_stat) {
	__nis_value_t				*val = 0, *nameVal, *exVal = 0;
	int					numName, caseInsens, cmp;
	int					i, j, k;
	char					**name;
	enum {rvOnly, rvThenLookup, lookupOnly}	check;
	unsigned char				fromldap = '\0';

	if (item == 0)
		return (0);

	/*
	 * First, we decide if we should look for the value in 'rv',
	 * directly from NIS+/LDAP, or both.
	 */
	switch (item->type) {
	case mit_nisplus:
		/* Do we have a valid index/object spec ? */
		if (item->searchSpec.obj.index.numIndexes <= 0 &&
				item->searchSpec.obj.name == 0) {
			/*
			 * No valid index/object. If we have a rule-value,
			 * use it. Otherwise, return error.
			 */
			if (rv != 0) {
				name = rv->colName;
				nameVal = rv->colVal;
				numName = rv->numColumns;
				caseInsens = 0;
				check = rvOnly;
			} else {
				return (0);
			}
		} else {
			/*
			 * Valid index, so skip the rule-value and do
			 * a direct NIS+ lookup.
			 */
			check = lookupOnly;
		}
		break;
	case mit_ldap:
		if (rv != 0) {
			name = rv->attrName;
			nameVal = rv->attrVal;
			numName = rv->numAttrs;
			caseInsens = 1;
			fromldap = '1';
		}
		/* Do we have a valid triple ? */
		if (item->searchSpec.triple.scope == LDAP_SCOPE_UNKNOWN) {
			/*
			 * No valid triple. If we have a rule-value, use it.
			 * Otherwise, return error.
			 */
			if (rv != 0) {
				check = rvOnly;
			} else {
				return (0);
			}
		} else if (item->searchSpec.triple.base == 0 &&
				item->searchSpec.triple.scope ==
					LDAP_SCOPE_ONELEVEL &&
				item->searchSpec.triple.attrs == 0 &&
				item->searchSpec.triple.element == 0) {
			/*
			 * We have a valid triple, but it points to the
			 * current LDAP container. Thus, first look in
			 * the rule-value; if that fails, perform a direct
			 * LDAP lookup.
			 */
			if (rv != 0) {
				check = rvThenLookup;
			} else {
				check = lookupOnly;
			}
		} else {
			/*
			 * Valid triple, and it's not the current container
			 * (at least not in the trivial sense). Hence, do
			 * a direct LDAP lookup.
			 */
			check = lookupOnly;
		}
		break;
	default:
		return (0);
	}

	/* Check the rule-value */
	if (check == rvOnly || check == rvThenLookup) {
		for (i = 0; i < numName; i++) {
			if (caseInsens)
				cmp = strcasecmp(item->name, name[i]);
			else
				cmp = strcmp(item->name, name[i]);
			if (cmp == 0) {
				if (nameVal[i].numVals <= 0)
					break;
				if (berstring == 0) {
					val = cloneValue(&nameVal[i], 1);
				} else if (yp2ldap && berstring[0] == 'a') {
					val = cloneValue(&nameVal[i], 1);
				} else {
					val = berDecode(&nameVal[i],
						berstring);
				}
				if (val != 0) {
					val->repeat = item->repeat;
					/*
					 * If value for nis+ column is
					 * passed with value, val is
					 * manipulated in cloneValue().
					 * To decide whether there are
					 * enough nis+ column values
					 * for rule to produce a value,
					 * we need nis+ column values
					 * as well as nis_mapping_element
					 * from the rule. If we are here,
					 * it indicates that the 'val has
					 * an valid value for the column
					 * item-> name. So set
					 * NP_LDAP_MAP_SUCCESS
					 * to np_ldap-stat.
					 */

					if (np_ldap_stat != NULL)
						*np_ldap_stat =
							NP_LDAP_MAP_SUCCESS;
				}
				break;
			}
		}
	}

	/* Do a direct lookup ? */
	if (val == 0 && (check == rvThenLookup || check == lookupOnly)) {
		if (item->type == mit_ldap) {
			int	err = 0;
			__nis_search_triple_t	triple;
			char			*baseDN;

			/*
			 * If item->searchSpec.triple.base is NULL, or ends
			 * in a comma, append the current search base from
			 * the TSD (put there by an upper layer).
			 *
			 * Special case for N2L mode:
			 * if item->searchSpec.triple.base ends in a comma,
			 * the current domain Context is used.
			 */
			if (yp2ldap && item->searchSpec.triple.base &&
				strlen(item->searchSpec.triple.base) > 0) {
				baseDN = __nisdb_get_tsd()->domainContext;
			} else {
				baseDN = __nisdb_get_tsd()->searchBase;
			}
			triple.base = appendBase(item->searchSpec.triple.base,
				baseDN, &err, 0);
			if (err == 0) {
				triple.scope = item->searchSpec.triple.scope;
				triple.attrs = item->searchSpec.triple.attrs;
				triple.element =
					item->searchSpec.triple.element;
				val = lookupLDAP(&triple, item->name, rv, 0,
					np_ldap_stat);
				fromldap = '1';
			} else {
				val = 0;
			}
			sfree(triple.base);
		}
	}


	/* Special processing for NIS to LDAP mode */
	if (yp2ldap && val != 0) {

		/*
		 * Escape special chars from dn before sending to DIT,
		 * provided val is not ldap-based
		 */
		if (fromldap == '\0' && __nisdb_get_tsd()->escapeFlag == '1') {
			if (escapeSpecialChars(val) < 0) {
				freeValue(val, 1);
				return (0);
			}
		} else if (__nisdb_get_tsd()->escapeFlag == '2') {
			/* Remove escape chars from data received from DIT */
			(void) removeEscapeChars(val);
		}

		/*
		 * Remove from 'val', any values obtained using
		 * the 'removespec' syntax
		 */

		/* Obtain exVal */
		if (item->exItem)
			exVal = getMappingItemVal(item->exItem, native, rv,
			    berstring, NULL);

		/* delete */
		if (exVal != 0) {
			for (i = 0; i < val->numVals; ) {
				for (j = 0; j < exVal->numVals; j++) {
					if (sstrncmp(val->val[i].value,
							exVal->val[j].value,
							MAX(val->val[i].length,
							exVal->val[j].length))
							== 0)
						break;
				}
				if (j < exVal->numVals) {
					sfree(val->val[i].value);
					val->val[i].value = 0;
					val->val[i].length = 0;
					for (k = i; k < val->numVals - 1; k++) {
						val->val[k] = val->val[k + 1];
						val->val[k + 1].value = 0;
						val->val[k + 1].length = 0;
					}
					val->numVals--;
				} else
					i++;
			}

			freeValue(exVal, 1);

			/*
			 * If val->numVals <= 0, then we have no val to
			 * return. So free up stuff.
			 */
			if (val->numVals <= 0) {
				free(val->val);
				val->val = 0;
				free(val);
				return (0);
			}
		}
	}

	return (val);
}

__nis_value_t *
getMappingFormat(__nis_mapping_format_t *f, __nis_rule_value_t *rv,
			__nis_format_arg_t at, void *a, int *numArg) {
	char		*myself = "getMappingFormat";
	__nis_value_t	*val = 0;
	__nis_buffer_t	b = {0, 0};
	int		i;

	if (f == 0)
		return (0);

	if (rv == 0) {
		val = am(myself, sizeof (*val));
		if (val == 0)
			return (0);

		switch (f->type) {
		case mmt_item:
			bp2buf(myself, &b, "%%s");
			break;
		case mmt_string:
			bp2buf(myself, &b, "%s", NIL(f->match.string));
			break;
		case mmt_single:
			bp2buf(myself, &b, "[");
			for (i = 0; i < f->match.single.numRange; i++) {
				if (f->match.single.lo[i] ==
						f->match.single.hi[i])
					bp2buf(myself, &b, "%c",
						f->match.single.lo[i]);
				else
					bp2buf(myself, &b, "%c-%c",
						f->match.single.lo[i],
						f->match.single.hi[i]);
			}
			bp2buf(myself, &b, "]");
			break;
		case mmt_limit:
			break;
		case mmt_any:
			bp2buf(myself, &b, "*");
			break;
		case mmt_berstring:
			bp2buf(myself, &b, "%s", NIL(f->match.berString));
			break;
		case mmt_begin:
		case mmt_end:
			bp2buf(myself, &b, "\"");
			break;
		default:
			bp2buf(myself, &b, "<unknown>");
		}
		val->type = vt_string;
		val->numVals = 1;
		val->val = am(myself, sizeof (val->val[0]));
		if (val->val == 0) {
			sfree(val);
			return (0);
		}
		val->val[0].value = b.buf;
		val->val[0].length = b.len;
	} else {
		switch (f->type) {
		case mmt_item:
		case mmt_berstring:
			if (a != 0) {
				if (at == fa_item) {
					val = getMappingItemVal(
						(__nis_mapping_item_t *)a,
						mit_any, rv,
		(f->type == mmt_berstring) ? f->match.berString : 0, NULL);
					if (numArg != 0)
						(*numArg)++;
				} else {
					val = cloneValue(
						(__nis_value_t *)a, 1);
					if (numArg != 0)
						(*numArg)++;
				}
			}
			break;
		case mmt_string:
			val = am(myself, sizeof (*val));
			if (val == 0)
				return (0);
			val->type = vt_string;
			val->numVals = 1;
			val->val = am(myself, sizeof (val->val[0]));
			if (val->val == 0) {
				sfree(val);
				return (0);
			}
			val->val[0].value = sdup(myself, T, f->match.string);
			val->val[0].length = strlen(val->val[0].value);
			break;
		case mmt_single:
		case mmt_limit:
		case mmt_any:
		case mmt_begin:
		case mmt_end:
			/* Not an error, so return an empty value */
			val = am(myself, sizeof (*val));
			if (val == 0)
				return (0);
			val->type = vt_string;
			val->numVals = 0;
			val->val = 0;
			break;
		default:
			/* Do nothing */
			val = 0;
			break;
		}
	}
	return (val);
}

/*
 * Used when evaluating an expression. Typically, the value of the
 * expression so far will be kept in 'v1', and 'v2' is the value
 * of the current component of the expression. In the general case,
 * both will be multi-valued, and the result is an "explosion"
 * resulting in N*M new values (if 'v1' had N values, and 'v2'
 * M ditto).
 *
 * For example, if v1 = {"ab", "cd", "ef"}, and v2 = {"gh", "ij", "kl"},
 * the result will be {"abgh", "abij", "abkl", "cdgh", "cdij", "cdkl",
 * "efgh", "efij", "efkl"}.
 *
 * There are special cases when v1->repeat and/or v2->repeat are set.
 * Repeat mostly makes sense with single values; for example, if
 * v1 = {"x="} with repeat on, and v2 = {"1", "2", "3"}, the result
 * is {"x=1", "x=2", "x=3"}.
 *
 * The result if v2 also had repeat on would be {"x=1x=2x=3"}. It's
 * not clear if there's a useful application for this, but the code's
 * there for the sake of orthogonality.
 */
__nis_value_t *
explodeValues(__nis_value_t *v1, __nis_value_t *v2) {
	int		i1, i2, n, nv;
	__nis_value_t	*v;
	__nis_buffer_t	b = {0, 0};
	char		*myself = "explodeValues";

	if (v1 == 0 || v1->numVals <= 0)
		return (cloneValue(v2, 1));
	if (v2 == 0 || v2->numVals <= 0)
		return (cloneValue(v1, 1));

	/*
	 * XXX What should we do if (v1->type != v2->type) ?
	 * Policy: Just explode anyway, even though the result is
	 * unlikely to be very useful.
	 */

	v = am(myself, sizeof (*v));
	if (v == 0)
		return (0);

	if (!v1->repeat && !v2->repeat)
		nv = v1->numVals * v2->numVals;
	else if (v1->repeat && !v2->repeat)
		nv = v2->numVals;
	else if (!v1->repeat && v2->repeat)
		nv = v1->numVals;
	else /* v1->repeat && v2->repeat */
		nv = 1;

	v->val = am(myself, nv * sizeof (v->val[0]));
	if (v->val == 0) {
		free(v);
		return (0);
	}

	/*
	 * Four different cases, depending on the 'repeat' flags.
	 */
	if (!v1->repeat && !v2->repeat) {
		for (i1 = 0, n = 0; i1 < v1->numVals; i1++) {
			for (i2 = 0; i2 < v2->numVals; i2++) {
				if (v1->type == vt_string)
					sbc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				else
					bc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				if (v2->type == vt_string)
					sbc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
				else
					bc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
				v->val[n].value = b.buf;
				v->val[n].length = b.len;
				n++;
				b.buf = 0;
				b.len = 0;
			}
		}
	} else if (v1->repeat && !v2->repeat) {
		for (i2 = 0; i2 < v2->numVals; i2++) {
			for (i1 = 0, n = 0; i1 < v1->numVals; i1++) {
				if (v1->type == vt_string)
					sbc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				else
					bc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				if (v2->type == vt_string)
					sbc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
				else
					bc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
			}
			v->val[n].value = b.buf;
			v->val[n].length = b.len;
			n++;
			b.buf = 0;
			b.len = 0;
		}
	} else if (!v1->repeat && v2->repeat) {
		for (i1 = 0, n = 0; i1 < v1->numVals; i1++) {
			for (i2 = 0; i2 < v2->numVals; i2++) {
				if (v1->type == vt_string)
					sbc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				else
					bc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				if (v2->type == vt_string)
					sbc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
				else
					bc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
			}
			v->val[n].value = b.buf;
			v->val[n].length = b.len;
			n++;
			b.buf = 0;
			b.len = 0;
		}
	} else { /* v1->repeat && v2->repeat */
		for (i1 = 0, n = 0; i1 < v1->numVals; i1++) {
			for (i2 = 0; i2 < v2->numVals; i2++) {
				if (v1->type == vt_string)
					sbc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				else
					bc2buf(myself, v1->val[i1].value,
						v1->val[i1].length,
						&b);
				if (v2->type == vt_string)
					sbc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
				else
					bc2buf(myself, v2->val[i2].value,
						v2->val[i2].length,
						&b);
			}
		}
		v->val[n].value = b.buf;
		v->val[n].length = b.len;
		n++;
		b.buf = 0;
		b.len = 0;
	}

#ifdef	NISDB_LDAP_DEBUG
	/* Sanity check */
	if (n != nv)
		abort();
#endif	/* NISD__LDAP_DEBUG */

	v->type = (v1->type == vt_string) ?
			((v2->type == vt_string) ?
				vt_string : vt_ber) : vt_ber;
	v->repeat = 0;
	v->numVals = n;

	return (v);
}

__nis_value_t *
getMappingFormatArray(__nis_mapping_format_t *a, __nis_rule_value_t *rv,
			__nis_format_arg_t at, int numArgs, void *arg) {
	int			i, ia = 0;
	__nis_value_t		*val, *v = 0;
	bool_t			moreFormat = (a != 0);
	bool_t			moreArgs = (numArgs > 0);

	while (moreFormat && (arg == 0 || ia < numArgs)) {
		for (i = 0; moreFormat; i++) {
			moreFormat = (a[i].type != mmt_end);
			if (at == fa_item) {
				__nis_mapping_item_t *item = arg;
				val = getMappingFormat(&a[i], rv, at,
					((item != 0) ? &item[ia] : 0), &ia);
			} else {
				__nis_value_t **ival = arg;
				val = getMappingFormat(&a[i], rv, at,
					((ival != 0) ? ival[ia] : 0), &ia);
			}
			if (val != 0) {
				__nis_value_t	*new = explodeValues(v, val);

				freeValue(v, 1);
				freeValue(val, 1);
				if (new == 0)
					return (0);

				v = new;
			} else {
				freeValue(v, 1);
				return (0);
			}
			/*
			 * If we run out of arguments, but still have format
			 * remaining, repeat the last argument. Keep track of
			 * the fact that we've really consumed all arguments.
			 */
			if (moreFormat && ia >= numArgs) {
				ia = (numArgs > 0) ? numArgs - 1 : 0;
				moreArgs = FALSE;
			}
		}
		/*
		 * We've run out of format, so if we still have arguments
		 * left, start over on the format.
		 */
		if (ia < numArgs && moreArgs) {
			/*
			 * However, if we didn't consume any arguments going
			 * through the format once, abort to avoid an infinite
			 * loop.
			 */
			if (numArgs > 0 && ia <= 0) {
				freeValue(v, 1);
				return (0);
			}
			moreFormat = 1;
		}
	}

	return (v);
}

/*
 * Returns a string representation (such as "[name=foo, value=bar]")
 * of a nis_index_t.
 */
char *
getIndex(__nis_index_t *i, int *len) {
	int		n;
	__nis_buffer_t	b = {0, 0};
	char		*myself = "getIndex";

	if (i == 0)
		return (0);

	if (i->numIndexes > 0) {
		bp2buf(myself, &b, "[");
		for (n = 0; n < i->numIndexes; n++) {
			__nis_value_t	*val;
			int		j;

			val = getMappingFormatArray(i->value[n],
						0, fa_any, 0, 0);
			if (n > 0)
				bp2buf(myself, &b, ", ");
			bp2buf(myself, &b, "%s=", i->name[n]);
			if (val != 0) {
				for (j = 0; j < val->numVals; j++) {
					bc2buf(myself, val->val[j].value,
						val->val[j].length, &b);
				}
			} else {
				bp2buf(myself, &b, "<no-vals>");
			}
			freeValue(val, 1);
		}
		bp2buf(myself, &b, "]");
	}
	if (len != 0)
		*len = b.len;
	return (b.buf);
}

char *
getObjSpec(__nis_obj_spec_t *o, int *len) {
	__nis_buffer_t	b = {0, 0};
	char		*myself = "getObjSpec";

	if (o == 0)
		return (0);

	b.buf = getIndex(&o->index, &b.len);
	sbc2buf(myself, o->name, slen(o->name), &b);
	if (len != 0)
		*len = b.len;
	return (b.buf);
}

/*
 * Returns a string representation of the LDAP scope. Note that the
 * returned value is a static entity, and must be copied by the
 * caller (but, obviously, must not be freed).
 */
char *
getScope(int scope) {
	switch (scope) {
	case LDAP_SCOPE_BASE:
		return ("base");
	case LDAP_SCOPE_ONELEVEL:
		return ("one");
	case LDAP_SCOPE_SUBTREE:
		return ("sub");
	default:
		return ("one");
	}
}

/*
 * Return a string representation of an LDAP search triple (such as
 * "ou=Hosts,dc=eng,dc=sun,dc=com?one?cn=xyzzy").
 */
char *
getSearchTriple(__nis_search_triple_t *s, int *len) {
	__nis_buffer_t	b = {0, 0};
	char		*a;
	int		l;
	char		*myself = "getSearchTriple";

	/* If the scope is LDAP_SCOPE_UNKNOWN, the search triple is unused */
	if (s == 0 || s->scope == LDAP_SCOPE_UNKNOWN) {
		if (len != 0)
			*len = 0;
		return (0);
	}

	if (s->base != 0)
		sbc2buf(myself, s->base, slen(s->base), &b);
	if (!(s->scope == LDAP_SCOPE_ONELEVEL &&
			(s->base == 0 || s->base[0] == '\0'))) {
		bp2buf(myself, &b, "?%s?", getScope(s->scope));
	}
	if ((l = slen(s->attrs)) > 0) {
		/*
		 * Remove white space from the filter/attribute list.
		 * The parser usually keeps any white space from the
		 * config file (or LDAP/command line), but we don't
		 * want it.
		 */
		a = am(myself, l+1);
		if (a != 0) {
			int	i, la;

			for (i = 0, la = 0; i < l; i++) {
				if (s->attrs[i] != ' ' &&
						s->attrs[i] != '\t')
					a[la++] = s->attrs[i];
			}
			sbc2buf(myself, a, la, &b);
			sfree(a);
		} else {
			sbc2buf(myself, s->attrs, slen(s->attrs), &b);
		}
	}

	if (len != 0)
		*len = b.len;
	return (b.buf);
}

__nis_value_t *
getMappingItem(__nis_mapping_item_t *i, __nis_mapping_item_type_t native,
		__nis_rule_value_t *rv, char *berstring, int *np_ldap_stat) {
	char		*myself = "getMappingItem";
	__nis_value_t	*val = 0;
	__nis_buffer_t	b = {0, 0};
	int		len = 0;
	char		*buf;

	if (i == 0)
		return (0);

	if (rv != 0)
		return (getMappingItemVal(i, native, rv, berstring,
			np_ldap_stat));

	val = am(myself, sizeof (*val));
	if (val == 0)
		return (0);

	switch (i->type) {
	case mit_nisplus:
		if (native != mit_nisplus)
			bp2buf(myself, &b, "nis+:");
		bp2buf(myself, &b, "%s", NIL(i->name));
		buf = getObjSpec(&i->searchSpec.obj, &len);
		if (buf != 0 && len > 0) {
			bc2buf(myself, ":", 1, &b);
			sbc2buf(myself, buf, len, &b);
		}
		sfree(buf);
		val->type = vt_string;
		val->repeat = i->repeat;
		val->numVals = 1;
		val->val = am(myself, sizeof (val->val[0]));
		if (val->val == 0) {
			sfree(b.buf);
			free(val);
			return (0);
		}
		val->val[0].value = b.buf;
		val->val[0].length = b.len;
		break;
	case mit_ldap:
		if (native != mit_ldap)
			bp2buf(myself, &b, "ldap:");
		bp2buf(myself, &b, "%s", NIL(i->name));
		buf = getSearchTriple(&i->searchSpec.triple, &len);
		if (buf != 0 && len > 0) {
			bc2buf(myself, ":", 1, &b);
			sbc2buf(myself, buf, len, &b);
		}
		sfree(buf);
		val->type = vt_string;
		val->repeat = i->repeat;
		val->numVals = 1;
		val->val = am(myself, sizeof (val->val[0]));
		if (val->val == 0) {
			sfree(b.buf);
			free(val);
			return (0);
		}
		val->val[0].value = b.buf;
		val->val[0].length = b.len;
		break;
	default:
		p2buf(myself, "<unknown>:");
		p2buf(myself, "%s", NIL(i->name));
		break;
	}

	return (val);
}

void
copyObjSpec(__nis_obj_spec_t *old, __nis_obj_spec_t *new, int *err) {
	char	*myself = "copyObjSpec";

	if (old == 0 || new == 0) {
		*err = EINVAL;
		return;
	}

	if (new->index.name == 0) {
		new->index.name = am(myself, old->index.numIndexes *
						sizeof (new->index.name[0]));
		if (old->index.numIndexes > 0 && new->index.name == 0) {
			*err = ENOMEM;
			return;
		}
		new->index.value = am(myself, old->index.numIndexes *
						sizeof (new->index.value[0]));
		if (old->index.numIndexes > 0 && new->index.value == 0) {
			*err = ENOMEM;
			return;
		}
	}
	new->name = sdup(myself, T, old->name);
	if (new->name == 0 && old->name != 0) {
		*err = ENOMEM;
		return;
	}
	copyIndex(&old->index, &new->index, err);
}

__nis_obj_spec_t *
cloneObjSpec(__nis_obj_spec_t *old) {
	char			*myself = "cloneObjSpec";
	int			err = 0;
	__nis_obj_spec_t	*new = am(myself, sizeof (*new));

	if (new != 0) {
		copyObjSpec(old, new, &err);
		if (err != 0) {
			freeObjSpec(new, 1);
			new = 0;
		}
	}

	return (new);
}

void
freeObjSpec(__nis_obj_spec_t *old, bool_t doFree) {

	if (old == 0)
		return;

	sfree(old->name);
	freeIndex(&old->index, FALSE);
	if (doFree)
		free(old);
}

void
copySearchTriple(__nis_search_triple_t *old, __nis_search_triple_t *new,
		int *err) {
	char			*myself = "copySearchTriple";

	*err = 0;

	if (old == 0 || new == 0) {
		*err = EINVAL;
		return;
	}

	if (old->base != NULL)
		new->base = sdup(myself, T, old->base);
	else
		new->base = NULL;
	if (old->attrs != NULL)
		new->attrs = sdup(myself, T, old->attrs);
	else
		new->attrs = NULL;
	if ((new->base == 0 && old->base != 0) ||
			(new->attrs == 0 && old->attrs != 0)) {
		sfree(new->base);
		new->base = 0;
		sfree(new->attrs);
		new->attrs = 0;
		*err = ENOMEM;
		return;
	}
	new->scope = old->scope;
	/*
	 * XXX Really should have a cloneMappingElement() function.
	 * However, since whatever the 'element' field points to
	 * is allocated at parse time, and never is freed or modified,
	 * it's sufficient to copy the pointer value.
	 */
	new->element = old->element;
}

__nis_search_triple_t *
cloneSearchTriple(__nis_search_triple_t *old) {
	char			*myself = "cloneSearchTriple";
	int			err = 0;
	__nis_search_triple_t	*new = am(myself, sizeof (*new));

	if (new != 0) {
		copySearchTriple(old, new, &err);
		if (err != 0) {
			freeSearchTriple(new, 1);
			new = 0;
		}
	}

	return (new);
}

void
freeSearchTriple(__nis_search_triple_t *old, bool_t doFree) {

	if (old == 0)
		return;

	sfree(old->base);
	sfree(old->attrs);
	/*
	 * Since we only copied the element pointer when this structure
	 * was created, we don't free old->element.
	 */
	if (doFree)
		free(old);
}

void
copyTripleOrObj(__nis_mapping_item_type_t type,
		__nis_triple_or_obj_t *old, __nis_triple_or_obj_t *new,
		int *err) {

	*err = 0;

	if (old == 0 || new == 0) {
		*err = EINVAL;
		return;
	}

	if (type == mit_nisplus) {
		copyObjSpec(&old->obj, &new->obj, err);
	} else if (type == mit_ldap) {
		copySearchTriple(&old->triple, &new->triple, err);
	}
}

__nis_triple_or_obj_t *
cloneTripleOrObj(__nis_mapping_item_type_t type, __nis_triple_or_obj_t *old) {
	char			*myself = "cloneTripleOrObj";
	int			err = 0;
	__nis_triple_or_obj_t	*new = am(myself, sizeof (*new));

	if (new != 0) {
		copyTripleOrObj(type, old, new, &err);
		if (err != 0) {
			freeTripleOrObj(type, new, 1);
			new = 0;
		}
	}

	return (new);
}

void
freeTripleOrObj(__nis_mapping_item_type_t type, __nis_triple_or_obj_t *old,
		bool_t doFree) {

	if (old == 0)
		return;

	if (type == mit_nisplus)
		freeObjSpec(&old->obj, doFree);
	else if (type == mit_ldap)
		freeSearchTriple(&old->triple, doFree);

	if (doFree)
		free(old);
}

void
copyItem(__nis_mapping_item_t *old, __nis_mapping_item_t *new, int *err) {

	*err = 0;

	if (old == 0 || new == 0) {
		*err = EINVAL;
		return;
	}

	new->type = old->type;
	new->repeat = old->repeat;
	if (old->name != 0) {
		new->name = strdup(old->name);
		if (new->name == 0) {
			*err = ENOMEM;
			return;
		}
	} else {
		new->name = 0;
	}
	if (old->type == mit_nisplus || old->type == mit_ldap)
		copyTripleOrObj(old->type, &old->searchSpec, &new->searchSpec,
				err);
	else
		memset(&new->searchSpec, 0, sizeof (new->searchSpec));
}

__nis_mapping_item_t *
cloneItem(__nis_mapping_item_t *old) {
	__nis_mapping_item_t	*new;
	int			err = 0;
	char			*myself = "cloneItem";

	if (old == 0)
		return (0);

	new = am(myself, sizeof (*new));
	if (new == 0)
		return (0);

	copyItem(old, new, &err);
	if (err != 0) {
		freeMappingItem(new, 1);
		return (0);
	}

	return (new);
}

void
freeMappingItem(__nis_mapping_item_t *item, int numItems) {
	int	i;

	if (item == 0)
		return;

	for (i = 0; i < numItems; i++) {
		sfree(item[i].name);
		freeTripleOrObj(item[i].type, &item[i].searchSpec, FALSE);
	}
	sfree(item);
}

__nis_mapping_item_t *
concatenateMappingItem(__nis_mapping_item_t *old, int numItems,
		__nis_mapping_item_t *cat) {
	__nis_mapping_item_t	*new;
	int			i, err = 0;
	char			*myself = "concatenateMappingItem";

	if (old == 0 || numItems < 1)
		return (cloneItem(cat));

	new = am(myself, (numItems + 1) * sizeof (*new));
	if (new == 0)
		return (0);

	for (i = 0; i < numItems; i++) {
		copyItem(&old[i], &new[i], &err);
		if (err != 0) {
			freeMappingItem(new, i);
			return (0);
		}
	}
	copyItem(cat, &new[numItems], &err);
	if (err != 0) {
		freeMappingItem(new, numItems);
		new = 0;
	}

	return (new);
}

__nis_value_t *
concatenateValues(__nis_value_t *v1, __nis_value_t *v2) {
	int		i, n, a;
	__nis_value_t	*v;
	char		*myself = "concatenateValues";

	if (v1 == 0 || v1->numVals <= 0)
		return (cloneValue(v2, 1));
	if (v2 == 0 || v2->numVals <= 0)
		return (cloneValue(v1, 1));

	if (v1->type != v2->type)
		return (0);

	n = v1->numVals + v2->numVals;
	v = am(myself, sizeof (*v));
	if (v == 0)
		return (0);
	v->val = am(myself, n * sizeof (v->val[0]));
	if (v->val == 0) {
		free(v);
		return (0);
	}
	v->type = v1->type;
	v->numVals = 0;

	for (a = 0; a < 2; a++) {
		__nis_single_value_t	*val = (a == 0) ? v1->val : v2->val;
		int			numv = (a == 0) ? v1->numVals :
							v2->numVals;
		for (i = 0; i < numv; i++) {
			int	clen, alen = val[i].length;

			clen = alen;

			/*
			 * Make sure there's a NUL at the end of a string,
			 * but avoid adding to the allocated length if there's
			 * already a NUL at the end.
			 */
			if (alen > 0 && v->type == vt_string &&
					((char *)val[i].value)[alen-1] != '\0')
				alen += 1;
			v->val[v->numVals].value = am(myself, alen);
			if (v->val[v->numVals].value == 0) {
				freeValue(v, 1);
				return (0);
			}
			memcpy(v->val[v->numVals].value, val[i].value, clen);
			v->val[v->numVals].length = val[i].length;
			v->numVals++;
		}
	}

	return (v);
}

__nis_value_t *
splitMappingItem(__nis_mapping_item_t *item, char delim,
		__nis_rule_value_t *rv) {
	__nis_value_t		*val = getMappingItem(item, mit_any,
			rv, 0, NULL);
	__nis_single_value_t	*nval;
	int			i, n, nv;

	if (val == 0)
		return (0);
	else if (delim == 0 || val->val == 0 || val->numVals <= 0 ||
			val->type != vt_string) {
		freeValue(val, 1);
		return (0);
	}

	nval = val->val;
	nv = val->numVals;
	val->repeat = FALSE;
	val->val = 0;
	val->numVals = 0;

	/* In N2L, space and tab delimiters are treated the same */
	if (yp2ldap && delim == '\t')
		delim = ' ';

	/* If the item has multiple values, we split each one independently */
	for (i = 0; i < nv; i++) {
		char			*str;
		int			s, e;
		char			*newstr;
		__nis_single_value_t	*newval;

		if (yp2ldap && delim == ' ')
			nval[i].value = trimWhiteSpaces(nval[i].value,
							&nval[i].length, 1);

		str = nval[i].value;

		if (nval[i].value == 0)
			continue;

		for (s = 0; s < nval[i].length; s = e+1) {
			/* Find the next delimiter, or end-of-string */
			for (e = s; str[e] != '\0' && str[e] != delim; e++);
			/*
			 * 'str[e]' is either a delimiter, or the concluding
			 * NUL. Make sure it's NUL.
			 */
			str[e] = '\0';
			/* Add to val->val */
			newstr = strdup(&str[s]);
			newval = realloc(val->val,
					(val->numVals+1) *
						sizeof (val->val[0]));
			if (newval != 0)
				val->val = newval;
			if (newstr == 0 || newval == 0) {
				freeValue(val, 1);
				for (n = i; n < nv; n++) {
					sfree(nval[n].value);
				}
				free(nval);
				sfree(newstr);
				return (0);
			}
			val->val[val->numVals].value = newstr;
			val->val[val->numVals].length = strlen(newstr) + 1;
			val->numVals++;
		}
		free(nval[i].value);
		nval[i].value = 0;
	}
	/* Already freed the nval[i].value's as we traversed nval */
	free(nval);

	return (val);
}

/*
 * Match the format spec 'f[curf]' to the input value string 'str'.
 *
 * If successful, returns the updated position in the value string 'str'.
 * Otherwise, NULL is returned.
 *
 * curf		Current index (i.e., the one we should look at) in 'f'
 * nf		Number of elements in 'f', including 'mmt_end'
 * str		The value string we're scanning
 * val		Pointer to where an item value (if any) should be returned
 *		Set to NULL if not an 'mmt_item'.
 * fmtstart	If non-zero on entry, skip characters in 'str' until we find
 *		the f[curf].type data, if doing so makes any sense. On exit,
 *		set to the start of the fmt element data (which will be 'str',
 *		unless we did skip characters)
 * sepset	List of separators
 */
char *
scanMappingFormat(__nis_mapping_format_t *f, int curf, int nf, char *str,
		char **val, char **fmtstart, char *sepset) {
	char	*mstr, *next, *start = 0, *tmpstr;
	int	i, len;
	bool_t	match;
	char	*myself = "scanMappingFormat";
	/* N2L variables */
	int	af, skipspaces = 0;
	bool_t	ipaddr = FALSE;
	char	*spacestr = " ", *emptystr = "";


	if (f == 0 || curf < 0 || nf <= 0 || str == 0)
		return (0);

	/*
	 * If separator list is NULL (which will be the case for
	 * nis+2ldap), then simply use empty string
	 */
	if (sepset == 0)
		sepset = emptystr;

	if (curf >= nf) {
		/* OK if the string also is exhausted */
		if (strchr(sepset, *str) != 0)
			return (str);
		else
			return (0);
	}

	switch (f[curf].type) {
	case mmt_berstring:
		if (f[curf].match.berString[0] != 'a') {
			/* Not a matchable element */
			return (0);
		}

		/*
		 * If here, it means it's an IP address (N2L case)
		 * So continue processing as if it was mmt_item
		 */
		ipaddr = TRUE;
		/* FALLTHROUGH */
	case mmt_item:
		/*
		 * In order to find the end of the item value, we must look
		 * ahead and determine the start of the next formatting element.
		 * If successful, 'next' will be the start of the fmt element
		 * after the next one; we don't care about that, other than to
		 * check for error.
		 *
		 * Since an item match is somewhat like an any match, in that
		 * we don't know a priori if the first occurence of the next
		 * element really is the one we want, we have to scan ahead
		 * until we've reached the end.
		 */
		tmpstr = str;
		while ((next = scanMappingFormat(f, curf+1, nf, tmpstr, 0,
				&start, sepset)) != 0) {
			char	*tmp = next;
			int	cf;

			for (cf = curf+2; cf < nf; cf++) {
				tmp = scanMappingFormat(f, cf, nf, tmp, 0,
					0, sepset);
				if (tmp == 0)
					break;
			}
			if (tmp == 0) {
				tmpstr = next;
			} else if (strchr(sepset, *tmp) != 0) {
				break;
			} else {
				return (0);
			}

		}
		if (next == 0 || start == 0)
			return (0);

		if (val != 0) {
			len = (int)((long)start - (long)str);
			*val = am(myself, len + 1);
			if (*val == 0)
				return (0);
			memcpy(*val, str, len);
			(*val)[len] = '\0';

			if (ipaddr == TRUE) {
				/*
				 * In N2L, we need to check if *val is truly an
				 * IP address
				 */
				af = checkIPaddress(*val, len, &tmpstr);

				if (af == -2) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s:Internal error while "
						"processing IPaddress %s",
						myself, *val);
					sfree(*val);
					return (0);
				} else if (af == -1) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s:%s is not an IP address",
						myself, *val);
					sfree(*val);
					return (0);
				} else if (af == 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s:IP address %s is not "
						"supported by rfc2307bis",
						myself, *val);
					sfree(*val);
					return (0);
				} else if (sstrncmp(*val, tmpstr, len) != 0) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s:IPaddress %s converted "
						"to %s", myself, *val, tmpstr);
				}

				sfree(*val);
				*val = tmpstr;
			}
		}

		if (fmtstart != 0)
			*fmtstart = str;

		return (start);

	case mmt_string:
		if ((mstr = f[curf].match.string) == 0 || *mstr == '\0') {
			/*
			 * Count this as a successful match of an empty
			 * string.
			 */
			if (fmtstart != 0)
				*fmtstart = str;
			return (str);
		}

		/*
		 * In N2L, if the format string 'mstr' contains only
		 * whitespaces (spaces and tabs), then it should
		 * match one or more whitespaces from the input
		 * string 'str'.
		 */
		if (yp2ldap && strspn(mstr, " \t") == strlen(mstr)) {
				mstr = spacestr;
				skipspaces = 1;
				next = str + strcspn(str, " \t");
				/*
				 * Even if there is no whitespace in 'str',
				 * it's OK. This is to allow formats like
				 * "%s %s %s" to match inputs like "foo bar".
				 */
				if (*next == '\0')
					mstr = emptystr;
		} else {
			/* No match string in 'str' => failure */
			if ((next = strstr(str, mstr)) == 0)
				return (0);
		}

		/* If 'fmtstart' == 0, we require 'next' == 'str' */
		if (fmtstart == 0 && next != str)
			return (0);
		/* Success; save start of match string if requested */
		if (fmtstart != 0)
			*fmtstart = next;
		/* Update position in the value string */
		str = (char *)((long)next + (long)strlen(mstr));

		/* Skip whitespaces for N2L */
		if (skipspaces == 1)
			for (; *str == ' ' || *str == '\t'; str++);

		return (str);

	case mmt_single:
		if (fmtstart != 0) {
			match = FALSE;
			/* Skip ahead until we match */
			for (next = str; *next != '\0'; next++) {
				unsigned char	*lo = f[curf].match.single.lo;
				unsigned char	*hi = f[curf].match.single.hi;

				for (i = 0; i < f[curf].match.single.numRange;
						i++) {
					if (*next >= lo[i] && *next <= hi[i]) {
						match = TRUE;
						break;
					}
				}
				if (match)
					break;
			}
			if (!match)
				return (0);
			*fmtstart = next;
			str = next;
		} else {
			match = FALSE;
			for (i = 0; i < f[curf].match.single.numRange; i++) {
				if (*str >= f[curf].match.single.lo[i] &&
					*str <= f[curf].match.single.hi[i]) {
					match = TRUE;
					break;
				}
			}
			if (!match)
				return (0);
		}
		/* Step over the matched character */
		str++;
		return (str);

	case mmt_any:
		/*
		 * Look ahead to find the beginning of the next element.
		 * Because a wildcard-match isn't necessarily uniquely
		 * determined until we've reached the end, we then continue
		 * to scan ahead.
		 */
		while ((next = scanMappingFormat(f, curf+1, nf, str, 0,
						&start, sepset)) != 0) {
			char	*tmp = next;
			int	cf;

			for (cf = curf+2; cf < nf; cf++) {
				tmp = scanMappingFormat(f, cf, nf, tmp, 0,
					0, sepset);
				if (tmp == 0)
					break;
			}
			if (tmp == 0) {
				str = next;
			} else if (*tmp == '\0') {
				break;
			} else {
				return (0);
			}
		}
		if (next == 0 || start == 0)
			return (0);

		if (fmtstart != 0)
			*fmtstart = str;

		return (start);

	case mmt_limit:
		if (f[curf].match.limit == eos) {
			if (fmtstart != 0) {
				/* Skip to the end */
				str = str + strcspn(str, sepset);
				*fmtstart = str;
			} else if (strchr(sepset, *str) == 0) {
				return (0);
			}
		}
		return (str);

	case mmt_begin:
		if (fmtstart != 0)
			*fmtstart = str;
		return (str);

	case mmt_end:
		if (fmtstart != 0) {
			/* Skip to the end */
			str = str + strcspn(str, sepset);
			*fmtstart = str;
			return (str);
		}
		/* No skipping, so we must be at the end of the value */
		if (strchr(sepset, *str) == 0)
			return (0);
		return (str);

	default:
		break;
	}

	return (0);
}

/*
 * Verify that the string 'str' matches the mapping format array 'f'.
 * Returns 1 in case of a match, 0 otherwise.
 */
int
verifyMappingMatch(__nis_mapping_format_t *f, char *str) {
	int			n, nf;
	__nis_mapping_format_t	*ftmp;

	/* Count the number of format elements in the format */
	for (nf = 0, ftmp = f; ftmp->type != mmt_end; ftmp++) {
		nf++;
	}
	/* Count the mmt_end as well */
	nf++;

	for (n = 0; n < nf; n++) {
		str = scanMappingFormat(f, n, nf, str, 0, 0, 0);
		if (str == 0)
			break;
	}

	return ((str != 0) ? 1 : 0);
}

/*
 * Perform a match operation. For example, given the rule
 *	("{%s}%s", auth_name, public_data)=nisPublicKey
 * and assuming that 'nisPublicKey' has the value "{dh640-0}abcdef12345",
 * assign "dh640-0" to 'auth_name' and "abcdef12345" to 'public_data'.
 *
 * Note that this function doesn't perform the actual assignment. Rather,
 * it returns an array of __nis_value_t's, with element zero of the value
 * array being the new value of the first matched item, element one the
 * value of the second matched item, etc. In the example above, we'd
 * return a value array with two elements.
 *
 * If there is more than one input value (inVal->numVals > 1), the
 * output array elements will also be multi-valued.
 *
 * f		The match format
 * inVal	Input value(s)
 * numVal	Number of elements in the output value array
 * sepset	List of separators
 * outstr	Points to the updated position upto which the
 *		input string has been matched
 */
__nis_value_t **
matchMappingItem(__nis_mapping_format_t *f, __nis_value_t *inVal,
		int *numVals, char *sepset, char **outstr) {
	__nis_value_t		**v = 0;
	int			i, n, ni, numItems, nf;
	char			*str, *valstr;
	__nis_mapping_format_t	*ftmp;
	char			*myself = "matchMappingItem";

	if (f == 0 ||
		inVal == 0 || inVal->numVals < 1 || inVal->type != vt_string)
		return (0);

	/* Count the number of format elements and items in the format */
	for (nf = numItems = 0, ftmp = f; ftmp->type != mmt_end; ftmp++) {
		nf++;

		/*
		 * Count mmt_item and mmt_berstring (used by N2L to
		 * represent address %a)
		 */
		if (ftmp->type == mmt_item)
				numItems++;
		else if (ftmp->type == mmt_berstring && ftmp->match.berString &&
				ftmp->match.berString[0] == 'a')
				numItems++;
	}
	/* Count the mmt_end as well */
	nf++;

	/*
	 * If no items, there will be no values. This isn't exactly an error
	 * from the limited point of view of this function, so we return a
	 * __nis_value_t with zero values.
	 */
	if (numItems <= 0) {
		v = am(myself, sizeof (v[0]));
		if (v == 0)
			return (0);
		v[0] = am(myself, sizeof (*v[0]));
		if (v[0] == 0) {
			sfree(v);
			return (0);
		}
		v[0]->type = vt_string;
		v[0]->numVals = 0;
		v[0]->val = 0;
		if (numVals != 0)
			*numVals = 1;
		return (v);
	}

	/* Allocate and initialize the return array */
	v = am(myself, numItems * sizeof (v[0]));
	if (v == 0)
		return (0);
	for (n = 0; n < numItems; n++) {
		v[n] = am(myself, sizeof (*v[n]));
		if (v[n] == 0) {
			int	j;

			for (j = 0; j < n; j++)
				freeValue(v[j], 1);
			sfree(v);
			return (0);
		}
		v[n]->type = vt_string;
		v[n]->numVals = 0;
		v[n]->val = am(myself, inVal->numVals * sizeof (v[n]->val[0]));
		if (v[n]->val == 0) {
			int	j;

			for (j = 0; j < n; j++)
				freeValue(v[j], 1);
			sfree(v);
			return (0);
		}
		for (i = 0; i < inVal->numVals; i++) {
			v[n]->val[i].length = 0;
			v[n]->val[i].value = 0;
		}
	}

	/* For each input value, perform the match operation */
	for (i = 0; i < inVal->numVals; i++) {
		str = inVal->val[i].value;
		if (str == 0)
			continue;
		for (n = 0, ni = 0; n < nf; n++) {
			valstr = 0;
			str = scanMappingFormat(f, n, nf, str, &valstr,
				0, sepset);
			if (str == 0)
				break;
			if (valstr != 0 && ni < numItems &&
					v[ni]->numVals < inVal->numVals) {
				v[ni]->val[v[ni]->numVals].value = valstr;
				v[ni]->val[v[ni]->numVals].length =
							strlen(valstr) + 1;
				v[ni]->numVals++;
				ni++;
			} else if (valstr != 0) {
				sfree(valstr);
			}
		}
		if (str == 0) {
			for (n = 0; n < numItems; n++)
				freeValue(v[n], 1);
			sfree(v);
			return (0);
		}
	}

	if (numVals != 0)
		*numVals = numItems;

	/*
	 * Update the return string upto the point it has been matched
	 * This string will be used by the N2L code in its next call
	 * to this function
	 */
	if (outstr != 0)
		*outstr = str;

	return (v);
}

/*
 * Perform an extract operation. For example, given the expression
 *	(name, "%s.*")
 * and assuming 'name' is an item with the value "some.thing", the
 * value returned by the extract is "some".
 */
__nis_value_t *
extractMappingItem(__nis_mapping_item_t *item, __nis_mapping_format_t *f,
		__nis_rule_value_t *rv, int *stat) {
	__nis_value_t		*val = getMappingItem(item, mit_any,
			rv, 0, stat);
	__nis_single_value_t	*nval;
	int			i, n, nv, nf;
	__nis_mapping_format_t	*ftmp;

	if (val == 0)
		return (0);
	else if (f == 0 || rv == 0 || val->val == 0 ||
			val->numVals <= 0 || val->type != vt_string) {
		freeValue(val, 1);
		return (0);
	}

	/* Sanity check the format; it must have one and only one mmt_item */
	{
		int	numitem;

		for (nf = numitem = 0, ftmp = f; ftmp->type != mmt_end;
				ftmp++) {
			nf++;
			if (ftmp->type == mmt_item)
				numitem++;
		}
		/* Count the mmt_end as well */
		nf++;
		if (numitem != 1) {
			freeValue(val, 1);
			return (0);
		}
	}

	nval = val->val;
	nv = val->numVals;
	val->repeat = FALSE;
	val->val = 0;
	val->numVals = 0;

	/* If the item has multiple values, we extract each one independently */
	for (i = 0; i < nv; i++) {
		char			*str = nval[i].value;
		char			*newstr = 0;
		__nis_single_value_t	*newval;

		if (nval[i].value == 0)
			continue;

		/*
		 * We match the whole string, even if we find a value for
		 * the item before exhausting all format elements. By doing
		 * this, we ensure that the string really matches the complete
		 * format specification.
		 */
		for (n = 0; n < nf; n++) {
			str = scanMappingFormat(f, n, nf, str, &newstr, 0, 0);
			if (str == 0)
				break;
		}

		/*
		 * *str should now be NUL, meaning we've reached the end of
		 * the string (value), and it completely matched the format.
		 * If 'str' is NULL, there was an error, and if 'newstr' is
		 * 0, we somehow failed to obtain a value.
		 */
		if (str == 0 || *str != '\0' || newstr == 0 ||
				(newval = realloc(val->val,
					(val->numVals+1) *
					sizeof (val->val[0]))) == 0) {
			freeValue(val, 1);
			for (n = 0; n < nv; n++) {
				sfree(nval[n].value);
			}
			free(nval);
			sfree(newstr);
			return (0);
		}

		val->val = newval;
		val->val[val->numVals].value = newstr;
		val->val[val->numVals].length = strlen(newstr) + 1;
		val->numVals++;

		free(nval[i].value);
		nval[i].value = 0;
	}
	free(nval);

	return (val);
}

/*
 * For each value in 'val', remove the last character, provided that
 * it matches 'elide'.
 */
void
stringElide(__nis_value_t *val, char elide) {

	if (val != 0 && val->type == vt_string) {
		int	i;

		for (i = 0; i < val->numVals; i++) {
			int	end = val->val[i].length;
			char	*str = val->val[i].value;

			if (str == 0 || end <= 0)
				continue;

			/*
			 * If the NUL was counted in the length, step back
			 * over it.
			 */
			if (str[end-1] == '\0')
				end--;
			if (end > 0 && str[end-1] == elide) {
				str[end-1] = '\0';
				val->val[i].length--;
			}
		}
	}
}

/*
 * Obtain the value for the mapping sub-element 'e', given the input
 * rule-value 'rv'.
 */
__nis_value_t *
getMappingSubElement(__nis_mapping_sub_element_t *e,
	__nis_rule_value_t *rv, int *np_ldap_stat) {
	__nis_value_t	*val;

	if (e == 0)
		return (0);

	switch (e->type) {
	case me_item:
		val = getMappingItem(&e->element.item, mit_any, rv, 0,
			np_ldap_stat);
		break;
	case me_print:
		val = getMappingFormatArray(e->element.print.fmt, rv,
						fa_item,
						e->element.print.numItems,
						e->element.print.item);
		if (e->element.print.doElide)
			stringElide(val, e->element.print.elide);
		break;
	case me_split:
		val = splitMappingItem(&e->element.split.item,
					e->element.split.delim,
					rv);
		break;
	case me_extract:
		val = extractMappingItem(&e->element.extract.item,
					e->element.extract.fmt,
					rv, np_ldap_stat);
		break;
	case me_match:
	default:
		val = 0;
		break;
	}

	return (val);
}

/*
 * Obtain the value of the mapping element 'e', given the input rule-
 * value 'rv'. The 'native' mapping type is used when 'rv' is NULL,
 * and the result is a string representation of the mapping element;
 * in that case, items of the 'native' type are printed without their
 * type designation ("nis+" or "ldap").
 */
__nis_value_t *
getMappingElement(__nis_mapping_element_t *e, __nis_mapping_item_type_t native,
		__nis_rule_value_t *rv, int *stat) {
	__nis_value_t	*val, **tv;
	int		i, success = 0, novalue = 0;
	int *np_ldap_stat;
	char		*myself = "getMappingElement";

	switch (e->type) {
	case me_item:
		val = getMappingItem(&e->element.item, native, rv, 0, NULL);
		break;
	case me_print:
		tv = am(myself, e->element.print.numSubElements *
			sizeof (tv[0]));
		np_ldap_stat = am(myself,
			e->element.print.numSubElements * sizeof (int));
		if ((e->element.print.numSubElements > 0) &&
				(tv == 0 || np_ldap_stat == 0)) {
			val = 0;
			sfree(tv);
			sfree(np_ldap_stat);
			break;
		}
		for (i = 0; i < e->element.print.numSubElements; i++) {
			np_ldap_stat[i] = 0;
			tv[i] = getMappingSubElement(
				&e->element.print.subElement[i],
				rv, &np_ldap_stat[i]);
		}
		/*
		 * if we get NP_LDAP_NO_VALUE to any of the subelement
		 * and we get NP_LDAP_MAP_SUCCESS to all other subelement
		 * then we had enough nis+ column values which can
		 * produce value for this rule, but didn't. So return
		 * NP_LDAP_RULES_NO_VALUE to indicate to proceed to
		 * next database id.
		 */
		for (i = 0; i < e->element.print.numSubElements; i++) {
			if (np_ldap_stat[i] == NP_LDAP_MAP_SUCCESS)
				success++;
			if (np_ldap_stat[i] == NP_LDAP_NO_VALUE)
				novalue++;
		}
		if (stat != NULL && novalue > 0 &&
				((novalue+success) ==
					e->element.print.numSubElements))
					    *stat = NP_LDAP_RULES_NO_VALUE;
		val = getMappingFormatArray(e->element.print.fmt, rv,
						fa_value,
						e->element.print.numSubElements,
						tv);
		for (i = 0; i < e->element.print.numSubElements; i++) {
			freeValue(tv[i], 1);
		}
		sfree(tv);
		sfree(np_ldap_stat);
		if (e->element.print.doElide)
			stringElide(val, e->element.print.elide);
		break;
	case me_split:
		val = splitMappingItem(&e->element.split.item,
					e->element.split.delim,
					rv);
		break;
	case me_match:
		/*
		 * A match doesn't produce an assignable value per se,
		 * so we shouldn't get one here.
		 */
		val = 0;
		break;
	case me_extract:
		val = extractMappingItem(&e->element.extract.item,
					e->element.extract.fmt,
					rv, NULL);
		break;
	default:
		val = 0;
		break;
	}

	return (val);
}
