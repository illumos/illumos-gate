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
#include <string.h>
#include <lber.h>
#include <ldap.h>

#include "db_item_c.h"

#include "nisdb_mt.h"

#include "ldap_util.h"
#include "ldap_structs.h"
#include "ldap_val.h"
#include "ldap_ruleval.h"
#include "ldap_op.h"
#include "ldap_nisdbquery.h"
#include "ldap_attr.h"
#include "ldap_xdr.h"
#include "ldap_ldap.h"


item *
buildItem(int len, void *value) {
	char	*myself = "buildItem";
	item	*i = am(myself, sizeof (*i));
	int	mlen = len;

	if (i == 0)
		return (0);

	/*
	 * To this function, a NULL value, or a length less than or equal
	 * zero means an item with no value. Hence, buildItem(0, 0) is
	 * _not_ the right way to create index_value == 0 to indicate
	 * deletion.
	 */
	if (value == 0 || len <= 0) {
		i->itemvalue.itemvalue_len = 0;
		i->itemvalue.itemvalue_val = 0;
		return (i);
	}

	/*
	 * NIS+ usually stores the terminating NUL for strings, so we add
	 * it here just in case. This means we usually waste a byte for
	 * binary column values...
	 */
	if (len > 0 && ((char *)value)[len-1] != '\0')
		mlen++;

	i->itemvalue.itemvalue_len = len;
	i->itemvalue.itemvalue_val = am(myself, mlen);
	if (mlen > 0 && i->itemvalue.itemvalue_val == 0) {
		free(i);
		return (0);
	}
	memcpy(i->itemvalue.itemvalue_val, value, len);

	return (i);
}

void
freeItem(item *i) {
	if (i != 0) {
		sfree(i->itemvalue.itemvalue_val);
		free(i);
	}
}

void
freeQcomp(db_qcomp *qc, int doFree) {

	if (qc == 0)
		return;

	freeItem(qc->index_value);
	if (doFree)
		free(qc);
}

db_query *
buildQuery(int num_components, db_qcomp *components) {
	char		*myself = "buildQuery";
	db_query	*q = am(myself, sizeof (*q));

	if (q == 0)
		return (0);

	q->components.components_len = num_components;
	q->components.components_val = components;

	return (q);
}

/*
 * Clone a db_query. The 'numComps' parameter can be used to specify
 * the number of db_qcomp's to allocate (in the 'components.components_val'
 * array), if 'components.components_len' hasn't yet reached its expected
 * maximum value.
 */
db_query *
cloneQuery(db_query *old, int numComps) {
	db_query	*new;
	int		i;
	char		*myself = "cloneQuery";

	if (old == 0)
		return (0);

	new = am(myself, sizeof (*new));
	if (new == 0)
		return (0);

	if (old->components.components_len > numComps)
		numComps = old->components.components_len;

	new->components.components_val = am(myself,
				sizeof (new->components.components_val[0]) *
				numComps);
	if (numComps > 0 && new->components.components_val == 0) {
		free(new);
		return (0);
	}

	for (i = 0; i < old->components.components_len; i++) {
		item	*it;

		if (old->components.components_val[i].index_value == 0) {
			new->components.components_val[i].index_value = 0;
			new->components.components_val[i].which_index =
				old->components.components_val[i].which_index;
			continue;
		}

		it = buildItem(old->components.components_val[i].index_value->
					itemvalue.itemvalue_len,
				old->components.components_val[i].index_value->
					itemvalue.itemvalue_val);

		if (it == 0) {
			new->components.components_len = i + 1;
			freeQuery(new);
			return (0);
		}

		new->components.components_val[i].index_value = it;
		new->components.components_val[i].which_index =
			old->components.components_val[i].which_index;
	}

	new->components.components_len = old->components.components_len;

	return (new);
}

void
freeQuery(db_query *q) {
	int	i;

	if (q == 0)
		return;

	for (i = 0; i < q->components.components_len; i++) {
		freeItem(q->components.components_val[i].index_value);
	}

	sfree(q->components.components_val);
	sfree(q);
}

void
freeQueries(db_query **q, int numQ) {
	int	i;

	if (q == 0)
		return;

	for (i = 0; i < numQ; i++)
		freeQuery(q[i]);

	sfree(q);
}

/*
 * Given an array index[0..num-1] of pointers to strings of the form
 * "name=value", create the corresponding db_queries. "name=" indicates
 * deletion, which results in a db_query component where index_value == 0.
 *
 * The __nis_table_mapping_t structure is used to translate column
 * names to indices.
 *
 * If 'rvP' is non-NULL, the searchable columns from the 'index'
 * name/value pairs are used to retrieve copies of the corresponding NIS+
 * entries, and '*rvP' is initialized with the current entry values
 * and object attributes. Names/values supplied in 'index' override
 * those from existing NIS+ entries.
 */
db_query **
createQuery(int num, char **index, __nis_table_mapping_t *t,
		__nis_rule_value_t **rvP, int *numVals) {
	db_query		**q;
	db_qcomp		*qc;
	int			i, j, n, a, nv, niv;
	__nis_rule_value_t	*rvq;
	__nis_buffer_t		b = {0, 0};
	char			*table = 0;
	char			*myself = "createQuery";

	rvq = initRuleValue(1, 0);
	if (rvq == 0)
		return (0);

	if (numVals == 0)
		numVals = &nv;
	*numVals = 0;

	if (rvP != 0) {
		/*
		 * Try to obtain a copy of the table object, in order to
		 * determine the searchable columns. A failure isn't
		 * necessarily fatal; we just try to compose the entire
		 * LDAP data from the col=val pairs.
		 */
		table = fullObjName(F, t->objName);
		if (table == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error converting \"%s\" to FQ object name",
				myself, NIL(t->objName));
			freeRuleValue(rvq, 1);
			return (0);
		}
	}

	/* Create a rule-value from the col=val pairs */
	for (n = 0; n < num; n++) {
		char	*value;

		if ((value = strchr(index[n], '=')) == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: no '=' in \"%s\"",
				myself, index[n]);
			continue;
		}

		*value = '\0';
		value++;

		for (a = 0; a < t->numColumns; a++) {
			if (strcmp(index[n], t->column[a]) == 0) {

				/* Add col=val pair to 'rvq' */
				if (addSCol2RuleValue(index[n], value, rvq)) {
					freeRuleValue(rvq, 1);
					sfree(table);
					return (0);
				}

				break;
			}
		}
		if (a >= t->numColumns) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Ignoring unknown column \"%s\"",
				myself, NIL(index[n]));
		}
	}

	/*
	 * Find out if any of the columns specified via the 'index'
	 * array are multi-valued.
	 */
	for (n = 0, niv = 1; n < rvq->numColumns; n++) {
		if (rvq->colVal[n].numVals > 1)
			niv *= rvq->colVal[n].numVals;
	}

	*numVals = 1;

	sfree(b.buf);
	sfree(table);

	if (rvq->numColumns <= 0) {
		freeRuleValue(rvq, *numVals);
		*numVals = 0;
		return (0);
	}

	/*
	 * If any column name was repeated in the col=val pairs (but with
	 * different values), 'rvq' will have one or more multi-valued
	 * column values. We now convert those into an array of rule-values
	 * where every column is single-valued.
	 *
	 * Since we want all combinations of column values, the number
	 * of array elements is the product of all column value counts.
	 *
	 * There are four possible combinations of 'index' and NIS+ data:
	 *
	 * (1)	Only single-valued 'index' columns, and at most one NIS+
	 *	entry, so 'rvq' is complete, and '*numVals' == 1.
	 *
	 * (2)	Single-valued 'index' columns, but multiple NIS+ entries.
	 *	'*numVals' reflects the number of NIS+ entries, and no
	 *	expansion of 'index' column values to array elements is
	 *	needed.
	 *
	 * (3)	At least one multi-valued 'index', and multiple NIS+
	 *	entries. We already rejected the NIS+ data for this case
	 *	above, so it is in fact equivalent to case (4).
	 *
	 * (4)	At least one multi-valued 'index', but at most one NIS+
	 *	entry. This is the case where we must expand the multi-valued
	 *	columns to multiple array elements.
	 */
	if (niv > 1 && *numVals == 1) {
		__nis_rule_value_t	*rv;
		int			repeat;

		/*
		 * By using initRuleValue() to create 'rv', and make each
		 * element a clone of 'rvq', we save a lot of code. The
		 * down side is that 'rv' only really needs one element
		 * for each rv[].colVal[].val array, but we know that at
		 * least one rvq->colVal[].val array has more than one
		 * element. Hence, making 'rv' a clone of 'rvq' will waste
		 * memory.
		 *
		 * However, we believe this waste is acceptable, because
		 * we expect that 'niv' will be small. Also, we are executing
		 * in the context of a utility command, not in a daemon.
		 */
		rv = initRuleValue(niv, rvq);
		if (rv == 0) {
			freeRuleValue(rvq, 1);
			*numVals = 0;
			return (0);
		}

		/*
		 * For each column value in 'rvq', copy to the appropriate
		 * place in 'rv', so that the end result is that all
		 * combinations of values are enumerated, and each
		 * 'rv[n].colVal[i]' is single-valued.
		 *
		 * We do this by traversing the rv[] array 'rvq->numColumns'
		 * times, where each traversal 'i' works on the values
		 * for rvq->colVal[i]. A repeat factor 'repeat' starts out
		 * at '1', and is multiplied by 'rvq->colVal[i].numVals'
		 * at the end of each traversal. Every value
		 * rvq->colVal[i].val[j] is repeated 'repeat' times.
		 *
		 * This algorithm works by regarding the rv[] array as
		 * an I-dimensional array (I = rvq->numColumns), where
		 * each dimension 'i' corresponds to the values for
		 * rvq->colVal[i]. The I-dimensional array is stored
		 * in column-major order.
		 *
		 * Since the 'rv' elements start out as copies of 'rvq',
		 * we achieve the "copy" of the 'rvq' column values by
		 * deleting those we don't want from the 'rv' elements.
		 */
		for (i = 0, repeat = 1; i < rvq->numColumns; i++) {
			int	r, k;
			for (n = 0, j = 0, r = 0; n < niv; n++) {
				/*
				 * Free all but element 'j' of the
				 * rv[n].colVal[i].val array.
				 */
				for (k = 0; k < rv[n].colVal[i].numVals; k++) {
					/* Leave element 'j' in place */
					if (k == j)
						continue;
					sfree(rv[n].colVal[i].val[k].
						value);
				}
				rv[n].colVal[i].numVals = 1;
				/* Move element 'j' to zero */
				if (j != 0)
					rv[n].colVal[i].val[0] =
						rv[n].colVal[i].val[j];

				/*
				 * Increment the repeat index 'r'. If >=
				 * 'repeat', reset 'r' and increment the
				 * value index 'j'. If 'j' >=
				 * rvq->colVal[i].numVals, start over on
				 * the column values for column 'i' (i.e.,
				 * reset 'j' to zero).
				 */
				r += 1;
				if (r >= repeat) {
					r = 0;
					j += 1;
					if (j >= rvq->colVal[i].numVals)
						j = 0;
				}
			}
			repeat *= rvq->colVal[i].numVals;
		}

		*numVals = niv;
		freeRuleValue(rvq, 1);
		rvq = rv;
		rv = 0;
	}

	q = am(myself, *numVals * sizeof (q[0]));
	if (q == 0) {
		freeRuleValue(rvq, *numVals);
		return (0);
	}

	/*
	 * Create queries from the rvq[] array.
	 */
	for (a = 0; a < *numVals; a++) {
		int	nn, err = 0;

		qc = am(myself, rvq[a].numColumns * sizeof (*qc));
		if (qc != 0) {
			for (nn = 0, i = 0; i < rvq[a].numColumns; i++) {
				for (j = 0; j < t->numColumns; j++) {
					if (strcmp(rvq[a].colName[i],
							t->column[j]) == 0) {
						break;
					}
				}
				if (j >= t->numColumns)
					continue;
				qc[nn].which_index = j;
				if (rvq[a].colVal[i].numVals > 0) {
					qc[nn].index_value = buildItem(
						rvq[a].colVal[i].val[0].length,
						rvq[a].colVal[i].val[0].value);
					if (qc[nn].index_value == 0)
						err++;
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"%s: No values for [%d]%s",
						myself, a, rvq[a].colName[i]);
					err++;
				}
				nn++;
			}
			if (err == 0)
				q[a] = buildQuery(nn, qc);
		}
		if (err > 0 || q[a] == 0) {
			freeQueries(q, a);
			for (a = 0; a < nn; a++)
				freeQcomp(&qc[a], F);
			sfree(qc);
			freeRuleValue(rvq, *numVals);
			return (0);
		}
	}

	if (rvP != 0) {
		*rvP = rvq;
	} else {
		freeRuleValue(rvq, 1);
		*numVals = 0;
	}

	return (q);
}

void
printQuery(db_query *q, __nis_table_mapping_t *t) {
	int	i, mc = -1;
	char	*myself = "printQuery";
	char	*val[NIS_MAXCOLUMNS];

	if (q == 0)
		return;

	(void) memset(val, 0, sizeof (val));

	/*
	 * Collect the values, which may be out of order in 'q'.
	 * Remember the largest index.
	 */
	for (i = 0; i < q->components.components_len; i++) {
		int	ix = q->components.components_val[i].which_index;

		if (ix >= NIS_MAXCOLUMNS ||
				(t != 0 && ix >= t->numColumns))
			continue;
		if (ix > mc)
			mc = ix;
		val[ix] = q->components.components_val[i].index_value->
				itemvalue.itemvalue_val;
	}

	/* Print the values we collected */
	for (i = 0; i <= mc; i++) {
		p2buf(myself, "%s%s", (i != 0 ? " " : ""),
			(val[i] != 0 ? val[i] : ""));
	}
	/* If we printed anything, add a newline */
	if (mc >= 0)
		p2buf(myself, "\n");
}

/*
 * Verify that the db_query's 'q' and 'fq' match, in the sense that if
 * they both have a value for a certain index, the values are the same.
 */
int
verifyQueryMatch(db_query *q, db_query *fq) {
	int	i, j, match;

	if (fq == 0)
		return (1);

	if (q == 0)
		return ((fq == 0) ? 1 : 0);

	for (i = 0, match = 1; match && i < q->components.components_len;
			i++) {
		for (j = 0; j < fq->components.components_len; j++) {
			int	len, flen;

			/* Same index ? */
			if (q->components.components_val[i].which_index !=
					fq->components.components_val[j].
						which_index)
				continue;
			/*
			 * If one 'index_value' is NULL, the other one must
			 * be NULL as well.
			 */
			if (q->components.components_val[i].index_value == 0) {
				if (fq->components.components_val[j].
						index_value == 0)
					continue;
				else {
					match = 0;
					break;
				}
			}
			if (fq->components.components_val[j].index_value ==
					0) {
				match = 0;
				break;
			}
			/* Same value lengths ? */
			len = q->components.components_val[i].index_value->
				itemvalue.itemvalue_len;
			flen = fq->components.components_val[j].index_value->
				itemvalue.itemvalue_len;
			if (len != flen) {
				/*
				 * There's a twist here: the input query
				 * may well _not_ count a concluding NUL
				 * in a string value, while the output
				 * usually will. So, if the difference in
				 * length is one, and the "extra" byte is
				 * a zero-valued one, we accept equality.
				 * 'q' is assumed to be the output, and
				 * 'fq' the input.
				 */
				if (!(len > 0 && len == (flen+1) &&
					q->components.components_val[i].
					index_value->
					itemvalue.itemvalue_val[len-1] == 0)) {
					match = 0;
					break;
				}
			}
			/* Same value ? */
			if (memcmp(q->components.components_val[i].index_value->
					itemvalue.itemvalue_val,
				fq->components.components_val[j].index_value->
					itemvalue.itemvalue_val,
					flen) != 0) {
				match = 0;
				break;
			}
		}
	}

	return (match);
}

/*
 * Remove those queries in 'q' that don't match t->index.
 * Returns a pointer to the filtered array, which could be
 * a compacted version of the original, or a new copy; in
 * the latter case, the original will have been freed.
 *
 * Filtered/removed db_query's are freed.
 */
db_query **
filterQuery(__nis_table_mapping_t *t, db_query **q, db_query *qin,
		__nis_obj_attr_t ***objAttr, int *numQueries) {
	db_query		**new;
	__nis_obj_attr_t	**attr;
	int			i, nq, nn;
	char			*myself = "filterQuery";

	if ((t == 0 && qin == 0) || q == 0 ||
			numQueries == 0 || *numQueries <= 0)
		return (q);

	nq = *numQueries;
	new = am(myself, nq * sizeof (new[0]));
	if (objAttr != 0)
		attr = am(myself, nq * sizeof (attr[0]));
	else
		attr = 0;
	if (new == 0 || (objAttr != 0 && attr == 0)) {
		sfree(new);
		freeQueries(q, nq);
		sfree(attr);
		if (objAttr != 0) {
			freeObjAttr(*objAttr, nq);
			*objAttr = 0;
		}
		*numQueries = -1;
		return (0);
	}

	for (i = 0, nn = 0; i < nq; i++) {
		int	retain = 1;

		if (t != 0)
			retain = verifyIndexMatch(t, q[i], 0, 0, 0);

		if (retain && qin != 0)
			retain = verifyQueryMatch(q[i], qin);

		if (retain) {
			new[nn] = q[i];
			if (objAttr != 0)
				attr[nn] = (*objAttr)[i];
			nn++;
		} else {
			freeQuery(q[i]);
			q[i] = 0;
			if (objAttr != 0) {
				freeSingleObjAttr((*objAttr)[i]);
				(*objAttr)[i] = 0;
			}
		}
	}

	/* All q[i]'s are either in 'new', or have been deleted */
	free(q);
	if (objAttr != 0) {
		sfree(*objAttr);
		*objAttr = attr;
	}

	*numQueries = nn;

	return (new);
}

db_query **
createNisPlusEntry(__nis_table_mapping_t *t, __nis_rule_value_t *rv,
			db_query *qin, __nis_obj_attr_t ***objAttr,
			int *numQueries) {
	db_query		**query = 0;
	int			r, i, j, ir;
	__nis_value_t		*rval, *lval;
	__nis_mapping_item_t	*litem;
	int			numItems;
	int			nq;
	__nis_obj_attr_t	**attr = 0;
	char			**dn = 0;
	int			numDN = 0;
	char			*myself = "createNisPlusEntry";

	if (t == 0 || t->objectDN == 0 || rv == 0)
		return (0);

	/* Establish default, per-thread, search base */
	__nisdb_get_tsd()->searchBase = t->objectDN->read.base;

	for (r = 0, nq = 0; r < t->numRulesFromLDAP; r++) {
		int			nrq, ntq, err;
		db_query		**newq;
		__nis_obj_attr_t	**newattr;

		rval = buildRvalue(&t->ruleFromLDAP[r]->rhs,
			mit_ldap, rv, NULL);
		if (rval == 0)
			continue;

		litem = buildLvalue(&t->ruleFromLDAP[r]->lhs, &rval,
					&numItems);
		if (litem == 0) {
			freeValue(rval, 1);
			/* XXX Should this be a fatal error ? */
			continue;
		}

		lval = 0;
		for (i = 0; i < numItems; i++) {
			__nis_value_t	*tmpval, *old;

			tmpval = getMappingItem(&litem[i],
				mit_nisplus, 0, 0, NULL);

			/*
			 * If the LHS specifies an out-of-context LDAP or
			 * NIS+ item, we do the update right here. We
			 * don't add any values to 'lval'; instead, we
			 * skip to the next item. (However, we still
			 * get a string representation of the LHS in case
			 * we need to report an error.)
			 */
			if (litem[i].type == mit_ldap) {
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

		freeMappingItem(litem, numItems);
		if (lval == 0 || lval->numVals <= 0 || rval->numVals <= 0) {
			freeValue(lval, 1);
			freeValue(rval, 1);
			continue;
		}

		/*
		 * We now have a number of possible cases. The notation
		 * used in the table is:
		 *
		 *	single		A single value (numVals == 1)
		 *	single/rep	A single value with repeat == 1
		 *	multi[N]	N values
		 *	multi[N]/rep	M values with repeat == 1
		 *	(M)		M resulting db_query's
		 *
		 * lval \ rval	single	single/rep	multi[N] multi[N]/rep
		 * single	  (1)	    (1)		 (1)	    (1)
		 * single/rep	  (1)	    (1)		 (N)	    (N)
		 * multi[M]	  (1)	    (1)		 (1)	 1+(N-1)/M
		 * multi[M]/rep	  (1)	    (1)		 (1)	 1+(N-1)/M
		 *
		 * Of course, we already have 'nq' db_query's from previous
		 * rules, so the resulting number of queries is max(1,nq)
		 * times the numbers in the table above.
		 */

		/* The number of queries resulting from the current rule */
		if (rval->numVals > 1) {
			if (lval->numVals == 1 && lval->repeat)
				nrq = rval->numVals;
			else if (lval->numVals > 1 && rval->repeat)
				nrq = 1 + ((rval->numVals-1)/lval->numVals);
			else
				nrq = 1;
		} else {
			nrq = 1;
		}

		/* Total number of queries after adding the current rule */
		if (nq <= 0)
			ntq = nrq;
		else
			ntq = nq * nrq;

		if (ntq > nq) {
			newq = realloc(query, ntq * sizeof (query[0]));
			newattr = realloc(attr, ntq * sizeof (attr[0]));
			if (newq == 0 || newattr == 0) {
				logmsg(MSG_NOMEM, LOG_ERR,
					"%s: realloc(%d) => NULL",
					myself, ntq * sizeof (query[0]));
				freeValue(lval, 1);
				freeValue(rval, 1);
				freeQueries(query, nq);
				freeObjAttr(attr, nq);
				sfree(newq);
				freeDNs(dn, numDN);
				return (0);
			}
			query = newq;
			attr = newattr;
		}

		/*
		 * Copy/clone the existing queries to the new array,
		 * remembering that realloc() has done the first 'nq'
		 * ones.
		 *
		 * If there's an error (probably memory allocation), we
		 * still go through the rest of the array, so that it's
		 * simple to free the elements when we clean up.
		 */
		for (i = 1, err = 0; i < nrq; i++) {
			for (j = 0; j < nq; j++) {
				query[(nq*i)+j] = cloneQuery(query[j],
						t->numColumns);
				if (query[(nq*i)+j] == 0 &&
						query[j] != 0)
					err++;
				attr[(nq*i)+j] = cloneObjAttr(attr[j]);
				if (attr[(nq*i)+j] == 0 &&
						attr[j] != 0)
					err++;
			}
		}

		if (err > 0) {
			freeValue(lval, 1);
			freeValue(rval, 1);
			freeQueries(query, ntq);
			freeObjAttr(attr, ntq);
			freeDNs(dn, numDN);
			return (0);
		}

		/*
		 * Special case if nq == 0 (i.e., the first time we
		 * allocated db_query's). If so, we now allocate empty
		 * db_qcomp arrays, which simplifies subsequent
		 * copying of values.
		 */
		if (nq <= 0) {
			(void) memset(query, 0, ntq * sizeof (query[0]));
			(void) memset(attr, 0, ntq * sizeof (attr[0]));
			for (i = 0, err = 0; i < ntq; i++) {
				query[i] = am(myself, sizeof (*query[i]));
				if (query[i] == 0) {
					err++;
					break;
				}
				query[i]->components.components_val =
					am(myself, t->numColumns *
			sizeof (query[i]->components.components_val[0]));
				if (query[i]->components.components_val == 0) {
					err++;
					break;
				}
				query[i]->components.components_len = 0;
			}
			if (err > 0) {
				freeValue(lval, 1);
				freeValue(rval, 1);
				freeQueries(query, ntq);
				freeObjAttr(attr, ntq);
				freeDNs(dn, numDN);
				return (0);
			}
		}

		/* Now we're ready to add the new values */
		for (i = 0, ir = 0; i < lval->numVals; i++) {
			char	*oaName = 0;
			int	index;

			/* Find column index */
			for (index = 0; index < t->numColumns;
					index++) {
				if (strncmp(t->column[index],
						lval->val[i].value,
					lval->val[i].length) == 0)
					break;
			}
			if (index >= t->numColumns) {
				/*
				 * Could be one of the special object
				 * attributes.
				 */
				oaName = isObjAttr(&lval->val[i]);
				if (oaName == 0)
					continue;
			}

			for (j = i*nrq; j < (i+1)*nrq; j++) {
				int	k;

				/* If we're out of values, repeat last one */
				ir = (j < rval->numVals) ?
					j : rval->numVals - 1;

				/*
				 * Step through the query array, adding
				 * the new value every 'nrq' queries, and
				 * starting at 'query[j % nrq]'.
				 */
				for (k = j % nrq, err = 0; k < ntq; k += nrq) {
					int	ic, c;

					if (oaName != 0) {
						int	fail = setObjAttrField(
								oaName,
								&rval->val[ir],
								&attr[k]);
						if (fail) {
							err++;
							break;
						}
						continue;
					}

					ic = query[k]->components.
						components_len;
					/*
					 * If we've already filled this
					 * query, the new value is a dup
					 * which we'll ignore.
					 */
					if (ic >= t->numColumns)
						continue;

					/*
					 * Do we already have a value for
					 * this 'index' ?
					 */
					for (c = 0; c < ic; c++) {
						if (query[k]->components.
							components_val[c].
							which_index == index)
							break;
					}

					/* If no previous value, add it */
					if (c >= ic) {
						int	l;
						char	*v;

						query[k]->components.
							components_val[ic].
							which_index = index;
						l = rval->val[ir].length;
						v = rval->val[ir].value;
						if (rval->type == vt_string &&
							l > 0 &&
							v[l-1] != '\0' &&
							v[l] == '\0')
							l++;
						query[k]->components.
							components_val[ic].
							index_value =
							buildItem(l, v);
						if (query[k]->
							components.
							components_val[ic].
							index_value == 0) {
							err++;
							break;
						}
						query[k]->components.
							components_len++;
					}
				}
				if (err > 0) {
					freeValue(lval, 1);
					freeValue(rval, 1);
					freeQueries(query, ntq);
					freeObjAttr(attr, ntq);
					freeDNs(dn, numDN);
					return (0);
				}
			}
		}
		freeValue(lval, 1);
		freeValue(rval, 1);

		nq = ntq;
	}

	freeDNs(dn, numDN);

	if (nq <= 0) {
		sfree(query);
		query = 0;
	}

	/* Should we filter on index or input query ? */
	if (query != 0) {
		if (t->index.numIndexes > 0)
			query = filterQuery(t, query, qin, &attr, &nq);
		else if (qin != 0)
			query = filterQuery(0, query, qin, &attr, &nq);
	}

	if (query != 0 && numQueries != 0)
		*numQueries = nq;

	if (objAttr != 0)
		*objAttr = attr;
	else
		freeObjAttr(attr, nq);

	return (query);
}
/*
 * Given a table mapping and a rule-value, convert to an array of
 * (db_query *), using the fromLDAP ruleset.
 *
 * On entry, '*numQueries' holds the number of elements in the 'rv'
 * array. On exit, it holds the number of (db_query *)'s in the return
 * value array.
 */
db_query **
ruleValue2Query(__nis_table_mapping_t *t, __nis_rule_value_t *rv,
		db_query *qin, __nis_obj_attr_t ***objAttr, int *numQueries) {
	db_query		**q = 0, ***qp = 0;
	int			i, nqp, nq, *nnp = 0, nv;
	__nis_obj_attr_t	**attr = 0, ***atp = 0;
	char			*myself = "ruleValue2Query";


	if (t == 0 || rv == 0 || numQueries == 0)
		return (0);

	nv = *numQueries;
	if (nv <= 0)
		return (0);

	/*
	 * 'qp' is an array of (db_query **), and we get one element for
	 * each call to createNisPlusEntry(); i.e., one for each rule-value.
	 *
	 * 'nnp[i]' is the count of (db_query *) in each 'qp[i]'.
	 */
	qp = am(myself, nv * sizeof (*qp));
	nnp = am(myself, nv * sizeof (*nnp));
	atp = am(myself, nv * sizeof (*atp));
	if (qp == 0 || nnp == 0 || atp == 0) {
		sfree(qp);
		sfree(nnp);
		sfree(atp);
		return (0);
	}

	for (i = 0, nq = 0, nqp = 0; i < nv; i++) {
		qp[nqp] = createNisPlusEntry(t, &rv[i], qin, &atp[nqp],
						&nnp[nqp]);
		/* If we fail, abort (XXX??? or continue ???) */
		if (qp[nqp] == 0)
			goto cleanup;
		nq += nnp[nqp];
		nqp++;
	}

	/* If we didn't get any (db_query **)'s, return failure */
	if (nqp == 0 || nq <= 0)
		goto cleanup;

	q = am(myself, nq * sizeof (q[0]));
	attr = am(myself, nq * sizeof (attr[0]));
	if (q == 0 || attr == 0) {
		nq = 0;
		goto cleanup;
	}

	/* Convert 'qp' to an array of (db_query *)'s */
	for (i = 0, nq = 0; i < nqp; i++) {
		(void) memcpy(&q[nq], qp[i], nnp[i] * sizeof (qp[i][0]));
		(void) memcpy(&attr[nq], atp[i], nnp[i] * sizeof (atp[i][0]));
		nq += nnp[i];
		free(qp[i]);
		free(atp[i]);
	}

	*numQueries = nq;
	if (objAttr != 0)
		*objAttr = attr;
	else
		freeObjAttr(attr, nq);

	/* Make sure 'cleanup' doesn't free the db_query pointers */
	nqp = 0;

cleanup:
	for (i = 0; i < nqp; i++) {
		freeQueries(qp[i], nnp[i]);
		sfree(atp[i]);
	}
	sfree(qp);
	sfree(nnp);
	sfree(atp);

	return (q);
}

db_query *
pseudoEntryObj2Query(entry_obj *e, nis_object *tobj, __nis_rule_value_t *rv) {
	db_query		*qbuf;
	db_qcomp		*qcbuf;
	int			nc, i;
	__nis_rule_value_t	*rvt = 0;
	char			*myself = "pseudoEntryObj2Query";

	nc = e->en_cols.en_cols_len - 1;

	if (e == 0 || nc < 0 || nc > NIS_MAXCOLUMNS)
		return (0);

	/*
	 * If 'rvP' is non-NULL, build a rule value from the pseudo-
	 * nis_object in e->en_cols.en_cols_val[0].
	 */
	if (rv != 0) {
		nis_object		*o;

		o = unmakePseudoEntryObj(e, tobj);
		if (o == 0)
			return (0);
		rvt = addObjAttr2RuleValue(o, 0);
		nis_destroy_object(o);
		if (rvt == 0)
			return (0);
	}

	qbuf = am(myself, sizeof (*qbuf));
	/*
	 * If there are no columns (other than the pseudo-entry object),
	 * we're done.
	 */
	if (nc == 0)
		return (qbuf);

	qcbuf = am(myself, nc * sizeof (*qcbuf));
	if (qcbuf == 0) {
		sfree(qcbuf);
		if (rvt != 0)
			freeRuleValue(rvt, 1);
		return (0);
	}

	/*
	 * Build the db_query, remembering that e->en_cols.en_cols_val[0]
	 * is the pseudo-nis_object.
	 */
	qbuf->components.components_val = qcbuf;
	qbuf->components.components_len = nc;
	for (i = 0; i < nc; i++) {
		qcbuf[i].which_index = i;
		qcbuf[i].index_value = buildItem(
			e->en_cols.en_cols_val[i+1].ec_value.ec_value_len,
			e->en_cols.en_cols_val[i+1].ec_value.ec_value_val);
		if (qcbuf[i].index_value == 0) {
			freeQuery(qbuf);
			if (rvt != 0)
				freeRuleValue(rvt, 1);
			return (0);
		}
	}

	if (rvt != 0) {
		*rv = *rvt;
		sfree(rvt);
	}

	return (qbuf);
}

/*
 * Given an input query 'q', and a db_query work buffer 'qbuf', return
 * a pointer to a query with one component corresponding to component
 * 'index' in 'q'.
 *
 * Note that no memory is allocated, and that the returned query has
 * pointers into 'q'.
 */
db_query *
queryFromComponent(db_query *q, int index, db_query *qbuf) {

	if (q == 0 || index < 0 || index >= q->components.components_len ||
			qbuf == 0)
		return (0);

	qbuf->components.components_len = 1;
	qbuf->components.components_val = &q->components.components_val[index];

	return (qbuf);
}
