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

#include "ldap_util.h"
#include "ldap_print.h"


void
printMappingFormat(__nis_mapping_format_t *f) {
	__nis_value_t	*val = getMappingFormat(f, 0, fa_any, 0, 0);
	int		i;
	char		*myself = "printMappingFormat";

	if (val == 0)
		return;

	for (i = 0; i < val->numVals; i++) {
		c2buf(myself, val->val[i].value, val->val[i].length);
	}
	freeValue(val, 1);
}

void
printMappingFormatArray(__nis_mapping_format_t *a) {
	__nis_value_t	*val = getMappingFormatArray(a, 0, fa_any, 0, 0);
	char		*myself = "printMappingFormatArray";

	if (val != 0) {
		if (val->type == vt_string) {
			int	i;

			if (a[0].type != mmt_begin)
				p2buf(myself, "\"");
			for (i = 0; i < val->numVals; i++) {
				sc2buf(myself, val->val[i].value,
					val->val[i].length);
			}
		} else {
			p2buf(myself, "<illegal>");
		}
		freeValue(val, 1);
	} else {
		p2buf(myself, "<novals>");
	}
}

void
printIndex(__nis_index_t *i) {
	int	len = 0;
	char	*str = getIndex(i, &len);
	char	*myself = "printIndex";

	sc2buf(myself, str, len);
	sfree(str);
}

void
printObjSpec(__nis_obj_spec_t *o) {
	int	len = 0;
	char	*str = getObjSpec(o, &len);
	char	*myself = "printObjSpec";

	sc2buf(myself, str, len);
	sfree(str);
}

void
printSearchTriple(__nis_search_triple_t *s) {
	int	len = 0;
	char	*str = getSearchTriple(s, &len);
	char	*myself = "printSearchTriple";

	sc2buf(myself, str, len);
	sfree(str);
}

void
printMappingItem(__nis_mapping_item_t *i, __nis_mapping_item_type_t native) {
	__nis_value_t	*val = getMappingItem(i, native, 0, 0, NULL);
	int		j;
	char		*myself = "printMappingItem";

	if (val == 0)
		return;

	if (i->repeat)
		p2buf(myself, "(");
	for (j = 0; j < val->numVals; j++) {
		c2buf(myself, val->val[j].value, val->val[j].length);
	}
	if (i->repeat)
		p2buf(myself, ")");
	freeValue(val, 1);
}

void
printMappingSubElement(__nis_mapping_sub_element_t *e,
			__nis_mapping_item_type_t native) {
	int	i;
	char	*myself = "printMappingSubElement";

	switch (e->type) {
	case me_item:
		printMappingItem(&e->element.item, native);
		break;
	case me_print:
		p2buf(myself, "(");
		printMappingFormatArray(e->element.print.fmt);
		for (i = 0; i < e->element.print.numItems; i++) {
			p2buf(myself, ", ");
			printMappingItem(&e->element.print.item[i], native);
		}
		if (e->element.print.doElide) {
			p2buf(myself, ", \"%c\"", e->element.print.elide);
		}
		p2buf(myself, ")");
		break;
	case me_split:
		p2buf(myself, "(");
		printMappingItem(&e->element.split.item, native);
		p2buf(myself, ", \"%c\")", e->element.split.delim);
		break;
	case me_match:
		p2buf(myself, "<me_match>");
		break;
	case me_extract:
		p2buf(myself, "(");
		printMappingItem(&e->element.extract.item, native);
		p2buf(myself, ", ");
		printMappingFormatArray(e->element.extract.fmt);
		p2buf(myself, ")");
		break;
	default:
		p2buf(myself, "(<unknown>)");
		break;
	}
}

void
printMappingElement(__nis_mapping_element_t *e,
			__nis_mapping_item_type_t native) {
	int	i;
	char	*myself = "printMappingElement";

	switch (e->type) {
	case me_item:
		printMappingItem(&e->element.item, native);
		break;
	case me_print:
		p2buf(myself, "(");
		printMappingFormatArray(e->element.print.fmt);
		for (i = 0; i < e->element.print.numSubElements; i++) {
			p2buf(myself, ", ");
			printMappingSubElement(
				&e->element.print.subElement[i], native);
		}
		if (e->element.print.doElide) {
			p2buf(myself, ", \"%c\"", e->element.print.elide);
		}
		p2buf(myself, ")");
		break;
	case me_split:
		p2buf(myself, "(");
		printMappingItem(&e->element.split.item, native);
		p2buf(myself, ", \"%c\")", e->element.split.delim);
		break;
	case me_match:
		p2buf(myself, "(");
		printMappingFormatArray(e->element.match.fmt);
		for (i = 0; i < e->element.match.numItems; i++) {
			p2buf(myself, ", ");
			printMappingItem(&e->element.match.item[i], native);
		}
		p2buf(myself, ")");
		break;
	case me_extract:
		p2buf(myself, "(");
		printMappingItem(&e->element.extract.item, native);
		p2buf(myself, ", ");
		printMappingFormatArray(e->element.extract.fmt);
		p2buf(myself, ")");
		break;
	default:
		p2buf(myself, "(<unknown>)");
		break;
	}
}

void
printMappingRLHS(__nis_mapping_rlhs_t *m, __nis_mapping_item_type_t native) {
	int	i;
	char	*myself = "printMappingRLHS";

	if (m->numElements > 1)
		p2buf(myself, "(");
	for (i = 0; i < m->numElements; i++) {
		printMappingElement(&m->element[i], native);
	}
	if (m->numElements > 1)
		p2buf(myself, ")");
}

void
printMappingRule(__nis_mapping_rule_t *r,
		__nis_mapping_item_type_t nativeLhs,
		__nis_mapping_item_type_t nativeRhs) {
	char		*myself = "printMappingRule";

	printMappingRLHS(&r->lhs, nativeLhs);
	p2buf(myself, "=");
	printMappingRLHS(&r->rhs, nativeRhs);
}

void
printObjName(__nis_index_t *index, char *name) {
	char		*myself = "printObjName";

	printIndex(index);
	p2buf(myself, "%s", NIL(name));
}

void
printobjectDN(__nis_object_dn_t *o) {
	char		*myself = "printobjectDN";
	int		i;

	p2buf(myself, "\t");
	printSearchTriple(&o->read);
	p2buf(myself, ":\n\t");
	printSearchTriple(&o->write);
	switch (o->delDisp) {
	case dd_always:
		p2buf(myself, ":\n\t\talways");
		break;
	case dd_perDbId:
		p2buf(myself, ":\n\t\tdbid=%s\n", NIL(o->dbIdName));
		for (i = 0; i < o->numDbIds; i++) {
			p2buf(myself, "\t\t\t");
			printMappingRule(o->dbId[i], mit_ldap, mit_nisplus);
		}
		break;
	case dd_never:
		p2buf(myself, ":\n\t\tnever");
		break;
	default:
		p2buf(myself, ":\n\t\t<unknown>");
	}
}

void
printTableMapping(__nis_table_mapping_t *t) {
	__nis_object_dn_t	*o;
	int			i;
	char			*myself = "printTableMapping";

	p2buf(myself, "\n%s:", NIL(t->dbId));
	printObjName(&t->index, t->objName);
	p2buf(myself, "\n\t%s \t%s", NIL(t->objName), NIL(t->objPath));
	p2buf(myself, "\n\tTTL = (%d - %d) -> %d\n",
		t->initTtlLo, t->initTtlHi, t->ttl);

	for (o = t->objectDN; o != 0; o = o->next) {
		printobjectDN(o);
		p2buf(myself, "\n");
	}

	p2buf(myself, "\tLDAP -> NIS+\n");
	p2buf(myself, "\tRules:\n");
	for (i = 0; i < t->numRulesFromLDAP; i++) {
		p2buf(myself, "\t\t");
		printMappingRule(t->ruleFromLDAP[i], mit_nisplus, mit_ldap);
		p2buf(myself, "\n");
	}

	p2buf(myself, "\tNIS+ -> LDAP\n");
	p2buf(myself, "\tRules:\n");
	for (i = 0; i < t->numRulesToLDAP; i++) {
		p2buf(myself, "\t\t");
		printMappingRule(t->ruleToLDAP[i], mit_ldap, mit_nisplus);
		p2buf(myself, "\n");
	}
}

void
printRuleValue(__nis_rule_value_t *rv) {
	int		i, j;
	__nis_buffer_t	b = {0, 0};
	char		*myself = "printRuleValue";

	if (rv == 0)
		return;

	if (rv->colName != 0) {
		bp2buf(myself, &b, "Columns:\n");
		for (i = 0; i < rv->numColumns; i++) {
			bp2buf(myself, &b, "\t%s", NIL(rv->colName[i]));
			if (rv->colVal[i].numVals == 1) {
				bp2buf(myself, &b, "=");
				if (rv->colVal[i].type == vt_string)
					sbc2buf(myself,
						rv->colVal[i].val[0].value,
					rv->colVal[i].val[0].length, &b);
				else
					bc2buf(myself,
						rv->colVal[i].val[0].value,
					rv->colVal[i].val[0].length, &b);
				bp2buf(myself, &b, "\n");
			} else {
				bp2buf(myself, &b, "\n");
				for (j = 0; j < rv->colVal[i].numVals; j++) {
					bp2buf(myself, &b, "\t\t");
					if (rv->colVal[i].type == vt_string)
						sbc2buf(myself,
						rv->colVal[i].val[j].value,
						rv->colVal[i].val[j].length,
						&b);
					else
						bc2buf(myself,
						rv->colVal[i].val[j].value,
						rv->colVal[i].val[j].length,
						&b);
					bp2buf(myself, &b, "\n");
				}
			}
		}
	}

	if (rv->attrName != 0) {
		bp2buf(myself, &b, "Attributes:\n");
		for (i = 0; i < rv->numAttrs; i++) {
			bp2buf(myself, &b, "\t%s", NIL(rv->attrName[i]));
			if (rv->attrVal[i].numVals == 1) {
				bp2buf(myself, &b, "=");
				if (rv->attrVal[i].type == vt_string)
					sbc2buf(myself,
						rv->attrVal[i].val[0].value,
						rv->attrVal[i].val[0].length,
						&b);
				else
					bc2buf(myself,
						rv->attrVal[i].val[0].value,
						rv->attrVal[i].val[0].length,
						&b);
				bp2buf(myself, &b, "\n");
			} else {
				bp2buf(myself, &b, "\n");
				for (j = 0; j < rv->attrVal[i].numVals; j++) {
					bp2buf(myself, &b, "\t\t");
					if (rv->attrVal[i].type == vt_string)
						sbc2buf(myself,
						rv->attrVal[i].val[j].value,
						rv->attrVal[i].val[j].length,
						&b);
					else
						bc2buf(myself,
						rv->attrVal[i].val[j].value,
						rv->attrVal[i].val[j].length,
						&b);
					bp2buf(myself, &b, "\n");
				}
			}
		}
	}

	c2buf(myself, b.buf, b.len);
	sfree(b.buf);
	printbuf();
}

void
printLdapMod(LDAPMod **mods, __nis_buffer_t *b) {
	LDAPMod		*m;
	char		*s;
	char		*myself = "printLdapMod";

	if (mods == 0)
		return;

	if (b == 0)
		b = &pb;

	while ((m = *mods) != 0) {
		if ((m->mod_op & LDAP_MOD_ADD) != 0 ||
				(m->mod_op & ~LDAP_MOD_BVALUES) == 0) {
			s = "ADD    ";
		} else if ((m->mod_op & LDAP_MOD_DELETE) != 0) {
			s = "DELETE ";
		} else if ((m->mod_op & LDAP_MOD_REPLACE) != 0) {
			s = "REPLACE";
		} else {
			s = "UNKNOWN";
		}
		bp2buf(myself, b, "%s: %s\n", s, m->mod_type);
		if ((m->mod_op & LDAP_MOD_BVALUES) == 0) {
			char	**v = m->mod_values;

			if (v != 0) {
				while (*v != 0) {
					bp2buf(myself, b, "\t%s\n", *v);
					v++;
				}
			}
		} else {
			struct berval	**bv = m->mod_bvalues;

			if (bv != 0) {
				while (*bv != 0) {
					bp2buf(myself, b, "\t<ber> %d bytes\n",
						(*bv)->bv_len);
					bv++;
				}
			}
		}
		mods++;
	}
}

static void
printObjRights(char *msg, void *access) {
	uchar_t	*a = access;
	int	i;

	if (a == 0)
		return;

	for (i = 0; i < 4; i++) {
		p2buf(msg, "%s", (a[i] & NIS_READ_ACC) ? "r" : "-");
		p2buf(msg, "%s", (a[i] & NIS_MODIFY_ACC) ? "m" : "-");
		p2buf(msg, "%s", (a[i] & NIS_CREATE_ACC) ? "c" : "-");
		p2buf(msg, "%s", (a[i] & NIS_DESTROY_ACC) ? "d" : "-");
	}
}

void
printObjAttr(__nis_obj_attr_t *attr) {
	char	*myself = "printObjAttr";

	if (attr == 0)
		return;

	p2buf(myself, "\tzo_owner  = %s\n", NIL(attr->zo_owner));
	p2buf(myself, "\tzo_group  = %s\n", NIL(attr->zo_group));
	p2buf(myself, "\tzo_domain = %s\n", NIL(attr->zo_domain));
	p2buf(myself, "\tzo_access = ");
	printObjRights(myself, &attr->zo_access);
	p2buf(myself, " (0x%08x)\n", attr->zo_access);
	p2buf(myself, "\tzo_ttl    = %d\n", attr->zo_ttl);
}
