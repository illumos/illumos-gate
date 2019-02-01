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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2019, Joyent, Inc. All rights reserved.
 */

#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/fm/protocol.h>
#include <sys/utsname.h>

#include <topo_parse.h>
#include <topo_prop.h>
#include <topo_tree.h>

/*
 * In the XML representation of the topo snapshot, 32-bit integer values are
 * represented as base-10 values.
 *
 * 10 bytes for base-10 value + 1 for sign + nul
 */
#define	INT32BUFSZ	12
/* 2 bytes for "0x" + 16 bytes for the hex value + 1 for sign + nul */
#define	INT64BUFSZ	20
#define	XML_VERSION	"1.0"

static int txml_print_range(topo_hdl_t *, FILE *, tnode_t *, int);

void
print_header(FILE *fp)
{
	char buf[32];
	time_t tod = time(NULL);
	struct utsname uts;

	(void) fprintf(fp, "<?xml version=\"%s\"?>\n", XML_VERSION);
	(void) fprintf(fp, "<!DOCTYPE topology SYSTEM \"%s\">\n",
	    TOPO_DTD_PATH);

	(void) uname(&uts);
	(void) strftime(buf, sizeof (buf), "%b %d %T", localtime(&tod));
	(void) fprintf(fp, "<!--\n");
	(void) fprintf(fp, " This topology map file was generated on "
	    "%-15s for %s\n", buf, uts.nodename);
	(void) fprintf(fp, "<-->\n\n");
}

void
begin_element(FILE *fp, const char *ename, ...)
{
	char *name, *value;
	va_list ap;

	(void) fprintf(fp, "<%s ", ename);
	va_start(ap, ename);
	name = va_arg(ap, char *);
	while (name != NULL) {
		value = va_arg(ap, char *);
		(void) fprintf(fp, "%s='%s' ", name, value);
		name = va_arg(ap, char *);
	}
	(void) fprintf(fp, ">\n");
}

void
begin_end_element(FILE *fp, const char *ename, ...)
{
	char *name, *value;
	va_list ap;

	(void) fprintf(fp, "<%s ", ename);
	va_start(ap, ename);
	name = va_arg(ap, char *);
	while (name != NULL) {
		value = va_arg(ap, char *);
		(void) fprintf(fp, "%s='%s' ", name, value);
		name = va_arg(ap, char *);
	}
	(void) fprintf(fp, "/>\n");
}

void
end_element(FILE *fp, const char *ename)
{
	(void) fprintf(fp, "</%s>\n", ename);
}

static void
txml_print_prop(topo_hdl_t *thp, FILE *fp, tnode_t *node, const char *pgname,
    topo_propval_t *pv)
{
	int err;
	char *fmri = NULL;
	char vbuf[INT64BUFSZ], tbuf[32], *pval = NULL, *aval = NULL;

	switch (pv->tp_type) {
		case TOPO_TYPE_INT32: {
			int32_t val;
			if (topo_prop_get_int32(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "%d", val);
				(void) snprintf(tbuf, sizeof (tbuf), "%s",
				    Int32);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;
			if (topo_prop_get_uint32(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%x", val);
				(void) snprintf(tbuf, sizeof (tbuf), "%s",
				    UInt32);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;
			if (topo_prop_get_int64(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%llx",
				    (longlong_t)val);
				(void) snprintf(tbuf, sizeof (tbuf), "%s",
				    Int64);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;
			if (topo_prop_get_uint64(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%llx",
				    (u_longlong_t)val);
				(void) snprintf(tbuf, sizeof (tbuf), "%s",
				    UInt64);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_STRING: {
			if (topo_prop_get_string(node, pgname, pv->tp_name,
			    &pval, &err) != 0)
				return;
			(void) snprintf(tbuf, sizeof (tbuf), "%s", "string");
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *val;

			if (topo_prop_get_fmri(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				if (topo_fmri_nvl2str(thp, val, &fmri, &err)
				    == 0) {
					nvlist_free(val);
					pval = fmri;
				} else {
					nvlist_free(val);
					return;
				}
			} else
				return;
			(void) snprintf(tbuf, sizeof (tbuf), "%s", FMRI);
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint32_t *val;
			uint_t nelem, i;
			if (topo_prop_get_uint32_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			if (nelem > 0) {
				if ((aval = calloc((nelem * 9 - 1),
				    sizeof (uchar_t))) == NULL) {

					topo_hdl_free(thp, val,
					    nelem * sizeof (uint32_t));
					return;
				}

				(void) sprintf(aval, "0x%x", val[0]);
				for (i = 1; i < nelem; i++) {
					(void) sprintf(vbuf, " 0x%x", val[i]);
					(void) strcat(aval, vbuf);
				}
				topo_hdl_free(thp, val,
				    nelem * sizeof (uint32_t));
				(void) snprintf(tbuf, sizeof (tbuf), "%s",
				    UInt32_Arr);
				pval = aval;
			}
			break;
		}
		default:
			return;
	}

	begin_end_element(fp, Propval, Name, pv->tp_name, Type, tbuf,
	    Value, pval, NULL);

	if (pval != NULL && pv->tp_type == TOPO_TYPE_STRING)
		topo_hdl_strfree(thp, pval);

	if (fmri != NULL)
		topo_hdl_strfree(thp, fmri);

	if (aval != NULL)
		free(aval);
}

static void
txml_print_pgroup(topo_hdl_t *thp, FILE *fp, tnode_t *node, topo_pgroup_t *pg)
{
	topo_ipgroup_info_t *pip = pg->tpg_info;
	topo_proplist_t *plp;
	const char *namestab, *datastab;
	char version[INT32BUFSZ];

	namestab = topo_stability2name(pip->tpi_namestab);
	datastab = topo_stability2name(pip->tpi_datastab);
	(void) snprintf(version, INT32BUFSZ, "%d", pip->tpi_version);
	begin_element(fp, Propgrp, Name, pip->tpi_name, Namestab,
	    namestab, Datastab, datastab, Version, version, NULL);
	for (plp = topo_list_next(&pg->tpg_pvals); plp != NULL;
	    plp = topo_list_next(plp)) {
		txml_print_prop(thp, fp, node, pip->tpi_name, plp->tp_pval);
	}
	end_element(fp, Propgrp);
}

static void
txml_print_dependents(topo_hdl_t *thp, FILE *fp, tnode_t *node)
{
	if (topo_list_next(&node->tn_children) == NULL)
		return;

	if (txml_print_range(thp, fp, node, 1) == 1)
		end_element(fp, Dependents);
}

static void
txml_print_node(topo_hdl_t *thp, FILE *fp, tnode_t *node)
{
	char inst[INT32BUFSZ];
	topo_pgroup_t *pg;

	(void) snprintf(inst, INT32BUFSZ, "%d", node->tn_instance);
	begin_element(fp, Node, Instance, inst, Static, True, NULL);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		txml_print_pgroup(thp, fp, node, pg);
	}
	txml_print_dependents(thp, fp, node);
	end_element(fp, Node);

}

static int
txml_print_range(topo_hdl_t *thp, FILE *fp, tnode_t *node, int dependent)
{
	int i, create = 0, ret = 0;
	topo_nodehash_t *nhp;
	char min[INT32BUFSZ], max[INT32BUFSZ];

	for (nhp = topo_list_next(&node->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		(void) snprintf(min, INT32BUFSZ, "%d", nhp->th_range.tr_min);
		(void) snprintf(max, INT32BUFSZ, "%d", nhp->th_range.tr_max);

		/*
		 * Some enumerators create empty ranges: make sure there
		 * are real nodes before creating this range
		 */
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				++create;
		}
		if (!create)
			continue;

		if (dependent) {
			begin_element(fp, Dependents, Grouping, Children, NULL);
			dependent = 0;
			ret = 1;
		}
		begin_element(fp, Range, Name, nhp->th_name, Min, min, Max,
		    max, NULL);
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				txml_print_node(thp, fp, nhp->th_nodearr[i]);
		}
		end_element(fp, Range);
	}

	return (ret);
}

static void
txml_print_topology(topo_hdl_t *thp, FILE *fp, char *scheme, tnode_t *node)
{
	char *name;

	if (thp->th_product != NULL)
		name = thp->th_product;
	else
		name = thp->th_platform;

	begin_element(fp, Topology, Name, name, Scheme, scheme,
	    NULL);
	(void) txml_print_range(thp, fp, node, 0);
	end_element(fp, Topology);

}

int
topo_xml_print(topo_hdl_t *thp,  FILE *fp, const char *scheme, int *err)
{
	ttree_t *tp;

	print_header(fp);
	for (tp = topo_list_next(&thp->th_trees); tp != NULL;
	    tp = topo_list_next(tp)) {
		if (strcmp(scheme, tp->tt_scheme) == 0) {
			txml_print_topology(thp, fp, tp->tt_scheme,
			    tp->tt_root);
			return (0);
		}
	}

	*err = EINVAL;
	return (-1);
}
