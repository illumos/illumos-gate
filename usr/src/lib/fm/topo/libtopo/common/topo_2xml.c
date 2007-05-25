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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/fm/protocol.h>
#include <sys/utsname.h>

#include <topo_parse.h>
#include <topo_prop.h>
#include <topo_tree.h>

#define	INT32BUFSZ	sizeof (UINT32_MAX) + 1
#define	INT64BUFSZ	sizeof (UINT64_MAX) + 1
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
txml_print_prop(topo_hdl_t *thp, FILE *fp, topo_propval_t *pv)
{
	int err;
	char *fmri = NULL;
	char vbuf[INT64BUFSZ], tbuf[10], *pval;
	nvpair_t *nvp;

	nvp = nvlist_next_nvpair(pv->tp_val, NULL);
	while (nvp && (strcmp(TOPO_PROP_VAL_VAL, nvpair_name(nvp)) != 0))
			nvp = nvlist_next_nvpair(pv->tp_val, nvp);

	if (nvp == NULL)
		return;

	switch (pv->tp_type) {
		case TOPO_TYPE_INT32: {
			int32_t val;
			(void) nvpair_value_int32(nvp, &val);
			(void) snprintf(vbuf, INT64BUFSZ, "%d", val);
			(void) snprintf(tbuf, 10, "%s", Int32);
			pval = vbuf;
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;
			(void) nvpair_value_uint32(nvp, &val);
			(void) snprintf(vbuf, INT64BUFSZ, "0x%x", val);
			(void) snprintf(tbuf, 10, "%s", UInt32);
			pval = vbuf;
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;
			(void) nvpair_value_int64(nvp, &val);
			(void) snprintf(vbuf, INT64BUFSZ, "%lld",
			    (longlong_t)val);
			(void) snprintf(tbuf, 10, "%s", Int64);
			pval = vbuf;
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;
			(void) nvpair_value_uint64(nvp, &val);
			(void) snprintf(vbuf, INT64BUFSZ, "0x%llx",
			    (u_longlong_t)val);
			(void) snprintf(tbuf, 10, "%s", UInt64);
			pval = vbuf;
			break;
		}
		case TOPO_TYPE_STRING: {
			(void) nvpair_value_string(nvp, &pval);
			(void) snprintf(tbuf, 10, "%s", String);
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *val;

			(void) nvpair_value_nvlist(nvp, &val);
			if (topo_fmri_nvl2str(thp, val, &fmri, &err) == 0)
				pval = fmri;
			else
				return;

			(void) snprintf(tbuf, 10, "%s", FMRI);
			break;
		}
	}

	begin_end_element(fp, Propval, Name, pv->tp_name, Type, tbuf,
	    Value, pval, NULL);

	if (fmri != NULL)
		topo_hdl_strfree(thp, fmri);

}

static void
txml_print_pgroup(topo_hdl_t *thp, FILE *fp, topo_pgroup_t *pg)
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
		txml_print_prop(thp, fp, plp->tp_pval);
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
		txml_print_pgroup(thp, fp, pg);
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
