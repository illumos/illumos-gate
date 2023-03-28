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
/*
 * Buffer that is large enough to hold the string representation of any signed
 * or unsigned 64-bit integer.
 *
 * 2 bytes for "0x" + 16 bytes for the base-16 value + nul
 * or
 * 19 bytes for base-10 value + 1 for sign + nul
 */
#define	INT64BUFSZ	21
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
	uint_t nelem;
	char vbuf[INT64BUFSZ];

	switch (pv->tp_type) {
		case TOPO_TYPE_INT32: {
			int32_t val;

			if (topo_prop_get_int32(node, pgname, pv->tp_name, &val,
			    &err) != 0)
				return;

			(void) snprintf(vbuf, INT64BUFSZ, "%d", val);
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    Int32, Value, vbuf, NULL);
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;

			if (topo_prop_get_uint32(node, pgname, pv->tp_name,
			    &val, &err) != 0)
				return;

			(void) snprintf(vbuf, INT64BUFSZ, "0x%x", val);
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    UInt32, Value, vbuf, NULL);
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;

			if (topo_prop_get_int64(node, pgname, pv->tp_name, &val,
			    &err) != 0)
				return;

			(void) snprintf(vbuf, INT64BUFSZ, "%" PRId64, val);
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    Int64, Value, vbuf, NULL);
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;

			if (topo_prop_get_uint64(node, pgname, pv->tp_name,
			    &val, &err) != 0)
				return;

			(void) snprintf(vbuf, INT64BUFSZ, "0x%" PRIx64, val);
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    UInt64, Value, vbuf, NULL);
			break;
		}
		case TOPO_TYPE_DOUBLE: {
			double val;
			char *dblstr = NULL;

			if (topo_prop_get_double(node, pgname, pv->tp_name,
			    &val, &err) != 0)
				return;

			/*
			 * The %a format specifier allows floating point values
			 * to be serialized without losing precision.
			 */
			if (asprintf(&dblstr, "%a", val) < 0)
				return;
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    Double, Value, dblstr, NULL);
			free(dblstr);
			break;
		}
		case TOPO_TYPE_STRING: {
			char *strbuf = NULL;

			if (topo_prop_get_string(node, pgname, pv->tp_name,
			    &strbuf, &err) != 0)
				return;

			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    String, Value, strbuf, NULL);
			topo_hdl_strfree(thp, strbuf);
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *val = NULL;
			char *fmristr = NULL;

			if (topo_prop_get_fmri(node, pgname, pv->tp_name, &val,
			    &err) != 0 ||
			    topo_fmri_nvl2str(thp, val, &fmristr, &err) != 0) {
				nvlist_free(val);
				return;
			}
			nvlist_free(val);
			begin_end_element(fp, Propval, Name, pv->tp_name, Type,
			    FMRI, Value, fmristr, NULL);
			topo_hdl_strfree(thp, fmristr);
			break;
		}
		case TOPO_TYPE_INT32_ARRAY: {
			int32_t *val;

			if (topo_prop_get_int32_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    Int32_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				(void) snprintf(vbuf, INT64BUFSZ, "%d", val[i]);
				begin_end_element(fp, Propitem, Value, vbuf,
				    NULL);
			}

			topo_hdl_free(thp, val, nelem * sizeof (int32_t));
			end_element(fp, Propval);
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint32_t *val;

			if (topo_prop_get_uint32_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    UInt32_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%x",
				    val[i]);
				begin_end_element(fp, Propitem, Value, vbuf,
				    NULL);
			}

			topo_hdl_free(thp, val, nelem * sizeof (uint32_t));
			end_element(fp, Propval);
			break;
		}
		case TOPO_TYPE_INT64_ARRAY: {
			int64_t *val;

			if (topo_prop_get_int64_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    Int64_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				(void) snprintf(vbuf, INT64BUFSZ, "%" PRId64,
				    val[i]);
				begin_end_element(fp, Propitem, Value, vbuf,
				    NULL);
			}

			topo_hdl_free(thp, val, nelem * sizeof (int64_t));
			end_element(fp, Propval);
			break;
		}
		case TOPO_TYPE_UINT64_ARRAY: {
			uint64_t *val;

			if (topo_prop_get_uint64_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    UInt64_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%" PRIx64,
				    val[i]);
				begin_end_element(fp, Propitem, Value, vbuf,
				    NULL);
			}

			topo_hdl_free(thp, val, nelem * sizeof (uint64_t));
			end_element(fp, Propval);
			break;
		}
		case TOPO_TYPE_STRING_ARRAY: {
			char **val;

			if (topo_prop_get_string_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    String_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				begin_end_element(fp, Propitem, Value, val[i],
				    NULL);
			}
			topo_hdl_strfreev(thp, val, nelem);

			end_element(fp, Propval);
			break;
		}
		case TOPO_TYPE_FMRI_ARRAY: {
			nvlist_t **val;
			char *fmristr = NULL;
			int ret;

			if (topo_prop_get_fmri_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			begin_element(fp, Propval, Name, pv->tp_name, Type,
			    FMRI_Arr, NULL);

			for (uint_t i = 0; i < nelem; i++) {
				if ((ret = topo_fmri_nvl2str(thp, val[i],
				    &fmristr, &err)) != 0)
					break;
				begin_end_element(fp, Propitem, Value, fmristr,
				    NULL);
				topo_hdl_strfree(thp, fmristr);
			}
			for (uint_t i = 0; i < nelem; i++) {
				nvlist_free(val[i]);
			}
			topo_hdl_free(thp, val, nelem * sizeof (nvlist_t *));
			end_element(fp, Propval);
			break;
		}
		default:
			return;
	}
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
	/*
	 * The "static" attribute for the "node" element controls whether the
	 * node gets enumerated, if it doesn't already exist.  Setting it to
	 * true causes the node to not be created.  The primary use-case for
	 * setting it to true is when want to use XML to override a property
	 * value on a topo node that was already created by an enumerator
	 * module.  In this case we're trying to serialize the whole topology
	 * in a fashion such that we could reconstitute it from the generated
	 * XML. In which case, we relly need it to create all the nodes becuase
	 * no enumerator modules will be running.  Hence, we set static to
	 * false.
	 */
	begin_element(fp, Node, Instance, inst, Static, False, NULL);
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
	const char *name = thp->th_product;

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
