/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

/*
 * This file implements the following two routines for serializing and
 * deserializing digraphs to/from XML, respectively:
 *
 * topo_digraph_serialize()
 * topo_digraph_deserialize()
 *
 * Refer to the following file for the XML schema being used:
 * usr/src/lib/fm/topo/maps/common/digraph-topology.dtd.1
 */
#include <time.h>
#include <sys/utsname.h>
#include <libxml/parser.h>
#include <libtopo.h>

#include <topo_digraph.h>
#include <topo_digraph_xml.h>

#define	__STDC_FORMAT_MACROS
#include <inttypes.h>

extern int xmlattr_to_int(topo_mod_t *, xmlNodePtr, const char *, uint64_t *);
static int serialize_nvpair(topo_hdl_t *thp, FILE *, uint_t, const char *,
    nvpair_t *);

static void
tdg_xml_nvstring(FILE *fp, uint_t pad, const char *name, const char *value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%s' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_STRING,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvlist(FILE *fp, uint_t pad, const char *name)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_NVLIST);
}

static void
tdg_xml_nvuint8(FILE *fp, uint_t pad, const char *name, const uint8_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%u' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT8,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint8(FILE *fp, uint_t pad, const char *name, const uint8_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%d' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_INT8,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint16(FILE *fp, uint_t pad, const char *name, const uint8_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%u' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT16,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint16(FILE *fp, uint_t pad, const char *name, const uint8_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%d' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_INT16,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint32(FILE *fp, uint_t pad, const char *name, const uint32_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%u' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT32,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint32(FILE *fp, uint_t pad, const char *name, const int32_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%d' />\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT32,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvuint64(FILE *fp, uint_t pad, const char *name, const uint64_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='0x%" PRIx64 "' />\n",
	    pad, "", TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_UINT64, TDG_XML_VALUE, value);
}

static void
tdg_xml_nvint64(FILE *fp, uint_t pad, const char *name, const int64_t value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%" PRIi64 "' />\n", pad,
	    "", TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_UINT64, TDG_XML_VALUE, value);
}

static void
tdg_xml_nvdbl(FILE *fp, uint_t pad, const char *name, const double value)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s' %s='%lf' />\n", pad, ""
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, TDG_XML_UINT64,
	    TDG_XML_VALUE, value);
}

static void
tdg_xml_nvarray(FILE *fp, uint_t pad, const char *name, const char *type)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE, type);
}

static void
tdg_xml_nvint32arr(FILE *fp, uint_t pad, const char *name, int32_t *val,
    uint_t nelems)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_INT32_ARR);

	for (uint_t i = 0; i < nelems; i++) {
		(void) fprintf(fp, "%*s<%s %s='%d' />\n", (pad + 2), "",
		    TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
	}
	(void) fprintf(fp, "%*s</%s>\n", pad, "", TDG_XML_NVPAIR);
}

static void
tdg_xml_nvuint32arr(FILE *fp, uint_t pad, const char *name, uint32_t *val,
    uint_t nelems)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_UINT32_ARR);

	for (uint_t i = 0; i < nelems; i++) {
		(void) fprintf(fp, "%*s<%s %s='%d' />\n", (pad + 2), "",
		    TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
	}
	(void) fprintf(fp, "%*s</%s>\n", pad, "", TDG_XML_NVPAIR);
}

static void
tdg_xml_nvint64arr(FILE *fp, uint_t pad, const char *name, int64_t *val,
    uint_t nelems)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_INT64_ARR);

	for (uint_t i = 0; i < nelems; i++) {
		(void) fprintf(fp, "%*s<%s %s='%" PRIi64 "' />\n", (pad + 2),
		    "", TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
	}
	(void) fprintf(fp, "%*s</%s>\n", pad, "", TDG_XML_NVPAIR);
}

static void
tdg_xml_nvuint64arr(FILE *fp, uint_t pad, const char *name, uint64_t *val,
    uint_t nelems)
{
	(void) fprintf(fp, "%*s<%s %s='%s' %s='%s'>\n", pad, "",
	    TDG_XML_NVPAIR, TDG_XML_NAME, name, TDG_XML_TYPE,
	    TDG_XML_UINT64_ARR);

	for (uint_t i = 0; i < nelems; i++) {
		(void) fprintf(fp, "%*s<%s %s='0x%" PRIx64 "' />\n", (pad + 2),
		    "", TDG_XML_NVPAIR, TDG_XML_VALUE, val[i]);
	}
	(void) fprintf(fp, "%*s</%s>\n", pad, "", TDG_XML_NVPAIR);
}

static int
serialize_nvpair_nvlist(topo_hdl_t *thp, FILE *fp, uint_t pad,
    const char *name, nvlist_t *nvl)
{
	nvpair_t *elem = NULL;

	tdg_xml_nvlist(fp, pad, name);

	(void) fprintf(fp, "%*s<%s>\n", pad, "", TDG_XML_NVLIST);

	while ((elem = nvlist_next_nvpair(nvl, elem)) != NULL) {
		char *nvname = nvpair_name(elem);

		if (serialize_nvpair(thp, fp, (pad + 2), nvname, elem) != 0) {
			/* errno set */
			return (-1);
		}
	}

	(void) fprintf(fp, "%*s</%s>\n", pad, "", TDG_XML_NVLIST);
	(void) fprintf(fp, "%*s</%s> <!-- %s -->\n", pad, "", TDG_XML_NVPAIR,
	    name);

	return (0);
}

static int
serialize_nvpair(topo_hdl_t *thp, FILE *fp, uint_t pad, const char *pname,
    nvpair_t *nvp)
{
	data_type_t type = nvpair_type(nvp);

	switch (type) {
		case DATA_TYPE_INT8: {
			int8_t val;

			if (nvpair_value_int8(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint8(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT8: {
			uint8_t val;

			if (nvpair_value_uint8(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint8(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT16: {
			int16_t val;

			if (nvpair_value_int16(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint16(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT16: {
			uint16_t val;

			if (nvpair_value_uint16(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint16(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT32: {
			int32_t val;

			if (nvpair_value_int32(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint32(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT32: {
			uint32_t val;

			if (nvpair_value_uint32(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint32(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_INT64: {
			int64_t val;

			if (nvpair_value_int64(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint64(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_UINT64: {
			uint64_t val;

			if (nvpair_value_uint64(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint64(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_DOUBLE: {
			double val;

			if (nvpair_value_double(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvdbl(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_STRING: {
			char *val;

			if (nvpair_value_string(nvp, &val) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvstring(fp, pad, pname, val);
			break;
		}
		case DATA_TYPE_NVLIST: {
			nvlist_t *nvl;

			if (nvpair_value_nvlist(nvp, &nvl) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			if (serialize_nvpair_nvlist(thp, fp, pad + 2, pname,
			    nvl) != 0) {
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));
			}
			break;
		}
		case DATA_TYPE_INT32_ARRAY: {
			uint_t nelems;
			int32_t *val;

			if (nvpair_value_int32_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint32arr(fp, pad + 2, pname, val, nelems);

			break;
		}
		case DATA_TYPE_UINT32_ARRAY: {
			uint_t nelems;
			uint32_t *val;

			if (nvpair_value_uint32_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint32arr(fp, pad + 2, pname,  val, nelems);

			break;
		}
		case DATA_TYPE_INT64_ARRAY: {
			uint_t nelems;
			int64_t *val;

			if (nvpair_value_int64_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvint64arr(fp, pad + 2, pname,  val, nelems);

			break;
		}
		case DATA_TYPE_UINT64_ARRAY: {
			uint_t nelems;
			uint64_t *val;

			if (nvpair_value_uint64_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvuint64arr(fp, pad + 2, pname,  val, nelems);

			break;
		}
		case DATA_TYPE_STRING_ARRAY: {
			uint_t nelems;
			char **val;

			if (nvpair_value_string_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_STRING_ARR);
			for (uint_t i = 0; i < nelems; i++) {
				(void) fprintf(fp, "%*s<%s %s='%s' />\n",
				    (pad + 2), "", TDG_XML_NVPAIR,
				    TDG_XML_VALUE, val[i]);
			}
			(void) fprintf(fp, "%*s</%s>\n", (pad + 2), "",
			    TDG_XML_NVPAIR);

			break;
		}
		case DATA_TYPE_NVLIST_ARRAY: {
			uint_t nelems;
			nvlist_t **val;

			if (nvpair_value_nvlist_array(nvp, &val, &nelems) != 0)
				return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));

			tdg_xml_nvarray(fp, pad, pname, TDG_XML_NVLIST_ARR);
			for (uint_t i = 0; i < nelems; i++) {
				nvpair_t *elem = NULL;

				(void) fprintf(fp, "%*s<%s>\n", (pad + 2), "",
				    TDG_XML_NVLIST);

				while ((elem = nvlist_next_nvpair(val[i],
				    elem)) != NULL) {
					char *nvname = nvpair_name(elem);

					if (serialize_nvpair(thp, fp,
					    (pad + 4), nvname, elem) != 0) {
						/* errno set */
						return (-1);
					}
				}

				(void) fprintf(fp, "%*s</%s>\n", (pad + 2), "",
				    TDG_XML_NVLIST);
			}
			(void) fprintf(fp, "%*s</%s>\n", pad, "",
			    TDG_XML_NVPAIR);

			break;
		}
		default:
			topo_dprintf(thp, TOPO_DBG_XML, "Invalid nvpair data "
			    "type: %d\n", type);
			(void) topo_hdl_seterrno(thp, ETOPO_MOD_XENUM);
			return (-1);
	}
	return (0);
}

static int
serialize_edge(topo_hdl_t *thp, topo_edge_t *edge, boolean_t last_edge,
    void *arg)
{
	nvlist_t *fmri = NULL;
	char *fmristr;
	int err;
	tnode_t *tn;
	FILE *fp = (FILE *)arg;

	tn = topo_vertex_node(edge->tve_vertex);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		/* errno set */
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}
	nvlist_free(fmri);

	(void) fprintf(fp, "%*s<%s %s='%s' />\n", 4, "", TDG_XML_EDGE,
	    TDG_XML_FMRI, fmristr);
	topo_hdl_strfree(thp, fmristr);

	return (TOPO_WALK_NEXT);
}

/*
 * Some node property values aren't available unless we go through the libtopo
 * API's topo_prop_get_* routines. We do that here to make sure the nodes have
 * all of their properties populated, then we vector off to type-specific
 * XML serialization functions.
 */
static int
serialize_property(topo_hdl_t *thp, FILE *fp, uint_t pad, tnode_t *tn,
    topo_propval_t *pv, const char *pgname)
{
	topo_type_t type = pv->tp_type;
	const char *pname = pv->tp_name;
	int err;
	char *name = TDG_XML_PROP_VALUE;

	switch (type) {
		case TOPO_TYPE_INT32: {
			int32_t val;

			if (topo_prop_get_int32(tn, pgname, pname, &val,
			    &err) != 0)
				return (-1);

			tdg_xml_nvint32(fp, pad, name, val);
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;

			if (topo_prop_get_uint32(tn, pgname, pname, &val,
			    &err) != 0)
				return (-1);

			tdg_xml_nvuint32(fp, pad, name, val);
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;

			if (topo_prop_get_int64(tn, pgname, pname, &val,
			    &err) != 0)
				return (-1);

			tdg_xml_nvint64(fp, pad, name, val);
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;

			if (topo_prop_get_uint64(tn, pgname, pname, &val,
			    &err) != 0)
				return (-1);

			tdg_xml_nvuint64(fp, pad, name, val);
			break;
		}
		case TOPO_TYPE_STRING: {
			char *val;

			if (topo_prop_get_string(tn, pgname, pname, &val,
			    &err) != 0)
				return (-1);

			tdg_xml_nvstring(fp, pad, name, val);

			topo_hdl_strfree(thp, val);
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *nvl;

			if (topo_prop_get_fmri(tn, pgname, pname, &nvl,
			    &err) != 0)
				return (-1);

			if (serialize_nvpair_nvlist(thp, fp, pad + 2, name,
			    nvl) != 0) {
				nvlist_free(nvl);
				return (-1);
			}

			nvlist_free(nvl);
			break;
		}
		case TOPO_TYPE_INT32_ARRAY: {
			uint_t nelems;
			int32_t *val;

			if (topo_prop_get_int32_array(tn, pgname, pname, &val,
			    &nelems, &err) != 0)
				return (-1);

			tdg_xml_nvint32arr(fp, pad, pname, val, nelems);
			topo_hdl_free(thp, val, (sizeof (int32_t) * nelems));
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint_t nelems;
			uint32_t *val;

			if (topo_prop_get_uint32_array(tn, pgname, pname, &val,
			    &nelems, &err) != 0)
				return (-1);

			tdg_xml_nvuint32arr(fp, pad, pname,  val, nelems);
			topo_hdl_free(thp, val, (sizeof (uint32_t) * nelems));
			break;
		}
		case TOPO_TYPE_INT64_ARRAY: {
			uint_t nelems;
			int64_t *val;

			if (topo_prop_get_int64_array(tn, pgname, pname, &val,
			    &nelems, &err) != 0)
				return (-1);

			tdg_xml_nvint64arr(fp, pad, pname,  val, nelems);
			topo_hdl_free(thp, val, (sizeof (int64_t) * nelems));
			break;
		}
		case TOPO_TYPE_UINT64_ARRAY: {
			uint_t nelems;
			uint64_t *val;

			if (topo_prop_get_uint64_array(tn, pgname, pname, &val,
			    &nelems, &err) != 0)
				return (-1);

			tdg_xml_nvuint64arr(fp, pad, pname,  val, nelems);
			topo_hdl_free(thp, val, (sizeof (uint64_t) * nelems));
			break;
		}
		default:
			topo_dprintf(thp, TOPO_DBG_XML, "Invalid nvpair data "
			    "type: %d\n", type);
			(void) topo_hdl_seterrno(thp, ETOPO_MOD_XENUM);
			return (-1);
	}
	return (0);
}

static int
serialize_pgroups(topo_hdl_t *thp, FILE *fp, tnode_t *tn)
{
	topo_pgroup_t *pg;
	uint_t npgs = 0;

	for (pg = topo_list_next(&tn->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		npgs++;
	}

	tdg_xml_nvarray(fp, 2, TDG_XML_PGROUPS, TDG_XML_NVLIST_ARR);

	for (pg = topo_list_next(&tn->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		topo_proplist_t *pvl;
		uint_t nprops = 0;

		(void) fprintf(fp, "%*s<%s>\n", 4, "", TDG_XML_NVLIST);
		tdg_xml_nvstring(fp, 6, TOPO_PROP_GROUP_NAME,
		    pg->tpg_info->tpi_name);

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl))
			nprops++;

		tdg_xml_nvarray(fp, 6, TDG_XML_PVALS, TDG_XML_NVLIST_ARR);

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			topo_propval_t *pv = pvl->tp_pval;

			(void) fprintf(fp, "%*s<%s>\n", 8, "", TDG_XML_NVLIST);
			tdg_xml_nvstring(fp, 10, TDG_XML_PROP_NAME,
			    pv->tp_name);
			tdg_xml_nvuint32(fp, 10, TDG_XML_PROP_TYPE,
			    pv->tp_type);

			if (serialize_property(thp, fp, 10, tn, pv,
			    pg->tpg_info->tpi_name) != 0) {
				/* errno set */
				return (-1);
			}
			(void) fprintf(fp, "%*s</%s>\n", 8, "",
			    TDG_XML_NVLIST);
		}

		(void) fprintf(fp, "%*s</%s> <!-- %s -->\n", 6, "",
		    TDG_XML_NVPAIR, TDG_XML_PVALS);
		(void) fprintf(fp, "%*s</%s>\n", 4, "", TDG_XML_NVLIST);
	}
	(void) fprintf(fp, "%*s</%s> <!-- %s -->\n", 2, "", TDG_XML_NVPAIR,
	    TDG_XML_PGROUPS);

	return (0);
}

static int
serialize_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last_vtx,
    void *arg)
{
	nvlist_t *fmri = NULL;
	char *fmristr;
	tnode_t *tn;
	int err;
	FILE *fp = (FILE *)arg;

	tn = topo_vertex_node(vtx);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		/* errno set */
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}
	nvlist_free(fmri);

	(void) fprintf(fp, "<%s %s='%s' %s='0x%" PRIx64 "' %s='%s'>\n",
	    TDG_XML_VERTEX, TDG_XML_NAME, topo_node_name(tn),
	    TDG_XML_INSTANCE, topo_node_instance(tn),
	    TDG_XML_FMRI, fmristr);

	topo_hdl_strfree(thp, fmristr);

	if (serialize_pgroups(thp, fp, tn) != 0) {
		/* errno set */
		return (TOPO_WALK_ERR);
	}

	if (vtx->tvt_noutgoing != 0) {
		(void) fprintf(fp, "  <%s>\n", TDG_XML_OUTEDGES);

		if (topo_edge_iter(thp, vtx, serialize_edge, fp) != 0) {
			topo_dprintf(thp, TOPO_DBG_XML, "failed to iterate "
			    "edges on %s=%" PRIx64 "\n", topo_node_name(tn),
			    topo_node_instance(tn));
			/* errno set */
			return (TOPO_WALK_ERR);
		}
		(void) fprintf(fp, "  </%s>\n", TDG_XML_OUTEDGES);
	}
	(void) fprintf(fp, "</%s>\n\n", TDG_XML_VERTEX);

	return (TOPO_WALK_NEXT);
}

/*
 * This function takes a topo_digraph_t and serializes it to XML.
 *
 * The schema is described in detail in:
 * usr/src/lib/fm/topo/maps/common/digraph-topology.dtd.1
 *
 * On success, this function writes the XML to the specified file and
 * returns 0.
 *
 * On failure, this function returns -1.
 */
int
topo_digraph_serialize(topo_hdl_t *thp, topo_digraph_t *tdg, FILE *fp)
{
	struct utsname uts = { 0 };
	time_t utc_time;
	char tstamp[64];
	int ret;

	if ((ret = uname(&uts)) < 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "uname failed (ret = %d)\n",
		    ret);
		return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));
	}

	if (time(&utc_time) < 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "uname failed (%s)\n",
		    strerror(errno));
		return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));
	}

	/*
	 * strftime returns 0 if the size of the result is larger than the
	 * buffer size passed in to it.  We've sized tstamp to be pretty
	 * large, so this really shouldn't happen.
	 */
	if (strftime(tstamp, sizeof (tstamp), "%Y-%m-%dT%H:%M:%SZ",
	    gmtime(&utc_time)) == 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "strftime failed\n");
		return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));
	}

	(void) fprintf(fp, "<?xml version=\"1.0\"?>\n");
	(void) fprintf(fp, "<!DOCTYPE topology SYSTEM \"%s\">\n", TDG_DTD);
	(void) fprintf(fp, "<%s %s='%s' %s='%s' %s='%s' %s='%s' %s='%s'>\n",
	    TDG_XML_TOPO_DIGRAPH, TDG_XML_SCHEME, tdg->tdg_scheme,
	    TDG_XML_NODENAME, uts.nodename, TDG_XML_OSVERSION, uts.version,
	    TDG_XML_PRODUCT, thp->th_product, TDG_XML_TSTAMP, tstamp);
	(void) fprintf(fp, "<%s>\n", TDG_XML_VERTICES);

	if (topo_vertex_iter(thp, tdg, serialize_vertex, fp) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "\nfailed to iterate "
		    "vertices\n");
		/* errno set */
		return (-1);
	}

	(void) fprintf(fp, "</%s>\n", TDG_XML_VERTICES);
	(void) fprintf(fp, "</%s>\n", TDG_XML_TOPO_DIGRAPH);

	if (ferror(fp) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "An unknown error ocurrred "
		    "while writing out the serialize topology.");
		return (topo_hdl_seterrno(thp, ETOPO_UNKNOWN));
	}
	return (0);
}

static xmlNodePtr
get_child_by_name(xmlNodePtr xn, xmlChar *name)
{
	for (xmlNodePtr cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next)
		if (xmlStrcmp(cn->name, name) == 0)
			return (cn);

	return (NULL);
}

static void
dump_xml_node(topo_hdl_t *thp, xmlNodePtr xn)
{
	topo_dprintf(thp, TOPO_DBG_XML, "node: %s", (char *)xn->name);
	for (xmlAttrPtr attr = xn->properties; attr != NULL; attr = attr->next)
		topo_dprintf(thp, TOPO_DBG_XML, "attribute: %s",
		    (char *)attr->name);

	for (xmlNodePtr cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next)
		topo_dprintf(thp, TOPO_DBG_XML, "\tchild node: %s",
		    (char *)cn->name);
}

struct edge_cb_arg {
	const char	*from_fmri;
	const char	*to_fmri;
	topo_vertex_t	*from_vtx;
	topo_vertex_t	*to_vtx;
};

static int
edge_cb(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last_vtx, void *arg)
{
	struct edge_cb_arg *cbarg = arg;
	tnode_t *tn;
	nvlist_t *fmri = NULL;
	char *fmristr = NULL;
	int err;

	tn = topo_vertex_node(vtx);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "failed to convert FMRI for "
		    "%s=%" PRIx64 " to a string\n", topo_node_name(tn),
		    topo_node_instance(tn));
		if (thp->th_debug & TOPO_DBG_XML)
			nvlist_print(stdout, fmri);
		nvlist_free(fmri);
		return (TOPO_WALK_ERR);
	}
	nvlist_free(fmri);

	if (strcmp(fmristr, cbarg->from_fmri) == 0)
		cbarg->from_vtx = vtx;
	else if (strcmp(fmristr, cbarg->to_fmri) == 0)
		cbarg->to_vtx = vtx;

	topo_hdl_strfree(thp, fmristr);
	if (cbarg->from_vtx != NULL && cbarg->to_vtx != NULL)
		return (TOPO_WALK_TERMINATE);
	else
		return (TOPO_WALK_NEXT);
}

static int
deserialize_edges(topo_hdl_t *thp, topo_mod_t *mod, topo_digraph_t *tdg,
    xmlChar *from_fmri, xmlNodePtr xn)
{
	for (xmlNodePtr cn = xn->xmlChildrenNode; cn != NULL;
	    cn = cn->next) {
		xmlChar *fmri;
		struct edge_cb_arg cbarg = { 0 };

		if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_EDGE) != 0)
			continue;

		if ((fmri = xmlGetProp(cn, (xmlChar *)TDG_XML_FMRI)) == NULL) {
			topo_dprintf(thp, TOPO_DBG_XML,
			    "error parsing %s element", (char *)cn->name);
			dump_xml_node(thp, cn);
			return (-1);
		}
		cbarg.from_fmri = (char *)from_fmri;
		cbarg.to_fmri = (char *)fmri;

		if (topo_vertex_iter(mod->tm_hdl, tdg, edge_cb, &cbarg) != 0) {
			xmlFree(fmri);
			return (-1);
		}
		xmlFree(fmri);

		if (cbarg.from_vtx == NULL || cbarg.to_vtx == NULL) {
			return (-1);
		}
		if (topo_edge_new(mod, cbarg.from_vtx, cbarg.to_vtx) != 0) {
			return (-1);
		}
	}

	return (0);
}

static int
add_edges(topo_hdl_t *thp, topo_mod_t *mod, topo_digraph_t *tdg,
    xmlNodePtr xn)
{
	int ret = -1;
	nvlist_t *props = NULL;
	xmlChar *name = NULL, *fmri = NULL;
	xmlNodePtr cn;
	uint64_t inst;

	if ((name = xmlGetProp(xn, (xmlChar *)TDG_XML_NAME)) == NULL ||
	    (fmri = xmlGetProp(xn, (xmlChar *)TDG_XML_FMRI)) == NULL ||
	    xmlattr_to_int(mod, xn, TDG_XML_INSTANCE, &inst) != 0) {
		goto fail;
	}

	if ((cn = get_child_by_name(xn, (xmlChar *)TDG_XML_OUTEDGES)) !=
	    NULL) {
		if (deserialize_edges(thp, mod, tdg, fmri, cn) != 0)
			goto fail;
	}
	ret = 0;

fail:
	if (ret != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "%s: error parsing %s element",
		    __func__, TDG_XML_VERTEX);
		dump_xml_node(thp, xn);
	}
	nvlist_free(props);
	if (name != NULL)
		xmlFree(name);
	if (fmri != NULL)
		xmlFree(fmri);

	return (ret);
}

static topo_pgroup_info_t pginfo = {
	NULL,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static int
add_props(topo_hdl_t *thp, topo_vertex_t *vtx, nvlist_t *pgroups)
{
	tnode_t *tn;
	nvlist_t **pgs;
	uint_t npgs = 0;

	tn = topo_vertex_node(vtx);
	if (nvlist_lookup_nvlist_array(pgroups, TDG_XML_PGROUPS, &pgs,
	    &npgs) != 0) {
		goto fail;
	}

	for (uint_t i = 0; i < npgs; i++) {
		char *pgname;
		nvlist_t **props;
		uint_t nprops;
		int err;

		if (nvlist_lookup_string(pgs[i], TDG_XML_PGROUP_NAME,
		    &pgname) != 0 ||
		    nvlist_lookup_nvlist_array(pgs[i], TDG_XML_PVALS, &props,
		    &nprops) != 0) {
			goto fail;
		}
		pginfo.tpi_name = pgname;

		if (topo_pgroup_create(tn, &pginfo, &err) != 0) {
			topo_dprintf(thp, TOPO_DBG_XML, "failed to create "
			    "pgroup: %s", pgname);
			goto fail;
		}
		for (uint_t j = 0; j < nprops; j++) {
			if (topo_prop_setprop(tn, pgname, props[j],
			    TOPO_PROP_IMMUTABLE, props[j], &err) != 0) {
				topo_dprintf(thp, TOPO_DBG_XML, "failed to "
				    "set properties in pgroup: %s", pgname);
				goto fail;
			}
		}
	}
	return (0);
fail:
	topo_dprintf(thp, TOPO_DBG_XML, "%s: error decoding properties for "
	    "%s=%" PRIx64, __func__, topo_node_name(tn),
	    topo_node_instance(tn));
	if (thp->th_debug & TOPO_DBG_XML)
		nvlist_print(stdout, pgroups);

	return (-1);
}

static void
free_nvlist_array(topo_hdl_t *thp, nvlist_t **nvlarr, uint_t nelems)
{
	for (uint_t i = 0; i < nelems; i++) {
		if (nvlarr[i] != NULL)
			nvlist_free(nvlarr[i]);
	}
	topo_hdl_free(thp, nvlarr, nelems * sizeof (nvlist_t *));
}

static boolean_t
is_overflow(topo_hdl_t *thp, uint64_t val, uint_t nbits)
{
	if ((val >> nbits) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "value exceeds %u bits", nbits);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Recursive function for parsing nvpair XML elements, which can contain
 * nested nvlist and nvpair elements.
 */
static int
deserialize_nvpair(topo_hdl_t *thp, topo_mod_t *mod, nvlist_t *nvl,
    xmlNodePtr xn)
{
	int ret = -1;
	xmlChar *name = NULL, *type = NULL, *sval = NULL;
	uint64_t val;

	if ((name = xmlGetProp(xn, (xmlChar *)TDG_XML_NAME)) == NULL ||
	    (type = xmlGetProp(xn, (xmlChar *)TDG_XML_TYPE)) == NULL) {
		goto fail;
	}

	if (xmlStrcmp(type, (xmlChar *)TDG_XML_NVLIST) == 0) {
		nvlist_t *cnvl = NULL;

		if (topo_hdl_nvalloc(thp, &cnvl, NV_UNIQUE_NAME) != 0) {
			goto fail;
		}

		for (xmlNodePtr cn = xn->xmlChildrenNode;
		    cn != NULL; cn = cn->next) {

			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVLIST) != 0)
				continue;

			for (xmlNodePtr gcn = cn->xmlChildrenNode;
			    gcn != NULL; gcn = gcn->next) {

				if (xmlStrcmp(gcn->name,
				    (xmlChar *)TDG_XML_NVPAIR) != 0)
					continue;
				if (deserialize_nvpair(thp, mod, cnvl, gcn) !=
				    0) {
					nvlist_free(cnvl);
					goto fail;
				}
			}
			if (nvlist_add_nvlist(nvl, (char *)name, cnvl) != 0) {
				nvlist_free(cnvl);
				goto fail;
			}
			nvlist_free(cnvl);
			break;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT8) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 8) ||
		    nvlist_add_int8(nvl, (char *)name, (int8_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT16) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 16) ||
		    nvlist_add_int16(nvl, (char *)name, (int16_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT32) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 32) ||
		    nvlist_add_int32(nvl, (char *)name, (int32_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT64) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    nvlist_add_int64(nvl, (char *)name, (int64_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT8) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 8) ||
		    nvlist_add_uint8(nvl, (char *)name, (uint8_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT16) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 16) ||
		    nvlist_add_uint16(nvl, (char *)name, (uint16_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT32) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    is_overflow(thp, val, 32) ||
		    nvlist_add_uint32(nvl, (char *)name, (uint32_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT64) == 0) {
		if (xmlattr_to_int(mod, xn, TDG_XML_VALUE, &val) != 0 ||
		    nvlist_add_uint64(nvl, (char *)name, (uint64_t)val) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_STRING) == 0) {
		if ((sval = xmlGetProp(xn, (xmlChar *)TDG_XML_VALUE)) == NULL ||
		    nvlist_add_string(nvl, (char *)name, (char *)sval) != 0) {
			goto fail;
		}
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_NVLIST_ARR) == 0) {
		uint64_t nelem = 0;
		nvlist_t **nvlarr = NULL;
		uint_t i = 0;
		xmlNodePtr cn = xn->xmlChildrenNode;

		/*
		 * Count the number of child nvlist elements
		 */
		while (cn != NULL) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVLIST) ==
			    0) {
				nelem++;
			}
			cn = cn->next;
		}

		if ((nvlarr = topo_hdl_zalloc(thp,
		    (nelem * sizeof (nvlist_t *)))) == NULL) {
			goto fail;
		}

		for (cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVLIST) !=
			    0)
				continue;

			if (topo_hdl_nvalloc(thp, &nvlarr[i],
			    NV_UNIQUE_NAME) != 0) {
				free_nvlist_array(thp, nvlarr, nelem);
				goto fail;
			}

			for (xmlNodePtr gcn = cn->xmlChildrenNode;
			    gcn != NULL; gcn = gcn->next) {
				if (xmlStrcmp(gcn->name,
				    (xmlChar *)TDG_XML_NVPAIR) != 0)
					continue;
				if (deserialize_nvpair(thp, mod, nvlarr[i],
				    gcn) != 0) {
					free_nvlist_array(thp, nvlarr, nelem);
					goto fail;
				}
			}
			i++;
		}
		if (nvlist_add_nvlist_array(nvl, (char *)name, nvlarr,
		    nelem) != 0) {
			free_nvlist_array(thp, nvlarr, nelem);
			goto fail;
		}
		free_nvlist_array(thp, nvlarr, nelem);
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT32_ARR) == 0) {
		uint64_t nelem = 0;
		uint32_t *arr = NULL;
		uint_t i = 0;
		xmlNodePtr cn = xn->xmlChildrenNode;

		/*
		 * Count the number of child nvpair elements
		 */
		while (cn != NULL) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) ==
			    0) {
				nelem++;
			}
			cn = cn->next;
		}

		if ((arr = topo_hdl_zalloc(thp,
		    (nelem * sizeof (uint32_t)))) == NULL) {
			goto fail;
		}

		for (cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) != 0)
				continue;

			if (xmlattr_to_int(mod, cn, TDG_XML_VALUE, &val) != 0) {
				topo_hdl_free(thp, arr,
				    (nelem * sizeof (uint32_t)));
				goto fail;
			}

			arr[i] = val;
			i++;
		}
		if (nvlist_add_uint32_array(nvl, (char *)name, arr,
		    nelem) != 0) {
			topo_hdl_free(thp, arr, (nelem * sizeof (uint32_t)));
			goto fail;
		}
		topo_hdl_free(thp, arr, (nelem * sizeof (uint32_t)));
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT32_ARR) == 0) {
		uint64_t nelem = 0;
		int32_t *arr = NULL;
		uint_t i = 0;
		xmlNodePtr cn = xn->xmlChildrenNode;

		/*
		 * Count the number of child nvpair elements
		 */
		while (cn != NULL) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) ==
			    0) {
				nelem++;
			}
			cn = cn->next;
		}

		if ((arr = topo_hdl_zalloc(thp,
		    (nelem * sizeof (int32_t)))) == NULL) {
			goto fail;
		}

		for (cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) != 0)
				continue;

			if (xmlattr_to_int(mod, cn, TDG_XML_VALUE, &val) != 0) {
				topo_hdl_free(thp, arr,
				    (nelem * sizeof (int32_t)));
				goto fail;
			}

			arr[i] = val;
			i++;
		}
		if (nvlist_add_int32_array(nvl, (char *)name, arr,
		    nelem) != 0) {
			topo_hdl_free(thp, arr, (nelem * sizeof (int32_t)));
			goto fail;
		}
		topo_hdl_free(thp, arr, (nelem * sizeof (int32_t)));
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_UINT64_ARR) == 0) {
		uint64_t nelem = 0, *arr = NULL;
		uint_t i = 0;
		xmlNodePtr cn = xn->xmlChildrenNode;

		/*
		 * Count the number of child nvpair elements
		 */
		while (cn != NULL) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) ==
			    0) {
				nelem++;
			}
			cn = cn->next;
		}

		if ((arr = topo_hdl_zalloc(thp,
		    (nelem * sizeof (uint64_t)))) == NULL) {
			goto fail;
		}

		for (cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) != 0)
				continue;

			if (xmlattr_to_int(mod, cn, TDG_XML_VALUE, &val) != 0) {
				topo_hdl_free(thp, arr,
				    (nelem * sizeof (uint64_t)));
				goto fail;
			}

			arr[i] = val;
			i++;
		}
		if (nvlist_add_uint64_array(nvl, (char *)name, arr,
		    nelem) != 0) {
			topo_hdl_free(thp, arr, (nelem * sizeof (uint64_t)));
			goto fail;
		}
		topo_hdl_free(thp, arr, (nelem * sizeof (uint64_t)));
	} else if (xmlStrcmp(type, (xmlChar *)TDG_XML_INT64_ARR) == 0) {
		uint64_t nelem = 0;
		int64_t *arr = NULL;
		uint_t i = 0;
		xmlNodePtr cn = xn->xmlChildrenNode;

		/*
		 * Count the number of child nvpair elements
		 */
		while (cn != NULL) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) ==
			    0) {
				nelem++;
			}
			cn = cn->next;
		}

		if ((arr = topo_hdl_zalloc(thp,
		    (nelem * sizeof (int64_t)))) == NULL) {
			goto fail;
		}

		for (cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
			if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) != 0)
				continue;

			if (xmlattr_to_int(mod, cn, TDG_XML_VALUE, &val) != 0) {
				topo_hdl_free(thp, arr,
				    (nelem * sizeof (int64_t)));
				goto fail;
			}

			arr[i] = val;
			i++;
		}
		if (nvlist_add_int64_array(nvl, (char *)name, arr,
		    nelem) != 0) {
			topo_hdl_free(thp, arr, (nelem * sizeof (int64_t)));
			goto fail;
		}
		topo_hdl_free(thp, arr, (nelem * sizeof (int64_t)));
	}
	ret = 0;
fail:
	if (ret != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "%s: error parsing %s "
		    "element: name: %s, type: %s, nvl: %p", __func__, xn->name,
		    (name != NULL) ? (char *)name : "MISSING!",
		    (type != NULL) ? (char *)type : "MISSING!", nvl);
		dump_xml_node(thp, xn);
	}
	if (name != NULL)
		xmlFree(name);
	if (type != NULL)
		xmlFree(type);
	if (sval != NULL)
		xmlFree(sval);

	return (ret);
}

static int
deserialize_vertex(topo_hdl_t *thp, topo_mod_t *mod, topo_digraph_t *tdg,
    xmlNodePtr xn)
{
	int ret = -1;
	topo_vertex_t *vtx = NULL;
	nvlist_t *props = NULL;
	xmlChar *name = NULL, *fmri = NULL;
	uint64_t inst;

	if ((name = xmlGetProp(xn, (xmlChar *)TDG_XML_NAME)) == NULL ||
	    (fmri = xmlGetProp(xn, (xmlChar *)TDG_XML_FMRI)) == NULL ||
	    xmlattr_to_int(mod, xn, TDG_XML_INSTANCE, &inst) != 0) {
		goto fail;
	}

	if ((vtx = topo_vertex_new(mod, (char *)name, inst)) == NULL) {
		goto fail;
	}

	for (xmlNodePtr cn = xn->xmlChildrenNode; cn != NULL; cn = cn->next) {
		if (xmlStrcmp(cn->name, (xmlChar *)TDG_XML_NVPAIR) == 0) {
			if (topo_hdl_nvalloc(thp, &props, NV_UNIQUE_NAME) != 0)
				goto fail;
			if (deserialize_nvpair(thp, mod, props, cn) != 0 ||
			    add_props(thp, vtx, props) != 0)
				goto fail;
		}
	}
	ret = 0;

fail:
	if (ret != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "%s: error parsing %s element",
		    __func__, TDG_XML_VERTEX);
		dump_xml_node(thp, xn);
	}
	nvlist_free(props);
	if (name != NULL)
		xmlFree(name);
	if (fmri != NULL)
		xmlFree(fmri);

	return (ret);
}

/*
 * This function takes a buffer containing XML data describing a directed graph
 * topology.  This data is parsed to the original directed graph is rehydrated.
 *
 * On success, a pointer to a topo_digraph_t representing the graph is
 * returned.  The caller is responsible for destroying the graph via a call to
 * topo_digraph_destroy()
 *
 * On failure, NULL is returned.
 */
topo_digraph_t *
topo_digraph_deserialize(topo_hdl_t *thp, const char *xml, size_t sz)
{
	xmlDocPtr doc;
	xmlDtdPtr dtd = NULL;
	xmlNodePtr root, vertices;
	xmlChar *scheme = NULL;
	topo_mod_t *mod;
	topo_digraph_t *tdg, *ret = NULL;

	if ((doc = xmlReadMemory(xml, sz, "", NULL, 0)) == NULL) {
		topo_dprintf(thp, TOPO_DBG_XML, "Failed to parse XML");
		goto fail;
	}

	/*
	 * As a sanity check, extract the DTD from the XML and verify it
	 * matches the DTD for a digraph topology.
	 */
	if ((dtd = xmlGetIntSubset(doc)) == NULL) {
		topo_dprintf(thp, TOPO_DBG_XML,  "document has no DTD.\n");
		goto fail;
	}

	if (strcmp((const char *)dtd->SystemID, TDG_DTD) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "unexpected DTD: %s",
		    dtd->SystemID);
		goto fail;
	}

	/*
	 * Verify the root element is what we're expecting and then grab the
	 * FMRI scheme from its attributes.
	 */
	if ((root = xmlDocGetRootElement(doc)) == NULL) {
		topo_dprintf(thp, TOPO_DBG_XML, "document is empty.\n");
		goto fail;
	}

	if (xmlStrcmp(root->name, (xmlChar *)TDG_XML_TOPO_DIGRAPH) != 0 ||
	    (scheme = xmlGetProp(root, (xmlChar *)TDG_XML_SCHEME)) ==
	    NULL) {
		topo_dprintf(thp, TOPO_DBG_XML,
		    "failed to parse %s element", TDG_XML_TOPO_DIGRAPH);
		goto fail;
	}

	/*
	 * Load the topo module associated with this FMRI scheme.
	 */
	if ((mod = topo_mod_lookup(thp, (const char *)scheme, 1)) == NULL) {
		topo_dprintf(thp, TOPO_DBG_XML, "failed to load %s module",
		    scheme);
		goto fail;
	}
	/*
	 * If we have a builtin module for this scheme, then there will
	 * already be an empty digraph attached to the handle.  Otherwise,
	 * create a new empty digraph and attach it to the handle.
	 */
	tdg = topo_digraph_get(mod->tm_hdl, mod->tm_info->tmi_scheme);
	if (tdg == NULL) {
		if ((tdg = topo_digraph_new(thp, mod, (const char *)scheme)) ==
		    NULL) {
			topo_dprintf(thp, TOPO_DBG_XML, "failed to create new "
			    "digraph");
			goto fail;
		} else {
			topo_list_append(&thp->th_digraphs, tdg);
		}
	}

	/*
	 * Iterate through the vertex XML elements to reconstruct the graph
	 */
	vertices = get_child_by_name(root, (xmlChar *)TDG_XML_VERTICES);
	if (vertices == NULL ||
	    xmlStrcmp(vertices->name, (xmlChar *)TDG_XML_VERTICES) != 0) {
		topo_dprintf(thp, TOPO_DBG_XML, "failed to parse %s element",
		    TDG_XML_VERTICES);
		dump_xml_node(thp, root);
		goto fail;
	}

	for (xmlNodePtr xn = vertices->xmlChildrenNode; xn != NULL;
	    xn = xn->next) {
		if (xmlStrcmp(xn->name, (xmlChar *)TDG_XML_VERTEX) != 0)
			continue;
		if (deserialize_vertex(thp, mod, tdg, xn) != 0)
			goto fail;
	}

	/*
	 * Now that all of the vertices have been created, go back through
	 * the vertex XML elements and add the edges.
	 */
	for (xmlNodePtr xn = vertices->xmlChildrenNode; xn != NULL;
	    xn = xn->next) {
		if (xmlStrcmp(xn->name, (xmlChar *)TDG_XML_VERTEX) != 0)
			continue;
		if (add_edges(thp, mod, tdg, xn) != 0)
			goto fail;
	}

	ret = tdg;

fail:
	if (scheme != NULL)
		xmlFree(scheme);

	if (doc != NULL)
		xmlFreeDoc(doc);

	(void) topo_hdl_seterrno(thp, ETOPO_MOD_XENUM);
	return (ret);
}
