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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */


#include <sys/fm/protocol.h>
#include <fm/libtopo.h>
#include <ctype.h>
#include <fnmatch.h>
#include <limits.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <umem.h>
#include <zone.h>
#include <sys/param.h>

#define	FMTOPO_EXIT_SUCCESS	0
#define	FMTOPO_EXIT_ERROR	1
#define	FMTOPO_EXIT_USAGE	2

#define	STDERR	"stderr"
#define	DOTS	"..."
#define	ALL	"all"

static const char *g_pname;
static const char *g_fmri = NULL;

static const char *opt_R = "/";
static const char *opt_s = FM_FMRI_SCHEME_HC;
static const char optstr[] = "bCdem:P:pR:s:StVx";
static const char *opt_m;

static int opt_b = 0;
static int opt_d = 0;
static int opt_e = 0;
static int opt_p = 0;
static int opt_S = 0;
static int opt_t = 0;
static int opt_V = 0;
static int opt_x = 0;
static int opt_all = 0;

struct prop_args {
	const char *group;
	const char *prop;
	const char *type;
	const char *value;
};

static struct prop_args **pargs = NULL;
static int pcnt = 0;

static int
usage(FILE *fp)
{
	(void) fprintf(fp,
	    "Usage: %s [-bCedpSVx] [-P group.property[=type:value]] "
	    "[-R root] [-m method] [-s scheme] [fmri]\n", g_pname);

	(void) fprintf(fp,
	    "\t-b  walk in sibling-first order (default is child-first)\n"
	    "\t-C  dump core after completing execution\n"
	    "\t-d  set debug mode for libtopo modules\n"
	    "\t-e  display FMRIs as paths using esc/eft notation\n"
	    "\t-m  execute given method\n"
	    "\t-P  get/set specified properties\n"
	    "\t-p  display of FMRI protocol properties\n"
	    "\t-R  set root directory for libtopo plug-ins and other files\n"
	    "\t-s  display topology for the specified FMRI scheme\n"
	    "\t-S  display FMRI status (present/usable)\n"
	    "\t-V  set verbose mode\n"
	    "\t-x  display a xml formatted topology\n");

	return (FMTOPO_EXIT_USAGE);
}

static topo_type_t
str2type(const char *tstr)
{
	topo_type_t type;

	if (tstr == NULL)
		return (TOPO_TYPE_INVALID);

	if (strcmp(tstr, "int32") == 0)
		type = TOPO_TYPE_INT32;
	else if (strcmp(tstr, "uint32") == 0)
		type = TOPO_TYPE_UINT32;
	else if (strcmp(tstr, "int64") == 0)
		type = TOPO_TYPE_INT64;
	else if (strcmp(tstr, "uint64") == 0)
		type = TOPO_TYPE_UINT64;
	else if (strcmp(tstr, "string") == 0)
		type = TOPO_TYPE_STRING;
	else if (strcmp(tstr, "fmri") == 0)
		type = TOPO_TYPE_FMRI;
	else {
		type = TOPO_TYPE_INVALID;
	}

	return (type);
}

static void
print_node(topo_hdl_t *thp, tnode_t *node, nvlist_t *nvl, const char *fmri)
{
	int err, ret;

	(void) printf("%s\n", (char *)fmri);

	if (opt_p && !(pcnt > 0 || opt_V || opt_all)) {
		char *aname = NULL, *fname = NULL, *lname = NULL;
		nvlist_t *asru = NULL;
		nvlist_t *fru = NULL;

		if (topo_node_asru(node, &asru, NULL, &err) == 0)
			(void) topo_fmri_nvl2str(thp, asru, &aname, &err);
		if (topo_node_fru(node, &fru, NULL, &err) == 0)
			(void) topo_fmri_nvl2str(thp, fru, &fname, &err);
		(void) topo_node_label(node, &lname, &err);
		if (aname != NULL) {
			nvlist_free(asru);
			(void) printf("\tASRU: %s\n", aname);
			topo_hdl_strfree(thp, aname);
		} else {
			(void) printf("\tASRU: -\n");
		}
		if (fname != NULL) {
			nvlist_free(fru);
			(void) printf("\tFRU: %s\n", fname);
			topo_hdl_strfree(thp, fname);
		} else {
			(void) printf("\tFRU: -\n");
		}
		if (lname != NULL) {
			(void) printf("\tLabel: %s\n", lname);
			topo_hdl_strfree(thp, lname);
		} else {
			(void) printf("\tLabel: -\n");
		}
	}

	if (opt_S) {
		if ((ret = topo_fmri_present(thp, nvl, &err)) < 0)
			(void) printf("\tPresent: -\n");
		else
			(void) printf("\tPresent: %s\n",
			    ret ? "true" : "false");

		if ((ret = topo_fmri_unusable(thp, nvl, &err)) < 0)
			(void) printf("\tUnusable: -\n");
		else
			(void) printf("\tUnusable: %s\n",
			    ret ? "true" : "false");
	}
}

static void
print_everstyle(tnode_t *node)
{
	char buf[PATH_MAX], numbuf[64];
	nvlist_t *fmri, **hcl;
	int i, err;
	uint_t n;

	if (topo_prop_get_fmri(node, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, &fmri, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to get fmri for %s=%d: %s\n",
		    g_pname, topo_node_name(node),
		    topo_node_instance(node), topo_strerror(err));
		return;
	}

	if (nvlist_lookup_nvlist_array(fmri, FM_FMRI_HC_LIST, &hcl, &n) != 0) {
		(void) fprintf(stderr, "%s: failed to find %s for %s=%d\n",
		    g_pname, FM_FMRI_HC_LIST, topo_node_name(node),
		    topo_node_instance(node));
		nvlist_free(fmri);
		return;
	}

	buf[0] = '\0';

	for (i = 0; i < n; i++) {
		char *name, *inst, *estr;
		ulong_t ul;

		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name) != 0 ||
		    nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &inst) != 0) {
			(void) fprintf(stderr, "%s: failed to get "
			    "name-instance for %s=%d\n", g_pname,
			    topo_node_name(node), topo_node_instance(node));
			nvlist_free(fmri);
			return;
		}

		errno = 0;
		ul = strtoul(inst, &estr, 10);

		if (errno != 0 || estr == inst) {
			(void) fprintf(stderr, "%s: instance %s does not "
			    "convert to an unsigned integer\n", g_pname, inst);
		}

		(void) strlcat(buf, "/", sizeof (buf));
		(void) strlcat(buf, name, sizeof (buf));
		(void) snprintf(numbuf, sizeof (numbuf), "%u", ul);
		(void) strlcat(buf, numbuf, sizeof (buf));
	}
	nvlist_free(fmri);

	(void) printf("%s\n", buf);
}

static void
print_prop_nameval(topo_hdl_t *thp, tnode_t *node, nvlist_t *nvl)
{
	int err;
	topo_type_t type;
	char *tstr, *propn, buf[48], *factype;
	nvpair_t *pv_nvp;
	int i;
	uint_t nelem;

	if ((pv_nvp = nvlist_next_nvpair(nvl, NULL)) == NULL)
		return;

	/* Print property name */
	if ((pv_nvp = nvlist_next_nvpair(nvl, NULL)) == NULL ||
	    nvpair_name(pv_nvp) == NULL ||
	    strcmp(TOPO_PROP_VAL_NAME, nvpair_name(pv_nvp)) != 0) {
		(void) fprintf(stderr, "%s: malformed property name\n",
		    g_pname);
		return;
	} else {
		(void) nvpair_value_string(pv_nvp, &propn);
	}

	if ((pv_nvp = nvlist_next_nvpair(nvl, pv_nvp)) == NULL ||
	    nvpair_name(pv_nvp) == NULL ||
	    strcmp(nvpair_name(pv_nvp), TOPO_PROP_VAL_TYPE) != 0 ||
	    nvpair_type(pv_nvp) != DATA_TYPE_UINT32)  {
		(void) fprintf(stderr, "%s: malformed property type for %s\n",
		    g_pname, propn);
		return;
	} else {
		(void) nvpair_value_uint32(pv_nvp, (uint32_t *)&type);
	}

	switch (type) {
		case TOPO_TYPE_BOOLEAN: tstr = "boolean"; break;
		case TOPO_TYPE_INT32: tstr = "int32"; break;
		case TOPO_TYPE_UINT32: tstr = "uint32"; break;
		case TOPO_TYPE_INT64: tstr = "int64"; break;
		case TOPO_TYPE_UINT64: tstr = "uint64"; break;
		case TOPO_TYPE_DOUBLE: tstr = "double"; break;
		case TOPO_TYPE_STRING: tstr = "string"; break;
		case TOPO_TYPE_FMRI: tstr = "fmri"; break;
		case TOPO_TYPE_INT32_ARRAY: tstr = "int32[]"; break;
		case TOPO_TYPE_UINT32_ARRAY: tstr = "uint32[]"; break;
		case TOPO_TYPE_INT64_ARRAY: tstr = "int64[]"; break;
		case TOPO_TYPE_UINT64_ARRAY: tstr = "uint64[]"; break;
		case TOPO_TYPE_STRING_ARRAY: tstr = "string[]"; break;
		case TOPO_TYPE_FMRI_ARRAY: tstr = "fmri[]"; break;
		default: tstr = "unknown type";
	}

	(void) printf("    %-17s %-8s ", propn, tstr);

	/*
	 * Get property value
	 */
	if (nvpair_name(pv_nvp) == NULL ||
	    (pv_nvp = nvlist_next_nvpair(nvl, pv_nvp)) == NULL) {
		(void) fprintf(stderr, "%s: malformed property value\n",
		    g_pname);
		return;
	}

	switch (nvpair_type(pv_nvp)) {
		case DATA_TYPE_INT32: {
			int32_t val;
			(void) nvpair_value_int32(pv_nvp, &val);
			(void) printf(" %d", val);
			break;
		}
		case DATA_TYPE_UINT32: {
			uint32_t val, type;
			char val_str[49];
			nvlist_t *fac, *rsrc = NULL;

			(void) nvpair_value_uint32(pv_nvp, &val);
			if (node == NULL || topo_node_flags(node) !=
			    TOPO_NODE_FACILITY)
				goto uint32_def;

			if (topo_node_resource(node, &rsrc, &err) != 0)
				goto uint32_def;

			if (nvlist_lookup_nvlist(rsrc, "facility", &fac) != 0)
				goto uint32_def;

			if (nvlist_lookup_string(fac, FM_FMRI_FACILITY_TYPE,
			    &factype) != 0)
				goto uint32_def;

			nvlist_free(rsrc);
			rsrc = NULL;

			/*
			 * Special case code to do friendlier printing of
			 * facility node properties
			 */
			if ((strcmp(propn, TOPO_FACILITY_TYPE) == 0) &&
			    (strcmp(factype, TOPO_FAC_TYPE_SENSOR) == 0)) {
				topo_sensor_type_name(val, val_str, 48);
				(void) printf(" 0x%x (%s)", val, val_str);
				break;
			} else if ((strcmp(propn, TOPO_FACILITY_TYPE) == 0) &&
			    (strcmp(factype, TOPO_FAC_TYPE_INDICATOR) == 0)) {
				topo_led_type_name(val, val_str, 48);
				(void) printf(" 0x%x (%s)", val, val_str);
				break;
			} else if (strcmp(propn, TOPO_SENSOR_UNITS) == 0) {
				topo_sensor_units_name(val, val_str, 48);
				(void) printf(" 0x%x (%s)", val, val_str);
				break;
			} else if (strcmp(propn, TOPO_LED_MODE) == 0) {
				topo_led_state_name(val, val_str, 48);
				(void) printf(" 0x%x (%s)", val, val_str);
				break;
			} else if ((strcmp(propn, TOPO_SENSOR_STATE) == 0) &&
			    (strcmp(factype, TOPO_FAC_TYPE_SENSOR) == 0)) {
				if (topo_prop_get_uint32(node,
				    TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE,
				    &type, &err) != 0) {
					goto uint32_def;
				}
				topo_sensor_state_name(type, val, val_str, 48);
				(void) printf(" 0x%x (%s)", val, val_str);
				break;
			}
uint32_def:
			(void) printf(" 0x%x", val);
			if (rsrc != NULL)
				nvlist_free(rsrc);
			break;
		}
		case DATA_TYPE_INT64: {
			int64_t val;
			(void) nvpair_value_int64(pv_nvp, &val);
			(void) printf(" %lld", (longlong_t)val);
			break;
		}
		case DATA_TYPE_UINT64: {
			uint64_t val;
			(void) nvpair_value_uint64(pv_nvp, &val);
			(void) printf(" 0x%llx", (u_longlong_t)val);
			break;
		}
		case DATA_TYPE_DOUBLE: {
			double val;
			(void) nvpair_value_double(pv_nvp, &val);
			(void) printf(" %lf", (double)val);
			break;
		}
		case DATA_TYPE_STRING: {
			char *val;
			(void) nvpair_value_string(pv_nvp, &val);
			if (!opt_V && strlen(val) > 48) {
				(void) snprintf(buf, 48, "%s...", val);
				(void) printf(" %s", buf);
			} else {
				(void) printf(" %s", val);
			}
			break;
		}
		case DATA_TYPE_NVLIST: {
			nvlist_t *val;
			char *fmri;
			(void) nvpair_value_nvlist(pv_nvp, &val);
			if (topo_fmri_nvl2str(thp, val, &fmri, &err) != 0) {
				if (opt_V)
					nvlist_print(stdout, nvl);
				break;
			}

			if (!opt_V && strlen(fmri) > 48) {
				(void) snprintf(buf, 48, "%s", fmri);
				(void) snprintf(&buf[45], 4, "%s", DOTS);
				(void) printf(" %s", buf);
			} else {
				(void) printf(" %s", fmri);
			}

			topo_hdl_strfree(thp, fmri);
			break;
		}
		case DATA_TYPE_INT32_ARRAY: {
			int32_t *val;

			(void) nvpair_value_int32_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("%d ", val[i]);
			(void) printf("]");
			break;
		}
		case DATA_TYPE_UINT32_ARRAY: {
			uint32_t *val;

			(void) nvpair_value_uint32_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("%u ", val[i]);
			(void) printf("]");
			break;
		}
		case DATA_TYPE_INT64_ARRAY: {
			int64_t *val;

			(void) nvpair_value_int64_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("%lld ", val[i]);
			(void) printf("]");
			break;
		}
		case DATA_TYPE_UINT64_ARRAY: {
			uint64_t *val;

			(void) nvpair_value_uint64_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("%llu ", val[i]);
			(void) printf("]");
			break;
		}
		case DATA_TYPE_STRING_ARRAY: {
			char **val;

			(void) nvpair_value_string_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("\"%s\" ", val[i]);
			(void) printf("]");
			break;
		}
		default:
			(void) fprintf(stderr, " unknown data type (%d)",
			    nvpair_type(pv_nvp));
			break;
		}
		(void) printf("\n");
}

static void
print_pgroup(topo_hdl_t *thp, tnode_t *node, const char *pgn, char *dstab,
    char *nstab, int32_t version)
{
	int err;
	char buf[30];
	topo_pgroup_info_t *pgi = NULL;

	if (pgn == NULL)
		return;

	if (node != NULL && (dstab == NULL || nstab == NULL || version == -1)) {
		if ((pgi = topo_pgroup_info(node, pgn, &err)) != NULL) {
			dstab = (char *)topo_stability2name(pgi->tpi_datastab);
			nstab = (char *)topo_stability2name(pgi->tpi_namestab);
			version = pgi->tpi_version;
		}
	}

	if (dstab == NULL || nstab == NULL || version == -1) {
		(void) printf("  group: %-30s version: - stability: -/-\n",
		    pgn);
	} else if (!opt_V && strlen(pgn) > 30) {
		(void) snprintf(buf, 26, "%s", pgn);
		(void) snprintf(&buf[27], 4, "%s", DOTS);
		(void) printf("  group: %-30s version: %-3d stability: %s/%s\n",
		    buf, version, nstab, dstab);
	} else {
		(void) printf("  group: %-30s version: %-3d stability: %s/%s\n",
		    pgn, version, nstab, dstab);
	}

	if (pgi != NULL) {
		topo_hdl_strfree(thp, (char *)pgi->tpi_name);
		topo_hdl_free(thp, pgi, sizeof (topo_pgroup_info_t));
	}
}

static void
print_all_props(topo_hdl_t *thp, tnode_t *node, nvlist_t *p_nv,
    const char *group)
{
	char *pgn = NULL, *dstab = NULL, *nstab = NULL;
	int32_t version;
	nvlist_t *pg_nv, *pv_nv;
	nvpair_t *nvp, *pg_nvp;
	int pg_done, match, all = strcmp(group, ALL) == 0;

	for (nvp = nvlist_next_nvpair(p_nv, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(p_nv, nvp)) {
		if (strcmp(TOPO_PROP_GROUP, nvpair_name(nvp)) != 0 ||
		    nvpair_type(nvp) != DATA_TYPE_NVLIST)
			continue;

		nstab = NULL;
		dstab = NULL;
		version = -1;
		pg_done = match = 0;
		(void) nvpair_value_nvlist(nvp, &pg_nv);
		for (pg_nvp = nvlist_next_nvpair(pg_nv, NULL); pg_nvp != NULL;
		    pg_nvp = nvlist_next_nvpair(pg_nv, pg_nvp)) {
			/*
			 * Print property group name and stability levels
			 */
			if (strcmp(TOPO_PROP_GROUP_NAME, nvpair_name(pg_nvp))
			    == 0 && nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &pgn);
				match = strcmp(group, pgn) == 0;
				continue;
			}

			if (strcmp(TOPO_PROP_GROUP_NSTAB,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &nstab);
				continue;
			}

			if (strcmp(TOPO_PROP_GROUP_DSTAB,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &dstab);
				continue;
			}

			if (strcmp(TOPO_PROP_GROUP_VERSION,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_INT32) {
				(void) nvpair_value_int32(pg_nvp, &version);
				continue;
			}

			if ((match || all) && !pg_done) {
				print_pgroup(thp, node, pgn, dstab, nstab,
				    version);
				pg_done++;
			}

			/*
			 * Print property group and property name-value pair
			 */
			if (strcmp(TOPO_PROP_VAL, nvpair_name(pg_nvp))
			    == 0 && nvpair_type(pg_nvp) == DATA_TYPE_NVLIST) {
				(void) nvpair_value_nvlist(pg_nvp, &pv_nv);
				if ((match || all) && pg_done) {
					print_prop_nameval(thp, node, pv_nv);
				}

			}

		}
		if (match && !all)
			return;
	}
}

static void
set_prop(topo_hdl_t *thp, tnode_t *node, nvlist_t *fmri, struct prop_args *pp)
{
	int ret, err = 0;
	topo_type_t type;
	nvlist_t *nvl = NULL;
	char *end;

	if (pp->prop == NULL || pp->type == NULL || pp->value == NULL)
		goto out;

	if ((type = str2type(pp->type)) == TOPO_TYPE_INVALID) {
		(void) fprintf(stderr, "%s: invalid property type %s for %s\n",
		    g_pname, pp->type, pp->prop);
		goto out;
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		(void) fprintf(stderr, "%s: nvlist allocation failed for "
		    "%s=%s:%s\n", g_pname, pp->prop, pp->type, pp->value);
		goto out;
	}
	ret = nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, pp->prop);
	ret |= nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, type);
	if (ret != 0) {
		(void) fprintf(stderr, "%s: invalid property type %s for %s\n",
		    g_pname, pp->type, pp->prop);
		goto out;
	}

	errno = 0;
	switch (type) {
		case TOPO_TYPE_INT32:
		{
			int32_t val;

			val = strtol(pp->value, &end, 0);
			if (errno == ERANGE) {
				ret = -1;
				break;
			}
			ret = nvlist_add_int32(nvl, TOPO_PROP_VAL_VAL, val);
			break;
		}
		case TOPO_TYPE_UINT32:
		{
			uint32_t val;

			val = strtoul(pp->value, &end, 0);
			if (errno == ERANGE) {
				ret = -1;
				break;
			}
			ret = nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, val);
			break;
		}
		case TOPO_TYPE_INT64:
		{
			int64_t val;

			val = strtoll(pp->value, &end, 0);
			if (errno == ERANGE) {
				ret = -1;
				break;
			}
			ret = nvlist_add_int64(nvl, TOPO_PROP_VAL_VAL, val);
			break;
		}
		case TOPO_TYPE_UINT64:
		{
			uint64_t val;

			val = strtoull(pp->value, &end, 0);
			if (errno == ERANGE) {
				ret = -1;
				break;
			}
			ret = nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL, val);
			break;
		}
		case TOPO_TYPE_STRING:
		{
			ret = nvlist_add_string(nvl, TOPO_PROP_VAL_VAL,
			    pp->value);
			break;
		}
		case TOPO_TYPE_FMRI:
		{
			nvlist_t *val = NULL;

			if ((ret = topo_fmri_str2nvl(thp, pp->value, &val,
			    &err)) < 0)
				break;

			if ((ret = nvlist_add_nvlist(nvl, TOPO_PROP_VAL_VAL,
			    val)) != 0)
				err = ETOPO_PROP_NVL;

			nvlist_free(val);
			break;
		}
		default:
			ret = -1;
	}

	if (ret != 0) {
		(void) fprintf(stderr, "%s: unable to set property value for "
		    "%s: %s\n", g_pname, pp->prop,  topo_strerror(err));
		goto out;
	}

	if (node != NULL) {
		if ((ret = topo_prop_setprop(node, pp->group, nvl,
		    TOPO_PROP_MUTABLE, nvl, &err)) < 0) {
			(void) fprintf(stderr, "%s: unable to set property "
			    "value for " "%s=%s:%s: %s\n", g_pname, pp->prop,
			    pp->type, pp->value, topo_strerror(err));
			goto out;
		}
	} else {
		if ((ret = topo_fmri_setprop(thp, fmri,  pp->group, nvl,
		    TOPO_PROP_MUTABLE, nvl, &err)) < 0) {
			(void) fprintf(stderr, "%s: unable to set property "
			    "value for " "%s=%s:%s: %s\n", g_pname, pp->prop,
			    pp->type, pp->value, topo_strerror(err));
			goto out;
		}
	}

	nvlist_free(nvl);
	nvl = NULL;

	/*
	 * Now, get the property back for printing
	 */
	if (node != NULL) {
		if ((ret = topo_prop_getprop(node, pp->group, pp->prop, NULL,
		    &nvl, &err)) < 0) {
			(void) fprintf(stderr, "%s: failed to get %s.%s: %s\n",
			    g_pname, pp->group, pp->prop, topo_strerror(err));
			goto out;
		}
	} else {
		if ((ret = topo_fmri_getprop(thp, fmri, pp->group, pp->prop,
		    NULL, &nvl, &err)) < 0) {
			(void) fprintf(stderr, "%s: failed to get %s.%s: %s\n",
			    g_pname, pp->group, pp->prop, topo_strerror(err));
			goto out;
		}
	}

	print_pgroup(thp, node, pp->group, NULL, NULL, 0);
	print_prop_nameval(thp, node, nvl);

out:
	nvlist_free(nvl);
}

static void
print_props(topo_hdl_t *thp, tnode_t *node)
{
	int i, err;
	nvlist_t *nvl;
	struct prop_args *pp;

	if (pcnt == 0)
		return;

	for (i = 0; i < pcnt; ++i) {
		pp = pargs[i];

		if (pp->group == NULL)
			continue;

		/*
		 * If we have a valid value, this is a request to
		 * set a property.  Otherwise, just print the property
		 * group and any specified properties.
		 */
		if (pp->value == NULL) {
			if (pp->prop == NULL) {

				/*
				 * Print all properties in this group
				 */
				if ((nvl = topo_prop_getprops(node, &err))
				    == NULL) {
					(void) fprintf(stderr, "%s: failed to "
					    "get %s: %s\n", g_pname,
					    pp->group,
					    topo_strerror(err));
					continue;
				} else {
					print_all_props(thp, node, nvl,
					    pp->group);
					nvlist_free(nvl);
					continue;
				}
			}
			if (topo_prop_getprop(node, pp->group, pp->prop,
			    NULL, &nvl, &err) < 0) {
				(void) fprintf(stderr, "%s: failed to get "
				    "%s.%s: %s\n", g_pname,
				    pp->group, pp->prop,
				    topo_strerror(err));
				continue;
			} else {
				print_pgroup(thp, node, pp->group, NULL,
				    NULL, 0);
				print_prop_nameval(thp, node, nvl);
				nvlist_free(nvl);
			}
		} else {
			set_prop(thp, node, NULL, pp);
		}
	}
}

/*ARGSUSED*/
static int
walk_node(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *nvl;
	nvlist_t *rsrc, *out;
	char *s;

	if (opt_e && strcmp(opt_s, FM_FMRI_SCHEME_HC) == 0) {
		print_everstyle(node);
		return (TOPO_WALK_NEXT);
	}

	if (topo_node_resource(node, &rsrc, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to get resource: "
		    "%s", g_pname, topo_strerror(err));
		return (TOPO_WALK_NEXT);
	}
	if (topo_fmri_nvl2str(thp, rsrc, &s, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to convert "
		    "resource to FMRI string: %s", g_pname,
		    topo_strerror(err));
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}

	if (g_fmri != NULL && fnmatch(g_fmri, s, 0) != 0) {
		nvlist_free(rsrc);
		topo_hdl_strfree(thp, s);
		return (TOPO_WALK_NEXT);
	}

	print_node(thp, node, rsrc, s);
	topo_hdl_strfree(thp, s);
	nvlist_free(rsrc);

	if (opt_m != NULL) {
		if (topo_method_invoke(node, opt_m, 0, NULL, &out, &err) == 0) {
			nvlist_print(stdout, out);
			nvlist_free(out);
		} else if (err != ETOPO_METHOD_NOTSUP)
			(void) fprintf(stderr, "%s: method failed unexpectedly "
			    "on %s=%d (%s)\n", g_pname, topo_node_name(node),
			    topo_node_instance(node), topo_strerror(err));
	}

	if (opt_V || opt_all) {
		if ((nvl = topo_prop_getprops(node, &err)) == NULL) {
			(void) fprintf(stderr, "%s: failed to get "
			    "properties for %s=%d: %s\n", g_pname,
			    topo_node_name(node), topo_node_instance(node),
			    topo_strerror(err));
		} else {
			print_all_props(thp, node, nvl, ALL);
			nvlist_free(nvl);
		}
	} else if (pcnt > 0)
		print_props(thp, node);

	(void) printf("\n");

	return (TOPO_WALK_NEXT);
}

static void
get_pargs(int argc, char *argv[])
{
	struct prop_args *pp;
	char c, *s, *p;
	int i = 0;

	if ((pargs = malloc(sizeof (struct prop_args *) * pcnt)) == NULL) {
		(void) fprintf(stderr, "%s: failed to allocate property "
		    "arguments\n", g_pname);
		return;
	}

	for (optind = 1; (c = getopt(argc, argv, optstr)) != EOF; ) {
		if (c == 'P') {

			if (strcmp(optarg, ALL) == 0) {
				opt_all++;
				break;
			}

			if ((pp = pargs[i] = malloc(sizeof (struct prop_args)))
			    == NULL) {
				(void) fprintf(stderr, "%s: failed to "
				    "allocate propertyarguments\n", g_pname);
				return;
			}
			++i;
			pp->group = NULL;
			pp->prop = NULL;
			pp->type = NULL;
			pp->value = NULL;

			p = optarg;
			if ((s = strchr(p, '.')) != NULL) {
				*s++ = '\0'; /* strike out delimiter */
				pp->group = p;
				p = s;
				if ((s = strchr(p, '=')) != NULL) {
					*s++ = '\0'; /* strike out delimiter */
					pp->prop = p;
					p = s;
					if ((s = strchr(p, ':')) != NULL) {
						*s++ = '\0';
						pp->type = p;
						pp->value = s;
					} else {
						(void) fprintf(stderr, "%s: "
						    "property type not "
						    "specified for assignment "
						    " of %s.%s\n", g_pname,
						    pp->group, pp->prop);
						break;
					}
				} else {
					pp->prop = p;
				}
			} else {
				pp->group = p;
			}
			if (i >= pcnt)
				break;
		}
	}

	if (opt_all > 0) {
		int j;

		for (j = 0; j < i; ++j)
			free(pargs[i]);
		free(pargs);
		pargs = NULL;
	}
}

static int
walk_topo(topo_hdl_t *thp, char *uuid)
{
	int err;
	topo_walk_t *twp;
	int flag;

	if (getzoneid() != GLOBAL_ZONEID &&
	    strcmp(opt_s, FM_FMRI_SCHEME_HC) == 0) {
		return (0);
	}

	if ((twp = topo_walk_init(thp, opt_s, walk_node, NULL, &err))
	    == NULL) {
		(void) fprintf(stderr, "%s: failed to walk %s topology:"
		    " %s\n", g_pname, opt_s, topo_strerror(err));

		return (-1);
	}

	/*
	 * Print standard header
	 */
	if (!opt_e) {
		char buf[32];
		time_t tod = time(NULL);

		(void) printf("TIME                 UUID\n");
		(void) strftime(buf, sizeof (buf), "%b %d %T", localtime(&tod));
		(void) printf("%-15s %-32s\n", buf, uuid);
		(void) printf("\n");
	}

	flag = opt_b != 0 ? TOPO_WALK_SIBLING : TOPO_WALK_CHILD;

	if (topo_walk_step(twp, flag) == TOPO_WALK_ERR) {
		(void) fprintf(stderr, "%s: failed to walk topology\n",
		    g_pname);
		topo_walk_fini(twp);
		return (-1);
	}

	topo_walk_fini(twp);

	return (0);
}

static void
print_fmri_pgroup(topo_hdl_t *thp, const char *pgn, nvlist_t *nvl)
{
	char *dstab = NULL, *nstab = NULL;
	int32_t version = -1;
	nvlist_t *pnvl;
	nvpair_t *pnvp;

	(void) nvlist_lookup_string(nvl, TOPO_PROP_GROUP_NSTAB, &nstab);
	(void) nvlist_lookup_string(nvl, TOPO_PROP_GROUP_DSTAB, &dstab);
	(void) nvlist_lookup_int32(nvl, TOPO_PROP_GROUP_VERSION, &version);

	print_pgroup(thp, NULL, pgn, dstab, nstab, version);

	for (pnvp = nvlist_next_nvpair(nvl, NULL); pnvp != NULL;
	    pnvp = nvlist_next_nvpair(nvl, pnvp)) {

		/*
		 * Print property group and property name-value pair
		 */
		if (strcmp(TOPO_PROP_VAL, nvpair_name(pnvp))
		    == 0 && nvpair_type(pnvp) == DATA_TYPE_NVLIST) {
			(void) nvpair_value_nvlist(pnvp, &pnvl);
				print_prop_nameval(thp, NULL, pnvl);

		}

	}
}

static void
print_fmri_props(topo_hdl_t *thp, nvlist_t *nvl)
{
	int i, err;
	struct prop_args *pp;
	nvlist_t *pnvl;

	for (i = 0; i < pcnt; ++i) {
		pp = pargs[i];

		if (pp->group == NULL)
			continue;

		pnvl = NULL;

		/*
		 * If we have a valid value, this is a request to
		 * set a property.  Otherwise, just print the property
		 * group and any specified properties.
		 */
		if (pp->value == NULL) {
			if (pp->prop == NULL) {

				/*
				 * Print all properties in this group
				 */
				if (topo_fmri_getpgrp(thp, nvl, pp->group,
				    &pnvl, &err) < 0) {
					(void) fprintf(stderr, "%s: failed to "
					    "get group %s: %s\n", g_pname,
					    pp->group, topo_strerror(err));
					continue;
				} else {
					print_fmri_pgroup(thp, pp->group,
					    pnvl);
					nvlist_free(pnvl);
					continue;
				}
			}
			if (topo_fmri_getprop(thp, nvl, pp->group, pp->prop,
			    NULL, &pnvl, &err) < 0) {
				(void) fprintf(stderr, "%s: failed to get "
				    "%s.%s: %s\n", g_pname,
				    pp->group, pp->prop,
				    topo_strerror(err));
				continue;
			} else {
				print_fmri_pgroup(thp, pp->group, pnvl);
				print_prop_nameval(thp, NULL, pnvl);
				nvlist_free(nvl);
			}
		} else {
			set_prop(thp, NULL, nvl, pp);
		}
	}
}

void
print_fmri(topo_hdl_t *thp, char *uuid)
{
	int ret, err;
	nvlist_t *nvl;
	char buf[32];
	time_t tod = time(NULL);

	if (topo_fmri_str2nvl(thp, g_fmri, &nvl, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to convert %s to nvlist: "
		    "%s\n", g_pname, g_fmri, topo_strerror(err));
		return;
	}

	(void) printf("TIME                 UUID\n");
	(void) strftime(buf, sizeof (buf), "%b %d %T", localtime(&tod));
	(void) printf("%-15s %-32s\n", buf, uuid);
	(void) printf("\n");

	(void) printf("%s\n", (char *)g_fmri);

	if (opt_p && !(pcnt > 0 || opt_V || opt_all)) {
		char *aname = NULL, *fname = NULL, *lname = NULL;
		nvlist_t *asru = NULL;
		nvlist_t *fru = NULL;

		if (topo_fmri_asru(thp, nvl, &asru, &err) == 0)
			(void) topo_fmri_nvl2str(thp, asru, &aname, &err);
		if (topo_fmri_fru(thp, nvl, &fru, &err) == 0)
			(void) topo_fmri_nvl2str(thp, fru, &fname, &err);
		(void) topo_fmri_label(thp, nvl, &lname, &err);

		nvlist_free(fru);
		nvlist_free(asru);

		if (aname != NULL) {
			(void) printf("\tASRU: %s\n", aname);
			topo_hdl_strfree(thp, aname);
		} else {
			(void) printf("\tASRU: -\n");
		}
		if (fname != NULL) {
			(void) printf("\tFRU: %s\n", fname);
			topo_hdl_strfree(thp, fname);
		} else {
			(void) printf("\tFRU: -\n");
		}
		if (lname != NULL) {
			(void) printf("\tLabel: %s\n", lname);
			topo_hdl_strfree(thp, lname);
		} else {
			(void) printf("\tLabel: -\n");
		}
	}

	if (opt_S) {
		if (topo_fmri_str2nvl(thp, g_fmri, &nvl, &err) < 0) {
			(void) printf("\tPresent: -\n");
			(void) printf("\tUnusable: -\n");
			return;
		}

		if ((ret = topo_fmri_present(thp, nvl, &err)) < 0)
			(void) printf("\tPresent: -\n");
		else
			(void) printf("\tPresent: %s\n",
			    ret ? "true" : "false");

		if ((ret = topo_fmri_unusable(thp, nvl, &err)) < 0)
			(void) printf("\tUnusable: -\n");
		else
			(void) printf("\tUnusable: %s\n",
			    ret ? "true" : "false");

		nvlist_free(nvl);
	}

	if (pargs && pcnt > 0)
		print_fmri_props(thp, nvl);
}

int
fmtopo_exit(topo_hdl_t *thp, char *uuid, int err)
{
	if (uuid != NULL)
		topo_hdl_strfree(thp, uuid);

	if (thp != NULL) {
		topo_snap_release(thp);
		topo_close(thp);
	}

	if (pargs) {
		int i;
		for (i = 0; i < pcnt; ++i)
			free(pargs[i]);
		free(pargs);
	}

	return (err);
}

int
main(int argc, char *argv[])
{
	topo_hdl_t *thp = NULL;
	char *uuid = NULL;
	int c, err = 0;

	g_pname = argv[0];

	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != -1) {
			switch (c) {
			case 'b':
				opt_b++;
				break;
			case 'C':
				(void) atexit(abort);
				break;
			case 'd':
				opt_d++;
				break;
			case 'e':
				opt_e++;
				break;
			case 'm':
				opt_m = optarg;
				break;
			case 'P':
				pcnt++;
				break;
			case 'p':
				opt_p++;
				break;
			case 'V':
				opt_V++;
				break;
			case 'R':
				opt_R = optarg;
				break;
			case 's':
				opt_s = optarg;
				break;
			case 'S':
				opt_S++;
				break;
			case 't':
				opt_t++;
				break;
			case 'x':
				opt_x++;
				break;
			default:
				return (usage(stderr));
			}
		}

		if (optind < argc) {
			if (g_fmri != NULL) {
				(void) fprintf(stderr, "%s: illegal argument "
				    "-- %s\n", g_pname, argv[optind]);
				return (FMTOPO_EXIT_USAGE);
			} else {
				g_fmri = argv[optind++];
			}
		}
	}

	if (pcnt > 0)
		get_pargs(argc, argv);

	if ((thp = topo_open(TOPO_VERSION, opt_R, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to open topology tree: %s\n",
		    g_pname, topo_strerror(err));
		return (fmtopo_exit(thp, uuid, FMTOPO_EXIT_ERROR));
	}

	if (opt_d)
		topo_debug_set(thp, "module", "stderr");

	if ((uuid = topo_snap_hold(thp, NULL, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to snapshot topology: %s\n",
		    g_pname, topo_strerror(err));
		return (fmtopo_exit(thp, uuid, FMTOPO_EXIT_ERROR));
	} else if (err != 0) {
		(void) fprintf(stderr, "%s: topology snapshot incomplete%s\n",
		    g_pname, getzoneid() != GLOBAL_ZONEID &&
		    strcmp(opt_s, FM_FMRI_SCHEME_HC) == 0 ?
		    " (" FM_FMRI_SCHEME_HC " scheme does not enumerate "
		    "in a non-global zone)": "");
	}

	if (opt_x) {
		if (opt_b) {
			(void) fprintf(stderr,
			    "%s: -b and -x cannot be specified together\n",
			    g_pname);
			return (fmtopo_exit(thp, uuid, FMTOPO_EXIT_USAGE));
		}

		err = 0;
		if (topo_xml_print(thp, stdout, opt_s, &err) < 0)
			(void) fprintf(stderr, "%s: failed to print xml "
			    "formatted topology:%s",  g_pname,
			    topo_strerror(err));

		return (fmtopo_exit(thp, uuid, err ? FMTOPO_EXIT_ERROR :
		    FMTOPO_EXIT_SUCCESS));
	}

	if (opt_t || walk_topo(thp, uuid) < 0) {
		if (g_fmri != NULL)
			/*
			 * Try getting some useful information
			 */
			print_fmri(thp, uuid);

		return (fmtopo_exit(thp, uuid, FMTOPO_EXIT_ERROR));
	}

	return (fmtopo_exit(thp, uuid, FMTOPO_EXIT_SUCCESS));
}
