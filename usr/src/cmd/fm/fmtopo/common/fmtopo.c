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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <fm/libtopo.h>
#include <ctype.h>
#include <limits.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <sys/param.h>

#define	FMTOPO_EXIT_SUCCESS	0
#define	FMTOPO_EXIT_ERROR	1
#define	FMTOPO_EXIT_USAGE	2

#define	STDERR	"stderr"
#define	DOTS	"..."
#define	ALL	"all"

static const char *g_pname;

static const char *opt_R = "/";
static const char *opt_P = NULL;
static const char *opt_s = FM_FMRI_SCHEME_HC;

static int opt_e = 0;
static int opt_d = 0;
static int opt_V = 0;
static int opt_p = 0;
static int opt_x = 0;

static int
usage(FILE *fp)
{
	(void) fprintf(fp,
	    "Usage: %s [-edpvVx] [-Cdev] [-P properties] [-R root] "
		    "[-s scheme]\n", g_pname);

	(void) fprintf(fp,
	    "\t-C  dump core after completing execution\n"
	    "\t-d  set debug mode for libtopo modules\n"
	    "\t-e  display FMRIs as paths using esc/eft notation\n"
	    "\t-P  display of FMRI with the specified properties\n"
	    "\t-p  display of FMRI protocol properties\n"
	    "\t-R  set root directory for libtopo plug-ins and other files\n"
	    "\t-s  display topology for the specified FMRI scheme\n"
	    "\t-V  set verbose mode\n"
	    "\t-x  display a xml formatted topology\n");

	return (FMTOPO_EXIT_USAGE);
}

static void
print_fmri(topo_hdl_t *thp, tnode_t *node)
{
	int err;
	char *name;
	nvlist_t *fmri;

	if (topo_node_resource(node, &fmri, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to get fmri for %s=%d: %s\n",
		    g_pname, topo_node_name(node),
		    topo_node_instance(node), topo_strerror(err));
		return;
	}

	if (topo_fmri_nvl2str(thp, fmri, &name, &err) < 0) {
		(void) fprintf(stderr, "%s: failed to convert fmri for %s=%d "
		    "to a string: %s\n", g_pname, topo_node_name(node),
		    topo_node_instance(node), topo_strerror(err));
		nvlist_free(fmri);
		return;
	}

	(void) printf("%s\n", name);

	if (opt_p) {
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
	nvlist_free(fmri);

	topo_hdl_strfree(thp, name);
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

	(void) printf("%s\n", buf);
}

static void
print_prop_nameval(topo_hdl_t *thp, nvlist_t *nvl, int skip)
{
	int err;
	topo_type_t type;
	char *tstr, *propn, buf[48];
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
	    nvpair_type(pv_nvp) != DATA_TYPE_INT32)  {
		(void) fprintf(stderr, "%s: malformed property type for %s\n",
		    g_pname, propn);
		return;
	} else {
		(void) nvpair_value_int32(pv_nvp, (int32_t *)&type);
	}

	switch (type) {
		case TOPO_TYPE_BOOLEAN: tstr = "boolean"; break;
		case TOPO_TYPE_INT32: tstr = "int32"; break;
		case TOPO_TYPE_UINT32: tstr = "uint32"; break;
		case TOPO_TYPE_INT64: tstr = "int64"; break;
		case TOPO_TYPE_UINT64: tstr = "uint64"; break;
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

	if (!skip)
		printf("    %-17s %-8s ", propn, tstr);

	/*
	 * Get property value
	 */
	if (nvpair_name(pv_nvp) == NULL ||
	    (pv_nvp = nvlist_next_nvpair(nvl, pv_nvp)) == NULL) {
		(void) fprintf(stderr, "%s: malformed property value\n",
		    g_pname);
		return;
	}

	if (skip)
		return;

	switch (nvpair_type(pv_nvp)) {
		case DATA_TYPE_INT32: {
			int32_t val;
			(void) nvpair_value_int32(pv_nvp, &val);
			(void) printf(" %d", val);
			break;
		}
		case DATA_TYPE_UINT32: {
			uint32_t val;
			(void) nvpair_value_uint32(pv_nvp, &val);
			(void) printf(" 0x%x", val);
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
		case DATA_TYPE_UINT32_ARRAY: {
			uint32_t *val;

			(void) nvpair_value_uint32_array(pv_nvp, &val, &nelem);
			(void) printf(" [ ");
			for (i = 0; i < nelem; i++)
				(void) printf("%u ", val[i]);
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
print_pgroup(char *pgn, char *dstab, char *nstab, int32_t version, int skip)
{
	char buf[30];

	if (skip)
		return;

	if (!opt_V && strlen(pgn) > 30) {
		(void) snprintf(buf, 26, "%s", pgn);
		(void) snprintf(&buf[27], 4, "%s", DOTS);
		printf("  group: %-30s version: %-3d stability: %s/%s\n",
		    buf, version, nstab, dstab);
	} else {
		printf("  group: %-30s version: %-3d stability: %s/%s\n",
		    pgn, version, nstab, dstab);
	}
}

static int
cmp_name(const char *props, char *pgn)
{
	char buf[MAXNAMELEN];
	size_t count;
	char *begin, *end, *value, *next;
	char *np;

	if (props == NULL)
		return (0);

	if (strcmp(props, ALL) == 0)
		return (0);


	value = np = strdup(props);

	for (end = np; *end != '\0'; value = next) {
		end = strchr(value, ',');
		if (end != NULL)
			next = end + 1; /* skip the comma */
		else
			next = end = value + strlen(value);

		/*
		 * Eat up white space at beginning or end of the
		 * property group name
		 */
		begin = value;
		while (begin < end && isspace(*begin))
			begin++;
		while (begin < end && isspace(*(end - 1)))
			end--;

		if (begin >= end)
			return (1);

		count = end - begin;
		count += 1;

		if (count > sizeof (buf))
			return (1);

		(void) snprintf(buf, count, "%s", begin);
		if (strcmp(pgn, buf) == 0) {
			free(np);
			return (0);
		}
	}

	free(np);
	return (1);
}

static void
print_props(topo_hdl_t *thp, nvlist_t *p_nv, const char *props)
{
	char *pgn = NULL, *dstab = NULL, *nstab = NULL;
	int32_t version = 0;
	nvlist_t *pg_nv, *pv_nv;
	nvpair_t *nvp, *pg_nvp;
	int pg_done = 0, skip = 0;

	for (nvp = nvlist_next_nvpair(p_nv, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(p_nv, nvp)) {
		if (strcmp(TOPO_PROP_GROUP, nvpair_name(nvp)) != 0 ||
		    nvpair_type(nvp) != DATA_TYPE_NVLIST)
			continue;

		(void) nvpair_value_nvlist(nvp, &pg_nv);
		for (pg_nvp = nvlist_next_nvpair(pg_nv, NULL); pg_nvp != NULL;
		    pg_nvp = nvlist_next_nvpair(pg_nv, pg_nvp)) {
			/*
			 * Print property group name and stability levels
			 */
			if (strcmp(TOPO_PROP_GROUP_NAME, nvpair_name(pg_nvp))
			    == 0 && nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &pgn);

				skip = cmp_name(props, pgn);

			} else if (strcmp(TOPO_PROP_GROUP_NSTAB,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &nstab);
			} else if (strcmp(TOPO_PROP_GROUP_DSTAB,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_STRING) {
				(void) nvpair_value_string(pg_nvp, &dstab);
			} else if (strcmp(TOPO_PROP_GROUP_VERSION,
			    nvpair_name(pg_nvp)) == 0 &&
			    nvpair_type(pg_nvp) == DATA_TYPE_INT32) {
				(void) nvpair_value_int32(pg_nvp, &version);
			}

			if (!pg_done) {
				if (pgn && dstab && nstab && version) {
					print_pgroup(pgn, dstab, nstab,
					    version, skip);
					pg_done++;
				} else {
					continue;
				}
			/*
			 * Print property name-value pair
			 */
			} else if (strcmp(TOPO_PROP_VAL, nvpair_name(pg_nvp))
			    == 0 && nvpair_type(pg_nvp) == DATA_TYPE_NVLIST) {
				(void) nvpair_value_nvlist(pg_nvp, &pv_nv);
				print_prop_nameval(thp, pv_nv, skip);

			}
		}
		pg_done = 0;
		skip = 0;
	}
}

/*ARGSUSED*/
static int
print_tnode(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *nvl;

	if (opt_e && strcmp(opt_s, FM_FMRI_SCHEME_HC) == 0) {
		print_everstyle(node);
		return (TOPO_WALK_NEXT);
	}

	print_fmri(thp, node);

	if (opt_V || opt_P) {
		if ((nvl = topo_prop_getprops(node, &err)) == NULL) {
			(void) fprintf(stderr, "%s: failed to get "
			    "properties for %s=%d: %s\n", g_pname,
			    topo_node_name(node), topo_node_instance(node),
			    topo_strerror(err));
		} else {
			print_props(thp, nvl, opt_P);
			nvlist_free(nvl);
		}
	}

	printf("\n");

	return (TOPO_WALK_NEXT);
}

int
main(int argc, char *argv[])
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	char *uuid;
	int c, err = 0;

	g_pname = argv[0];

	while (optind < argc) {
		while ((c = getopt(argc, argv, "aCdeP:pR:s:vVx")) != -1) {
			switch (c) {
			case 'C':
				atexit(abort);
				break;
			case 'd':
				opt_d++;
				break;
			case 'e':
				opt_e++;
				break;
			case 'P':
				opt_P = optarg;
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
			case 'x':
				opt_x++;
				break;
			default:
				return (usage(stderr));
			}
		}

		if (optind < argc) {
			(void) fprintf(stderr, "%s: illegal argument -- %s\n",
			    g_pname, argv[optind]);
			return (FMTOPO_EXIT_USAGE);
		}
	}

	if ((thp = topo_open(TOPO_VERSION, opt_R, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to open topology tree: %s\n",
		    g_pname, topo_strerror(err));
		return (FMTOPO_EXIT_ERROR);
	}

	if (opt_d)
		topo_debug_set(thp, "module", "stderr");

	if ((uuid = topo_snap_hold(thp, NULL, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to snapshot topology: %s\n",
		    g_pname, topo_strerror(err));
		topo_close(thp);
		return (FMTOPO_EXIT_ERROR);
	} else if (err != 0) {
		(void) fprintf(stderr, "%s: topology snapshot incomplete\n",
		    g_pname);
	}


	if (opt_x) {
		err = 0;
		if (topo_xml_print(thp, stdout, opt_s, &err) < 0)
			(void) fprintf(stderr, "%s: failed to print xml "
			    "formatted topology:%s",  g_pname,
			    topo_strerror(err));

		topo_hdl_strfree(thp, uuid);
		topo_snap_release(thp);
		topo_close(thp);
		return (err ? FMTOPO_EXIT_ERROR : FMTOPO_EXIT_SUCCESS);
	}
	if ((twp = topo_walk_init(thp, opt_s, print_tnode, NULL, &err))
	    == NULL) {
		(void) fprintf(stderr, "%s: failed to walk %s topology:"
		    " %s\n", g_pname, opt_s, topo_strerror(err));

		topo_hdl_strfree(thp, uuid);
		topo_snap_release(thp);
		topo_close(thp);

		return (err ? FMTOPO_EXIT_ERROR : FMTOPO_EXIT_SUCCESS);
	}

	/*
	 * Print standard header
	 */
	if (!opt_e) {
		char buf[32];
		time_t tod = time(NULL);

		printf("TIME                 UUID\n");
		(void) strftime(buf, sizeof (buf), "%b %d %T", localtime(&tod));
		(void) printf("%-15s %-32s\n", buf, uuid);
		(void) printf("\n");
	}

	topo_hdl_strfree(thp, uuid);

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		(void) fprintf(stderr, "%s: failed to walk topology\n",
		    g_pname);
		topo_walk_fini(twp);
		topo_snap_release(thp);
		topo_close(thp);
		return (FMTOPO_EXIT_ERROR);
	}

	topo_walk_fini(twp);
	topo_snap_release(thp);
	topo_close(thp);

	return (FMTOPO_EXIT_SUCCESS);
}
