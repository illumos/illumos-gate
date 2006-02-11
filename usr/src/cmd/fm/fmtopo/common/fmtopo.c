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
#include <limits.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>

#define	FMTOPO_EXIT_SUCCESS	0
#define	FMTOPO_EXIT_ERROR	1
#define	FMTOPO_EXIT_USAGE	2

static const char *g_pname;

static const char *opt_R = "/";
static const char *opt_s = FM_FMRI_SCHEME_HC;

static int opt_e;
static int opt_d;
static int opt_v;
static int opt_V;

static int
usage(FILE *fp)
{
	(void) fprintf(fp,
	    "Usage: %s [-Cdev] [-R root] [-s scheme]\n", g_pname);

	(void) fprintf(fp,
	    "\t-C  dump core after completing execution\n"
	    "\t-d  set debug mode for libtopo\n"
	    "\t-e  display nodes as paths using esc/eft notation\n"
	    "\t-R  set root directory for libtopo plug-ins and other files\n"
	    "\t-s  display topology for the specified FMRI scheme\n"
	    "\t-v  set verbose mode (display node ASRU, FRU and label)\n"
	    "\t-V  set verbose mode (display node properties)\n");

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

	if (opt_v) {
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

	if (opt_d) {
		fmri = NULL;

		if (topo_fmri_str2nvl(thp, name, &fmri, &err) < 0) {
			(void) fprintf(stderr, "%s: failed to convert "
			    "alternate fmri for %s=%d: %s\n", g_pname,
			    topo_node_name(node), topo_node_instance(node),
			    topo_strerror(err));
		} else {
			nvlist_print(stderr, fmri);
			nvlist_free(fmri);
		}
	}

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

/*ARGSUSED*/
static int
print_tnode(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	if (opt_e && strcmp(opt_s, FM_FMRI_SCHEME_HC) == 0)
		print_everstyle(node);
	else
		print_fmri(thp, node);

	if (opt_V) {
		nvlist_t *nvl = topo_prop_get_all(thp, node);

		if (nvl == NULL) {
			(void) fprintf(stderr, "%s: failed to get properties "
			    "for %s=%d\n", g_pname, topo_node_name(node),
			    topo_node_instance(node));
		} else {
			nvlist_print(stdout, nvl);
			nvlist_free(nvl);
		}
	}

	return (TOPO_WALK_NEXT);
}

int
main(int argc, char *argv[])
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	char *uuid;
	int c, err;

	g_pname = argv[0];

	while (optind < argc) {
		while ((c = getopt(argc, argv, "aCdeR:s:vV")) != -1) {
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
			case 'v':
				opt_v++;
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
		topo_debug_set(thp, TOPO_DBG_ALL, "stderr");

	if ((uuid = topo_snap_hold(thp, NULL, &err)) == NULL) {
		(void) fprintf(stderr, "%s: failed to snapshot topology: %s\n",
		    g_pname, topo_strerror(err));
		topo_close(thp);
		return (FMTOPO_EXIT_ERROR);
	}

	if ((twp = topo_walk_init(thp, opt_s, print_tnode, NULL, &err))
	    == NULL) {
		(void) fprintf(stderr, "%s: failed to walk %s topology:"
		    " %s\n", g_pname, opt_s, topo_strerror(err));

		topo_hdl_strfree(thp, uuid);
		topo_close(thp);

		return (err ? FMTOPO_EXIT_ERROR : FMTOPO_EXIT_SUCCESS);
	}

	if (!opt_e)
		(void) printf("Topology Snapshot %s\n", uuid);

	topo_hdl_strfree(thp, uuid);

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		(void) fprintf(stderr, "%s: failed to walk topology\n",
		    g_pname);
		topo_close(thp);
		return (FMTOPO_EXIT_ERROR);
	}

	if (opt_d)
		(void) printf("--------------------\n");

	topo_walk_fini(twp);
	topo_snap_release(thp);
	topo_close(thp);

	return (FMTOPO_EXIT_SUCCESS);
}
