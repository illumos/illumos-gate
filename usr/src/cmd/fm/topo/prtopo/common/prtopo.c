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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/fm/protocol.h>
#include <fm/libtopo.h>

int Allprops;
int Everstyle;

void
Usage(char *progname, char badopt)
{
	(void) fprintf(stderr, "Option not recognized -%c\n", badopt);
	(void) fprintf(stderr, "Usage: %s [-a] [-d] [-e] [-v] [-p path]\n\n",
	    progname);
	(void) fprintf(stderr, "\tBy default, %s\n"
	    "\tdisplays each node in the topology tree of the system in\n"
	    "\thc FMRI string format, for example:\n"
	    "\t\thc:///motherboard=0/pcibus=0/pcidev=1/pcifn=0\n\n",
	    progname);
	(void) fprintf(stderr, "\t-v: "
	    "display properties attached to a node along with the node\n");
	(void) fprintf(stderr, "\t-a: "
	    "same as -v except includes \"invisible\" properties \n");
	(void) fprintf(stderr, "\t-d: "
	    "display massive amounts of debug output from libtopo\n");
	(void) fprintf(stderr, "\t-e: "
	    "display nodes as simple paths, \"eversholt style\", "
	    "for example:\n"
	    "\t\t/motherboard0/pcibus0/pcidev1/pcifn0\n\n");
	(void) fprintf(stderr, "\t-p path:\n"
	    "\t\tdisplay the topology node associated with the\n"
	    "\t\tprovided simple path.\n\n");
	exit(3);
}

void
print_buf(const char *pme)
{
	(void) printf("%s", pme);
}

/*
 * buf_append -- Append str to buf if it's non-NULL.  Add prepend to buf
 * in front of str and append behind it (if they're non-NULL).  Update
 * size as you proceed, even if we run out of space to actually stuff
 * characters in the buffer.
 */
static void
buf_append(ssize_t *sz, char *buf, size_t buflen, char *str,
    char *prepend, char *append)
{
	ssize_t left;

	if (str == NULL)
		return;

	if (buflen == 0 || (left = buflen - *sz) < 0)
		left = 0;

	if (buf != NULL && left != 0)
		buf += *sz;

	if (prepend == NULL && append == NULL)
		*sz += snprintf(buf, left, "%s", str);
	else if (prepend == NULL)
		*sz += snprintf(buf, left, "%s%s", str, append);
	else
		*sz += snprintf(buf, left, "%s%s%s", prepend, str, append);
}


ssize_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvlist_t **hcprs = NULL;
	nvlist_t *anvl = NULL;
	uint8_t version;
	ssize_t size = 0;
	uint_t hcnprs;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *serial = NULL;
	char *part = NULL;
	char *root = NULL;
	char *rev = NULL;
	int more_auth = 0;
	int err, i;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_HC_SCHEME_VERSION)
		return (-1);

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != ENOENT)
		return (-1);

	if ((err = nvlist_lookup_string(nvl, FM_FMRI_HC_ROOT, &root)) != 0)
		return (-1);

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	if (err != 0 || hcprs == NULL)
		return (-1);

	(void) nvlist_lookup_string(anvl, FM_FMRI_AUTH_PRODUCT, &aprod);
	(void) nvlist_lookup_string(anvl, FM_FMRI_AUTH_CHASSIS, &achas);
	(void) nvlist_lookup_string(anvl, FM_FMRI_AUTH_DOMAIN, &adom);
	(void) nvlist_lookup_string(anvl, FM_FMRI_AUTH_SERVER, &asrvr);
	if (aprod != NULL)
		more_auth++;
	if (achas != NULL)
		more_auth++;
	if (adom != NULL)
		more_auth++;
	if (asrvr != NULL)
		more_auth++;

	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_SERIAL_ID, &serial);
	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_PART, &part);
	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_REVISION, &rev);

	/* hc:// */
	buf_append(&size, buf, buflen, FM_FMRI_SCHEME_HC, NULL, "://");

	/* authority, if any */
	more_auth--;
	buf_append(&size, buf, buflen, aprod, FM_FMRI_AUTH_PRODUCT "=",
	    more_auth > 0 ? "," : NULL);
	more_auth--;
	buf_append(&size, buf, buflen, achas, FM_FMRI_AUTH_CHASSIS "=",
	    more_auth > 0 ? "," : NULL);
	more_auth--;
	buf_append(&size, buf, buflen, adom, FM_FMRI_AUTH_DOMAIN "=",
	    more_auth > 0 ? "," : NULL);
	more_auth--;
	buf_append(&size, buf, buflen, asrvr, FM_FMRI_AUTH_SERVER "=", NULL);

	/* separating slash */
	if (serial != NULL || part != NULL || rev != NULL)
		buf_append(&size, buf, buflen, "/", NULL, NULL);

	/* hardware-id part */
	buf_append(&size, buf, buflen, serial, ":" FM_FMRI_HC_SERIAL_ID "=",
	    NULL);
	buf_append(&size, buf, buflen, part, ":" FM_FMRI_HC_PART "=", NULL);
	buf_append(&size, buf, buflen, rev, ":" FM_FMRI_HC_REVISION "=", NULL);

	/* separating slash */
	buf_append(&size, buf, buflen, "/", NULL, NULL);

	/* hc-root */
	buf_append(&size, buf, buflen, root, NULL, NULL);

	/* all the pairs */
	for (i = 0; i < hcnprs; i++) {
		char *nm = NULL;
		char *id = NULL;

		if (i > 0)
			buf_append(&size, buf, buflen, "/", NULL, NULL);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_NAME, &nm);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_ID, &id);
		if (nm == NULL || id == NULL)
			return (-1);
		buf_append(&size, buf, buflen, nm, NULL, "=");
		buf_append(&size, buf, buflen, id, NULL, NULL);
	}

	return (size);
}

void
print_hc_fmri(nvlist_t *fmri)
{
	ssize_t len;
	char *pbuf;

	len = fmri_nvl2str(fmri, NULL, 0);
	if (len < 0 || (pbuf = malloc(len + 1)) == NULL)
		return;
	(void) fmri_nvl2str(fmri, pbuf, len + 1);
	(void) printf("%s\n", pbuf);
	free(pbuf);
}

void
print_tnode(tnode_t *node, void *arg)
{
	const char *propn, *propv;
	char *path;
	nvlist_t *asfmri;

	if (Everstyle) {
		path = topo_hc_path(node);
		(void) printf("%s\n", path);
		topo_free_path(path);
	} else {
		asfmri = topo_hc_fmri(node);
		print_hc_fmri(asfmri);
		topo_free_fmri(asfmri);
	}

	if ((int)arg == 0)
		return;

	propn = NULL;
	while ((propn = topo_next_prop(node, propn)) != NULL) {
		propv = topo_get_prop(node, propn);
		if (!Allprops && propn[0] == '.')
			continue;
		if (strchr(propv, ' ') != NULL || strchr(propv, '\t') != NULL)
			(void) printf("\t%s = \"%s\"\n", propn, propv);
		else
			(void) printf("\t%s = %s\n", propn, propv);
	}
}

void
main(int argc, char **argv)
{
	tnode_t *root, *node;
	char *Path = NULL;
	int Verbose = 0;
	int Debug = 0;
	int c;

	while ((c = getopt(argc, argv, ":adevp:")) != -1) {
		switch (c) {
		case 'a':
			Allprops++;
			Verbose++;
			break;
		case 'd':
			Debug++;
			break;
		case 'e':
			Everstyle++;
			break;
		case 'v':
			Verbose++;
			break;
		case 'p':
			Path = optarg;
			break;
		case ':':	/* path not included with the given -p */
			(void) fprintf(stderr, "Path option (-p) "
			    "requires accompanying hc path.\n");
			exit(1);
			/*NOTREACHED*/
		case '?':
		default:
			Usage(argv[0], optopt);
			/*NOTREACHED*/
		}
	}

	topo_set_out_method(print_buf);
	topo_init(0, NULL);

	if (Debug)
		topo_debug_on(0);

	root = topo_next_sibling(NULL, NULL);
	if (root == NULL) {
		(void) printf("No root of topo tree.\n");
		exit(5);
	}

	if (Path != NULL) {
		if ((node = topo_find_path(root, Path)) == NULL) {
			(void) fprintf(stderr,
			    "No node found for path %s.\n", Path);
			exit(2);
		} else {
			print_tnode(node, (void *)Verbose);
			exit(0);
		}
	}

	if (Debug)
		(void) printf("--------------------\n");

	topo_walk(root, TOPO_VISIT_SELF_FIRST, (void *)Verbose, print_tnode);
	topo_tree_release(root);
	topo_fini();
	exit(0);
}
