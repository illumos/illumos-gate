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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <fm/libtopo.h>
#include <sys/fm/util.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpathInternals.h>

#include "fabric-xlate.h"

#define	XMLTOPOFILE "/var/run/fab-xlate-topo.xml"

fmd_xprt_t *fab_fmd_xprt;	/* FMD transport layer handle */
char fab_buf[FM_MAX_CLASS];

/* Static FM Topo XML Format and XML XPath Context  */
static xmlDocPtr	fab_doc = NULL;
xmlXPathContextPtr	fab_xpathCtx = NULL;
static int		fab_valid_topo = 0;
static pthread_mutex_t	fab_lock = PTHREAD_MUTEX_INITIALIZER;

static void
fab_update_topo(fmd_hdl_t *hdl)
{
	topo_hdl_t	*thp = NULL;
	FILE		*fp = NULL;
	int		err = 0;
	int		fd = -1;

	/* Open the temporary file with proper ownership */
	while (fd == -1) {
		if ((unlink(XMLTOPOFILE) == -1) && (errno != ENOENT)) {
			fmd_hdl_debug(hdl, "Failed to remove XML topo file\n");
			return;
		}
		fd = open(XMLTOPOFILE, O_RDWR | O_CREAT | O_EXCL, 0600);
		if ((fd == -1) && (errno != EEXIST)) {
			fmd_hdl_debug(hdl, "Failed to create XML topo file\n");
			return;
		}
	}

	/* Associate a stream with the temporary file */
	if ((fp = fdopen(fd, "w")) == NULL) {
		fmd_hdl_debug(hdl, "Failed to open XML topo file\n");
		goto cleanup;
	}

	/* Hold topology */
	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL) {
		fmd_hdl_debug(hdl, "Failed to hold topo\n");
		goto cleanup;
	}

	/* Print topology to XML file */
	if (topo_xml_print(thp, fp, FM_FMRI_SCHEME_HC, &err) < 0) {
		fmd_hdl_debug(hdl, "Failed to get XML topo\n");
		fmd_hdl_topo_rele(hdl, thp);
		goto cleanup;
	}

	/* Release topology */
	fmd_hdl_topo_rele(hdl, thp);

	/* Reload topology from XML file */
	if (fab_xpathCtx)
		xmlXPathFreeContext(fab_xpathCtx);
	if (fab_doc)
		xmlFreeDoc(fab_doc);
	fab_doc = xmlParseFile(XMLTOPOFILE);
	fab_xpathCtx = xmlXPathNewContext(fab_doc);
	fab_set_fake_rp(hdl);
	fab_valid_topo = 1;

cleanup:
	if (fp != NULL)
		(void) fclose(fp);
	else if (fd != -1)
		(void) close(fd);
	(void) unlink(XMLTOPOFILE);
}

/*ARGSUSED*/
static void
fab_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	nvlist_t *new_nvl;

	(void) pthread_mutex_lock(&fab_lock);
	if (!fab_valid_topo)
		fab_update_topo(hdl);
	(void) pthread_mutex_unlock(&fab_lock);

	if (nvlist_dup(nvl, &new_nvl, NV_UNIQUE_NAME) != 0) {
		fmd_hdl_error(hdl, "failed to duplicate event");
		return;
	}

	if (fmd_nvl_class_match(hdl, new_nvl, "ereport.io.pci.fabric")) {
		fab_xlate_fabric_erpts(hdl, new_nvl, class);
	} else {
		fab_pr(hdl, ep, new_nvl);
		if (fmd_nvl_class_match(hdl, new_nvl,
		    "ereport.io.pciex.rc.epkt")) {
			fab_xlate_epkt_erpts(hdl, new_nvl, class);
		} else {
			fab_xlate_fire_erpts(hdl, new_nvl, class);
		}
	}

	nvlist_free(new_nvl);
}

/* ARGSUSED */
static void
fab_topo(fmd_hdl_t *hdl, topo_hdl_t *topo)
{
	(void) pthread_mutex_lock(&fab_lock);
	fab_valid_topo = 0;
	(void) pthread_mutex_unlock(&fab_lock);
}

static const fmd_hdl_ops_t fmd_ops = {
	fab_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	fab_topo,	/* fmdo_topo */
};

static const fmd_hdl_info_t fmd_info = {
	"Fabric Ereport Translater", "1.0", &fmd_ops, NULL
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	/* Init libxml */
	xmlInitParser();

	fab_fmd_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	fmd_hdl_debug(hdl, "Fabric Translater Started\n");

	fab_setup_master_table();
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	/* Fini xpath */
	if (fab_xpathCtx)
		xmlXPathFreeContext(fab_xpathCtx);
	/* Free xml document */
	if (fab_doc)
		xmlFreeDoc(fab_doc);
	/* Fini libxml */
	xmlCleanupParser();

	fmd_xprt_close(hdl, fab_fmd_xprt);
}
