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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <fm/libtopo.h>
#include <sys/fm/util.h>

#include <libxml/xpathInternals.h>

#include "fabric-xlate.h"

#define	XMLTOPOFILE "/tmp/fab-xlate-topo.xml"

fmd_xprt_t *fab_fmd_xprt;	/* FMD transport layer handle */
char fab_buf[FM_MAX_CLASS];

/* Static FM Topo XML Format and XML XPath Context  */
static xmlDocPtr	fab_doc = NULL;
xmlXPathContextPtr	fab_xpathCtx = NULL;
static int		fab_valid_topo = 0;

static void
fab_update_topo(fmd_hdl_t *hdl)
{
	topo_hdl_t	*thp = NULL;
	FILE		*fp;
	int		err = 0;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL) {
		fmd_hdl_debug(hdl, "Failed to hold topo\n");
	}

	fp = fopen(XMLTOPOFILE, "w");

	if (topo_xml_print(thp, fp, FM_FMRI_SCHEME_HC, &err) < 0) {
		fmd_hdl_debug(hdl, "Failed to get XML topo\n");
	}

	(void) fclose(fp);

	fmd_hdl_topo_rele(hdl, thp);

	if (fab_xpathCtx)
		xmlXPathFreeContext(fab_xpathCtx);
	if (fab_doc)
		xmlFreeDoc(fab_doc);

	/* Load xml document */
	fab_doc = xmlParseFile(XMLTOPOFILE);

	/* Init xpath */
	fab_xpathCtx = xmlXPathNewContext(fab_doc);

	fab_set_fake_rp(hdl);

	fab_valid_topo = 1;
}

/*ARGSUSED*/
static void
fab_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	nvlist_t *new_nvl;

	if (!fab_valid_topo)
		fab_update_topo(hdl);

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
	fab_valid_topo = 0;
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
