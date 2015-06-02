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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Utility functions for working with XML documents that are validated against
 * Document Type Definitions (DTD) shipped in the operating system.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <zone.h>

#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

#include "os_dtd.h"

struct os_dtd_path {
	os_dtd_id_t odp_id;
	const char *odp_name;
	const char *odp_public_ident;
	const char *odp_path;
};

static os_dtd_path_t os_dtd_paths[] = {
	/*
	 * DTDs for Zones infrastructure:
	 */
	{ OS_DTD_ZONES_BRAND, "brand",
	    "-//Sun Microsystems Inc//DTD Brands//EN",
	    "/usr/share/lib/xml/dtd/brand.dtd.1" },
	{ OS_DTD_ZONES_ZONE, "zone",
	    "-//Sun Microsystems Inc//DTD Zones//EN",
	    "/usr/share/lib/xml/dtd/zonecfg.dtd.1" },
	{ OS_DTD_ZONES_PLATFORM, "platform",
	    "-//Sun Microsystems Inc//Zones Platform//EN",
	    "/usr/share/lib/xml/dtd/zone_platform.dtd.1" },

	/*
	 * DTDs for smf(5):
	 */
	{ OS_DTD_SMF_SERVICE_BUNDLE, "service_bundle",
	    NULL,
	    "/usr/share/lib/xml/dtd/service_bundle.dtd.1" },

	{ OS_DTD_UNKNOWN, NULL, NULL, NULL }
};

/*
 * Check this document to see if it references the public identifier of a
 * well-known DTD that we ship with the operating system.  If there is no DTD,
 * or the public identifier is unknown to us, return OS_DTD_UNKNOWN.
 */
os_dtd_id_t
os_dtd_identify(xmlDocPtr doc)
{
	xmlDtdPtr dp;
	int i;

	if ((dp = xmlGetIntSubset(doc)) == NULL) {
		/*
		 * This document does not have an internal subset pointing
		 * to a DTD.
		 */
		errno = EIO;
		return (OS_DTD_UNKNOWN);
	}

	/*
	 * The use of a symbolic name via the public identifier is preferred.
	 * Check to see if the document refers to a public identifier for any
	 * well-known DTD:
	 */
	for (i = 0; os_dtd_paths[i].odp_id != OS_DTD_UNKNOWN; i++) {
		os_dtd_path_t *odp = &os_dtd_paths[i];
		const xmlChar *pubid = (const xmlChar *)odp->odp_public_ident;

		if (dp->ExternalID == NULL || odp->odp_public_ident == NULL) {
			continue;
		}

		if (xmlStrEqual(pubid, dp->ExternalID)) {
			return (odp->odp_id);
		}
	}

	/*
	 * If a public identifier is not present, or does not match any known
	 * DTD, fall back to inspecting the system identifier.
	 */
	for (i = 0; os_dtd_paths[i].odp_id != OS_DTD_UNKNOWN; i++) {
		os_dtd_path_t *odp = &os_dtd_paths[i];
		char uri[sizeof ("file://") + MAXPATHLEN];
		const xmlChar *path = (const xmlChar *)odp->odp_path;

		if (dp->SystemID == NULL || odp->odp_path == NULL) {
			continue;
		}

		/*
		 * The system identifier may be a regular path.
		 */
		if (xmlStrEqual(path, dp->SystemID)) {
			return (odp->odp_id);
		}

		/*
		 * The system identifier may also be a "file://"
		 * URI referring to a path:
		 */
		(void) snprintf(uri, sizeof (uri), "file://%s", odp->odp_path);
		if (xmlStrEqual((const xmlChar *)uri, dp->SystemID)) {
			return (odp->odp_id);
		}
	}

	errno = ENOENT;
	return (OS_DTD_UNKNOWN);
}

static os_dtd_path_t *
os_dtd_lookup(os_dtd_id_t id)
{
	int i;

	for (i = 0; os_dtd_paths[i].odp_id != OS_DTD_UNKNOWN; i++) {
		os_dtd_path_t *odp = &os_dtd_paths[i];

		if (odp->odp_id == id) {
			return (odp);
		}
	}

	errno = ENOENT;
	return (NULL);
}

/*
 * If this document references a DTD, remove that reference (the "internal
 * subset").  Install a new internal subset reference to the well-known
 * operating system DTD passed by the caller.  The URI in this reference will
 * respect the current native system prefix (e.g. "/native") if there is one,
 * such as when running in a branded zone.
 */
int
os_dtd_attach(xmlDocPtr doc, os_dtd_id_t id)
{
	xmlDtdPtr dp;
	os_dtd_path_t *odp;
	const char *zroot = zone_get_nroot();
	char uri[sizeof ("file://") + MAXPATHLEN];

	if ((odp = os_dtd_lookup(id)) == NULL) {
		return (-1);
	}

	if ((dp = xmlGetIntSubset(doc)) != NULL) {
		/*
		 * This document already has an internal subset.  Remove it
		 * before attaching the new one.
		 */
		xmlUnlinkNode((xmlNodePtr)dp);
		xmlFreeNode((xmlNodePtr)dp);
	}

	/*
	 * The "system identifier" of this internal subset must refer to the
	 * path in the filesystem where the DTD file (the external subset) is
	 * stored.  If we are running in a branded zone, that file may be at a
	 * different path (e.g. under "/native").
	 */
	(void) snprintf(uri, sizeof (uri), "file://%s%s", zroot != NULL ?
	    zroot : "", odp->odp_path);

	if (xmlCreateIntSubset(doc, (const xmlChar *)odp->odp_name,
	    (const xmlChar *)odp->odp_public_ident,
	    (const xmlChar *)uri) == NULL) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static void
os_dtd_print_nothing(void *ctx, const char *msg, ...)
{
}

int
os_dtd_validate(xmlDocPtr doc, boolean_t emit_messages, boolean_t *valid)
{
	int ret;
	xmlValidCtxtPtr cvp;
	os_dtd_id_t dtdid;

	if ((dtdid = os_dtd_identify(doc)) != OS_DTD_UNKNOWN) {
		/*
		 * This document refers to a well-known DTD shipped with
		 * the operating system.  Ensure that it points to the
		 * correct local path for validation in the current context.
		 */
		if (os_dtd_attach(doc, dtdid) != 0) {
			return (-1);
		}
	}

	if ((cvp = xmlNewValidCtxt()) == NULL) {
		return (-1);
	}

	if (!emit_messages) {
		cvp->error = os_dtd_print_nothing;
		cvp->warning = os_dtd_print_nothing;
	}

	ret = xmlValidateDocument(cvp, doc);
	xmlFreeValidCtxt(cvp);

	*valid = (ret == 1 ? B_TRUE : B_FALSE);
	return (0);
}
