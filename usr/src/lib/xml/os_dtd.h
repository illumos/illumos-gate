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

#ifndef _OS_DTD_H
#define	_OS_DTD_H

/*
 * Utility functions for working with XML documents that are validated against
 * Document Type Definitions (DTD) shipped in the operating system.
 */

#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum os_dtd_id {
	OS_DTD_UNKNOWN = 0,
	OS_DTD_ZONES_BRAND,
	OS_DTD_ZONES_ZONE,
	OS_DTD_ZONES_PLATFORM,
	OS_DTD_SMF_SERVICE_BUNDLE
} os_dtd_id_t;

typedef struct os_dtd_path os_dtd_path_t;

extern os_dtd_id_t os_dtd_identify(xmlDocPtr);
extern int os_dtd_attach(xmlDocPtr, os_dtd_id_t);
extern int os_dtd_validate(xmlDocPtr, boolean_t, boolean_t *);

#ifdef __cplusplus
}
#endif

#endif /* _OS_DTD_H */
