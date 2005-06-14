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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _XML_CONVERT_H
#define	_XML_CONVERT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libxml/parser.h>
#include "volume_request.h"
#include "volume_defaults.h"

/* The location of the volume-request.dtd */
#define	VOLUME_REQUEST_DTD_LOC	"/usr/share/lib/xml/dtd/volume-request.dtd"

/* The location of the volume-request-defaults.dtd */
#define	VOLUME_DEFAULTS_DTD_LOC	"/usr/share/lib/xml/dtd/volume-defaults.dtd"

/* The location of the volume-config.dtd */
#define	VOLUME_CONFIG_DTD_LOC	"/usr/share/lib/xml/dtd/volume-config.dtd"

/* Location of the volume-command.xsl file */
#define	VOLUME_COMMAND_XSL_LOC	"/usr/share/lib/xml/style/volume-command.xsl"

/*
 * Valid values for attributes
 */
#define	VALID_ATTR_TRUE			"TRUE"
#define	VALID_ATTR_FALSE		"FALSE"
#define	VALID_MIRROR_READ_GEOMETRIC	"GEOMETRIC"
#define	VALID_MIRROR_READ_FIRST		"FIRST"
#define	VALID_MIRROR_READ_ROUNDROBIN	"ROUNDROBIN"
#define	VALID_MIRROR_WRITE_SERIAL	"SERIAL"
#define	VALID_MIRROR_WRITE_PARALLEL	"PARALLEL"

/*
 * Standard units
 */
#define	UNIT_BLOCKS	"BLOCKS"
#define	UNIT_KILOBYTES	"KB"
#define	UNIT_MEGABYTES	"MB"
#define	UNIT_GIGABYTES	"GB"
#define	UNIT_TERABYTES	"TB"

/*
 * Initialize the XML parser, setting defaults across all XML
 * routines.
 */
extern void init_xml();

/*
 * Clean up any remaining structures before exiting.
 */
extern void cleanup_xml();

/*
 * Converts a volume-request XML document into a request_t.
 *
 * @param       doc
 *		an existing volume-request XML document
 *
 * @param       request
 *		RETURN: a new request_t which must be freed via
 *		free_request
 *
 * @return      0 on success, non-zero otherwise.
 */
extern int xml_to_request(xmlDocPtr doc, request_t **request);

/*
 * Converts a volume-defaults XML document into a defaults_t.
 *
 * @param       doc
 *		an existing volume-defaults XML document
 *
 * @param       defaults
 *		RETURN: a new defaults_t which must be freed via
 *		free_defaults
 *
 * @return      0 on success, non-zero otherwise.
 */
extern int xml_to_defaults(xmlDocPtr doc, defaults_t **defaults);

/*
 * Converts a volume-config XML document into a devconfig_t.
 *
 * @param       doc
 *		an existing volume-config XML document
 *
 * @param       config
 *		RETURN: a new devconfig_t which must be freed via
 *		free_devconfig
 *
 * @return      0 on success, non-zero otherwise.
 */
extern int xml_to_config(xmlDocPtr doc, devconfig_t **config);

/*
 * Converts a devconfig_t into a volume-config XML document.
 *
 * @param       config
 *		an existing devconfig_t representing a volume
 *		configuration.
 *
 * @param       doc
 *		RETURN: a new volume-config XML document which must be
 *		freed via xmlFreeDoc
 *
 * @return      0 on success, non-zero otherwise.
 */
extern int config_to_xml(devconfig_t *config, xmlDocPtr *doc);

/*
 * Converts a volume-config XML document into a Bourne shell script.
 *
 * @param       doc
 *		an existing volume-config XML document
 *
 * @param       commands
 *		RETURN: a new char* which must be freed
 *
 * @return      0 on success, non-zero otherwise.
 */
extern int xml_to_commands(xmlDocPtr doc, char **commands);

#ifdef __cplusplus
}
#endif

#endif /* _XML_CONVERT_H */
