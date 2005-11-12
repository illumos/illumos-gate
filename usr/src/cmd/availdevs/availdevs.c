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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "availdevs.h"
#include <libzfs_jni_diskmgt.h>
#include <libzfs_jni_ipool.h>
#include <libxml/parser.h>

/*
 * Function prototypes
 */

static void handle_error(const char *, va_list);
static int add_disk_to_xml(dmgt_disk_t *, void *);
static int add_pool_to_xml(char *, uint64_t, uint64_t, char *, void *);
static xmlDocPtr create_doc();
int main();

/*
 * Static functions
 */

static void
handle_error(const char *fmt, va_list ap)
{
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
}

static int
add_disk_to_xml(dmgt_disk_t *dp, void *data)
{
	int i;
	char tmp[64];
	xmlNodePtr available = *((xmlNodePtr *)data);

	xmlNodePtr disk = xmlNewChild(
	    available, NULL, (xmlChar *)ELEMENT_DISK, NULL);
	xmlSetProp(disk,
	    (xmlChar *)ATTR_DISK_NAME, (xmlChar *)dp->name);
	snprintf(tmp, sizeof (tmp), "%llu", dp->size);
	xmlSetProp(disk, (xmlChar *)ATTR_DISK_SIZE, (xmlChar *)tmp);

	if (dp->aliases != NULL) {
		for (i = 0; dp->aliases[i] != NULL; i++) {
			xmlNodePtr alias = xmlNewChild(
			    disk, NULL, (xmlChar *)ELEMENT_ALIAS, NULL);
			xmlSetProp(alias,
			    (xmlChar *)ATTR_ALIAS_NAME,
			    (xmlChar *)dp->aliases[i]);
		}
	}

	if (dp->slices != NULL) {
		for (i = 0; dp->slices[i] != NULL; i++) {
			dmgt_slice_t *sp = dp->slices[i];
			xmlNodePtr slice = xmlNewChild(
			    disk, NULL, (xmlChar *)ELEMENT_SLICE, NULL);
			xmlSetProp(slice,
			    (xmlChar *)ATTR_SLICE_NAME, (xmlChar *)sp->name);

			snprintf(tmp, sizeof (tmp), "%llu", sp->size);
			xmlSetProp(slice, (xmlChar *)ATTR_SLICE_SIZE,
			    (xmlChar *)tmp);

			snprintf(tmp, sizeof (tmp), "%llu", sp->start);
			xmlSetProp(slice, (xmlChar *)ATTR_SLICE_START,
			    (xmlChar *)tmp);

			if (sp->used_name != NULL) {
				xmlSetProp(slice,
				    (xmlChar *)ATTR_SLICE_USED_NAME,
				    (xmlChar *)sp->used_name);
			}

			if (sp->used_by != NULL) {
				xmlSetProp(slice, (xmlChar *)ATTR_SLICE_USED_BY,
				    (xmlChar *)sp->used_by);
			}
		}
	}

	return (0);
}

static int
add_pool_to_xml(char *name, uint64_t guid,
    uint64_t pool_state, char *health, void *data)
{
	char *state;
	char tmp[64];
	xmlNodePtr importable = *((xmlNodePtr *)data);

	xmlNodePtr pool = xmlNewChild(
	    importable, NULL, (xmlChar *)ELEMENT_POOL, NULL);
	xmlSetProp(pool, (xmlChar *)ATTR_POOL_NAME, (xmlChar *)name);

	state = zjni_get_state_str(pool_state);
	if (state == NULL) {
		state = "";
	}
	xmlSetProp(pool, (xmlChar *)ATTR_POOL_STATE, (xmlChar *)state);
	xmlSetProp(pool, (xmlChar *)ATTR_POOL_HEALTH, (xmlChar *)health);

	snprintf(tmp, sizeof (tmp), "%llu", guid);
	xmlSetProp(pool, (xmlChar *)ATTR_POOL_ID, (xmlChar *)tmp);

	return (0);
}

static xmlDocPtr
create_doc(void)
{
	/* Create the XML document */
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");

	/* Create the root node */
	xmlNodePtr root = xmlNewDocNode(
	    doc, NULL, (xmlChar *)ELEMENT_ROOT, NULL);
	xmlAddChild((xmlNodePtr) doc, (xmlNodePtr)root);

	return (doc);
}

/*
 * Main entry to availdisks.
 *
 * @return      0 on successful exit, non-zero otherwise
 */
int
main(int argc, char **argv)
{
	int error = 0;
	int get_pools = 0;
	int get_devices = 0;

	/* Examine first arg */
	int c = getopt(argc, argv, CLI_OPTSTRING);
	switch (c) {
		case CLI_ARG_ALL:
			get_devices = 1;
			get_pools = 1;
			break;

		case CLI_ARG_DEVICES:
			get_devices = 1;
			break;

		case CLI_ARG_POOLS:
			get_pools = 1;
			break;

		default:
			return (1);
			break;
	}

	argc -= optind;
	argv += optind;

	if (get_pools || get_devices) {
		xmlDocPtr doc = create_doc();
		xmlNodePtr root = xmlDocGetRootElement(doc);

		if (get_devices) {
			/* Create the available node */
			xmlNodePtr available = xmlNewChild(root, NULL,
			    (xmlChar *)ELEMENT_AVAILABLE, NULL);

			/* libzfs_jni_diskmgt.o error handler */
			dmgt_set_error_handler(handle_error);

			error = dmgt_avail_disk_iter(
			    add_disk_to_xml, &available);
		}

		if (get_pools && !error) {
			/* Create the importable node */
			xmlNodePtr importable = xmlNewChild(root, NULL,
			    (xmlChar *)ELEMENT_IMPORTABLE, NULL);

			error = zjni_ipool_iter(
			    argc, argv, add_pool_to_xml, &importable);
		}

		if (!error) {
			/* Print out XML */
			xmlDocFormatDump(stdout, doc, 1);
		}

		xmlFreeDoc(doc);
	}

	return (error != 0);
}
