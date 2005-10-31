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
#include <libxml/parser.h>

/*
 * Function prototypes
 */

static void handle_error(const char *, va_list);
static int add_disk_to_xml(dmgt_disk_t *, void *);
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
	int i, n;
	char tmp[64];
	xmlNodePtr available = *((xmlNodePtr *)data);

	xmlNodePtr disk = xmlNewChild(
	    available, NULL, (xmlChar *)ELEMENT_DISK, NULL);
	xmlSetProp(disk,
	    (xmlChar *)ATTR_DISK_NAME, (xmlChar *)dp->name);
	n = snprintf(tmp, sizeof (tmp) - 1, "%llu", dp->size);
	tmp[n] = '\0';
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

			n = snprintf(tmp, sizeof (tmp) - 1, "%llu", sp->size);
			tmp[n] = '\0';
			xmlSetProp(slice, (xmlChar *)ATTR_SLICE_SIZE,
			    (xmlChar *)tmp);

			n = snprintf(tmp, sizeof (tmp) - 1, "%llu", sp->start);
			tmp[n] = '\0';
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

static xmlDocPtr
create_doc(void)
{
	/* Create the XML document */
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");

	/* Create the root node */
	xmlNodePtr root = xmlNewDocNode(
	    doc, NULL, (xmlChar *)ELEMENT_ROOT, NULL);
	xmlAddChild((xmlNodePtr) doc, (xmlNodePtr)root);

	/* Create the available node */
	xmlNewChild(root, NULL, (xmlChar *)ELEMENT_AVAILABLE, NULL);

	return (doc);
}

/*
 * Main entry to availdisks.
 *
 * @return      0 on successful exit, non-zero otherwise
 */
int
main(void)
{
	int error;
	xmlDocPtr doc;
	xmlNodePtr root;
	xmlNodePtr available;

	/* diskmgt.o error handler */
	dmgt_set_error_handler(handle_error);

	doc = create_doc();
	root = xmlDocGetRootElement(doc);
	available = xmlGetLastChild(root);

	error = dmgt_avail_disk_iter(add_disk_to_xml, &available);
	if (!error) {
		/* Print out XML */
		xmlDocFormatDump(stdout, doc, 1);
	}

	xmlFreeDoc(doc);

	return (error != 0);
}
