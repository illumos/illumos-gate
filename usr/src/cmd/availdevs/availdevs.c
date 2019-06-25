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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include "availdevs.h"
#include <libzfs.h>
#include <libzfs_jni_diskmgt.h>
#include <libzfs_jni_ipool.h>
#include <libxml/parser.h>

/*
 * Function prototypes
 */

static void handle_error(const char *, va_list);
static void set_uint64_prop(xmlNodePtr, const char *, uint64_t);
static int add_disk_to_xml(dmgt_disk_t *, void *);
static int add_pool_to_xml(nvlist_t *, void *);
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

static void
set_uint64_prop(xmlNodePtr node, const char *attr, uint64_t value)
{
	static char tmp[64];
	(void) snprintf(tmp, sizeof (tmp), "%llu", value);
	(void) xmlSetProp(node, (xmlChar *)attr, (xmlChar *)tmp);
}

static int
add_disk_to_xml(dmgt_disk_t *dp, void *data)
{
	int i;
	xmlNodePtr available = *((xmlNodePtr *)data);

	xmlNodePtr disk = xmlNewChild(
	    available, NULL, (xmlChar *)ELEMENT_DISK, NULL);
	(void) xmlSetProp(disk,
	    (xmlChar *)ATTR_DISK_NAME, (xmlChar *)dp->name);

	set_uint64_prop(disk, ATTR_DISK_SIZE, dp->size);

	(void) xmlSetProp(disk, (xmlChar *)ATTR_DISK_INUSE, (xmlChar *)
	    (dp->in_use ? VAL_ATTR_TRUE : VAL_ATTR_FALSE));

	if (dp->aliases != NULL) {
		for (i = 0; dp->aliases[i] != NULL; i++) {
			xmlNodePtr alias = xmlNewChild(
			    disk, NULL, (xmlChar *)ELEMENT_ALIAS, NULL);
			(void) xmlSetProp(alias,
			    (xmlChar *)ATTR_ALIAS_NAME,
			    (xmlChar *)dp->aliases[i]);
		}
	}

	if (dp->slices != NULL) {
		for (i = 0; dp->slices[i] != NULL; i++) {
			dmgt_slice_t *sp = dp->slices[i];
			xmlNodePtr slice = xmlNewChild(
			    disk, NULL, (xmlChar *)ELEMENT_SLICE, NULL);
			(void) xmlSetProp(slice,
			    (xmlChar *)ATTR_SLICE_NAME, (xmlChar *)sp->name);

			set_uint64_prop(slice, ATTR_SLICE_SIZE, sp->size);
			set_uint64_prop(slice, ATTR_SLICE_START, sp->start);

			if (sp->used_name != NULL) {
				(void) xmlSetProp(slice,
				    (xmlChar *)ATTR_SLICE_USED_NAME,
				    (xmlChar *)sp->used_name);
			}

			if (sp->used_by != NULL) {
				(void) xmlSetProp(slice,
				    (xmlChar *)ATTR_SLICE_USED_BY,
				    (xmlChar *)sp->used_by);
			}
		}
	}

	return (0);
}

static int
add_pool_to_xml(nvlist_t *config, void *data)
{
	char *c;
	char *name;
	uint64_t guid;
	uint64_t version;
	uint64_t state;
	nvlist_t *devices;
	uint_t n;
	vdev_stat_t *vs;
	xmlNodePtr pool;
	xmlNodePtr importable = *((xmlNodePtr *)data);

	if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_VERSION, &version) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE, &state) ||
	    nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &devices) ||
	    nvlist_lookup_uint64_array(
	    devices, ZPOOL_CONFIG_VDEV_STATS, (uint64_t **)&vs, &n)) {
		return (-1);
	}

	pool = xmlNewChild(importable, NULL, (xmlChar *)ELEMENT_POOL, NULL);
	(void) xmlSetProp(pool, (xmlChar *)ATTR_POOL_NAME, (xmlChar *)name);

	set_uint64_prop(pool, ATTR_POOL_ID, guid);
	set_uint64_prop(pool, ATTR_POOL_VERSION, version);
	set_uint64_prop(pool, ATTR_POOL_USED, vs->vs_alloc);
	set_uint64_prop(pool, ATTR_POOL_SIZE, vs->vs_space);
	set_uint64_prop(pool, ATTR_POOL_REPLACEMENT_SIZE, vs->vs_rsize);
	set_uint64_prop(pool, ATTR_POOL_READ_BYTES,
	    vs->vs_bytes[ZIO_TYPE_READ]);
	set_uint64_prop(pool, ATTR_POOL_WRITE_BYTES,
	    vs->vs_bytes[ZIO_TYPE_WRITE]);
	set_uint64_prop(pool, ATTR_POOL_READ_OPERATIONS,
	    vs->vs_ops[ZIO_TYPE_READ]);
	set_uint64_prop(pool, ATTR_POOL_WRITE_OPERATIONS,
	    vs->vs_ops[ZIO_TYPE_WRITE]);
	set_uint64_prop(pool, ATTR_POOL_READ_ERRORS, vs->vs_read_errors);
	set_uint64_prop(pool, ATTR_POOL_WRITE_ERRORS, vs->vs_write_errors);
	set_uint64_prop(pool, ATTR_POOL_CHECKSUM_ERRORS,
	    vs->vs_checksum_errors);

	(void) xmlSetProp(pool, (xmlChar *)ATTR_DEVICE_STATE,
	    (xmlChar *)zjni_vdev_state_to_str(vs->vs_state));

	(void) xmlSetProp(pool, (xmlChar *)ATTR_DEVICE_STATUS,
	    (xmlChar *)zjni_vdev_aux_to_str(vs->vs_aux));

	(void) xmlSetProp(pool, (xmlChar *)ATTR_POOL_STATE,
	    (xmlChar *)zjni_pool_state_to_str(state));

	(void) xmlSetProp(pool, (xmlChar *)ATTR_POOL_STATUS, (xmlChar *)
	    zjni_pool_status_to_str(zpool_import_status(config, &c, NULL)));

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
	(void) xmlAddChild((xmlNodePtr) doc, (xmlNodePtr)root);

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
			(void) xmlDocFormatDump(stdout, doc, 1);
		}

		xmlFreeDoc(doc);
	}

	return (error != 0);
}
