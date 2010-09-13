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

#ifndef	_POOL_XML_IMPL_H
#define	_POOL_XML_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains the definitions of types and supporting
 * functions to implement the libpool XML specific data manipulation
 * facility.
 *
 * For more information on the libpool generic data manipulation
 * facility, look at pool_impl.h.
 *
 * The central types for the generic data representation/storage
 * facility are here enhanced to provide additional XML specific
 * information.
 */

/*
 * pool_xml_elem_t is the XML (to be precise, libxml - although this
 * could be easily ported to an alternative C-API xml library)
 * specific representation of the pool_elem_t structure.
 *
 * The pxe_node pointer is a pointer to an XML element which
 * represents the element in the XML document
 */
typedef struct pool_xml_elem {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pxe_elem;
	void *pxe_pad1;
	void *pxe_pad2;
	/*
	 * Common to pool_xml_elem_t
	 */
	xmlNodePtr pxe_node;				/* XML Element */
} pool_xml_elem_t;

typedef pool_xml_elem_t pool_xml_system_t;

typedef struct pool_xml_resource  {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pxe_elem;
	/*
	 * Specific to pool_resource_t
	 */
	int (*pr_is_system)(const pool_resource_t *);
	int (*pr_can_associate)(const pool_resource_t *);
	/*
	 * Common to pool_xml_elem_t
	 */
	xmlNodePtr pxe_node;				/* XML Element */
} pool_xml_resource_t;

typedef struct pool_xml_pool {
	/*
	 * Common to pool_elem_t
	 */
	pool_elem_t pxe_elem;
	/*
	 * Specific to pool_t
	 */
	int (*pp_associate)(pool_t *, const pool_resource_t *);
	int (*pp_dissociate)(pool_t *, const pool_resource_t *);
	/*
	 * Common to pool_xml_elem_t
	 */
	xmlNodePtr pxe_node;				/* XML Element */
} pool_xml_pool_t;

typedef pool_xml_elem_t pool_xml_component_t;

/*
 * pool_xml_result_set_t is the XML (to be precise, libxml - although
 * this could be easily ported to an alternative C-API xml library)
 * specific representation of the pool_result_set_t structure.
 *
 * The pxr_ctx member is a pointer to an XML XPath Context which
 * represents the context in which this result set is valid. AN
 * alternative way of thinking about this is to envisage the context
 * as the root of the search which is used to build the result set.
 *
 * The pxr_path member is a pointer to the compiled XPath statement
 * used to generate this result set.
 *
 * The prs_index member is a cursor into the result set and is used by
 * the various result set functions to determine which result set
 * member to access.
 *
 */
typedef struct pool_xml_result_set {
	const pool_conf_t *prs_conf;			/* Configuration */
	int prs_active;					/* Query active? */
	int prs_index;					/* Result Index */
	pool_elem_t *(*prs_next)(pool_result_set_t *);
	pool_elem_t *(*prs_prev)(pool_result_set_t *);
	pool_elem_t *(*prs_first)(pool_result_set_t *);
	pool_elem_t *(*prs_last)(pool_result_set_t *);
	int (*prs_set_index)(pool_result_set_t *, int);
	int (*prs_get_index)(pool_result_set_t *);
	int (*prs_close)(pool_result_set_t *);
	int (*prs_count)(pool_result_set_t *);
	/*
	 * End of common part
	 */
	xmlXPathContextPtr pxr_ctx;			/* Result Context */
	xmlXPathObjectPtr pxr_path;			/* Result Path Object */
} pool_xml_result_set_t;

/*
 * pool_xml_connection_t is the XML (to be precise, libxml - although
 * this could be easily ported to an alternative C-API xml library)
 * specific representation of the pool_result_set_t structure.
 *
 * The pxc_doc member is a pointer to an XML document structure which
 * contains information about the XML document which acts as the data
 * store for this connection.
 *
 * The pxc_file member is a FILE pointer to the data file used to
 * store the XML document.
 *
 * The pxc_oflags member is the OR'd list of options specified when
 * opening this connection.
 *
 * The pxc_cleanup member is a boolean flag indicating whether a
 * configuration has a backup which needs to be cleaned up. This is
 * used as a means of providing resilient configuration changes in the
 * face of potential failure.
 *
 */
typedef struct pool_xml_connection {
	const char *pc_name;				/* Provider name */
	int pc_store_type;				/* Datastore type */
	int pc_oflags;					/* Open flags */
	int (*pc_close)(pool_conf_t *);
	int (*pc_validate)(const pool_conf_t *, pool_valid_level_t);
	int (*pc_commit)(pool_conf_t *);
	int (*pc_export)(const pool_conf_t *, const char *,
	    pool_export_format_t);
	int (*pc_rollback)(pool_conf_t *);
	pool_result_set_t *(*pc_exec_query)(const pool_conf_t *,
	    const pool_elem_t *, const char *,
	    pool_elem_class_t, pool_value_t **);
	pool_elem_t *(*pc_elem_create)(pool_conf_t *, pool_elem_class_t,
	    pool_resource_elem_class_t, pool_component_elem_class_t);
	int (*pc_remove)(pool_conf_t *);
	int (*pc_res_xfer)(pool_resource_t *, pool_resource_t *, uint64_t);
	int (*pc_res_xxfer)(pool_resource_t *, pool_resource_t *,
	    pool_component_t **);
	char *(*pc_get_binding)(pool_conf_t *, pid_t);
	int (*pc_set_binding)(pool_conf_t *, const char *, idtype_t, id_t);
	char *(*pc_get_resource_binding)(pool_conf_t *,
	    pool_resource_elem_class_t, pid_t);
	/*
	 * End of common part
	 */
	xmlDocPtr pxc_doc;				/* XML document */
	FILE *pxc_file;					/* XML File */
} pool_xml_connection_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _POOL_XML_IMPL_H */
