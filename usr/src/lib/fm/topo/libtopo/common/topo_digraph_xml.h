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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _TOPO_DIGRAPH_XML_H
#define	_TOPO_DIGRAPH_XML_H

#include <fm/topo_mod.h>

#include <topo_list.h>
#include <topo_prop.h>
#include <topo_method.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_module.h>
#include <topo_string.h>
#include <topo_subr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TDG_DTD		"/usr/share/lib/xml/dtd/digraph-topology.dtd.1"

/*
 * List of attribute names and values used when serializing a topo_digraph_t
 * to XML.
 *
 * When deserializing an XML representation of a topo_digraph_t, the XML is
 * first converted to an nvlist representation and then that nvlist is
 * processed to produce a topo_digraph_t.  These property names are also
 * used as the nvpair names in that intermediate nvlist.
 */
#define	TDG_XML_EDGE		"edge"
#define	TDG_XML_FMRI		"fmri"
#define	TDG_XML_SCHEME		"fmri-scheme"
#define	TDG_XML_NAME		"name"
#define	TDG_XML_NVLIST		"nvlist"
#define	TDG_XML_NVLIST_ARR	"nvlist-array"
#define	TDG_XML_NVPAIR		"nvpair"
#define	TDG_XML_INSTANCE	"instance"
#define	TDG_XML_INT8		"int8"
#define	TDG_XML_INT16		"int16"
#define	TDG_XML_INT32		"int32"
#define	TDG_XML_INT32_ARR	"int32-array"
#define	TDG_XML_INT64		"int64"
#define	TDG_XML_INT64_ARR	"int64-array"
#define	TDG_XML_OSVERSION	"os-version"
#define	TDG_XML_NODENAME	"nodename"
#define	TDG_XML_PGROUPS		"property-groups"
#define	TDG_XML_PGROUP_NAME	"property-group-name"
#define	TDG_XML_PRODUCT		"product-id"
#define	TDG_XML_PROP_NAME	TOPO_PROP_VAL_NAME
#define	TDG_XML_PROP_TYPE	TOPO_PROP_VAL_TYPE
#define	TDG_XML_PROP_VALUE	TOPO_PROP_VAL_VAL
#define	TDG_XML_PVALS		"property-values"
#define	TDG_XML_OUTEDGES	"outgoing-edges"
#define	TDG_XML_STRING		"string"
#define	TDG_XML_STRING_ARR	"string-array"
#define	TDG_XML_TOPO_DIGRAPH	"topo-digraph"
#define	TDG_XML_TSTAMP		"timestamp"
#define	TDG_XML_TYPE		"type"
#define	TDG_XML_UINT8		"uint8"
#define	TDG_XML_UINT16		"uint16"
#define	TDG_XML_UINT32		"uint32"
#define	TDG_XML_UINT32_ARR	"uint32-array"
#define	TDG_XML_UINT64		"uint64"
#define	TDG_XML_UINT64_ARR	"uint64-array"
#define	TDG_XML_VALUE		"value"
#define	TDG_XML_VERTEX		"vertex"
#define	TDG_XML_VERTICES	"vertices"

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_DIGRAPH_XML_H */
