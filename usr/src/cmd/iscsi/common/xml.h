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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TARGET_XML_H
#define	_TARGET_XML_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <libxml/xmlreader.h>

#include "local_types.h"

/*
 * XML element defines.
 */
#define	XML_ELEMENT_ERROR	"error"
#define	XML_ELEMENT_CODE	"code"
#define	XML_ELEMENT_MESSAGE	"message"
#define	XML_ELEMENT_TRANSVERS	"transport-version"
#define	XML_ELEMENT_PROPS	"props"
#define	XML_ELEMENT_DATAOUT	"data-out-size"
#define	XML_ELEMENT_BASEDIR	"base-directory"
#define	XML_ELEMENT_CHAPSECRET	"chap-secret"
#define	XML_ELEMENT_CHAPNAME	"chap-name"
#define	XML_ELEMENT_RAD_ACCESS	"radius-access"
#define	XML_ELEMENT_RAD_SERV	"radius-server"
#define	XML_ELEMENT_RAD_SECRET	"radius-secret"
#define	XML_ELEMENT_ISNS_ACCESS	"isns-access"
#define	XML_ELEMENT_FAST	"fast-write-ack"
#define	XML_ELEMENT_NAME	"name"
#define	XML_ELEMENT_ACL		"acl"
#define	XML_ELEMENT_ACLLIST	"acl-list"
#define	XML_ELEMENT_TPGT	"tpgt"
#define	XML_ELEMENT_TPGTLIST	"tpgt-list"
#define	XML_ELEMENT_SIZE	"size"
#define	XML_ELEMENT_LUN		"lun"
#define	XML_ELEMENT_LUNLIST	"lun-list"
#define	XML_ELEMENT_TYPE	"type"
#define	XML_ELEMENT_ALIAS	"alias"
#define	XML_ELEMENT_BACK	"backing-store"
#define	XML_ELEMENT_DELETE_BACK	"delete-backing-store"
#define	XML_ELEMENT_TARG	"target"
#define	XML_ELEMENT_INIT	"initiator"
#define	XML_ELEMENT_ADMIN	"admin"
#define	XML_ELEMENT_INAME	"iscsi-name"
#define	XML_ELEMENT_MAXRECV	"maxrecv"
#define	XML_ELEMENT_IPADDR	"ip-address"
#define	XML_ELEMENT_ALL		"all"
#define	XML_ELEMENT_VERBOSE	"verbose"
#define	XML_ELEMENT_LIST	"list"
#define	XML_ELEMENT_RESULT	"result"
#define	XML_ELEMENT_TIMECON	"time-connected"
#define	XML_ELEMENT_READCMDS	"read-commands"
#define	XML_ELEMENT_WRITECMDS	"write-commands"
#define	XML_ELEMENT_READBLKS	"read-blks"
#define	XML_ELEMENT_WRITEBLKS	"write-blks"
#define	XML_ELEMENT_STATS	"statistics"
#define	XML_ELEMENT_CONN	"connection"
#define	XML_ELEMENT_LUNINFO	"lun-information"
#define	XML_ELEMENT_VID		"vid"
#define	XML_ELEMENT_PID		"pid"
#define	XML_ELEMENT_GUID	"guid"
#define	XML_ELEMENT_DTYPE	"dtype"
#define	XML_ELEMENT_IOSTAT	"iostat"
#define	XML_ELEMENT_MACADDR	"mac-addr"
#define	XML_ELEMENT_MGMTPORT	"mgmt-port"
#define	XML_ELEMENT_ISCSIPORT	"iscsi-port"
#define	XML_ELEMENT_TARGLOG	"target-log"
#define	XML_ELEMENT_DBGLVL	"dbg-lvl"
#define	XML_ELEMENT_LOGLVL	"qlog-lvl"
#define	XML_ELEMENT_DBGDAEMON	"daemonize"
#define	XML_ELEMENT_ENFORCE	"enforce-strict-guid"
#define	XML_ELEMENT_VERS	"version"
#define	XML_ELEMENT_MMAP_LUN	"mmap-lun"
#define	XML_ELEMENT_RPM		"rpm"
#define	XML_ELEMENT_HEADS	"heads"
#define	XML_ELEMENT_CYLINDERS	"cylinders"
#define	XML_ELEMENT_SPT		"spt"
#define	XML_ELEMENT_BPS		"bps"
#define	XML_ELEMENT_INTERLEAVE	"interleave"
#define	XML_ELEMENT_PARAMS	"params"
#define	XML_ELEMENT_MAXCMDS	"max-outstanding-cmds"
#define	XML_ELEMENT_THIN_PROVO	"thin-provisioning"
#define	XML_ELEMENT_DISABLE_TPGS	"disable-tpgs"
#define	XML_ELEMENT_STATUS	"status"
#define	XML_ELEMENT_PROGRESS	"progress"
#define	XML_ELEMENT_TIMESTAMPS	"time-stamps"

typedef enum {
	NodeFree,
	NodeAlloc,
	NodeName,
	NodeValue
} xml_node_state;

typedef enum { MatchName, MatchBoth } match_type_t;

typedef struct xml_node {
	struct xml_node	*x_parent,
			*x_child,
			*x_sibling,
			*x_attr;
	char		*x_name,
			*x_value;
	xml_node_state	x_state;
} xml_node_t;

typedef enum val_type { Tag_String, Tag_Start, Tag_End } val_type_t;
typedef enum xml_val_type { String, Int, Uint64 } xml_val_type_t;

void xml_tree_free(xml_node_t *x);
void xml_walk(xml_node_t *x, int depth);
void xml_walk_to_buf(xml_node_t *n, char **buf);
void xml_update_config(xml_node_t *t, int depth, FILE *output);
void buf_add_str(char **b, char *str);
void buf_add_tag(char **b, char *str, val_type_t type);
void buf_add_tag_and_attr(char **b, char *str, char *attr);
void buf_add_node_attr(char **b, xml_node_t *x);
void xml_add_tag(char **b, char *element, char *cdata);
void xml_add_comment(char **b, char *comment);
void xml_replace_child(xml_node_t *parent, xml_node_t *child, match_type_t m);
Boolean_t xml_remove_child(xml_node_t *parent, xml_node_t *child,
    match_type_t m);
Boolean_t xml_encode_bytes(uint8_t *ip, size_t ip_size, char **buf,
    size_t *buf_size);
Boolean_t xml_decode_bytes(char *buf, uint8_t **ip, size_t *ip_size);
Boolean_t xml_find_value_str(xml_node_t *n, char *name, char **value);
Boolean_t xml_find_value_int(xml_node_t *n, char *name, int *value);
Boolean_t xml_find_value_intchk(xml_node_t *n, char *name, int *value);
Boolean_t xml_update_value_ull(xml_node_t *root, char *name, uint64_t value);
Boolean_t xml_dump2file(xml_node_t *root, char *path);
Boolean_t xml_find_value_boolean(xml_node_t *n, char *name, Boolean_t *value);
Boolean_t xml_find_attr_str(xml_node_t *n, char *attr, char **value);
Boolean_t xml_process_node(xmlTextReaderPtr r, xml_node_t **node);
Boolean_t xml_add_child(xml_node_t *p, xml_node_t *c);
xml_node_t *xml_alloc_node(char *name, xml_val_type_t type, void *value);
void xml_free_node(xml_node_t *node);
xml_node_t *xml_node_next(xml_node_t *n, char *name, xml_node_t *cur);
xml_node_t *xml_node_next_child(xml_node_t *n, char *name, xml_node_t *cur);
xml_node_t *xml_node_dup(xml_node_t *n);
xml_node_t *xml_find_child(xml_node_t *n, char *name);
Boolean_t xml_update_value_str(xml_node_t *node, char *name, char *str);

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_XML_H */
