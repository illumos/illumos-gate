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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISCSITGT_IMPL_H
#define	_ISCSITGT_IMPL_H

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <libxml/xmlreader.h>

#ifndef MIN
#define	MIN(x, y)	((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define	MAX(x, y)	((x) > (y) ? (x) : (y))
#endif

/*
 * Solaris typedefs boolean_t to be an enum with B_TRUE and B_FALSE.
 * MacOS X typedefs boolean_t to be an int with #defines for TRUE & FALSE
 * I like the use of enum's for return codes so that compilers can catch
 * sloppy coding practices so I've defined a Boolean_t which is unique here.
 */
typedef enum {
	False = 0,
	True = 1
} Boolean_t;

#ifndef DTYPE_OSD
#define	DTYPE_OSD	0x11
#endif

#define	DOOR_MIN_SPACE	128

#define	ISCSI_TARGET_MGMT_DOOR	"/var/run/iscsi_tgt_door"
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
#define	XML_ELEMENT_DELETE_CHAPSECRET	"delete-chap-secret"
#define	XML_ELEMENT_CHAPNAME	"chap-name"
#define	XML_ELEMENT_DELETE_CHAPNAME	"delete-chap-name"
#define	XML_ELEMENT_RAD_ACCESS	"radius-access"
#define	XML_ELEMENT_RAD_SERV	"radius-server"
#define	XML_ELEMENT_DELETE_RAD_SERV	"delete-radius-server"
#define	XML_ELEMENT_RAD_SECRET	"radius-secret"
#define	XML_ELEMENT_DELETE_RAD_SECRET	"delete-radius-secret"
#define	XML_ELEMENT_ISNS_ACCESS	"isns-access"
#define	XML_ELEMENT_ISNS_SERV	"isns-server"
#define	XML_ELEMENT_ISNS_SERVER_STATUS	"isns-server-status"
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
#define	XML_ELEMENT_ZFS		"zfs"
#define	XML_ELEMENT_ADMIN	"admin"
#define	XML_ELEMENT_INAME	"iscsi-name"
#define	XML_ELEMENT_MAXRECV	"maxrecv"
#define	XML_ELEMENT_IPADDR	"ip-address"
#define	XML_ELEMENT_IPADDRLIST	"ip-address-list"
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
#define	XML_ELEMENT_INCORE	"in-core"
#define	XML_ELEMENT_VALIDATE	"validate"
#define	XML_ELEMENT_MORESPACE	"more-space-required"
#define	XML_VALUE_TRUE		"true"
#define	XML_ELEMENT_PGR_PERSIST	"PGR-persist"
#define	XML_ELEMENT_PGR_BASEDIR	"PGR-basedir"

typedef enum {
	NodeFree,
	NodeAlloc,
	NodeName,
	NodeValue
} tgt_node_state;

typedef enum { MatchName, MatchBoth } match_type_t;

typedef struct tgt_node {
	struct tgt_node	*x_parent,
			*x_child,
			*x_sibling,
			*x_attr;
	char		*x_name,
			*x_value;
	tgt_node_state	x_state;
} tgt_node_t;

typedef enum val_type { Tag_String, Tag_Start, Tag_End } val_type_t;
typedef enum xml_val_type { String, Int, Uint64 } xml_val_type_t;

tgt_node_t *tgt_door_call(char *str, int smf_flags);
void tgt_dump2buf(tgt_node_t *t, char **buf);

tgt_node_t *tgt_node_alloc(char *name, xml_val_type_t type, void *value);
void tgt_node_free(tgt_node_t *x);
void tgt_node_replace(tgt_node_t *parent, tgt_node_t *child, match_type_t m);
Boolean_t tgt_node_remove(tgt_node_t *parent, tgt_node_t *child,
    match_type_t m);
tgt_node_t *tgt_node_next(tgt_node_t *n, char *name, tgt_node_t *cur);
tgt_node_t *tgt_node_next_child(tgt_node_t *n, char *name, tgt_node_t *cur);
tgt_node_t *tgt_node_dup(tgt_node_t *n);
tgt_node_t *tgt_node_find(tgt_node_t *n, char *name);
void tgt_node_add(tgt_node_t *p, tgt_node_t *c);
void tgt_node_add_attr(tgt_node_t *p, tgt_node_t *a);
Boolean_t tgt_node_process(xmlTextReaderPtr r, tgt_node_t **node);

void tgt_buf_add(char **b, char *element, const char *cdata);
void tgt_buf_add_tag(char **b, const char *str, val_type_t type);
void tgt_buf_add_tag_and_attr(char **b, char *str, char *attr);

Boolean_t tgt_xml_encode(uint8_t *ip, size_t ip_size, char **buf,
    size_t *buf_size);
Boolean_t tgt_xml_decode(char *buf, uint8_t **ip, size_t *ip_size);
Boolean_t tgt_find_value_str(tgt_node_t *n, char *name, char **value);
Boolean_t tgt_find_value_int(tgt_node_t *n, char *name, int *value);
Boolean_t tgt_find_value_intchk(tgt_node_t *n, char *name, int *value);
Boolean_t tgt_find_value_boolean(tgt_node_t *n, char *name, Boolean_t *value);
Boolean_t tgt_find_attr_str(tgt_node_t *n, char *attr, char **value);
Boolean_t tgt_update_value_str(tgt_node_t *node, char *name, char *str);

#ifdef __cplusplus
}
#endif

#endif /* _ISCSITGT_IMPL_H */
