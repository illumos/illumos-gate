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

#ifndef _TARGET_H
#define	_TARGET_H

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	DEFAULT_CONFIG		"/etc/iscsi/"
#define	DEFAULT_CONFIG_LOCATION	DEFAULT_CONFIG "target_config.xml"
#define	DEFAULT_TARGET_BASEDIR	DEFAULT_CONFIG
#define	DEFAULT_TARGET_LOG	"/tmp/target_log"

/*
 * []------------------------------------------------------------------[]
 * | Common strings which are used throughout the target.		|
 * []------------------------------------------------------------------[]
 */
/*
 * Target type strings are used to distinguish between the emulated types.
 * These strings are stored in the params file so they must not be changed
 * without thinking about upgrade issues.
 */
#define	TGT_TYPE_DISK		"disk"
#define	TGT_TYPE_TAPE		"tape"
#define	TGT_TYPE_OSD		"osd"
#define	TGT_TYPE_RAW		"raw"
#define	TGT_TYPE_INVALID	"invalid"

/*
 * During the creation phase of a LU it starts out offline during block
 * initialization, once initialization is complete it will transition to
 * online. If during the initialization an error occurs it will be so marked.
 */
#define	TGT_STATUS_OFFLINE	"offline"
#define	TGT_STATUS_ONLINE	"online"
#define	TGT_STATUS_ERRORED	"errored"

/*
 * Base file names for the logical units (LU). The format used is params.%d and
 * lun.%d These are used both to build the LU name and when searching the
 * target directory for valid luns. Don't change these names unless the upgrade
 * path has been thought about.
 */
#define	PARAMBASE		"params."
#define	LUNBASE			"lun."
#define	OSDBASE			"osd_root."
#define	PERSISTENCEBASE		"pgr."
#define	ISCSI_TARGET_ALIAS	"TargetAlias"
#define	ZVOL_PATH		"/dev/zvol/rdsk/"

/*
 * Base file name for persistent reservation data (PR). The format used is pr.
 * This name is used both to build the PR name and when searching the target
 * directory for persistent reservation data. Don't change these names unless
 * the upgrade path has been thought about.
 */
#define	PRBASE			"persistent_reservations"

/*
 * The IQN names that are created use libuuid + the local target name
 * as the idr_str portion of: iqn.1986-03.com.sun:<version>:<id_str>
 * In case this changes we also include a version number. Currently
 * version 1 is used by the Solaris iSCSI Initiator which has the MAC address,
 * timestamp, and hostname.
 */
#define	TARGET_NAME_VERS	2
#define	TARGET_NOFILE		10000

/*
 * Minimum and maximum values for Target Portal Group Tag as specified
 * by RFC3720
 */
#define	TPGT_MIN		1
#define	TPGT_MAX		65535

/*
 * Minimum and maximum values for MaxRecvDataSegmentLength
 */
#define	MAXRCVDATA_MIN		512
#define	MAXRCVDATA_MAX		((1 << 24) - 1)

/*
 * Major/minor versioning for the configuration files.
 * If we find a configuration file that has a higher
 * major number than we support we exit. Major number
 * changes are for radical structure differences. Shouldn't
 * happen, but we've got a means of detecting such a situation
 * a bailing out before doing any damage. Minor number changes
 * mean additions to the current format have been added. For
 * right now, we use -1, which means ignore the minor number. In
 * the future it would be possible for the software to determine
 * that a file had certain additions, but maybe not all changes.
 */
#define	XML_VERS_MAIN_MAJ	1
#define	XML_VERS_MAIN_MIN	-1
#define	XML_VERS_TARG_MAJ	1
#define	XML_VERS_TARG_MIN	-1
#define	XML_VERS_LUN_MAJ	1
#define	XML_VERS_LUN_MIN	-1
#define	XML_VERS_RESULT_MAJ	1
#define	XML_VERS_RESULT_MIN	-1

/*
 * Default values of the LUN parameters
 */
#define	DEFAULT_LUN_SIZE	((1024 * 1024 * 1024) / 512)
#define	DEFAULT_RPM		7200
#define	DEFAULT_HEADS		16
#define	DEFAULT_CYLINDERS	100
#define	DEFAULT_SPT		128
#define	DEFAULT_BYTES_PER	512
#define	DEFAULT_INTERLEAVE	1
#define	DEFAULT_PID		"SOLARIS"
#define	DEFAULT_VID		"SUN"
#define	DEFAULT_REVISION	"1"

/*
 * SPC-3 revision 21c, section 7.6.4.4.4
 * EUI-64 based 16-byte IDENTIFIER field format
 */
typedef struct eui_16 {
	uchar_t	e_vers,
		e_resrv1,
		e_mac[6],
		e_company_id[3],
		e_resv2,
		e_timestamp[4];
} eui_16_t;

/*
 * SPC-4 revision 11, section 7.6.3.6.5
 * NAA IEEE Registered Extended designator format
 */
typedef struct naa_16 {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	n_company_id_hi	: 4,
		n_naa		: 4;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	n_naa		: 4,
		n_company_id_hi	: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	n_company_id_b1,
		n_company_id_b2;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t	n_resv1		: 4,
		n_company_id_lo	: 4;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	n_company_id_lo	: 4,
		n_resv1		: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t	n_timestamp[4];
	uchar_t	n_resv2;
	uchar_t	n_mac[6];
	uchar_t	n_resv3;
} naa_16_t;

#define	SUN_EUI_16_VERS		1
#define	SUN_NAA_16_TYPE		6

#define	SUN_INQUIRY_ID_TYPE(GUID)	\
	(((naa_16_t *)(GUID))->n_naa == SUN_NAA_16_TYPE ? \
	SPC_INQUIRY_ID_TYPE_NAA : SPC_INQUIRY_ID_TYPE_EUI)

#define	SUN_EN			0x144f
#define	MIN_VAL			4

#ifndef min
#define	min(a, b) ((a) > (b) ? (b) : (a))
#endif
#ifndef max
#define	max(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef struct {
	char	*name;
	char	*(*func)(char *, char *);
	char	*delete_name;
} admin_table_t;

#include <sys/socket.h>
#include <umem.h>
#include <iscsitgt_impl.h>
#include "queue.h"

void create_func(tgt_node_t *, target_queue_t *, target_queue_t *, ucred_t *);
void modify_func(tgt_node_t *, target_queue_t *, target_queue_t *, ucred_t *);
void remove_func(tgt_node_t *, target_queue_t *, target_queue_t *, ucred_t *);
void list_func(tgt_node_t *, target_queue_t *, target_queue_t *, ucred_t *);
void logout_targ(char *targ);
char *update_basedir(char *, char *);
char *valid_radius_srv(char *name, char *prop);
char *valid_isns_srv(char *name, char *prop);
Boolean_t if_find_mac(target_queue_t *mgmt);
void if_target_address(char **text, int *text_length, struct sockaddr *sp);

extern admin_table_t	admin_prop_list[];
extern char 		*target_basedir;
extern char 		*target_log;
extern char		*config_file;
extern char		*pgr_basedir;
extern tgt_node_t	*targets_config;
extern tgt_node_t	*main_config;
extern uchar_t		mac_addr[];
extern size_t		mac_len;
extern int		main_vers_maj,
			main_vers_min,
			targets_vers_maj,
			targets_vers_min,
			iscsi_port;
extern Boolean_t	enforce_strict_guid,
			thin_provisioning,
			disable_tpgs,
			dbg_timestamps,
			pgr_persist;
extern pthread_rwlock_t	targ_config_mutex;
extern umem_cache_t	*iscsi_cmd_cache,
			*t10_cmd_cache,
			*queue_cache;

#ifdef __cplusplus
}
#endif

#endif /* _TARGET_H */
