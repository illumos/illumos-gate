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

#ifndef _SYS_SCSI_ADAPTERS_MPAPI_SCSI_VHCI_H
#define	_SYS_SCSI_ADAPTERS_MPAPI_SCSI_VHCI_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */


#include <sys/scsi/adapters/mpapi_impl.h>

#define	MPAPI_SCSI_MAXPCLASSLEN	25

/* Structure for MP_OID (kernel level only) */

typedef struct mp_oid {
#if defined(_BIT_FIELDS_HTOL)
	uint32_t	tstamp;
	uint32_t	type:8,
			seq_id:24;
#else
	uint32_t	seq_id:24,
			type:8;
	uint32_t	tstamp;
#endif
} mp_oid_t;

typedef union mpoid {
	uint64_t	raw_oid;	/* raw oid */
	mp_oid_t	disc_oid;	/* discrete oid */
} mpoid_t;


/*
 * MP API item - A generic one to use in a list setup
 * in a common way for all types of elements of
 * Object type items required for mpapi.
 */

typedef	struct mpapi_item {
	mpoid_t			oid;
	void			*idata; /* item data */
	kmutex_t		item_mutex;
} mpapi_item_t;

typedef	struct mpapi_item_list {
	mpapi_item_t		*item;
	struct mpapi_item_list	*next;
} mpapi_item_list_t;

/*
 * MP API item header definition.
 */

typedef struct mpapi_list_header {
	mpapi_item_list_t	*head;
	mpapi_item_list_t	*tail;
} mpapi_list_header_t;

/*
 * Structure to maintain mpapi initiator data.
 */
typedef struct mpapi_initiator_data {
	void			*resp; /* initiator-port prop */
	mpapi_list_header_t	*path_list;
	int			valid;
	mp_init_port_prop_t	prop;
} mpapi_initiator_data_t;

/*
 * Structure to maintain mpapi lu data.
 */
typedef struct mpapi_lu_data {
	void			*resp; /* vlun */
	mpapi_list_header_t	*path_list;
	mpapi_list_header_t	*tpg_list;
	int			valid;
	mp_logical_unit_prop_t	prop;
} mpapi_lu_data_t;

/*
 * Structure to maintain mpapi path data.
 *
 * The hide flag is set when pip was detroyed or should
 * have been destroyed(MDI_PATHINFO_FLAGS_DEVICE_REMOVED).
 * The valid flag is set to 0 when the path is neither online
 * nor standby state. When hide flag is set the valid flag set
 * to 0 also.
 */
typedef struct mpapi_path_data {
	void			*resp; /* pip */
	char			*path_name;
	int			valid;
	int			hide;
	char			pclass[MPAPI_SCSI_MAXPCLASSLEN];
	mp_path_prop_t		prop;
} mpapi_path_data_t;

/*
 * Structure to maintain mpapi tpg data.
 */
typedef struct mpapi_tpg_data {
	void			*resp;
	mpapi_list_header_t	*tport_list;
	mpapi_list_header_t	*lu_list; /* mpath lu or lun list */
	int			valid;
	char			pclass[MPAPI_SCSI_MAXPCLASSLEN];
	mp_tpg_prop_t		prop;
} mpapi_tpg_data_t;

/*
 * Structure to maintain mpapi tport data.
 */
typedef struct mpapi_tport_data {
	void			*resp; /* target port prop */
	mpapi_list_header_t	*path_list;
	int			valid;
	mp_target_port_prop_t	prop;
} mpapi_tport_data_t;


/* Structure for mpapi private data */

typedef struct mpapi_priv {

	/*
	 * Will be initialized with tod(time of day)
	 * This will enable detection of stale OIDs used by the upper layers.
	 */
	uint32_t		tstamp;
	/*
	 * The Sequence number space is unique within an Object Type -
	 * that is there can be a seq# 2 in Object Type "initiator port"
	 * and also a seq#2 in object type 'Path LU'.
	 * Even though the Seq# space collides, the Object type field
	 * will make the OIDs unique.
	 * The following field will indicate what the next sequence number
	 * that can be used for a particular type of Object type -
	 * Object type will be used to index into the array element.
	 */
	uint32_t		oid_seq[MP_MAX_OBJECT_TYPE];

	/*
	 * One list for each type of object.
	 */
	mpapi_list_header_t	*obj_hdr_list[MP_MAX_OBJECT_TYPE];

} mpapi_priv_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SCSI_ADAPTERS_MPAPI_SCSI_VHCI_H */
