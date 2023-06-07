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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LOWLEVEL_IMPL_H
#define	_LOWLEVEL_IMPL_H

#include "libscf_impl.h"

#include <door.h>
#include <libuutil.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>

#include <sys/zone.h>

#include "repcache_protocol.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct scf_datael {
	scf_handle_t	*rd_handle;
	uint32_t	rd_entity;
	uint32_t	rd_type;
	uint32_t	rd_reset;
	uu_list_node_t	rd_node;
} scf_datael_t;
#define	DATAEL_VALID		0x0001

/*
 * Handle structure.
 *
 * Access to handles is serialized -- access to and modification of a handle
 * and all of its children is protected by rh_lock.
 *
 * Different handles don't interfere with each other.
 */
struct scf_handle {
	pthread_mutex_t	rh_lock;
	pthread_cond_t	rh_cv;

	uint32_t	rh_nextiter;
	uint32_t	rh_nextentity;
	uint32_t	rh_nextchangeid;

	int		rh_doorfd;
	int		rh_doorfd_old;	/* fd to close once rh_fd_users == 0 */
	door_id_t	rh_doorid;
	pid_t		rh_doorpid;	/* pid at bind time */

	uid_t		rh_uid;
	uint32_t	rh_debug;
	uint32_t	rh_flags;	/* HANDLE_*, below */
	uint32_t	rh_fd_users;	/* non-locked users of rh_doorfd */

	uu_list_t	*rh_dataels;
	uu_list_t	*rh_iters;
	long		rh_entries;
	long		rh_values;

	long		rh_extrefs;	/* user-created subhandle count */
	long		rh_intrefs;	/* handle-internal subhandle count */

	char		rh_doorpath[PATH_MAX + 1];
	zoneid_t	rh_zoneid;	/* expected zone ID for door server */

	pthread_t	rh_holder;		/* thread using subhandles */
	uint32_t	rh_hold_flags;		/* which are in use */

	scf_iter_t		*rh_iter;
	scf_scope_t		*rh_scope;
	scf_service_t		*rh_service;
	scf_instance_t		*rh_instance;
	scf_snapshot_t		*rh_snapshot;
	scf_snaplevel_t		*rh_snaplvl;
	scf_propertygroup_t	*rh_pg;
	scf_property_t		*rh_property;
	scf_value_t		*rh_value;
};
#define	HANDLE_DEAD		0x0001
#define	HANDLE_UNREFED		0x0002
#define	HANDLE_WRAPPED_ENTITY	0x0004
#define	HANDLE_WRAPPED_ITER	0x0008

#define	RH_HOLD_ITER		0x0001
#define	RH_HOLD_SCOPE		0x0002
#define	RH_HOLD_SERVICE		0x0004
#define	RH_HOLD_INSTANCE	0x0008
#define	RH_HOLD_SNAPSHOT	0x0010
#define	RH_HOLD_SNAPLVL		0x0020
#define	RH_HOLD_PG		0x0040
#define	RH_HOLD_PROPERTY	0x0080
#define	RH_HOLD_VALUE		0x0100

#define	RH_HOLD_ALL		0x01ff

struct scf_scope {
	scf_datael_t	rd_d;
};

struct scf_service {
	scf_datael_t	rd_d;
};

struct scf_instance {
	scf_datael_t	rd_d;
};

struct scf_snapshot {
	scf_datael_t	rd_d;
};

/*
 * note: be careful of adding more state here -- snaplevel_next() relies on
 * the fact that the entityid is the only library-level state.
 */
struct scf_snaplevel {
	scf_datael_t	rd_d;
};

struct scf_propertygroup {
	scf_datael_t	rd_d;
};

struct scf_property {
	scf_datael_t	rd_d;
};

struct scf_value {
	scf_handle_t		*value_handle;
	scf_value_t		*value_next;
	scf_transaction_entry_t	*value_tx;

	rep_protocol_value_type_t value_type;
	size_t			value_size;	/* only for opaque values */
	char			value_value[REP_PROTOCOL_VALUE_LEN];
};

enum scf_entry_state {
	ENTRY_STATE_INVALID,
	ENTRY_STATE_IN_TX_ACTION
};
struct scf_transaction_entry {
	const char	*entry_property;
	scf_handle_t	*entry_handle;
	scf_transaction_t *entry_tx;
	enum scf_entry_state entry_state;
	uu_list_node_t	entry_link;		/* for property name list */

	scf_value_t	*entry_head;
	scf_value_t	*entry_tail;		/* for linked values */

	enum rep_protocol_transaction_action	entry_action;
	rep_protocol_value_type_t		entry_type;
	char		entry_namebuf[REP_PROTOCOL_NAME_LEN];
};

enum scf_tx_state {
	TRAN_STATE_NEW,
	TRAN_STATE_SETUP,
	TRAN_STATE_COMMITTED
};

struct scf_transaction {
	enum scf_tx_state	tran_state;
	scf_propertygroup_t	tran_pg;
	int			tran_invalid;
	uu_list_t		*tran_props;
};

struct scf_iter {
	scf_handle_t	*iter_handle;
	int		iter_type;
	uint32_t	iter_id;
	uint32_t	iter_sequence;
	uu_list_node_t	iter_node;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _LOWLEVEL_IMPL_H */
