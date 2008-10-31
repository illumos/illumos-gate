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

#ifndef _DID_IMPL_H
#define	_DID_IMPL_H

#include <sys/pci.h>
#include <fm/libtopo.h>
#include <libdevinfo.h>
#include <libnvpair.h>
#include <did.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	REC_HASHLEN	253

/*
 * Slot name info is attached to devinfo nodes, compressed inside of
 * a "slot-names" property.  When we dig this out we store each name
 * as an FMRI, along with the device number to which it applies.
 */
typedef struct slotnm {
	topo_mod_t *snm_mod;	/* module that allocated the slot name */
	struct slotnm *snm_next;
	int snm_dev;	 /* device on the bus that implements the slot */
	char *snm_label; /* label describing the slot */
} slotnm_t;

typedef struct did_hash did_hash_t;

/*
 * Private data stored with a tnode_t.  We collect slot-name info from
 * di_nodes that describe buses, but then don't use it until we get to
 * a tnode_t actually describing a function of a device.  We also use
 * this struct to pass around bus, dev, function info so that doesn't
 * have to be re-computed.
 */
struct did {
	struct did *dp_next; /* for chaining in a hash bucket */
	struct did *dp_link; /* for chaining to related did_t */
	struct did *dp_chain; /* for chaining to another chain of did_ts */
	did_hash_t *dp_hash; /* the hash table where we reside */
	topo_mod_t *dp_mod; /* module that allocated the did private data */
	di_node_t dp_src; /* di_node_t from which the info was derived */
	int dp_refcnt;	/* multiple nodes allowed to point at a did_t */
	uint_t dp_excap;	/* PCI-Express port/device type */
	int dp_physlot;		/* PCI-Express physical slot # */
	char *dp_physlot_label; /* PCI-Express slot implemented */
	int dp_class;		/* PCI class */
	int dp_subclass;	/* PCI subclass */
	char *dp_devtype;	/* PCI 1275 spec device-type */
	int dp_board;		/* Board number */
	int dp_bridge;		/* Bridge number */
	int dp_rc;		/* Root Complex number */
	int dp_bus;		/* PCI bus number */
	int dp_dev;		/* PCI device number on the above bus */
	int dp_fn;		/* PCI function number of the above device */
	int dp_bdf;		/* PCI "real" bdf */
	/*
	 * There may be some slot name info on devinfo node for a bus or
	 * hostbridge.  We'll copy or reference it for child nodes of that
	 * bus or hostbridge.
	 */
	int dp_nslots;		/* number of slots actually described */
	slotnm_t *dp_slotnames; /* the slot names as labels */
	tnode_t *dp_tnode;  /* the parent tnode */
};

struct did_hash {
	did_t **dph_hash;	/* hash bucket array */
	uint_t dph_hashlen;	/* size of hash bucket array */
	uint_t dph_nelems;	/* number of elements in the hash */
	topo_mod_t *dph_mod;	/* module that allocated the hash table */
};

#ifdef __cplusplus
}
#endif

#endif /* _DID_IMPL_H */
