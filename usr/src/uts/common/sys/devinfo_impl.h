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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DEVINFO_IMPL_H
#define	_SYS_DEVINFO_IMPL_H

#include <sys/ddi_impldefs.h>

/*
 * This file is separate from libdevinfo.h because the devinfo driver
 * needs to know about the stuff. Library consumer should not care
 * about stuff defined here.
 *
 * The only exception is di_priv_data (consolidation private) and
 * DINFO* ioctls.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* ioctl commands for devinfo driver */

#define	DIIOC		(0xdf<<8)
#define	DIIOC_MASK	(0xffff00ff)

/*
 * Any combination of the following ORed together will take a snapshot
 * of the device configuration data.
 */
#define	DINFOSUBTREE	(DIIOC | 0x01)	/* include subtree */
#define	DINFOMINOR	(DIIOC | 0x02)	/* include minor data */
#define	DINFOPROP	(DIIOC | 0x04)	/* include properties */
#define	DINFOPATH	(DIIOC | 0x08)	/* include i/o pathing information */

/* private bits */
#define	DINFOPRIVDATA	(DIIOC | 0x10)	/* include private data */
#define	DINFOFORCE	(DIIOC | 0x20)	/* force load all drivers */
#define	DINFOCACHE	(DIIOC | 0x100000) /* use cached data  */
#define	DINFOCLEANUP	(DIIOC | 0x200000) /* cleanup /etc/devices files */

/* new public flag for the layered drivers framework */
#define	DINFOLYR	(DIIOC | 0x40)	/* get device layering information */

/* new public flag for the hotplug framework */
#define	DINFOHP		(DIIOC | 0x400000)  /* include hotplug information */

/*
 * Straight ioctl commands, not bitwise operation
 */
#define	DINFOUSRLD	(DIIOC | 0x80)	/* copy snapshot to usrland */
#define	DINFOLODRV	(DIIOC | 0x81)	/* force load a driver */
#define	DINFOIDENT	(DIIOC | 0x82)	/* identify the driver */

/*
 * ioctl for taking a snapshot a single node and all nodes
 */
#define	DINFOCPYONE	DIIOC
#define	DINFOCPYALL	(DINFOSUBTREE | DINFOPROP | DINFOMINOR)

#define	DI_MAGIC	0xdfdf	/* magic number returned by DINFOIDENT */

/* driver ops encoding */

#define	DI_BUS_OPS	0x1
#define	DI_CB_OPS	0x2
#define	DI_STREAM_OPS	0x4

/* property list enumeration */

#define	DI_PROP_DRV_LIST	0
#define	DI_PROP_SYS_LIST	1
#define	DI_PROP_GLB_LIST	2
#define	DI_PROP_HW_LIST		3

/* misc parameters */

#define	MAX_TREE_DEPTH	64
#define	MAX_PTR_IN_PRV	5
#define	DI_SNAPSHOT_VERSION_0	0	/* reserved */
#define	DI_SNAPSHOT_VERSION_1	1	/* reserved */
#define	DI_SNAPSHOT_VERSION_2	2	/* reserved */
#define	DI_SNAPSHOT_VERSION	DI_SNAPSHOT_VERSION_2	/* current version */
#define	DI_PRIVDATA_VERSION_0	10	/* Start from 10 so caller must set */
#define	DI_BIG_ENDIAN		0	/* reserved */
#define	DI_LITTLE_ENDIAN	1	/* reserved */

#define	DI_CACHE_MAGIC		0xdfcac6ed	/* magic # for cache */
#define	DI_CACHE_PERMS		(0444)
#define	DI_CACHE_SNAPSHOT_FLAGS	\
	(DINFOFORCE|DINFOSUBTREE|DINFOMINOR|DINFOPROP|DINFOPATH)

#define	DI_NODE(addr)		((struct di_node *)((void *)(addr)))
#define	DI_MINOR(addr)		((struct di_minor *)((void *)(addr)))
#define	DI_PROP(addr)		((struct di_prop *)((void *)(addr)))
#define	DI_PATH(addr)		((struct di_path *)((void *)(addr)))
#define	DI_PATHPROP(addr)	((struct di_path_prop *)((void *)(addr)))
#define	DI_ALL(addr)		((struct di_all *)((void *)(addr)))
#define	DI_DEVNM(addr)		((struct di_devnm *)((void *)(addr)))
#define	DI_LINK(addr)		((struct di_link *)((void *)(addr)))
#define	DI_LNODE(addr)		((struct di_lnode *)((void *)(addr)))
#define	DI_PRIV_FORMAT(addr)	((struct di_priv_format *)((void *)(addr)))
#define	DI_HP(addr)		((struct di_hp *)((void *)(addr)))
#define	DI_ALIAS(addr)		((struct di_alias *)((void *)(addr)))

/*
 * multipath component definitions:  Follows the registered component of
 * the mpxio system.
 */
#define	MULTIPATH_COMPONENT_NONE	0
#define	MULTIPATH_COMPONENT_VHCI	0x1
#define	MULTIPATH_COMPONENT_PHCI	0x2
#define	MULTIPATH_COMPONENT_CLIENT	0x4

typedef int32_t di_off_t;

/*
 * devinfo driver snapshot data structure
 */
struct di_all {
	int	version;	/* snapshot version, reserved */
	int	cache_magic;	/* magic number for cached snapshot */
	int	pd_version;	/* private data format version */
	int	endianness;	/* reserved for future use */
	int	generation;	/* reserved for future use */
	uint32_t	cache_checksum;	/* snapshot checksum */
	uint64_t	snapshot_time;	/* snapshot timestamp */
	di_off_t	top_devinfo;  /* actual top devinfo in snapshot */
	di_off_t	top_vhci_devinfo;
	di_off_t	devnames;
	di_off_t	ppdata_format;	/* parent priv data format array */
	di_off_t	dpdata_format;	/* driver priv data format array */
	di_off_t	aliases;	/* offset to alias tree */
	int	n_ppdata;	/* size of ppdata_format array */
	int	n_dpdata;	/* size of pddata_format array */
	int	devcnt;		/* size of devnames array */
	uint_t	command;	/* same as in di_init() */
	uint_t	map_size;	/* size of the snapshot */
	char	req_path[MAXPATHLEN];	/* path to requested root */
	char	root_path[1];	/* path to actual snapshot root */
};

struct di_devnm {
	di_off_t name;
	di_off_t global_prop;
	di_off_t head;	/* head of per instance list */
	int flags;	/* driver attachment info */
	int instance;	/* next instance to assign */
	uint_t ops;	/* bit-encoded driver ops */
};


struct di_lnode;

struct di_link {
	di_off_t	self;
	int		count;
	int		spec_type;	/* block or char access type */
	di_off_t	src_lnode;	/* src di_lnode */
	di_off_t	tgt_lnode;	/* tgt di_lnode */
	di_off_t	src_link_next;	/* next src di_link /w same di_lnode */
	di_off_t	tgt_link_next;	/* next tgt di_link /w same di_lnode */
	di_off_t	src_node_next;	/* next src di_link /w same di_node */
	di_off_t	tgt_node_next;	/* next tgt di_link /w same di_node */
	uint64_t 	user_private_data;
};

struct di_lnode {
	di_off_t	self;

	/*
	 * public information describing a link endpoint
	 */
	major_t		dev_major;	/* dev_t can be 64-bit */
	minor_t		dev_minor;	/* dev_t can be 64-bit */
	di_off_t	node;		/* offset of di_node */

	/*
	 * di_link ptr to links comming into this node
	 * (this lnode is the target of these di_links)
	 */
	di_off_t	link_in;

	/*
	 * di_link ptr to links going out of this node
	 * (this lnode is the source of these di_links)
	 */
	di_off_t	link_out;

	/*
	 * di_lnode pointer to the next lnode associated with the
	 * same di_node
	 */
	di_off_t	node_next;

	uint64_t 	user_private_data;
};

struct di_node {	/* useful info to export for each tree node */
	/*
	 * offset to di_node structures
	 */
	di_off_t self;		/* make it self addressable */
	di_off_t parent;	/* offset of parent node */
	di_off_t child;		/* offset of child node */
	di_off_t sibling;	/* offset of sibling */
	di_off_t next;		/* next node on per-instance list */
	/*
	 * offset to char strings of current node
	 */
	di_off_t node_name;	/* offset of device node name */
	di_off_t address;	/* offset of address part of name */
	di_off_t bind_name;	/* offset of binding name */
	di_off_t compat_names;	/* offset of compatible names */
	/*
	 * offset to property lists, private data, etc.
	 */
	di_off_t minor_data;
	di_off_t drv_prop;
	di_off_t sys_prop;
	di_off_t glob_prop;
	di_off_t hw_prop;
	di_off_t parent_data;
	di_off_t driver_data;
	di_off_t multipath_client;
	di_off_t multipath_phci;
	di_off_t devid;		/* registered device id */
	di_off_t pm_info;	/* RESERVED FOR FUTURE USE */
	/*
	 * misc values
	 */
	int compat_length;	/* size of compatible name list */
	int drv_major;		/* for indexing into devnames array */
	/*
	 * value attributes of current node
	 */
	int instance;		/* instance number */
	int nodeid;		/* node id */
	ddi_node_class_t node_class;	/* node class */
	int attributes;		/* node attributes */
	uint_t state;		/* hotplugging device state */
	ddi_node_state_t node_state;	/* devinfo state */

	di_off_t lnodes;	/* lnodes associated with this di_node */
	di_off_t tgt_links;
	di_off_t src_links;

	uint32_t di_pad1;	/* 4 byte padding for 32bit x86 app. */
	uint64_t user_private_data;
	/*
	 * offset to link vhci/phci nodes.
	 */
	di_off_t next_vhci;
	di_off_t top_phci;
	di_off_t next_phci;
	uint32_t multipath_component;	/* stores MDI_COMPONENT_* value. */
	/*
	 * devi_flags field
	 */
	uint32_t flags;
	uint32_t di_pad2;	/* 4 byte padding for 32bit x86 app. */
	/*
	 * offset to hotplug nodes.
	 */
	di_off_t hp_data;
};

/*
 * chain of ddi_minor_data structure
 */
struct di_minor {
	di_off_t	self;		/* make it self addressable */
	di_off_t	next;		/* next one in the chain */
	di_off_t	name;		/* name of node */
	di_off_t	node_type;	/* block, byte, serial, network */
	ddi_minor_type	type;		/* data type */
	major_t		dev_major;	/* dev_t can be 64-bit */
	minor_t		dev_minor;
	int		spec_type;	/* block or char */
	unsigned int	mdclass;	/* no longer used, may be removed */
	di_off_t	node;		/* address of di_node */
	uint64_t 	user_private_data;
};

typedef enum {
	DI_PATH_STATE_UNKNOWN,
	DI_PATH_STATE_OFFLINE,
	DI_PATH_STATE_STANDBY,
	DI_PATH_STATE_ONLINE,
	DI_PATH_STATE_FAULT
} di_path_state_t;

/*
 * multipathing information structures
 */
struct di_path {
	di_off_t	self;		/* make it self addressable */
	di_off_t	path_c_link;	/* next pathinfo via client linkage */
	di_off_t	path_p_link;	/* next pathinfo via phci linkage */
	di_off_t	path_client;	/* reference to client node */
	di_off_t	path_phci;	/* reference to phci node */
	di_off_t	path_prop;	/* property list */
	di_off_t	path_addr;	/* path addressing information */
	di_path_state_t path_state;	/* path state */
	uint_t		path_snap_state; /* describes valid fields */
	int		path_instance;	/* path instance */
	uint64_t 	user_private_data;
	uint_t		path_flags;	/* path flags */
};

/*
 * chain of hotplug information structures
 */
struct di_hp {
	di_off_t	self;		/* make it self addressable */
	di_off_t	next;		/* next one in chain */
	di_off_t	hp_name;	/* name of hotplug connection */
	int		hp_connection;	/* connection number */
	int		hp_depends_on;	/* connection number depended upon */
	int		hp_state;	/* current hotplug state */
	int		hp_type;	/* connection type: PCI, ... */
	di_off_t	hp_type_str;	/* description of connection type */
	uint32_t	hp_last_change;	/* timestamp of last change */
	di_off_t	hp_child;	/* child device node */
};

/*
 * Flags for snap_state
 */
#define	DI_PATH_SNAP_NOCLIENT	0x01	/* client endpt not in snapshot */
#define	DI_PATH_SNAP_NOPHCI	0x02	/* phci endpt not in snapshot */
#define	DI_PATH_SNAP_ENDPTS	0x04	/* Endpoints have been postprocessed */

#define	DI_PATH_SNAP_NOCLINK	0x10	/* client linkage not in snapshot */
#define	DI_PATH_SNAP_NOPLINK	0x20	/* phci linkage not in snapshot */
#define	DI_PATH_SNAP_LINKS	0x40	/* linkages have been postprocessed */

/*
 * Flags for path_flags
 */
#define	DI_PATH_FLAGS_DEVICE_REMOVED	0x01	/* peer of DI_DEVICE_REMOVED */

/*
 * path properties
 */
struct di_path_prop {
	di_off_t	self;		/* make it self addressable */
	di_off_t	prop_next;	/* next property linkage */
	di_off_t	prop_name;	/* property name */
	di_off_t	prop_data;	/* property data */
	int		prop_type;	/* property data type */
	int		prop_len;	/* prop length in bytes */
};

/*
 * Now the properties.
 */
struct di_prop {
	di_off_t	self;		/* make it self addressable */
	di_off_t	next;
	di_off_t	prop_name;	/* Property name */
	di_off_t	prop_data;	/* property data */
	major_t		dev_major;	/* dev_t can be 64 bit */
	minor_t		dev_minor;
	int		prop_flags;	/* mark prop value types & more */
	int		prop_len;	/* prop len in bytes (boolean if 0) */
	int		prop_list;	/* which list (DI_PROP_SYS_LIST), etc */
};

/*
 * Private data stuff for supporting prtconf.
 * Allows one level of indirection of fixed sized obj or obj array.
 * The array size may be an int member of the array.
 */

struct di_priv_format {
	char drv_name[MAXPATHLEN];	/* name of parent drv for ppdata */
	size_t bytes;			/* size in bytes of this struct */
	struct {			/* ptrs to dereference */
		int size;	/* size of object assoc. this ptr */
		int offset;	/* location of pointer within struct */
		int len_offset;	/* offset to var. containing the len */
	} ptr[MAX_PTR_IN_PRV];
};

struct di_priv_data {
	int version;
	int n_parent;
	int n_driver;
	struct di_priv_format *parent;
	struct di_priv_format *driver;
};


/*
 * structure for saving alias information
 */
struct di_alias {
	di_off_t	self;		/* make it self addressable */
	di_off_t	curroff;	/* offset to curr dip's snapshot */
	di_off_t	next;		/* next alias */
	char		alias[1];	/* alias path */
};

/*
 * structure passed in from ioctl
 */
struct dinfo_io {
	char root_path[MAXPATHLEN];
	struct di_priv_data priv;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVINFO_IMPL_H */
