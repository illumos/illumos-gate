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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_TOPO_PCIE_IMPL_H
#define	_TOPO_PCIE_IMPL_H

#include <libdevinfo.h>
#include <libnvpair.h>
#include <stdbool.h>
#include <fm/topo_mod.h>
#include <sys/bitext.h>
#include <sys/pci.h>
#include "topo_pcie.h"

/*
 * Implementation-specific PCIe module header file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	PCI_MAX_BUS		0xff
#define	PCI_MAX_DEV		0x1f
#define	PCI_MAX_FUNC		0x7

typedef enum {
	PCIE_NODE_ROOTNEXUS,
	PCIE_NODE_ROOTPORT,
	PCIE_NODE_PCI_DEV,
	PCIE_NODE_PCIE_DEV,
	PCIE_NODE_SWITCH_UP,
	PCIE_NODE_SWITCH_DOWN,
	PCIE_NODE_PCIE_PCI,
	PCIE_NODE_PCI_PCIE,
} pcie_node_type_t;

typedef enum {
	TOPO_PORT_DOWNSTREAM,
	TOPO_PORT_UPSTREAM,
} topo_port_type_t;

typedef struct pcie {
	di_node_t		tp_devinfo;
	pcidb_hdl_t		*tp_pcidb_hdl;
	topo_list_t		tp_rootnexus;
	bool			tp_enumdone;
	uint8_t			tp_nchip;
	nvlist_t		*tp_cpupcidata;
	void			*tp_privdata;
} pcie_t;

typedef struct pcie_node {
	topo_list_t		pn_link;

	pcie_t			*pn_pcie;
	di_node_t		pn_did;
	pcie_node_type_t	pn_type;
	topo_instance_t		pn_inst;
	topo_instance_t		pn_cpu;
	int			pn_class;
	int			pn_subclass;
	int			pn_intf;
	int			pn_bus;
	int			pn_dev;
	int			pn_func;
	bool			pn_is_pcie;
	const char		*pn_path;
	char			*pn_drvname;
	int			pn_drvinst;

	/*
	 * These two keep track of devices that have already been seen
	 * underneath this node, and the topology function number that was last
	 * allocated. They are both indexed by the PCI device ID of the child.
	 */
	tnode_t			*pn_devices[PCI_MAX_DEV + 1];
	topo_instance_t		pn_devfunc[PCI_MAX_DEV + 1];

	topo_list_t		pn_children;
	struct pcie_node	*pn_parent;
} pcie_node_t;

typedef enum {
	PCI_LINK_UNKNOWN,
	PCI_LINK_UP,
	PCI_LINK_DOWN,
} topo_pcie_link_status_t;

#define	TOPO_PCIE_LINK_UP_STR		"up"
#define	TOPO_PCIE_LINK_DOWN_STR		"down"

extern bool pcie_set_platdata(pcie_t *, void *);
extern void *pcie_get_platdata(const pcie_t *);

/*
 * Each architecture must provide implementations of the following
 * mod_pcie_*() functions that can be used to decorate or extend topology nodes
 * based on system-specific knowledge.
 */

extern bool mod_pcie_platform_init(topo_mod_t *, pcie_t *);
extern void mod_pcie_platform_fini(topo_mod_t *, pcie_t *);

/*
 * This hook is called to create the authority information for the node.
 */
extern nvlist_t *mod_pcie_platform_auth(topo_mod_t *, const pcie_t *,
    tnode_t *);

/*
 * This hook is called for every newly created topology node, after the core
 * module has populated common properties. The return value is the topology
 * node from which to continue, allowing additional nodes to be inserted
 * into the hierarchy by the module if required.
 */
extern tnode_t *mod_pcie_platform_topo_node_decorate(topo_mod_t *,
    const pcie_t *, const pcie_node_t *, tnode_t *);

/* topo_pcie_util.c */

extern bool topo_pcie_set_io_props(topo_mod_t *, pcie_t *, pcie_node_t *,
    tnode_t *);
extern bool topo_pcie_set_pci_props(topo_mod_t *, pcie_t *, pcie_node_t *,
    tnode_t *);
extern bool topo_pcie_set_port_props(topo_mod_t *, pcie_t *, pcie_node_t *,
    tnode_t *, topo_port_type_t);
extern bool topo_pcie_set_link_props(topo_mod_t *, pcie_t *, pcie_node_t *,
    tnode_t *);

extern const char *pcie_type_name(pcie_node_type_t);
extern uint_t pcie_speed2gen(int64_t);
extern const char *pcie_speed2str(int64_t);

/* topo_pcie_prop.c */

extern bool pcie_topo_pgroup_create(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *);
extern bool pcie_topo_range_create(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t);

extern int32_t pcie_devinfo_get32(topo_mod_t *, di_node_t, const char *);
extern int64_t pcie_devinfo_get64(topo_mod_t *, di_node_t, const char *);
extern bool pcie_devinfo_getbool(topo_mod_t *, di_node_t, const char *);

extern bool pcie_topo_prop_set32(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *, const char *, uint32_t);
extern bool pcie_topo_prop_set64(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *, const char *, uint64_t);
extern bool pcie_topo_prop_set32_array(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *, const char *, uint32_t *, int);
extern bool pcie_topo_prop_set64_array(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *, const char *, uint64_t *, int);
extern bool pcie_topo_prop_setstr(topo_mod_t *, tnode_t *,
    const topo_pgroup_info_t *, const char *, const char *);

extern bool pcie_topo_prop_copy(topo_mod_t *, di_node_t, tnode_t *,
    const topo_pgroup_info_t *, topo_type_t, const char *, const char *);

/* topo_pcie_cfgspace.c */

extern topo_pcie_link_status_t topo_pcie_link_status(topo_mod_t *,
    pcie_node_t *);

#define	GETCLASS(x)	bitx32((x), 23, 16);
#define	GETSUBCLASS(x)	bitx32((x), 15, 8);
#define	GETINTF(x)	bitx32((x), 7, 0);

#define	PCIE			"pcie"
#define	PCIE_VERSION		1

#define	PCIE_ROOT_NEXUS		"pciex_root_complex"

/*
 * Devinfo properties
 */

#define	DI_COMPATPROP		"compatible"
#define	DI_DEVTYPPROP		"device_type"
#define	DI_PCIETYPPROP		"pcie-type"
#define	DI_VENDIDPROP		"vendor-id"
#define	DI_SUBVENDIDPROP	"subsystem-vendor-id"
#define	DI_SUBSYSTEMID		"subsystem-id"
#define	DI_REVIDPROP		"revision-id"
#define	DI_DEVIDPROP		"device-id"
#define	DI_CLASSPROP		"class-code"
#define	DI_REGPROP		"reg"
#define	DI_PHYSPROP		"physical-slot#"
#define	DI_AADDRPROP		"assigned-addresses"
#define	DI_MODELNAME		"model"
#define	DI_VENDORNAME		"vendor-name"
#define	DI_DEVICENAME		"device-name"
#define	DI_SUBSYSNAME		"subsystem-name"
#define	DI_BUSRANGE		"bus-range"

#define	DI_PCIE_MAX_WIDTH	"pcie-link-maximum-width"
#define	DI_PCIE_CUR_WIDTH	"pcie-link-current-width"
#define	DI_PCIE_MAX_SPEED	"pcie-link-maximum-speed"
#define	DI_PCIE_CUR_SPEED	"pcie-link-current-speed"
#define	DI_PCIE_SUP_SPEEDS	"pcie-link-supported-speeds"
#define	DI_PCIE_TARG_SPEED	"pcie-link-target-speed"
#define	DI_PCIE_ADMIN_TAG	"pcie-link-admin-target-speed"

#define	DI_PCI_66MHZ_CAPABLE	"66mhz-capable"

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_PCIE_IMPL_H */
