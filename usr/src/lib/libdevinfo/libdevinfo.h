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

#ifndef	_LIBDEVINFO_H
#define	_LIBDEVINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <errno.h>
#include <libnvpair.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/sunmdi.h>
#include <sys/openpromio.h>
#include <sys/ddi_impldefs.h>
#include <sys/devinfo_impl.h>
#include <limits.h>

/*
 * flags for di_walk_node
 */
#define	DI_WALK_CLDFIRST	0
#define	DI_WALK_SIBFIRST	1
#define	DI_WALK_LINKGEN		2

#define	DI_WALK_MASK		0xf

/*
 * flags for di_walk_link
 */
#define	DI_LINK_SRC		1
#define	DI_LINK_TGT		2

/*
 * return code for node_callback
 */
#define	DI_WALK_CONTINUE	0
#define	DI_WALK_PRUNESIB	-1
#define	DI_WALK_PRUNECHILD	-2
#define	DI_WALK_TERMINATE	-3

/*
 * flags for di_walk_minor
 */
#define	DI_CHECK_ALIAS		0x10
#define	DI_CHECK_INTERNAL_PATH	0x20

#define	DI_CHECK_MASK		0xf0

/* nodeid types */
#define	DI_PSEUDO_NODEID	-1
#define	DI_SID_NODEID		-2
#define	DI_PROM_NODEID		-3

/* node & device states */
#define	DI_DRIVER_DETACHED	0x8000
#define	DI_DEVICE_OFFLINE	0x1
#define	DI_DEVICE_DOWN		0x2
#define	DI_DEVICE_DEGRADED	0x4
#define	DI_BUS_QUIESCED		0x100
#define	DI_BUS_DOWN		0x200

/* property types */
#define	DI_PROP_TYPE_BOOLEAN	0
#define	DI_PROP_TYPE_INT	1
#define	DI_PROP_TYPE_STRING	2
#define	DI_PROP_TYPE_BYTE	3
#define	DI_PROP_TYPE_UNKNOWN	4
#define	DI_PROP_TYPE_UNDEF_IT	5
#define	DI_PROP_TYPE_INT64	6

/* private macro for checking if a prop type is valid */
#define	DI_PROP_TYPE_VALID(type) \
	((((type) >= DI_PROP_TYPE_INT) && ((type) <= DI_PROP_TYPE_BYTE)) || \
	    ((type) == DI_PROP_TYPE_INT64))

/* opaque handles */
typedef struct di_node		*di_node_t;		/* node */
typedef struct di_minor		*di_minor_t;		/* minor_node */
typedef struct di_path		*di_path_t;		/* path_node */
typedef struct di_link		*di_link_t;		/* link */
typedef struct di_lnode		*di_lnode_t;		/* endpoint */
typedef struct di_devlink	*di_devlink_t;		/* devlink */

typedef struct di_prop		*di_prop_t;		/* node property */
typedef struct di_path_prop	*di_path_prop_t;	/* path property */
typedef struct di_prom_prop	*di_prom_prop_t;	/* prom property */

typedef struct di_prom_handle	*di_prom_handle_t;	/* prom snapshot */
typedef struct di_devlink_handle *di_devlink_handle_t;	/* devlink snapshot */


/*
 * Null handles to make handles really opaque
 */
#define	DI_NODE_NIL		NULL
#define	DI_MINOR_NIL		NULL
#define	DI_PATH_NIL		NULL
#define	DI_LINK_NIL		NULL
#define	DI_LNODE_NIL		NULL
#define	DI_PROP_NIL		NULL
#define	DI_PROM_PROP_NIL	NULL
#define	DI_PROM_HANDLE_NIL	NULL

/*
 * IEEE 1275 properties and other standardized property names
 */
#define	DI_PROP_FIRST_CHAS	"first-in-chassis"
#define	DI_PROP_SLOT_NAMES	"slot-names"
#define	DI_PROP_PHYS_SLOT	"physical-slot#"
#define	DI_PROP_DEV_TYPE	"device_type"
#define	DI_PROP_BUS_RANGE	"bus-range"
#define	DI_PROP_SERID		"serialid#"
#define	DI_PROP_REG		"reg"
#define	DI_PROP_AP_NAMES	"ap-names"

/* Interface Prototypes */

/*
 * Snapshot initialization and cleanup
 */
extern di_node_t	di_init(const char *phys_path, uint_t flag);
extern void		di_fini(di_node_t root);

/*
 * node: traversal, data access, and parameters
 */
extern int		di_walk_node(di_node_t root, uint_t flag, void *arg,
			    int (*node_callback)(di_node_t node, void *arg));

extern di_node_t	di_drv_first_node(const char *drv_name, di_node_t root);
extern di_node_t	di_drv_next_node(di_node_t node);

extern di_node_t	di_parent_node(di_node_t node);
extern di_node_t	di_sibling_node(di_node_t node);
extern di_node_t	di_child_node(di_node_t node);

extern char		*di_node_name(di_node_t node);
extern char		*di_bus_addr(di_node_t node);
extern char		*di_binding_name(di_node_t node);
extern int		di_compatible_names(di_node_t, char **names);
extern int		di_instance(di_node_t node);
extern int		di_nodeid(di_node_t node);
extern int		di_driver_major(di_node_t node);
extern uint_t		di_state(di_node_t node);
extern ddi_node_state_t	di_node_state(di_node_t node);
extern ddi_devid_t	di_devid(di_node_t node);
extern char		*di_driver_name(di_node_t node);
extern uint_t		di_driver_ops(di_node_t node);

extern void		di_node_private_set(di_node_t node, void *data);
extern void		*di_node_private_get(di_node_t node);

extern char		*di_devfs_path(di_node_t node);
extern char		*di_devfs_minor_path(di_minor_t minor);
extern void		di_devfs_path_free(char *path_buf);

/*
 * path_node: traversal, data access, and parameters
 */
extern di_path_t	di_path_phci_next_path(di_node_t node, di_path_t);
extern di_path_t	di_path_client_next_path(di_node_t node, di_path_t);

extern di_node_t	di_path_phci_node(di_path_t path);
extern di_node_t	di_path_client_node(di_path_t path);

extern char		*di_path_node_name(di_path_t path);
extern char		*di_path_bus_addr(di_path_t path);
extern int		di_path_instance(di_path_t path);
extern di_path_state_t	di_path_state(di_path_t path);

extern char		*di_path_devfs_path(di_path_t path);
extern char		*di_path_client_devfs_path(di_path_t path);

extern void		di_path_private_set(di_path_t path, void *data);
extern void		*di_path_private_get(di_path_t path);

/*
 * minor_node: traversal, data access, and parameters
 */
extern int		di_walk_minor(di_node_t root, const char *minortype,
			    uint_t flag, void *arg,
			    int (*minor_callback)(di_node_t node,
			    di_minor_t minor, void *arg));
extern di_minor_t	di_minor_next(di_node_t node, di_minor_t minor);

extern di_node_t	di_minor_devinfo(di_minor_t minor);
extern ddi_minor_type	di_minor_type(di_minor_t minor);
extern char		*di_minor_name(di_minor_t minor);
extern dev_t		di_minor_devt(di_minor_t minor);
extern int		di_minor_spectype(di_minor_t minor);
extern char		*di_minor_nodetype(di_minor_t node);

extern void		di_minor_private_set(di_minor_t minor, void *data);
extern void		*di_minor_private_get(di_minor_t minor);

/*
 * node: property access
 */
extern di_prop_t	di_prop_next(di_node_t node, di_prop_t prop);

extern char		*di_prop_name(di_prop_t prop);
extern int		di_prop_type(di_prop_t prop);
extern dev_t		di_prop_devt(di_prop_t prop);

extern int		di_prop_ints(di_prop_t prop, int **prop_data);
extern int		di_prop_int64(di_prop_t prop, int64_t **prop_data);
extern int		di_prop_strings(di_prop_t prop, char **prop_data);
extern int		di_prop_bytes(di_prop_t prop, uchar_t **prop_data);

extern int		di_prop_lookup_bytes(dev_t dev, di_node_t node,
			    const char *prop_name, uchar_t **prop_data);
extern int		di_prop_lookup_ints(dev_t dev, di_node_t node,
			    const char *prop_name, int **prop_data);
extern int		di_prop_lookup_int64(dev_t dev, di_node_t node,
			    const char *prop_name, int64_t **prop_data);
extern int		di_prop_lookup_strings(dev_t dev, di_node_t node,
			    const char *prop_name, char **prop_data);

/*
 * prom_node: property access
 */
extern di_prom_handle_t	di_prom_init(void);
extern void		di_prom_fini(di_prom_handle_t ph);

extern di_prom_prop_t	di_prom_prop_next(di_prom_handle_t ph, di_node_t node,
			    di_prom_prop_t prom_prop);

extern char		*di_prom_prop_name(di_prom_prop_t prom_prop);
extern int		di_prom_prop_data(di_prom_prop_t prop,
			    uchar_t **prom_prop_data);

extern int		di_prom_prop_lookup_ints(di_prom_handle_t prom,
			    di_node_t node, const char *prom_prop_name,
			    int **prom_prop_data);
extern int		di_prom_prop_lookup_strings(di_prom_handle_t prom,
			    di_node_t node, const char *prom_prop_name,
			    char **prom_prop_data);
extern int		di_prom_prop_lookup_bytes(di_prom_handle_t prom,
			    di_node_t node, const char *prom_prop_name,
			    uchar_t **prom_prop_data);

/*
 * path_node: property access
 */
extern di_path_prop_t	di_path_prop_next(di_path_t path, di_path_prop_t prop);

extern char		*di_path_prop_name(di_path_prop_t prop);
extern int		di_path_prop_type(di_path_prop_t prop);
extern int		di_path_prop_len(di_path_prop_t prop);

extern int		di_path_prop_bytes(di_path_prop_t prop,
			    uchar_t **prop_data);
extern int		di_path_prop_ints(di_path_prop_t prop,
			    int **prop_data);
extern int		di_path_prop_int64s(di_path_prop_t prop,
			    int64_t **prop_data);
extern int		di_path_prop_strings(di_path_prop_t prop,
			    char **prop_data);

extern int		di_path_prop_lookup_bytes(di_path_t path,
			    const char *prop_name, uchar_t **prop_data);
extern int		di_path_prop_lookup_ints(di_path_t path,
			    const char *prop_name, int **prop_data);
extern int		di_path_prop_lookup_int64s(di_path_t path,
			    const char *prop_name, int64_t **prop_data);
extern int		di_path_prop_lookup_strings(di_path_t path,
			    const char *prop_name, char **prop_data);

/*
 * layering link/lnode: traversal, data access, and parameters
 */
extern int		di_walk_link(di_node_t root, uint_t flag,
			    uint_t endpoint, void *arg,
			    int (*link_callback)(di_link_t link, void *arg));
extern int		di_walk_lnode(di_node_t root, uint_t flag, void *arg,
			    int (*lnode_callback)(di_lnode_t lnode, void *arg));

extern di_link_t	di_link_next_by_node(di_node_t node,
			    di_link_t link, uint_t endpoint);
extern di_link_t	di_link_next_by_lnode(di_lnode_t lnode,
			    di_link_t link, uint_t endpoint);
extern di_lnode_t	di_lnode_next(di_node_t node, di_lnode_t lnode);
extern char		*di_lnode_name(di_lnode_t lnode);

extern int		di_link_spectype(di_link_t link);
extern di_lnode_t	di_link_to_lnode(di_link_t link, uint_t endpoint);

extern di_node_t	di_lnode_devinfo(di_lnode_t lnode);
extern int		di_lnode_devt(di_lnode_t lnode, dev_t *devt);

extern void		di_link_private_set(di_link_t link, void *data);
extern void		*di_link_private_get(di_link_t link);
extern void		di_lnode_private_set(di_lnode_t lnode, void *data);
extern void		*di_lnode_private_get(di_lnode_t lnode);


/*
 * Private interfaces
 *
 * The interfaces and structures below are private to this implementation
 * of Solaris and are subject to change at any time without notice.
 *
 * Applications and drivers using these interfaces may fail
 * to run on future releases.
 */
extern di_prop_t di_prop_find(dev_t match_dev, di_node_t node,
    const char *name);
extern int di_devfs_path_match(const char *dp1, const char *dp2);

extern di_node_t	di_vhci_first_node(di_node_t root);
extern di_node_t	di_vhci_next_node(di_node_t node);
extern di_node_t	di_phci_first_node(di_node_t vhci_node);
extern di_node_t	di_phci_next_node(di_node_t node);

/*
 * Interfaces for handling IEEE 1275 and other standardized properties
 */

/* structure for a single slot */
typedef struct di_slot_name {
	int num;	/* corresponding pci device number */
	char *name;
} di_slot_name_t;

extern void di_slot_names_free(int count, di_slot_name_t *slot_names);
extern int di_slot_names_decode(uchar_t *rawdata, int rawlen,
    di_slot_name_t **prop_data);
extern int di_prop_slot_names(di_prop_t prop, di_slot_name_t **prop_data);
extern int di_prom_prop_slot_names(di_prom_prop_t prom_prop,
    di_slot_name_t **prop_data);
extern int di_prop_lookup_slot_names(dev_t dev, di_node_t node,
    di_slot_name_t **prop_data);
extern int di_prom_prop_lookup_slot_names(di_prom_handle_t ph, di_node_t node,
    di_slot_name_t **prop_data);

/*
 * XXX Remove the private di_path_(addr,next,next_phci,next_client) interfaces
 * below after NWS consolidation switches to using di_path_bus_addr,
 * di_path_phci_next_path, and di_path_client_next_path per CR6638521.
 */
extern char *di_path_addr(di_path_t path, char *buf);
extern di_path_t di_path_next(di_node_t node, di_path_t path);
extern di_path_t di_path_next_phci(di_node_t node, di_path_t path);
extern di_path_t di_path_next_client(di_node_t node, di_path_t path);

/*
 * Interfaces for private data
 */
extern di_node_t di_init_driver(const char *drv_name, uint_t flag);
extern di_node_t di_init_impl(const char *phys_path, uint_t flag,
    struct di_priv_data *priv_data);

/*
 * Prtconf needs to know property lists, raw prop_data, and private data
 */
extern di_prop_t di_prop_drv_next(di_node_t node, di_prop_t prop);
extern di_prop_t di_prop_sys_next(di_node_t node, di_prop_t prop);
extern di_prop_t di_prop_global_next(di_node_t node, di_prop_t prop);
extern di_prop_t di_prop_hw_next(di_node_t node, di_prop_t prop);

extern int di_prop_rawdata(di_prop_t prop, uchar_t **prop_data);
extern void *di_parent_private_data(di_node_t node);
extern void *di_driver_private_data(di_node_t node);

/*
 * The value of the dip's devi_flags field
 */
uint_t di_flags(di_node_t node);

/*
 * Types of links for devlink lookup
 */
#define	DI_PRIMARY_LINK		0x01
#define	DI_SECONDARY_LINK	0x02
#define	DI_LINK_TYPES		0x03

/*
 * Flag for di_devlink_init()
 */
#define	DI_MAKE_LINK	0x01

/*
 * Flag for di_devlink_close()
 */
#define	DI_LINK_ERROR	0x01

/*
 * For devfsadm synchronous link creation interfaces
 */
#define	DEVFSADM_SYNCH_DOOR	".devfsadm_synch_door"

/*
 * devlink create argument
 */
struct dca_off {
	uint32_t	dca_root;
	uint32_t	dca_minor;
	uint32_t	dca_driver;
	int		dca_error;
	int		dca_flags;
	char		dca_name[PATH_MAX+MAXNAMELEN];
};

extern di_devlink_handle_t di_devlink_init(const char *name, uint_t flags);
extern int di_devlink_walk(di_devlink_handle_t hdl, const char *re,
    const char *minor_path, uint_t flags, void *arg,
    int (*devlink_callback)(di_devlink_t, void *));
extern const char *di_devlink_path(di_devlink_t devlink);
extern const char *di_devlink_content(di_devlink_t devlink);
extern int di_devlink_type(di_devlink_t devlink);
extern di_devlink_t di_devlink_dup(di_devlink_t devlink);
extern int di_devlink_free(di_devlink_t devlink);
extern int di_devlink_fini(di_devlink_handle_t *hdlp);

extern di_devlink_handle_t di_devlink_open(const char *root_dir, uint_t flags);
extern int di_devlink_close(di_devlink_handle_t *pp, int flag);
extern int di_devlink_rm_link(di_devlink_handle_t hdp, const char *link);
extern int di_devlink_add_link(di_devlink_handle_t hdp, const char *link,
    const char *content, int flags);
extern int di_devlink_update(di_devlink_handle_t hdp);
extern di_devlink_handle_t di_devlink_init_root(const char *root,
    const char *name, uint_t flags);
extern int di_devlink_cache_walk(di_devlink_handle_t hdp, const char *re,
    const char *path, uint_t flags, void *arg,
    int (*devlink_callback)(di_devlink_t, void *));

/*
 * Private interfaces for I/O retire
 */
typedef struct di_retire {
	void	*rt_hdl;
	void	(*rt_abort)(void *hdl, const char *format, ...);
	void	(*rt_debug)(void *hdl, const char *format, ...);
} di_retire_t;

extern int di_retire_device(char *path, di_retire_t *dp, int flags);
extern int di_unretire_device(char *path, di_retire_t *dp);
extern uint_t di_retired(di_node_t node);

/*
 * Private interfaces for /etc/logindevperm
 */
extern int di_devperm_login(const char *, uid_t, gid_t, void (*)(char *));
extern int di_devperm_logout(const char *);

/*
 * Private interface for looking up, by path string, a node/path/minor
 * in a snapshot.
 */
extern di_path_t di_lookup_path(di_node_t root, char *path);
extern di_node_t di_lookup_node(di_node_t root, char *path);

/*
 * Private hotplug interfaces to be used between cfgadm pci plugin and
 * devfsadm link generator.
 */
extern char *di_dli_name(char *);
extern int di_dli_openr(char *);
extern int di_dli_openw(char *);
extern void di_dli_close(int);

/*
 * Private interface for parsing devname binding info
 */
extern void di_devname_print_mapinfo(nvlist_t *);
extern int di_devname_get_mapinfo(char *, nvlist_t **);
extern int di_devname_get_mapent(char *, char *, nvlist_t **);
extern int di_devname_action_on_key(nvlist_t *, uint8_t, char *, void *);

/*
 * Private interface for parsing path_to_inst binding file
 */
extern int devfs_parse_binding_file(const char *,
	int (*)(void *, const char *, int, const char *), void *);
extern int devfs_walk_minor_nodes(const char *,
	int (*)(void *, const char *), void *);

/*
 * finddev - alternate readdir to discover only /dev persisted device names
 */
typedef struct __finddevhdl *finddevhdl_t;

extern int		device_exists(const char *);
extern int		finddev_readdir(const char *, finddevhdl_t *);
extern int		finddev_emptydir(const char *);
extern void		finddev_close(finddevhdl_t);
extern const char	*finddev_next(finddevhdl_t);


/*
 * Private interfaces for non-global /dev profile
 */
typedef struct __di_prof	*di_prof_t;

extern int	di_prof_init(const char *mountpt, di_prof_t *);
extern void	di_prof_fini(di_prof_t);
extern int	di_prof_commit(di_prof_t);
extern int	di_prof_add_dev(di_prof_t, const char *);
extern int	di_prof_add_exclude(di_prof_t, const char *);
extern int	di_prof_add_symlink(di_prof_t, const char *, const char *);
extern int	di_prof_add_map(di_prof_t, const char *, const char *);

/*
 * Private interfaces for <driver><instance><minor> to path conversion.
 * NOTE: These interfaces do not require or cause attach.  The implementation
 * uses the kernel instance-tree (/etc/path_to_inst) and the di_devlinks
 * database information.
 */
typedef struct __di_dim	*di_dim_t;

extern di_dim_t	di_dim_init();
extern void	di_dim_fini(di_dim_t);
extern char	*di_dim_path_devices(di_dim_t,
		    char *drv_name, int instance, char *minor_name);
extern char	*di_dim_path_dev(di_dim_t,
		    char *drv_name, int instance, char *minor_name);


#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDEVINFO_H */
