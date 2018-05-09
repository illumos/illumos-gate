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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _LIBVARPD_IMPL_H
#define	_LIBVARPD_IMPL_H

/*
 * varpd internal interfaces
 */

#include <libvarpd.h>
#include <libvarpd_provider.h>
#include <sys/avl.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include <libidspace.h>
#include <umem.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	LIBVARPD_ID_MIN	1
#define	LIBVARPD_ID_MAX	INT32_MAX

typedef struct varpd_plugin {
	avl_node_t		vpp_node;
	const char		*vpp_name;
	overlay_target_mode_t	vpp_mode;
	const varpd_plugin_ops_t *vpp_ops;
	mutex_t			vpp_lock;
	uint_t			vpp_active;
} varpd_plugin_t;

typedef struct varpd_impl {
	mutex_t		vdi_lock;
	rwlock_t	vdi_pfdlock;
	avl_tree_t	vdi_plugins;	/* vdi_lock */
	avl_tree_t	vdi_instances;	/* vdi_lock */
	avl_tree_t	vdi_linstances;	/* vdi_lock */
	id_space_t	*vdi_idspace;	/* RO */
	umem_cache_t	*vdi_qcache;	/* RO */
	bunyan_logger_t	*vdi_bunyan;	/* RO */
	int		vdi_overlayfd;	/* RO */
	int		vdi_doorfd;	/* vdi_lock */
	int		vdi_persistfd;	/* vdi_plock */
	cond_t		vdi_lthr_cv;	/* vdi_lock */
	boolean_t	vdi_lthr_quiesce;	/* vdi_lock */
	uint_t		vdi_lthr_count;	/* vdi_lock */
} varpd_impl_t;

typedef enum varpd_instance_flags {
	VARPD_INSTANCE_F_ACTIVATED = 0x01
} varpd_instance_flags_t;

typedef struct varpd_instance {
	avl_node_t	vri_inode;
	avl_node_t	vri_lnode;
	uint64_t	vri_id;			/* RO */
	uint64_t	vri_vnetid;		/* RO */
	datalink_id_t	vri_linkid;		/* RO */
	overlay_target_mode_t vri_mode;		/* RO */
	overlay_plugin_dest_t vri_dest;		/* RO */
	varpd_impl_t	*vri_impl;		/* RO */
	varpd_plugin_t	*vri_plugin;		/* RO */
	void		*vri_private;		/* RO */
	mutex_t		vri_lock;
	varpd_instance_flags_t vri_flags;	/* vri_lock */
} varpd_instance_t;

typedef struct varpd_query {
	overlay_targ_lookup_t	vq_lookup;
	overlay_targ_resp_t	vq_response;
	varpd_instance_t	*vq_instance;
} varpd_query_t;

typedef struct varpd_client_create_arg {
	datalink_id_t	vcca_linkid;
	uint64_t	vcca_id;
	char		vcca_plugin[LIBVARPD_PROP_NAMELEN];
} varpd_client_create_arg_t;

typedef struct varpd_client_instance_arg {
	uint64_t	vcia_id;
} varpd_client_instance_arg_t;

typedef struct varpd_client_nprops_arg {
	uint64_t	vcna_id;
	uint_t		vcna_nprops;
	uint8_t		vcna_pad[4];
} varpd_client_nprops_arg_t;

typedef struct varpd_client_propinfo_arg {
	uint64_t	vcfa_id;
	uint_t		vcfa_propid;
	uint_t		vcfa_type;
	uint_t		vcfa_prot;
	uint32_t	vcfa_defsize;
	uint32_t	vcfa_psize;
	uint8_t		vcfa_pad[4];
	char		vcfa_name[LIBVARPD_PROP_NAMELEN];
	uint8_t		vcfa_default[LIBVARPD_PROP_SIZEMAX];
	uint8_t		vcfa_poss[LIBVARPD_PROP_SIZEMAX];
} varpd_client_propinfo_arg_t;

typedef struct varpd_client_prop_arg {
	uint64_t	vcpa_id;
	uint_t		vcpa_propid;
	uint8_t		vcpa_buf[LIBVARPD_PROP_SIZEMAX];
	size_t		vcpa_bufsize;
} varpd_client_prop_arg_t;

typedef struct varpd_client_lookup_arg {
	datalink_id_t	vcla_linkid;
	uint32_t	vcla_pad;
	uint64_t	vcla_id;
} varpd_client_lookup_arg_t;

typedef struct varpd_client_target_mode_arg {
	uint64_t	vtma_id;
	uint32_t	vtma_dest;
	uint32_t	vtma_mode;
} varpd_client_target_mode_arg_t;

typedef struct varpd_client_target_cache_arg {
	uint64_t	vtca_id;
	uint8_t		vtca_key[ETHERADDRL];
	uint8_t		vtca_pad[2];
	varpd_client_cache_entry_t vtca_entry;
} varpd_client_target_cache_arg_t;

typedef struct varpd_client_target_walk_arg {
	uint64_t	vtcw_id;
	uint64_t	vtcw_marker;
	uint64_t	vtcw_count;
	overlay_targ_cache_entry_t vtcw_ents[];
} varpd_client_target_walk_arg_t;

typedef enum varpd_client_command {
	VARPD_CLIENT_INVALID = 0x0,
	VARPD_CLIENT_CREATE,
	VARPD_CLIENT_ACTIVATE,
	VARPD_CLIENT_DESTROY,
	VARPD_CLIENT_NPROPS,
	VARPD_CLIENT_PROPINFO,
	VARPD_CLIENT_GETPROP,
	VARPD_CLIENT_SETPROP,
	VARPD_CLIENT_LOOKUP,
	VARPD_CLIENT_TARGET_MODE,
	VARPD_CLIENT_CACHE_FLUSH,
	VARPD_CLIENT_CACHE_DELETE,
	VARPD_CLIENT_CACHE_GET,
	VARPD_CLIENT_CACHE_SET,
	VARPD_CLIENT_CACHE_WALK,
	VARPD_CLIENT_MAX
} varpd_client_command_t;

typedef struct varpd_client_arg {
	uint_t	vca_command;
	uint_t	vca_errno;
	union {
		varpd_client_create_arg_t vca_create;
		varpd_client_instance_arg_t vca_instance;
		varpd_client_nprops_arg_t vca_nprops;
		varpd_client_propinfo_arg_t vca_info;
		varpd_client_prop_arg_t vca_prop;
		varpd_client_lookup_arg_t vca_lookup;
		varpd_client_target_mode_arg_t vca_mode;
		varpd_client_target_cache_arg_t vca_cache;
		varpd_client_target_walk_arg_t vca_walk;
	} vca_un;
} varpd_client_arg_t;

typedef struct varpd_client_eresp {
	uint_t vce_command;
	uint_t vce_errno;
} varpd_client_eresp_t;

extern void libvarpd_plugin_init(void);
extern void libvarpd_plugin_prefork(void);
extern void libvarpd_plugin_postfork(void);
extern void libvarpd_plugin_fini(void);
extern int libvarpd_plugin_comparator(const void *, const void *);
extern varpd_plugin_t *libvarpd_plugin_lookup(varpd_impl_t *, const char *);

extern varpd_instance_t *libvarpd_instance_lookup_by_dlid(varpd_impl_t *,
    datalink_id_t);

extern void libvarpd_prop_door_convert(const varpd_prop_handle_t *,
    varpd_client_propinfo_arg_t *);

extern const char *libvarpd_isaext(void);
typedef int (*libvarpd_dirwalk_f)(varpd_impl_t *, const char *, void *);
extern int libvarpd_dirwalk(varpd_impl_t *, const char *, const char *,
    libvarpd_dirwalk_f, void *);

extern int libvarpd_overlay_init(varpd_impl_t *);
extern void libvarpd_overlay_fini(varpd_impl_t *);
extern int libvarpd_overlay_info(varpd_impl_t *, datalink_id_t,
    overlay_plugin_dest_t *, uint64_t *, uint64_t *);
extern int libvarpd_overlay_associate(varpd_instance_t *);
extern int libvarpd_overlay_disassociate(varpd_instance_t *);
extern int libvarpd_overlay_degrade(varpd_instance_t *, const char *);
extern int libvarpd_overlay_degrade_datalink(varpd_impl_t *, datalink_id_t,
    const char *);
extern int libvarpd_overlay_restore(varpd_instance_t *);
extern int libvarpd_overlay_packet(varpd_impl_t *,
    const overlay_targ_lookup_t *, void *, size_t *);
extern int libvarpd_overlay_inject(varpd_impl_t *,
    const overlay_targ_lookup_t *, void *, size_t);
extern int libvarpd_overlay_instance_inject(varpd_instance_t *, void *, size_t);
extern int libvarpd_overlay_resend(varpd_impl_t *,
    const overlay_targ_lookup_t *, void *, size_t);
typedef int (*libvarpd_overlay_iter_f)(varpd_impl_t *, datalink_id_t, void *);
extern int libvarpd_overlay_iter(varpd_impl_t *, libvarpd_overlay_iter_f,
    void *);
extern int libvarpd_overlay_cache_flush(varpd_instance_t *);
extern int libvarpd_overlay_cache_delete(varpd_instance_t *, const uint8_t *);
extern int libvarpd_overlay_cache_delete(varpd_instance_t *, const uint8_t *);
extern int libvarpd_overlay_cache_get(varpd_instance_t *, const uint8_t *,
    varpd_client_cache_entry_t *);
extern int libvarpd_overlay_cache_set(varpd_instance_t *, const uint8_t *,
    const varpd_client_cache_entry_t *);
extern int libvarpd_overlay_cache_walk_fill(varpd_instance_t *, uint64_t *,
    uint64_t *, overlay_targ_cache_entry_t *);

extern void libvarpd_persist_init(varpd_impl_t *);
extern void libvarpd_persist_fini(varpd_impl_t *);
extern int libvarpd_persist_instance(varpd_impl_t *, varpd_instance_t *);
extern void libvarpd_torch_instance(varpd_impl_t *,  varpd_instance_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_IMPL_H */
