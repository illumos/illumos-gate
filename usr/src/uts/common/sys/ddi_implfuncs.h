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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

#ifndef _SYS_DDI_IMPLFUNCS_H
#define	_SYS_DDI_IMPLFUNCS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/obpdefs.h>
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/task.h>
#include <sys/project.h>

#ifdef	_KERNEL

/*
 * Declare implementation functions that sunddi functions can call in order to
 * perform their required task.  Each kernel architecture must provide them.
 */
extern int i_ddi_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp);
extern int i_ddi_apply_range(dev_info_t *dip, dev_info_t *rdip,
    struct regspec *rp);
extern struct regspec *i_ddi_rnumber_to_regspec(dev_info_t *dip, int rnumber);
extern int i_ddi_map_fault(dev_info_t *dip, dev_info_t *rdip,
    struct hat *hat, struct seg *seg, caddr_t addr,
    struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock);

/*
 * Implementation-specific memory allocation and de-allocation routines
 */
extern int i_ddi_mem_alloc(dev_info_t *dip, ddi_dma_attr_t *attributes,
    size_t length, int cansleep, int streaming,
    ddi_device_acc_attr_t *accattrp, caddr_t *kaddrp,
    size_t *real_length, ddi_acc_hdl_t *handlep);
extern void i_ddi_mem_free(caddr_t kaddr, ddi_acc_hdl_t *ap);

extern int i_ddi_devi_get_ppa(dev_info_t *);
extern void i_ddi_devi_set_ppa(dev_info_t *, int);

extern void i_ddi_devacc_to_hatacc(ddi_device_acc_attr_t *devaccp,
    uint_t *hataccp);
extern void i_ddi_cacheattr_to_hatacc(uint_t flags, uint_t *hataccp);
extern boolean_t i_ddi_check_cache_attr(uint_t flags);

/*
 * Access and DMA handle fault set/clear routines
 */
extern void i_ddi_acc_set_fault(ddi_acc_handle_t handle);
extern void i_ddi_acc_clr_fault(ddi_acc_handle_t handle);
extern void i_ddi_dma_set_fault(ddi_dma_handle_t handle);
extern void i_ddi_dma_clr_fault(ddi_dma_handle_t handle);

/*
 * Event-handling functions for rootnex.
 * These provide the standard implementation of fault handling.
 */
extern void i_ddi_rootnex_init_events(dev_info_t *);
extern int i_ddi_rootnex_get_eventcookie(dev_info_t *, dev_info_t *, char *,
    ddi_eventcookie_t *);
extern int i_ddi_rootnex_add_eventcall(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void (*)(dev_info_t *, ddi_eventcookie_t, void *,
    void *), void *, ddi_callback_id_t *);
extern int i_ddi_rootnex_remove_eventcall(dev_info_t *, ddi_callback_id_t);
extern int i_ddi_rootnex_post_event(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void *);

/*
 * Search and return properties from the PROM
 */
extern int impl_ddi_bus_prop_op(dev_t, dev_info_t *, dev_info_t *,
    ddi_prop_op_t, int, char *, caddr_t, int *);

/*
 * Copy an integer from PROM to native machine representation
 */
extern int impl_ddi_prop_int_from_prom(uchar_t *intp, int n);

extern int impl_ddi_sunbus_initchild(dev_info_t *);
extern void impl_ddi_sunbus_removechild(dev_info_t *);

/*
 * Implementation-specific access handle allocator and init. routines
 */
extern ddi_acc_handle_t impl_acc_hdl_alloc(int (*waitfp)(caddr_t),
    caddr_t arg);
extern void impl_acc_hdl_free(ddi_acc_handle_t handle);
extern ddi_acc_hdl_t *impl_acc_hdl_get(ddi_acc_handle_t handle);
extern void impl_acc_hdl_init(ddi_acc_hdl_t *hp);

/*
 * Access error handling support
 */
extern void impl_acc_err_init(ddi_acc_hdl_t *);
extern int impl_dma_check(dev_info_t *, const void *, const void *,
    const void *);
extern int i_ddi_ontrap(ddi_acc_handle_t);
extern void i_ddi_notrap(ddi_acc_handle_t);
extern int i_ddi_prot_trampoline(void);
extern int i_ddi_caut_trampoline(void);

/*
 * misc/bootdev entry points - these are private routines and subject
 * to change
 */
extern int i_devname_to_promname(char *dev_name, char *ret_buf, size_t);
extern int i_promname_to_devname(char *prom_name, char *ret_buf);
extern char *i_convert_boot_device_name(char *, char *, size_t *);

/*
 * Nodeid management
 */
extern void impl_ddi_init_nodeid(void);
extern int impl_ddi_alloc_nodeid(int *);
extern int impl_ddi_take_nodeid(int, int);
extern void impl_ddi_free_nodeid(int);

/*
 * minorname/devtspectype conversions
 */
extern char *i_ddi_devtspectype_to_minorname(dev_info_t *, dev_t, int);
extern int i_ddi_minorname_to_devtspectype(dev_info_t *, char *, dev_t *,
    int *);

/*
 * Routines in ddi_v9_asm.s
 */
extern int do_peek(size_t, void *, void *);
extern int do_poke(size_t, void *, void *);
extern void peek_fault(void);
extern void poke_fault(void);
extern int peekpoke_mem(ddi_ctl_enum_t, peekpoke_ctlops_t *);

/*
 * Helper functions
 */
extern char *i_ddi_strdup(char *, uint_t);
extern void i_ddi_prop_list_delete(ddi_prop_t *);
extern ddi_prop_t *i_ddi_prop_list_dup(ddi_prop_t *, uint_t);
extern int i_ddi_load_drvconf(major_t);
extern int i_ddi_unload_drvconf(major_t);
extern ddi_node_state_t i_ddi_node_state(dev_info_t *);
extern int i_ddi_devi_attached(dev_info_t *);
extern void i_ddi_parse_name(char *, char **, char **, char **);
extern void i_ddi_set_node_state(dev_info_t *, ddi_node_state_t);
extern int i_ddi_detach_installed_driver(major_t, int);
extern void i_ddi_set_binding_name(dev_info_t *, char *);
extern void i_ddi_bind_devs(void);
extern int i_ddi_unbind_devs_by_alias(major_t, char *);
extern void i_ddi_unbind_devs(major_t);
extern ddi_prop_list_t *i_ddi_prop_list_create(ddi_prop_t *);
struct devnames;
extern void i_ddi_prop_list_hold(ddi_prop_list_t *, struct devnames *);
extern void i_ddi_prop_list_rele(ddi_prop_list_t *, struct devnames *);
extern ddi_prop_t *i_ddi_prop_search(dev_t, char *, uint_t, ddi_prop_t **);
extern int resolve_pathname(char *, dev_info_t **, dev_t *, int *);
extern int i_ddi_prompath_to_devfspath(char *, char *);
extern int i_ddi_attach_node_hierarchy(dev_info_t *);
extern dev_info_t *i_ddi_attach_pseudo_node(char *);
extern int i_ddi_attach_hw_nodes(char *);
extern int i_ddi_devs_attached(major_t);
extern int i_ddi_minor_node_count(dev_info_t *, const char *);
extern int ddi_is_pci_dip(dev_info_t *dip);

/*
 * Non-DDI functions: wrapper around mod_hold/rele_dev_by_major()
 */
extern struct dev_ops *ddi_hold_driver(major_t);
extern void ddi_rele_driver(major_t);

/*
 * /etc/devices cache files management
 */
extern void i_ddi_devices_init(void);
extern void i_ddi_read_devices_files(void);
extern void i_ddi_clean_devices_files(void);

/*
 * devid cache
 */
extern void devid_cache_init(void);
extern void devid_cache_read(void);
extern void devid_cache_cleanup(void);
extern int i_ddi_devi_get_devid(dev_t, dev_info_t *, ddi_devid_t *);
extern int e_ddi_devid_discovery(ddi_devid_t);
extern int e_devid_cache_register(dev_info_t *, ddi_devid_t);
extern void e_devid_cache_unregister(dev_info_t *);
extern int e_devid_cache_to_devt_list(ddi_devid_t, char *, int *, dev_t **);
extern void e_devid_cache_free_devt_list(int, dev_t *);

/*
 * I/O retire persistent store
 */
extern void retire_store_init(void);
extern void retire_store_read(void);
extern int e_ddi_retire_persist(char *);
extern int e_ddi_retire_unpersist(char *);
extern int e_ddi_device_retired(char *);

/*
 * Resource control functions to lock down device memory
 */
extern int i_ddi_incr_locked_memory(proc_t *, rctl_qty_t);
extern void i_ddi_decr_locked_memory(proc_t *, rctl_qty_t);

/*
 * Direct I/O support functions
 */
extern void translate_devid(dev_info_t *dip);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_IMPLFUNCS_H */
