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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SUNMDI_H
#define	_SYS_SUNMDI_H

/*
 * Multiplexed I/O global include
 */

#include <sys/note.h>
#include <sys/esunddi.h>
#include <sys/sunddi.h>
#include <sys/ddipropdefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Most MDI functions return success or failure
 */
#define	MDI_SUCCESS		0	/* Call Success */
#define	MDI_FAILURE		-1	/* Unspecified Error */
#define	MDI_NOMEM		-2	/* No resources available */
#define	MDI_ACCEPT		-3	/* Request accepted */
#define	MDI_BUSY		-4	/* Busy */
#define	MDI_NOPATH		-5	/* No more paths are available */
#define	MDI_EINVAL		-6	/* Invalid parameter */
#define	MDI_NOT_SUPPORTED	-8	/* Device not supported */
#define	MDI_DEVI_ONLINING	-9	/* Devi is onlining */

/*
 * handle to mdi_pathinfo node
 */
typedef struct x_mdi_pathinfo *mdi_pathinfo_t;

/*
 * Path info node state definitions
 */
typedef enum {
	MDI_PATHINFO_STATE_INIT,
	MDI_PATHINFO_STATE_ONLINE,
	MDI_PATHINFO_STATE_STANDBY,
	MDI_PATHINFO_STATE_FAULT,
	MDI_PATHINFO_STATE_OFFLINE
} mdi_pathinfo_state_t;

/*
 * MDI vHCI class definitions
 */
#define	MDI_HCI_CLASS_SCSI	"scsi_vhci"
#define	MDI_HCI_CLASS_IB	"ib"

#ifdef _KERNEL

/*
 * mpxio component definitions:  Every registered component of the
 * mpxio system has a "mpxio-component" property attached to it.
 * Identify its function
 */
#define	MDI_COMPONENT_NONE	0
#define	MDI_COMPONENT_VHCI	0x1
#define	MDI_COMPONENT_PHCI	0x2
#define	MDI_COMPONENT_CLIENT	0x4

/*
 * mdi_pathinfo node state utility definitions (bits in mdi_pathinfo_state_t)
 *
 * NOTE: having mdi_pathinfo_state_t contain both state and flags is error
 * prone.  For new flags, please consider using MDI_PATHINFO_FLAG_ (and
 * moving existing EXT_STATE_MASK flags over would be good too).
 */
#define	MDI_PATHINFO_STATE_TRANSIENT			0x00010000
#define	MDI_PATHINFO_STATE_USER_DISABLE			0x00100000
#define	MDI_PATHINFO_STATE_DRV_DISABLE			0x00200000
#define	MDI_PATHINFO_STATE_DRV_DISABLE_TRANSIENT	0x00400000
#define	MDI_PATHINFO_STATE_MASK				0x0000FFFF
#define	MDI_PATHINFO_EXT_STATE_MASK			0xFFF00000

/*
 * mdi_pathinfo flags definitions
 */
#define	MDI_PATHINFO_FLAGS_HIDDEN			0x00000001
#define	MDI_PATHINFO_FLAGS_DEVICE_REMOVED		0x00000002

#define	USER_DISABLE			1
#define	DRIVER_DISABLE			2
#define	DRIVER_DISABLE_TRANSIENT	3


/*
 * Most MDI functions return success or failure
 */
#define	MDI_SUCCESS		0	/* Call Success			*/
#define	MDI_FAILURE		-1	/* Unspecified Error		*/
#define	MDI_NOMEM		-2	/* No resources available	*/
#define	MDI_ACCEPT		-3	/* Request accepted		*/
#define	MDI_BUSY		-4	/* Busy				*/
#define	MDI_NOPATH		-5	/* No more paths are available	*/
#define	MDI_EINVAL		-6	/* Invalid parameter		*/
#define	MDI_NOT_SUPPORTED	-8	/* Device not supported		*/
#define	MDI_DEVI_ONLINING	-9	/* Devi is onlining		*/

/*
 * MDI operation vector structure definition
 */
#define	MDI_OPS_REV_1			1
#define	MDI_OPS_REV			MDI_OPS_REV_1

#define	MDI_VHCI(dip)	(DEVI(dip)->devi_mdi_component & MDI_COMPONENT_VHCI)
#define	MDI_PHCI(dip)	(DEVI(dip)->devi_mdi_component & MDI_COMPONENT_PHCI)
#define	MDI_CLIENT(dip)	(DEVI(dip)->devi_mdi_component & MDI_COMPONENT_CLIENT)

/*
 * MDI device hotplug notification
 */
int mdi_devi_online(dev_info_t *, uint_t);
int mdi_devi_offline(dev_info_t *, uint_t);

/*
 * MDI path retire interfaces
 */
void mdi_phci_mark_retiring(dev_info_t *dip, char **cons_array);
void mdi_phci_retire_notify(dev_info_t *dip, int *constraint);
void mdi_phci_retire_finalize(dev_info_t *dip, int phci_only, void *constraint);
void mdi_phci_unretire(dev_info_t *dip);

/*
 * MDI devinfo locking functions.
 */
void mdi_devi_enter(dev_info_t *, int *);
int mdi_devi_tryenter(dev_info_t *, int *);
void mdi_devi_exit_phci(dev_info_t *, int);
void mdi_devi_enter_phci(dev_info_t *, int *);
void mdi_devi_exit(dev_info_t *, int);

/*
 * MDI device support functions.
 */
dev_info_t *mdi_devi_get_vdip(dev_info_t *);
int mdi_devi_pdip_entered(dev_info_t *);

/*
 * MDI component device instance attach/detach notification
 */
int mdi_pre_attach(dev_info_t *, ddi_attach_cmd_t);
void mdi_post_attach(dev_info_t *, ddi_attach_cmd_t, int);
int mdi_pre_detach(dev_info_t *, ddi_detach_cmd_t);
void mdi_post_detach(dev_info_t *, ddi_detach_cmd_t, int);

/*
 * mdi_pathinfo management functions.
 *
 * Find, allocate and Free functions.
 */
mdi_pathinfo_t *mdi_pi_find(dev_info_t *, char *, char *);
int mdi_pi_alloc(dev_info_t *, char *, char *, char *, int, mdi_pathinfo_t **);
int mdi_pi_alloc_compatible(dev_info_t *, char *, char *, char *,
	char **, int, int, mdi_pathinfo_t **);
int mdi_pi_free(mdi_pathinfo_t *, int);

void mdi_hold_path(mdi_pathinfo_t *);
void mdi_rele_path(mdi_pathinfo_t *);

/*
 * mdi_pathinfo node state change functions.
 */
int mdi_pi_online(mdi_pathinfo_t *, int);
int mdi_pi_standby(mdi_pathinfo_t *, int);
int mdi_pi_fault(mdi_pathinfo_t *, int);
int mdi_pi_offline(mdi_pathinfo_t *, int);
/*
 * NOTE: the next 2 interfaces will be removed once the NWS files are
 * changed to use the new mdi_{enable,disable}_path interfaces
 */
int mdi_pi_disable(dev_info_t *, dev_info_t *, int);
int mdi_pi_enable(dev_info_t *, dev_info_t *, int);
int mdi_pi_disable_path(mdi_pathinfo_t *, int);
int mdi_pi_enable_path(mdi_pathinfo_t *, int);

int mdi_pi_ishidden(mdi_pathinfo_t *);

int mdi_pi_device_isremoved(mdi_pathinfo_t *);
int mdi_pi_device_remove(mdi_pathinfo_t *);
int mdi_pi_device_insert(mdi_pathinfo_t *);

/*
 * MPxIO-PM stuff
 */
typedef enum {
	MDI_PM_PRE_CONFIG = 0,
	MDI_PM_POST_CONFIG,
	MDI_PM_PRE_UNCONFIG,
	MDI_PM_POST_UNCONFIG,
	MDI_PM_HOLD_POWER,
	MDI_PM_RELE_POWER
} mdi_pm_op_t;

int
mdi_bus_power(dev_info_t *, void *, pm_bus_power_op_t, void *, void *);

int
mdi_power(dev_info_t *, mdi_pm_op_t, void *, char *, int);

/*
 * mdi_pathinfo node walker function.
 */
int mdi_component_is_vhci(dev_info_t *, const char **);
int mdi_component_is_phci(dev_info_t *, const char **);
int mdi_component_is_client(dev_info_t *, const char **);
mdi_pathinfo_t *mdi_get_next_phci_path(dev_info_t *, mdi_pathinfo_t *);
mdi_pathinfo_t *mdi_get_next_client_path(dev_info_t *, mdi_pathinfo_t *);

/*
 * mdi_pathinfo node member functions
 */
void mdi_pi_lock(mdi_pathinfo_t *);
void mdi_pi_unlock(mdi_pathinfo_t *);
dev_info_t *mdi_pi_get_client(mdi_pathinfo_t *);
dev_info_t *mdi_pi_get_phci(mdi_pathinfo_t *);
char *mdi_pi_get_node_name(mdi_pathinfo_t *);
char *mdi_pi_get_addr(mdi_pathinfo_t *);
mdi_pathinfo_state_t mdi_pi_get_state(mdi_pathinfo_t *);
uint_t mdi_pi_get_flags(mdi_pathinfo_t *);
int mdi_pi_get_path_instance(mdi_pathinfo_t *);
char *mdi_pi_pathname_by_instance(int);
char *mdi_pi_pathname(mdi_pathinfo_t *);
char *mdi_pi_pathname_obp(mdi_pathinfo_t *, char *);
int mdi_pi_pathname_obp_set(mdi_pathinfo_t *, char *);
char *mdi_pi_spathname_by_instance(int);
char *mdi_pi_spathname(mdi_pathinfo_t *);

/*
 * mdi_pathinfo Property handling functions
 */
int mdi_prop_remove(mdi_pathinfo_t *, char *);
int mdi_prop_update_byte_array(mdi_pathinfo_t *, char *, uchar_t *, uint_t);
int mdi_prop_update_int(mdi_pathinfo_t *, char *, int);
int mdi_prop_update_int64(mdi_pathinfo_t *, char *, int64_t);
int mdi_prop_update_int_array(mdi_pathinfo_t *, char *, int *, uint_t);
int mdi_prop_update_string(mdi_pathinfo_t *, char *, char *);
int mdi_prop_update_string_array(mdi_pathinfo_t *, char *, char **, uint_t);
nvpair_t *mdi_pi_get_next_prop(mdi_pathinfo_t *, nvpair_t *);

int mdi_prop_lookup_byte_array(mdi_pathinfo_t *, char *, uchar_t **, uint_t *);
int mdi_prop_lookup_int(mdi_pathinfo_t *, char *, int *);
int mdi_prop_lookup_int64(mdi_pathinfo_t *, char *, int64_t *);
int mdi_prop_lookup_int_array(mdi_pathinfo_t *, char *, int **, uint_t *);
int mdi_prop_lookup_string(mdi_pathinfo_t *, char *, char **);
int mdi_prop_lookup_string_array(mdi_pathinfo_t *, char *, char ***, uint_t *);
int mdi_prop_free(void *);

/*
 * pHCI driver instance registration/unregistration
 *
 * mdi_phci_register() is called by a pHCI drivers to register itself as a
 * transport provider for a specific 'class' (see mdi_vhci_register() above);
 * it should be called from attach(9e).
 *
 * mdi_phci_unregister() is called from detach(9e) to unregister a pHCI
 * instance from the framework.
 */
int		mdi_phci_register(char *, dev_info_t *, int);
int		mdi_phci_unregister(dev_info_t *, int);

/* get set phci private data */
caddr_t mdi_pi_get_phci_private(mdi_pathinfo_t *);
void mdi_pi_set_phci_private(mdi_pathinfo_t *, caddr_t);

int mdi_vhci_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t, void *,
    dev_info_t **, char *);

/*
 * mdi_vhci node walker function
 */
void mdi_walk_vhcis(int (*f)(dev_info_t *, void *), void *arg);

/*
 * mdi_phci node walker function
 */
void mdi_vhci_walk_phcis(dev_info_t *, int (*f)(dev_info_t *, void *),
    void *arg);

/*
 * mdi_client node walker function
 */
void mdi_vhci_walk_clients(dev_info_t *, int (*f)(dev_info_t *, void *),
    void *arg);

/*
 * MDI PHCI driver list helper functions
 */
char **mdi_get_phci_driver_list(char *vhci_class, int	*ndrivers);
void mdi_free_phci_driver_list(char **driver_list, int ndrivers);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNMDI_H */
