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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * tavor.c
 *    Tavor (InfiniBand) HCA Driver attach/detach Routines
 *
 *    Implements all the routines necessary for the attach, setup,
 *    initialization (and subsequent possible teardown and detach) of the
 *    Tavor InfiniBand HCA driver.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/bitmap.h>
#include <sys/policy.h>

#include <sys/ib/adapters/tavor/tavor.h>
#include <sys/pci.h>

/* Tavor HCA State Pointer */
void *tavor_statep;

/*
 * The Tavor "userland resource database" is common to instances of the
 * Tavor HCA driver.  This structure "tavor_userland_rsrc_db" contains all
 * the necessary information to maintain it.
 */
tavor_umap_db_t tavor_userland_rsrc_db;

static int tavor_attach(dev_info_t *, ddi_attach_cmd_t);
static int tavor_detach(dev_info_t *, ddi_detach_cmd_t);
static int tavor_open(dev_t *, int, int, cred_t *);
static int tavor_close(dev_t, int, int, cred_t *);
static int tavor_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int tavor_drv_init(tavor_state_t *state, dev_info_t *dip, int instance);
static void tavor_drv_fini(tavor_state_t *state);
static void tavor_drv_fini2(tavor_state_t *state);
static int tavor_isr_init(tavor_state_t *state);
static void tavor_isr_fini(tavor_state_t *state);
static int tavor_hw_init(tavor_state_t *state);
static void tavor_hw_fini(tavor_state_t *state,
    tavor_drv_cleanup_level_t cleanup);
static int tavor_soft_state_init(tavor_state_t *state);
static void tavor_soft_state_fini(tavor_state_t *state);
static int tavor_hca_port_init(tavor_state_t *state);
static int tavor_hca_ports_shutdown(tavor_state_t *state, uint_t num_init);
static void tavor_hca_config_setup(tavor_state_t *state,
    tavor_hw_initqueryhca_t *inithca);
static int tavor_internal_uarpgs_init(tavor_state_t *state);
static void tavor_internal_uarpgs_fini(tavor_state_t *state);
static int tavor_special_qp_contexts_reserve(tavor_state_t *state);
static void tavor_special_qp_contexts_unreserve(tavor_state_t *state);
static int tavor_sw_reset(tavor_state_t *state);
static int tavor_mcg_init(tavor_state_t *state);
static void tavor_mcg_fini(tavor_state_t *state);
static int tavor_fw_version_check(tavor_state_t *state);
static void tavor_device_info_report(tavor_state_t *state);
static void tavor_pci_capability_list(tavor_state_t *state,
    ddi_acc_handle_t hdl);
static void tavor_pci_capability_vpd(tavor_state_t *state,
    ddi_acc_handle_t hdl, uint_t offset);
static int tavor_pci_read_vpd(ddi_acc_handle_t hdl, uint_t offset,
    uint32_t addr, uint32_t *data);
static void tavor_pci_capability_pcix(tavor_state_t *state,
    ddi_acc_handle_t hdl, uint_t offset);
static int tavor_intr_or_msi_init(tavor_state_t *state);
static int tavor_add_intrs(tavor_state_t *state, int intr_type);
static int tavor_intr_or_msi_fini(tavor_state_t *state);

/* X86 fastreboot support */
static int tavor_intr_disable(tavor_state_t *);
static int tavor_quiesce(dev_info_t *);

/* Character/Block Operations */
static struct cb_ops tavor_cb_ops = {
	tavor_open,		/* open */
	tavor_close,		/* close */
	nodev,			/* strategy (block) */
	nodev,			/* print (block) */
	nodev,			/* dump (block) */
	nodev,			/* read */
	nodev,			/* write */
	tavor_ioctl,		/* ioctl */
	tavor_devmap,		/* devmap */
	NULL,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streams */
	D_NEW | D_MP |
	D_64BIT | D_HOTPLUG |
	D_DEVMAP,		/* flags */
	CB_REV			/* rev */
};

/* Driver Operations */
static struct dev_ops tavor_ops = {
	DEVO_REV,		/* struct rev */
	0,			/* refcnt */
	tavor_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	tavor_attach,		/* attach */
	tavor_detach,		/* detach */
	nodev,			/* reset */
	&tavor_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	nodev,			/* power */
	tavor_quiesce,		/* devo_quiesce */
};

/* Module Driver Info */
static struct modldrv tavor_modldrv = {
	&mod_driverops,
	"Tavor InfiniBand HCA Driver",
	&tavor_ops
};

/* Module Linkage */
static struct modlinkage tavor_modlinkage = {
	MODREV_1,
	&tavor_modldrv,
	NULL
};

/*
 * This extern refers to the ibc_operations_t function vector that is defined
 * in the tavor_ci.c file.
 */
extern ibc_operations_t	tavor_ibc_ops;

#ifndef NPROBE
extern int tnf_mod_load(void);
extern int tnf_mod_unload(struct modlinkage *mlp);
#endif


/*
 * _init()
 */
int
_init()
{
	int	status;

#ifndef NPROBE
	(void) tnf_mod_load();
#endif
	TAVOR_TNF_ENTER(tavor_init);

	status = ddi_soft_state_init(&tavor_statep, sizeof (tavor_state_t),
	    (size_t)TAVOR_INITIAL_STATES);
	if (status != 0) {
		TNF_PROBE_0(tavor_init_ssi_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_init);
#ifndef NPROBE
		(void) tnf_mod_unload(&tavor_modlinkage);
#endif
		return (status);
	}

	status = ibc_init(&tavor_modlinkage);
	if (status != 0) {
		TNF_PROBE_0(tavor_init_ibc_init_fail, TAVOR_TNF_ERROR, "");
		ddi_soft_state_fini(&tavor_statep);
		TAVOR_TNF_EXIT(tavor_init);
#ifndef NPROBE
		(void) tnf_mod_unload(&tavor_modlinkage);
#endif
		return (status);
	}
	status = mod_install(&tavor_modlinkage);
	if (status != 0) {
		TNF_PROBE_0(tavor_init_modi_fail, TAVOR_TNF_ERROR, "");
		ibc_fini(&tavor_modlinkage);
		ddi_soft_state_fini(&tavor_statep);
		TAVOR_TNF_EXIT(tavor_init);
#ifndef NPROBE
		(void) tnf_mod_unload(&tavor_modlinkage);
#endif
		return (status);
	}

	/* Initialize the Tavor "userland resources database" */
	tavor_umap_db_init();

	TAVOR_TNF_EXIT(tavor_init);
	return (status);
}


/*
 * _info()
 */
int
_info(struct modinfo *modinfop)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_info);
	status = mod_info(&tavor_modlinkage, modinfop);
	TAVOR_TNF_EXIT(tavor_info);
	return (status);
}


/*
 * _fini()
 */
int
_fini()
{
	int	status;

	TAVOR_TNF_ENTER(tavor_fini);

	status = mod_remove(&tavor_modlinkage);
	if (status != 0) {
		TNF_PROBE_0(tavor_fini_modr_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_fini);
		return (status);
	}

	/* Destroy the Tavor "userland resources database" */
	tavor_umap_db_fini();

	ibc_fini(&tavor_modlinkage);
	ddi_soft_state_fini(&tavor_statep);
#ifndef NPROBE
	(void) tnf_mod_unload(&tavor_modlinkage);
#endif
	TAVOR_TNF_EXIT(tavor_fini);
	return (status);
}


/*
 * tavor_getinfo()
 */
/* ARGSUSED */
static int
tavor_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t		dev;
	tavor_state_t	*state;
	minor_t		instance;

	TAVOR_TNF_ENTER(tavor_getinfo);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = TAVOR_DEV_INSTANCE(dev);
		state = ddi_get_soft_state(tavor_statep, instance);
		if (state == NULL) {
			TNF_PROBE_0(tavor_getinfo_gss_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_getinfo);
			return (DDI_FAILURE);
		}
		*result = (void *)state->ts_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = TAVOR_DEV_INSTANCE(dev);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		TNF_PROBE_0(tavor_getinfo_default_fail, TAVOR_TNF_ERROR, "");
		break;
	}

	TAVOR_TNF_EXIT(tavor_getinfo);
	return (DDI_FAILURE);
}


/*
 * tavor_open()
 */
/* ARGSUSED */
static int
tavor_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	tavor_state_t		*state;
	tavor_rsrc_t		*rsrcp;
	tavor_umap_db_entry_t	*umapdb, *umapdb2;
	minor_t			instance;
	uint64_t		key, value;
	uint_t			tr_indx;
	dev_t			dev;
	int			status;

	TAVOR_TNF_ENTER(tavor_open);

	instance = TAVOR_DEV_INSTANCE(*devp);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		TNF_PROBE_0(tavor_open_gss_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_open);
		return (ENXIO);
	}

	/*
	 * Only allow driver to be opened for character access, and verify
	 * whether exclusive access is allowed.
	 */
	if ((otyp != OTYP_CHR) || ((flag & FEXCL) &&
	    secpolicy_excl_open(credp) != 0)) {
		TNF_PROBE_0(tavor_open_invflags_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_open);
		return (EINVAL);
	}

	/*
	 * Search for the current process PID in the "userland resources
	 * database".  If it is not found, then attempt to allocate a UAR
	 * page and add the ("key", "value") pair to the database.
	 * Note:  As a last step we always return a devp appropriate for
	 * the open.  Either we return a new minor number (based on the
	 * instance and the UAR page index) or we return the current minor
	 * number for the given client process.
	 *
	 * We also add an entry to the database to allow for lookup from
	 * "dev_t" to the current process PID.  This is necessary because,
	 * under certain circumstance, the process PID that calls the Tavor
	 * close() entry point may not be the same as the one who called
	 * open().  Specifically, this can happen if a child process calls
	 * the Tavor's open() entry point, gets a UAR page, maps it out (using
	 * mmap()), and then exits without calling munmap().  Because mmap()
	 * adds a reference to the file descriptor, at the exit of the child
	 * process the file descriptor is "inherited" by the parent (and will
	 * be close()'d by the parent's PID only when it exits).
	 *
	 * Note: We use the tavor_umap_db_find_nolock() and
	 * tavor_umap_db_add_nolock() database access routines below (with
	 * an explicit mutex_enter of the database lock - "tdl_umapdb_lock")
	 * to ensure that the multiple accesses (in this case searching for,
	 * and then adding _two_ database entries) can be done atomically.
	 */
	key = ddi_get_pid();
	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	status = tavor_umap_db_find_nolock(instance, key,
	    MLNX_UMAP_UARPG_RSRC, &value, 0, NULL);
	if (status != DDI_SUCCESS) {
		/*
		 * If we are in 'maintenance mode', we cannot alloc a UAR page.
		 * But we still need some rsrcp value, and a mostly unique
		 * tr_indx value.  So we set rsrcp to NULL for maintenance
		 * mode, and use a rolling count for tr_indx.  The field
		 * 'ts_open_tr_indx' is used only in this maintenance mode
		 * condition.
		 *
		 * Otherwise, if we are in operational mode then we allocate
		 * the UAR page as normal, and use the rsrcp value and tr_indx
		 * value from that allocation.
		 */
		if (!TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
			rsrcp = NULL;
			tr_indx = state->ts_open_tr_indx++;
		} else {
			/* Allocate a new UAR page for this process */
			status = tavor_rsrc_alloc(state, TAVOR_UARPG, 1,
			    TAVOR_NOSLEEP, &rsrcp);
			if (status != DDI_SUCCESS) {
				mutex_exit(
				    &tavor_userland_rsrc_db.tdl_umapdb_lock);
				TNF_PROBE_0(tavor_open_rsrcalloc_uarpg_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_open);
				return (EAGAIN);
			}

			tr_indx = rsrcp->tr_indx;
		}

		/*
		 * Allocate an entry to track the UAR page resource in the
		 * "userland resources database".
		 */
		umapdb = tavor_umap_db_alloc(instance, key,
		    MLNX_UMAP_UARPG_RSRC, (uint64_t)(uintptr_t)rsrcp);
		if (umapdb == NULL) {
			mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
			/* If in "maintenance mode", don't free the rsrc */
			if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
				tavor_rsrc_free(state, &rsrcp);
			}
			TNF_PROBE_0(tavor_open_umap_db_alloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_open);
			return (EAGAIN);
		}

		/*
		 * Create a new device number.  Minor number is a function of
		 * the UAR page index (15 bits) and the device instance number
		 * (3 bits).
		 */
		dev = makedevice(getmajor(*devp), (tr_indx <<
		    TAVOR_MINORNUM_SHIFT) | instance);

		/*
		 * Allocate another entry in the "userland resources database"
		 * to track the association of the device number (above) to
		 * the current process ID (in "key").
		 */
		umapdb2 = tavor_umap_db_alloc(instance, dev,
		    MLNX_UMAP_PID_RSRC, (uint64_t)key);
		if (umapdb2 == NULL) {
			mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);
			tavor_umap_db_free(umapdb);
			/* If in "maintenance mode", don't free the rsrc */
			if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
				tavor_rsrc_free(state, &rsrcp);
			}
			TNF_PROBE_0(tavor_open_umap_db_alloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_open);
			return (EAGAIN);
		}

		/* Add the entries to the database */
		tavor_umap_db_add_nolock(umapdb);
		tavor_umap_db_add_nolock(umapdb2);

	} else {
		/*
		 * Return the same device number as on the original open()
		 * call.  This was calculated as a function of the UAR page
		 * index (top 16 bits) and the device instance number
		 */
		rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
		dev = makedevice(getmajor(*devp), (rsrcp->tr_indx <<
		    TAVOR_MINORNUM_SHIFT) | instance);
	}
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);

	*devp = dev;

	TAVOR_TNF_EXIT(tavor_open);
	return (0);
}


/*
 * tavor_close()
 */
/* ARGSUSED */
static int
tavor_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	tavor_state_t		*state;
	tavor_rsrc_t		*rsrcp;
	tavor_umap_db_entry_t	*umapdb;
	tavor_umap_db_priv_t	*priv;
	minor_t			instance;
	uint64_t		key, value;
	int			status;

	TAVOR_TNF_ENTER(tavor_close);

	instance = TAVOR_DEV_INSTANCE(dev);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		TNF_PROBE_0(tavor_close_gss_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_close);
		return (ENXIO);
	}

	/*
	 * Search for "dev_t" in the "userland resources database".  As
	 * explained above in tavor_open(), we can't depend on using the
	 * current process ID here to do the lookup because the process
	 * that ultimately closes may not be the same one who opened
	 * (because of inheritance).
	 * So we lookup the "dev_t" (which points to the PID of the process
	 * that opened), and we remove the entry from the database (and free
	 * it up).  Then we do another query based on the PID value.  And when
	 * we find that database entry, we free it up too and then free the
	 * Tavor UAR page resource.
	 *
	 * Note: We use the tavor_umap_db_find_nolock() database access
	 * routine below (with an explicit mutex_enter of the database lock)
	 * to ensure that the multiple accesses (which attempt to remove the
	 * two database entries) can be done atomically.
	 *
	 * This works the same in both maintenance mode and HCA mode, except
	 * for the call to tavor_rsrc_free().  In the case of maintenance mode,
	 * this call is not needed, as it was not allocated in tavor_open()
	 * above.
	 */
	key = dev;
	mutex_enter(&tavor_userland_rsrc_db.tdl_umapdb_lock);
	status = tavor_umap_db_find_nolock(instance, key, MLNX_UMAP_PID_RSRC,
	    &value, TAVOR_UMAP_DB_REMOVE, &umapdb);
	if (status == DDI_SUCCESS) {
		/*
		 * If the "tdb_priv" field is non-NULL, it indicates that
		 * some "on close" handling is still necessary.  Call
		 * tavor_umap_db_handle_onclose_cb() to do the handling (i.e.
		 * to invoke all the registered callbacks).  Then free up
		 * the resources associated with "tdb_priv" and continue
		 * closing.
		 */
		priv = (tavor_umap_db_priv_t *)umapdb->tdbe_common.tdb_priv;
		if (priv != NULL) {
			tavor_umap_db_handle_onclose_cb(priv);
			kmem_free(priv, sizeof (tavor_umap_db_priv_t));
			umapdb->tdbe_common.tdb_priv = (void *)NULL;
		}

		tavor_umap_db_free(umapdb);

		/*
		 * Now do another lookup using PID as the key (copy it from
		 * "value").  When this lookup is complete, the "value" field
		 * will contain the tavor_rsrc_t pointer for the UAR page
		 * resource.
		 */
		key = value;
		status = tavor_umap_db_find_nolock(instance, key,
		    MLNX_UMAP_UARPG_RSRC, &value, TAVOR_UMAP_DB_REMOVE,
		    &umapdb);
		if (status == DDI_SUCCESS) {
			tavor_umap_db_free(umapdb);
			/* If in "maintenance mode", don't free the rsrc */
			if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
				rsrcp = (tavor_rsrc_t *)(uintptr_t)value;
				tavor_rsrc_free(state, &rsrcp);
			}
		}
	}
	mutex_exit(&tavor_userland_rsrc_db.tdl_umapdb_lock);

	TAVOR_TNF_EXIT(tavor_close);
	return (0);
}


/*
 * tavor_attach()
 *    Context: Only called from attach() path context
 */
static int
tavor_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	tavor_state_t	*state;
	ibc_clnt_hdl_t	tmp_ibtfpriv;
	ibc_status_t	ibc_status;
	int		instance;
	int		status;

	TAVOR_TNF_ENTER(tavor_attach);

#ifdef __lock_lint
	(void) tavor_quiesce(dip);
#endif

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);
		status = ddi_soft_state_zalloc(tavor_statep, instance);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_attach_ssz_fail, TAVOR_TNF_ERROR, "");
			cmn_err(CE_NOTE, "tavor%d: driver failed to attach: "
			    "attach_ssz_fail", instance);
			goto fail_attach_nomsg;

		}
		state = ddi_get_soft_state(tavor_statep, instance);
		if (state == NULL) {
			ddi_soft_state_free(tavor_statep, instance);
			TNF_PROBE_0(tavor_attach_gss_fail, TAVOR_TNF_ERROR, "");
			cmn_err(CE_NOTE, "tavor%d: driver failed to attach: "
			    "attach_gss_fail", instance);
			goto fail_attach_nomsg;
		}

		/* clear the attach error buffer */
		TAVOR_ATTACH_MSG_INIT(state->ts_attach_buf);

		/*
		 * Initialize Tavor driver and hardware.
		 *
		 * Note: If this initialization fails we may still wish to
		 * create a device node and remain operational so that Tavor
		 * firmware can be updated/flashed (i.e. "maintenance mode").
		 * If this is the case, then "ts_operational_mode" will be
		 * equal to TAVOR_MAINTENANCE_MODE.  We will not attempt to
		 * attach to the IBTF or register with the IBMF (i.e. no
		 * InfiniBand interfaces will be enabled).
		 */
		status = tavor_drv_init(state, dip, instance);
		if ((status != DDI_SUCCESS) &&
		    (TAVOR_IS_OPERATIONAL(state->ts_operational_mode))) {
			TNF_PROBE_0(tavor_attach_drvinit_fail,
			    TAVOR_TNF_ERROR, "");
			goto fail_attach;
		}

		/* Create the minor node for device */
		status = ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
		    DDI_PSEUDO, 0);
		if (status != DDI_SUCCESS) {
			tavor_drv_fini(state);
			TAVOR_ATTACH_MSG(state->ts_attach_buf,
			    "attach_create_mn_fail");
			TNF_PROBE_0(tavor_attach_create_mn_fail,
			    TAVOR_TNF_ERROR, "");
			goto fail_attach;
		}

		/*
		 * If we are in "maintenance mode", then we don't want to
		 * register with the IBTF.  All InfiniBand interfaces are
		 * uninitialized, and the device is only capable of handling
		 * requests to update/flash firmware (or test/debug requests).
		 */
		if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {

			/* Attach to InfiniBand Transport Framework (IBTF) */
			ibc_status = ibc_attach(&tmp_ibtfpriv,
			    &state->ts_ibtfinfo);
			if (ibc_status != IBC_SUCCESS) {
				ddi_remove_minor_node(dip, "devctl");
				tavor_drv_fini(state);
				TNF_PROBE_0(tavor_attach_ibcattach_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_ATTACH_MSG(state->ts_attach_buf,
				    "attach_ibcattach_fail");
				goto fail_attach;
			}

			/*
			 * Now that we've successfully attached to the IBTF,
			 * we enable all appropriate asynch and CQ events to
			 * be forwarded to the IBTF.
			 */
			TAVOR_ENABLE_IBTF_CALLB(state, tmp_ibtfpriv);

			ibc_post_attach(state->ts_ibtfpriv);

			/* Register agents with IB Mgmt Framework (IBMF) */
			status = tavor_agent_handlers_init(state);
			if (status != DDI_SUCCESS) {
				(void) ibc_pre_detach(tmp_ibtfpriv, DDI_DETACH);
				TAVOR_QUIESCE_IBTF_CALLB(state);
				if (state->ts_in_evcallb != 0) {
					TAVOR_WARNING(state, "unable to "
					    "quiesce Tavor IBTF callbacks");
				}
				ibc_detach(tmp_ibtfpriv);
				ddi_remove_minor_node(dip, "devctl");
				tavor_drv_fini(state);
				TNF_PROBE_0(tavor_attach_agentinit_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_ATTACH_MSG(state->ts_attach_buf,
				    "attach_agentinit_fail");
				goto fail_attach;
			}
		}

		/* Report that driver was loaded */
		ddi_report_dev(dip);

		/* Send device information to log file */
		tavor_device_info_report(state);

		/* Report attach in maintenance mode, if appropriate */
		if (!(TAVOR_IS_OPERATIONAL(state->ts_operational_mode))) {
			cmn_err(CE_NOTE, "tavor%d: driver attached "
			    "(for maintenance mode only)", state->ts_instance);
		}

		TAVOR_TNF_EXIT(tavor_attach);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		/* Add code here for DDI_RESUME XXX */
		TAVOR_TNF_EXIT(tavor_attach);
		return (DDI_FAILURE);

	default:
		TNF_PROBE_0(tavor_attach_default_fail, TAVOR_TNF_ERROR, "");
		break;
	}

fail_attach:
	cmn_err(CE_NOTE, "tavor%d: driver failed to attach: %s", instance,
	    state->ts_attach_buf);
	tavor_drv_fini2(state);
	ddi_soft_state_free(tavor_statep, instance);
fail_attach_nomsg:
	TAVOR_TNF_EXIT(tavor_attach);
	return (DDI_FAILURE);
}


/*
 * tavor_detach()
 *    Context: Only called from detach() path context
 */
static int
tavor_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	tavor_state_t	*state;
	ibc_clnt_hdl_t	tmp_ibtfpriv;
	ibc_status_t	ibc_status;
	int		instance, status;

	TAVOR_TNF_ENTER(tavor_detach);

	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(tavor_statep, instance);
	if (state == NULL) {
		TNF_PROBE_0(tavor_detach_gss_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_detach);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * If we are in "maintenance mode", then we do not want to
		 * do teardown for any of the InfiniBand interfaces.
		 * Specifically, this means not detaching from IBTF (we never
		 * attached to begin with) and not deregistering from IBMF.
		 */
		if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
			/* Unregister agents from IB Mgmt Framework (IBMF) */
			status = tavor_agent_handlers_fini(state);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_detach_agentfini_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_detach);
				return (DDI_FAILURE);
			}

			/*
			 * Attempt the "pre-detach" from InfiniBand Transport
			 * Framework (IBTF).  At this point the IBTF is still
			 * capable of handling incoming asynch and completion
			 * events.  This "pre-detach" is primarily a mechanism
			 * to notify the appropriate IBTF clients that the
			 * HCA is being removed/offlined.
			 */
			ibc_status = ibc_pre_detach(state->ts_ibtfpriv, cmd);
			if (ibc_status != IBC_SUCCESS) {
				status = tavor_agent_handlers_init(state);
				if (status != DDI_SUCCESS) {
					TAVOR_WARNING(state, "failed to "
					    "restart Tavor agents");
				}
				TNF_PROBE_0(tavor_detach_ibcpredetach_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_detach);
				return (DDI_FAILURE);
			}

			/*
			 * Before we can fully detach from the IBTF we need to
			 * ensure that we have handled all outstanding event
			 * callbacks.  This is accomplished by quiescing the
			 * event callback mechanism.  Note: if we are unable
			 * to successfully quiesce the callbacks, then this is
			 * an indication that something has probably gone
			 * seriously wrong.  We print out a warning, but
			 * continue.
			 */
			tmp_ibtfpriv = state->ts_ibtfpriv;
			TAVOR_QUIESCE_IBTF_CALLB(state);
			if (state->ts_in_evcallb != 0) {
				TAVOR_WARNING(state, "unable to quiesce Tavor "
				    "IBTF callbacks");
			}

			/* Complete the detach from the IBTF */
			ibc_detach(tmp_ibtfpriv);
		}

		/* Remove the minor node for device */
		ddi_remove_minor_node(dip, "devctl");

		/*
		 * Only call tavor_drv_fini() if we are in Tavor HCA mode.
		 * (Because if we are in "maintenance mode", then we never
		 * successfully finished init.)  Only report successful
		 * detach for normal HCA mode.
		 */
		if (TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
			/* Cleanup driver resources and shutdown hardware */
			tavor_drv_fini(state);
			cmn_err(CE_CONT, "Tavor driver successfully "
			    "detached\n");
		}

		tavor_drv_fini2(state);
		ddi_soft_state_free(tavor_statep, instance);

		TAVOR_TNF_EXIT(tavor_detach);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* Add code here for DDI_SUSPEND XXX */
		TAVOR_TNF_EXIT(tavor_detach);
		return (DDI_FAILURE);

	default:
		TNF_PROBE_0(tavor_detach_default_fail, TAVOR_TNF_ERROR, "");
		break;
	}

	TAVOR_TNF_EXIT(tavor_detach);
	return (DDI_FAILURE);
}


/*
 * tavor_drv_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_drv_init(tavor_state_t *state, dev_info_t *dip, int instance)
{
	int			status;

	TAVOR_TNF_ENTER(tavor_drv_init);

	/* Save away devinfo and instance */
	state->ts_dip = dip;
	state->ts_instance = instance;

	/*
	 * Check and set the operational mode of the device. If the driver is
	 * bound to the Tavor device in "maintenance mode", then this generally
	 * means that either the device has been specifically jumpered to
	 * start in this mode or the firmware boot process has failed to
	 * successfully load either the primary or the secondary firmware
	 * image.
	 */
	if (TAVOR_IS_HCA_MODE(state->ts_dip)) {
		state->ts_operational_mode = TAVOR_HCA_MODE;

	} else if (TAVOR_IS_COMPAT_MODE(state->ts_dip)) {
		state->ts_operational_mode = TAVOR_COMPAT_MODE;

	} else if (TAVOR_IS_MAINTENANCE_MODE(state->ts_dip)) {
		state->ts_operational_mode = TAVOR_MAINTENANCE_MODE;
		return (DDI_FAILURE);

	} else {
		state->ts_operational_mode = 0;	/* invalid operational mode */
		TAVOR_WARNING(state, "unexpected device type detected");
		TNF_PROBE_0(tavor_hw_init_unexpected_dev_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/*
	 * Initialize the Tavor hardware.
	 * Note:  If this routine returns an error, it is often an reasonably
	 * good indication that something Tavor firmware-related has caused
	 * the failure.  In order to give the user an opportunity (if desired)
	 * to update or reflash the Tavor firmware image, we set
	 * "ts_operational_mode" flag (described above) to indicate that we
	 * wish to enter maintenance mode.
	 */
	status = tavor_hw_init(state);
	if (status != DDI_SUCCESS) {
		state->ts_operational_mode = TAVOR_MAINTENANCE_MODE;
		cmn_err(CE_NOTE, "tavor%d: error during attach: %s", instance,
		    state->ts_attach_buf);
		TNF_PROBE_0(tavor_drv_init_hwinit_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_drv_init);
		return (DDI_FAILURE);
	}

	/* Setup Tavor interrupt handler */
	status = tavor_isr_init(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, TAVOR_DRV_CLEANUP_ALL);
		TNF_PROBE_0(tavor_drv_init_isrinit_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_drv_init);
		return (DDI_FAILURE);
	}

	/* Initialize Tavor softstate */
	status = tavor_soft_state_init(state);
	if (status != DDI_SUCCESS) {
		tavor_isr_fini(state);
		tavor_hw_fini(state, TAVOR_DRV_CLEANUP_ALL);
		TNF_PROBE_0(tavor_drv_init_ssiinit_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_drv_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_drv_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_drv_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_drv_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_drv_fini);

	/* Cleanup Tavor softstate */
	tavor_soft_state_fini(state);

	/* Teardown Tavor interrupts */
	tavor_isr_fini(state);

	/* Cleanup Tavor resources and shutdown hardware */
	tavor_hw_fini(state, TAVOR_DRV_CLEANUP_ALL);

	TAVOR_TNF_EXIT(tavor_drv_fini);
}

/*
 * tavor_drv_fini2()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_drv_fini2(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_drv_fini2);

	/* TAVOR_DRV_CLEANUP_LEVEL1 */
	if (state->ts_reg_cmdhdl) {
		ddi_regs_map_free(&state->ts_reg_cmdhdl);
		state->ts_reg_cmdhdl = NULL;
	}

	/* TAVOR_DRV_CLEANUP_LEVEL0 */
	if (state->ts_pci_cfghdl) {
		pci_config_teardown(&state->ts_pci_cfghdl);
		state->ts_pci_cfghdl = NULL;
	}

	TAVOR_TNF_EXIT(tavor_drv_fini2);
}

/*
 * tavor_isr_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_isr_init(tavor_state_t *state)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_isr_init);

	/*
	 * Add a handler for the interrupt or MSI
	 */
	status = ddi_intr_add_handler(state->ts_intrmsi_hdl, tavor_isr,
	    (caddr_t)state, NULL);
	if (status  != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_isr_init_addhndlr_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_isr_init);
		return (DDI_FAILURE);
	}

	/*
	 * Enable the software interrupt.  Note: Even though we are only
	 * using one (1) interrupt/MSI, depending on the value returned in
	 * the capability flag, we have to call either ddi_intr_block_enable()
	 * or ddi_intr_enable().
	 */
	if (state->ts_intrmsi_cap & DDI_INTR_FLAG_BLOCK) {
		status = ddi_intr_block_enable(&state->ts_intrmsi_hdl, 1);
		if (status  != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_isr_init_blockenable_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_isr_init);
			return (DDI_FAILURE);
		}
	} else {
		status = ddi_intr_enable(state->ts_intrmsi_hdl);
		if (status  != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_isr_init_intrenable_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_isr_init);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Now that the ISR has been setup, arm all the EQs for event
	 * generation.
	 */
	tavor_eq_arm_all(state);

	TAVOR_TNF_EXIT(tavor_isr_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_isr_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_isr_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_isr_fini);

	/* Disable the software interrupt */
	if (state->ts_intrmsi_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(&state->ts_intrmsi_hdl, 1);
	} else {
		(void) ddi_intr_disable(state->ts_intrmsi_hdl);
	}

	/*
	 * Remove the software handler for the interrupt or MSI
	 */
	(void) ddi_intr_remove_handler(state->ts_intrmsi_hdl);

	TAVOR_TNF_EXIT(tavor_isr_fini);
}


/*
 * tavor_fix_error_buf()
 *	Context: Only called from attach().
 *
 * The error_buf_addr returned from QUERY_FW is a PCI address.
 * We need to convert it to an offset from the base address,
 * which is stored in the assigned-addresses property.
 */
static int
tavor_fix_error_buf(tavor_state_t *state)
{
	int		assigned_addr_len;
	pci_regspec_t	*assigned_addr;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "assigned-addresses", (int **)&assigned_addr,
	    (uint_t *)&assigned_addr_len) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	state->ts_fw.error_buf_addr -= assigned_addr[0].pci_phys_low +
	    ((uint64_t)(assigned_addr[0].pci_phys_mid) << 32);
	ddi_prop_free(assigned_addr);
	return (DDI_SUCCESS);
}

/*
 * tavor_hw_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_hw_init(tavor_state_t *state)
{
	tavor_drv_cleanup_level_t	cleanup;
	sm_nodeinfo_t			nodeinfo;
	uint64_t			errorcode;
	off_t				ddr_size;
	int				status;
	int				retries;

	TAVOR_TNF_ENTER(tavor_hw_init);

	/* This is where driver initialization begins */
	cleanup = TAVOR_DRV_CLEANUP_LEVEL0;

	/* Setup device access attributes */
	state->ts_reg_accattr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	state->ts_reg_accattr.devacc_attr_endian_flags = DDI_STRUCTURE_BE_ACC;
	state->ts_reg_accattr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Setup for PCI config read/write of HCA device  */
	status = pci_config_setup(state->ts_dip, &state->ts_pci_cfghdl);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_PCI_config_space_regmap_fail");
		/* This case is not the degraded one */
		return (DDI_FAILURE);
	}

	/* Map in Tavor registers (CMD, UAR, DDR) and setup offsets */
	status = ddi_regs_map_setup(state->ts_dip, TAVOR_CMD_BAR,
	    &state->ts_reg_cmd_baseaddr, 0, 0, &state->ts_reg_accattr,
	    &state->ts_reg_cmdhdl);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_CMD_ddirms_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_CMD_ddirms_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL1;

	status = ddi_regs_map_setup(state->ts_dip, TAVOR_UAR_BAR,
	    &state->ts_reg_uar_baseaddr, 0, 0, &state->ts_reg_accattr,
	    &state->ts_reg_uarhdl);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_UAR_ddirms_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_UAR_ddirms_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL2;

	status = ddi_dev_regsize(state->ts_dip, TAVOR_DDR_BAR, &ddr_size);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: ddi_dev_regsize() failed "
		    "(check HCA-attached DIMM memory?)\n");
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_DDR_ddi_regsize_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_DDR_ddi_regsize_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

#if !defined(_ELF64) && !defined(__sparc)
	/*
	 * For 32 bit x86/x64 kernels, where there is limited kernel virtual
	 * memory available, define a minimal memory footprint. This is
	 * specified in order to not take up too much resources, thus starving
	 * out others. Only specified if the HCA DIMM is equal to or greater
	 * than 256MB.
	 *
	 * Note: x86/x64 install and safemode boot are both 32bit.
	 */
	ddr_size = TAVOR_DDR_SIZE_MIN;
#endif	/* !(_ELF64) && !(__sparc) */

	state->ts_cfg_profile_setting = ddr_size;

	status = ddi_regs_map_setup(state->ts_dip, TAVOR_DDR_BAR,
	    &state->ts_reg_ddr_baseaddr, 0, ddr_size, &state->ts_reg_accattr,
	    &state->ts_reg_ddrhdl);

	/*
	 * On 32-bit platform testing (primarily x86), it was seen that the
	 * ddi_regs_map_setup() call would fail because there wasn't enough
	 * kernel virtual address space available to map in the entire 256MB
	 * DDR.  So we add this check in here, so that if the 256 (or other
	 * larger value of DDR) map in fails, that we fallback to try the lower
	 * size of 128MB.
	 *
	 * Note: If we only have 128MB of DDR in the system in the first place,
	 * we don't try another ddi_regs_map_setup(), and just skip over this
	 * check and return failures.
	 */
	if (status == DDI_ME_NORESOURCES && ddr_size > TAVOR_DDR_SIZE_128) {
		/* Try falling back to 128MB DDR mapping */
		status = ddi_regs_map_setup(state->ts_dip, TAVOR_DDR_BAR,
		    &state->ts_reg_ddr_baseaddr, 0, TAVOR_DDR_SIZE_128,
		    &state->ts_reg_accattr, &state->ts_reg_ddrhdl);

		/*
		 * 128MB DDR mapping worked.
		 * Set the updated config profile setting here.
		 */
		if (status == DDI_SUCCESS) {
			TNF_PROBE_0(tavor_hw_init_DDR_128mb_fallback_success,
			    TAVOR_TNF_TRACE, "");
			state->ts_cfg_profile_setting = TAVOR_DDR_SIZE_128;
		}
	}

	if (status != DDI_SUCCESS) {
		if (status == DDI_ME_RNUMBER_RANGE) {
			cmn_err(CE_CONT, "Tavor: ddi_regs_map_setup() failed "
			    "(check HCA-attached DIMM memory?)\n");
		}
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_DDR_ddirms_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_DDR_ddirms_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL3;

	/* Setup Tavor Host Command Register (HCR) */
	state->ts_cmd_regs.hcr = (tavor_hw_hcr_t *)
	    ((uintptr_t)state->ts_reg_cmd_baseaddr + TAVOR_CMD_HCR_OFFSET);

	/* Setup Tavor Event Cause Register (ecr and clr_ecr) */
	state->ts_cmd_regs.ecr = (uint64_t *)
	    ((uintptr_t)state->ts_reg_cmd_baseaddr + TAVOR_CMD_ECR_OFFSET);
	state->ts_cmd_regs.clr_ecr = (uint64_t *)
	    ((uintptr_t)state->ts_reg_cmd_baseaddr + TAVOR_CMD_CLR_ECR_OFFSET);

	/* Setup Tavor Software Reset register (sw_reset) */
	state->ts_cmd_regs.sw_reset = (uint32_t *)
	    ((uintptr_t)state->ts_reg_cmd_baseaddr + TAVOR_CMD_SW_RESET_OFFSET);

	/* Setup Tavor Clear Interrupt register (clr_int) */
	state->ts_cmd_regs.clr_int = (uint64_t *)
	    ((uintptr_t)state->ts_reg_cmd_baseaddr + TAVOR_CMD_CLR_INT_OFFSET);

	/* Initialize the Phase1 Tavor configuration profile */
	status = tavor_cfg_profile_init_phase1(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_cfginit_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf, "hw_init_cfginit_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL4;

	/* Do a software reset of the Tavor HW to ensure proper state */
	status = tavor_sw_reset(state);
	if (status != TAVOR_CMD_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_sw_reset_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf, "hw_init_sw_reset_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Post the SYS_EN command to start the hardware */
	status = tavor_sys_en_cmd_post(state, TAVOR_CMD_SYS_EN_NORMAL,
	    &errorcode, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if ((status == TAVOR_CMD_BAD_NVMEM) ||
		    (status == TAVOR_CMD_DDR_MEM_ERR)) {
			cmn_err(CE_CONT, "Tavor: SYS_EN command failed: 0x%x "
			    "0x%" PRIx64 " (invalid firmware image?)\n",
			    status, errorcode);
		} else {
			cmn_err(CE_CONT, "Tavor: SYS_EN command failed: 0x%x "
			    "0x%" PRIx64 "\n", status, errorcode);
		}
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_sys_en_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_sys_en_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL5;

	/* First phase of init for Tavor configuration/resources */
	status = tavor_rsrc_init_phase1(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_rsrcinit1_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_rsrcinit1_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL6;

	/* Query the DDR properties (e.g. total DDR size) */
	status = tavor_cmn_query_cmd_post(state, QUERY_DDR, 0,
	    &state->ts_ddr, sizeof (tavor_hw_queryddr_t),
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: QUERY_DDR command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_query_ddr_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_query_ddr_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Figure out how big the firmware image (in DDR) is */
	status = tavor_cmn_query_cmd_post(state, QUERY_FW, 0, &state->ts_fw,
	    sizeof (tavor_hw_queryfw_t), TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: QUERY_FW command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_query_fw_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_query_fw_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	if (tavor_fix_error_buf(state) != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_fixerrorbuf_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_fixerrorbuf_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Validate that the FW version is appropriate */
	status = tavor_fw_version_check(state);
	if (status != DDI_SUCCESS) {
		if (state->ts_operational_mode == TAVOR_HCA_MODE) {
			cmn_err(CE_CONT, "Unsupported Tavor FW version: "
			    "expected: %04d.%04d.%04d, "
			    "actual: %04d.%04d.%04d\n",
			    TAVOR_FW_VER_MAJOR,
			    TAVOR_FW_VER_MINOR,
			    TAVOR_FW_VER_SUBMINOR,
			    state->ts_fw.fw_rev_major,
			    state->ts_fw.fw_rev_minor,
			    state->ts_fw.fw_rev_subminor);
		} else if (state->ts_operational_mode == TAVOR_COMPAT_MODE) {
			cmn_err(CE_CONT, "Unsupported Tavor Compat FW version: "
			    "expected: %04d.%04d.%04d, "
			    "actual: %04d.%04d.%04d\n",
			    TAVOR_COMPAT_FW_VER_MAJOR,
			    TAVOR_COMPAT_FW_VER_MINOR,
			    TAVOR_COMPAT_FW_VER_SUBMINOR,
			    state->ts_fw.fw_rev_major,
			    state->ts_fw.fw_rev_minor,
			    state->ts_fw.fw_rev_subminor);
		} else {
			cmn_err(CE_CONT, "Unsupported FW version: "
			    "%04d.%04d.%04d\n",
			    state->ts_fw.fw_rev_major,
			    state->ts_fw.fw_rev_minor,
			    state->ts_fw.fw_rev_subminor);
		}
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_checkfwver_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_checkfwver_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	drv_usecwait(10);
	retries = 1000;		/* retry up to 1 second before giving up */
retry:
	/* Call MOD_STAT_CFG to setup SRQ support (or disable) */
	status = tavor_mod_stat_cfg_cmd_post(state);
	if (status != DDI_SUCCESS) {
		if (retries > 0) {
			drv_usecwait(1000);
			retries--;
			goto retry;
		}
		cmn_err(CE_CONT, "Tavor: MOD_STAT_CFG command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_mod_stat_cfg_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_mod_stat_cfg_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Figure out Tavor device limits */
	status = tavor_cmn_query_cmd_post(state, QUERY_DEV_LIM, 0,
	    &state->ts_devlim, sizeof (tavor_hw_querydevlim_t),
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: QUERY_DEV_LIM command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_query_devlim_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_query_devlim_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Initialize the Phase2 Tavor configuration profile */
	status = tavor_cfg_profile_init_phase2(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_cfginit2_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf, "hw_init_cfginit2_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Second phase of init for Tavor configuration/resources */
	status = tavor_rsrc_init_phase2(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_rsrcinit2_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_rsrcinit2_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL7;

	/* Miscellaneous query information */
	status = tavor_cmn_query_cmd_post(state, QUERY_ADAPTER, 0,
	    &state->ts_adapter, sizeof (tavor_hw_queryadapter_t),
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: QUERY_ADAPTER command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_query_adapter_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_query_adapter_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/* Prepare configuration for Tavor INIT_HCA command */
	tavor_hca_config_setup(state, &state->ts_hcaparams);

	/* Post command to init Tavor HCA */
	status = tavor_init_hca_cmd_post(state, &state->ts_hcaparams,
	    TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: INIT_HCA command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_init_hca_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_init_hca_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL8;

	/* Allocate protection domain (PD) for Tavor internal use */
	status = tavor_pd_alloc(state, &state->ts_pdhdl_internal, TAVOR_SLEEP);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_internal_pd_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_internal_pd_alloc_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL9;

	/* Setup Tavor internal UAR pages (0 and 1) */
	status = tavor_internal_uarpgs_init(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_internal_uarpgs_alloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_internal_uarpgs_alloc_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL10;

	/* Query and initialize the Tavor interrupt/MSI information */
	status = tavor_intr_or_msi_init(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_intr_or_msi_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "intr_or_msi_init_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL11;

	/* Setup all of the Tavor EQs */
	status = tavor_eq_init_all(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_eqinitall_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_eqinitall_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL12;

	/* Set aside contexts for QP0 and QP1 */
	status = tavor_special_qp_contexts_reserve(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_reserve_special_qp_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_reserve_special_qp_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL13;

	/* Initialize for multicast group handling */
	status = tavor_mcg_init(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_mcg_init_fail, TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf, "hw_init_mcg_init_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_LEVEL14;

	/* Initialize the Tavor IB port(s) */
	status = tavor_hca_port_init(state);
	if (status != DDI_SUCCESS) {
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_hca_port_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_hca_port_init_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}
	cleanup = TAVOR_DRV_CLEANUP_ALL;

	/* Determine NodeGUID and SystemImageGUID */
	status = tavor_getnodeinfo_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN,
	    &nodeinfo);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: GetNodeInfo command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_getnodeinfo_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_getnodeinfo_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	/*
	 * If the NodeGUID value was set in OBP properties, then we use that
	 * value.  But we still print a message if the value we queried from
	 * firmware does not match this value.
	 *
	 * Otherwise if OBP value is not set then we use the value from
	 * firmware unconditionally.
	 */
	if (state->ts_cfg_profile->cp_nodeguid) {
		state->ts_nodeguid   = state->ts_cfg_profile->cp_nodeguid;
	} else {
		state->ts_nodeguid = nodeinfo.NodeGUID;
	}

	if (state->ts_nodeguid != nodeinfo.NodeGUID) {
		cmn_err(CE_NOTE, "!NodeGUID value queried from firmware "
		    "does not match value set by device property");
	}

	/*
	 * If the SystemImageGUID value was set in OBP properties, then we use
	 * that value.  But we still print a message if the value we queried
	 * from firmware does not match this value.
	 *
	 * Otherwise if OBP value is not set then we use the value from
	 * firmware unconditionally.
	 */
	if (state->ts_cfg_profile->cp_sysimgguid) {
		state->ts_sysimgguid = state->ts_cfg_profile->cp_sysimgguid;
	} else {
		state->ts_sysimgguid = nodeinfo.SystemImageGUID;
	}

	if (state->ts_sysimgguid != nodeinfo.SystemImageGUID) {
		cmn_err(CE_NOTE, "!SystemImageGUID value queried from firmware "
		    "does not match value set by device property");
	}

	/* Get NodeDescription */
	status = tavor_getnodedesc_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN,
	    (sm_nodedesc_t *)&state->ts_nodedesc);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: GetNodeDesc command failed: %08x\n",
		    status);
		tavor_hw_fini(state, cleanup);
		TNF_PROBE_0(tavor_hw_init_getnodedesc_cmd_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "hw_init_getnodedesc_cmd_fail");
		TAVOR_TNF_EXIT(tavor_hw_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_hw_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_hw_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_hw_fini(tavor_state_t *state, tavor_drv_cleanup_level_t cleanup)
{
	uint_t		num_ports;
	int		status;

	TAVOR_TNF_ENTER(tavor_hw_fini);

	switch (cleanup) {
	/*
	 * If we add more driver initialization steps that should be cleaned
	 * up here, we need to ensure that TAVOR_DRV_CLEANUP_ALL is still the
	 * first entry (i.e. corresponds to the last init step).
	 */
	case TAVOR_DRV_CLEANUP_ALL:
		/* Shutdown the Tavor IB port(s) */
		num_ports = state->ts_cfg_profile->cp_num_ports;
		(void) tavor_hca_ports_shutdown(state, num_ports);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL14:
		/* Teardown resources used for multicast group handling */
		tavor_mcg_fini(state);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL13:
		/* Unreserve the special QP contexts */
		tavor_special_qp_contexts_unreserve(state);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL12:
		/*
		 * Attempt to teardown all event queues (EQ).  If we fail
		 * here then print a warning message and return.  Something
		 * (either in HW or SW) has gone seriously wrong.
		 */
		status = tavor_eq_fini_all(state);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to teardown EQs");
			TNF_PROBE_0(tavor_hw_fini_eqfiniall_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_hw_fini);
			return;
		}
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL11:
		status = tavor_intr_or_msi_fini(state);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to free intr/MSI");
			TNF_PROBE_0(tavor_hw_fini_intrmsifini_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_hw_fini);
			return;
		}
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL10:
		/* Free the resources for the Tavor internal UAR pages */
		tavor_internal_uarpgs_fini(state);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL9:
		/*
		 * Free the PD that was used internally by Tavor software.  If
		 * we fail here then print a warning and return.  Something
		 * (probably software-related, but perhaps HW) has gone wrong.
		 */
		status = tavor_pd_free(state, &state->ts_pdhdl_internal);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to free internal PD");
			TNF_PROBE_0(tavor_hw_fini_internal_pd_free_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_hw_fini);
			return;
		}
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL8:
		/*
		 * Post the CLOSE_HCA command to Tavor firmware.  If we fail
		 * here then print a warning and return.  Something (either in
		 * HW or SW) has gone seriously wrong.
		 */
		status = tavor_close_hca_cmd_post(state,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TAVOR_WARNING(state, "failed to shutdown HCA");
			TNF_PROBE_0(tavor_hw_fini_closehcacmd_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_hw_fini);
			return;
		}
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL7:
		/* Cleanup all the phase2 resources first */
		tavor_rsrc_fini(state, TAVOR_RSRC_CLEANUP_ALL);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL6:
		/* Then cleanup the phase1 resources */
		tavor_rsrc_fini(state, TAVOR_RSRC_CLEANUP_PHASE1_COMPLETE);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL5:
		/*
		 * Post the SYS_DIS command to Tavor firmware to shut
		 * everything down again.  If we fail here then print a
		 * warning and return.  Something (probably in HW, but maybe
		 * in SW) has gone seriously wrong.
		 */
		status = tavor_sys_dis_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TAVOR_WARNING(state, "failed to shutdown hardware");
			TNF_PROBE_0(tavor_hw_fini_sys_dis_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_hw_fini);
			return;
		}
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL4:
		/* Teardown any resources allocated for the config profile */
		tavor_cfg_profile_fini(state);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL3:
		ddi_regs_map_free(&state->ts_reg_ddrhdl);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL2:
		ddi_regs_map_free(&state->ts_reg_uarhdl);
		/* FALLTHROUGH */

	case TAVOR_DRV_CLEANUP_LEVEL1:
	case TAVOR_DRV_CLEANUP_LEVEL0:
		/*
		 * LEVEL1 and LEVEL0 resources are freed in
		 * tavor_drv_fini2().
		 */
		break;

	default:
		TAVOR_WARNING(state, "unexpected driver cleanup level");
		TNF_PROBE_0(tavor_hw_fini_default_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_hw_fini);
		return;
	}

	TAVOR_TNF_EXIT(tavor_hw_fini);
}


/*
 * tavor_soft_state_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_soft_state_init(tavor_state_t *state)
{
	ibt_hca_attr_t		*hca_attr;
	uint64_t		maxval, val;
	ibt_hca_flags_t		caps = IBT_HCA_NO_FLAGS;
	int			status;

	TAVOR_TNF_ENTER(tavor_soft_state_init);

	/*
	 * The ibc_hca_info_t struct is passed to the IBTF.  This is the
	 * routine where we initialize it.  Many of the init values come from
	 * either configuration variables or successful queries of the Tavor
	 * hardware abilities
	 */
	state->ts_ibtfinfo.hca_ci_vers	= IBCI_V4;
	state->ts_ibtfinfo.hca_handle	= (ibc_hca_hdl_t)state;
	state->ts_ibtfinfo.hca_ops	= &tavor_ibc_ops;

	hca_attr = kmem_zalloc(sizeof (ibt_hca_attr_t), KM_SLEEP);
	state->ts_ibtfinfo.hca_attr = hca_attr;

	hca_attr->hca_dip = state->ts_dip;
	hca_attr->hca_fw_major_version = state->ts_fw.fw_rev_major;
	hca_attr->hca_fw_minor_version = state->ts_fw.fw_rev_minor;
	hca_attr->hca_fw_micro_version = state->ts_fw.fw_rev_subminor;

	/*
	 * Determine HCA capabilities:
	 * No default support for IBT_HCA_RD, IBT_HCA_RAW_MULTICAST,
	 *    IBT_HCA_ATOMICS_GLOBAL, IBT_HCA_RESIZE_CHAN, IBT_HCA_INIT_TYPE,
	 *    or IBT_HCA_SHUTDOWN_PORT
	 * But IBT_HCA_AH_PORT_CHECK, IBT_HCA_SQD_RTS_PORT, IBT_HCA_SI_GUID,
	 *    IBT_HCA_RNR_NAK, and IBT_HCA_CURRENT_QP_STATE are always
	 *    supported
	 * All other features are conditionally supported, depending on the
	 *    status return by the Tavor HCA (in QUERY_DEV_LIM)
	 */
	if (state->ts_devlim.ud_multi) {
		caps |= IBT_HCA_UD_MULTICAST;
	}
	if (state->ts_devlim.atomic) {
		caps |= IBT_HCA_ATOMICS_HCA;
	}
	if (state->ts_devlim.apm) {
		caps |= IBT_HCA_AUTO_PATH_MIG;
	}
	if (state->ts_devlim.pkey_v) {
		caps |= IBT_HCA_PKEY_CNTR;
	}
	if (state->ts_devlim.qkey_v) {
		caps |= IBT_HCA_QKEY_CNTR;
	}
	if (state->ts_cfg_profile->cp_srq_enable) {
		caps |= IBT_HCA_SRQ | IBT_HCA_RESIZE_SRQ;
	}
	caps |= (IBT_HCA_AH_PORT_CHECK | IBT_HCA_SQD_SQD_PORT |
	    IBT_HCA_SI_GUID | IBT_HCA_RNR_NAK | IBT_HCA_CURRENT_QP_STATE |
	    IBT_HCA_PORT_UP | IBT_HCA_SQD_STATE);
	hca_attr->hca_flags = caps;
	hca_attr->hca_flags2 = IBT_HCA2_DMA_MR;

	/* Determine VendorID, DeviceID, and revision ID */
	hca_attr->hca_vendor_id	 = state->ts_adapter.vendor_id;
	hca_attr->hca_device_id	 = state->ts_adapter.device_id;
	hca_attr->hca_version_id = state->ts_adapter.rev_id;

	/*
	 * Determine number of available QPs and max QP size.  Number of
	 * available QPs is determined by subtracting the number of
	 * "reserved QPs" (i.e. reserved for firmware use) from the
	 * total number configured.
	 */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_qp);
	hca_attr->hca_max_qp = val - ((uint64_t)1 <<
	    state->ts_devlim.log_rsvd_qp);
	maxval	= ((uint64_t)1 << state->ts_devlim.log_max_qp_sz);
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_qp_sz);
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_maxqpsz_toobig_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max QP size "
		    "exceeds device maximum", tnf_uint, maxsz, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_maxqpsz_toobig_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_qp_sz = val;

	/* Determine max scatter-gather size in WQEs */
	maxval	= state->ts_devlim.max_sg;
	val	= state->ts_cfg_profile->cp_wqe_max_sgl;
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanysgl_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of sgl "
		    "exceeds device maximum", tnf_uint, maxsgl, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanysgl_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	/* If the rounded value for max SGL is too large, cap it */
	if (state->ts_cfg_profile->cp_wqe_real_max_sgl > maxval) {
		state->ts_cfg_profile->cp_wqe_real_max_sgl = maxval;
		val = maxval;
	} else {
		val = state->ts_cfg_profile->cp_wqe_real_max_sgl;
	}

	hca_attr->hca_max_sgl	 = val;
	hca_attr->hca_max_rd_sgl = 0;	/* zero because RD is unsupported */

	/*
	 * Determine number of available CQs and max CQ size. Number of
	 * available CQs is determined by subtracting the number of
	 * "reserved CQs" (i.e. reserved for firmware use) from the
	 * total number configured.
	 */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_cq);
	hca_attr->hca_max_cq = val - ((uint64_t)1 <<
	    state->ts_devlim.log_rsvd_cq);
	maxval	= ((uint64_t)1 << state->ts_devlim.log_max_cq_sz);
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_cq_sz) - 1;
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_maxcqsz_toobig_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max CQ size "
		    "exceeds device maximum", tnf_uint, maxsz, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_maxcqsz_toobig_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_cq_sz = val;

	/*
	 * Determine number of available SRQs and max SRQ size. Number of
	 * available SRQs is determined by subtracting the number of
	 * "reserved SRQs" (i.e. reserved for firmware use) from the
	 * total number configured.
	 */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_srq);
	hca_attr->hca_max_srqs = val - ((uint64_t)1 <<
	    state->ts_devlim.log_rsvd_srq);
	maxval  = ((uint64_t)1 << state->ts_devlim.log_max_srq_sz);
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_srq_sz);

	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_maxsrqsz_toobig_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max SRQ size "
		    "exceeds device maximum", tnf_uint, maxsz, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_maxsrqsz_toobig_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_srqs_sz = val;

	val    = state->ts_cfg_profile->cp_srq_max_sgl;
	maxval	= state->ts_devlim.max_sg;
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanysrqsgl_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of srq "
		    "sgl exceeds device maximum", tnf_uint, maxsgl, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanysrqsgl_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_srq_sgl = val;

	/*
	 * Determine supported HCA page sizes
	 * XXX
	 * For now we simply return the system pagesize as the only supported
	 * pagesize
	 */
	hca_attr->hca_page_sz = ((PAGESIZE == (1 << 13)) ? IBT_PAGE_8K :
	    IBT_PAGE_4K);

	/*
	 * Determine number of available MemReg, MemWin, and their max size.
	 * Number of available MRs and MWs is determined by subtracting
	 * the number of "reserved MPTs" (i.e. reserved for firmware use)
	 * from the total number configured for each.
	 */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_mpt);
	hca_attr->hca_max_memr	  = val - ((uint64_t)1 <<
	    state->ts_devlim.log_rsvd_mpt);
	hca_attr->hca_max_mem_win = val - ((uint64_t)1 <<
	    state->ts_devlim.log_rsvd_mpt);
	maxval	= state->ts_devlim.log_max_mrw_sz;
	val	= state->ts_cfg_profile->cp_log_max_mrw_sz;
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_maxmrwsz_toobig_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max mrw size "
		    "exceeds device maximum", tnf_uint, maxsz, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_maxmrwsz_toobig_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_memr_len = ((uint64_t)1 << val);

	/* Determine RDMA/Atomic properties */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_rdb);
	hca_attr->hca_max_rsc = val;
	val = state->ts_cfg_profile->cp_hca_max_rdma_in_qp;
	hca_attr->hca_max_rdma_in_qp  = val;
	val = state->ts_cfg_profile->cp_hca_max_rdma_out_qp;
	hca_attr->hca_max_rdma_out_qp = val;
	hca_attr->hca_max_rdma_in_ee  = 0;
	hca_attr->hca_max_rdma_out_ee = 0;

	/*
	 * Determine maximum number of raw IPv6 and Ether QPs.  Set to 0
	 * because neither type of raw QP is supported
	 */
	hca_attr->hca_max_ipv6_qp  = 0;
	hca_attr->hca_max_ether_qp = 0;

	/* Determine max number of MCGs and max QP-per-MCG */
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_qp);
	hca_attr->hca_max_mcg_qps   = val;
	val = ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_mcg);
	hca_attr->hca_max_mcg	    = val;
	val = state->ts_cfg_profile->cp_num_qp_per_mcg;
	hca_attr->hca_max_qp_per_mcg = val;

	/* Determine max number partitions (i.e. PKeys) */
	maxval	= ((uint64_t)1 << state->ts_devlim.log_max_pkey);
	val	= ((uint64_t)state->ts_cfg_profile->cp_num_ports <<
	    state->ts_cfg_profile->cp_log_max_pkeytbl);

	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanypkey_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of PKeys "
		    "exceeds device maximum", tnf_uint, maxpkey, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanypkey_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_partitions = val;

	/* Determine number of ports */
	maxval = state->ts_devlim.num_ports;
	val = state->ts_cfg_profile->cp_num_ports;
	if ((val > maxval) || (val == 0)) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanyports_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of ports "
		    "exceeds device maximum", tnf_uint, maxports, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanyports_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_nports = val;

	/* Copy NodeGUID and SystemImageGUID from softstate */
	hca_attr->hca_node_guid = state->ts_nodeguid;
	hca_attr->hca_si_guid	= state->ts_sysimgguid;

	/*
	 * Determine local ACK delay.  Use the value suggested by the Tavor
	 * hardware (from the QUERY_DEV_LIM command)
	 */
	hca_attr->hca_local_ack_delay = state->ts_devlim.ca_ack_delay;

	/* Determine max SGID table and PKey table sizes */
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_gidtbl);
	hca_attr->hca_max_port_sgid_tbl_sz = val;
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_max_pkeytbl);
	hca_attr->hca_max_port_pkey_tbl_sz = val;

	/* Determine max number of PDs */
	maxval	= ((uint64_t)1 << state->ts_devlim.log_max_pd);
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_pd);
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanypd_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of PD "
		    "exceeds device maximum", tnf_uint, maxpd, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanypd_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_pd = val;

	/* Determine max number of Address Handles */
	maxval	= ((uint64_t)1 << state->ts_devlim.log_max_av);
	val	= ((uint64_t)1 << state->ts_cfg_profile->cp_log_num_ah);
	if (val > maxval) {
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_2(tavor_soft_state_init_toomanyah_fail,
		    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "number of AH "
		    "exceeds device maximum", tnf_uint, maxah, maxval);
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_toomanyah_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}
	hca_attr->hca_max_ah = val;

	/* No RDDs or EECs (since Reliable Datagram is not supported) */
	hca_attr->hca_max_rdd = 0;
	hca_attr->hca_max_eec = 0;

	/* Initialize lock for reserved UAR page access */
	mutex_init(&state->ts_uar_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/* Initialize the flash fields */
	state->ts_fw_flashstarted = 0;
	mutex_init(&state->ts_fw_flashlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/* Initialize the lock for the info ioctl */
	mutex_init(&state->ts_info_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/* Initialize the AVL tree for QP number support */
	tavor_qpn_avl_init(state);

	/* Initialize the kstat info structure */
	status = tavor_kstat_init(state);
	if (status != DDI_SUCCESS) {
		tavor_qpn_avl_fini(state);
		mutex_destroy(&state->ts_info_lock);
		mutex_destroy(&state->ts_fw_flashlock);
		mutex_destroy(&state->ts_uar_lock);
		kmem_free(hca_attr, sizeof (ibt_hca_attr_t));
		TNF_PROBE_0(tavor_soft_state_init_kstatinit_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_ATTACH_MSG(state->ts_attach_buf,
		    "soft_state_init_kstatinit_fail");
		TAVOR_TNF_EXIT(tavor_soft_state_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_soft_state_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_soft_state_fini()
 *    Context: Called only from detach() path context
 */
static void
tavor_soft_state_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_soft_state_fini);

	/* Teardown the kstat info */
	tavor_kstat_fini(state);

	/* Teardown the AVL tree for QP number support */
	tavor_qpn_avl_fini(state);

	/* Free up info ioctl mutex */
	mutex_destroy(&state->ts_info_lock);

	/* Free up flash mutex */
	mutex_destroy(&state->ts_fw_flashlock);

	/* Free up the UAR page access mutex */
	mutex_destroy(&state->ts_uar_lock);

	/* Free up the hca_attr struct */
	kmem_free(state->ts_ibtfinfo.hca_attr, sizeof (ibt_hca_attr_t));

	TAVOR_TNF_EXIT(tavor_soft_state_fini);
}


/*
 * tavor_hca_config_setup()
 *    Context: Only called from attach() path context
 */
static void
tavor_hca_config_setup(tavor_state_t *state,
    tavor_hw_initqueryhca_t *inithca)
{
	tavor_rsrc_pool_info_t	*rsrc_pool;
	uint64_t		ddr_baseaddr, ddr_base_map_addr;
	uint64_t		offset, addr;
	uint_t			mcg_size;

	TAVOR_TNF_ENTER(tavor_hca_config_setup);

	/* Set "host endianness".  Default is big endian */
#ifdef	_LITTLE_ENDIAN
	inithca->big_endian	= 0;
#else
	inithca->big_endian	= 1;
#endif
	/* No Address Vector Protection, but Port Checking on by default */
	inithca->udav_chk	= TAVOR_UDAV_PROTECT_DISABLED;
	inithca->udav_port_chk	= TAVOR_UDAV_PORTCHK_ENABLED;

	ddr_baseaddr	  = (uint64_t)(uintptr_t)state->ts_reg_ddr_baseaddr;
	ddr_base_map_addr = (uint64_t)state->ts_ddr.ddr_baseaddr;

	/* Setup QPC table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_QPC];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.qpc_baseaddr_h = (addr >> 32);
	inithca->context.qpc_baseaddr_l = (addr & 0xFFFFFFFF) >> 7;
	inithca->context.log_num_qp	= state->ts_cfg_profile->cp_log_num_qp;

	/* Setup EEC table (initialize to zero - RD unsupported) */
	inithca->context.eec_baseaddr_h	= 0;
	inithca->context.eec_baseaddr_l	= 0;
	inithca->context.log_num_ee	= 0;

	/* Setup CQC table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_CQC];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.cqc_baseaddr_h = (addr >> 32);
	inithca->context.cqc_baseaddr_l = (addr & 0xFFFFFFFF) >> 6;
	inithca->context.log_num_cq	= state->ts_cfg_profile->cp_log_num_cq;

	/* Setup SRQC table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_SRQC];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.srqc_baseaddr_h = (addr >> 32);
	inithca->context.srqc_baseaddr_l = (addr & 0xFFFFFFFF) >> 6;
	inithca->context.log_num_srq	 =
	    state->ts_cfg_profile->cp_log_num_srq;

	/* Setup EQPC table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_EQPC];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.eqpc_baseaddr	= addr;

	/* Setup EEEC table (initialize to zero - RD unsupported) */
	inithca->context.eeec_baseaddr	= 0;

	/* Setup EQC table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_EQC];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.eqc_baseaddr_h = (addr >> 32);
	inithca->context.eqc_baseaddr_l = (addr & 0xFFFFFFFF) >> 6;
	inithca->context.log_num_eq	= TAVOR_NUM_EQ_SHIFT;

	/* Setup RDB table */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_RDB];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->context.rdb_baseaddr_h	= (addr >> 32);
	inithca->context.rdb_baseaddr_l = 0;

	/* Setup Multicast */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MCG];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->multi.mc_baseaddr	= addr;
	mcg_size = TAVOR_MCGMEM_SZ(state);
	inithca->multi.log_mc_tbl_ent	= highbit(mcg_size) - 1;
	inithca->multi.mc_tbl_hash_sz	=
	    (1 << state->ts_cfg_profile->cp_log_num_mcg_hash);
	inithca->multi.mc_hash_fn	= TAVOR_MCG_DEFAULT_HASH_FN;
	inithca->multi.log_mc_tbl_sz	= state->ts_cfg_profile->cp_log_num_mcg;


	/* Setup TPT */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MPT];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->tpt.mpt_baseaddr	= addr;
	inithca->tpt.mttseg_sz		= TAVOR_MTTSEG_SIZE_SHIFT;
	inithca->tpt.log_mpt_sz		= state->ts_cfg_profile->cp_log_num_mpt;
	inithca->tpt.mtt_version	= TAVOR_MTT_PG_WALK_VER;

	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_MTT];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->tpt.mtt_baseaddr	= addr;

	/* Setup UAR */
	rsrc_pool = &state->ts_rsrc_hdl[TAVOR_UAR_SCR];
	offset = (uint64_t)(uintptr_t)rsrc_pool->rsrc_start - ddr_baseaddr;
	addr = ddr_base_map_addr + offset;
	inithca->uar.uarscr_baseaddr	= addr;

	inithca->uar.uar_pg_sz = PAGESHIFT - 0xC;

	TAVOR_TNF_EXIT(tavor_hca_config_setup);
}


/*
 * tavor_hca_port_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_hca_port_init(tavor_state_t *state)
{
	tavor_hw_initib_t	*portinits, *initib;
	tavor_cfg_profile_t	*cfgprof;
	uint_t			num_ports;
	int			i, status;
	uint64_t		maxval, val;
	uint64_t		sysimgguid, nodeguid, portguid;

	TAVOR_TNF_ENTER(tavor_hca_port_init);

	cfgprof = state->ts_cfg_profile;

	/* Get number of HCA ports */
	num_ports = cfgprof->cp_num_ports;

	/* Allocate space for Tavor port init struct(s) */
	portinits = (tavor_hw_initib_t *)kmem_zalloc(num_ports *
	    sizeof (tavor_hw_initib_t), KM_SLEEP);

	/* Post command to initialize Tavor HCA port */
	for (i = 0; i < num_ports; i++) {
		initib = &portinits[i];

		/*
		 * Determine whether we need to override the firmware's
		 * default SystemImageGUID setting.
		 */
		sysimgguid = cfgprof->cp_sysimgguid;
		if (sysimgguid != 0) {
			initib->set_sysimg_guid	= 1;
			initib->sysimg_guid	= sysimgguid;
		}

		/*
		 * Determine whether we need to override the firmware's
		 * default NodeGUID setting.
		 */
		nodeguid = cfgprof->cp_nodeguid;
		if (nodeguid != 0) {
			initib->set_node_guid	= 1;
			initib->node_guid	= nodeguid;
		}

		/*
		 * Determine whether we need to override the firmware's
		 * default PortGUID setting.
		 */
		portguid = cfgprof->cp_portguid[i];
		if (portguid != 0) {
			initib->set_port_guid0	= 1;
			initib->guid0		= portguid;
		}

		/* Validate max MTU size */
		maxval  = state->ts_devlim.max_mtu;
		val	= cfgprof->cp_max_mtu;
		if (val > maxval) {
			TNF_PROBE_2(tavor_hca_port_init_maxmtu_fail,
			    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max "
			    "MTU size exceeds device maximum", tnf_uint,
			    maxmtu, maxval);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
		initib->mtu_cap = val;

		/* Validate the max port width */
		maxval  = state->ts_devlim.max_port_width;
		val	= cfgprof->cp_max_port_width;
		if (val > maxval) {
			TNF_PROBE_2(tavor_hca_port_init_maxportwidth_fail,
			    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max "
			    "port width exceeds device maximum", tnf_uint,
			    maxportwidth, maxval);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
		initib->port_width_cap = val;

		/* Validate max VL cap size */
		maxval  = state->ts_devlim.max_vl;
		val	= cfgprof->cp_max_vlcap;
		if (val > maxval) {
			TNF_PROBE_2(tavor_hca_port_init_maxvlcap_fail,
			    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max "
			    "VLcap size exceeds device maximum", tnf_uint,
			    maxvlcap, maxval);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
		initib->vl_cap = val;

		/* Validate max GID table size */
		maxval  = ((uint64_t)1 << state->ts_devlim.log_max_gid);
		val	= ((uint64_t)1 << cfgprof->cp_log_max_gidtbl);
		if (val > maxval) {
			TNF_PROBE_2(tavor_hca_port_init_gidtable_fail,
			    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max "
			    "GID table size exceeds device maximum", tnf_uint,
			    maxgidtbl, maxval);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
		initib->max_gid = val;

		/* Validate max PKey table size */
		maxval	= ((uint64_t)1 << state->ts_devlim.log_max_pkey);
		val	= ((uint64_t)1 << cfgprof->cp_log_max_pkeytbl);
		if (val > maxval) {
			TNF_PROBE_2(tavor_hca_port_init_pkeytable_fail,
			    TAVOR_TNF_ERROR, "", tnf_string, errmsg, "max "
			    "PKey table size exceeds device maximum", tnf_uint,
			    maxpkeytbl, maxval);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
		initib->max_pkey = val;

		/*
		 * Post the INIT_IB command to Tavor firmware.  When this
		 * command completes, the corresponding Tavor port will be
		 * physically "Up" and initialized.
		 */
		status = tavor_init_ib_cmd_post(state, initib, i + 1,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			cmn_err(CE_CONT, "Tavor: INIT_IB (port %02d) command "
			    "failed: %08x\n", i + 1, status);
			TNF_PROBE_2(tavor_hca_port_init_init_ib_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, port, i + 1);
			TAVOR_TNF_EXIT(tavor_hca_port_init);
			goto init_ports_fail;
		}
	}

	/* Free up the memory for Tavor port init struct(s), return success */
	kmem_free(portinits, num_ports * sizeof (tavor_hw_initib_t));
	TAVOR_TNF_EXIT(tavor_hca_port_init);
	return (DDI_SUCCESS);

init_ports_fail:
	/*
	 * Free up the memory for Tavor port init struct(s), shutdown any
	 * successfully initialized ports, and return failure
	 */
	kmem_free(portinits, num_ports * sizeof (tavor_hw_initib_t));
	(void) tavor_hca_ports_shutdown(state, i);

	TAVOR_TNF_EXIT(tavor_hca_port_init);
	return (DDI_FAILURE);
}


/*
 * tavor_hca_ports_shutdown()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static int
tavor_hca_ports_shutdown(tavor_state_t *state, uint_t num_init)
{
	int	i, status;

	TAVOR_TNF_ENTER(tavor_hca_ports_shutdown);

	/*
	 * Post commands to shutdown all init'd Tavor HCA ports.  Note: if
	 * any of these commands fail for any reason, it would be entirely
	 * unexpected and probably indicative a serious problem (HW or SW).
	 * Although we do return void from this function, this type of failure
	 * should not go unreported.  That is why we have the warning message
	 * and the detailed TNF information.
	 */
	for (i = 0; i < num_init; i++) {
		status = tavor_close_ib_cmd_post(state, i + 1,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			TAVOR_WARNING(state, "failed to shutdown HCA port");
			TNF_PROBE_2(tavor_hca_ports_shutdown_close_ib_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, cmd_status, status,
			    tnf_uint, port, i + 1);
			TAVOR_TNF_EXIT(tavor_hca_ports_shutdown);
			return (status);
		}
	}

	TAVOR_TNF_EXIT(tavor_hca_ports_shutdown);

	return (TAVOR_CMD_SUCCESS);
}


/*
 * tavor_internal_uarpgs_init
 *    Context: Only called from attach() path context
 */
static int
tavor_internal_uarpgs_init(tavor_state_t *state)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_internal_uarpgs_init);

	/*
	 * Save away reserved Tavor UAR page #0.  This UAR page is not to
	 * be used by software.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_UARPG, 1, TAVOR_SLEEP,
	    &state->ts_uarpg0_rsrc_rsrvd);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_uarpg0_rsrcalloc_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_internal_uarpgs_init);
		return (DDI_FAILURE);
	}

	/*
	 * Save away Tavor UAR page #1 (for internal use).  This UAR page is
	 * the privileged UAR page through which all kernel generated
	 * doorbells will be rung.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_UARPG, 1, TAVOR_SLEEP,
	    &state->ts_uarpg1_rsrc);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_free(state, &state->ts_uarpg0_rsrc_rsrvd);
		TNF_PROBE_0(tavor_uarpg1_rsrcalloc_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_internal_uarpgs_init);
		return (DDI_FAILURE);
	}

	/* Setup pointer to UAR page #1 doorbells */
	state->ts_uar = (tavor_hw_uar_t *)state->ts_uarpg1_rsrc->tr_addr;

	TAVOR_TNF_EXIT(tavor_internal_uarpgs_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_internal_uarpgs_fini
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_internal_uarpgs_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_internal_uarpgs_fini);

	/* Free up Tavor UAR page #1 (kernel driver doorbells) */
	tavor_rsrc_free(state, &state->ts_uarpg1_rsrc);

	/* Free up Tavor UAR page #0 (reserved) */
	tavor_rsrc_free(state, &state->ts_uarpg0_rsrc_rsrvd);

	TAVOR_TNF_EXIT(tavor_internal_uarpgs_fini);
}


/*
 * tavor_special_qp_contexts_reserve()
 *    Context: Only called from attach() path context
 */
static int
tavor_special_qp_contexts_reserve(tavor_state_t *state)
{
	tavor_rsrc_t	*qp0_rsrc, *qp1_rsrc;
	int		status;

	TAVOR_TNF_ENTER(tavor_special_qp_contexts_reserve);

	/* Initialize the lock used for special QP rsrc management */
	mutex_init(&state->ts_spec_qplock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	/*
	 * Reserve contexts for QP0.  These QP contexts will be setup to
	 * act as aliases for the real QP0.  Note: We are required to grab
	 * two QPs (one per port) even if we are operating in single-port
	 * mode.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_QPC, 2, TAVOR_SLEEP, &qp0_rsrc);
	if (status != DDI_SUCCESS) {
		mutex_destroy(&state->ts_spec_qplock);
		TNF_PROBE_0(tavor_special_qp_contexts_reserve_qp0_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_special_qp_contexts_reserve);
		return (DDI_FAILURE);
	}
	state->ts_spec_qp0 = qp0_rsrc;

	/*
	 * Reserve contexts for QP1.  These QP contexts will be setup to
	 * act as aliases for the real QP1.  Note: We are required to grab
	 * two QPs (one per port) even if we are operating in single-port
	 * mode.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_QPC, 2, TAVOR_SLEEP, &qp1_rsrc);
	if (status != DDI_SUCCESS) {
		tavor_rsrc_free(state, &qp0_rsrc);
		mutex_destroy(&state->ts_spec_qplock);
		TNF_PROBE_0(tavor_special_qp_contexts_reserve_qp1_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_special_qp_contexts_reserve);
		return (DDI_FAILURE);
	}
	state->ts_spec_qp1 = qp1_rsrc;

	TAVOR_TNF_EXIT(tavor_special_qp_contexts_reserve);
	return (DDI_SUCCESS);
}


/*
 * tavor_special_qp_contexts_unreserve()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_special_qp_contexts_unreserve(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_special_qp_contexts_unreserve);

	/* Unreserve contexts for QP1 */
	tavor_rsrc_free(state, &state->ts_spec_qp1);

	/* Unreserve contexts for QP0 */
	tavor_rsrc_free(state, &state->ts_spec_qp0);

	/* Destroy the lock used for special QP rsrc management */
	mutex_destroy(&state->ts_spec_qplock);

	TAVOR_TNF_EXIT(tavor_special_qp_contexts_unreserve);
}


/*
 * tavor_sw_reset()
 *    Context: Currently called only from attach() path context
 */
static int
tavor_sw_reset(tavor_state_t *state)
{
	dev_info_t		*dip, *pdip;
	ddi_acc_handle_t	hdl = state->ts_pci_cfghdl, phdl;
	uint32_t		reset_delay;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_sw_reset);

	/*
	 * If the configured software reset delay is set to zero, then we
	 * will not attempt a software reset of the Tavor device.
	 */
	reset_delay = state->ts_cfg_profile->cp_sw_reset_delay;
	if (reset_delay == 0) {
		TAVOR_TNF_EXIT(tavor_sw_reset);
		return (DDI_SUCCESS);
	}

	/*
	 * Get dip for HCA device _and_ parent device as well.  Parent access
	 * is necessary here because software reset of the Tavor hardware
	 * will reinitialize both the config registers of the PCI bridge
	 * (parent, if it exists) and the IB HCA (self)
	 */
	dip  = state->ts_dip;
	pdip = ddi_get_parent(dip);

	/* Query the PCI capabilities of the HCA device */
	tavor_pci_capability_list(state, hdl);

	/*
	 * Read all PCI config info (reg0...reg63).  Note: According to the
	 * Tavor software reset application note, we should not read or
	 * restore the values in reg22 and reg23.
	 */
	for (i = 0; i < TAVOR_SW_RESET_NUMREGS; i++) {
		if ((i != TAVOR_SW_RESET_REG22_RSVD) &&
		    (i != TAVOR_SW_RESET_REG23_RSVD)) {
			state->ts_cfg_data[i]  = pci_config_get32(hdl, i << 2);
		}
	}

	if (TAVOR_PARENT_IS_BRIDGE(pdip)) {
		/*
		 * Setup for PCI config read/write of bridge device
		 */
		status = pci_config_setup(pdip, &phdl);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_sw_reset_pcicfg_p_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_sw_reset);
			return (DDI_FAILURE);
		}

		/*
		 * Read all PCI config info (reg0...reg63).  Note: According to
		 * the Tavor software reset application note, we should not
		 * read or restore the values in reg22 and reg23.
		 */
		for (i = 0; i < TAVOR_SW_RESET_NUMREGS; i++) {
			if ((i != TAVOR_SW_RESET_REG22_RSVD) &&
			    (i != TAVOR_SW_RESET_REG23_RSVD)) {
				state->ts_cfg_pdata[i] =
				    pci_config_get32(phdl, i << 2);
			}
		}
	}

	/*
	 * Perform the software reset (by writing 1 at offset 0xF0010)
	 */
	ddi_put32(state->ts_reg_cmdhdl, state->ts_cmd_regs.sw_reset,
	    TAVOR_SW_RESET_START);

	drv_usecwait(reset_delay);

	if (TAVOR_PARENT_IS_BRIDGE(pdip)) {
		/*
		 * Bridge exists, so wait for the bridge to become ready.
		 *
		 * The above delay is necessary to avoid system panic from
		 * Master Abort.  If the device is accessed before this delay,
		 * device will not respond to config cycles and they will be
		 * terminate with a Master Abort which will panic the system.
		 * Below is the loop we use to poll status from the device to
		 * determine if it is OK to proceed.
		 */
		i = 0;
		while (pci_config_get32(phdl, 0) == TAVOR_SW_RESET_NOTDONE) {
			drv_usecwait(TAVOR_SW_RESET_POLL_DELAY);
		}

		/*
		 * Write all the PCI config registers back into each device
		 * (except for reg22 and reg23 - see above)
		 */
		for (i = 0; i < TAVOR_SW_RESET_NUMREGS; i++) {
			if ((i != TAVOR_SW_RESET_REG22_RSVD) &&
			    (i != TAVOR_SW_RESET_REG23_RSVD)) {
				pci_config_put32(phdl, i << 2,
				    state->ts_cfg_pdata[i]);
			}
		}

		/*
		 * Tear down the config setup (for bridge device)
		 */
		pci_config_teardown(&phdl);

	/* No Bridge Device */
	} else {
		/*
		 * Bridge does not exist, so instead wait for the device itself
		 * to become ready.
		 *
		 * The above delay is necessary to avoid system panic from
		 * Master Abort.  If the device is accessed before this delay,
		 * device will not respond to config cycles and they will be
		 * terminate with a Master Abort which will panic the system.
		 * Below is the loop we use to poll status from the device to
		 * determine if it is OK to proceed.
		 */
		i = 0;
		while (pci_config_get32(hdl, 0) == TAVOR_SW_RESET_NOTDONE) {
			drv_usecwait(TAVOR_SW_RESET_POLL_DELAY);
		}
	}

	for (i = 0; i < TAVOR_SW_RESET_NUMREGS; i++) {
		if ((i != TAVOR_SW_RESET_REG22_RSVD) &&
		    (i != TAVOR_SW_RESET_REG23_RSVD)) {
			pci_config_put32(hdl, i << 2, state->ts_cfg_data[i]);
		}
	}

	TAVOR_TNF_EXIT(tavor_sw_reset);
	return (DDI_SUCCESS);
}


/*
 * tavor_mcg_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_mcg_init(tavor_state_t *state)
{
	uint_t		mcg_tmp_sz;

	TAVOR_TNF_ENTER(tavor_mcg_init);

	/*
	 * Allocate space for the MCG temporary copy buffer.  This is
	 * used by the Attach/Detach Multicast Group code
	 */
	mcg_tmp_sz = TAVOR_MCGMEM_SZ(state);
	state->ts_mcgtmp = kmem_zalloc(mcg_tmp_sz, KM_SLEEP);

	/*
	 * Initialize the multicast group mutex.  This ensures atomic
	 * access to add, modify, and remove entries in the multicast
	 * group hash lists.
	 */
	mutex_init(&state->ts_mcglock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));

	TAVOR_TNF_EXIT(tavor_mcg_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_mcg_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_mcg_fini(tavor_state_t *state)
{
	uint_t		mcg_tmp_sz;

	TAVOR_TNF_ENTER(tavor_mcg_fini);

	/* Free up the space used for the MCG temporary copy buffer */
	mcg_tmp_sz = TAVOR_MCGMEM_SZ(state);
	kmem_free(state->ts_mcgtmp, mcg_tmp_sz);

	/* Destroy the multicast group mutex */
	mutex_destroy(&state->ts_mcglock);

	TAVOR_TNF_EXIT(tavor_mcg_fini);
}


/*
 * tavor_fw_version_check()
 *    Context: Only called from attach() path context
 */
static int
tavor_fw_version_check(tavor_state_t *state)
{
	uint_t	tavor_fw_ver_major;
	uint_t	tavor_fw_ver_minor;
	uint_t	tavor_fw_ver_subminor;

	/*
	 * Depending on which version of driver we have attached, the firmware
	 * version checks will be different.  We set up the comparison values
	 * for both HCA Mode (Tavor hardware) or COMPAT Mode (Arbel hardware
	 * running in tavor mode).
	 */
	switch (state->ts_operational_mode) {
	case TAVOR_HCA_MODE:
		tavor_fw_ver_major = TAVOR_FW_VER_MAJOR;
		tavor_fw_ver_minor = TAVOR_FW_VER_MINOR;
		tavor_fw_ver_subminor = TAVOR_FW_VER_SUBMINOR;
		break;

	case TAVOR_COMPAT_MODE:
		tavor_fw_ver_major = TAVOR_COMPAT_FW_VER_MAJOR;
		tavor_fw_ver_minor = TAVOR_COMPAT_FW_VER_MINOR;
		tavor_fw_ver_subminor = TAVOR_COMPAT_FW_VER_SUBMINOR;
		break;

	default:
		return (DDI_FAILURE);
	}

	/*
	 * If FW revision major number is less than acceptable,
	 * return failure, else if greater return success.  If
	 * the major numbers are equal than check the minor number
	 */
	if (state->ts_fw.fw_rev_major < tavor_fw_ver_major) {
		return (DDI_FAILURE);
	} else if (state->ts_fw.fw_rev_major > tavor_fw_ver_major) {
		return (DDI_SUCCESS);
	}
	/*
	 * Do the same check as above, except for minor revision numbers
	 * If the minor numbers are equal than check the subminor number
	 */
	if (state->ts_fw.fw_rev_minor < tavor_fw_ver_minor) {
		return (DDI_FAILURE);
	} else if (state->ts_fw.fw_rev_minor > tavor_fw_ver_minor) {
		return (DDI_SUCCESS);
	}

	/*
	 * Once again we do the same check as above, except for the subminor
	 * revision number.  If the subminor numbers are equal here, then
	 * these are the same firmware version, return success
	 */
	if (state->ts_fw.fw_rev_subminor < tavor_fw_ver_subminor) {
		return (DDI_FAILURE);
	} else if (state->ts_fw.fw_rev_subminor > tavor_fw_ver_subminor) {
		return (DDI_SUCCESS);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_device_info_report()
 *    Context: Only called from attach() path context
 */
static void
tavor_device_info_report(tavor_state_t *state)
{
	cmn_err(CE_CONT, "?tavor%d: FW ver: %04d.%04d.%04d, "
	    "HW rev: %02x\n", state->ts_instance, state->ts_fw.fw_rev_major,
	    state->ts_fw.fw_rev_minor, state->ts_fw.fw_rev_subminor,
	    state->ts_adapter.rev_id);
	cmn_err(CE_CONT, "?tavor%d: %64s (0x%016" PRIx64 ")\n",
	    state->ts_instance, state->ts_nodedesc, state->ts_nodeguid);
}


/*
 * tavor_pci_capability_list()
 *    Context: Only called from attach() path context
 */
static void
tavor_pci_capability_list(tavor_state_t *state, ddi_acc_handle_t hdl)
{
	uint_t	offset, data;

	TAVOR_TNF_ENTER(tavor_pci_capability_list);

	/*
	 * Check for the "PCI Capabilities" bit in the "Status Register".
	 * Bit 4 in this register indicates the presence of a "PCI
	 * Capabilities" list.
	 */
	data = pci_config_get16(hdl, 0x6);
	if ((data & 0x10) == 0) {
		TNF_PROBE_0(tavor_pci_capab_list_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_pci_capability_list);
		return;
	}

	/*
	 * Starting from offset 0x34 in PCI config space, find the
	 * head of "PCI capabilities" list, and walk the list.  If
	 * capabilities of a known type are encountered (e.g.
	 * "PCI-X Capability"), then call the appropriate handler
	 * function.
	 */
	offset = pci_config_get8(hdl, 0x34);
	while (offset != 0x0) {
		data = pci_config_get8(hdl, offset);

		/*
		 * Check for known capability types.  Tavor has the
		 * following:
		 *    o VPD Capability   (0x03)
		 *    o PCI-X Capability (0x07)
		 *    o MSI Capability   (0x05)
		 *    o MSIX Capability  (0x11)
		 */
		switch (data) {
		case 0x03:
			tavor_pci_capability_vpd(state, hdl, offset);
			break;
		case 0x07:
			tavor_pci_capability_pcix(state, hdl, offset);
			break;
		case 0x05:
			break;
		default:
			break;
		}

		/* Get offset of next entry in list */
		offset = pci_config_get8(hdl, offset + 1);
	}

	TAVOR_TNF_EXIT(tavor_pci_capability_list);
}

/*
 * tavor_pci_read_vpd()
 *    Context: Only called from attach() path context
 *    utility routine for tavor_pci_capability_vpd()
 */
static int
tavor_pci_read_vpd(ddi_acc_handle_t hdl, uint_t offset, uint32_t addr,
    uint32_t *data)
{
	int		retry = 4;  /* retry counter for EEPROM poll */
	uint32_t	val;
	int		vpd_addr = offset + 2;
	int		vpd_data = offset + 4;

	TAVOR_TNF_ENTER(tavor_pci_read_vpd);

	/*
	 * In order to read a 32-bit value from VPD, we are to write down
	 * the address (offset in the VPD itself) to the address register.
	 * To signal the read, we also clear bit 31.  We then poll on bit 31
	 * and when it is set, we can then read our 4 bytes from the data
	 * register.
	 */
	(void) pci_config_put32(hdl, offset, addr << 16);
	do {
		drv_usecwait(1000);
		val = pci_config_get16(hdl, vpd_addr);
		if ((val >> 15) & 0x01) {
			*data = pci_config_get32(hdl, vpd_data);
			TAVOR_TNF_EXIT(tavor_pci_read_vpd);
			return (DDI_SUCCESS);
		}
	} while (--retry);

	TNF_PROBE_0(tavor_pci_read_vpd_fail, TAVOR_TNF_ERROR, "");
	TAVOR_TNF_EXIT(tavor_pci_read_vpd);
	return (DDI_FAILURE);
}


/*
 * tavor_pci_capability_vpd()
 *    Context: Only called from attach() path context
 */
static void
tavor_pci_capability_vpd(tavor_state_t *state, ddi_acc_handle_t hdl,
    uint_t offset)
{
	uint8_t			name_length;
	uint8_t			pn_length;
	int			i, err = 0;
	int			vpd_str_id = 0;
	int			vpd_ro_desc;
	int			vpd_ro_pn_desc;
#ifndef _LITTLE_ENDIAN
	uint32_t		data32;
#endif /* _LITTLE_ENDIAN */
	union {
		uint32_t	vpd_int[TAVOR_VPD_HDR_DWSIZE];
		uchar_t		vpd_char[TAVOR_VPD_HDR_BSIZE];
	} vpd;

	TAVOR_TNF_ENTER(tavor_pci_capability_vpd);

	/*
	 * Read Vital Product Data (VPD) from PCI-X capability.
	 */
	for (i = 0; i < TAVOR_VPD_HDR_DWSIZE; i++) {
		err = tavor_pci_read_vpd(hdl, offset, i << 2, &vpd.vpd_int[i]);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "!VPD read failed\n");
			goto out;
		}
	}

#ifndef _LITTLE_ENDIAN
	/*
	 * Need to swap bytes for big endian.
	 */
	for (i = 0; i < TAVOR_VPD_HDR_DWSIZE; i++) {
		data32 = vpd.vpd_int[i];
		vpd.vpd_char[(i << 2) + 3] =
		    (uchar_t)((data32 & 0xFF000000) >> 24);
		vpd.vpd_char[(i << 2) + 2] =
		    (uchar_t)((data32 & 0x00FF0000) >> 16);
		vpd.vpd_char[(i << 2) + 1] =
		    (uchar_t)((data32 & 0x0000FF00) >> 8);
		vpd.vpd_char[i << 2] = (uchar_t)(data32 & 0x000000FF);
	}
#endif	/* _LITTLE_ENDIAN */

	/* Check for VPD String ID Tag */
	if (vpd.vpd_char[vpd_str_id] == 0x82) {
		/* get the product name */
		name_length = (uint8_t)vpd.vpd_char[vpd_str_id + 1];
		if (name_length > sizeof (state->ts_hca_name)) {
			cmn_err(CE_NOTE, "!VPD name too large (0x%x)\n",
			    name_length);
			goto out;
		}
		(void) memcpy(state->ts_hca_name, &vpd.vpd_char[vpd_str_id + 3],
		    name_length);
		state->ts_hca_name[name_length] = 0;

		/* get the part number */
		vpd_ro_desc = name_length + 3; /* read-only tag location */
		vpd_ro_pn_desc = vpd_ro_desc + 3; /* P/N keyword location */
		/*
		 * Verify read-only tag and Part Number keyword.
		 */
		if (vpd.vpd_char[vpd_ro_desc] != 0x90 ||
		    (vpd.vpd_char[vpd_ro_pn_desc] != 'P' &&
		    vpd.vpd_char[vpd_ro_pn_desc + 1] != 'N')) {
			cmn_err(CE_NOTE, "!VPD Part Number not found\n");
			goto out;
		}

		pn_length = (uint8_t)vpd.vpd_char[vpd_ro_pn_desc + 2];
		if (pn_length > sizeof (state->ts_hca_pn)) {
			cmn_err(CE_NOTE, "!VPD part number too large (0x%x)\n",
			    name_length);
			goto out;
		}
		(void) memcpy(state->ts_hca_pn,
		    &vpd.vpd_char[vpd_ro_pn_desc + 3],
		    pn_length);
		state->ts_hca_pn[pn_length] = 0;
		state->ts_hca_pn_len = pn_length;
	} else {
		/* Wrong VPD String ID Tag */
		cmn_err(CE_NOTE, "!VPD String ID Tag not found, tag: %02x\n",
		    vpd.vpd_char[0]);
		goto out;
	}
	TAVOR_TNF_EXIT(tavor_pci_capability_vpd);
	return;
out:
	state->ts_hca_pn_len = 0;
	TNF_PROBE_0(tavor_pci_capability_vpd_fail, TAVOR_TNF_ERROR, "");
	TAVOR_TNF_EXIT(tavor_pci_capability_vpd);
}

/*
 * tavor_pci_capability_pcix()
 *    Context: Only called from attach() path context
 */
static void
tavor_pci_capability_pcix(tavor_state_t *state, ddi_acc_handle_t hdl,
    uint_t offset)
{
	uint_t	command, status;
	int	max_out_splt_trans, max_mem_rd_byte_cnt;
	int	designed_max_out_splt_trans, designed_max_mem_rd_byte_cnt;

	TAVOR_TNF_ENTER(tavor_pci_capability_pcix);

	/*
	 * Query the current values for the PCI-X Command Register and
	 * the PCI-X Status Register.
	 */
	command = pci_config_get16(hdl, offset + 2);
	status  = pci_config_get32(hdl, offset + 4);

	/*
	 * Check for config property specifying "maximum outstanding
	 * split transactions".  If the property is defined and valid
	 * (i.e. no larger than the so-called "designed maximum"),
	 * then use the specified value to update the PCI-X Command Register.
	 * Otherwise, extract the value from the Tavor config profile.
	 */
	designed_max_out_splt_trans = ((status >> 23) & 7);
	max_out_splt_trans = ddi_prop_get_int(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "pcix-max-outstanding-split-trans", -1);
	if ((max_out_splt_trans != -1) &&
	    ((max_out_splt_trans < 0) ||
	    (max_out_splt_trans > designed_max_out_splt_trans))) {
		cmn_err(CE_NOTE, "!tavor%d: property \"pcix-max-outstanding-"
		    "split-trans\" (%d) invalid or exceeds device maximum"
		    " (%d), using default value (%d)\n", state->ts_instance,
		    max_out_splt_trans, designed_max_out_splt_trans,
		    state->ts_cfg_profile->cp_max_out_splt_trans);
		max_out_splt_trans =
		    state->ts_cfg_profile->cp_max_out_splt_trans;
	} else if (max_out_splt_trans == -1) {
		max_out_splt_trans =
		    state->ts_cfg_profile->cp_max_out_splt_trans;
	}

	/*
	 * The config profile setting for max_out_splt_trans is determined
	 * based on arch.  Check tavor_cfg.c for more information.  A value of
	 * '-1' in the patchable variable means "do not change".  A value of
	 * '0' means 1 outstanding splt trans and other values as defined by
	 * PCI.  So we do one more check here, that if 'max_out_splt_trans' is
	 * -1 (ie: < 0) we do not set the PCI command and leave it at the
	 * default.
	 */
	if (max_out_splt_trans >= 0) {
		command = ((command & 0xFF8F) | max_out_splt_trans << 4);
	}

	/*
	 * Check for config property specifying "maximum memory read
	 * byte count.  If the property is defined and valid
	 * (i.e. no larger than the so-called "designed maximum"),
	 * then use the specified value to update the PCI-X Command Register.
	 * Otherwise, extract the value from the Tavor config profile.
	 */
	designed_max_mem_rd_byte_cnt = ((status >> 21) & 3);
	max_mem_rd_byte_cnt = ddi_prop_get_int(DDI_DEV_T_ANY, state->ts_dip,
	    DDI_PROP_DONTPASS, "pcix-max-read-byte-count", -1);
	if ((max_mem_rd_byte_cnt != -1) &&
	    ((max_mem_rd_byte_cnt < 0) ||
	    (max_mem_rd_byte_cnt > designed_max_mem_rd_byte_cnt))) {
		cmn_err(CE_NOTE, "!tavor%d: property \"pcix-max-read-byte-"
		    "count\" (%d) invalid or exceeds device maximum"
		    " (%d), using default value (%d)\n", state->ts_instance,
		    max_mem_rd_byte_cnt, designed_max_mem_rd_byte_cnt,
		    state->ts_cfg_profile->cp_max_mem_rd_byte_cnt);
		max_mem_rd_byte_cnt =
		    state->ts_cfg_profile->cp_max_mem_rd_byte_cnt;
	} else if (max_mem_rd_byte_cnt == -1) {
		max_mem_rd_byte_cnt =
		    state->ts_cfg_profile->cp_max_mem_rd_byte_cnt;
	}

	/*
	 * The config profile setting for max_mem_rd_byte_cnt is determined
	 * based on arch.  Check tavor_cfg.c for more information.  A value of
	 * '-1' in the patchable variable means "do not change".  A value of
	 * '0' means minimum (512B) read, and other values as defined by
	 * PCI.  So we do one more check here, that if 'max_mem_rd_byte_cnt' is
	 * -1 (ie: < 0) we do not set the PCI command and leave it at the
	 * default.
	 */
	if (max_mem_rd_byte_cnt >= 0) {
		command = ((command & 0xFFF3) | max_mem_rd_byte_cnt << 2);
	}

	/*
	 * Update the PCI-X Command Register with the newly configured
	 * values.
	 */
	pci_config_put16(hdl, offset + 2, command);

	TAVOR_TNF_EXIT(tavor_pci_capability_pcix);
}


/*
 * tavor_intr_or_msi_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_intr_or_msi_init(tavor_state_t *state)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_intr_or_msi_init);

	/* Query for the list of supported interrupt event types */
	status = ddi_intr_get_supported_types(state->ts_dip,
	    &state->ts_intr_types_avail);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_intr_or_msi_init_gettypes_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_intr_or_msi_init);
		return (DDI_FAILURE);
	}

	/*
	 * If Tavor/Arbel supports MSI in this system (and, if it
	 * hasn't been overridden by a configuration variable), then
	 * the default behavior is to use a single MSI.  Otherwise,
	 * fallback to using legacy interrupts.  Also, if MSI allocatis chosen,
	 * but fails for whatever reasons, then fallback to using legacy
	 * interrupts.
	 */
	if ((state->ts_cfg_profile->cp_use_msi_if_avail != 0) &&
	    (state->ts_intr_types_avail & DDI_INTR_TYPE_MSI)) {
		status = tavor_add_intrs(state, DDI_INTR_TYPE_MSI);
		if (status == DDI_SUCCESS) {
			state->ts_intr_type_chosen = DDI_INTR_TYPE_MSI;
			TAVOR_TNF_EXIT(tavor_intr_or_msi_init);
			return (DDI_SUCCESS);
		}
	}

	/*
	 * MSI interrupt allocation failed, or was not available.  Fallback to
	 * legacy interrupt support.
	 */
	if (state->ts_intr_types_avail & DDI_INTR_TYPE_FIXED) {
		status = tavor_add_intrs(state, DDI_INTR_TYPE_FIXED);
		if (status == DDI_SUCCESS) {
			state->ts_intr_type_chosen = DDI_INTR_TYPE_FIXED;
			TAVOR_TNF_EXIT(tavor_intr_or_msi_init);
			return (DDI_SUCCESS);
		}
	}

	/*
	 * Neither MSI or legacy interrupts were successful.  return failure.
	 */
	TAVOR_TNF_EXIT(tavor_intr_or_msi_setup);
	return (DDI_FAILURE);
}

/*
 * tavor_add_intrs()
 *    Context: Only called from attach() patch context
 */
static int
tavor_add_intrs(tavor_state_t *state, int intr_type)
{
	int status;

	TAVOR_TNF_ENTER(tavor_add_intrs);

	/* Get number of interrupts/MSI supported */
	status = ddi_intr_get_nintrs(state->ts_dip, intr_type,
	    &state->ts_intrmsi_count);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_add_intrs_getnintrs_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Get number of available interrupts/MSI */
	status = ddi_intr_get_navail(state->ts_dip, intr_type,
	    &state->ts_intrmsi_avail);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_add_intrs_getnavail_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Ensure that we have at least one (1) usable MSI or interrupt */
	if ((state->ts_intrmsi_avail < 1) || (state->ts_intrmsi_count < 1)) {
		TNF_PROBE_0(tavor_add_intrs_notenoughts_intrmsi_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Attempt to allocate a single interrupt/MSI handle */
	status = ddi_intr_alloc(state->ts_dip, &state->ts_intrmsi_hdl,
	    intr_type, 0, 1, &state->ts_intrmsi_allocd,
	    DDI_INTR_ALLOC_STRICT);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_add_intrs_intralloc_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Ensure that we have allocated at least one (1) MSI or interrupt */
	if (state->ts_intrmsi_allocd < 1) {
		TNF_PROBE_0(tavor_add_intrs_noallocts_intrmsi_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/*
	 * Extract the priority for the allocated interrupt/MSI.  This
	 * will be used later when initializing certain mutexes.
	 */
	status = ddi_intr_get_pri(state->ts_intrmsi_hdl,
	    &state->ts_intrmsi_pri);
	if (status != DDI_SUCCESS) {
		/* Free the allocated interrupt/MSI handle */
		(void) ddi_intr_free(state->ts_intrmsi_hdl);

		TNF_PROBE_0(tavor_add_intrs_getpri_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Make sure the interrupt/MSI priority is below 'high level' */
	if (state->ts_intrmsi_pri >= ddi_intr_get_hilevel_pri()) {
		/* Free the allocated interrupt/MSI handle */
		(void) ddi_intr_free(state->ts_intrmsi_hdl);

		TNF_PROBE_0(tavor_add_intrs_hilevelpri_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	/* Get add'l capability information regarding interrupt/MSI */
	status = ddi_intr_get_cap(state->ts_intrmsi_hdl,
	    &state->ts_intrmsi_cap);
	if (status != DDI_SUCCESS) {
		/* Free the allocated interrupt/MSI handle */
		(void) ddi_intr_free(state->ts_intrmsi_hdl);

		TNF_PROBE_0(tavor_add_intrs_getcap_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_add_intrs);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_add_intrs);
	return (DDI_SUCCESS);
}


/*
 * tavor_intr_or_msi_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static int
tavor_intr_or_msi_fini(tavor_state_t *state)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_intr_or_msi_fini);

	/* Free the allocated interrupt/MSI handle */
	status = ddi_intr_free(state->ts_intrmsi_hdl);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_intr_or_msi_fini_freehdl_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_intr_or_msi_fini);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_intr_or_msi_fini);
	return (DDI_SUCCESS);
}


/* Disable Tavor interrupts */
static int
tavor_intr_disable(tavor_state_t *state)
{
	ushort_t msi_ctrl = 0, caps_ctrl = 0;
	ddi_acc_handle_t pci_cfg_hdl = state->ts_pci_cfghdl;
	ASSERT(pci_cfg_hdl != NULL);
	ASSERT(state->ts_intr_types_avail &
	    (DDI_INTR_TYPE_FIXED | DDI_INTR_TYPE_MSI));

	/*
	 * Check if MSI interrupts are used. If so, disable MSI interupts.
	 * If not, since Tavor doesn't support MSI-X interrupts, assuming the
	 * legacy interrupt is used instead, disable the legacy interrupt.
	 */
	if ((state->ts_cfg_profile->cp_use_msi_if_avail != 0) &&
	    (state->ts_intr_types_avail & DDI_INTR_TYPE_MSI)) {

		if ((PCI_CAP_LOCATE(pci_cfg_hdl, PCI_CAP_ID_MSI,
		    &caps_ctrl) == DDI_SUCCESS)) {
			if ((msi_ctrl = PCI_CAP_GET16(pci_cfg_hdl, 0,
			    caps_ctrl, PCI_MSI_CTRL)) == PCI_CAP_EINVAL16)
				return (DDI_FAILURE);
		}
		ASSERT(msi_ctrl != 0);

		if (!(msi_ctrl & PCI_MSI_ENABLE_BIT))
			return (DDI_SUCCESS);

		if (msi_ctrl &  PCI_MSI_PVM_MASK) {
			int offset = (msi_ctrl &  PCI_MSI_64BIT_MASK) ?
			    PCI_MSI_64BIT_MASKBITS : PCI_MSI_32BIT_MASK;

			/* Clear all inums in MSI */
			PCI_CAP_PUT32(pci_cfg_hdl, 0, caps_ctrl, offset, 0);
		}

		/* Disable MSI interrupts */
		msi_ctrl &= ~PCI_MSI_ENABLE_BIT;
		PCI_CAP_PUT16(pci_cfg_hdl, 0, caps_ctrl, PCI_MSI_CTRL,
		    msi_ctrl);

	} else {
		uint16_t cmdreg = pci_config_get16(pci_cfg_hdl, PCI_CONF_COMM);
		ASSERT(state->ts_intr_types_avail & DDI_INTR_TYPE_FIXED);

		/* Disable the legacy interrupts */
		cmdreg |= PCI_COMM_INTX_DISABLE;
		pci_config_put16(pci_cfg_hdl, PCI_CONF_COMM, cmdreg);
	}

	return (DDI_SUCCESS);
}

/* Tavor quiesce(9F) entry */
static int
tavor_quiesce(dev_info_t *dip)
{
	tavor_state_t *state = ddi_get_soft_state(tavor_statep,
	    DEVI(dip)->devi_instance);
	ASSERT(state != NULL);

	/* start fastreboot */
	state->ts_quiescing = B_TRUE;

	/* If it's in maintenance mode, do nothing but return with SUCCESS */
	if (!TAVOR_IS_OPERATIONAL(state->ts_operational_mode)) {
		return (DDI_SUCCESS);
	}

	/* Shutdown HCA ports */
	if (tavor_hca_ports_shutdown(state,
	    state->ts_cfg_profile->cp_num_ports) != TAVOR_CMD_SUCCESS) {
		state->ts_quiescing = B_FALSE;
		return (DDI_FAILURE);
	}

	/* Close HCA */
	if (tavor_close_hca_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN) !=
	    TAVOR_CMD_SUCCESS) {
		state->ts_quiescing = B_FALSE;
		return (DDI_FAILURE);
	}

	/* Shutdown FW */
	if (tavor_sys_dis_cmd_post(state, TAVOR_CMD_NOSLEEP_SPIN) !=
	    TAVOR_CMD_SUCCESS) {
		state->ts_quiescing = B_FALSE;
		return (DDI_FAILURE);
	}

	/* Disable interrupts */
	if (tavor_intr_disable(state) != DDI_SUCCESS) {
		state->ts_quiescing = B_FALSE;
		return (DDI_FAILURE);
	}

	/* SW-reset */
	if (tavor_sw_reset(state) != DDI_SUCCESS) {
		state->ts_quiescing = B_FALSE;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
