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

/*
 * SD card nexus support.
 *
 * NB that this file contains a fair bit of non-DDI compliant code.
 * But writing a nexus driver would be impossible to do with only DDI
 * compliant interfaces.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/list.h>
#include <sys/mkdev.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sdcard/sda.h>
#include <sys/sdcard/sda_ioctl.h>
#include <sys/sdcard/sda_impl.h>
#include <sys/fs/dv_node.h>

/*
 * Local prototypes.
 */

static sda_host_t *sda_nexus_lookup_dev(dev_t);
static int sda_nexus_ap_ioctl(sda_host_t *, int, int, intptr_t);
static int sda_nexus_ap_control(sda_host_t *, int, intptr_t, int);
static int sda_nexus_ap_disconnect(sda_slot_t *);
static int sda_nexus_ap_configure(sda_slot_t *);
static int sda_nexus_ap_unconfigure(sda_slot_t *);
static void sda_nexus_ap_getstate(sda_slot_t *, devctl_ap_state_t *);
static void sda_nexus_reinsert(sda_slot_t *);
static void sda_nexus_create(sda_slot_t *);

/*
 * Static Variables.
 */

static kmutex_t	sda_nexus_lock;
static list_t	sda_nexus_list;

/*
 * Minor number allocation.
 *
 * We have up to NBITSMINOR32 (18) bits available.
 *
 * For each instance, we need one minor number for each slot, and one
 * minor number for the devctl node.
 *
 * For simplicity's sake, we use the lower 8 bits for AP and DEVCTL nodes,
 * and the remaining 10 bits for the instance number.
 */
#define	MINOR_DC		0xff
#define	DEV_SLOT(dev)		(getminor(dev) & 0xff)
#define	DEV_INST(dev)		(getminor(dev) >> 8)
#define	MKMINOR_AP(inst, slot)	(((slot) & 0xff) | ((inst) << 8))
#define	MKMINOR_DC(inst)	(((inst) << 8) | MINOR_DC)

/*
 * Implementation.
 */

void
sda_nexus_init(void)
{
	list_create(&sda_nexus_list, sizeof (sda_host_t),
	    offsetof(struct sda_host, h_node));
	mutex_init(&sda_nexus_lock, NULL, MUTEX_DRIVER, NULL);
}

void
sda_nexus_fini(void)
{
	list_destroy(&sda_nexus_list);
	mutex_destroy(&sda_nexus_lock);
}

int
sda_nexus_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
	{
		cmn_err(CE_CONT, "?SD-device: %s@%s, %s#%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t	*child_dip = (dev_info_t *)arg;
		dev_info_t	*ndip;
		sda_slot_t	*slot;
		char		addr[16];

		if ((slot = ddi_get_parent_data(child_dip)) == NULL) {
			sda_slot_err(NULL, "Parent data struct missing!");
			return (DDI_NOT_WELL_FORMED);
		}

		/*
		 * TODO: SDIO: We will need to use x,y addresses for
		 * SDIO function numbers.  Memory cards will always
		 * resid at address 0.  Probably this can be passed in
		 * to this function using properties.
		 */
		(void) snprintf(addr, sizeof (addr), "%x", slot->s_slot_num);

		/*
		 * Prevent duplicate nodes.
		 */
		ndip = ndi_devi_find(dip, ddi_node_name(child_dip), addr);
		if (ndip && (ndip != child_dip)) {
			sda_slot_err(slot, "Duplicate device node found "
			    "(%s@%d)", ddi_node_name(ndip), addr);
		}

		/*
		 * Stash the address in the devinfo node.
		 */
		ddi_set_name_addr(child_dip, addr);

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t	*child_dip = (dev_info_t *)arg;

		ddi_set_name_addr(child_dip, NULL);
		ndi_prop_remove_all(child_dip);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_SIDDEV:
		/*
		 * All SDA target devices are self-identifying.
		 */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SLAVEONLY:
		/*
		 * We don't support DMA master for SDA targets.
		 */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_AFFINITY:
		/*
		 * NB: We may want to revisit this later, so that functions
		 * on one card can see other functions on the same card.
		 * Right now there is no need.
		 */
		return (DDI_FAILURE);

	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_REGSIZE:
		/*
		 * We don't support any of these (yet?).
		 */
		return (DDI_FAILURE);

	default:
		/*
		 * Everything else goes to the parent nexus.
		 */
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

void
sda_nexus_register(sda_host_t *h)
{
	int	i;
	int	inst;
	char	name[16];

	mutex_enter(&sda_nexus_lock);
	list_insert_tail(&sda_nexus_list, h);
	mutex_exit(&sda_nexus_lock);

	/*
	 * Now create minor nodes.  Note that failures to create these nodes
	 * are mostly harmless, so we don't do much besides warn about it.
	 * (It means cfgadm will be useless, but most folks aren't likely
	 * to use cfgadm anyway.)
	 */

	inst = ddi_get_instance(h->h_dip);

	/*
	 * Create the devctl minor node.
	 */
	if (ddi_create_minor_node(h->h_dip, "devctl", S_IFCHR,
	    MKMINOR_DC(inst), DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		sda_slot_err(NULL, "Unable to create devctl node");
	}

	for (i = 0; i < h->h_nslot; i++) {

		sda_slot_t	*slot;

		slot = &h->h_slots[i];
		/*
		 * Create the attachment point minor nodes.
		 */
		(void) snprintf(name, sizeof (name), "%d", i);
		if (ddi_create_minor_node(h->h_dip, name, S_IFCHR,
		    MKMINOR_AP(inst, i), DDI_NT_SDCARD_ATTACHMENT_POINT,
		    0) != DDI_SUCCESS) {
			sda_slot_err(slot,
			    "Unable to create attachment point node");
		}
	}
}

void
sda_nexus_unregister(sda_host_t *h)
{
	/*
	 * Remove all minor nodes.
	 */
	ddi_remove_minor_node(h->h_dip, NULL);

	mutex_enter(&sda_nexus_lock);
	list_remove(&sda_nexus_list, h);
	mutex_exit(&sda_nexus_lock);
}

sda_host_t *
sda_nexus_lookup_dev(dev_t dev)
{
	major_t		maj;
	int		inst;
	sda_host_t	*h;

	ASSERT(mutex_owned(&sda_nexus_lock));

	maj = getmajor(dev);
	inst = DEV_INST(dev);

	h = list_head(&sda_nexus_list);
	while (h != NULL) {
		if ((ddi_driver_major(h->h_dip) == maj) &&
		    (ddi_get_instance(h->h_dip) == inst)) {
			break;
		}
		h = list_next(&sda_nexus_list, h);
	}
	return (h);
}

void
sda_nexus_create(sda_slot_t *slot)
{
	dev_info_t	*pdip, *cdip;
	int		rv;

	pdip = slot->s_hostp->h_dip;

	/*
	 * SDIO: This whole function will need to be recrafted to
	 * support non-memory children.  For SDIO, there could be
	 * multiple functions, which get inserted or removed together.
	 */

	if (ndi_devi_alloc(pdip, "sdcard", DEVI_SID_NODEID, &cdip) !=
	    NDI_SUCCESS) {
		sda_slot_err(slot, "Failed allocating devinfo node");
		return;
	}

	ddi_set_parent_data(cdip, slot);
	slot->s_dip = NULL;

	/*
	 * Make sure the child node gets suspend/resume events.
	 */
	rv = ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "pm-capable", 1);
	if (rv != 0) {
		sda_slot_err(slot, "Failed creating pm-capable property");
		(void) ndi_devi_free(cdip);
		return;
	}

	sda_slot_enter(slot);
	slot->s_ready = B_TRUE;
	sda_slot_exit(slot);

	if (ndi_devi_online(cdip, NDI_ONLINE_ATTACH) != NDI_SUCCESS) {
		sda_slot_err(slot, "Failed bringing node online");
		(void) ndi_devi_free(cdip);
	} else {
		slot->s_dip = cdip;
	}
}

void
sda_nexus_reinsert(sda_slot_t *slot)
{
	dev_info_t	*cdip, *pdip;
	int		circ;

	pdip = slot->s_hostp->h_dip;

	ndi_devi_enter(pdip, &circ);
	sda_slot_enter(slot);
	if ((cdip = slot->s_dip) !=  NULL) {
		mutex_enter(&DEVI(cdip)->devi_lock);
		DEVI_SET_DEVICE_REINSERTED(cdip);
		mutex_exit(&DEVI(cdip)->devi_lock);
	}
	sda_slot_exit(slot);
	slot->s_warn = B_FALSE;
	slot->s_ready = B_TRUE;
	ndi_devi_exit(pdip, circ);
}

void
sda_nexus_insert(sda_slot_t *slot)
{
	char		uuid[40];
	boolean_t	match;

	if (slot->s_flags & SLOTF_MEMORY) {
		(void) snprintf(uuid, sizeof (uuid), "%c%08X%08X%08X%08X",
		    slot->s_flags & SLOTF_MMC ? 'M' : 'S',
		    slot->s_rcid[0], slot->s_rcid[1],
		    slot->s_rcid[2], slot->s_rcid[3]);
	} else {
		/*
		 * SDIO: For SDIO, we can write the card's MANFID
		 * tuple in CIS to the UUID.  Until we support SDIO,
		 * we just suppress creating devinfo nodes.
		 */
		sda_slot_err(slot, "Non-memory target not supported");
		uuid[0] = 0;
	}

	match = ((uuid[0] != 0) && (strcmp(slot->s_uuid, uuid) == 0));

	if (slot->s_dip != NULL) {
		if (!match) {
			sda_slot_err(slot, "Card removed while still in use.");
			sda_slot_err(slot, "Please reinsert previous card.");

			sda_nexus_remove(slot);
		} else {
			sda_nexus_reinsert(slot);
		}
	} else {
		/*
		 * Remember the UUID.
		 */
		(void) strlcpy(slot->s_uuid, uuid, sizeof (slot->s_uuid));
		/*
		 * Create the children.
		 */
		if (uuid[0] != 0)
			sda_nexus_create(slot);
	}
}

void
sda_nexus_remove(sda_slot_t *slot)
{
	sda_host_t	*h  = slot->s_hostp;
	dev_info_t	*pdip = h->h_dip;
	dev_info_t	*cdip;
	int		circ;
	boolean_t	reap = B_FALSE;

	ndi_devi_enter(pdip, &circ);
	if ((cdip = slot->s_dip) != NULL) {
		reap = B_TRUE;

		mutex_enter(&(DEVI(cdip))->devi_lock);
		DEVI_SET_DEVICE_REMOVED(cdip);
		mutex_exit(&(DEVI(cdip))->devi_lock);
	}
	ndi_devi_exit(pdip, circ);

	if (reap) {
		mutex_enter(&slot->s_evlock);
		slot->s_reap = B_TRUE;
		mutex_exit(&slot->s_evlock);
		sda_slot_wakeup(slot);
	}
}

void
sda_nexus_reap(void *arg)
{
	sda_slot_t	*slot = arg;
	dev_info_t	*pdip = slot->s_hostp->h_dip;
	dev_info_t	*cdip;
	int		circ;
	char		*devnm;
	int		rv;

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	ndi_devi_enter(pdip, &circ);
	sda_slot_enter(slot);

	cdip = slot->s_dip;

	if ((cdip != NULL) && DEVI_IS_DEVICE_REMOVED(cdip)) {

		sda_slot_exit(slot);

		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			rv = ddi_remove_child(cdip, 0);
		} else {
			(void) ddi_deviname(cdip, devnm);
			(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);
			rv = ndi_devi_unconfig_one(pdip, devnm + 1, NULL,
			    NDI_DEVI_REMOVE | NDI_UNCONFIG);
		}

		if (rv != NDI_SUCCESS) {

			mutex_enter(&slot->s_evlock);
			slot->s_reap = B_TRUE;
			mutex_exit(&slot->s_evlock);
			ndi_devi_exit(pdip, circ);
			return;
		}
		sda_slot_enter(slot);

		if (slot->s_dip == cdip) {
			slot->s_dip = NULL;
		}
	}
	sda_slot_exit(slot);

	mutex_enter(&slot->s_evlock);
	/* woohoo, done reaping nodes */
	slot->s_reap = B_FALSE;
	mutex_exit(&slot->s_evlock);

	ndi_devi_exit(pdip, circ);
	kmem_free(devnm, MAXNAMELEN + 1);
}

/*ARGSUSED3*/
int
sda_nexus_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int		rv = 0;
	sda_host_t	*h;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&sda_nexus_lock);
	if ((h = sda_nexus_lookup_dev(*devp)) == NULL) {
		mutex_exit(&sda_nexus_lock);
		return (ENXIO);
	}

	if (flags & FEXCL) {
		if ((h->h_flags & (HOST_SOPEN|HOST_XOPEN)) != 0) {
			rv = EBUSY;
		} else {
			h->h_flags |= HOST_XOPEN;
		}
	} else {
		if ((h->h_flags & HOST_XOPEN) != 0) {
			rv = EBUSY;
		} else {
			h->h_flags |= HOST_SOPEN;
		}
	}
	mutex_exit(&sda_nexus_lock);
	return (rv);
}

/*ARGSUSED1*/
int
sda_nexus_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	sda_host_t	*h;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&sda_nexus_lock);
	if ((h = sda_nexus_lookup_dev(dev)) == NULL) {
		mutex_exit(&sda_nexus_lock);
		return (ENXIO);
	}
	h->h_flags &= ~(HOST_XOPEN | HOST_SOPEN);
	mutex_exit(&sda_nexus_lock);
	return (0);
}

void
sda_nexus_ap_getstate(sda_slot_t *slot, devctl_ap_state_t *ap_state)
{
	dev_info_t	*cdip;
	dev_info_t	*pdip = slot->s_hostp->h_dip;
	int		circ;

	ndi_devi_enter(pdip, &circ);
	sda_slot_enter(slot);

	/*
	 * Default state.
	 */
	ap_state->ap_rstate = AP_RSTATE_EMPTY;
	ap_state->ap_condition = AP_COND_OK;
	ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;

	if (slot->s_inserted) {
		ap_state->ap_rstate = AP_RSTATE_CONNECTED;
	}

	if ((cdip = slot->s_dip) != NULL) {
		mutex_enter(&DEVI(cdip)->devi_lock);
		if (DEVI_IS_DEVICE_REMOVED(cdip)) {
			ap_state->ap_condition = AP_COND_UNUSABLE;
		}
		if (DEVI_IS_DEVICE_OFFLINE(cdip) ||
		    DEVI_IS_DEVICE_DOWN(cdip)) {
			ap_state->ap_ostate = AP_OSTATE_UNCONFIGURED;
		} else {
			ap_state->ap_ostate = AP_OSTATE_CONFIGURED;
		}
		mutex_exit(&DEVI(cdip)->devi_lock);
	}

	if (slot->s_failed) {
		ap_state->ap_condition = AP_COND_FAILED;
	}

	ap_state->ap_last_change = slot->s_stamp;
	ap_state->ap_in_transition = slot->s_intransit;

	sda_slot_exit(slot);
	ndi_devi_exit(pdip, circ);
}

int
sda_nexus_ap_disconnect(sda_slot_t *slot)
{
	dev_info_t	*cdip;
	dev_info_t	*pdip = slot->s_hostp->h_dip;
	int		rv = 0;
	int		circ;

	/* if a child node exists, try to delete it */
	ndi_devi_enter(pdip, &circ);

	sda_slot_enter(slot);
	if ((cdip = slot->s_dip) != NULL) {
		if (ndi_devi_offline(cdip, NDI_DEVI_REMOVE) != NDI_SUCCESS) {
			/* couldn't disconnect, why not? */
			rv = EBUSY;
			goto done;
		}
	}
	slot->s_stamp = ddi_get_time();
	slot->s_dip = NULL;
done:
	sda_slot_exit(slot);
	ndi_devi_exit(pdip, circ);
	return (rv);
}

int
sda_nexus_ap_unconfigure(sda_slot_t *slot)
{
	dev_info_t	*cdip;
	dev_info_t	*pdip = slot->s_hostp->h_dip;
	int		rv = 0;
	int		circ;

	/* attempt to unconfigure the node */
	ndi_devi_enter(pdip, &circ);
	sda_slot_enter(slot);
	if ((cdip = slot->s_dip) != NULL) {
		if (ndi_devi_offline(cdip, NDI_UNCONFIG) != NDI_SUCCESS) {
			/* failed to unconfigure the node (EBUSY?) */
			rv = EIO;
			goto done;
		}
	}
	slot->s_stamp = ddi_get_time();
	slot->s_dip = NULL;
done:
	sda_slot_exit(slot);
	ndi_devi_exit(pdip, circ);
	return (rv);
}

int
sda_nexus_ap_configure(sda_slot_t *slot)
{
	dev_info_t	*cdip;

	sda_slot_enter(slot);
	if (slot->s_inserted == B_FALSE) {
		/* device not present */
		sda_slot_exit(slot);
		return (ENXIO);
	}

	/* attempt to configure the node */
	if ((cdip = slot->s_dip) == NULL) {
		sda_slot_exit(slot);
		/* node not there! */
		return (ENXIO);
	}
	sda_slot_exit(slot);

	slot->s_intransit = 1;

	if (ndi_devi_online(cdip, NDI_CONFIG) != NDI_SUCCESS) {
		/* failed to configure the node */
		slot->s_intransit = 0;
		return (EIO);
	}
	slot->s_intransit = 0;
	slot->s_stamp = ddi_get_time();
	return (0);
}

int
sda_nexus_ap_ioctl(sda_host_t *h, int snum, int cmd, intptr_t arg)
{
	struct devctl_iocdata	*dcp = NULL;
	devctl_ap_state_t	ap_state;
	sda_slot_t		*slot;
	int			rv = 0;

	/*
	 * In theory we could try to support this operation on the
	 * DEVCTL minor, but then we would need a slot member in the
	 * user nvlist.  For now its easiest to assume a 1:1 relation
	 * between the AP minor node, and the slot number.
	 */
	if (snum >= h->h_nslot) {
		return (ENXIO);
	}
	slot = &h->h_slots[snum];

	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {
	case DEVCTL_AP_DISCONNECT:
		rv = sda_nexus_ap_disconnect(slot);
		break;

	case DEVCTL_AP_UNCONFIGURE:
		rv = sda_nexus_ap_unconfigure(slot);
		break;

	case DEVCTL_AP_CONFIGURE:
		rv = sda_nexus_ap_configure(slot);
		break;

	case DEVCTL_AP_GETSTATE:
		sda_nexus_ap_getstate(slot, &ap_state);
		if (ndi_dc_return_ap_state(&ap_state, dcp) != NDI_SUCCESS) {
			rv = EFAULT;
		}
		break;
	}

	ndi_dc_freehdl(dcp);

	return (rv);
}

int
sda_nexus_ap_control(sda_host_t *h, int snum, intptr_t arg, int mode)
{
	struct sda_ap_control	apc;
	struct sda_ap_control32	apc32;
	sda_slot_t		*slot;
	int			rv = 0;

	if (snum >= h->h_nslot) {
		return (ENXIO);
	}
	slot = &h->h_slots[snum];

	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &apc32, sizeof (apc32), mode) !=
		    0) {
			return (EFAULT);
		}
		apc.cmd = apc32.cmd;
		apc.size = apc32.size;
		apc.data = (caddr_t *)(intptr_t)apc32.data;
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &apc, sizeof (apc), mode) != 0) {
			return (EFAULT);
		}
		break;
	}

	switch (apc.cmd) {
	case SDA_CFGA_GET_CARD_INFO: {
		sda_card_info_t	ci;

		if (apc.size < sizeof (sda_card_info_t)) {
			apc.size = sizeof (sda_card_info_t);
			break;
		}
		sda_slot_enter(slot);
		if (!slot->s_inserted) {
			ci.ci_type = SDA_CT_UNKNOWN;
		} else if (slot->s_flags & SLOTF_MMC) {
			ci.ci_type = SDA_CT_MMC;
		} else if (slot->s_flags & SLOTF_SDIO) {
			if (slot->s_flags & SLOTF_MEMORY) {
				ci.ci_type = SDA_CT_SDCOMBO;
			} else {
				ci.ci_type = SDA_CT_SDIO;
			}
		} else if (slot->s_flags & SLOTF_SDMEM) {
			if (slot->s_flags & SLOTF_SDHC) {
				ci.ci_type = SDA_CT_SDHC;
			} else {
				ci.ci_type = SDA_CT_SDMEM;
			}
		} else {
			ci.ci_type = SDA_CT_UNKNOWN;
		}

		if (slot->s_flags & SLOTF_MEMORY) {
			ci.ci_mfg = slot->s_mfg;
			(void) strlcpy(ci.ci_oem,
			    slot->s_oem, sizeof (ci.ci_oem));
			(void) strlcpy(ci.ci_pid,
			    slot->s_prod, sizeof (ci.ci_pid));
			ci.ci_serial = slot->s_serial;
			ci.ci_month = slot->s_month;
			ci.ci_year = (slot->s_year - 1900) & 0xff;
			ci.ci_major = slot->s_majver;
			ci.ci_minor = slot->s_minver;
		}

		sda_slot_exit(slot);

		if (ddi_copyout(&ci, apc.data, sizeof (ci), mode) != 0) {
			return (EFAULT);
		}

		break;
	}

	case SDA_CFGA_GET_DEVICE_PATH:
	{
		char		path[MAXPATHLEN];
		dev_info_t	*cdip;
		int		slen;

		sda_slot_enter(slot);
		if ((cdip = slot->s_dip) == NULL) {
			sda_slot_exit(slot);
			return (ENOENT);
		}
		(void) strcpy(path, "/devices");
		(void) ddi_pathname(cdip, path + strlen(path));
		slen = strlen(path) + 1;
		sda_slot_exit(slot);
		if (apc.size < slen) {
			apc.size = slen;
			rv = ENOSPC;
			break;
		}
		apc.size = slen;
		if (ddi_copyout(path, apc.data, slen, mode) != 0) {
			return (EFAULT);
		}
		break;
	}

	case SDA_CFGA_RESET_SLOT:
	{
		sda_slot_enter(slot);
		slot->s_failed = B_FALSE;
		sda_slot_exit(slot);
		sda_slot_reset(slot);
		sda_slot_detect(slot);
		break;
	}

	default:
		return (EINVAL);
	}

	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		apc32.cmd = apc.cmd;
		apc32.size = (size32_t)apc.size;
		apc32.data = (caddr32_t)(intptr_t)apc.data;
		if (ddi_copyout(&apc32, (void *)arg, sizeof (apc32), mode) !=
		    0) {
			return (EFAULT);
		}
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyout(&apc, (void *)arg, sizeof (apc), mode) != 0) {
			return (EFAULT);
		}
		break;
	}
	return (rv);
}

/*ARGSUSED4*/
int
sda_nexus_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvp)
{
	sda_host_t	*h;

	mutex_enter(&sda_nexus_lock);
	h = sda_nexus_lookup_dev(dev);
	mutex_exit(&sda_nexus_lock);

	if (h == NULL)
		return (ENXIO);

	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(h->h_dip, cmd, arg, mode, 0));

	case DEVCTL_AP_DISCONNECT:
	case DEVCTL_AP_CONFIGURE:
	case DEVCTL_AP_UNCONFIGURE:
	case DEVCTL_AP_GETSTATE:
		return (sda_nexus_ap_ioctl(h, DEV_SLOT(dev), cmd, arg));

	case DEVCTL_AP_CONTROL:
		return (sda_nexus_ap_control(h, DEV_SLOT(dev), arg, mode));

	default:
		return (ENOTSUP);
	}
}

/*ARGSUSED*/
int
sda_nexus_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	sda_host_t	*h;
	int		rv;

	rv = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		mutex_enter(&sda_nexus_lock);
		h = sda_nexus_lookup_dev((dev_t)arg);
		if (h != NULL) {
			*resp = h->h_dip;
			rv = DDI_SUCCESS;
		}
		mutex_exit(&sda_nexus_lock);
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)(intptr_t)DEV_INST((dev_t)arg);
		rv = DDI_SUCCESS;
		break;
	}
	return (rv);
}
