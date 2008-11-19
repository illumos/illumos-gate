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

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/strsun.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <sys/varargs.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/taskq.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mac.h>
#include <sys/mdeg.h>
#include <sys/ldc.h>
#include <sys/vsw_fdb.h>
#include <sys/vsw.h>
#include <sys/vio_mailbox.h>
#include <sys/vnet_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/vio_util.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include <sys/callb.h>


#define	VSW_DDS_NEXT_REQID(vsharep)	(++vsharep->vs_req_id)

extern boolean_t vsw_hio_enabled;		/* HybridIO enabled? */
extern int vsw_hio_max_cleanup_retries;
extern int vsw_hio_cleanup_delay;

/* Functions imported from other files */
extern int vsw_send_msg(vsw_ldc_t *, void *, int, boolean_t);
extern int vsw_set_hw(vsw_t *, vsw_port_t *, int);
extern int vsw_unset_hw(vsw_t *, vsw_port_t *, int);
extern void vsw_hio_port_reset(vsw_port_t *portp, boolean_t immediate);

/* Functions exported to other files */
void vsw_hio_init(vsw_t *vswp);
void vsw_hio_cleanup(vsw_t *vswp);
void vsw_hio_start(vsw_t *vswp, vsw_ldc_t *ldcp);
void vsw_hio_stop(vsw_t *vswp, vsw_ldc_t *ldcp);
void vsw_process_dds_msg(vsw_t *vswp, vsw_ldc_t *ldcp, void *msg);
void vsw_hio_start_ports(vsw_t *vswp);
void vsw_hio_stop_port(vsw_port_t *portp);

/* Support functions */
static void vsw_hio_free_all_shares(vsw_t *vswp, boolean_t reboot);
static vsw_share_t *vsw_hio_alloc_share(vsw_t *vswp, vsw_ldc_t *ldcp);
static void vsw_hio_free_share(vsw_share_t *vsharep);
static vsw_share_t *vsw_hio_find_free_share(vsw_t *vswp);
static vsw_share_t *vsw_hio_find_vshare_ldcid(vsw_t *vswp, uint64_t ldc_id);
static vsw_share_t *vsw_hio_find_vshare_port(vsw_t *vswp, vsw_port_t *portp);
static int vsw_send_dds_msg(vsw_ldc_t *ldcp, uint8_t dds_subclass,
    uint64_t cookie, uint64_t macaddr, uint32_t req_id);
static int vsw_send_dds_resp_msg(vsw_ldc_t *ldcp, vio_dds_msg_t *dmsg, int ack);
static int vsw_hio_send_delshare_msg(vsw_share_t *vsharep);
static int vsw_hio_bind_macaddr(vsw_share_t *vsharep);
static void vsw_hio_unbind_macaddr(vsw_share_t *vsharep);
static boolean_t vsw_hio_reboot_callb(void *arg, int code);
static boolean_t vsw_hio_panic_callb(void *arg, int code);

static kstat_t *vsw_hio_setup_kstats(char *ks_mod, char *ks_name, vsw_t *vswp);
static void vsw_hio_destroy_kstats(vsw_t *vswp);
static int vsw_hio_kstats_update(kstat_t *ksp, int rw);

/*
 * vsw_hio_init -- Initialize the HybridIO related info.
 *	- Query SHARES and RINGS capability. Both capabilities
 *	  need to be supported by the physical-device.
 */
void
vsw_hio_init(vsw_t *vswp)
{
	vsw_hio_t	*hiop = &vswp->vhio;
	int		i;
	int		rv;

	D1(vswp, "%s:enter\n", __func__);
	mutex_enter(&vswp->hw_lock);
	if (vsw_hio_enabled == B_FALSE) {
		mutex_exit(&vswp->hw_lock);
		return;
	}

	vswp->hio_capable = B_FALSE;
	rv = mac_capab_get(vswp->mh, MAC_CAPAB_SHARES, &hiop->vh_scapab);
	if (rv == B_FALSE) {
		D2(vswp, "%s: %s is not HybridIO capable\n", __func__,
		    vswp->physname);
		mutex_exit(&vswp->hw_lock);
		return;
	}
	rv = mac_capab_get(vswp->mh, MAC_CAPAB_RINGS, &hiop->vh_rcapab);
	if (rv == B_FALSE) {
		DWARN(vswp, "%s: %s has no RINGS capability\n", __func__,
		    vswp->physname);
		mutex_exit(&vswp->hw_lock);
		return;
	}
	hiop->vh_num_shares = hiop->vh_scapab.ms_snum;
	hiop->vh_shares = kmem_zalloc((sizeof (vsw_share_t) *
	    hiop->vh_num_shares), KM_SLEEP);
	for (i = 0; i < hiop->vh_num_shares; i++) {
		hiop->vh_shares[i].vs_state = VSW_SHARE_FREE;
		hiop->vh_shares[i].vs_index = i;
		hiop->vh_shares[i].vs_vswp = vswp;
	}
	vswp->hio_capable = B_TRUE;

	/*
	 * Register to get reboot and panic events so that
	 * we can cleanup HybridIO resources gracefully.
	 */
	vswp->hio_reboot_cb_id = callb_add(vsw_hio_reboot_callb,
	    (void *)vswp, CB_CL_MDBOOT, "vsw_hio");

	vswp->hio_panic_cb_id = callb_add(vsw_hio_panic_callb,
	    (void *)vswp, CB_CL_PANIC, "vsw_hio");

	/* setup kstats for hybrid resources */
	hiop->vh_ksp = vsw_hio_setup_kstats(DRV_NAME, "hio", vswp);
	if (hiop->vh_ksp == NULL) {
		DERR(vswp, "%s: kstats setup failed", __func__);
	}

	D2(vswp, "%s: %s is HybridIO capable num_shares=%d\n", __func__,
	    vswp->physname, hiop->vh_num_shares);
	D1(vswp, "%s:exit\n", __func__);
	mutex_exit(&vswp->hw_lock);
}

/*
 * vsw_hio_alloc_share -- Allocate and setup the share for a guest domain.
 *	- Allocate a free share.
 *	- Bind the Guest's MAC address.
 */
static vsw_share_t *
vsw_hio_alloc_share(vsw_t *vswp, vsw_ldc_t *ldcp)
{
	vsw_hio_t	*hiop = &vswp->vhio;
	mac_capab_share_t *hcapab = &hiop->vh_scapab;
	vsw_share_t	*vsharep;
	vsw_port_t	*portp = ldcp->ldc_port;
	uint64_t	ldc_id = ldcp->ldc_id;
	uint32_t	rmin, rmax;
	uint64_t	rmap;
	int		rv;

	D1(vswp, "%s:enter\n", __func__);
	vsharep = vsw_hio_find_free_share(vswp);
	if (vsharep == NULL) {
		/* No free shares available */
		return (NULL);
	}
	/*
	 * Allocate a Share - it will come with rings/groups
	 * already assigned to it.
	 */
	rv = hcapab->ms_salloc(hcapab->ms_handle, ldc_id,
	    &vsharep->vs_cookie, &vsharep->vs_shdl);
	if (rv != 0) {
		D2(vswp, "Alloc a share failed for ldc=0x%lx rv=%d",
		    ldc_id, rv);
		return (NULL);
	}

	/*
	 * Query the RX group number to bind the port's
	 * MAC address to it.
	 */
	hcapab->ms_squery(vsharep->vs_shdl, MAC_RING_TYPE_RX,
	    &rmin, &rmax, &rmap, &vsharep->vs_gnum);

	/* Cache some useful info */
	vsharep->vs_ldcid = ldcp->ldc_id;
	vsharep->vs_macaddr = vnet_macaddr_strtoul(
	    portp->p_macaddr.ether_addr_octet);
	vsharep->vs_portp = ldcp->ldc_port;

	/* Bind the Guest's MAC address */
	rv = vsw_hio_bind_macaddr(vsharep);
	if (rv != 0) {
		/* something went wrong, cleanup */
		hcapab->ms_sfree(vsharep->vs_shdl);
		return (NULL);
	}

	vsharep->vs_state |= VSW_SHARE_ASSIGNED;

	D1(vswp, "%s:exit\n", __func__);
	return (vsharep);
}

/*
 * vsw_hio_bind_macaddr -- Remove the port's MAC address from the
 *	physdev and bind it to the Share's RX group.
 */
static int
vsw_hio_bind_macaddr(vsw_share_t *vsharep)
{
	vsw_t		*vswp = vsharep->vs_vswp;
	vsw_port_t	*portp = vsharep->vs_portp;
	mac_capab_rings_t *rcapab = &vswp->vhio.vh_rcapab;
	mac_group_info_t *ginfop = &vsharep->vs_rxginfo;
	int		rv;

	/* Get the RX groupinfo */
	rcapab->mr_gget(rcapab->mr_handle, MAC_RING_TYPE_RX,
	    vsharep->vs_gnum, &vsharep->vs_rxginfo, NULL);

	/* Unset the MAC address first */
	if (portp->addr_set != VSW_ADDR_UNSET) {
		(void) vsw_unset_hw(vswp, portp, VSW_VNETPORT);
	}

	/* Bind the MAC address to the RX group */
	rv = ginfop->mrg_addmac(ginfop->mrg_driver,
	    (uint8_t *)&portp->p_macaddr.ether_addr_octet);
	if (rv != 0) {
		/* Restore the address back as it was */
		(void) vsw_set_hw(vswp, portp, VSW_VNETPORT);
		return (rv);
	}
	return (0);
}

/*
 * vsw_hio_unbind_macaddr -- Unbind the port's MAC address and restore
 *	it back as it was before.
 */
static void
vsw_hio_unbind_macaddr(vsw_share_t *vsharep)
{
	vsw_t		*vswp = vsharep->vs_vswp;
	vsw_port_t	*portp = vsharep->vs_portp;
	mac_group_info_t *ginfop = &vsharep->vs_rxginfo;

	if (portp == NULL) {
		return;
	}
	/* Unbind the MAC address from the RX group */
	(void) ginfop->mrg_remmac(ginfop->mrg_driver,
	    (uint8_t *)&portp->p_macaddr.ether_addr_octet);

	/* Program the MAC address back */
	(void) vsw_set_hw(vswp, portp, VSW_VNETPORT);
}

/*
 * vsw_hio_find_free_share -- Find a free Share.
 */
static vsw_share_t *
vsw_hio_find_free_share(vsw_t *vswp)
{
	vsw_hio_t *hiop = &vswp->vhio;
	vsw_share_t *vsharep;
	int i;

	D1(vswp, "%s:enter\n", __func__);
	for (i = 0; i < hiop->vh_num_shares; i++) {
		vsharep = &hiop->vh_shares[i];
		if (vsharep->vs_state == VSW_SHARE_FREE) {
			D1(vswp, "%s:Returning free share(%d)\n",
			    __func__, vsharep->vs_index);
			return (vsharep);
		}
	}
	D1(vswp, "%s:no free share\n", __func__);
	return (NULL);
}

/*
 * vsw_hio_find_vshare_ldcid -- Given ldc_id, find the corresponding
 *	share structure.
 */
static vsw_share_t *
vsw_hio_find_vshare_ldcid(vsw_t *vswp, uint64_t ldc_id)
{
	vsw_hio_t *hiop = &vswp->vhio;
	vsw_share_t *vsharep;
	int i;

	D1(vswp, "%s:enter, ldc=0x%lx", __func__, ldc_id);
	for (i = 0; i < hiop->vh_num_shares; i++) {
		vsharep = &hiop->vh_shares[i];
		if (vsharep->vs_state == VSW_SHARE_FREE) {
			continue;
		}
		if (vsharep->vs_ldcid == ldc_id) {
			D1(vswp, "%s:returning share(%d)",
			    __func__, vsharep->vs_index);
			return (vsharep);
		}
	}
	D1(vswp, "%s:returning NULL", __func__);
	return (NULL);
}

/*
 * vsw_hio_find_vshare_port -- Given portp, find the corresponding
 *	share structure.
 */
static vsw_share_t *
vsw_hio_find_vshare_port(vsw_t *vswp, vsw_port_t *portp)
{
	vsw_hio_t *hiop = &vswp->vhio;
	vsw_share_t *vsharep;
	int i;

	D1(vswp, "%s:enter, portp=0x%p", __func__, portp);
	for (i = 0; i < hiop->vh_num_shares; i++) {
		vsharep = &hiop->vh_shares[i];
		if (vsharep->vs_state == VSW_SHARE_FREE) {
			continue;
		}
		if (vsharep->vs_portp == portp) {
			D1(vswp, "%s:returning share(%d)",
			    __func__, vsharep->vs_index);
			return (vsharep);
		}
	}
	D1(vswp, "%s:returning NULL", __func__);
	return (NULL);
}

/*
 * vsw_hio_free_share -- Unbind the MAC address and free share.
 */
static void
vsw_hio_free_share(vsw_share_t *vsharep)
{
	vsw_t		*vswp = vsharep->vs_vswp;
	vsw_hio_t	*hiop = &vswp->vhio;
	mac_capab_share_t *hcapab = &hiop->vh_scapab;

	D1(vswp, "%s:enter\n", __func__);

	/* First unbind the MAC address and restore it back */
	vsw_hio_unbind_macaddr(vsharep);

	/* free share */
	hcapab->ms_sfree(vsharep->vs_shdl);
	vsharep->vs_state = VSW_SHARE_FREE;
	vsharep->vs_macaddr = 0;

	/* DERR only for printing by default */
	DERR(vswp, "Share freed for ldc_id=0x%lx Cookie=0x%lX",
	    vsharep->vs_ldcid, vsharep->vs_cookie);
	D1(vswp, "%s:exit\n", __func__);
}


/*
 * vsw_hio_cleanup -- Cleanup the HybridIO. It unregisters the callbs
 *	and frees all shares.
 */
void
vsw_hio_cleanup(vsw_t *vswp)
{
	D1(vswp, "%s:enter\n", __func__);

	/* Unregister reboot and panic callbs. */
	if (vswp->hio_reboot_cb_id) {
		(void) callb_delete(vswp->hio_reboot_cb_id);
		vswp->hio_reboot_cb_id = 0;
	}
	if (vswp->hio_panic_cb_id) {
		(void) callb_delete(vswp->hio_panic_cb_id);
		vswp->hio_panic_cb_id = 0;
	}
	vsw_hio_free_all_shares(vswp, B_FALSE);
	vsw_hio_destroy_kstats(vswp);
	D1(vswp, "%s:exit\n", __func__);
}

/*
 * vsw_hio_free_all_shares -- A routine to free all shares gracefully.
 *	The following are the steps followed to accomplish this:
 *
 *	- First clear 'hio_capable' to avoid further share allocations.
 *	- If a share is in accepted(ACKD) state, that means the guest
 *	  has HybridIO setup etc. If so, send a DEL_SHARE message and
 *	  give some time(delay) for the guest to ACK.
 *	- If the Share is another state, give some time to transition to
 *	  ACKD state, then try the above.
 *	- After max retries, reset the ports to brute force the shares
 *	  to be freed. Give a little delay for the LDC reset code to
 *	  free the Share.
 */
static void
vsw_hio_free_all_shares(vsw_t *vswp, boolean_t reboot)
{
	vsw_hio_t	*hiop = &vswp->vhio;
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_share_t	*vsharep;
	int		free_shares = 0;
	int		max_retries = vsw_hio_max_cleanup_retries;
	int		i;

	D1(vswp, "%s:enter\n", __func__);

	/*
	 * Acquire plist->lockrw to make the locking a bit easier
	 * and keep the ports in a stable state while we are cleaningup
	 * HybridIO.
	 */
	READ_ENTER(&plist->lockrw);
	mutex_enter(&vswp->hw_lock);
	/*
	 * first clear the hio_capable flag so that no more
	 * HybridIO operations are initiated.
	 */
	vswp->hio_capable = B_FALSE;

	do {
		free_shares = 0;
		for (i = 0; i < hiop->vh_num_shares; i++) {
			vsharep = &hiop->vh_shares[i];
			if (vsharep->vs_state == VSW_SHARE_FREE) {
				free_shares++;
				continue;
			}
			/*
			 * If the share is in DDS_ACKD state, then
			 * send DEL_SHARE message so that guest can
			 * release its Hybrid resource.
			 */
			if (vsharep->vs_state & VSW_SHARE_DDS_ACKD) {
				int rv;

				/* send DDS_DEL_SHARE */
				D1(vswp, "%s:sending DEL_SHARE msg for "
				    "share(%d)", __func__, vsharep->vs_index);
				rv = vsw_hio_send_delshare_msg(vsharep);
				if (rv != 0) {
					/*
					 * No alternative, reset the port
					 * to force the release of Hybrid
					 * resources.
					 */
					vsw_hio_port_reset(vsharep->vs_portp,
					    B_FALSE);
				}
			}
			if (max_retries == 1) {
				/*
				 * Last retry,  reset the port.
				 * If it is reboot case, issue an immediate
				 * reset.
				 */
				DWARN(vswp, "%s:All retries failed, "
				    " cause a reset to trigger cleanup for "
				    "share(%d)", __func__, vsharep->vs_index);
				vsw_hio_port_reset(vsharep->vs_portp, reboot);
			}
		}
		if (free_shares == hiop->vh_num_shares) {
			/* Clean up is done */
			break;
		}
		/*
		 * Release the lock so that reply for DEL_SHARE
		 * messages come and get processed, that is, shares
		 * get freed.
		 * This delay is also needed for the port reset to
		 * release the Hybrid resource.
		 */
		mutex_exit(&vswp->hw_lock);
		drv_usecwait(vsw_hio_cleanup_delay);
		mutex_enter(&vswp->hw_lock);
		max_retries--;
	} while ((free_shares < hiop->vh_num_shares) && (max_retries > 0));

	/* By now, all shares should be freed */
	if (free_shares != hiop->vh_num_shares) {
		if (reboot == B_FALSE) {
			cmn_err(CE_NOTE, "vsw%d: All physical resources "
			    "could not be freed", vswp->instance);
		}
	}

	kmem_free(hiop->vh_shares, sizeof (vsw_share_t) * hiop->vh_num_shares);
	hiop->vh_shares = NULL;
	hiop->vh_num_shares = 0;
	mutex_exit(&vswp->hw_lock);
	RW_EXIT(&plist->lockrw);
	D1(vswp, "%s:exit\n", __func__);
}

/*
 * vsw_hio_start_ports -- Start HybridIO for ports that have
 *	already established connection before HybridIO is intialized.
 */
void
vsw_hio_start_ports(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*portp;
	vsw_share_t	*vsharep;
	boolean_t	reset;

	if (vswp->hio_capable == B_FALSE) {
		return;
	}
	READ_ENTER(&plist->lockrw);
	for (portp = plist->head; portp != NULL; portp = portp->p_next) {
		if ((portp->p_hio_enabled == B_FALSE) ||
		    (portp->p_hio_capable == B_FALSE)) {
			continue;
		}

		reset = B_FALSE;
		mutex_enter(&vswp->hw_lock);
		vsharep = vsw_hio_find_vshare_port(vswp, portp);
		if (vsharep == NULL) {
			reset = B_TRUE;
		}
		mutex_exit(&vswp->hw_lock);

		if (reset == B_TRUE) {
			/* Cause a rest to trigger HybridIO setup */
			vsw_hio_port_reset(portp, B_FALSE);
		}
	}
	RW_EXIT(&plist->lockrw);
}

/*
 * vsw_hio_start -- Start HybridIO for a guest(given LDC)
 */
void
vsw_hio_start(vsw_t *vswp, vsw_ldc_t *ldcp)
{
	vsw_share_t	*vsharep;
	uint32_t	req_id;
	int		rv;

	D1(vswp, "%s:enter ldc=0x%lx", __func__, ldcp->ldc_id);
	mutex_enter(&vswp->hw_lock);
	if (vswp->hio_capable == B_FALSE) {
		mutex_exit(&vswp->hw_lock);
		D2(vswp, "%s:not HIO capable", __func__);
		return;
	}

	/* Verify if a share was already allocated */
	vsharep = vsw_hio_find_vshare_ldcid(vswp, ldcp->ldc_id);
	if (vsharep != NULL) {
		mutex_exit(&vswp->hw_lock);
		D2(vswp, "%s:Share already allocated to ldc=0x%lx",
		    __func__, ldcp->ldc_id);
		return;
	}
	vsharep = vsw_hio_alloc_share(vswp, ldcp);
	if (vsharep == NULL) {
		mutex_exit(&vswp->hw_lock);
		D2(vswp, "%s: no Share available for ldc=0x%lx",
		    __func__, ldcp->ldc_id);
		return;
	}
	req_id = VSW_DDS_NEXT_REQID(vsharep);
	rv = vsw_send_dds_msg(ldcp, DDS_VNET_ADD_SHARE, vsharep->vs_cookie,
	    vsharep->vs_macaddr, req_id);
	if (rv != 0) {
		/*
		 * Failed to send a DDS message, so cleanup now.
		 */
		vsw_hio_free_share(vsharep);
		mutex_exit(&vswp->hw_lock);
		return;
	}
	vsharep->vs_state &= ~VSW_SHARE_DDS_ACKD;
	vsharep->vs_state |= VSW_SHARE_DDS_SENT;
	mutex_exit(&vswp->hw_lock);

	/* DERR only to print by default */
	DERR(vswp, "Share allocated for ldc_id=0x%lx Cookie=0x%lX",
	    ldcp->ldc_id, vsharep->vs_cookie);

	D1(vswp, "%s:exit ldc=0x%lx", __func__, ldcp->ldc_id);
}

/*
 * vsw_hio_stop -- Stop/clean the HybridIO config for a guest(given ldc).
 */
void
vsw_hio_stop(vsw_t *vswp, vsw_ldc_t *ldcp)
{
	vsw_share_t *vsharep;

	D1(vswp, "%s:enter ldc=0x%lx", __func__, ldcp->ldc_id);

	mutex_enter(&vswp->hw_lock);
	vsharep = vsw_hio_find_vshare_ldcid(vswp, ldcp->ldc_id);
	if (vsharep == NULL) {
		D1(vswp, "%s:no share found for ldc=0x%lx",
		    __func__, ldcp->ldc_id);
		mutex_exit(&vswp->hw_lock);
		return;
	}
	vsw_hio_free_share(vsharep);
	mutex_exit(&vswp->hw_lock);

	D1(vswp, "%s:exit ldc=0x%lx", __func__, ldcp->ldc_id);
}

/*
 * vsw_hio_send_delshare_msg -- Send a DEL_SHARE message to the	guest.
 */
static int
vsw_hio_send_delshare_msg(vsw_share_t *vsharep)
{
	vsw_t *vswp = vsharep->vs_vswp;
	vsw_port_t *portp;
	vsw_ldc_list_t	*ldcl;
	vsw_ldc_t	*ldcp;
	uint32_t	req_id;
	uint64_t	cookie = vsharep->vs_cookie;
	uint64_t	macaddr = vsharep->vs_macaddr;
	int		rv;

	ASSERT(MUTEX_HELD(&vswp->hw_lock));
	mutex_exit(&vswp->hw_lock);

	portp = vsharep->vs_portp;
	if (portp == NULL) {
		mutex_enter(&vswp->hw_lock);
		return (0);
	}

	ldcl = &portp->p_ldclist;
	READ_ENTER(&ldcl->lockrw);
	ldcp = ldcl->head;
	if ((ldcp == NULL) || (ldcp->ldc_id != vsharep->vs_ldcid)) {
		RW_EXIT(&ldcl->lockrw);
		mutex_enter(&vswp->hw_lock);
		return (0);
	}
	req_id = VSW_DDS_NEXT_REQID(vsharep);
	rv = vsw_send_dds_msg(ldcp, DDS_VNET_DEL_SHARE,
	    cookie, macaddr, req_id);

	RW_EXIT(&ldcl->lockrw);
	mutex_enter(&vswp->hw_lock);
	if (rv == 0) {
		vsharep->vs_state &= ~VSW_SHARE_DDS_ACKD;
		vsharep->vs_state |= VSW_SHARE_DDS_SENT;
	}
	return (rv);
}

/*
 * vsw_send_dds_msg -- Send a DDS message.
 */
static int
vsw_send_dds_msg(vsw_ldc_t *ldcp, uint8_t dds_subclass, uint64_t
    cookie, uint64_t macaddr, uint32_t req_id)
{
	vsw_t *vswp = ldcp->ldc_port->p_vswp;
	vio_dds_msg_t	vmsg;
	dds_share_msg_t	*smsg = &vmsg.msg.share_msg;
	int rv;

	D1(vswp, "%s:enter\n", __func__);
	vmsg.tag.vio_msgtype = VIO_TYPE_CTRL;
	vmsg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	vmsg.tag.vio_subtype_env = VIO_DDS_INFO;
	vmsg.tag.vio_sid = ldcp->local_session;
	vmsg.dds_class = DDS_VNET_NIU;
	vmsg.dds_subclass = dds_subclass;
	vmsg.dds_req_id = req_id;
	smsg->macaddr = macaddr;
	smsg->cookie = cookie;
	rv = vsw_send_msg(ldcp, &vmsg, sizeof (vmsg), B_FALSE);
	D1(vswp, "%s:exit rv=%d\n", __func__, rv);
	return (rv);
}

/*
 * vsw_process_dds_msg -- Process a DDS message received from a guest.
 */
void
vsw_process_dds_msg(vsw_t *vswp, vsw_ldc_t *ldcp, void *msg)
{
	vsw_share_t	*vsharep;
	vio_dds_msg_t	*dmsg = msg;

	D1(vswp, "%s:enter ldc=0x%lx\n", __func__, ldcp->ldc_id);
	if (dmsg->dds_class != DDS_VNET_NIU) {
		/* discard */
		return;
	}
	mutex_enter(&vswp->hw_lock);
	/*
	 * We expect to receive DDS messages only from guests that
	 * have HybridIO started.
	 */
	vsharep = vsw_hio_find_vshare_ldcid(vswp, ldcp->ldc_id);
	if (vsharep == NULL) {
		mutex_exit(&vswp->hw_lock);
		return;
	}

	switch (dmsg->dds_subclass) {
	case DDS_VNET_ADD_SHARE:
		/* A response for ADD_SHARE message. */
		D1(vswp, "%s:DDS_VNET_ADD_SHARE\n", __func__);
		if (!(vsharep->vs_state & VSW_SHARE_DDS_SENT)) {
			DWARN(vswp, "%s: invalid ADD_SHARE response  message "
			    " share state=0x%X", __func__, vsharep->vs_state);
			break;
		}

		if (dmsg->dds_req_id != vsharep->vs_req_id) {
			DWARN(vswp, "%s: invalid req_id in ADD_SHARE response"
			    " message req_id=0x%X share's req_id=0x%X",
			    __func__, dmsg->dds_req_id, vsharep->vs_req_id);
			break;
		}

		if (dmsg->tag.vio_subtype == VIO_SUBTYPE_NACK) {
			DWARN(vswp, "%s: NACK received for ADD_SHARE"
			    " message ldcid=0x%lx", __func__, ldcp->ldc_id);
			/* cleanup for NACK */
			vsw_hio_free_share(vsharep);
		} else {
			D2(vswp, "%s: ACK received for ADD_SHARE", __func__);
			vsharep->vs_state &= ~VSW_SHARE_DDS_SENT;
			vsharep->vs_state |= VSW_SHARE_DDS_ACKD;
		}
		break;

	case DDS_VNET_DEL_SHARE:
		/* A response for DEL_SHARE message */
		D1(vswp, "%s:DDS_VNET_DEL_SHARE\n", __func__);
		if (!(vsharep->vs_state & VSW_SHARE_DDS_SENT)) {
			DWARN(vswp, "%s: invalid DEL_SHARE response message "
			    " share state=0x%X", __func__, vsharep->vs_state);
			break;
		}

		if (dmsg->dds_req_id != vsharep->vs_req_id) {
			DWARN(vswp, "%s: invalid req_id in DEL_SHARE response"
			    " message share req_id=0x%X share's req_id=0x%X",
			    __func__, dmsg->dds_req_id, vsharep->vs_req_id);
			break;
		}
		if (dmsg->tag.vio_subtype == VIO_SUBTYPE_NACK) {
			DWARN(vswp, "%s: NACK received for DEL_SHARE",
			    __func__);
		}

		/* There is nothing we can do, free share now */
		vsw_hio_free_share(vsharep);
		break;

	case DDS_VNET_REL_SHARE:
		/* Guest has released Share voluntarily, so free it now */
		D1(vswp, "%s:DDS_VNET_REL_SHARE\n", __func__);
		/* send ACK */
		(void) vsw_send_dds_resp_msg(ldcp, dmsg, B_FALSE);
		vsw_hio_free_share(vsharep);
		break;
	default:
		DERR(vswp, "%s: Invalid DDS message type=0x%X",
		    __func__, dmsg->dds_subclass);
		break;
	}
	mutex_exit(&vswp->hw_lock);
	D1(vswp, "%s:exit ldc=0x%lx\n", __func__, ldcp->ldc_id);
}

/*
 * vsw_send_dds_resp_msg -- Send a DDS response message.
 */
static int
vsw_send_dds_resp_msg(vsw_ldc_t *ldcp, vio_dds_msg_t *dmsg, int ack)
{
	vsw_t	*vswp = ldcp->ldc_port->p_vswp;
	int	rv;

	D1(vswp, "%s:enter\n", __func__);
	if (ack == B_TRUE) {
		dmsg->tag.vio_subtype = VIO_SUBTYPE_ACK;
		dmsg->msg.share_resp_msg.status = DDS_VNET_SUCCESS;
	} else {
		dmsg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		dmsg->msg.share_resp_msg.status = DDS_VNET_FAIL;
	}
	rv = vsw_send_msg(ldcp, dmsg, sizeof (vio_dds_msg_t), B_FALSE);
	D1(vswp, "%s:exit rv=%d\n", __func__, rv);
	return (rv);
}

/*
 * vsw_hio_port_update -- update Hybrid mode change for a port.
 */
void
vsw_hio_port_update(vsw_port_t *portp, boolean_t hio_enabled)
{
	/* Verify if the mode really changed */
	if (portp->p_hio_enabled == hio_enabled) {
		return;
	}

	if (hio_enabled == B_FALSE) {
		/* Hybrid Mode is disabled, so stop HybridIO */
		vsw_hio_stop_port(portp);
		portp->p_hio_enabled = B_FALSE;
	} else {
		portp->p_hio_enabled =  B_TRUE;
		/* reset the port to initiate HybridIO setup */
		vsw_hio_port_reset(portp, B_FALSE);
	}
}

/*
 * vsw_hio_stop_port -- Stop HybridIO for a given port. Sequence
 *	followed is similar to vsw_hio_free_all_shares().
 *
 */
void
vsw_hio_stop_port(vsw_port_t *portp)
{
	vsw_t *vswp = portp->p_vswp;
	vsw_share_t *vsharep;
	int max_retries = vsw_hio_max_cleanup_retries;

	D1(vswp, "%s:enter\n", __func__);
	mutex_enter(&vswp->hw_lock);

	if (vswp->hio_capable == B_FALSE) {
		mutex_exit(&vswp->hw_lock);
		return;
	}

	vsharep = vsw_hio_find_vshare_port(vswp, portp);
	if (vsharep == NULL) {
		mutex_exit(&vswp->hw_lock);
		return;
	}

	do {
		if (vsharep->vs_state & VSW_SHARE_DDS_ACKD) {
			int rv;

			/* send DDS_DEL_SHARE */
			D1(vswp, "%s:sending DEL_SHARE msg for "
			    "share(%d)", __func__, vsharep->vs_index);
			rv = vsw_hio_send_delshare_msg(vsharep);
			if (rv != 0) {
				/*
				 * Cause a port reset to trigger
				 * cleanup.
				 */
				vsw_hio_port_reset(vsharep->vs_portp, B_FALSE);
			}
		}
		if (max_retries == 1) {
			/* last retry */
			DWARN(vswp, "%s:All retries failed, "
			    " cause a reset to trigger cleanup for "
			    "share(%d)", __func__, vsharep->vs_index);
			vsw_hio_port_reset(vsharep->vs_portp, B_FALSE);
		}

		/* Check if the share still assigned to this port */
		if ((vsharep->vs_portp != portp) ||
		    (vsharep->vs_state == VSW_SHARE_FREE)) {
			break;
		}

		/*
		 * Release the lock so that reply for DEL_SHARE
		 * messages come and get processed, that is, shares
		 * get freed.
		 */
		mutex_exit(&vswp->hw_lock);
		drv_usecwait(vsw_hio_cleanup_delay);
		mutex_enter(&vswp->hw_lock);

		/* Check if the share still assigned to this port */
		if ((vsharep->vs_portp != portp) ||
		    (vsharep->vs_state == VSW_SHARE_FREE)) {
			break;
		}
		max_retries--;
	} while ((vsharep->vs_state != VSW_SHARE_FREE) && (max_retries > 0));

	mutex_exit(&vswp->hw_lock);
	D1(vswp, "%s:exit\n", __func__);
}

/*
 * vsw_hio_rest_all -- Resets all ports that have shares allocated.
 *	It is called only in the panic code path, so the LDC channels
 *	are reset immediately.
 */
static void
vsw_hio_reset_all(vsw_t *vswp)
{
	vsw_hio_t	*hiop = &vswp->vhio;
	vsw_share_t	*vsharep;
	int		i;

	D1(vswp, "%s:enter\n", __func__);

	if (vswp->hio_capable != B_TRUE)
		return;

	for (i = 0; i < hiop->vh_num_shares; i++) {
		vsharep = &hiop->vh_shares[i];
		if (vsharep->vs_state == VSW_SHARE_FREE) {
			continue;
		}
		/*
		 * Reset the port with immediate flag enabled,
		 * to cause LDC reset immediately.
		 */
		vsw_hio_port_reset(vsharep->vs_portp, B_TRUE);
	}
	D1(vswp, "%s:exit\n", __func__);
}

/*
 * vsw_hio_reboot_callb -- Called for reboot event. It tries to
 *	free all currently allocated shares.
 */
/* ARGSUSED */
static boolean_t
vsw_hio_reboot_callb(void *arg, int code)
{
	vsw_t *vswp = arg;

	D1(vswp, "%s:enter\n", __func__);
	vsw_hio_free_all_shares(vswp, B_TRUE);
	D1(vswp, "%s:exit\n", __func__);
	return (B_TRUE);
}

/*
 * vsw_hio_panic_callb -- Called from panic event. It resets all
 *	the ports that have shares allocated. This is done to
 *	trigger the cleanup in the guest ahead of HV reset.
 */
/* ARGSUSED */
static boolean_t
vsw_hio_panic_callb(void *arg, int code)
{
	vsw_t *vswp = arg;

	D1(vswp, "%s:enter\n", __func__);
	vsw_hio_reset_all(vswp);
	D1(vswp, "%s:exit\n", __func__);
	return (B_TRUE);
}

/*
 * Setup kstats for hio statistics.
 */
static kstat_t *
vsw_hio_setup_kstats(char *ks_mod, char *ks_name, vsw_t *vswp)
{
	kstat_t			*ksp;
	vsw_hio_kstats_t	*hiokp;
	vsw_hio_t		*hiop;
	char			share_assigned_info[MAXNAMELEN];
	size_t			size;
	int			i;

	hiop = &vswp->vhio;
	/*
	 * vsw_hio_stats_t structure is variable size structure
	 * having fields defined only for one share. So, we need
	 * allocate additional space for the rest of the shares.
	 */
	size = sizeof (vsw_hio_kstats_t) / sizeof (kstat_named_t);
	ASSERT(hiop->vh_num_shares >= 1);
	size += ((hiop->vh_num_shares - 1) * 2);

	ksp = kstat_create(ks_mod, vswp->instance, ks_name, "misc",
	    KSTAT_TYPE_NAMED, size, KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL) {
		return (NULL);
	}
	hiokp = (vsw_hio_kstats_t *)kmem_zalloc(sizeof (kstat_named_t) *
	    size, KM_SLEEP);
	ksp->ks_data = hiokp;

	hiop->vh_ksp = ksp;
	hiop->vh_kstatsp = hiokp;
	hiop->vh_kstat_size =  size;

	kstat_named_init(&hiokp->hio_capable, "hio_capable", KSTAT_DATA_CHAR);
	kstat_named_init(&hiokp->hio_num_shares, "hio_num_shares",
	    KSTAT_DATA_ULONG);

	for (i = 0; i < hiop->vh_num_shares; i++) {
		(void) sprintf(share_assigned_info, "%s%d", "hio_share_", i);
		kstat_named_init(&(hiokp->share[i].assigned),
		    share_assigned_info, KSTAT_DATA_ULONG);

		(void) sprintf(share_assigned_info, "%s%d%s",
		    "hio_share_", i, "_state");
		kstat_named_init(&(hiokp->share[i].state),
		    share_assigned_info, KSTAT_DATA_ULONG);
	}

	ksp->ks_update = vsw_hio_kstats_update;
	ksp->ks_private = (void *)vswp;
	kstat_install(ksp);
	return (ksp);
}

/*
 * Destroy hio kstats.
 */
static void
vsw_hio_destroy_kstats(vsw_t *vswp)
{
	kstat_t			*ksp;
	vsw_hio_t		*hiop;

	ASSERT(vswp != NULL);

	ksp = vswp->vhio.vh_ksp;
	hiop = &vswp->vhio;
	if (ksp != NULL) {
		kmem_free(hiop->vh_kstatsp, sizeof (kstat_named_t) *
		    hiop->vh_kstat_size);
		kstat_delete(ksp);
		hiop->vh_kstatsp = NULL;
		hiop->vh_ksp = NULL;
	}
}

/*
 * Update hio kstats.
 */
static int
vsw_hio_kstats_update(kstat_t *ksp, int rw)
{
	vsw_t			*vswp;
	vsw_hio_t		*hiop;
	vsw_hio_kstats_t	*hiokp;
	int			i;

	vswp = (vsw_t *)ksp->ks_private;
	ASSERT(vswp != NULL);

	hiop = &vswp->vhio;
	hiokp = hiop->vh_kstatsp;

	if (rw == KSTAT_READ) {
		if (vswp->hio_capable) {
			(void) strcpy(hiokp->hio_capable.value.c, "Yes");
		} else {
			/* not hio capable, just return */
			(void) strcpy(hiokp->hio_capable.value.c, "No");
			return (0);
		}

		mutex_enter(&vswp->hw_lock);
		hiokp->hio_num_shares.value.ul = (uint32_t)hiop->vh_num_shares;
		for (i = 0; i < hiop->vh_num_shares; i++) {
			hiokp->share[i].assigned.value.ul =
			    hiop->vh_shares[i].vs_macaddr;
			hiokp->share[i].state.value.ul =
			    hiop->vh_shares[i].vs_state;
		}
		mutex_exit(&vswp->hw_lock);
	} else {
		return (EACCES);
	}

	return (0);
}
