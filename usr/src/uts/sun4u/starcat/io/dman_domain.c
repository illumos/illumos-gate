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
 * Domain specific portion of the Starcat Management Network Driver
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/ksynch.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/kstr.h>
#include <sys/errno.h>
#include <sys/ethernet.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/strsun.h>
#include <sys/pci.h>
#include <sys/callb.h>
#include <sys/pci.h>
#include <sys/iosramio.h>
#include <sys/mboxsc.h>
#include <netinet/in.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/socket.h>
#include <netinet/igmp_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/dman.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunndi.h>

#define	MAN_SCHIZO_BINDING_NAME		"pci108e,8001"
#define	MAN_XMITS_BINDING_NAME		"pci108e,8002"

int	man_is_on_domain = TRUE;

/*
 * Domain side function prototypes.
 */
int	man_get_iosram(manc_t *);
int	man_domain_configure(void);
int	man_domain_deconfigure(void);
int	man_path_discovery(void);
int	man_dossc_switch(uint32_t);
int	man_dr_attach(dev_info_t *);
int	man_dr_detach(dev_info_t *);
static int	man_dr_submit_work_wait(dev_info_t *, int);
static int	man_find_devs(mi_path_t *, uchar_t);
static int 	man_dip_is_schizoxmits0_pcib(dev_info_t *, int *, int *);
static int	man_dip_is_eri(dev_info_t *, man_dev_t *);
static int	man_dip_is_attached(dev_info_t *);
static int 	man_get_eri_dev_info(dev_info_t *, man_dev_t *);
static int	man_mbox_initialized = FALSE;

/*
 * Externs
 */
extern int	man_pg_cmd(mi_path_t *, man_work_t *);
extern kmutex_t		man_lock;
extern void		*man_softstate;
extern man_work_t	*man_work_alloc(int, int);
extern void		man_work_free(man_work_t *);
extern void		man_work_add(man_workq_t *, man_work_t *);
extern man_workq_t	*man_bwork_q;
extern man_workq_t	*man_iwork_q;
extern queue_t		*man_ctl_wq;

#if defined(DEBUG)
static void man_print_manc(manc_t *);
extern uint32_t	man_debug;
#endif  /* DEBUG */

int
man_domain_configure(void)
{
	int		status = 0;

	/*
	 * man_mbox_initialized is protected by inner perimiter lock.
	 */
	if (man_mbox_initialized == TRUE)
		goto exit;

	status = mboxsc_init(IOSRAM_KEY_SCMD, MBOXSC_MBOX_IN, NULL);

	if (status != 0) {
		cmn_err(CE_WARN, "man_domain_configure: failed to initialize"
		    " MBOXSC_MBOX_IN, errno = %d", status);
		goto exit;
	}

	status = mboxsc_init(IOSRAM_KEY_MDSC, MBOXSC_MBOX_OUT, NULL);
	if (status != 0) {
		mboxsc_fini(IOSRAM_KEY_SCMD);
		cmn_err(CE_WARN, "man_domain_configure: failed to initialize"
		    " MBOXSC_MBOX_OUT, errno = %d", status);
		goto exit;
	}

	man_mbox_initialized = TRUE;

	status = man_path_discovery();
	if (status != 0) {
		mboxsc_fini(IOSRAM_KEY_SCMD);
		mboxsc_fini(IOSRAM_KEY_MDSC);
		man_mbox_initialized = FALSE;
	}

exit:
	return (status);
}

/*
 * Build pathgroup connecting a domain to the SSC. Only called on domains
 * at first man_open. On the SSC, pathgroups are built by IOCTL requests
 * from the MAN daemon (see man_ioctl and mand(1M)).
 *
 * Locks held
 *	- exclusive innerperim.
 */
int
man_path_discovery(void)
{
	manc_t		manc;
	mi_path_t	mpath;
	int		num_devs;
	int		status = 0;
	int		i;

	MAN_DBG(MAN_CONFIG, ("man_path_discovery:"));

	if (status = man_get_iosram(&manc)) {
		goto exit;
	}

	/*
	 * If manc_ip_type indicates MAN network is not enabled
	 * for this domain, then lets just bailout from here as if no
	 * devices were found.
	 */
	if ((manc.manc_ip_type != AF_INET) &&
	    (manc.manc_ip_type != AF_INET6)) {
		goto exit;
	}

	MAN_DBGCALL(MAN_CONFIG, man_print_manc(&manc));

	/*
	 * Extract SC ethernet address from IOSRAM.
	 */
	ether_copy(&manc.manc_sc_eaddr, &mpath.mip_eaddr);

	mpath.mip_pg_id = 0;	/* SC is always pathgroup ID 0 */
	mpath.mip_man_ppa = 0;	/* Domain only has one ppa, 0 */

	/*
	 * Get list of present devices, and update man_paths[] as needed.
	 */
	num_devs = man_find_devs(&mpath, MAN_MAX_EXPANDERS);
	if (num_devs <= 0) {
		status = ENODEV;
		goto exit;
	}

	mpath.mip_cmd = MI_PATH_ASSIGN;

	mutex_enter(&man_lock);
	status = man_pg_cmd(&mpath, NULL);
	if (status) {
		mutex_exit(&man_lock);
		goto exit;
	}

	/*
	 * Now activate the ethernet on the golden io board.
	 */
	for (i = 0; i < num_devs; i++) {
		if (mpath.mip_devs[i].mdev_exp_id == manc.manc_golden_iob)
			mpath.mip_devs[0] = mpath.mip_devs[i];
	}
	mpath.mip_ndevs = 1;
	mpath.mip_cmd = MI_PATH_ACTIVATE;
	status = man_pg_cmd(&mpath, NULL);
	mutex_exit(&man_lock);

exit:
	MAN_DBG(MAN_CONFIG, ("man_path_discovery: returns %d\n", status));

	return (status);
}

int
man_domain_deconfigure(void)
{

	mboxsc_fini(IOSRAM_KEY_SCMD);
	mboxsc_fini(IOSRAM_KEY_MDSC);
	/*
	 * We are about to unload and know that there are no open
	 * streams, so this change outside of the perimiter is ok.
	 */
	man_mbox_initialized = FALSE;

	return (0);
}

/*
 * Add a work request to the inner perimeter with the new eri device info.
 */
/* ARGSUSED */
int
man_dr_attach(dev_info_t *dip)
{
	man_t		*manp;
	man_work_t	*wp;
	int		status = 0;
	man_dev_t	mdev;


	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, 0);
	if (manp == NULL || manp->man_pg == NULL) {
		goto exit;
	}

	if (man_get_eri_dev_info(dip, &mdev) == FALSE) {
		status = ENODEV;
		goto exit;
	}
	MAN_DBG(MAN_DR, ("man_dr_attach: dip major = %d instance =%d",
	    mdev.mdev_major, mdev.mdev_ppa));
	wp = man_work_alloc(MAN_WORK_DRATTACH, KM_NOSLEEP);
	if (wp == NULL) {
		status = ENOMEM;
		goto exit;
	}

	wp->mw_arg.a_man_ppa = 0;	/* Domain only has one ppa, 0 */
	wp->mw_arg.a_pg_id = 0;		/* SC is always pathgroup ID 0 */
	wp->mw_arg.a_sf_dev = mdev;
	wp->mw_flags = MAN_WFLAGS_NOWAITER;

	man_work_add(man_iwork_q, wp);

	if (man_ctl_wq)
		qenable(man_ctl_wq);

exit:
	mutex_exit(&man_lock);

	return (status);
}

int
man_dr_detach(dev_info_t *dip)
{
	man_t		*manp;
	int		status = 0;
	int		retries = 0;


	mutex_enter(&man_lock);
	manp = ddi_get_soft_state(man_softstate, 0);
	if (manp == NULL || manp->man_pg == NULL) {
		mutex_exit(&man_lock);
		goto exit;
	}
	mutex_exit(&man_lock);

	/*
	 * Arrange to have the detaching path switched if it is active.
	 * We will cv_wait_sig for the switch to complete if it is needed.
	 */
again:
	status = man_dr_submit_work_wait(dip, MAN_WORK_DRSWITCH);
	if (status == EAGAIN && retries < manp->man_dr_retries) {
		/*
		 * Delay a bit and retry.
		 */
		MAN_DBG(MAN_DR,
		    ("man_dr_detach(switch): EAGAIN - retrying..."));
		retries++;
		delay(drv_usectohz(manp->man_dr_delay));
		goto again;
	}

	if (status)
		goto exit;

	retries = 0;

	/*
	 * Detaching device no longer in use, remove it from our
	 * pathgroup.
	 */
	status = man_dr_submit_work_wait(dip, MAN_WORK_DRDETACH);
	if (status == EAGAIN && retries < manp->man_dr_retries) {
		MAN_DBG(MAN_DR,
		    ("man_dr_detach(detach): EAGAIN - retrying..."));
		retries++;
		goto again;
	}

exit:
	MAN_DBG(MAN_DR, ("man_dr_detach: returns %d", status));
	return (status);
}

static int
man_dr_submit_work_wait(dev_info_t *dip, int work_type)
{
	man_work_t	*wp;
	int		status = 0;

	wp = man_work_alloc(work_type, KM_NOSLEEP);
	if (wp == NULL) {
		status = ENOMEM;
		goto exit;
	}

	wp->mw_arg.a_man_ppa = 0;
	wp->mw_arg.a_pg_id = 0;
	wp->mw_arg.a_sf_dev.mdev_major = ddi_driver_major(dip);
	wp->mw_arg.a_sf_dev.mdev_ppa = ddi_get_instance(dip);

	mutex_enter(&man_lock);
	wp->mw_flags = MAN_WFLAGS_CVWAITER;
	man_work_add(man_iwork_q, wp);

	/* TBD - change to ASSERT ? */
	if (man_ctl_wq)
		qenable(man_ctl_wq);

	while (!(wp->mw_flags & MAN_WFLAGS_DONE)) {
		if (!cv_wait_sig(&wp->mw_cv, &man_lock)) {
			wp->mw_flags &= ~MAN_WFLAGS_CVWAITER;
			status = EINTR;
			break;
		}
	}

	/*
	 * Note that if cv_wait_sig() returns zero because a signal
	 * was received, MAN_WFLAGS_DONE may not be set.
	 * This will happen if man_dr_submit_work_wait() reacquires
	 * man_lock before man_iwork() can acquire man_lock just before
	 * signalling its work is complete.
	 * In this case, it is not necessary to call man_work_free()
	 * here because it will be called by man_iwork() because
	 * MAN_WFLAGS_CVWAITER was cleared.
	 * Should man_iwork() obtain man_lock to signal completion,
	 * MAN_WFLAGS_DONE will be set which will ensure man_work_free()
	 * is called here.
	 */
	if (wp->mw_flags & MAN_WFLAGS_DONE) {
		status = wp->mw_status;
		man_work_free(wp);
	}

	mutex_exit(&man_lock);

exit:
	return (status);
}

/*
 * Notify SSC of switch request and wait for response.
 */
int
man_dossc_switch(uint32_t exp_id)
{
	uint64_t	req_tid;
	uint32_t	req_cmd;
	uint64_t	resp_tid;
	uint32_t	resp_cmd;
	uint32_t	type;
	man_mbox_msg_t	req;
	man_mbox_msg_t	resp;
	uint32_t	length;
	int		status = 0;

	/*
	 *  There should be nothing in inbound mailbox.
	 */
	resp_tid = resp_cmd = type = 0;
	length = sizeof (man_mbox_msg_t);
	bzero((char *)&resp, sizeof (man_mbox_msg_t));
	while (mboxsc_getmsg(IOSRAM_KEY_SCMD, &type, &resp_cmd, &resp_tid,
	    &length, &resp, 0) == 0) {

		resp_tid = resp_cmd = type = 0;
		length = sizeof (man_mbox_msg_t);
		bzero((char *)&resp, sizeof (man_mbox_msg_t));

		MAN_DBG(MAN_IOSRAM, ("man_dossc_switch: dumping message"));
		MAN_DBG(MAN_IOSRAM, ("\tcommand = 0x%x", resp_cmd));
	}

	MAN_DBG(MAN_IOSRAM, ("man_dossc_switch: sending message"));

	bzero((char *)&req, sizeof (man_mbox_msg_t));
	req.mb_status = 0;
	req.mb_exp_id = exp_id;
	req_tid = 0;
	req_cmd = MAN_WORK_SWITCH;

	status = mboxsc_putmsg(IOSRAM_KEY_MDSC, MBOXSC_MSG_REQUEST,
	    req_cmd, &req_tid, sizeof (man_mbox_msg_t), &req,
	    MAN_IOSRAM_TIMEOUT);

	if (status != 0) {
		cmn_err(CE_WARN, "man_dossc_switch: mboxsc_putmsg failed,"
		    " errno = %d", status);
		goto exit;
	}

	bzero((char *)&resp, sizeof (man_mbox_msg_t));

	resp_tid = type = resp_cmd = 0;
	length = sizeof (man_mbox_msg_t);
	status = mboxsc_getmsg(IOSRAM_KEY_SCMD, &type, &resp_cmd, &resp_tid,
	    &length, (void *)&resp, MAN_IOSRAM_TIMEOUT);
	if (status != 0) {
		cmn_err(CE_WARN, "man_dossc_switch: mboxsc_getmsg failed,"
		    " errno = %d", status);
		goto exit;
	}

	MAN_DBG(MAN_IOSRAM, ("man_dossc_switch: received message"));

	if (req_cmd != resp_cmd || req_tid != resp_tid) {
		cmn_err(CE_WARN, "man_dossc_switch: failed,"
		    " cmd/transid mismatch (%d, %d)/(%d, %d)",
		    req_cmd, resp_cmd, (int)req_tid, (int)resp_tid);
		status = EINVAL;
		goto exit;
	}

	status = resp.mb_status;
	if (status != 0) {
		cmn_err(CE_WARN, "man_dossc_switch: failed errno == %d",
		    status);
	}
exit:
	return (status);
}


/*
 *  Read IOSRAM info.
 */
int
man_get_iosram(manc_t *mcp)
{
	int	status;

	if (mcp == NULL)
		return (EINVAL);

	status = iosram_rd(IOSRAM_KEY_MANC, 0, sizeof (manc_t), (caddr_t)mcp);
	if (status) {
		cmn_err(CE_WARN, "man_get_iosram: iosram_rd failed"
		    " errno = %d\n", status);
		return (status);
	}

	MAN_DBG(MAN_PATH, ("man_get_iosram:"));
	MAN_DBGCALL(MAN_PATH, man_print_manc(mcp));

	if (mcp->manc_magic != IOSRAM_KEY_MANC) {
		cmn_err(CE_WARN, "man_get_iosram: bad magic - got(0x%x)"
		    " expected(0x%x)\n", mcp->manc_magic, IOSRAM_KEY_MANC);
		status = EIO;
	} else if (mcp->manc_version != MANC_VERSION) {
		cmn_err(CE_WARN, "man_get_iosram: version mismatch -"
		    " got(0x%x) expected(0x%x)\n", mcp->manc_version,
		    MANC_VERSION);
		status = EIO;
	}

	return (status);
}

#if defined(MAN_NO_IOSRAM)

static manc_t	manc = {
	IOSRAM_KEY_MANC,
	MANC_VERSION,
	0,
	AF_INET,
/*	0x10010102,		Two */
	0x10010103,		/* Scot */
	0xFF000000,		/* Scot netmask */
	0x10010101,		/* SC 10.1.1.1 */
	{0},	/* AF_INET6 addrs */
	{0},	/* AF_INET6 addrs */
	{0},
/*	{0x8, 0x0, 0x20, 0x21, 0x44, 0x83},	Domain eaddr "two" */
	{0x8, 0x0, 0x20, 0x8f, 0x84, 0x63},	/* Domain eaddr "scot" */
	{0x8, 0x0, 0x20, 0x1f, 0xe3, 0x46},	/* SC eaddr "one" */
	0x1,
	0x1
};


/*
 *  Get IOSRAM info or release it.
 */
int
man_get_iosram(manc_t *mcp)
{
	int	status = 0;

	if (mcp == NULL)
		return (EINVAL);

	*mcp = manc;

	if (mcp->manc_magic != IOSRAM_KEY_MANC) {
		cmn_err(CE_WARN, "man_get_iosram: bad magic - got(0x%x)"
		    " expected(0x%x)\n", mcp->manc_magic, IOSRAM_KEY_MANC);
		status = EIO;
	} else if (mcp->manc_version != MANC_VERSION) {
		cmn_err(CE_WARN, "man_get_iosram: version mismatch -"
		    " got(0x%x) expected(0x%x)\n", mcp->manc_version,
		    MANC_VERSION);
		status = EIO;
	}

	return (status);
}
#endif  /* MAN_NO_IOSRAM */

/*
 * Find all RIOs on the IO boards for the domain. We walk all the children
 * of the root node looking for a PCI devinfo with a safari port ID of
 * 0xDC that has a child with device ID of 3.  This is gauranteed to be
 * the network portion of the RIO by virtue of the way Starcats are
 * physically built.
 */
static int
man_find_devs(mi_path_t *mipathp, uchar_t golden_iob)
{
	dev_info_t	*bus_dip;
	dev_info_t	*eri_dip;
	dev_info_t	*rdip, *pdip;
	int		exp_id;
	int		found = 0;
	int		circ;
	int		circ2;
	man_dev_t	ndev;
	int		xmits;

	MAN_DBG(MAN_PATH, ("man_find_devs: mdevpp(0x%p) golden_iob(%d)\n",
	    (void *)(mipathp), golden_iob));

	/*
	 * Hold parent busy while walking its child list.
	 */
	rdip = ddi_root_node();
	ndi_devi_enter(rdip, &circ);
	bus_dip = ddi_get_child(rdip);

	while (bus_dip != NULL) {
		exp_id = -1;
		xmits = 0;
		if (man_dip_is_schizoxmits0_pcib(bus_dip, &exp_id, &xmits)) {
			eri_dip = NULL;
			pdip = bus_dip;
			if (xmits) {
				/*
				 * If this is XMITS0 PCI_B leaf, then the
				 * pci_pci bridge which is the only child,
				 * is the parent to MAN RIO.
				 */
				pdip = ddi_get_child(bus_dip);
				if (pdip == NULL) {
					bus_dip = ddi_get_next_sibling(bus_dip);
					continue;
				}
			}
			ndi_devi_enter(pdip, &circ2);
			eri_dip = ddi_get_child(pdip);
			while (eri_dip != NULL) {
				MAN_DBG(MAN_PATH, ("man_find_devs: "
				    "eri_dip %s\n",
				    ddi_binding_name(eri_dip)));
				if (man_dip_is_eri(eri_dip, &ndev) &&
				    man_dip_is_attached(eri_dip)) {

					ASSERT(exp_id != -1);
					ndev.mdev_exp_id = exp_id;
					ndev.mdev_state = MDEV_ASSIGNED;
					mipathp->mip_devs[found] = ndev;
					found++;

					MAN_DBG(MAN_PATH,
					    ("man_find_devs: found eri maj(%d) "
					    "ppa(%d) on expander(%d)\n",
					    ndev.mdev_major,
					    ndev.mdev_ppa, exp_id));
				}
				eri_dip = ddi_get_next_sibling(eri_dip);
			}
			ndi_devi_exit(pdip, circ2);
		}
		bus_dip = ddi_get_next_sibling(bus_dip);
	}
	ndi_devi_exit(rdip, circ);

	MAN_DBG(MAN_PATH, ("man_find_devs returns found = %d\n", found));

	mipathp->mip_ndevs = found;
	return (found);
}

/*
 * Verify if the dip passed is an instance of 'eri' and set
 * the device info in mdevp.
 */
static int
man_get_eri_dev_info(dev_info_t *dip, man_dev_t *mdevp)
{
	dev_info_t	*parent_dip;
	int		exp_id;
	int		xmits;
	char		*name;

	ASSERT(dip != NULL);
	/*
	 * Verify if the parent is schizo(xmits)0 and pci B leaf.
	 */
	if (((parent_dip = ddi_get_parent(dip)) == NULL) ||
	    ((name = ddi_binding_name(parent_dip)) == NULL))
		return (FALSE);
	if (strcmp(name, MAN_SCHIZO_BINDING_NAME) != 0) {
		/*
		 * This RIO could be on XMITS, so get the dip to
		 * XMITS PCI Leaf.
		 */
		if ((parent_dip = ddi_get_parent(parent_dip)) == NULL)
			return (FALSE);
		if (((name = ddi_binding_name(parent_dip)) == NULL) ||
		    (strcmp(name, MAN_XMITS_BINDING_NAME) != 0)) {
			return (FALSE);
		}
	}
	if (man_dip_is_schizoxmits0_pcib(parent_dip, &exp_id, &xmits) == FALSE)
		return (FALSE);

	/*
	 * Make sure it is attached.
	 */
	if (man_dip_is_attached(dip) == FALSE) {
		MAN_DBG(MAN_DR, ("man_get_eri_dev_info: "
		    "dip 0x%p not attached\n", dip));
		return (FALSE);
	}
	mdevp->mdev_exp_id = exp_id;
	mdevp->mdev_ppa = ddi_get_instance(dip);
	mdevp->mdev_major = ddi_driver_major(dip);
	mdevp->mdev_state = MDEV_ASSIGNED;
	return (TRUE);
}

/*
 * MAN RIO is connected to SCHIZO/XMITS 0 and PCI_B Leaf.
 * Incase of XMITS, it is actually connected to a PCI Bridge(21154)
 * which is directly connected to the PCI_B leaf of XMITS0.
 *
 * This function verifies if the given dip is SCHIZO/XMITS 0 and
 * PCI_B Leaf. This is done as follows:
 *
 * 	- Check the binding name to verify SCHIZO/XMITS.
 * 	- Verify the Device type to be "pci".
 *	- Verify the PortID to be ending with 0x1C
 * 	- Verify the the CSR base to be 0x70.0000.
 */
static int
man_dip_is_schizoxmits0_pcib(dev_info_t *dip, int *exp_id, int *xmits)
{
	char			dtype[MAN_DDI_BUFLEN];
	int			portid;
	uint_t			pci_csr_base;
	struct pci_phys_spec	*regbuf = NULL;
	int			length = MAN_DDI_BUFLEN;
	char			*name;

	ASSERT(dip != NULL);
	*exp_id = -1;
	if ((name = ddi_binding_name(dip)) == NULL)
		return (FALSE);
	if (strcmp(name, MAN_SCHIZO_BINDING_NAME) == 0) {
		MAN_DBG(MAN_PATH, ("man_dip_is_schizoxmits0_pcib: "
		    "SCHIZO found 0x%p\n", dip));
	} else if (strcmp(name, MAN_XMITS_BINDING_NAME) == 0) {
		*xmits = TRUE;
		MAN_DBG(MAN_PATH, ("man_dip_is_schizoxmits0_pcib: "
		    "XMITS found 0x%p\n", dip));
	} else
		return (FALSE);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, MAN_DEVTYPE_PROP,
	    (caddr_t)dtype, &length) == DDI_PROP_SUCCESS) {

		MAN_DBG(MAN_PATH, ("dtype: %s\n", dtype));
		if (strncmp(dtype, MAN_DEVTYPE_PCI, 3) != 0)
			goto notfound;

		/*
		 * Get safari ID (DDI port ID).
		 */
		if ((portid = (int)ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		    MAN_PORTID_PROP, -1)) == -1) {

			MAN_DBG(MAN_PATH, ("ddi_getpropp: failed\n"));
			goto notfound;
		}

		/*
		 * All schizo 0 safari IDs end in 0x1C.
		 */
		if ((portid & MAN_SCHIZO_MASK) != MAN_SCHIZO_0_ID)
			goto notfound;

		/*
		 * All PCI nodes "B" are at configspace 0x70.0000
		 */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    MAN_REG_PROP, (caddr_t)&regbuf,
		    &length) != DDI_PROP_SUCCESS) {

			MAN_DBG(MAN_PATH, ("ddi_getlongprop_buf: failed"));
			goto notfound;
		}

		pci_csr_base = regbuf[0].pci_phys_mid & PCI_CONF_ADDR_MASK;
		kmem_free(regbuf, length);
		if (pci_csr_base == MAN_PCI_B_CSR_BASE) {

			MAN_DBG(MAN_PATH, ("man_dip_is_schizoxmits0_pcib:"
			    " found PCI B at dip(0x%p)\n", (void *)dip));

			*exp_id = portid >> 5;
			return (TRUE);
		}
	}

notfound:
	return (FALSE);
}

static int
man_dip_is_eri(dev_info_t *dip, man_dev_t *ndevp)
{
	struct pci_phys_spec	*regbuf = NULL;
	int			length = 0;
	uint_t			pci_device;
	uint_t			pci_function;

	MAN_DBG(MAN_PATH, ("man_dip_is_eri: dip(0x%p) ndevp(0x%p)\n",
	    (void *)dip, (void *)ndevp));
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    MAN_REG_PROP, (caddr_t)&regbuf,
	    &length) == DDI_PROP_SUCCESS) {

		pci_device = PCI_REG_DEV_G(regbuf->pci_phys_hi);
		pci_function = PCI_REG_FUNC_G(regbuf->pci_phys_hi);
		kmem_free(regbuf, length);

		/*
		 * The network function of the RIO ASIC will always
		 * be device 3 and function 1 ("network@3,1").
		 */
		if (pci_device == 3 && pci_function == 1) {
			ndevp->mdev_ppa = ddi_get_instance(dip);
			ndevp->mdev_major = ddi_driver_major(dip);

			MAN_DBG(MAN_PATH, ("man_dip_is_eri: found eri maj(%d)"
			    " ppa(%d)\n", ndevp->mdev_major, ndevp->mdev_ppa));

			return (TRUE);
		}
	}

	MAN_DBG(MAN_PATH, ("man_dip_is_eri: returns FALSE\n"));

	return (FALSE);
}

static int
man_dip_is_attached(dev_info_t *dip)
{
	int state;

	state = ddi_get_devstate(dip);
	if (i_ddi_devi_attached(dip) || (state == DDI_DEVSTATE_UP)) {
		/*
		 * The instance info is more important for us,
		 * so verify.
		 */
		if (ddi_get_instance(dip) >=  0) {
			return (TRUE);
		}
		cmn_err(CE_WARN, "man_dip_is_attached: "
		    "eri 0x%p instance is not set yet", dip);

	}
	return (FALSE);
}

#if defined(DEBUG)
static void
man_print_manc(manc_t *mcp)
{
	cmn_err(CE_CONT, "\tmcp(0x%p)\n\n", (void *)mcp);

	if (mcp == NULL)
		return;

	cmn_err(CE_CONT, "\tmagic: 0x%x\n", mcp->manc_magic);
	cmn_err(CE_CONT, "\tversion: 0x%x\n", mcp->manc_version);
	cmn_err(CE_CONT, "\tcsum: %d\n", mcp->manc_csum);
	cmn_err(CE_CONT, "\tdom_eaddr: %s\n",
	    ether_sprintf(&mcp->manc_dom_eaddr));
	cmn_err(CE_CONT, "\tsc_eaddr: %s\n",
	    ether_sprintf(&mcp->manc_sc_eaddr));
	cmn_err(CE_CONT, "\tiob_bitmap: 0x%x\n", mcp->manc_iob_bitmap);
	cmn_err(CE_CONT, "\tgolden_iob: %d\n", mcp->manc_golden_iob);

}

#endif  /* DEBUG */
