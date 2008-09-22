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


#if defined(DEBUG)
#define	PCRAM_DEBUG
#endif

/*
 *  PCMCIA SRAM/DRAM/MROM Memory Card Driver
 *
 *
 *  The PCMCIA memory card driver will be used to support disk-like
 *  I/O access to any standard PCMCIA memory cards such as:
 *
 *		- Non-Volatile Static RAM (SRAM)
 *		- Non-Volatile Dynamic RAM (DRAM)
 *		- Mask ROM (MROM)
 *
 *  The PCMCIA memory cards can be used as pseudo-floppy disks.
 *
 *  Features:
 *
 *  	- DO NOT support the FLASH, EEPROM, and OTP memory card.
 *	- modeling after the ramdisk pseudo-device.
 *  	- currently supporting character device and block device.
 *  	- supporting only single partition.
 *
 *  Support Utility:
 *
 *  	The fdformat(1) utility has to use PCRAM_PROBESIZE ioctl
 *	to request the card size information.
 *
 *	If a memory card has a Card Information Structure (CIS)
 *	then the card size is from a Common Memory CISTPL_DEVICE
 *	tuple.  If there is no CIS the driver must use
 *	write/read/restore operation on first byte of every 512KB
 *	block of data to determine the total card size.
 *	Refer to pcram_card_sizing().
 *
 *  	We do not need to support set geometry (DKIOCSGEOM) since we
 *  	provide PCRAM_PROBESIZE ioctl to probe the memory card size.
 *	PCRAM_PROBESIZE ioctl is a private interface which is
 *	used by the SunVTS and fdformat(1) utility.
 *
 *  SS2 CACHE+ problem note:
 *
 *  	Refer to card_byte_wr() for the problem of the SS2 CACHE+
 *	double word write to the 16-bit slave device.
 *
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>

/*
 * needed for: 	S_IFBLK - block special
 *		S_IFCHR - character special
 */
#include <sys/stat.h>

/* supporting eject(1) command (struct fd_drive) */
#include <sys/fdio.h>

/* The next headers may not be DDI-compliant */
#include <sys/dkio.h>
#include <sys/dklabel.h>	/* logical partitions */
#include <sys/vtoc.h>

/* DOS label */
#include <sys/fs/pc_label.h>

/*
 * PCMCIA and DDI related header files
 */
#include <sys/pccard.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * pcram-related header files
 */
#include <sys/pcmcia/pcramio.h>
#include <sys/pcmcia/pcramvar.h>

/*
 * Character/Block Operations (cb_ops) Structure
 */
static int pcram_getinstance(dev_t);
static int pcram_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int pcram_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int pcram_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int pcram_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int pcram_prop_op(dev_t dev, dev_info_t *dip,
				ddi_prop_op_t prop_op,
				int flags, char *name, caddr_t valuep,
				int *lengthp);
static int pcram_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				cred_t *credp, int *rvalp);
static int pcram_strategy(struct buf *bp);
static int pcram_print(dev_t dev, char *str);

/*
 * Device Operations (dev_ops) Structure
 */
static int pcram_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
				void *arg, void **resultp);
static int pcram_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcram_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * Called from pcram_strategy
 */
static void pcram_start(pcram_state_t *rs);

/*
 *  Misc functions
 */
static uint32_t pcram_softintr();


static int pcram_event(event_t, int, event_callback_args_t *);
static int pcram_card_insertion(pcram_state_t *);
static int pcram_card_removal(pcram_state_t *);
static int pcram_build_region_lists(pcram_state_t *);
static int pcram_build_region_list(pcram_state_t *,
					mem_region_t **, uint32_t);
static int pcram_get_bpbfat_info(pcram_state_t *, mem_region_t *);
static int pcram_get_solaris_info(pcram_state_t *, mem_region_t *);

static void pcram_destroy_region_lists(pcram_state_t *);
static void pcram_destroy_region_list(mem_region_t **, int *);

static mem_region_t *pcram_get_firstnext_region(mem_region_t *, uint32_t,
						uint32_t, uint32_t *);

#ifdef	PCRAM_DEBUG
int	pcram_debug = 0;
int	pcram_debug_events = 1;
static void pcram_display_card_status(get_status_t *);
static void pcram_debug_report_event(pcram_state_t *pcram, event_t event,
			int priority);
#endif


/* Character/Block Operations (cb_ops) Structure */
static struct cb_ops pcram_cb_ops = {
	pcram_open,		/* open 	*/
	pcram_close,		/* close 	*/
	pcram_strategy,		/* strategy 	*/
	pcram_print,		/* print 	*/
	nodev,			/* dump 	*/
	pcram_read,		/* read 	*/
	pcram_write,		/* write 	*/
	pcram_ioctl,		/* ioctl 	*/
	nodev,			/* devmap 	*/
	nodev,			/* mmap 	*/
	ddi_segmap,		/* segmap 	*/
	nochpoll,		/* poll 	*/
	pcram_prop_op,		/* prop_op 	*/
	NULL,			/* streamtab	*/
	D_NEW | D_MP		/* Driver compatibility flag */
};


/* Device Operations (dev_ops) Structure */
static struct dev_ops pcram_ops = {
	DEVO_REV,		/* devo_rev	*/
	0,			/* refcnt	*/
	pcram_getinfo,		/* info		*/
	nulldev,		/* identify	*/
	nulldev,		/* probe 	*/
	pcram_attach,		/* attach	*/
	pcram_detach,		/* detach	*/
	nodev,			/* reset (currently not supported)  */
	&pcram_cb_ops,		/* cb_ops pointer for leaf driver   */
	(struct bus_ops *)NULL, /* bus_ops pointer for nexus driver */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/* Module linkage information for the kernel */
extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops,		/* Type of module. This is a driver */
	PCRAM_DRIVERID,		/* Driver Identifier string */
	&pcram_ops,		/* Device Operation Structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&md,
	NULL
};


/*
 *  Local driver data
 */
static void *pcram_soft_state_p = NULL;

/* Determine PCMCIA memory card size */
static int pcram_card_sizing(pcram_state_t *rs);

/* Updating window size */
static int update_mapmempage(pcram_state_t *rs, int offset);

/* Byte write to the memory card */
static void card_byte_wr(pcram_state_t *rs, int xfer_size, int offset);

/* SPARC UNIX File System label checksum */
static int cksum(struct dk_label *label);

/* Writing disk label */
static int pcram_build_label_vtoc(pcram_state_t *rs, struct vtoc *vtoc);
static void pcram_write_label(pcram_state_t *rs);

/* Check media insertion/ejection status */
static int pcram_check_media(pcram_state_t *rs, enum dkio_state state);

/* Update drive characteristic structure */
static void update_hdrv_chars(pcram_state_t *, mem_region_t *);

/* external data of interest to us */
char *pcram_name = PCRAM_NAME;


/*
 * Module Initialization functions.
 *	1.  _init() routine
 *	2.  _info() routine
 *	3.  _fini() routine
 */
int
_init(void)
{
	int	error;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_init here\n");
#endif

	error = ddi_soft_state_init(&pcram_soft_state_p,
	    sizeof (pcram_state_t),
	    1	/* n_items */);
	if (error) {
		return (error);
	}

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&pcram_soft_state_p);
		return (error);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_info here\n");
#endif

	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	error;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_fini here\n");
#endif

	error = mod_remove(&modlinkage);
	if (error)
		return (error);
	ddi_soft_state_fini(&pcram_soft_state_p);

	return (error);
}


/*
 * Autoconfiguration Routines
 *	pcram_attach()
 *	pcram_detach()
 *	pcram_getinfo()
 */




/*
 * Wait for minor nodes to be created before returning from attach,
 * with a 5 sec. timeout to avoid hangs should an error occur.
 */
static void
pcram_minor_wait(pcram_state_t *rs)
{
	clock_t	timeout;

	timeout = ddi_get_lbolt() + drv_usectohz(5000000);
	mutex_enter(&rs->event_hilock);
	while ((rs->flags & PCRAM_MAKEDEVICENODE) == 0) {
		if (cv_timedwait(&rs->firstopenwait_cv, &rs->event_hilock,
		    timeout) == (clock_t)-1)
			break;
	}
	mutex_exit(&rs->event_hilock);
}


/*
 * pcram_attach() - performs board initialization
 *
 * This routine initializes the PCMCIA memory card driver
 * and the board.
 *
 *	Returns:	DDI_SUCCESS, if able to attach.
 *			DDI_FAILURE, if unable to attach.
 */
static int
pcram_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	pcram_state_t		*rs;
				/* CardServices variables */
	client_reg_t		client_reg;
	sockmask_t		sockmask;
	int			ret;
	map_log_socket_t	map_log_socket;
	get_status_t		get_status;


	instance = ddi_get_instance(dip);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT,
		    "pcram_attach: instance %d cmd 0x%x\n",
		    instance, cmd);
#endif

	/* resume from a checkpoint */
	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
		/* NOTREACHED */
	}


	/*
	 * make sure we're only being asked to do an attach
	 */
	if (cmd != DDI_ATTACH) {
		cmn_err(CE_NOTE, "pcram_attach[%d]: "
		    "cmd != DDI_ATTACH\n", instance);
		return (DDI_FAILURE);
		/* NOTREACHED */
	}

	if (ddi_soft_state_zalloc(pcram_soft_state_p,
	    instance) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "pcram_attach: could not allocate "
		    "state structure for instance %d.", instance);
		return (DDI_FAILURE);
		/* NOTREACHED */
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_attach: could not get "
		    "state structure for instance %d.",
		    instance);
		goto out;
	}


	/* Remember dev_info structure for getinfo  */
	rs->dip = dip;
	rs->instance = instance;
	ddi_set_driver_private(dip, rs);

	/*
	 * clear the per-unit flags field
	 */
	rs->flags = 0;

	/*
	 * Initialize the card event; initially say that the card
	 *	is removed; when we get a card insertion event and
	 *	validate the card, this will change.
	 */
	rs->card_event = 0;

	/*
	 * Clear the memory region pointers.
	 */
	rs->cm_regions = NULL;
	rs->am_regions = NULL;

	rs->host_sp = kmem_zalloc(HOST_BUF_SIZE, KM_SLEEP);

	rs->blk_open =  0;
	rs->chr_open =  0;
	rs->nlayered =  0;
	rs->busy =  0;
	rs->busy_wr =  0;
	rs->busy_rd =  0;

	/*
	 * Initialize to 0 until it is incremented in pcram_check_media
	 */
	rs->checkmedia_flag =  0;
	rs->ejected_media_flag =  0;
	rs->media_state = DKIO_NONE;

	/*
	 * Continueing to return EIO if the card is ejected while
	 * it is mounted until the LAST layered close is called
	 */
	rs->ejected_while_mounting = 0;

	rs->wp_posted = 0;


	/* initialize isit_pseudofloppy flag in each card struct */
	rs->isit_pseudofloppy = 0;

	/*
	 * Allocate hard drive characteristic structure
	 */
	rs->hdrv_chars = (struct hd_char *)
	    kmem_alloc(sizeof (struct hd_char), KM_SLEEP);

	/* allocate transfer list header */
	rs->blist = getrbuf(KM_SLEEP);
	if (rs->blist == NULL) {
		cmn_err(CE_NOTE, "pcram%d: attach card: "
		    "could not allocate transfer list header",
		    instance);
		goto out;
	}

	/* queue is empty */
	rs->blist->av_forw = NULL;

	/* Add Medium priority soft interrupt to the system */
	if (ddi_add_softintr(dip, DDI_SOFTINT_MED, &rs->softint_id,
	    &rs->soft_blk_cookie, (ddi_idevice_cookie_t *)NULL,
	    pcram_softintr, (caddr_t)rs) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "pcram%d attach: "
			    "could not add soft interrupt",
			    instance);
			goto out;
	}

	rs->flags |= PCRAM_SOFTINTROK;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_attach: "
		    "calling RegisterClient for instance %d\n",
		    instance);
	}
#endif

	/*
	 * Register with Card Services
	 * Note that we set CS_EVENT_CARD_REMOVAL_LOWP so that we get
	 *	low priority CS_EVENT_CARD_REMOVAL events as well.
	 */
	client_reg.Attributes = (INFO_MEM_CLIENT |
	    INFO_CARD_SHARE |
	    INFO_CARD_EXCL);
	client_reg.EventMask = (CS_EVENT_CARD_INSERTION |
	    CS_EVENT_CARD_REMOVAL |
	    CS_EVENT_CARD_REMOVAL_LOWP |
	    CS_EVENT_CLIENT_INFO |
	    CS_EVENT_REGISTRATION_COMPLETE);
	client_reg.event_handler = (csfunction_t *)pcram_event;
	client_reg.event_callback_args.client_data = rs;
	client_reg.Version = _VERSION(2, 1);
	client_reg.dip = dip;
	(void) strcpy(client_reg.driver_name, pcram_name);
	if ((ret = csx_RegisterClient(&rs->client_handle,
	    &client_reg)) != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_attach: "
		    "RegisterClient failed %s (0x%x)\n",
		    cft.text, ret);
		goto out;
	}

	rs->flags |= PCRAM_REGCLIENT;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_attach: "
		    "RegisterClient client_handle 0x%x\n",
		    rs->client_handle);
	}
#endif

	/* Get logical socket number and store in pcram_state_t */
	if ((ret = csx_MapLogSocket(rs->client_handle,
	    &map_log_socket)) != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_attach: "
		    "MapLogSocket failed %s (0x%x)\n",
		    cft.text, ret);
	}

	rs->sn = map_log_socket.PhySocket;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_attach: "
		    "MapLogSocket for socket %d\n", rs->sn);
	}
#endif

	/* Setup the event handler hi-level mutex */
	mutex_init(&rs->event_hilock, NULL, MUTEX_DRIVER,
	    *(client_reg.iblk_cookie));

	/* set up the mutex to protect the pcram_state_t */
	mutex_init(&rs->mutex, NULL, MUTEX_DRIVER, (void *)rs->soft_blk_cookie);

	/* strategy(): waiting for I/O to complete  */
	cv_init(&rs->condvar, NULL, CV_DRIVER, NULL);
	/* write(): waiting for I/O to complete  */
	cv_init(&rs->condvar_wr, NULL, CV_DRIVER, NULL);
	/* read(): waiting for I/O to complete  */
	cv_init(&rs->condvar_rd, NULL, CV_DRIVER, NULL);
	/* for DKIOCSTATE ioctl()  */
	cv_init(&rs->condvar_mediastate, NULL, CV_DRIVER, NULL);
	/* Init firstopenwait_cv */
	cv_init(&rs->firstopenwait_cv, NULL, CV_DRIVER, NULL);

	/* mutex to protect region lists */
	mutex_init(&rs->region_lock, NULL, MUTEX_DRIVER,
	    (void *)(rs->soft_blk_cookie));

	rs->flags |= PCRAM_DIDLOCKS;


	/*
	 * After the RequestSocketMask call,
	 * we can start receiving events
	 */
	sockmask.EventMask = (CS_EVENT_CARD_INSERTION |
	    CS_EVENT_CARD_REMOVAL);

	if ((ret = csx_RequestSocketMask(rs->client_handle,
	    &sockmask)) != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_attach: RequestSocketMask "
		    "failed %s (0x%x)\n", cft.text, ret);
		goto out;
	}

	rs->flags |= PCRAM_REQSOCKMASK;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT,
		    "pcram_attach: RequestSocketMask OK\n");
#endif

	/*
	 * Wait for minor node creation before continuing
	 */
	pcram_minor_wait(rs);

	/*
	 * Check to see if the card is inserted and if this
	 *	attach is triggered by an open, that open
	 *	will wait until pcram_card_insertion() is
	 *	completed
	 */
	/* XXX function return value ignored */
	(void) csx_GetStatus(rs->client_handle, &get_status);
	if (get_status.CardState & CS_EVENT_CARD_INSERTION) {
		if (!PCRAM_CARD_PRESENT(rs)) {
		mutex_enter(&rs->event_hilock);
		cv_wait(&rs->firstopenwait_cv, &rs->event_hilock);
		mutex_exit(&rs->event_hilock);
#ifdef	PCRAM_DEBUG
		if (!PCRAM_CARD_PRESENT(rs)) {
			cmn_err(CE_CONT, "pcram_attach:Card not found\n");
		} else {
			cmn_err(CE_CONT, "pcram_attach:Card found\n");
		}
#endif

		}
	}

	ddi_report_dev(dip);

	/*
	 * set a flag that pcram_open() can look at so that
	 * if this board doesn't make it all the way through
	 * pcram_attach(), we won't try to open it
	 */
	rs->flags |= PCRAM_ATTACHOK;

	return (DDI_SUCCESS);
	/* NOTREACHED */

out:
	(void) pcram_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}


static int
pcram_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance, ret;
	pcram_state_t	*rs;


	instance = ddi_get_instance(dip);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT,
		    "pcram_detach: instance %d cmd 0x%x\n",
		    instance, cmd);
#endif

	/* suspend */
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
		/* NOTREACHED */
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
		/* NOTREACHED */
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_detach: "
		    "could not get state structure "
		    "for instance %d.", instance);
		return (DDI_FAILURE);
		/* NOTREACHED */
	}

	/*
	 * Clear the PCRAM_ATTACHOK so that other layers of the code
	 *	will know that we're going away.
	 */
	rs->flags &= ~PCRAM_ATTACHOK;

	/*
	 * Call pcram_card_removal to do any final card cleanup
	 */
	(void) pcram_card_removal(rs);

	/*
	 * Release our socket mask - note that we can't do much
	 *	if we fail these calls other than to note that
	 *	the system will probably panic shortly.  Perhaps
	 *	we should fail the detach in the case where these
	 *	CS calls fail?
	 */
	if (rs->flags & PCRAM_REQSOCKMASK) {
		release_socket_mask_t rsm;
		if ((ret = csx_ReleaseSocketMask(rs->client_handle, &rsm))
		    != CS_SUCCESS) {
			error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_detach: Socket %d "
		    "ReleaseSocketMask failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		}
	}

	/*
	 * Deregister with Card Services - we will stop getting
	 *	events at this point.
	 */
	if (rs->flags & PCRAM_REGCLIENT) {
		if ((ret = csx_DeregisterClient(rs->client_handle))
		    != CS_SUCCESS) {
			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);

			cmn_err(CE_CONT, "pcram_detach: Socket %d "
			    "DeregisterClient failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
		}
	}

	if (rs->host_sp) {
		kmem_free(rs->host_sp, HOST_BUF_SIZE);
	}

	if (rs->hdrv_chars) {
		kmem_free(rs->hdrv_chars, sizeof (struct hd_char));
	}

	/* Free transfer list header */
	if (rs->blist) {
		freerbuf(rs->blist);
	}

	/* unregister the softinterrupt handler */
	if (rs->flags & PCRAM_SOFTINTROK) {
		ddi_remove_softintr(rs->softint_id);
	}

	/* free the various mutexii */
	if (rs->flags & PCRAM_DIDLOCKS) {
		mutex_destroy(&rs->event_hilock);
		mutex_destroy(&rs->region_lock);
		mutex_destroy(&rs->mutex);
		/* strategy(): waiting for I/O to complete  */
		cv_destroy(&rs->condvar);
		/* write(): waiting for I/O to complete  */
		cv_destroy(&rs->condvar_wr);
		/* read(): waiting for I/O to complete  */
		cv_destroy(&rs->condvar_rd);
		/* for DKIOCSTATE ioctl()  */
		cv_destroy(&rs->condvar_mediastate);
		/* Free firstopenwait_cv */
		cv_destroy(&rs->firstopenwait_cv);
	}

	ddi_soft_state_free(pcram_soft_state_p, instance);

	return (DDI_SUCCESS);
}


/*
 * pcram_getinfo()	this routine translates the dip
 *			info dev_t and vice versa.
 *
 *	Returns:	DDI_SUCCESS, if successful.
 *			DDI_FAILURE, if unsuccessful.
 */
/*ARGSUSED*/
static int
pcram_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
						void **result)
{
	int		error = DDI_SUCCESS;
	pcram_state_t	*rs;
	cs_ddi_info_t	cs_ddi_info;


	switch (cmd) {

		case DDI_INFO_DEVT2DEVINFO:
		case DDI_INFO_DEVT2INSTANCE:
		cs_ddi_info.Socket = PCRAM_SOCKET((dev_t)arg);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_getinfo: socket %d\n",
		    cs_ddi_info.Socket);
#endif

		cs_ddi_info.driver_name = pcram_name;
		if (csx_CS_DDI_Info(&cs_ddi_info) != CS_SUCCESS) {
			return (DDI_FAILURE);
			/* NOTREACHED */
		}

		switch (cmd) {
			case DDI_INFO_DEVT2DEVINFO:
			if (!(rs = ddi_get_soft_state(
			    pcram_soft_state_p,
			    cs_ddi_info.instance))) {
				*result = NULL;
			} else {
				*result = rs->dip;
			}
			break;

			case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)cs_ddi_info.instance;
			break;
		} /* switch */
		break;
		default:
		error = DDI_FAILURE;
		break;
	} /* switch */

	return (error);
}



static int
pcram_getinstance(dev_t devp)
{
	int		rval;
	cs_ddi_info_t	ddi_info;
	error2text_t	cft;

	ddi_info.Socket = PCRAM_SOCKET(devp);
	ddi_info.driver_name = pcram_name;
	if ((rval = csx_CS_DDI_Info(&ddi_info)) != CS_SUCCESS) {
		cft.item = rval;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_NOTE,
		    "pcram[%d]: csx_CS_DDI_Info failed - %s\n",
		    PCRAM_SOCKET(devp), cft.text);
		return (-1);
	}

	return (ddi_info.instance);
}


/*
 * User context (system call request)
 *
 *   Character Driver/Block Drivers:
 *
 *	pcram_open()
 *	pcram_close()
 *	pcram_prop_op()
 *	pcram_print()
 *
 *   Unique to character drivers:
 *
 *	pcram_read()
 *	pcram_write()
 *	pcram_ioctl()
 *	xxxxx_segmap()	( ddi_segmap )
 *	xxxxx_chpoll()	( nochpoll )
 */
/*ARGSUSED*/
static int
pcram_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	int		instance;
	int		err;
	pcram_state_t	*rs;
	get_status_t	get_status;

	/* get instance number */
	if ((instance = pcram_getinstance(*devp)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_open: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_open: "
		    "could not get state for instance %d\n",
		    instance);
		return (ENXIO);
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_open: socket %d "
		    "flag 0x%x otyp 0x%x\n", rs->sn, flag, otyp);
#endif

	mutex_enter(&rs->mutex);

	if (!(rs->flags & PCRAM_ATTACHOK)) {
		mutex_exit(&rs->mutex);
		return (ENXIO);
		/* NOTREACHED */
	}

	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->mutex);

		cft.item = err;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_open: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT,
		    "pcram_open: socket %d GetStatus returns:\n",
		    rs->sn);
		pcram_display_card_status(&get_status);
	}
#endif

	/*
	 * Check to see if the card is present.
	 *	If there is no card in the socket,
	 *	then return ENXIO.
	 */
	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION)) {

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_open: socket %d "
		    "ERROR: Found no memory card\n", rs->sn);
	}
#endif

		mutex_exit(&rs->mutex);
		return (ENXIO);
		/* NOTREACHED */
	}

	if (get_status.CardState & CS_EVENT_BATTERY_DEAD) {
		if (!rs->batter_dead_posted) {
			cmn_err(CE_WARN, "pcram_open: socket %d "
			    "Battery & Data integrity "
			    "is not guaranteed\n", rs->sn);
			/* Display once on the system console */
			rs->batter_dead_posted++;
		}
		if (flag & FWRITE) {
			mutex_exit(&rs->mutex);
			return (ENXIO);
			/* NOTREACHED */
		}
	}

	if (get_status.CardState & CS_EVENT_BATTERY_LOW) {
		if (!rs->batter_low_posted) {
			cmn_err(CE_WARN, "pcram_open: socket %d "
			    "Battery should be replaced; "
			    "Data is OK\n", rs->sn);
			/* Display once on the system console */
			rs->batter_low_posted++;
		}
	}

	/* Next check for read only file system */
	if ((flag & FWRITE) &&
	    (get_status.CardState & CS_EVENT_WRITE_PROTECT)) {
		mutex_exit(&rs->mutex);
		return (EROFS);
		/* NOTREACHED */
	}


	/*
	 * Only honor FEXCL.  If a regular open or a layered open
	 * is still outstanding on the device, the exclusive open
	 * must fail.
	 */
	if ((flag & FEXCL) && (rs->blk_open || rs->chr_open ||
	    rs->nlayered)) {
		mutex_exit(&rs->mutex);
		return (EAGAIN);
		/* NOTREACHED */
	}

	switch (otyp) {

		case OTYP_BLK:
			rs->blk_open = 1;
			break;

		case OTYP_CHR:
			rs->chr_open = 1;
			break;

		case OTYP_LYR:
			rs->nlayered++;
			break;

		default:
			mutex_exit(&rs->mutex);
			return (EINVAL);
			/* NOTREACHED */
	}

#ifdef  PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_open: default_size_flag=%d \n",
		    rs->default_size_flag);
	}
#endif


	/*
	 * For cards without attribute memory, probe the card to
	 * determine the memory size.
	 */

	err = 0;
	if (rs->default_size_flag) {

		/* Setup for default maximum size of 64MB */
		*rs->hdrv_chars = hdtypes;
		rs->card_size = MAX_CARD_SIZE;


		if ((rs->card_size = pcram_card_sizing(rs))
		    != UNRECOGNIZED_MEDIA) {
			rs->hdrv_chars->drv_ncyl =
			    GET_NCYL(rs->card_size,
			    rs->hdrv_chars->drv_nhead,
			    rs->hdrv_chars->drv_sec_size,
			    rs->hdrv_chars->drv_secptrack);
			/*
			 * Actual card size is determined
			 * so disable default_size_flag
			 */
			rs->default_size_flag = 0;
		} else {
			/*
			 * Found unregconized PCMCIA Static RAM media
			 * so treat it as an unlabeled memory card
			 * with a maximum size of 64MB (PCMCIA 2.0
			 * specification)
			 */
			cmn_err(CE_NOTE, "pcram: socket %d - "
			    "Unregconized PCMCIA Static RAM media",
			    rs->sn);
				err = ENXIO;
		}
	}
	mutex_exit(&rs->mutex);
	return (err);
}



/*ARGSUSED*/
static int
pcram_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int		instance;
	pcram_state_t	*rs;

	if ((instance = pcram_getinstance(dev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_close: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_close: "
		    "could not get state for instance %d\n",
		    instance);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_close: socket %d "
		    "flag 0x%x otyp 0x%x\n", rs->sn, flag, otyp);
#endif

	mutex_enter(&rs->mutex);

	switch (otyp) {

		case OTYP_BLK:
			rs->blk_open = 0;
		break;

		case OTYP_CHR:
			rs->chr_open = 0;
			break;

		case OTYP_LYR:
			rs->nlayered--;
			break;

		default:
			mutex_exit(&rs->mutex);
			return (EINVAL);
			/* NOTREACHED */
	}

	if (rs->blk_open || rs->chr_open || rs->nlayered) {
		/* not done yet */
		mutex_exit(&rs->mutex);
		return (0);
		/* NOTREACHED */
	}

	/*
	 * Continueing to return EIO if the card is ejected
	 * while it is mounted until the LAST layered close
	 * is called
	 */
	if (rs->nlayered == 0) {
#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_close: "
		    "Reset ejected_while_mounting flag\n");
	}
#endif
		rs->ejected_while_mounting = 0;
	}

	mutex_exit(&rs->mutex);
	return (0);
}



static int
pcram_print(dev_t dev, char *str)
{
	int		instance;
	pcram_state_t	*rs;


	if ((instance = pcram_getinstance(dev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_print: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_print: "
		"could not get state for instance %d.", instance);
		return (ENXIO);
		/* NOTREACHED */
	}

	cmn_err(CE_NOTE, "pcram_print: socket %d %s", rs->sn, str);
	return (0);
}



/*
 * Character driver routines
 *	pcram_read()
 *	pcram_write()
 */
/*ARGSUSED*/
static int
pcram_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int		instance;
	int		error;
	int		nbytes;
	int		offset, next_offset;
	int		remainder_wsize;
	int		rval;
	int		err;
	pcram_state_t	*rs;
	get_status_t	get_status;

	if ((instance = pcram_getinstance(dev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_read: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_read: "
		    "could not get state for instance %d.",
		    instance);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_read: socket %d\n", rs->sn);
#endif

	mutex_enter(&rs->mutex);

	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle,
	    &get_status)) != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->mutex);

		cft.item = err;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_read: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_read: socket %d "
		    "GetStatus returns:\n", rs->sn);
		pcram_display_card_status(&get_status);
	}
#endif

	/*
	 * Check to see if the card is present.
	 *	If the memory card has been removed or
	 *	was ever removed, return an I/O error (EIO)
	 *	not "No such device or address" (EMXIO).
	 *
	 * Continueing to return EIO if the card is ejected
	 * while it is mounted until the LAST layered close
	 * is called
	 */
	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION) ||
	    rs->ejected_while_mounting) {
		if (!rs->card_eject_posted) {
			/* XXX WARNING - card is ejected */
			rs->card_eject_posted++;
			rs->ejected_while_mounting = 1;
			cmn_err(CE_WARN, "pcram: socket%d "
			    "Card is ejected & "
			    "Data integrity is not guaranteed",
			    rs->sn);
		}
		mutex_exit(&rs->mutex);
		return (EIO);
		/* NOTREACHED */
	}

	mutex_exit(&rs->mutex);

	/*
	 * Wait for the current request to finish.  We can
	 * safely release the mutex once we complete the write
	 * operation, because anyone else calling pcram_read
	 * will wait here until we release it with a cv_signal.
	 */
	mutex_enter(&rs->mutex);
		while (rs->busy_rd == 1) {
			cv_wait(&rs->condvar_rd, &rs->mutex);
		}
		rs->busy_rd = 1;
	mutex_exit(&rs->mutex);

	if (uiop->uio_offset >= rs->card_size) {
		rval = ENOSPC;
		goto out;
	}

	offset = uiop->uio_offset;
	nbytes = min(uiop->uio_resid, rs->card_size - uiop->uio_offset);

	while (nbytes > 0) {
		int copybytes;

		next_offset = update_mapmempage(rs, offset);
		if (next_offset < 0) {
			/* something wrong with MapMemPage function */
			rval = EFAULT;
			goto out;
		}

		remainder_wsize = offset % rs->win_size;
		copybytes = min(rs->win_size - remainder_wsize, nbytes);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_SIZE) {
		if (nbytes > (rs->win_size-remainder_wsize))
			cmn_err(CE_CONT, "pcram_read: socket %d - "
			    "READ: size not on window boundary\n"
			    "\toffset 0x%x, rs->win_size 0x%x\n"
			    "\tnbytes 0x%x, remainder_wsize 0x%x\n",
			    rs->sn, offset, (int)rs->win_size,
			    nbytes, remainder_wsize);
	}
#endif

		if (PCRAM_CARD_PRESENT(rs)) {
			/*
			 * Transfer block in between the two windows
			 */
			uchar_t		*pbuf;

			/*
			 * We cannot use uiomoveto xfer directly
			 * between pcram device to user area because
			 * 64 byte * block xfers may be done in copyout.
			 * PCMCIA memory cards are cannot be read
			 * thru block move instructions.
			 *	just allocate pbuf
			 *	buffer and to use csx_RepGet8()
			 *	call to transfer from the
			 *	memory card to pbuf then use
			 *	uiomove() to move from pbuf
			 *	to the buffer(s) described by
			 *	uiop structure.
			 */
			pbuf = kmem_zalloc(copybytes, KM_SLEEP);
			csx_RepGet8(
				/* Card access handle */
			    rs->access_handle,
				/* base dest addr */
			    (uchar_t *)pbuf,
				/* card window offset */
			    (uint32_t)remainder_wsize,
				/* num_bytes xfer */
			    copybytes,
				/* flag */
			    DDI_DEV_AUTOINCR);
			error = uiomove((caddr_t)pbuf,
			    copybytes, UIO_READ, uiop);

			/* now free csbuf */
			kmem_free(pbuf, copybytes);

			if (error != 0) {
				rval = EFAULT;
				goto out;
			}

			nbytes -= copybytes;
			offset += copybytes;
		} else {
			/*
			 * stop to read the card when
			 * there is a card removal event
			 */
			rval = EFAULT;
			goto out;
		}
	} /* while */

	rval = 0;

out:
	mutex_enter(&rs->mutex);
	/*
	 * End of read operation, release the
	 * cv_wait() for the next thread
	 */
	rs->busy_rd = 0;
	cv_signal(&rs->condvar_rd);
	mutex_exit(&rs->mutex);

	return (rval);
}


/*ARGSUSED*/
static int
pcram_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int		instance;
	int		error;
	int		nbytes;
	int		offset;
	int		rval;
	int		err;
	pcram_state_t	*rs;
	get_status_t	get_status;


	if ((instance = pcram_getinstance(dev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_write: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_write: "
		    "could not get state for instance %d.",
		    instance);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_write: socket %d\n", rs->sn);
#endif

	mutex_enter(&rs->mutex);

	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->mutex);

		cft.item = err;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_write: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		return (ENXIO);
		/* NOTREACHED */
	}


	/*
	 * Check to see if the card is present.
	 *	If the memory card has been removed or
	 *	was ever removed, return an I/O error (EIO)
	 *	not "No such device or address" (EMXIO).
	 *
	 * Continueing to return EIO if the card is ejected
	 * while it is mounted until the LAST layered close
	 * is called
	 */
	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION) ||
	    rs->ejected_while_mounting) {
		if (!rs->card_eject_posted) {
			/* XXX WARNING - card is ejected */
			rs->card_eject_posted++;
			rs->ejected_while_mounting = 1;
			cmn_err(CE_WARN, "pcram: socket%d "
			    "Card is ejected & "
			    "Data integrity is not guaranteed",
			    rs->sn);
		}
		mutex_exit(&rs->mutex);
		return (EIO);
		/* NOTREACHED */
	}

	mutex_exit(&rs->mutex);

	/*
	 * Wait for the current request to finish.  We can
	 * safely release the mutex once we complete the write
	 * operation, because anyone else calling pcram_write
	 * will wait here until we release it with a cv_signal.
	 */
	mutex_enter(&rs->mutex);
		while (rs->busy_wr == 1) {
			cv_wait(&rs->condvar_wr, &rs->mutex);
		}
		rs->busy_wr = 1;
	mutex_exit(&rs->mutex);

	if (uiop->uio_offset >= rs->card_size) {
		rval = ENOSPC;
		goto out;
	}

	/* Save offset and byte count from uiop structure */
	offset = uiop->uio_offset;
	nbytes = min(uiop->uio_resid, rs->card_size-uiop->uio_offset);

	/*
	 * Start to transfer 1KB data to kernel buffer at a time
	 * The 1MB window offset is handled in card_byte_wr()
	 */

	while (nbytes > 0) {
		int	copybytes;
		int	next_offset;
		int	remainder_wsize;


		next_offset = update_mapmempage(rs, offset);
		if (next_offset < 0) {
			/* something wrong with MapMemPage function */
			rval = EFAULT;
			goto out;
		}

		remainder_wsize = offset % rs->win_size;
		copybytes = min(rs->win_size - remainder_wsize, nbytes);
		copybytes = min(copybytes, HOST_BUF_SIZE);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_SIZE) {
		if (nbytes > (rs->win_size-remainder_wsize))
			cmn_err(CE_CONT, "pcram_write: socket %d - "
			    "WRITE: size not on window boundary\n"
			    "\toffset 0x%x, rs->win_size 0x%x\n"
			    "\tnbytes 0x%x, remainder_wsize 0x%x\n",
			    rs->sn, offset, (int)rs->win_size,
			    nbytes, remainder_wsize);
	}
#endif

		if (PCRAM_CARD_PRESENT(rs)) {
			/*
			 *  Transfer block size is in between
			 *  the two windows
			 */
			error = uiomove(rs->host_sp, copybytes,
			    UIO_WRITE, uiop);
			if (error != 0) {
				rval = EFAULT;
				goto out;
			}

			mutex_enter(&rs->mutex);
			card_byte_wr(rs, copybytes, remainder_wsize);
			mutex_exit(&rs->mutex);

			nbytes -= copybytes;
			offset += copybytes;
		} else {
			/*
			 * stop to write to the card when
			 * there is a card removal event
			 */
			rval = EFAULT;
			goto out;
		}
	} /* while */

	rval = 0;

out:
	mutex_enter(&rs->mutex);
	/*
	 * End of write operation, release the
	 * cv_wait() for the next thread
	 */
	rs->busy_wr = 0;
	cv_signal(&rs->condvar_wr);
	mutex_exit(&rs->mutex);

	return (rval);

}



/*ARGSUSED*/
static int
pcram_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
							int *rvalp)
{
	int			i;
	int			instance;
	int			err;
	int			fdchange;
	daddr_t			nblks;
	struct	dk_geom		dkg;	    /* disk geometry */
	struct	vtoc		vtoc;
	struct	dk_cinfo	dkc;	    /* disk controller info */
	struct	pcmm_info	pcmminfo;   /* memory media type */
	struct	fd_drive	drvchar;    /* supporting eject(1) */
	struct	dk_map		dkmap[NDKMAP];
	pcram_state_t		*rs;
	enum dkio_state		state;
	get_status_t		get_status;


	if ((instance = pcram_getinstance(dev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_ioctl: pcram_getinfo failed\n");
		return (ENXIO);
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_ioctl: "
		    "could not get state for instance %d.",
		    instance);
		return (ENXIO);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_ioctl: socket %d "
		    "cmd 0x%x arg 0x%lx mode 0x%x\n",
		    rs->sn, cmd, arg, mode);
	}
#endif


	switch (cmd) {

	case DKIOCEJECT:
		/*
		 * Since we do not have hardware support for ejecting
		 * a memory card, we must not support the generic eject
		 * ioctl (DKIOCEJECT) which is used for eject(1) command
		 * because it leads the user to expect behavior that is
		 * not present.
		 */
		return (ENOSYS);
		/* NOTREACHED */

	case DKIOCGGEOM:
		/*
		 * newfs does this first
		 *	return dk_geom structure
		 */
		if (!rs->default_size_flag) {
			/*
			 * If the card is built with DOS_BPB or
			 *	Solaris VTOC or CIS info.
			 *	we just return the disk geometry
			 *	information
			 */
			bzero(&dkg, sizeof (struct dk_geom));
			dkg.dkg_ncyl  = rs->hdrv_chars->drv_ncyl;
			dkg.dkg_nhead = rs->hdrv_chars->drv_nhead;
			dkg.dkg_nsect = rs->hdrv_chars->drv_secptrack;
			dkg.dkg_pcyl  = rs->hdrv_chars->drv_ncyl;
			if (ddi_copyout(&dkg, (void *)arg,
			    sizeof (struct dk_geom), mode) != 0) {
				return (EFAULT);
				/* NOTREACHED */
			}
			return (0);
		} else {
			/*
			 * Return error when we can not find
			 *	the actual card size.
			 */
			return (EFAULT);
			/* NOTREACHED */
		}
		/* NOTREACHED */

	case DKIOCGVTOC:
		/*
		 * newfs does this second
		 *	return vtoc structure. 1 partion.
		 */
		bzero(&vtoc, sizeof (struct vtoc));
		vtoc.v_sanity = VTOC_SANE;
		vtoc.v_version = V_VERSION;
		bcopy("pccard", vtoc.v_volume, 7);
		vtoc.v_sectorsz = DEV_BSIZE;
		vtoc.v_nparts = 1;
		vtoc.v_part[0].p_tag = V_UNASSIGNED;
		vtoc.v_part[0].p_flag = V_UNMNT;
		vtoc.v_part[0].p_start = (daddr_t)0;
		vtoc.v_part[0].p_size = rs->card_size / DEV_BSIZE;
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct vtoc32 vtoc32;

			vtoctovtoc32(vtoc, vtoc32);
			if (ddi_copyout(&vtoc32, (void *)arg,
			    sizeof (struct vtoc32), mode))
				return (EFAULT);
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&vtoc, (void *)arg,
			    sizeof (struct vtoc), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&vtoc, (void *)arg,
		    sizeof (struct vtoc), mode) != 0)
			return (EFAULT);

#endif /* _MULTI_DATAMODEL */
		return (0);
		/* NOTREACHED */

	case DKIOCINFO:
		/*
		 * newfs does this third
		 *	return dk_cinfo structure.
		 */
		bzero(&dkc, sizeof (struct dk_cinfo));

		/*
		 * SunVTS uses PCRAM_DKC_CNAME "pcram"
		 *	for checking if it is a pcram controller
		 */
		(void) strcpy(dkc.dki_cname, PCRAM_DKC_CNAME);
		dkc.dki_ctype = DKC_PCMCIA_MEM;

		/*
		 * For pseudo floppy disk setup (pcfs file system)
		 *	dkc.dki_flags = DKI_PCMCIA_PFD;
		 */
		dkc.dki_flags = rs->isit_pseudofloppy;

		(void) strcpy(dkc.dki_dname, PCRAM_DKC_DNAME);

		/*
		 * volmgt will use this dki_unit as a PCMCIA
		 *	socket info. during a static mode
		 *	During a dynamic mode (physically
		 *	remove and insert a card), the socket
		 *	info. is from PCMCIA User Daemon
		 */
		dkc.dki_unit = (uint32_t)rs->sn;

		dkc.dki_maxtransfer = 1;

		if (ddi_copyout(&dkc, (void *)arg,
		    sizeof (struct dk_cinfo), mode) != 0) {
			return (EFAULT);
			/* NOTREACHED */
		}
		return (0);
		/* NOTREACHED */

	case DKIOCGAPART:
		nblks = rs->hdrv_chars->drv_nhead *
		    rs->hdrv_chars->drv_secptrack;
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct dk_map32 dkmap32[NDKMAP];

			/*
			 * XXX - support only one partition now
			 * should be NDKMAP later
			 */
			for (i = 0; i < 1; i++) {
				dkmap32[i].dkl_cylno = (daddr_t)0;
				dkmap32[i].dkl_nblk = nblks;
			}
			i = NDKMAP * sizeof (struct dk_map32);
			if (ddi_copyout(&dkmap32, (void *)arg, i, mode))
				return (EFAULT);
		}
		break;
		case DDI_MODEL_NONE:
			for (i = 0; i < 1; i++) {
				dkmap[i].dkl_cylno = (daddr_t)0;
				dkmap[i].dkl_nblk = nblks;
			}
			i = NDKMAP * sizeof (struct dk_map);
			if (ddi_copyout(&dkmap, (void *)arg, i, mode))
				return (EFAULT);
		}
#else /* ! _MULTI_DATAMODEL */
		for (i = 0; i < 1; i++) {
			dkmap[i].dkl_cylno = (daddr_t)0;
			dkmap[i].dkl_nblk = nblks;
		}
		i = NDKMAP * sizeof (struct dk_map);
		if (ddi_copyout(&dkmap, (void *)arg, i, mode))
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		return (0);

	case DKIOCSTATE:
		if (ddi_copyin((void *)arg, &state, sizeof (int), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}

		/*
		 * This function is used by the volume management
		 * to check the memory card state
		 */
		if (err = pcram_check_media(rs, state)) {
			return (err);
			/* NOTREACHED */
		}

		if (ddi_copyout(&rs->media_state, (void *)arg,
		    sizeof (int), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}
		return (0);
		/* NOTREACHED */

	case DKIOCSVTOC:
		/*
		 * fdformat(1) uses this ioctl() to ask the driver
		 * to construct the disk label.
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {

			struct vtoc32 vtoc32;

			if (ddi_copyin((void *)arg, &vtoc32,
			    sizeof (struct vtoc32), mode))
				return (EFAULT);
			vtoc32tovtoc(vtoc32, vtoc);
			break;
		}

		case DDI_MODEL_NONE:
			if (ddi_copyin((void *)arg, &vtoc,
			    sizeof (struct vtoc), mode))
				return (EFAULT);
			break;
		}
#else /* _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &vtoc, sizeof (struct vtoc), mode))
			return (EFAULT);

#endif /* _MULTI_DATAMODEL */

		if ((err = pcram_build_label_vtoc(rs, &vtoc)) != 0) {
			return (err);
			/* NOTREACHED */
		}

		pcram_write_label(rs);
		return (0);
		/* NOTREACHED */

	case DKIOCREMOVABLE:
		/*
		 * Supporting volmgt by returning a constant
		 *	since PCMCIA is a removable media.
		 *	Refer to PSARC/1996/004.
		 */
		i = 1;
		if (ddi_copyout(&i, (void *)arg, sizeof (int), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}
		return (0);
		/* NOTREACHED */

	case PCRAM_GETMEDIA:
		/*
		 * Support memory media type of SRAM/Masked ROM/DRAM
		 */
		mutex_enter(&rs->mutex);
		pcmminfo.pcmm_type =  PCMM_TYPE_RAM;
		mutex_exit(&rs->mutex);

		if (ddi_copyout(&pcmminfo, (void *)arg,
		    sizeof (struct pcmm_info), mode) != 0) {
			return (EFAULT);
			/* NOTREACHED */
		}
		return (0);
		/* NOTREACHED */

	case PCRAM_PROBESIZE:
		/*
		 *  After getting an error return from calling
		 *	DKIOCGGEOM ioctl, fdformat(1) *must* use
		 *	this ioctl() to get get the memory card size
		 *	before formatting the memory card.  This
		 *	allows the driver to do some destructive
		 *	write and verify operation (backup data
		 *	before writing to the card).
		 *
		 * If the card is built with DOS_BPB or Solaris VTOC
		 *	or CIS info., we do not need to probe card
		 *	size.  If the card is built with a default
		 *	size of 64MB then we need to probe the actual
		 *	card size
		 */
		if (!rs->default_size_flag) {
#ifdef	PCRAM_DEBUG
			if (pcram_debug & PCRAM_DEBUG_CIS) {
				cmn_err(CE_CONT, "pcram_ioctl: socket %d\n"
				"\tPCRAM_PROBESIZE: card size "
				"is already\n\t\tdetermined from "
				"DOS_BPB, VTOC, or CIS\n", rs->sn);
			}
#endif
			bzero(&dkg, sizeof (struct dk_geom));
			dkg.dkg_ncyl  = rs->hdrv_chars->drv_ncyl;
			dkg.dkg_nhead = rs->hdrv_chars->drv_nhead;
			dkg.dkg_nsect = rs->hdrv_chars->drv_secptrack;
			dkg.dkg_pcyl  = rs->hdrv_chars->drv_ncyl;
			if (ddi_copyout(&dkg, (void *)arg,
			    sizeof (struct dk_geom), mode) != 0) {
				return (EFAULT);
				/* NOTREACHED */
			}
			return (0);
			/* NOTREACHED */
		}

		mutex_enter(&rs->mutex);
		/* Setup for default maximum size of 64MB */
		*rs->hdrv_chars = hdtypes;
		rs->card_size = MAX_CARD_SIZE;


		/*
		 * Do a CS call to see if the card is present
		 */
		if ((err = csx_GetStatus(rs->client_handle, &get_status))
		    != CS_SUCCESS) {
			error2text_t cft;

			mutex_exit(&rs->mutex);
			cft.item = err;
			(void) csx_Error2Text(&cft);
			cmn_err(CE_CONT, "pcram_ioctl: socket %d "
			    "GetStatus failed %s (0x%x)\n",
			    rs->sn, cft.text, err);
			return (ENXIO);
			/* NOTREACHED */
		}

		if (get_status.CardState & CS_EVENT_WRITE_PROTECT) {
			err = EROFS;
		} else if ((rs->card_size = pcram_card_sizing(rs))
		    != UNRECOGNIZED_MEDIA) {
			rs->hdrv_chars->drv_ncyl =
			    GET_NCYL(rs->card_size,
			    rs->hdrv_chars->drv_nhead,
			    rs->hdrv_chars->drv_sec_size,
			    rs->hdrv_chars->drv_secptrack);
			/*
			 * Actual card size is determined
			 * so disable default_size_flag
			 */
			rs->default_size_flag = 0;
			err = 0;
		} else {
			/*
			 * Found unregconized PCMCIA Static RAM media
			 * so treat it as an unlabeled memory card
			 * with a maximum size of 64MB (PCMCIA 2.0
			 * specification)
			 */
			cmn_err(CE_NOTE, "pcram: socket %d - "
			    "Unregconized PCMCIA Static RAM media",
			    rs->sn);
			err = ENXIO;
		}

		mutex_exit(&rs->mutex);

		bzero(&dkg, sizeof (struct dk_geom));
		dkg.dkg_ncyl  = rs->hdrv_chars->drv_ncyl;
		dkg.dkg_nhead = rs->hdrv_chars->drv_nhead;
		dkg.dkg_nsect = rs->hdrv_chars->drv_secptrack;
		dkg.dkg_pcyl  = rs->hdrv_chars->drv_ncyl;
		if (ddi_copyout(&dkg, (void *)arg,
		    sizeof (struct dk_geom), mode) != 0) {
			return (EFAULT);
			/* NOTREACHED */
		}

		return (err);
		/* NOTREACHED */

	case FDGETDRIVECHAR:
		/* supporting eject(1) command */
		if (ddi_copyin((void *)arg, &drvchar,
		    sizeof (struct fd_drive), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}
		drvchar.fdd_ejectable = 0;	/* manually ejectable */
		drvchar.fdd_flags = 0;		/* not FDD_POLLABLE   */
		if (ddi_copyout(&drvchar, (void *)arg,
		    sizeof (struct fd_drive), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}
		return (0);
		/* NOTREACHED */

	case FDGETCHANGE:
		/*
		 * supporting volcheck(1) command
		 *
		 * FDGC_HISTORY    disk has changed since last i/o
		 * FDGC_CURRENT    current state of disk change
		 * FDGC_CURWPROT   current state of write protect
		 * FDGC_DETECTED   previous state of DISK CHANGE
		 *
		 */
		if (ddi_copyin((void *)arg, &fdchange, sizeof (int), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}

		/* GetStatus */
		if ((err = csx_GetStatus(rs->client_handle, &get_status))
		    != CS_SUCCESS) {
			error2text_t cft;

			mutex_exit(&rs->mutex);
			cft.item = err;
			(void) csx_Error2Text(&cft);
			cmn_err(CE_CONT, "pcram_ioctl: FDGETCHANGE - "
			    "socket %d GetStatus failed %s (0x%x)\n",
			    rs->sn, cft.text, err);
			return (ENXIO);
			/* NOTREACHED */
		}

		/*
		 * See eject.c or fdformat.c for bit definition
		 */
		if (get_status.CardState & CS_EVENT_CARD_INSERTION) {
			/* Simulating - floppy is present */
			fdchange &= ~FDGC_CURRENT;
			if (get_status.CardState &
			    CS_EVENT_WRITE_PROTECT) {
				/*
				 * Simulating
				 *	floppy is write protected
				 */
				fdchange |= FDGC_CURWPROT;
			} else {
				/*
				 * Simulating
				 *	floppy is NOT write protected
				 */
				fdchange &= ~FDGC_CURWPROT;
			}
		} else {
			/* Simulating - floppy is NOT present */
			fdchange |= FDGC_CURRENT;
		}

		if (ddi_copyout(&fdchange, (void *)arg, sizeof (int), mode)) {
			return (EFAULT);
			/* NOTREACHED */
		}

		return (0);
		/* NOTREACHED */

	default:
		return (ENOTTY);
		/* NOTREACHED */
	}
}



/*
 *  pcram_prop_op() - Property Management
 *
 *  All block drivers must support the "Nblocks" property,
 *  and all character drivers must support the "size" property.
 *  Since we support hot plugging for many different memory
 *  card size and the Nblocks and the size property are changed
 *  dynamically, so these property should be maintained by the
 *  driver.
 */
static int
pcram_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
		int mod_flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance;
	pcram_state_t	*rs;
	uint64_t	size64;

	/*
	 * Our dynamic properties are all device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_size with the size information, otherwise the
	 * request is passed to ddi_prop_op.
	 */
	if (dev == DDI_DEV_T_ANY) {
pass:		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	} else {
		if ((instance = pcram_getinstance(dev)) == -1) {
			cmn_err(CE_NOTE, "pcram_prop_op: "
			    "pcram_getinfo failed\n");
			goto pass;
		}

		rs = ddi_get_soft_state(pcram_soft_state_p, instance);
		if (rs == NULL) {
			cmn_err(CE_NOTE, "pcram_prop_op: "
			    "no state for instance %d", instance);
			goto pass;
		}

		/* get size in bytes */
		size64 = (uint_t)rs->card_size;
		return (ddi_prop_op_size(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, size64));
	}
}


/*
 * Block driver routines
 *	pcram_strategy()
 *	pcram_start()
 */
static int
pcram_strategy(struct buf *bp)
{
	int		instance;
	int		err;
	int		offset = bp->b_blkno * DEV_BSIZE;
	pcram_state_t	*rs;
	get_status_t	get_status;


	if ((instance = pcram_getinstance(bp->b_edev)) == -1) {
		cmn_err(CE_NOTE,
		    "pcram_strategy: pcram_getinfo failed\n");
		err = ENXIO;
		goto out;
	}

	rs = ddi_get_soft_state(pcram_soft_state_p, instance);
	if (rs == NULL) {
		cmn_err(CE_NOTE, "pcram_strategy: "
		    "could not get state for instance %d.",
		    instance);
		err = ENXIO;
		goto out;
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_strategy: socket %d\n", rs->sn);
#endif

	mutex_enter(&rs->mutex);

	/* Do a CS call to see if the card is present */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->mutex);
		cft.item = err;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_strategy: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		err = ENXIO;
		goto out;
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_strategy: socket %d "
		    "GetStatus returns:\n", rs->sn);
		pcram_display_card_status(&get_status);
	}
#endif

	/*
	 * Check to see if the card is present.
	 *	If the memory card has been removed or
	 *	was ever removed, return an I/O error (EIO)
	 *	not "No such device or address" (EMXIO).
	 *
	 * Continueing to return EIO if the card is ejected
	 * while it is mounted until the LAST layered close
	 * is called
	 */
	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION) ||
	    rs->ejected_while_mounting) {
		if (!rs->card_eject_posted) {
			/* XXX WARNING - card is ejected */
			rs->card_eject_posted++;
			rs->ejected_while_mounting = 1;
			cmn_err(CE_WARN, "pcram: socket%d "
		"Card is ejected & Data integrity is not guaranteed",
			    rs->sn);
		}
		mutex_exit(&rs->mutex);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_strategy: socket %d - ERROR: "
		    "Found no memory card\n", rs->sn);
	}
#endif

		err = EIO;
		goto out;
	}

	mutex_exit(&rs->mutex);

	/*
	 * Do not need the mutex around rs->card_size, since it
	 * will not change until detach/attach.
	 *
	 * XXXX: Is it still true for PCMCIA memory card driver?
	 * XXX Was this the cause of a tar causing a panic on too
	 *	small a card?
	 */
	if (offset >= rs->card_size) {
		err = ENOSPC;
		goto out;
	}

	/*
	 * Wait for the current request to finish.  We can safely
	 * release the mutex once we complete the write operation,
	 * because anyone else calling pcram_strategy will wait here
	 * until we release it with a cv_signal.
	 */
	mutex_enter(&rs->mutex);

	while (rs->busy == 1) {
		cv_wait(&rs->condvar, &rs->mutex);
	}

	rs->busy = 1;

	bp_mapin(bp);

	if (rs->blist->av_forw == NULL) {
		/* nothing on queue */
		bp->av_forw = NULL;
		bp->av_back = NULL;
		rs->blist->av_forw = bp;
		rs->blist->av_back = bp;
		/* start it */
		pcram_start(rs);
	} else {
		/* put on work list */
		bp->av_forw = NULL;
		rs->blist->av_back->av_forw = bp;
		rs->blist->av_back = bp;
		rs->busy = 0;
		cv_signal(&rs->condvar);
	}

	mutex_exit(&rs->mutex);
	return (0);

out:
	bioerror(bp, err);
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return (0);
}



static void
pcram_start(pcram_state_t *rs)
{

	int		offset;
	int		nbytes, origbytes;
	int		next_offset;
	int		remainder_wsize;
	caddr_t		buf_addr;
	struct	buf	*bp;


#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_start: socket %d\n", rs->sn);
#endif

	bp = rs->blist->av_forw;
	offset = bp->b_blkno * DEV_BSIZE;
	nbytes = min(bp->b_bcount, rs->card_size-offset);
	buf_addr = bp->b_un.b_addr;
	origbytes = nbytes;	/* save the original byte count */

	while (nbytes > 0) {
		int copybytes;

		next_offset = update_mapmempage(rs, offset);
		if (next_offset < 0) {
			/* something failed so abort */
			bp->b_error = EIO;
			break;
		}

		/* get partial block size if not on window boundary */
		remainder_wsize = offset % rs->win_size;
		copybytes = min(nbytes, rs->win_size - remainder_wsize);


#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_SIZE) {
		if (nbytes > (rs->win_size-remainder_wsize)) {
			cmn_err(CE_CONT, "pcram_start: socket %d - "
			    "%s: size not on window boundary\n"
			    "\toffset 0x%x, rs->win_size 0x%x\n"
			    "\tnbytes 0x%x, remainder_wsize 0x%x\n",
			    rs->sn,
			    (bp->b_flags & B_READ) ?
			    "READ" : "WRITE",
			    offset, (int)rs->win_size,
			    nbytes, remainder_wsize);
		}
	}
#endif

		if (bp->b_flags & B_READ) {
			/* Read direct from PC Card memory  */
			csx_RepGet8(/* Card access handle */
			    rs->access_handle,
				/* base dest addr */
			    (uchar_t *)buf_addr,
				/* card window offset */
			    (uint32_t)remainder_wsize,
				/* num_bytes xfer */
			    copybytes,
				/* flag */
			    DDI_DEV_AUTOINCR);

		} else {	/*  WRITE operation  */
			/*
			 * Start to transfer 1KB data
			 * to kernel buffer at a time
			 */

			copybytes = min(copybytes, HOST_BUF_SIZE);
			/*
			 * Update PC Card memory from the kernel buffer
			 */
			bcopy(buf_addr, rs->host_sp, copybytes);
			/*
			 * does not need mutex because it is already
			 * handled in pcram_strategy and pcram_softintr
			 */
			card_byte_wr(rs, copybytes, remainder_wsize);
		}
		nbytes -= copybytes;
		buf_addr += copybytes;
		offset += copybytes;

		if (!PCRAM_CARD_PRESENT(rs)) {
			/* stop when there is a card removal event */
			bp->b_error = EIO;
			break;
		}

	}  /* while (nbytes) */

	bp->b_resid = bp->b_bcount - origbytes;

	ddi_trigger_softintr(rs->softint_id);

}



/*
 * Software Interrupt Handler
 *	pcram_softintr()
 */
static uint32_t
pcram_softintr(pcram_state_t *rs)
{
	struct buf	*bp;


#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE)
		cmn_err(CE_CONT, "pcram_softintr: socket %d\n", rs->sn);
#endif

	if (!(rs->flags & PCRAM_ATTACHOK)) {
		return (DDI_INTR_UNCLAIMED);
	}

	mutex_enter(&rs->mutex);

	if (rs->busy) {
		/* got work to do */
		bp = rs->blist->av_forw;
		rs->blist->av_forw = bp->av_forw;
		if (rs->blist->av_forw != NULL) {
			pcram_start(rs);
		} else {
			rs->busy = 0;
			/*
			 * End of write operation, release the
			 * cv_wait() for the next thread
			 */
			cv_signal(&rs->condvar);
		}
		biodone(bp);
	}  /* rs->busy */

	mutex_exit(&rs->mutex);

	return (DDI_INTR_CLAIMED);
	/* NOTREACHED */
}



/*
 *  SPARCstation-2 CACHE+ bug
 *
 *  bcopy() with double-word write in SS2 machine only
 *  supports only word acknowledge.  The DoRight PCMCIA
 *  ASIC is a 16-bit device so it will not work correctly
 *  during a write from SS2 host to the PCMCIA memory card.
 *  Therefore we have to write *one* byte at a time.
 *  In order to avoid to have two version of the driver
 *  for SS2 and other platforms, we can use the same
 *  byte write mechanism for all platform.
 *
 *  bcopy() is commonly used in pcram_start and pcram_strategy.
 *
 *  There is no major performance impact between
 *  using bcopy() for writing to card and card_byte_wr().
 *
 *  Using double buffer write to transfer data from host
 *  memory (allocate 1KB) to the memory card.
 *
 */
static void
card_byte_wr(pcram_state_t *rs, int xfer_size, int offset)
{
	int 	i;
	uint32_t 	cardoffset = offset;
	uchar_t	*hostmempt;

	hostmempt = (uchar_t *)(rs->host_sp);
	for (i = 0; i < xfer_size; i++) {
		if (PCRAM_CARD_PRESENT(rs)) {
			if (rs->card_event & PCRAM_WRITE_PROTECT) {
				if (!rs->wp_posted) {
					rs->wp_posted++;
					cmn_err(CE_WARN, "pcram: socket%d "
					    "Write-Protect is enabled",
					    rs->sn);
				}
				/*
				 * stop writing when
				 *	write-protect is enabled
				 */
				break;
			} else {
				csx_Put8(rs->access_handle,
				    cardoffset, *hostmempt);
				hostmempt++;
				cardoffset++;
			}
		} else {
			/*
			 * stop to write to the card when
			 * there is a card removal event
			 */
			break;
		}
	}
}



/*
 * Updating window size
 */
static int
update_mapmempage(pcram_state_t *rs, int offset)
{

	int		ret;
	int		i;
	int		err;
	map_mem_page_t	map_mem_page;
	get_status_t	get_status;


	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = err;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "update_mapmempage: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		/* Let caller knows that there is some thing wrong */
		return (-1);
		/* NOTREACHED */
	}

	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION)) {
#ifdef	PCRAM_DEBUG
	cmn_err(CE_CONT, "update_mapmempage: "
	    "\tFound no memory card in socket %d\n", rs->sn);
#endif
		/* Let caller knows that there is no card */
		return (-1);
		/* NOTREACHED */
	}


	/*
	 * Do following setup AFTER checking if card is inserted
	 * or we will get "zero divide trap panic"
	 */

	/* We do not support page mode */
	map_mem_page.Page = 0;

	if (rs->win_size == 0) {
		cmn_err(CE_CONT, "update_mapmempage: "
		    "Found zero rs->win_size %d\n",
		    (int)rs->win_size);
		/* To avoid zero divide problem */
		return (-1);
		/* NOTREACHED */
	} else {
		/* setup for CardOffset of MapMemPage */
		i = offset / rs->win_size;
	}

	/*
	 * Now map the offset to the card
	 */
	map_mem_page.CardOffset = i * rs->win_size;

	offset -= (i * rs->win_size);


	if ((ret = csx_MapMemPage(rs->window_handle, &map_mem_page))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "update_mapmempage: "
		    "MapMemPage failed %s (0x%x)\n", cft.text, ret);

		if ((ret = csx_ReleaseWindow(rs->window_handle))
		    != CS_SUCCESS) {
			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);
			cmn_err(CE_CONT, "update_mapmempage: "
			    "ReleaseWindow failed %s (0x%x)\n",
			    cft.text, ret);
		}

		/* Let caller knows that there is some thing wrong */
		return (-1);
		/* NOTREACHED */
	}

	return (offset);
	/* NOTREACHED */
}



/*
 * pcram_card_sizing -  Determine memory card size
 *			by writing every block of window size.
 *
 *	The window size must be a multiple of 1KB size?.
 *
 *	returns: n - card size of n bytes
 *		-1 - if we can not read after writing
 *			a know value. (e.g. ROM/FLASH)
 */
static int pcram_card_sizing(pcram_state_t *rs)
{

	int		ret;
	int		offset;
	int		next_offset;
	int		blocksize, nbs;
	uchar_t		test_pattern;
	uchar_t		restore_data;
	uchar_t		cm_addr_zero, cm_next_addr;


	offset = 0;
	ret = update_mapmempage(rs, offset);
	if (ret < 0) {
		/* something failed so abort */
		return (-1);
		/* NOTREACHED */
	}

	cm_addr_zero = csx_Get8(rs->access_handle, 0);

	/*  Select test data pattern  */
	if (cm_addr_zero != PATTERN_1) {
		test_pattern = PATTERN_1;
	} else {
		test_pattern = PATTERN_2;
	}

	/*  Select block size sample */
	if (rs->win_size >= HALF_MEG) {
		blocksize = HALF_MEG;
	} else {
		blocksize = rs->win_size;
	}

	nbs = blocksize - (blocksize%SIZE_1KB);
	if (nbs < SIZE_1KB) {
		blocksize = SIZE_1KB;
	} else {
		blocksize = nbs;
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_SIZE) {
		cmn_err(CE_CONT, "pcram_card_sizing: socket %d \n"
		    "\tBlock size sample [%d bytes]\n",
		    rs->sn, blocksize);
	}
#endif

	while (offset < MAX_CARD_SIZE) {
		offset += blocksize;
		ret = update_mapmempage(rs, offset);
		if (ret < 0) {
			/* something failed so abort */
			return (-1);
			/* NOTREACHED */
		}

		next_offset = ret;
		/* Save data information */
		cm_next_addr = csx_Get8(rs->access_handle, next_offset);
		restore_data = cm_next_addr;

		/* Write this location with test_pattern */
		csx_Put8(rs->access_handle, next_offset, test_pattern);

		/*
		 * Write verification
		 *	If it is not a writen data,
		 *	this could be a ROM or FLASH card.
		 */
		cm_next_addr = csx_Get8(rs->access_handle, next_offset);
		if (cm_next_addr != test_pattern) {
			return (UNRECOGNIZED_MEDIA);
			/* NOTREACHED */
		}

		ret = update_mapmempage(rs, 0);
		if (ret < 0) {
			/* something failed so abort */
			return (-1);
			/* NOTREACHED */
		}

		cm_addr_zero = csx_Get8(rs->access_handle, 0);
		if (cm_addr_zero == test_pattern) {
			/*  Restore location 0 data  */
			csx_Put8(rs->access_handle, 0, restore_data);
			break;
		}

		ret = update_mapmempage(rs, offset);
		if (ret < 0) {
			/* something failed so abort */
			return (-1);
			/* NOTREACHED */
		}


		/*  Restore previous write data  */
		csx_Put8(rs->access_handle, next_offset, restore_data);

	} /* while */

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_SIZE) {
		cmn_err(CE_CONT, "pcram_card_sizing: socket %d \n"
		    "\tFound card_size [%d bytes]\n",
		    rs->sn, offset);
	}
#endif

	return (offset);
	/* NOTREACHED */
}



/*
 *  SPARC UFS label checksum
 */
static int
cksum(struct dk_label *label)
{
	int		i;
	unsigned char	value;
	uchar_t		*data;


	data = (uchar_t *)label;

	for (i = 0, value = 0; i < sizeof (struct dk_label); i++) {
		value ^= *data++;
	}

	return (value);
	/* NOTREACHED */
}


/*
 *  Check media insertion/ejection status
 */
static int
pcram_check_media(pcram_state_t *rs, enum dkio_state state)
{
	int		err;
	get_status_t	get_status;


	mutex_enter(&rs->mutex);

	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->mutex);

		cft.item = err;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_check_media: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		return (ENXIO);
		/* NOTREACHED */
	}

	/* Register rs->media_state */
	if ((get_status.CardState & CS_EVENT_CARD_INSERTION)) {
		rs->media_state = DKIO_INSERTED;
	} else {
		if (state == DKIO_NONE) {
			rs->media_state = DKIO_NONE;
		} else {
			rs->media_state = DKIO_EJECTED;
		}
	}


	/*
	 * XXXX - In order not to modify the volume management
	 *	we have to follow the current SCSI CDROM model
	 *	for checking media state (broken way, sigh!)
	 *		start with state = DKIO_NONE
	 *		wait until mediastate = DKIO_INSERTED
	 *		wait until mediastate = DKIO_EJECTED
	 *		if DKIOCSTATE ioctl() is called second time
	 *		with state = DKIO_EJECTED,
	 *		   return state = DKIO_NONE
	 *		restart with state = DKIO_NONE
	 *
	 */
	if (state != DKIO_NONE) {
		if (rs->ejected_media_flag &&
		    (rs->media_state == DKIO_EJECTED)) {
			rs->media_state = DKIO_NONE;
			rs->ejected_media_flag = 0;
			mutex_exit(&rs->mutex);
			return (0);
			/* NOTREACHED */
		}
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_VOLD) {
		cmn_err(CE_CONT, "pcram_check_media: socket %d \n"
		    "\tWaiting state change: rs->media_state %d state %d\n"
		    "\tDKIO_NONE %d DKIO_EJECTED %d DKIO_INSERTED %d\n",
		    rs->sn, rs->media_state, state,
		    DKIO_NONE, DKIO_EJECTED, DKIO_INSERTED);
	}
#endif

	/*
	 * wait for Card Detect Change Interrupt handler
	 * see either pcram_card_insertion/pcram_card_removal
	 * for cv_broadcast
	 */
	while (rs->media_state == state) {
		rs->checkmedia_flag++;
		if (cv_wait_sig(&rs->condvar_mediastate,
		    &rs->mutex) == 0) {
			mutex_exit(&rs->mutex);
			return (EINTR);
			/* NOTREACHED */
		}
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_VOLD) {
		cmn_err(CE_CONT, "pcram_check_media: socket %d \n"
		    "\tAfter state change: rs->media_state %d state %d\n"
		    "\tDKIO_NONE %d DKIO_EJECTED %d DKIO_INSERTED %d\n",
		    rs->sn, rs->media_state, state,
		    DKIO_NONE, DKIO_EJECTED, DKIO_INSERTED);
	}
#endif

	if (state != DKIO_NONE) {
		if (!rs->ejected_media_flag &&
		    (rs->media_state == DKIO_EJECTED)) {
			rs->ejected_media_flag++;
		}
	}

	mutex_exit(&rs->mutex);

	return (0);
	/* NOTREACHED */
}



/*
 *  Constructing disk label
 */
static int
pcram_build_label_vtoc(pcram_state_t *rs, struct vtoc *vtoc)
{

	int			i;
	short			sum, *sp;
	struct dk_map2		*lpart;
#if defined(__sparc)
	daddr_t			nblks;
#ifdef _SYSCALL32
	struct dk_map32		*lmap;
#else
	struct dk_map		*lmap;
#endif
	struct partition	*vpart;
#endif /* __sparc */


	mutex_enter(&rs->mutex);

	/* Sanity-check the vtoc */
	if (vtoc->v_sanity != VTOC_SANE) {
		mutex_exit(&rs->mutex);
		return (EINVAL);
		/* NOTREACHED */
	}

	bzero(&rs->un_label, sizeof (struct dk_label));

	bcopy(vtoc->v_bootinfo, rs->un_label.dkl_vtoc.v_bootinfo,
	    sizeof (vtoc->v_bootinfo));

	rs->un_label.dkl_vtoc.v_sanity = vtoc->v_sanity;
	rs->un_label.dkl_vtoc.v_version = vtoc->v_version;

	bcopy(vtoc->v_volume, rs->un_label.dkl_vtoc.v_volume, LEN_DKL_VVOL);

#if defined(__i386) || defined(__amd64)
	rs->un_label.dkl_vtoc.v_sectorsz = vtoc->v_sectorsz;
#endif

	rs->un_label.dkl_vtoc.v_nparts = vtoc->v_nparts;

	bcopy(vtoc->v_reserved, rs->un_label.dkl_vtoc.v_reserved,
	    sizeof (vtoc->v_reserved));

	lpart = (struct dk_map2 *)rs->un_label.dkl_vtoc.v_part;

	for (i = 0; i < NDKMAP; i++) {
		lpart->p_tag  = vtoc->v_part[i].p_tag;
		lpart->p_flag = vtoc->v_part[i].p_flag;
#ifdef XX
/* XXX - does not compile for x86 ??? */
#if defined(__i386) || defined(__amd64)
		lpart->p_start = vtoc->v_part[i].p_start;
		lpart->p_size = vtoc->v_part[i].p_size;
#endif
#endif /* XX */
		lpart++;
	}

	bcopy(vtoc->timestamp, rs->un_label.dkl_vtoc.v_timestamp,
	    sizeof (vtoc->timestamp));

#if defined(__i386) || defined(__amd64)
	bcopy(vtoc->v_asciilabel, rs->un_label.dkl_vtoc.v_asciilabel,
	    LEN_DKL_ASCII);
#endif


#if defined(__sparc)
	bcopy(vtoc->v_asciilabel, rs->un_label.dkl_asciilabel, LEN_DKL_ASCII);

	nblks = rs->hdrv_chars->drv_nhead *
	    rs->hdrv_chars->drv_secptrack;

	lmap = rs->un_label.dkl_map;
	vpart = vtoc->v_part;
	for (i = 0; i < NDKMAP; i++) {
		lmap->dkl_cylno = vpart->p_start / nblks;
		lmap->dkl_nblk = vpart->p_size;
		lmap++;
		vpart++;
	}
#endif /* __sparc */

	rs->un_label.dkl_ncyl  = rs->hdrv_chars->drv_ncyl;
	rs->un_label.dkl_nhead = rs->hdrv_chars->drv_nhead;
	rs->un_label.dkl_nsect = rs->hdrv_chars->drv_secptrack;
	rs->un_label.dkl_pcyl  = rs->hdrv_chars->drv_ncyl;

	rs->un_label.dkl_intrlv  = 1;

	rs->un_label.dkl_magic = DKL_MAGIC;

	sum = 0;
	rs->un_label.dkl_cksum = 0;
	sp = (short *)&rs->un_label;

	i = sizeof (struct dk_label)/sizeof (short);
	while (i--) {
		sum ^= *sp++;
	}

	rs->un_label.dkl_cksum = sum;

	mutex_exit(&rs->mutex);

#ifdef	PCRAM_DEBUG
	if (pcram_debug > 1) {
		cmn_err(CE_CONT, "pcram_build_label_vtoc: socket %d\n"
		    "\tncyl %d, nhd %d, nsec %d, pcyl %d\n",
		    rs->sn,
		    rs->un_label.dkl_ncyl, rs->un_label.dkl_nhead,
		    rs->un_label.dkl_nsect, rs->un_label.dkl_pcyl);
	}
#endif

	return (0);
	/* NOTREACHED */
}



/*
 *  Writing disk label to the memory card
 */
static void
pcram_write_label(pcram_state_t *rs)
{
	/*
	 * Update the kernel buffer with the dk_label structure
	 */
	bzero(rs->host_sp, HOST_BUF_SIZE);
	bcopy(&rs->un_label, rs->host_sp, sizeof (struct dk_label));
	/* Write to the memory card */
	mutex_enter(&rs->mutex);
	card_byte_wr(rs, sizeof (struct dk_label), (int)0);
	mutex_exit(&rs->mutex);

}



/*
 * pcram_event - this is the event handler
 */
static int
pcram_event(event_t event, int priority, event_callback_args_t *eca)
{
	int		retcode = CS_UNSUPPORTED_EVENT;
	pcram_state_t	*rs = eca->client_data;
	client_info_t	*ci = &eca->client_info;

#ifdef	DEBUG
	if (pcram_debug_events) {
		pcram_debug_report_event(rs, event, priority);
	}
#endif


	if (priority & CS_EVENT_PRI_HIGH) {
		mutex_enter(&rs->event_hilock);
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug > 1) {
		event2text_t	event2text;

		event2text.event = event;
		(void) csx_Event2Text(&event2text);

		cmn_err(CE_CONT, "pcram_event: socket %d \n"
		    "\tevent %s (0x%x) priority 0x%x\n",
		    rs->sn, event2text.text, event, priority);
	}
#endif
	/*
	 * Find out which event we got and do the appropriate thing
	 */
	switch (event) {
		case CS_EVENT_REGISTRATION_COMPLETE:
		break;
		case CS_EVENT_CARD_INSERTION:
		if (priority & CS_EVENT_PRI_LOW) {
			retcode = pcram_card_insertion(rs);
		}
		break;
		case CS_EVENT_BATTERY_LOW:
		break;
		case CS_EVENT_BATTERY_DEAD:
		break;
		case CS_EVENT_WRITE_PROTECT:
		if (priority & CS_EVENT_PRI_LOW) {
			mutex_enter(&rs->mutex);
		}
		if (eca->info) {
			rs->card_event |= PCRAM_WRITE_PROTECT;
		} else {
			rs->card_event &= ~PCRAM_WRITE_PROTECT;
			rs->wp_posted = 0;
		}
		if (priority & CS_EVENT_PRI_LOW) {
			mutex_exit(&rs->mutex);
		}
		break;
		/*
		 * Note that we get two CS_EVENT_CARD_REMOVAL events -
		 *  one at high priority and the other at low priority.
		 *  This is determined by the setting of the
		 *  CS_EVENT_CARD_REMOVAL_LOWP bit in either of the
		 *  event masks.
		 *  (See the call to RegisterClient).
		 */
		case CS_EVENT_CARD_REMOVAL:
		if (priority & CS_EVENT_PRI_HIGH) {
			retcode = CS_SUCCESS;
			rs->card_event &= ~PCRAM_CARD_INSERTED;
		} else {
			retcode = pcram_card_removal(rs);
			mutex_enter(&rs->event_hilock);
			rs->card_event &= ~PCRAM_CARD_INSERTED;
			mutex_exit(&rs->event_hilock);
		}
		break;
		case CS_EVENT_CLIENT_INFO:
		if (GET_CLIENT_INFO_SUBSVC(ci->Attributes) ==
		    CS_CLIENT_INFO_SUBSVC_CS) {
			ci->Revision = PCRAM_REV_LEVEL;
			ci->CSLevel = CS_VERSION;
			ci->RevDate = PCRAM_REV_DATE;
			(void) strcpy(ci->ClientName,
			    PCRAM_CLIENT_DESCRIPTION);
			(void) strcpy(ci->VendorName,
			    PCRAM_VENDOR_DESCRIPTION);
			ci->Attributes |= CS_CLIENT_INFO_VALID;
			retcode = CS_SUCCESS;
		} /* CS_CLIENT_INFO_SUBSVC_CS */
		break;
	}

	if (priority & CS_EVENT_PRI_HIGH) {
		mutex_exit(&rs->event_hilock);
	}

	return (retcode);
	/* NOTREACHED */
}



/*
 * pcram_card_insertion - handles card insertion events
 */
static int
pcram_card_insertion(pcram_state_t *rs)
{
	int		ret;
	int		rval = CS_SUCCESS;
	uint32_t	first;
	sockevent_t	se;
	win_req_t	win_req;
	convert_speed_t	convert_speed;
	map_mem_page_t	map_mem_page;
	get_status_t	get_status;
	mem_region_t	*mrp;


	mutex_enter(&rs->mutex);

	/* Reset battery DEAD/LOW status posted flag */
	rs->batter_dead_posted = 0;
	rs->batter_low_posted = 0;

	/* XXXX - for Volume Manager */
	if (rs->checkmedia_flag) {
		rs->checkmedia_flag = 0;
		rs->media_state = DKIO_INSERTED;
		cv_broadcast(&rs->condvar_mediastate);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_VOLD) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d \n"
		"\tdoing cv_broadcast - "
		"rs->media_state of DKIO_INSERTED\n", rs->sn);
	}
#endif
	}

	/*
	 * used by PCRAM_PROBESIZE ioctl() to determine if
	 * there is a DOS_BPB, Solaris VTOC, or CIS info
	 */
	rs->default_size_flag = 0;

	/*
	 * XXX  need more work search further for CIS tuple
	 *	level-2 and level-3 to determine the partition info.
	 */
	rs->isit_pseudofloppy = DKI_PCMCIA_PFD;
	rs->card_eject_posted = 0;

	mutex_exit(&rs->mutex);

	/*
	 * Do a CS call to check the card state
	 */
	if ((ret = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (ret);
		/* NOTREACHED */
	}

	/* Make sure that there is a card in the socket */
	if (!(get_status.CardState & CS_EVENT_CARD_INSERTION)) {
#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "ERROR: Found no memory card\n", rs->sn);
	}
#endif
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (CS_NO_CARD);
		/* NOTREACHED */
	}

	/*
	 * Set up the client event mask to give us WP and battery
	 *	events as well as what other events we have already
	 *	registered for.
	 * Note that since we set the global event mask in the call
	 *	to RegisterClient in pcram_attach, we don't have to
	 *	duplicate those events in this event mask.
	 */
	se.Attributes = CONF_EVENT_MASK_CLIENT;
	if ((ret = csx_GetEventMask(rs->client_handle, &se))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "GetEventMask failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (ret);
		/* NOTREACHED */
	}

	se.EventMask |= (CS_EVENT_BATTERY_LOW | CS_EVENT_BATTERY_DEAD |
	    CS_EVENT_WRITE_PROTECT);

	if ((ret = csx_SetEventMask(rs->client_handle, &se))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "SetEventMask failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (ret);
		/* NOTREACHED */
	}

	/*
	 * If we had a window, make sure to release
	 * before we request for the new window
	 */
	if (rs->flags & PCRAM_HAS_WINDOW) {

		mutex_enter(&rs->mutex);
		rs->flags &= ~PCRAM_HAS_WINDOW;
		mutex_exit(&rs->mutex);

		if ((ret = csx_ReleaseWindow(rs->window_handle))
		    != CS_SUCCESS) {
			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);
			cmn_err(CE_CONT,
			    "pcram_card_insertion: socket %d "
			    "ReleaseWindow failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
		}
	}

	/*
	 * Try to get a memory window to CM space
	 */
	win_req.Attributes = (WIN_MEMORY_TYPE_CM | WIN_DATA_WIDTH_16 |
	    WIN_ENABLE);
	win_req.Base.base = 0;	/* let CS find us a base address */
	win_req.Size = 0;	/* let CS return the smallest size */
				/* window it finds */

	convert_speed.Attributes = CONVERT_NS_TO_DEVSPEED;
	convert_speed.nS = 250;
	(void) csx_ConvertSpeed(&convert_speed);

	/* XXX - set to 0x32 until cis_convert_devspeed is fixed */
	convert_speed.devspeed = 0x32;

	win_req.win_params.AccessSpeed = convert_speed.devspeed;

	if ((ret = csx_RequestWindow(rs->client_handle,
	    &rs->window_handle, &win_req)) != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "RequestWindow failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (ret);
		/* NOTREACHED */
	}

	mutex_enter(&rs->mutex);
	rs->flags |= PCRAM_HAS_WINDOW;
	mutex_exit(&rs->mutex);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d \n"
		    "\tRequestWindow successful handle 0x%x\n"
		    "\tAttributes 0x%x Base 0x%x \n"
		    "\tSize 0x%x AccessSpeed 0x%x\n",
		    rs->sn, rs->window_handle,
		    win_req.Attributes,
		    win_req.Base.base,
		    win_req.Size,
		    win_req.win_params.AccessSpeed);
	}
#endif

	/*
	 * Now map the offset to the start of the card
	 */
	map_mem_page.CardOffset = 0;
	map_mem_page.Page = 0;

	if ((ret = csx_MapMemPage(rs->window_handle,
	    &map_mem_page)) != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		mutex_enter(&rs->mutex);
		rs->flags &= ~PCRAM_HAS_WINDOW;
		mutex_exit(&rs->mutex);

		cmn_err(CE_CONT, "pcram_card_insertion: socket %d "
		    "MapMemPage failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);

		if ((ret = csx_ReleaseWindow(rs->window_handle))
		    != CS_SUCCESS) {
			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);
			cmn_err(CE_CONT,
			    "pcram_card_insertion: socket %d "
			    "ReleaseWindow failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
		}
		mutex_enter(&rs->event_hilock);
		cv_broadcast(&rs->firstopenwait_cv);
		mutex_exit(&rs->event_hilock);
		return (ret);
		/* NOTREACHED */
	}

	/* Store rs->access_handle */
	mutex_enter(&rs->mutex);
	rs->access_handle = win_req.Base.handle;
	rs->win_size = win_req.Size;
	mutex_exit(&rs->mutex);

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d \n"
		    "\tBase 0x%x rs->access_handle 0x%p\n"
		    "\tSize 0x%x rs->win_size 0x%x\n",
		    rs->sn,
		    win_req.Base.base, (void *)rs->access_handle,
		    win_req.Size, (int)rs->win_size);
	}
#endif

	/*
	 * Build the memory region lists.  This function will build
	 *	the lists whether or not there is a CIS on the card
	 */
	mutex_enter(&rs->region_lock);
	if ((ret = pcram_build_region_lists(rs)) <= 0) {
		/* error */
		rval = CS_GENERAL_FAILURE;
		if (ret == 0) {
			cmn_err(CE_CONT,
			    "pcram_card_insertion: socket %d \n"
			    "\tERROR - pcram_build_region_lists - "
			    "AM[%d], CM[%d]\n",
			    rs->sn, rs->num_am_regions,
			    rs->num_cm_regions);
		} else if (ret == -2) {
			/*
			 * Found unsupported Device error
			 *	Specified socket is invalid
			 */
			rval = CS_BAD_SOCKET;
		}
	} else {
		/* no error */

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d \n"
		    "\tRegion number - AM[%d], CM[%d]\n",
		    rs->sn, rs->num_am_regions, rs->num_cm_regions);
	}
#endif

		/*
		 * Set "first" to one before you call the function if
		 * you want it to behave as a "get first" function; the
		 * function will automatically manipulate "first" from
		 * then on and it will behave as a "get next" function.
		 * Don't forget to set "first" back to one if you want
		 * a "get first" function again.
		 */

		/* XXX - Need more work on how to handle */
		/*		multiple regions later	 */

		/* Point to Common Memory region list */
		mrp = rs->cm_regions;

		/* Get  BUILD_DOS_BPBFAT_LIST list */
		first = 1;
		while (mrp = pcram_get_firstnext_region(mrp,
		    REGION_DOS_BPBFAT,
		    CISTPL_DEVICE_DTYPE_SRAM,
		    &first)) {
			/* XXX - For now assuming there is ONLY */
			/*	one DOS region 			*/

			/* Note that rs->hdrv_chars is setup in */
			/* pcram_get_bpbfat_info 		*/

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT,
		    "pcram_card_insertion: socket %d - "
		    "BUILD_DOS_BPBFAT_LIST\n\tdevice speed [%d]\n",
		    rs->sn, (int)mrp->nS_speed);
	}
#endif

			/* for VERBOSE mode */
			cmn_err(CE_CONT, "?pcram: "
			    "(MSDOS) socket %d card size %d\n",
			    rs->sn, rs->card_size);

		} /* while */


		/* Get  BUILD_SOLARIS_LIST list */
		mrp = rs->cm_regions;
		first = 1;
		while (mrp = pcram_get_firstnext_region(mrp,
		    REGION_SOLARIS,
		    CISTPL_DEVICE_DTYPE_SRAM,
		    &first)) {
			/* XXX - For now assuming there is ONLY */
			/*	one Solaris region 		*/

			/* Note that rs->hdrv_chars is setup in */
			/* pcram_get_solaris_info 		*/

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT,
		    "pcram_card_insertion: socket %d - BUILD_SOLARIS_LIST\n"
		    "\tdevice speed [%d]\n", rs->sn, (int)mrp->nS_speed);
	}
#endif

			/* for VERBOSE mode */
			cmn_err(CE_CONT, "?pcram: "
			    "(SOLARIS) socket %d card size %d\n",
			    rs->sn, rs->card_size);

		} /* while */


		/* Get  BUILD_DEFAULT_LIST list */
		mrp = rs->cm_regions;
		first = 1;
		while (mrp = pcram_get_firstnext_region(mrp,
		    REGION_DEFAULT,
		    CISTPL_DEVICE_DTYPE_SRAM,
		    &first)) {
			/* XXX - For now assuming there is ONLY */
			/*	one DEFAULT region 		*/

			/*
			 * XXX - check for non-zero for drv_nhead,
			 *	drv_secptrack, drv_sec_size to avoid
			 *	zero divide panic
			 */

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT,
		    "pcram_card_insertion: socket %d - BUILD_DEFAULT_LIST\n"
		    "\tdevice speed [%d]\n", rs->sn, (int)mrp->nS_speed);
	}
#endif
			update_hdrv_chars(rs, mrp);

			/* for VERBOSE mode */
			cmn_err(CE_CONT, "?pcram: "
			    "(DEFAULT) socket %d card size %d\n",
			    rs->sn, rs->card_size);

		} /* while */


		/* Get  BUILD_CM_LIST list */
		mrp = rs->cm_regions;
		first = 1;
		while (mrp = pcram_get_firstnext_region(mrp,
		    REGION_VALID,
		    CISTPL_DEVICE_DTYPE_SRAM,
		    &first)) {
			/* XXX - For now assuming there is ONLY */
			/*	one CM CIS region 		*/

			/*
			 * XXX - check for non-zero for drv_nhead,
			 *	drv_secptrack, drv_sec_size to avoid
			 *	zero divide panic
			 */

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d - "
		    "BUILD_CM_LIST\n\tdevice speed [%d]\n",
		    rs->sn, (int)mrp->nS_speed);
	}
#endif

			update_hdrv_chars(rs, mrp);

			/* for VERBOSE mode */
			cmn_err(CE_CONT,
			    "?pcram: (CIS) socket %d card size %d\n",
			    rs->sn, rs->card_size);

		} /* while */


		/*
		 * Create the device nodes.
		 *	This is an example that assumes
		 *	that we want to create four devices
		 *	for this instance.
		 */
		{
			int			n;
			char			devname[80];
			char			*dname;
			devnode_desc_t		*dnd;
			make_device_node_t	make_device_node;


			make_device_node.Action = CREATE_DEVICE_NODE;
			make_device_node.NumDevNodes = 2;

			make_device_node.devnode_desc =
			    kmem_zalloc(sizeof (struct devnode_desc) *
			    make_device_node.NumDevNodes, KM_SLEEP);

			dname = devname;

			/*
			 * Create only "c" partition for now since
			 * the driver support only one parttion
			 */

			for (n = 0; n < (make_device_node.NumDevNodes);
			    n++) {

				dnd = &make_device_node.devnode_desc[n];

				dnd->name = dname;
				dnd->minor_num =
				    PCRAM_SETMINOR(rs->sn, (n+4)/2);

				if (n&1) {
					dnd->spec_type = S_IFCHR;
					(void) sprintf(dname, "%c,raw",
					    (((n+4)/2)+'a'));
				} else {
					dnd->spec_type = S_IFBLK;
					(void) sprintf(dname, "%c",
					    (((n+4)/2)+'a'));
				}

				dnd->node_type = DDI_NT_BLOCK_CHAN;

				dname = &dname[strlen(dname)+1];
			} /* for */

			if ((ret = csx_MakeDeviceNode(rs->client_handle,
			    &make_device_node)) != CS_SUCCESS) {

				error2text_t cft;

				cft.item = ret;
				(void) csx_Error2Text(&cft);

				cmn_err(CE_CONT,
				    "pcram_card_insertion: socket %d "
				    "MakeDeviceNode failed %s (0x%x)\n",
				    rs->sn, cft.text, ret);
			}

			/*
			 * We don't need this structure anymore
			 *	since we've created the devices.
			 *	If we need to keep track of the
			 *	devices that we've created for
			 *	some reason, then you' want to keep
			 *	this structure and the
			 *	make_device_node_t structure around
			 *	in a global data area.
			 */
			kmem_free(make_device_node.devnode_desc,
			    sizeof (struct devnode_desc) *
			    make_device_node.NumDevNodes);

			make_device_node.devnode_desc = NULL;

		} /* create device nodes */

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_card_insertion: socket %d\n"
		    "\tRegion list - hard drive structure\n"
		    "\tcsize [%d] ncyl [%d] hd [%d] "
		    "spt [%d] ssize [%d]\n", rs->sn,
		    rs->card_size,
		    rs->hdrv_chars->drv_ncyl,
		    rs->hdrv_chars->drv_nhead,
		    rs->hdrv_chars->drv_secptrack,
		    rs->hdrv_chars->drv_sec_size);

		cmn_err(CE_CONT, "pcram: socket%d card size [%d bytes]\n",
		    rs->sn, rs->card_size);
	}
#endif


	}  /* if (!pcram_build_region_lists(rs)) */

	mutex_exit(&rs->region_lock);

	mutex_enter(&rs->event_hilock);
	rs->card_event |= PCRAM_CARD_INSERTED;
	rs->card_event |= PCRAM_FIRST_OPEN;
	rs->flags |= PCRAM_MAKEDEVICENODE;
	/*
	 * Wake up firstopenwait_cv in pcram_open()
	 */
	cv_broadcast(&rs->firstopenwait_cv);
	mutex_exit(&rs->event_hilock);

	return (rval);
	/* NOTREACHED */
}



/*
 * pcram_card_removal - handles card removal events; can only
 *			be called from the low priority card
 *			removal event
 */
static int
pcram_card_removal(pcram_state_t *rs)
{
	int		ret;
	get_status_t	get_status;
	sockevent_t	se;


	mutex_enter(&rs->mutex);

	/* Reset battery DEAD/LOW status posted flag */
	rs->batter_dead_posted = 0;
	rs->batter_low_posted = 0;

	/* Misc. flags */
	rs->busy =  0;
	rs->busy_wr =  0;
	rs->busy_rd =  0;

	/* XXX - DO NOT need to set win_size to zero	*/
	/* 		due to "zero divide trap panic"	*/
	/* rs->win_size = 0;				*/

	/* XXXX - for Volume Manager */
	if (rs->checkmedia_flag) {
		rs->checkmedia_flag = 0;
		rs->media_state = DKIO_EJECTED;
		cv_broadcast(&rs->condvar_mediastate);
#ifdef	PCRAM_DEBUG
		if (pcram_debug & PCRAM_DEBUG_VOLD) {
			cmn_err(CE_CONT,
			    "pcram_card_removal: socket %d \n"
			    "\tdoing cv_broadcast - "
			    "rs->media_state of DKIO_EJECTED\n",
			    rs->sn);
		}
#endif
	}

	rs->card_eject_posted = 0;
	rs->wp_posted = 0;

	/*
	 * Remove all the device nodes.  We don't have to explictly
	 *	specify the names if we want Card Services to remove
	 *	all of the devices.
	 * Note that when you call MakeDeviceNode with the Action
	 *	argument set to REMOVAL_ALL_DEVICE_NODES, the
	 *	NumDevNodes must be zero.
	 */
	if (rs->flags & PCRAM_REGCLIENT) {
		make_device_node_t	make_device_node;

		make_device_node.Action = REMOVAL_ALL_DEVICE_NODES;
		make_device_node.NumDevNodes = 0;

		if ((ret = csx_MakeDeviceNode(rs->client_handle,
		    &make_device_node)) != CS_SUCCESS) {

			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);

			cmn_err(CE_CONT,
			    "pcram_card_removal: socket %d "
			    "MakeDeviceNode failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
		}
	} /* remove device nodes */

	mutex_exit(&rs->mutex);

	/*
	 * Do a CS call to check the card state
	 */
	if ((ret = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcram_card_removal: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		return (ret);
		/* NOTREACHED */
	}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "pcram_card_removal: socket %d "
		    "GetStatus returns:\n", rs->sn);
		pcram_display_card_status(&get_status);
	}
#endif

	/*
	 * Destroy the memory region lists.
	 */
	mutex_enter(&rs->region_lock);
	pcram_destroy_region_lists(rs);
	mutex_exit(&rs->region_lock);

	/*
	 * Release the window if we allocated one
	 */
	if (rs->flags & PCRAM_HAS_WINDOW) {

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_TRACE) {
		cmn_err(CE_CONT, "pcram_card_removal: socket %d "
		    "PCRAM_HAS_WINDOW [0x%x]\n"
		    "\trs->flags [0x%x]:\n", rs->sn,
		    PCRAM_HAS_WINDOW, (int)rs->flags);
	}
#endif

		mutex_enter(&rs->mutex);
		rs->flags &= ~PCRAM_HAS_WINDOW;
		mutex_exit(&rs->mutex);

		if ((ret = csx_ReleaseWindow(rs->window_handle))
		    != CS_SUCCESS) {
			error2text_t cft;

			cft.item = ret;
			(void) csx_Error2Text(&cft);

			cmn_err(CE_CONT,
			    "pcram_card_removal: socket %d "
			    "ReleaseWindow failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
			return (ret);
			/* NOTREACHED */
		}
	}

	/*
	 * Set up the client event mask to clear WP and battery
	 *	events as well as what other events we have already
	 *	registered for.
	 * Note that since we set the global event mask in the call
	 *	to RegisterClient in pcram_attach, we don't have to
	 *	duplicate those events in this event mask.
	 */
	se.Attributes = CONF_EVENT_MASK_CLIENT;
	if ((ret = csx_GetEventMask(rs->client_handle, &se))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_card_removal: socket %d"
		    "GetEventMask failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		return (ret);
		/* NOTREACHED */
	}

	se.EventMask &= ~(CS_EVENT_BATTERY_LOW |
	    CS_EVENT_BATTERY_DEAD |
	    CS_EVENT_WRITE_PROTECT);

	if ((ret = csx_SetEventMask(rs->client_handle, &se))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		cmn_err(CE_CONT, "pcram_card_removal: socket %d"
		    "SetEventMask failed %s (0x%x)\n",
		    rs->sn, cft.text, ret);
		return (ret);
		/* NOTREACHED */
	}

	mutex_enter(&rs->mutex);
	rs->card_event &= ~PCRAM_FIRST_OPEN;
	rs->flags &= ~PCRAM_MAKEDEVICENODE;
	mutex_exit(&rs->mutex);

	return (CS_SUCCESS);
	/* NOTREACHED */
}



#ifdef	PCRAM_DEBUG

/*
 * pcram_display_card_status - wrapper for GetStatus CS function
 */
static void
pcram_display_card_status(get_status_t *gs)
{
	event2text_t	event2text;

	event2text.event = gs->CardState;
	(void) csx_Event2Text(&event2text);

	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "\tCardState [%s]\n", event2text.text);
	}

	event2text.event = gs->SocketState;
	(void) csx_Event2Text(&event2text);

	if (pcram_debug & PCRAM_DEBUG_CARD_STATUS) {
		cmn_err(CE_CONT, "\tSocketState [%s]\n",
		    event2text.text);
	}
}

#endif



/*
 * pcram_build_region_lists - builds a card memory region list for
 *				the passed card
 *
 *	calling: pcram_state_t *rs - pointer to the
 *					  per-card structure
 *
 *	returns: 0 if error building region list
 *		 1 if region list built
 *		-1 if found UNSUPPORTED DEVICE types
 *
 * Note: There are two lists that can be built - one for AM regions
 * and one for CM regions.  We can be called whether or not there is
 * a CIS on the card.  If there is a CIS, we use the inforamtion that
 * we find in it to build the lists; if there is no CIS on the card,
 * we look for an MS-DOS BPB-FAT pseudo floppy image; if it is found,
 * only a CM list is created which describes the one BPB-FAT region
 * in CM.  No AM list is built in this case.
 *
 * If neither a CIS nor a BPB-FAT are found, we create only one list.
 * That list is for the CM space and specifies one region that is as
 * large as the card.  In this case, it is expected the the driver
 * will provide read-only access to this one region.
 *
 * If the driver is asked to format the card, the existing lists will
 * be destroyed, a new CIS written to the card (if necessary), and both
 * lists recreated.
 *
 * XXX - need to think about the non-CIS non-DOS case
 */
static int
pcram_build_region_lists(pcram_state_t *rs)
{
	int		ret;
	cisinfo_t	cisinfo;


	/*
	 * Check for a CIS on this card - if there is one, our job
	 *	is very easy.
	 */
	if ((ret = csx_ValidateCIS(rs->client_handle, &cisinfo))
	    != CS_SUCCESS) {
		error2text_t cft;

		cft.item = ret;
		(void) csx_Error2Text(&cft);

		if (ret != CS_NO_CIS) {
			cmn_err(CE_CONT, "pcram_build_region_lists: "
			    "socket %d"
			    "ValidateCIS failed %s (0x%x)\n",
			    rs->sn, cft.text, ret);
			return (0);
			/* NOTREACHED */
		/*
		 * No CIS on card, try to find an MS-DOS BPB-FAT
		 *	filesystem and build our list from that.
		 */
		} else {

			if ((rs->num_cm_regions =
			    pcram_build_region_list(rs,
			    &rs->cm_regions,
			    BUILD_DOS_BPBFAT_LIST)) <= 0) {

				/*
				 * Couldn't find a BPB-FAT filesystem, so first
				 * destroy the CM list that was just built and
				 * build the default CM region list.
				 */
				pcram_destroy_region_lists(rs);

				if ((rs->num_cm_regions =
				    pcram_build_region_list(
				    rs, &rs->cm_regions,
				    BUILD_SOLARIS_LIST)) <= 0) {

					pcram_destroy_region_lists(rs);

					if ((rs->num_cm_regions =
					    pcram_build_region_list(
					    rs, &rs->cm_regions,
					    BUILD_DEFAULT_LIST)) <= 0) {
						cmn_err(CE_CONT,
						    "pcram_build_region_lists: "
						    "socket %d \n"
						    "\terror building "
						    "default list\n",
						    rs->sn);
						return (0);
						/* NOTREACHED */
					} /* (BUILD_DEFAULT_LIST) */

				} /* (BUILD_SOLARIS_LIST) */

			} /* (BUILD_DOS_BPBFAT_LIST) */

		} /* CS_NO_CIS */
	/*
	 * There is a CIS - build the lists.
	 */
	} else {
		/*
		 * Build the AM space list.  It is OK to have
		 * an empty AM space list.
		 */
		if ((rs->num_am_regions = pcram_build_region_list(rs,
		    &rs->am_regions, BUILD_AM_LIST)) < 0) {
			cmn_err(CE_CONT, "pcram_build_region_lists: "
			    "socket %d \n"
			    "\terror building AM region list\n",
			    rs->sn);
			return (0);
			/* NOTREACHED */
		}

		/*
		 * Build the CM space list. We need something in here
		 * for the driver to work at all.
		 */
		if ((rs->num_cm_regions = pcram_build_region_list(rs,
		    &rs->cm_regions, BUILD_CM_LIST)) < 0) {
			if (rs->num_cm_regions == -2) {
				/*
				 * Found unsupported Device
				 *	Error Return
				 */
				return (-1);
				/* NOTREACHED */
			} else {
				cmn_err(CE_CONT,
				    "pcram_build_region_lists: "
				    "socket %d \n"
				    "\terror building CM "
				    "region list\n", rs->sn);
				return (0);
				/* NOTREACHED */
			}
		} else if (!rs->num_cm_regions) {
			/*
			 * If we couldn't find any CM regions, the card
			 *	could have a badly-formed CIS.
			 *	Create a default CM region.
			 *
			 * XXX - is this the best thing to do, or should
			 *	we just return an error instead?
			 */
			rs->num_cm_regions = pcram_build_region_list(rs,
			    &rs->cm_regions,
			    (BUILD_CM_LIST |
			    BUILD_DEFAULT_LIST));
		}

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT,
		    "pcram_build_region_lists: socket %d \n"
		    "\t(BUILD_AM_LIST | BUILD_CM_LIST)\n", rs->sn);
	}
#endif

	} /* ValidateCIS */

	return (1);
	/* NOTREACHED */
}



/*
 * pcram_build_region_list - builds a region list for the passed
 *				memory region
 *
 *	calling: rs - pointer to caller's state structure
 *		 rlist - pointer to a mem_region_t * region
 *				list pointer
 *		 flags - type of list to build
 *
 *	returns: -1 if region list could not be built; region
 *			list pointer is not changed
 *		 >=0 number of regions found if region list
 *			could be built
 *
 *	returns: -2 if card is not supported
 *
 * Note: If a region list could not be built, the region list must
 *		be destroyed to prevent any memory leaks.  For this
 *		reason, if an error occurs building the region list,
 *		the rlist pointer address is not set to NULL since
 *		it may still have a partial region list.
 */
static int
pcram_build_region_list(pcram_state_t *rs,
				mem_region_t **rlist, uint32_t flags)
{
	mem_region_t		*mr;
	convert_speed_t		convert_speed;
	convert_size_t		convert_size;
	cisdata_t		device_tuple, JEDEC_tuple;
	tuple_t			tuple;
	int			ret, region_num;


	/*
	 * Make sure that we don't have an existing list hanging
	 *	off of this pointer - if we do, this is an error.
	 */
	if (*rlist) {
#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_build_region_list: socket %d "
		    "ERROR *rlist = 0x%p\n", rs->sn, (void *)*rlist);
	}
#endif
		return (-1);
		/* NOTREACHED */
	}

	/*
	 * Do the common setup for a default or DOS partition.
	 */
	if (flags & (BUILD_DEFAULT_LIST |
	    BUILD_DOS_BPBFAT_LIST | BUILD_SOLARIS_LIST)) {
		*rlist = kmem_zalloc(sizeof (mem_region_t), KM_SLEEP);
		mr = *rlist;
		mr->region_num = 0;
		mr->flags = 0;

		mr->next = NULL;
		mr->prev = NULL;

		mr->nS_speed = DEFAULT_CM_SPEED;
		convert_speed.Attributes = CONVERT_NS_TO_DEVSPEED;
		convert_speed.nS = mr->nS_speed;
		(void) csx_ConvertSpeed(&convert_speed);
		mr->speed = convert_speed.devspeed;

	} /* if (BUILD_DEFAULT_LIST | BUILD_DOS_BPBFAT_LIST) */

	/*
	 * See if were being asked to build a default region list.
	 *	If so, build a single region that is as large as the
	 *	max card size and mark it as a default read-only
	 *	region.
	 * XXX  We set the device type to say it's a
	 *	ROM device as well.
	 */
	if (flags & BUILD_DEFAULT_LIST) {
		mr->rflags = REGION_DEFAULT;
		mr->type = CISTPL_DEVICE_DTYPE_SRAM;

		mr->size_in_bytes = MAX_CARD_SIZE;
		convert_size.Attributes = CONVERT_BYTES_TO_DEVSIZE;
		convert_size.bytes = mr->size_in_bytes;
		(void) csx_ConvertSize(&convert_size);
		mr->size = convert_size.devsize;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_build_region_list: socket %d "
		    "BUILD_DEFAULT_LIST\n"
		    "\tsize_in_bytes - [%d] size [0x%x]\n",
		    rs->sn, (int)mr->size_in_bytes, (int)mr->size);
	}
#endif

		/*
		 * Enable default_size_flag so we will probe card
		 * size when PCRAM_PROBESIZE ioctl() is called.
		 * This default_size_flag is not enabled when the
		 * card contains DOS_BPBFAT or Solaris VTOC or
		 * CIS info.
		 */
		rs->default_size_flag++;

		return (1);
		/* NOTREACHED */
	}


	/*
	 * Create a list from an MS-DOS BPB-FAT filesystem.
	 */
	if (flags & BUILD_DOS_BPBFAT_LIST) {
		/*
		 * Check for an MS-DOS BPB-FAT filesystem.
		 *	If it exists, the mem_region_t structure
		 *	will be filled in with the correct values.
		 */
		if (!pcram_get_bpbfat_info(rs, mr)) {
			return (-1);
			/* NOTREACHED */
		}

		/*
		 * Convert the device size
		 *	from bytes to a devsize value.
		 */
		convert_size.Attributes = CONVERT_BYTES_TO_DEVSIZE;
		convert_size.bytes = mr->size_in_bytes;
		(void) csx_ConvertSize(&convert_size);
		mr->size = convert_size.devsize;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_build_region_list: socket %d "
		    "BUILD_DOS_BPBFAT_LIST\n"
		    "\tsize_in_bytes - [%d] size [0x%x]\n",
		    rs->sn, (int)mr->size_in_bytes, (int)mr->size);
	}
#endif

		return (1);
		/* NOTREACHED */
	}



	/*
	 * Create a list from a Solaris VTOC filesystem.
	 */
	if (flags & BUILD_SOLARIS_LIST) {
		if (!pcram_get_solaris_info(rs, mr)) {
			return (-1);
			/* NOTREACHED */
		}

		/*
		 * Convert the device size
		 *	from bytes to a devsize value.
		 */
		convert_size.Attributes = CONVERT_BYTES_TO_DEVSIZE;
		convert_size.bytes = mr->size_in_bytes;
		(void) csx_ConvertSize(&convert_size);
		mr->size = convert_size.devsize;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_build_region_list: socket %d "
		    "BUILD_SOLARIS_LIST\n"
		    "\tsize_in_bytes - [%d] size [0x%x]\n",
		    rs->sn, (int)mr->size_in_bytes, (int)mr->size);
	}
#endif

		return (1);
		/* NOTREACHED */
	}


	/*
	 * We've got a CIS so sort out the correct tuples to look for.
	 */
	switch (flags & (BUILD_AM_LIST | BUILD_CM_LIST)) {
	case BUILD_AM_LIST:
		device_tuple = CISTPL_DEVICE_A;
		JEDEC_tuple = CISTPL_JEDEC_A;
		break;
	case BUILD_CM_LIST:
		device_tuple = CISTPL_DEVICE;
		JEDEC_tuple = CISTPL_JEDEC_C;
		break;
	default:
		return (-1);
	/* NOTREACHED */
	} /* switch (flags) */

	/*
	 * Search for the first device tuple - if it's not found,
	 *	there's no point in searching for anything else.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = device_tuple;
	if ((ret = csx_GetFirstTuple(rs->client_handle, &tuple))
	    != CS_SUCCESS) {
		if (ret != CS_NO_MORE_ITEMS) {
			/* this is a real error */
			return (-1);
			/* NOTREACHED */
		} else {
			/* XXX - is 0 the right thing to return here? */
			return (0);
			/* NOTREACHED */
		}
	}

	/*
	 * Got the device tuple, now parse it.
	 */
	region_num = 0;

	do {
		cistpl_device_t		cistpl_device;
		mem_region_t		*mrr = NULL;
		int			i;

		/*
		 * We shouldn't ever fail parsing this tuple.
		 *	If we do, there's probably an internal
		 *	error in the CIS parser.
		 */
		bzero(&cistpl_device, sizeof (struct cistpl_device_t));
		if (csx_Parse_CISTPL_DEVICE(rs->client_handle,
		    &tuple, &cistpl_device) != CS_SUCCESS) {
			return (-1);
			/* NOTREACHED */
		}

		/*
		 * We should see at least one region.
		 *	This is definately an error.
		 */
		if (!cistpl_device.num_devices) {
			return (-1);
			/* NOTREACHED */
		}

		for (i = 0; i < cistpl_device.num_devices; i++) {

			cistpl_device_node_t *cistpl_device_node;

			cistpl_device_node = &cistpl_device.devnode[i];

			mr = kmem_zalloc(sizeof (mem_region_t), KM_SLEEP);

			/*
			 * IMPORTANT
			 *	setup for next CISTPL_DEVICE tuple
			 */
			mrr = mr;

			/*
			 * If this is the first entry in the list,
			 *	then assign it to the head of
			 *	the list pointer.
			 */
			if (!*rlist) {
				*rlist = mr;
				mr->prev = NULL;
			} else {
				mrr->next = mr;
				mr->prev = mrr;
			}

			mrr->region_num = region_num++;
			mrr->rflags = REGION_VALID;

			mrr->flags = cistpl_device_node->flags;
			mrr->speed = cistpl_device_node->speed;
			mrr->nS_speed = cistpl_device_node->nS_speed;

			if ((mrr->type = cistpl_device_node->type) ==
			    CISTPL_DEVICE_DTYPE_NULL) {
				mrr->rflags |= REGION_HOLE;
			}

			mrr->size = cistpl_device_node->size;
			mrr->size_in_bytes =
			    cistpl_device_node->size_in_bytes;


			/*
			 * Supporting Common Memory (CM) with
			 *	Masked-ROM(MROM) and Dynamic RAM(DRAM)
			 */
			if (device_tuple == CISTPL_DEVICE) {

				char *unsupported_fmt_string =
				    "pcram: WARNING - Found unsupported "
				    "%s device at socket %d\n";
				char *supported_fmt_string =
				    "?pcram: Found %s device at socket %d "
				    "card size %d\n";

				switch (cistpl_device_node->type) {

				case CISTPL_DEVICE_DTYPE_SRAM:
				/* Support this main device */
				break;

				case CISTPL_DEVICE_DTYPE_ROM:
				/* for VERBOSE mode */
				cmn_err(CE_CONT, supported_fmt_string,
				    "Masked ROM", rs->sn,
				    (int)cistpl_device_node->size_in_bytes);
				/* Now consider as SRAM type */
				mrr->type = CISTPL_DEVICE_DTYPE_SRAM;
				break;

				case CISTPL_DEVICE_DTYPE_DRAM:
				/* for VERBOSE mode */
				cmn_err(CE_CONT, supported_fmt_string,
				    "Dynamic RAM", rs->sn,
				    (int)cistpl_device_node->size_in_bytes);
				/* Now consider as SRAM type */
				mrr->type = CISTPL_DEVICE_DTYPE_SRAM;
				break;

				case CISTPL_DEVICE_DTYPE_OTPROM:
				cmn_err(CE_CONT, unsupported_fmt_string,
				    "OTPROM", rs->sn);
				return (-2);
				/* NOTREACHED */

				case CISTPL_DEVICE_DTYPE_EPROM:
				cmn_err(CE_CONT, unsupported_fmt_string,
				    "UV EPROM", rs->sn);
				return (-2);
				/* NOTREACHED */

				case CISTPL_DEVICE_DTYPE_EEPROM:
				cmn_err(CE_CONT, unsupported_fmt_string,
				    "EEPROM", rs->sn);
				return (-2);
				/* NOTREACHED */

				case CISTPL_DEVICE_DTYPE_FLASH:
				cmn_err(CE_CONT, unsupported_fmt_string,
				    "FLASH", rs->sn);
				return (-2);
				/* NOTREACHED */

				default:
				cmn_err(CE_CONT, unsupported_fmt_string,
				    "UNKNOWN", rs->sn);
				return (-2);
				/* NOTREACHED */

				} /* switch (cistpl_device_node->type) */

			}   /* if (device_tuple) */

			/*
			 * Initialize the JEDEC information.
			 *	XXX - need to find out what
			 *	reasonable default values are
			 */
			mrr->id = 0;
			mrr->info = 0;

			mrr->next = NULL;

		} /* for (cistpl_device_node->num_devices) */

	} while ((ret = csx_GetNextTuple(rs->client_handle, &tuple))
	    == CS_SUCCESS);

	/*
	 * If GetNextTuple gave us any error code other than
	 * 	CS_NO_MORE_ITEMS, it means that there is probably
	 *	an internal error in the CIS parser.
	 */
	if (ret != CS_NO_MORE_ITEMS) {
		return (-1);	/* this is a real error */
	    /* NOTREACHED */
	}

	/*
	 * Now that we've built the region list, search for the
	 *	first JEDEC tuple - if it's not found, that's not
	 *	necessarily an error.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = JEDEC_tuple;
	if ((ret = csx_GetFirstTuple(rs->client_handle, &tuple))
	    != CS_SUCCESS) {
		if (ret != CS_NO_MORE_ITEMS) {
			/* this is a real error */
			return (-1);
			/* NOTREACHED */
		} else {
			return (region_num);
			/* NOTREACHED */
		}
	}

	/*
	 * Got the JEDEC tuple, now parse it.
	 *	We will always get here with a non-NULL
	 *	region list pointer.
	 */
	mr = *rlist;	/* point to head of region list */

	do {
		cistpl_jedec_t	cistpl_jedec;
		int		i;

		/*
		 * We shouldn't ever fail parsing this tuple.
		 *	If we do, there's probably an internal
		 *	error in the CIS parser.
		 */
		bzero(&cistpl_jedec, sizeof (struct cistpl_jedec_t));
		if (csx_Parse_CISTPL_JEDEC_C(rs->client_handle,
		    &tuple, &cistpl_jedec) != CS_SUCCESS) {
			return (-1);
			/* NOTREACHED */
		}

		/*
		 * We should see at least one region definition.
		 *	It is definately an error if we don't see any.
		 */
		if (!cistpl_jedec.nid) {
			return (-1);
			/* NOTREACHED */
		}

		for (i = 0; i < cistpl_jedec.nid; i++) {
			/*
			 * Check the region list pointer;
			 *	if this pointer is NULL, it means
			 *	that we either have an internal
			 *	code error in the way we process
			 *	the device tuples or that the card
			 *	has more JEDEC identifiers than device
			 *	tuple device node entries. We still
			 *	return the number of regions
			 *	found, since this may or may not
			 *	be a serious error.
			 */
			if (!mr) {
				cmn_err(CE_CONT,
				    "pcram_build_region_list: socket %d"
				    "too many JEDEC device entries"
				    "in %s memory list\n",
				    rs->sn, (flags & BUILD_AM_LIST)?
				    "ATTRIBUTE":"COMMON");
				return (region_num);
				/* NOTREACHED */
			}

			mr->id = cistpl_jedec.jid[i].id;
			mr->info = cistpl_jedec.jid[i].info;

			/*
			 * Point to the next region in the list.
			 */
			mr = mr->next;

		} /* for (cistpl_jedec.nid) */

	} while ((ret = csx_GetNextTuple(rs->client_handle,
	    &tuple)) == CS_SUCCESS);

	/*
	 * If GetNextTuple gave us any error code other than
	 * CS_NO_MORE_ITEMS, it means that there is probably
	 * an internal error in the CIS parser.
	 */
	if (ret != CS_NO_MORE_ITEMS) {
		return (-1);	/* this is a real error */
		/* NOTREACHED */
	}

	/*
	 * Return the number of region entries in this list.
	 */
	return (region_num);
	/* NOTREACHED */
}



/*
 * pcram_get_bpbfat_info - scan the CM area looking for an
 *			   MS-DOS BPB-FAT filesystem.
 *
 *	calling: rs - pointer to caller's state structure
 *		 mr - pointer to memory region to fill in
 *			if BPB found
 *
 *	returns: 0 - if BPB-FAT not found
 *		 1 - if BPB-FAT found; the mem_region_t struct
 *			will be initialized with the correct values
 */
static int
pcram_get_bpbfat_info(pcram_state_t *rs, mem_region_t *mr)
{

	int			tsecvol;
	struct bootblock	bootblk;


	/*
	 * If there is a BPB-FAT filesystem on the device return 1.
	 * If there isn't, then just return a 0.
	 */

	/*
	 * If there is a way to determine from the BPB-FAT if the
	 * filesystem is read only, you should set the REGION_READONLY
	 * flag in the mr->rflags member.
	 * 	mr->rflags = (REGION_DOS_BPBFAT | REGION_VALID);
	 */

	/*
	 * Note here about the device type - I don't know what
	 * type to put in here, since it's possible to have a
	 * BPB-FAT filesystem on a Flash or EEPROM card.  You might
	 * consider doing some sort of testing to see if you can
	 * determine what type of device is actually in common
	 * memory.
	 * I think that you can interrogate many Flash and EEPROM
	 * devices and they will return their manufacturer and
	 * device code, or maybe a JEDEC code.  Ask Chuck about
	 * this too.  If you can find out that the CM area that
	 * has the DOS filesystem on it is something other than
	 * SRAM, you can set the REGION_READONLY flag in
	 * mr->rflags and possibily also the correct device type
	 * in the mr->type member.
	 *
	 *		mr->type = XXX;
	 */

	/*
	 * Fill this in with the size of the region after you get this
	 * information from the BPB-FAT header.
	 *
	 *		mr->size_in_bytes = XXX;
	 */

	mr->rflags = REGION_DOS_BPBFAT;
	mr->type = CISTPL_DEVICE_DTYPE_SRAM;

	csx_RepGet8(rs->access_handle, (uchar_t *)&bootblk, (uint32_t)0,
	    sizeof (struct bootblock), DDI_DEV_AUTOINCR);

	if (bootblk.sig[0] == DOS_ID1 ||
	    (bootblk.sig[0] == DOS_ID2a &&
	    bootblk.sig[2] == DOS_ID2b)) {

		rs->hdrv_chars->drv_sec_size =
		    GET_INFO(bootblk.bps[0], bootblk.bps[1]);
		rs->hdrv_chars->drv_secptrack =
		    GET_INFO(bootblk.sectrack[0],
		    bootblk.sectrack[1]);
		rs->hdrv_chars->drv_nhead =
		    GET_INFO(bootblk.heads[0], bootblk.heads[1]);

		tsecvol = GET_INFO(bootblk.tsec[0], bootblk.tsec[1]);

		rs->card_size = GET_CSIZ_DOS(tsecvol,
		    rs->hdrv_chars->drv_sec_size);

		/* Return error if found invalid DOS label */
		/* Avoiding zero divide panic when compute drv_ncyl */
		if ((rs->card_size == 0) ||
		    (rs->hdrv_chars->drv_sec_size == 0) ||
		    (rs->hdrv_chars->drv_secptrack == 0) ||
		    (rs->hdrv_chars->drv_nhead == 0)) {

			/* set to default default size of 64MB */
			*rs->hdrv_chars = hdtypes;
			rs->card_size = MAX_CARD_SIZE;
			cmn_err(CE_WARN, "pcram: socket%d "
			    "Found invalid DOS label", rs->sn);
			return (0);
			/* NOTREACHED */
		}

		rs->hdrv_chars->drv_ncyl = GET_NCYL(rs->card_size,
		    rs->hdrv_chars->drv_nhead,
		    rs->hdrv_chars->drv_sec_size,
		    rs->hdrv_chars->drv_secptrack);

		mr->size_in_bytes = rs->card_size;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_get_bpbfat_info: socket %d \n"
		    "\trs->card_size [%d] mr->size_in_bytes [%d]\n",
		    rs->sn, rs->card_size, (int)mr->size_in_bytes);
	}
#endif
		return (1);
		/* NOTREACHED */
	}

	/* Found NO DOS BPBFAT */
	return (0);
	/* NOTREACHED */
}



/*
 * pcram_get_solaris_info - scan the CM area looking for an
 *			   Solaris partition filesystem.
 *
 *	calling: rs - pointer to caller's state structure
 *		 mr - pointer to memory region to fill in
 *			if BPB found
 *
 *	returns: 0 - if Solaris VTOC not found
 *		 1 - if Solaris VTOC found; the mem_region_t struct
 *			will be initialized with the correct values
 */
static int
pcram_get_solaris_info(pcram_state_t *rs, mem_region_t *mr)
{
	struct dk_label		label;


#ifdef USE_REGION_VALID
	mr->rflags = (REGION_SOLARIS | REGION_VALID);
#endif

	mr->rflags = REGION_SOLARIS;
	mr->type = CISTPL_DEVICE_DTYPE_SRAM;

	csx_RepGet8(rs->access_handle, (uchar_t *)&label, (uint32_t)0,
	    sizeof (struct dk_label), DDI_DEV_AUTOINCR);

	if ((label.dkl_magic == DKL_MAGIC) && (cksum(&label) == 0)) {
		/*
		 *  If there is no CIS, try to read dk_label
		 *	to get card size information
		 */
		rs->hdrv_chars->drv_sec_size = 512;
		rs->hdrv_chars->drv_secptrack = label.dkl_nsect;
		rs->hdrv_chars->drv_nhead = label.dkl_nhead;
		rs->hdrv_chars->drv_ncyl = label.dkl_pcyl;

		rs->card_size = GET_CSIZ(rs->hdrv_chars->drv_ncyl,
		    rs->hdrv_chars->drv_nhead,
		    rs->hdrv_chars->drv_sec_size,
		    rs->hdrv_chars->drv_secptrack);

		/* Return error if found invalid SunOS label */
		if (rs->card_size == 0) {
			/* set to default default size of 64MB */
			*rs->hdrv_chars = hdtypes;
			rs->card_size = MAX_CARD_SIZE;
			cmn_err(CE_WARN, "pcram: socket%d "
			    "Found invalid SunOS label", rs->sn);
			return (0);
			/* NOTREACHED */
		}

		mr->size_in_bytes = rs->card_size;

#ifdef	PCRAM_DEBUG
	if (pcram_debug & PCRAM_DEBUG_CIS) {
		cmn_err(CE_CONT, "pcram_get_solaris_info: socket %d \n"
		    "\trs->card_size [%d] mr->size_in_bytes [%d]\n",
		    rs->sn, rs->card_size, (int)mr->size_in_bytes);
	}
#endif

		return (1);
		/* NOTREACHED */
	}

	/* Found no Solaris partition */
	return (0);
	/* NOTREACHED */
}



/*
 * pcram_destroy_region_lists - destroys all memory region lists
 *				on the caller's state structure
 *
 *	calling: rs - pointer to caller's state structure
 */
static void
pcram_destroy_region_lists(pcram_state_t *rs)
{


	pcram_destroy_region_list(&rs->am_regions,
	    &rs->num_am_regions);

	pcram_destroy_region_list(&rs->cm_regions,
	    &rs->num_cm_regions);
}


/*
 * pcram_destroy_region_list - destroys the region list pointed
 *				to be the rlist pointer
 *
 * Note: when we return, the region list pointer is set to NULL,
 *		and the region count is set to zero;
 */
static void
pcram_destroy_region_list(mem_region_t **rlist, int *num)
{
	mem_region_t	*mr, *mrr;


	if ((mr = *rlist) == 0) {
		return;
		/* NOTREACHED */
	}

	do {
		mrr = mr->next;
		kmem_free(mr, sizeof (mem_region_t));
	/* LINTED */
	} while (mr = mrr);

	*rlist = NULL;
	*num = 0;
}


/*
 * pcram_get_firstnext_region - returns memory region pointer for
 *				passed region type
 */
static mem_region_t *
pcram_get_firstnext_region(mem_region_t *mrp, uint32_t flags,
					uint32_t type, uint32_t *first)
{

	if (!mrp) {
		return (NULL);
		/* NOTREACHED */
	}

	if (*first) {
		*first = 0;

		do {
			if (((mrp->rflags & flags) == flags) &&
			    (mrp->type == type)) {
				return (mrp);
				/* NOTREACHED */
			}
		/* LINTED */
		} while (mrp = mrp->next);
	} else {
		/*
		 * This is a get next function.
		 */
		/* LINTED */
		while (mrp = mrp->next) {
			if (((mrp->rflags & flags) == flags) &&
			    (mrp->type == type)) {
				return (mrp);
				/* NOTREACHED */
			}
		}
	}

	return (NULL);
	/* NOTREACHED */
}


static void
update_hdrv_chars(pcram_state_t *rs, mem_region_t *mrp)
{


	mutex_enter(&rs->mutex);
	*rs->hdrv_chars = hdtypes;
	rs->card_size = mrp->size_in_bytes;

	/*
	 * XXX - check for non-zero of drv_nhead, drv_secptrack,
	 *		drv_sec_size to avoid zero divide panic
	 */
	rs->hdrv_chars->drv_ncyl = GET_NCYL(rs->card_size,
	    rs->hdrv_chars->drv_nhead,
	    rs->hdrv_chars->drv_sec_size,
	    rs->hdrv_chars->drv_secptrack);
	mutex_exit(&rs->mutex);
}



#ifdef	DEBUG
static void
pcram_debug_report_event(pcram_state_t *pcram, event_t event, int priority)
{
	char		*event_priority;
	char		*event_text;
	char		buf[64];

	event_priority = (priority & CS_EVENT_PRI_HIGH) ? "high" : "low";

	switch (event) {
	case CS_EVENT_REGISTRATION_COMPLETE:
		event_text = "Registration Complete";
		break;
	case CS_EVENT_PM_RESUME:
		event_text = "Power Management Resume";
		break;
	case CS_EVENT_CARD_INSERTION:
		event_text = "Card Insertion";
		break;
	case CS_EVENT_CARD_READY:
		event_text = "Card Ready";
		break;
	case CS_EVENT_BATTERY_LOW:
		event_text = "Battery Low";
		break;
	case CS_EVENT_BATTERY_DEAD:
		event_text = "Battery Dead";
		break;
	case CS_EVENT_CARD_LOCK:
		event_text = "Card Lock";
		break;
	case CS_EVENT_PM_SUSPEND:
		event_text = "Power Management Suspend";
		break;
	case CS_EVENT_CARD_RESET:
		event_text = "Card Reset";
		break;
	case CS_EVENT_CARD_UNLOCK:
		event_text = "Card Unlock";
		break;
	case CS_EVENT_EJECTION_COMPLETE:
		event_text = "Ejection Complete";
		break;
	case CS_EVENT_EJECTION_REQUEST:
		event_text = "Ejection Request";
		break;
	case CS_EVENT_ERASE_COMPLETE:
		event_text = "Erase Complete";
		break;
	case CS_EVENT_EXCLUSIVE_COMPLETE:
		event_text = "Exclusive Complete";
		break;
	case CS_EVENT_EXCLUSIVE_REQUEST:
		event_text = "Exclusive Request";
		break;
	case CS_EVENT_INSERTION_COMPLETE:
		event_text = "Insertion Complete";
		break;
	case CS_EVENT_INSERTION_REQUEST:
		event_text = "Insertion Request";
		break;
	case CS_EVENT_RESET_COMPLETE:
		event_text = "Reset Complete";
		break;
	case CS_EVENT_RESET_PHYSICAL:
		event_text = "Reset Physical";
		break;
	case CS_EVENT_RESET_REQUEST:
		event_text = "Reset Request";
		break;
	case CS_EVENT_MTD_REQUEST:
		event_text = "MTD Request";
		break;
	case CS_EVENT_CLIENT_INFO:
		event_text = "Client Info";
		break;
	case CS_EVENT_TIMER_EXPIRED:
		event_text = "Timer Expired";
		break;
	case CS_EVENT_WRITE_PROTECT:
		event_text = "Write Protect";
		break;
	case CS_EVENT_SS_UPDATED:
		event_text = "SS Updated";
		break;
	case CS_EVENT_STATUS_CHANGE:
		event_text = "Status Change";
		break;
	case CS_EVENT_CARD_REMOVAL:
		event_text = "Card Removal";
		break;
	case CS_EVENT_CARD_REMOVAL_LOWP:
		event_text = "Card Removal Low Power";
		break;
	default:
		event_text = buf;
		(void) sprintf(buf, "Unknown Event (0x%x)", event);
		break;
	}

	cmn_err(CE_CONT,
	    "pcram%d [socket %d]: %s (%s priority)\n",
	    ddi_get_instance(pcram->dip), pcram->sn,
	    event_text, event_priority);
}
#endif
