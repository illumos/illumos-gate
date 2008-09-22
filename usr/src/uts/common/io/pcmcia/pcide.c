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
 * ATA  disk driver
 *
 * Handles the standard PCMCIA ATA interface
 *
 */
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/scsi/scsi.h>

#include <sys/fdio.h>

#include <sys/errno.h>
#include <sys/open.h>
#include <sys/varargs.h>
#include <sys/fs/pc_label.h>

#include <sys/hdio.h>
#include <sys/dkio.h>
#include <sys/dktp/dadkio.h>

#include <sys/dklabel.h>

#include <sys/vtoc.h>

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dktp/cm.h>

#include <sys/dktp/fdisk.h>

#include <sys/fs/pc_label.h>

#include <sys/pctypes.h>


/*
 * PCMCIA and DDI related header files
 */
#include <sys/pccard.h>

#include <sys/pcmcia/pcata.h>

int	pcata_debug = 0;

static int pcata_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int pcata_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcata_att1(dev_info_t *dip, ata_soft_t *softp);
static int pcata_go(ata_unit_t *unitp);
static int pcata_wait(uint32_t port, ushort_t onbits, ushort_t offbits,
	ata_soft_t *softp);
static int pcata_wait1(uint32_t port, ushort_t onbits, ushort_t offbits,
	int interval, ata_soft_t *softp);
static void pcata_wait_complete(ata_soft_t *softp);
static uchar_t pcata_drive_type(ata_soft_t *softp, ushort_t *secbuf);
static int pcata_setpar(int drive, int heads, int sectors, ata_soft_t *softp);
static int pcata_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk);
static int pcata_print(dev_t dev, char *str);
static int pcata_rdrw(dev_t dev, struct uio *uio, int flag);
static int pcata_read(dev_t dev, struct uio *uio, cred_t *cred_p);
static int pcata_write(dev_t dev, struct uio *uio, cred_t *cred_p);
#ifdef  ATA_DEBUG
static void pcata_print_sttflag(int svalue);
#endif
static void pcata_clear_queues(ata_unit_t *unitp);
static void pcata_nack_packet(struct ata_cmpkt *pktp);
static void pcata_iosetup(ata_unit_t *unitp, struct ata_cmpkt *pktp);
static int pcata_send_data(ata_unit_t *unitp, int count);
static int pcata_get_data(ata_unit_t *unitp, int count);

struct cb_ops pcata_cb_ops = {
		pcata_open,		/* driver open routine		*/
		pcata_close,		/* driver close routine		*/
		pcata_strategy,		/* driver strategy routine	*/
		pcata_print,		/* driver print routine		*/
		pcata_dump,		/* driver dump routine		*/
		pcata_read,		/* driver read routine		*/
		pcata_write,		/* driver write routine		*/
		pcata_ioctl,		/* driver ioctl routine		*/
		nodev,			/* driver devmap routine	*/
		nodev,			/* driver mmap routine		*/
		nodev,			/* driver segmap routine	*/
		nochpoll,		/* driver chpoll routine	*/
		pcata_prop_op,		/* driver prop_op routine	*/
		0,			/* driver cb_str - STREAMS only	*/
		D_NEW | D_MTSAFE,	/* driver compatibility flag	*/
	};

static struct dev_ops ata_ops = {
		DEVO_REV,		/* devo_rev, */
		0,			/* refcnt  */
		pcata_getinfo,		/* info */
		nulldev,		/* identify */
		nulldev,		/* probe */
		pcata_attach,		/* attach */
		pcata_detach,		/* detach */
		nulldev,		/* reset */
		&pcata_cb_ops,		/* driver operations */
		NULL,			/* bus operations */
		NULL,			/* power */
		ddi_quiesce_not_needed,		/* quiesce */
	};



void	*pcata_soft = NULL;


#include <sys/modctl.h>

extern  struct mod_ops  mod_driverops;

static struct modldrv modldrv = {
		&mod_driverops, /* Type of module. This one is a driver */
		"PCMCIA ATA disk controller",
		&ata_ops, /* driver ops */
	};

static struct modlinkage modlinkage = {
		MODREV_1, (void *)&modldrv, NULL
	};

int
_init(void)
{
	int	status;

	status = mod_install(&modlinkage);
	if (status)
		return (status);

	status = ddi_soft_state_init(&pcata_soft, sizeof (ata_soft_t), 1);

	return (status);
}


int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (!status)
		ddi_soft_state_fini(&pcata_soft);

	return (status);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pcata_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	ata_soft_t	*softp;
	int		ret;

	/* resume from a checkpoint */
	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	if (cmd != DDI_ATTACH) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach returning FAILURE\n");
#endif
		return (DDI_FAILURE);
	}

	/* Allocate soft state associated with this instance. */
	ret = ddi_soft_state_zalloc(pcata_soft, ddi_get_instance(dip));
	if (ret != DDI_SUCCESS) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach: Unable to alloc state\n");
#endif
		return (DDI_FAILURE);
	}

	softp = ddi_get_soft_state(pcata_soft, instance);

#ifdef  ATA_DEBUG
	if (pcata_debug & DINIT)
		cmn_err(CE_CONT, "_attach softp=%p\n", (void *)softp);
#endif

	softp->dip		= dip;
	softp->instance		= instance;
	softp->ab_dip		= dip;
	softp->crashbuf		= getrbuf(KM_SLEEP);
	softp->flags		= 0;
	softp->card_state	= 0;
	softp->intr_pending	= 0;
	softp->softint_pending	= 0;
	softp->write_in_progress = 0;
	softp->blk_open		= 0;
	softp->chr_open		= 0;
	softp->ejected_while_mounted = 0;
	bzero(softp->lyr_open, sizeof (softp->lyr_open[NUM_PARTS]));

	/*
	 * Initialize to 0 until it is incremented in pcram_check_media
	 */
	softp->checkmedia_flag =  0;
	softp->ejected_media_flag =  0;
	softp->media_state = DKIO_NONE;

	/*
	 * if attach fails, Solaris won't call detach
	 * so we call detach here to release all flagged resources
	 */
	ret = pcata_att1(dip, softp);
	if (ret == DDI_FAILURE) {
		(void) pcata_detach(dip, DDI_DETACH);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
pcata_att1(dev_info_t *dip, ata_soft_t *softp)
{
	int		ret;
	client_reg_t	client_reg;
	sockmask_t	sockmask;
	map_log_socket_t map_log_socket;
	cs_ddi_info_t	cs_ddi_info;
	get_status_t	get_status;


	/*
	 * create ata_mutex
	 */
	ret = ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_MED,
	    &softp->soft_blk_cookie);
	if (ret != DDI_SUCCESS) {
#ifdef ATA_DEBUG
		cmn_err(CE_CONT, "_attach: unable to get iblock cookie\n");
#endif
		return (ret);
	}


	/*
	 * Setup the mutexii and condition variables.
	 * Initialize the mutex that protects the ATA registers.
	 */
	mutex_init(&softp->ata_mutex, NULL, MUTEX_DRIVER,
	    (void *)(softp->soft_blk_cookie));
	mutex_init(&softp->label_mutex, NULL, MUTEX_DRIVER, NULL);

	cv_init(&softp->readywait_cv, NULL, CV_DRIVER, NULL);
	/* for DKIOCSTATE ioctl()  */
	cv_init(&softp->condvar_mediastate, NULL, CV_DRIVER, NULL);
	softp->flags |= PCATA_DIDLOCKS;


	/*
	 * link in soft interrupt
	 */
	ret = ddi_add_softintr(dip, DDI_SOFTINT_MED, &softp->softint_id,
	    NULL, NULL, pcata_intr, (caddr_t)softp);
	if (ret != DDI_SUCCESS) {
#ifdef ATA_DEBUG
		cmn_err(CE_CONT, "_attach: unable to get soft interrupt\n");
#endif
		return (DDI_FAILURE);
	}
	softp->flags |= PCATA_SOFTINTROK;


	/*
	 * Register with Card Services
	 */
	client_reg.Attributes =
	    INFO_IO_CLIENT | INFO_CARD_SHARE | INFO_CARD_EXCL;

	client_reg.EventMask =
	    CS_EVENT_CARD_INSERTION |
	    CS_EVENT_CARD_REMOVAL |
	    CS_EVENT_CARD_REMOVAL_LOWP |
	    CS_EVENT_PM_RESUME |
	    CS_EVENT_CLIENT_INFO |
	    CS_EVENT_PM_SUSPEND |
	    CS_EVENT_REGISTRATION_COMPLETE;

	client_reg.event_handler = (csfunction_t *)pcata_event;
	client_reg.event_callback_args.client_data = softp;
	client_reg.Version = _VERSION(2, 1);
	client_reg.dip = dip;
	(void) strcpy(client_reg.driver_name, pcata_name);

	ret = csx_RegisterClient(&softp->client_handle, &client_reg);
	if (ret != CS_SUCCESS) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach RegisterClient failed %s\n",
		    pcata_CS_etext(ret));
#endif
		return (DDI_FAILURE);
	}

	mutex_init(&softp->event_hilock, NULL, MUTEX_DRIVER,
	    *(client_reg.iblk_cookie));

	softp->flags |= PCATA_REGCLIENT;


	/*
	 * Get logical socket number and store in softp struct
	 */
	ret = csx_MapLogSocket(softp->client_handle, &map_log_socket);
	if (ret != CS_SUCCESS) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach: MapLogSocket failed %s\n",
		    pcata_CS_etext(ret));
#endif
		return (DDI_FAILURE);
	}
	softp->sn = map_log_socket.PhySocket;


	/*
	 *
	 */
	cs_ddi_info.Socket	= softp->sn;
	cs_ddi_info.driver_name = pcata_name;
	cs_ddi_info.dip		= dip;
	cs_ddi_info.instance	= softp->instance;
	if ((ret = csx_CS_DDI_Info(&cs_ddi_info)) != CS_SUCCESS) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach: socket %d CS_DDI_Info failed %s\n",
		    softp->sn, pcata_CS_etext(ret));
#endif
		return (DDI_FAILURE);
	}

	/*
	 * After the RequestSocketMask call, we start receiving events
	 */
	sockmask.EventMask = CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL;
	ret = csx_RequestSocketMask(softp->client_handle, &sockmask);
	if (ret != CS_SUCCESS) {
#ifdef  ATA_DEBUG
		cmn_err(CE_CONT, "_attach: RequestSocketMask failed %s\n",
		    pcata_CS_etext(ret));
#endif
		return (DDI_FAILURE);
	}
	softp->flags |= PCATA_REQSOCKMASK;

	/*
	 * We may not get the CARD_READY event
	 * until after we leave this function.
	 */
	mutex_enter(&softp->event_hilock);
	softp->card_state |= PCATA_READY_WAIT;
	mutex_exit(&softp->event_hilock);

	(void) csx_GetStatus(softp->client_handle, &get_status);
	if (get_status.raw_CardState & CS_STATUS_CARD_INSERTED) {

		/* wait for drive to be initialized */
		(void) pcata_readywait(softp);

		if ((softp->card_state & PCATA_CARD_INSERTED) == 0 ||
		    (softp->flags & PCATA_READY) == 0) {

			mutex_enter(&softp->ata_mutex);
			mutex_enter(&softp->event_hilock);

			softp->card_state &= ~PCATA_READY_WAIT;

			mutex_exit(&softp->event_hilock);
			mutex_exit(&softp->ata_mutex);
		}
	}

	/*
	 * Wait for minor node creation before returning
	 */
	pcata_minor_wait(softp);

	/*
	 * print banner to announce device
	 */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
pcata_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int	instance = ddi_get_instance(devi);
	ata_soft_t *softp;
	int	ret;

	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	softp = ddi_get_soft_state(pcata_soft, instance);


	/*
	 * Call the card_removal routine to do any final card cleanup
	 */
	if (CARD_PRESENT_VALID(softp)) {
		(void) pcata_card_removal(softp, CS_EVENT_PRI_LOW);
	}


	/*
	 * Release our socket mask - note that we can't do much
	 * if we fail these calls other than to note that
	 * the system will probably panic shortly.  Perhaps
	 * we should fail the detach in the case where these
	 * CS calls fail?
	 */

	if (softp->flags & PCATA_REQSOCKMASK) {
		release_socket_mask_t rsm;
		ret = csx_ReleaseSocketMask(softp->client_handle, &rsm);
		if (ret != CS_SUCCESS) {
#ifdef ATA_DEBUG
			cmn_err(CE_CONT, "_detach "
			    "ReleaseSocketMask failed %s\n",
			    pcata_CS_etext(ret));
#endif
		}
	}


	/*
	 * Deregister with Card Services - we will stop getting
	 * events at this point.
	 */
	if (softp->flags & PCATA_REGCLIENT) {
		ret = csx_DeregisterClient(softp->client_handle);
		if (ret != CS_SUCCESS) {
#ifdef ATA_DEBUG
			cmn_err(CE_CONT, "_detach: "
			    "DeregisterClient failed %s\n",
			    pcata_CS_etext(ret));
#endif
			return (DDI_FAILURE);

		}
		softp->flags &= ~PCATA_REGCLIENT;
	}


	/* unregister the softintrrupt handler */
	if (softp->flags & PCATA_SOFTINTROK) {
		ddi_remove_softintr(softp->softint_id);
		softp->flags &= ~PCATA_SOFTINTROK;

	}

	if (softp->flags & PCATA_DIDLOCKS) {

		/*
		 * XXX/lcl make sure no threads are blocked
		 */
		mutex_destroy(&softp->ata_mutex);
		mutex_destroy(&softp->event_hilock);
		mutex_destroy(&softp->label_mutex);
		cv_destroy(&softp->readywait_cv);
		/* for DKIOCSTATE ioctl()  */
		cv_destroy(&softp->condvar_mediastate);
		softp->flags &= ~PCATA_DIDLOCKS;
	}

	/* Free various structures and memory here. */
	if (softp && softp->crashbuf)
		freerbuf(softp->crashbuf);

	/* Free the soft state structure here */
	ddi_soft_state_free(pcata_soft, instance);

#ifdef ATA_DEBUG
	if (pcata_debug & DPCM)
		cmn_err(CE_NOTE, "successful detach\n");
#endif

	return (DDI_SUCCESS);
}


/*
 *	Common controller object interface
 */
/*
 * initiate a new I/O request
 * either start it or add it to the request queue
 */
int
pcata_start(ata_unit_t *unitp, buf_t *bp, int blkno)
{
	ata_soft_t	*softp = unitp->a_blkp;
	struct ata_cmpkt *pktp;
	int		ret;
	int		kf = 0;

	ASSERT(mutex_owned(&softp->ata_mutex));

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_start unitp=%p, bp=%p bp->b_private=%p\n",
		    (void *)unitp,
		    (void *)bp,
		    bp->b_private);
	}
#endif

	if (!CARD_PRESENT_VALID(softp))
		return (CTL_SEND_FAILURE);

	/* XXX/lcl why is this different from CARD_PRESENT_VALID */
	if (softp->ab_status_flag & ATA_OFFLINE) {
		return (CTL_SEND_FAILURE);
	}

	pktp = (struct ata_cmpkt *)kmem_zalloc(sizeof (*pktp),  kf);
	if (!pktp) {
		cmn_err(CE_NOTE, "_start kmem_zalloc failed\n");
		return (CTL_SEND_FAILURE);
	}

#ifdef ATA_DEBUG
	if (pcata_debug & DENT)
		cmn_err(CE_CONT, "_start pktp=%p\n", (void *)pktp);
#endif

	if ((bp->b_flags & B_PAGEIO) || (bp->b_flags & B_PHYS))
		bp_mapin(bp);

	pktp->ac_bytes_per_block = unitp->au_bytes_per_block;
	pktp->ac_start_v_addr	= bp->b_un.b_addr;	/* xfer address */
	pktp->cp_bytexfer	= bp->b_bcount;
	pktp->cp_bp		= bp;
	pktp->cp_ctl_private	= unitp;
	pktp->cp_srtsec		= blkno;

	if (bp->b_flags & B_READ) {
		pktp->ac_direction	= AT_IN;
		pktp->ac_cdb		= DCMD_READ;
	} else {
		pktp->ac_direction	= AT_OUT;
		pktp->ac_cdb		= DCMD_WRITE;
	}

	/*
	 * b_private is set to 0xBEE by pcata_buf_setup
	 * which is called by an ioctl DIOCTL_RWCMD with a subcommand
	 * of either DADKIO_RWCMD_READ or DADKIO_RWCMD_WRITE
	 *
	 * these commands are used to do I/O through the IOCTL interface
	 *
	 * b_back contains a pointer to the ioctl packet struct (dadkio_rwcmd)
	 */
	if (bp->b_private == (void *)0xBEE)
		pktp->cp_passthru = bp->b_back;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "passthru command seen: 0x%p\n",
		    pktp->cp_passthru);
	}
#endif

	pcata_iosetup(unitp, pktp);	/* fill a packet */
	pktp->pkt_forw = 0;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_start: active: %c  head: %c\n",
		    (softp->ab_active == NULL ? 'N' : 'Y'),
		    (softp->ab_head == NULL ? 'N' : 'Y'));
	}
#endif

	if (softp->ab_active == NULL) {
		/*
		 * The controller is idle.
		 * Put the packet in ab_active....
		 */
		softp->ab_active = pktp;
		/*
		 * ... and start it off
		 */
		ret = PCATA_GO_RETRY;
		while (ret ==  PCATA_GO_RETRY) {
			ret = pcata_go(unitp);
		}
		if (ret == DDI_FAILURE) {
			cmn_err(CE_NOTE, "start_cmd failure \n");
			softp->ab_active = NULL;
			return (CTL_SEND_FAILURE);
		}

	} else {
		/*
		 * the controller is busy now so put the packet
		 * on ab_head or ab_last.
		 */

		if (softp->ab_head == NULL)
			softp->ab_head = pktp;
		else
			softp->ab_last->pkt_forw = pktp;

		softp->ab_last = pktp;
	}

	return (CTL_SEND_SUCCESS);
}


/*
 * initiate I/O for packet linked on ab_active
 */
static int
pcata_go(ata_unit_t *unitp)
{
	ata_soft_t	*softp = unitp->a_blkp;
	struct ata_cmpkt *pktp = softp->ab_active;
	uint32_t	nbytes;
	uint32_t	start_sec;
	uint32_t	cyl;
	uint32_t	resid;
	uchar_t		head;
	uchar_t		drvheads;
	uchar_t		drvsectors;

	uchar_t		ac_devctl;
	uchar_t		ac_sec;
	uchar_t		ac_count;
	uchar_t		ac_lwcyl;
	uchar_t		ac_hicyl;
	uchar_t		ac_hd;

	ASSERT(mutex_owned(&softp->ata_mutex));

	if (pktp == NULL)
		return (DDI_SUCCESS);

	if (!CARD_PRESENT_VALID(softp)) {
		pktp->ac_scb	= DERR_ABORT;
		pktp->cp_reason	= CPS_CHKERR;
		return (DDI_FAILURE);
	}

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_go (%p) altstatus %x error %x\n",
		    (void *)unitp,
		    csx_Get8(softp->handle, AT_ALTSTATUS),
		    csx_Get8(softp->handle, AT_ERROR));
		cmn_err(CE_CONT, "_go handle=%p\n", softp->handle);
	}
#endif

	/*
	 * calculate drive address based on pktp->cp_srtsec
	 */
	start_sec	= pktp->cp_srtsec;
	drvheads	= unitp->au_hd;
	drvsectors	= unitp->au_sec;
	resid		= start_sec / drvsectors;
	head		= resid % drvheads;
	cyl		= resid / drvheads;
	nbytes		= min(pktp->cp_resid, pktp->ac_bytes_per_block);
	ac_count	= (nbytes >> SCTRSHFT);
	ac_devctl	= unitp->au_ctl_bits;
	ac_sec		= (start_sec % drvsectors) + 1;
	ac_hd		= head | unitp->au_drive_bits;
	ac_lwcyl	= cyl;
	ac_hicyl	= (cyl >> 8);

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT,
		    "_go %s at lba=%d (%uc %uh %us) "
		    "%d sectors cmd=%x ctl=%x\n",
		    (pktp->ac_direction == AT_OUT) ? "WT" : "RD",
		    start_sec, cyl, head, ac_sec,
		    ac_count,
		    pktp->ac_cmd, ac_devctl);
	}
#endif

	if (pcata_wait(AT_ALTSTATUS, ATS_DRDY, ATS_BSY, softp))
		return (DDI_FAILURE);

	pcata_wait_complete(softp);

	PCIDE_OUTB(softp->handle, AT_DEVCTL, ac_devctl);
	PCIDE_OUTB(softp->handle, AT_SECT, ac_sec);
	PCIDE_OUTB(softp->handle, AT_COUNT, ac_count);
	PCIDE_OUTB(softp->handle, AT_LCYL, ac_lwcyl);
	PCIDE_OUTB(softp->handle, AT_HCYL, ac_hicyl);
	PCIDE_OUTB(softp->handle, AT_DRVHD, ac_hd);

	/*
	 * the command should make the controller status show BSY
	 * the ISR intr_hi will not record status while the controller is BSY
	 * therefore set interrupt expected state now
	 * the next time we receive an interrupt and the controller is not BSY
	 * the ISR will do the right thing
	 */

	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	if (pktp->ac_direction == AT_OUT)
		softp->write_in_progress++;
	csx_Put8(softp->handle, AT_CMD, pktp->ac_cmd);
	mutex_exit(&softp->hi_mutex);

	/*
	 * If there's data to go along with the command, send it now.
	 */
	if (pktp->ac_direction == AT_OUT) {
		if (pcata_send_data(unitp, nbytes) == DDI_FAILURE) {
			if (pktp->cp_retry >= RETRY_CNT) {
				pcata_clear_queues(unitp);
				return (DDI_FAILURE);
			} else {
				pktp->cp_retry++;
				cmn_err(CE_CONT, "_go: write failure,"
				    " retry=%d \n", pktp->cp_retry);
				cmn_err(CE_CONT,
				    "_go at lba=%d (%uc %uh %us) "
				    "%d sectors cmd=%x ctl=%x \n",
				    start_sec, cyl, head, ac_sec,
				    ac_count,
				    pktp->ac_cmd, ac_devctl);
				return (PCATA_GO_RETRY);
			}
		}
	}

	return (DDI_SUCCESS);
}

/*
 * return value
 *	success means go on o next block
 *	failure means continue with current block
 */
static void
pcata_iocmpl(ata_soft_t *softp)
{
	struct ata_cmpkt *pktp;
	ata_unit_t	*unitp;
	int		nbytes;
	int		ret;
	uchar_t		status;
	uchar_t		error;

	ASSERT(mutex_owned(&softp->ata_mutex));

	if (!CARD_PRESENT_VALID(softp)) {
		cmn_err(CE_CONT, "?_iocmpl Device not present\n");
		return;
	}

	pktp = softp->ab_active;

	error = pktp->ac_error;
	status = pktp->ac_status;

	unitp = (ata_unit_t *)pktp->cp_ctl_private;

	/*
	 * If there was an error, quit now
	 * XXX/lcl no retry is attempted?
	 */
	if ((status & ATS_ERR) || (error & ATE_ABORT)) {
#ifdef ATA_DEBUG
		if (pcata_debug & DIO)
			cmn_err(CE_CONT,
			    "_iocmpl I/O error status=%04x error=%04x\n",
			    status,
			    error);
#endif
		pktp->cp_reason = CPS_CHKERR;
		return;
	}

	nbytes = min(pktp->cp_resid, pktp->ac_bytes_per_block);

	if (pktp->ac_direction == AT_IN) {
		/*
		 * do the read of the block
		 */
		ret = pcata_get_data(unitp, nbytes);
		if (ret == DDI_FAILURE) {
			/*
			 * If the controller never presented the data
			 * and the error bit isn't set,
			 * there's a real problem.  Kill it now.
			 */
			pcata_clear_queues(unitp);
			return;
		}
	}

	/*
	 * update counts...
	 */
	pktp->ac_v_addr += nbytes;
	pktp->cp_resid -= nbytes;
	pktp->cp_reason = CPS_SUCCESS;
	pktp->cp_srtsec	+= (nbytes >> SCTRSHFT);

	/* If last command was a GET_DEFECTS delay a bit */
	if (pktp->ac_cmd == ATC_READDEFECTS)
		drv_usecwait(1000);
}

int
pcata_intr_hi(ata_soft_t *softp)
{
	/*
	 * In ata there is no hardware support to tell if the interrupt
	 * belongs to ata or not. So no checks necessary here.  Later
	 * will check the buffer and see if we have started a transaction.
	 */

	int		rval		= DDI_INTR_UNCLAIMED;
	struct ata_cmpkt *pktp;
	uchar_t		status;
	uchar_t		error;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT,
		    "_intr_hi  sn=%d status=%x intr_pending=%d "
		    "softint_pending=%d wr_in_prog=%d\n",
		    softp->sn, csx_Get8(softp->handle, AT_ALTSTATUS),
		    softp->intr_pending, softp->softint_pending,
		    softp->write_in_progress);
	}
#endif
	mutex_enter(&softp->hi_mutex);

	/*
	 * this test is not redundant (don't remove it)
	 * it is part of card removal processing
	 * and prevents losing interrupt threads
	 */
	if (!CARD_PRESENT_VALID(softp)) {
		mutex_exit(&softp->hi_mutex);
		return (rval);
	}

	status = csx_Get8(softp->handle, AT_ALTSTATUS);

	/*
	 * this is a shared interrupt
	 * if the controller is NOT busy,
	 *   and an interrupt is expected
	 */

	if ((status & ATS_ERR) &&
	    ((status & ATS_BSY) == 0) &&
	    (softp->intr_pending > 0)) {
		cmn_err(CE_CONT,
		    "?_intr_hi  sn=%d status=%x\n",
		    softp->sn, status);
		/* handle aborted commands */
		error = csx_Get8(softp->handle, AT_ERROR);
		if ((error & ATE_ABORT) &&
		    (softp->write_in_progress > 0)) {
			softp->write_in_progress = 0;
		}
	}

	if ((status & ATS_BSY) == 0 &&
	    (softp->write_in_progress == 0) &&
	    (softp->intr_pending > 0)) {
		/*
		 * Read the status register,
		 * this clears an interrupt from the ata device
		 */
		status = csx_Get8(softp->handle, AT_STATUS);
		error = csx_Get8(softp->handle, AT_ERROR);
		rval = DDI_INTR_CLAIMED;
		softp->intr_pending--;
		/*
		 * Make sure the interrupt is cleared, occasionally it is not
		 * cleared by the first status read.
		 */
		status = csx_Get8(softp->handle, AT_STATUS);
		/* put the error status in the right place */
		if ((pktp = softp->ab_active) != 0) {
			pktp->ac_error = error;
			pktp->ac_status = status;
		}
	}
	mutex_exit(&softp->hi_mutex);

#ifdef ATA_DEBUG
	if (pcata_debug & DENT)
		cmn_err(CE_CONT,
		    "_intr_hi status=%x error=%x claimed=%d pending=%d\n",
		    status, error,
		    (rval == DDI_INTR_CLAIMED),
		    softp->intr_pending);
#endif

	if ((rval == DDI_INTR_CLAIMED) &&
	    (softp->ab_active != NULL)) {
		mutex_enter(&softp->hi_mutex);
		softp->softint_pending++;
		mutex_exit(&softp->hi_mutex);
		ddi_trigger_softintr(softp->softint_id);
	}

	return (rval);
}

uint32_t
pcata_intr(char *parm)
{
	ata_soft_t	*softp = (ata_soft_t *)parm;
	ata_unit_t	*unitp;
	struct ata_cmpkt *pktp;
	buf_t		*bp;
	uint32_t	nbytes;
	uint32_t	start_sec;
	uint32_t	cyl;
	uint32_t	resid;
	uchar_t		head;
	uchar_t		drvheads;
	uchar_t		drvsectors;
	uchar_t		ac_devctl;
	uchar_t		ac_sec;
	uchar_t		ac_count;
	int		ret;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_intr entry (%p) sn=%d softint_pending=%d\n",
		    (void *)softp, softp->sn, softp->softint_pending);
	}
#endif


	if (softp->softint_pending == 0) {
		return (DDI_INTR_UNCLAIMED);
	}

	mutex_enter(&softp->ata_mutex);

	if (softp->ab_active == NULL) {
		cmn_err(CE_CONT, "?_intr No outstanding I/O\n");
		goto done;
	}

	/* perform I/O completion */
	pcata_iocmpl(softp);

	if (!CARD_PRESENT_VALID(softp))
		goto done;

	/*
	 * if packet is done (either errors or all bytes transfered)
	 *	pktp points to current packet
	 *	ab_active is cleared
	 * else
	 *	pktp is null
	 *	ab_active is unchanged
	 */
	pktp = softp->ab_active;
	if (pktp != NULL) {
		if (pktp->cp_resid == 0 || pktp->cp_reason != CPS_SUCCESS) {
#ifdef ATA_DEBUG
			if (pcata_debug & DENT) {
				cmn_err(CE_CONT, "_intr retry=%d reason=%d"
				    " CPS_SUCCESS=%d pkpt=%p cp_resid = %d\n",
				    pktp->cp_retry, pktp->cp_reason,
				    CPS_SUCCESS, (void *)pktp,
				    pktp->cp_resid);
			}
#endif
			if ((pktp->cp_retry < RETRY_CNT) &&
			    (pktp->cp_reason != CPS_SUCCESS)) {
				pktp->cp_retry++;
				unitp = softp->ab_active->cp_ctl_private;

				/*
				 * calculate drive address based on
				 * pktp->cp_srtsec
				 */
				start_sec = pktp->cp_srtsec;
				drvheads = unitp->au_hd;
				drvsectors = unitp->au_sec;
				resid = start_sec / drvsectors;
				head = resid % drvheads;
				cyl = resid / drvheads;
				nbytes = min(pktp->cp_resid,
				    pktp->ac_bytes_per_block);
				ac_count = (nbytes >> SCTRSHFT);
				ac_devctl = unitp->au_ctl_bits;
				ac_sec = (start_sec % drvsectors) + 1;

				cmn_err(CE_CONT, "_intr I/O failure,"
				    " retry %d\n", pktp->cp_retry);
				cmn_err(CE_CONT,
				    "_intr %s at lba=%d (%uc %uh %us) "
				    "%d sectors cmd=%x ctl=%x\n",
				    (pktp->ac_direction == AT_OUT) ?
				    "write" : "read",
				    start_sec, cyl, head, ac_sec,
				    ac_count,
				    pktp->ac_cmd, ac_devctl);

				pktp = 0;
			} else {
				/* I/O is complete or an error has occured */
				softp->ab_active = NULL;
			}
		} else {
			/* I/O is still in progress */
			pktp = 0;
		}
	}

	/*
	 * packet which caused this interrupt is now complete
	 */
	if (pktp) {
		if ((pktp->ac_status & ATS_ERR) || (pktp->ac_error)) {
			bioerror(pktp->cp_bp, EIO);
#ifdef  ATA_DEBUG
			cmn_err(CE_NOTE, "_intr ATA ERROR status=%x error=%x\n",
			    pktp->ac_status, pktp->ac_error);
#endif
		}

		bp =  pktp->cp_bp;
		bp->b_resid = bp->b_bcount - pktp->cp_bytexfer;

		/* release the thread for the I/O just completed */
		biodone(bp);

		kmem_free((void *)pktp, sizeof (*pktp));
	}


	/* if ab_active is NULL attempt to dequeue next I/O request */
	if (softp->ab_active == NULL && softp->ab_head != NULL) {
		softp->ab_active = softp->ab_head;
		softp->ab_head = softp->ab_head->pkt_forw;

#ifdef ATA_DEBUG
		if (pcata_debug & DIO) {
			cmn_err(CE_CONT,
			    "_start_next_cmd current:%p head:%p\n",
			    (void *)softp->ab_active,
			    (void *)softp->ab_head);
		}
#endif
	}

	mutex_enter(&softp->hi_mutex);
	softp->softint_pending--;
	mutex_exit(&softp->hi_mutex);

	/* if ab_active is not NULL, attempt to initiate I/O */
	if (softp->ab_active != NULL) {
		unitp = softp->ab_active->cp_ctl_private;

		ret = PCATA_GO_RETRY;
		while (ret == PCATA_GO_RETRY) {
			ret = pcata_go(unitp);
		}
	}
	goto exit;

done:
	mutex_enter(&softp->hi_mutex);
	softp->softint_pending--;
	mutex_exit(&softp->hi_mutex);
exit:
	mutex_exit(&softp->ata_mutex);
#ifdef ATA_DEBUG
	if (pcata_debug & DENT)
		cmn_err(CE_CONT, "_intr exit (%p)\n", (void *)softp);
#endif
	return (DDI_INTR_CLAIMED);
}


/*
 * XXX/lcl need determine if all drives or a single drive is to be cleared
 * if all drives then eliminate tests for pktp->cp_ctl_private == unitp
 * if single drive then examine usage of flag ATA_OFFLINE
 */
static void
pcata_clear_queues(ata_unit_t *unitp)
{
	ata_soft_t	*softp = unitp->a_blkp;
	struct ata_cmpkt *pktp;
	buf_t		*bp;

	ASSERT(mutex_owned(&softp->ata_mutex));

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_clear_queues (%p)\n", (void *)unitp);
	}
#endif
	/*
	 * nack the active request
	 */
	softp->ab_status_flag |= ATA_OFFLINE;

	pktp = softp->ab_active;
	if (pktp && pktp->cp_ctl_private == unitp)
		pcata_nack_packet(pktp);

	/*
	 * now nack all queued requests
	 */
	for (pktp = softp->ab_head; pktp; pktp = pktp->pkt_forw) {
		bp =  pktp->cp_bp;
		if (bp && ((bp->b_flags & B_DONE) == 0)) {
			if ((pktp->ac_status & ATS_ERR) || (pktp->ac_error)) {
				bioerror(bp, EIO);
			}

			/* release the thread for the I/O */
			biodone(bp);
		}
		if (pktp->cp_ctl_private == unitp)
			pcata_nack_packet(pktp);
	}
}

static void
pcata_nack_packet(struct ata_cmpkt *pktp)
{
#ifdef ATA_DEBUG
	if (pcata_debug & DENT)
		cmn_err(CE_CONT, "pcata_nack_packet (%p)\n", (void *)pktp);
#endif
	if (pktp != NULL) {
		pktp->cp_reason = CPS_CHKERR;
		pktp->ac_scb = DERR_ABORT;
	}
}

/*
 * pcata_wait --  wait for a register of a controller to achieve a
 *		specific state.  Arguments are a mask of bits we care about,
 *		and two sub-masks.  To return normally, all the bits in the
 *		first sub-mask must be ON, all the bits in the second sub-
 *		mask must be OFF.  If 5 seconds pass without the controller
 *		achieving the desired bit configuration, we return 1, else
 *		0.
 */
static int
pcata_wait(uint32_t port, ushort_t onbits, ushort_t offbits, ata_soft_t *softp)
{
	register int	i;
	register ushort_t maskval;
	int	ival = csx_Get8(softp->handle, port);

	for (i = 400000; i && (CARD_PRESENT_VALID(softp)); i--) {
		maskval = csx_Get8(softp->handle, port);
		if (((maskval & onbits) == onbits) &&
		    ((maskval & offbits) == 0))
			return (0);
		drv_usecwait(10);
	}
#ifdef ATA_DEBUG
	cmn_err(CE_CONT, "_wait timeout: "
	    "sn=%d port=%x on: 0x%x off: 0x%x ival: 0x%x  eval: 0x%x\n",
	    softp->sn, port, onbits, offbits, ival, maskval);
#endif
	return (1);
}


/*
 * Similar to pcata_wait but the timeout is much shorter.  It is only used
 * during initialization when long delays are noticable.
 */
static int
pcata_wait1(uint32_t port, ushort_t onbits, ushort_t offbits, int interval,
		ata_soft_t *softp)
{
	register int	i;
	register ushort_t maskval;

	for (i = interval; i && (CARD_PRESENT_VALID(softp)); i--) {
		maskval = csx_Get8(softp->handle, port);
		if (((maskval & onbits) == onbits) &&
		    ((maskval & offbits) == 0))
			return (0);
		drv_usecwait(10);
	}
	return (1);
}

/*
 * Wait until the command interrupt has been serviced before starting
 * another command.
 *
 */
static void
pcata_wait_complete(ata_soft_t *softp)
{
	int	i;

	for (i = 0; i < PCATA_WAIT_CNT &&
	    ((softp->intr_pending > 0) || (softp->softint_pending > 0)); i++) {
		drv_usecwait(10);
	}
}

static int
pcata_send_data(ata_unit_t *unitp, int count)
{
	ata_soft_t	*softp = unitp->a_blkp;
	struct ata_cmpkt *pktp = unitp->a_blkp->ab_active;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_send_data (%p, %x)\n",
		    (void *)unitp, count);
	}
#endif
	if (pcata_wait(AT_ALTSTATUS, ATS_DRQ, 0, softp)) {
		cmn_err(CE_CONT, "_send_data - NOT READY\n");
		mutex_enter(&softp->hi_mutex);
		softp->write_in_progress = 0;
		mutex_exit(&softp->hi_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * copy count bytes from pktp->v_addr to the data port
	 */
#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_send_data: port=%x addr=0x%p count=0x%x\n",
		    unitp->a_blkp->ab_data,
		    (void *)pktp->ac_v_addr,
		    count);
	}
#endif

	if (!CARD_PRESENT_VALID(softp)) {
		mutex_enter(&softp->hi_mutex);
		softp->write_in_progress = 0;
		mutex_exit(&softp->hi_mutex);
		return (DDI_FAILURE);
	}

	mutex_enter(&softp->hi_mutex);
	csx_RepPut16(softp->handle, (ushort_t *)pktp->ac_v_addr, AT_DATA,
	    (count >> 1), DDI_DEV_NO_AUTOINCR);
	if (softp->write_in_progress > 0)
		softp->write_in_progress--;
	mutex_exit(&softp->hi_mutex);

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_send_data: ");
		pcata_print_sttflag(csx_Get8(softp->handle, AT_ALTSTATUS));
	}

#endif
	return (DDI_SUCCESS);
}


static int
pcata_get_data(ata_unit_t *unitp, int count)
{
	ata_soft_t	*softp = unitp->a_blkp;
	register struct ata_cmpkt *pktp = unitp->a_blkp->ab_active;

	if (pcata_wait(AT_ALTSTATUS, ATS_DRQ, 0, softp)) {
		cmn_err(CE_CONT, "_get_data - NOT READY\n");
		return (DDI_FAILURE);
	}
	/*
	 * copy count bytes from the data port to pktp->ac_v_addr
	 */

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_get_data port=%x addr=0x%p count=0x%x\n",
		    unitp->a_blkp->ab_data, (void *)pktp->ac_v_addr, count);
	}
#endif

	if (!CARD_PRESENT_VALID(softp))
		return (DDI_FAILURE);

	csx_RepGet8(softp->handle, (uchar_t *)pktp->ac_v_addr,
	    AT_DATA, count, DDI_DEV_NO_AUTOINCR);

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT, "_get_data complete\n");
#endif
	return (DDI_SUCCESS);
}


int
pcata_getedt(ata_soft_t *softp, int dmax)
{
	ushort_t *secbuf;
	struct atarpbuf	*rpbp;
	int drive, dcount;
	char buf[41];
	int i;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_getedt (%p)\n", (void *)softp);
	}
#endif
	/* toggle reset bit to trigger a software reset		*/
	if (!(CARD_PRESENT_VALID(softp)))
		return (DDI_FAILURE);
	csx_Put8(softp->handle, AT_DEVCTL, AT_DEVCTL_D3|AT_SRST);

	drv_usecwait(1000);
	if (!(CARD_PRESENT_VALID(softp)))
		return (DDI_FAILURE);

	/*
	 * The interrupt disable command does not work reliably with
	 * all PC ATA cards. It is better to leave interupts enabled
	 * and process them as they occur.
	 */

	PCIDE_OUTB(softp->handle, AT_DEVCTL, ENABLE_INTERRUPT);

	secbuf = (ushort_t *)kmem_zalloc(NBPSCTR, KM_NOSLEEP);
	if (!secbuf) {
		return (DDI_FAILURE);
	}

	for (dcount = drive = 0; drive < dmax; drive++) {
		if (!(rpbp = (struct atarpbuf *)kmem_zalloc(
		    (sizeof (struct atarpbuf) +
				sizeof (struct scsi_inquiry)), KM_NOSLEEP))) {
			kmem_free(secbuf, NBPSCTR);
			return (DDI_FAILURE);
		}

		/*
		 * load up with the drive number
		 */
		if (drive == 0) {
			PCIDE_OUTB(softp->handle, AT_DRVHD, ATDH_DRIVE0);
		} else {
			PCIDE_OUTB(softp->handle, AT_DRVHD, ATDH_DRIVE1);
		}
		PCIDE_OUTB(softp->handle, AT_FEATURE, 0);

		softp->ab_dev_type[drive] = pcata_drive_type(softp, secbuf);

		if (softp->ab_dev_type[drive] == ATA_DEV_NONE) {
			kmem_free(rpbp, (sizeof (struct atarpbuf) +
			    sizeof (struct scsi_inquiry)));
			continue;
		}
		dcount++;
		bcopy((caddr_t)secbuf, (caddr_t)rpbp, sizeof (struct atarpbuf));

		mutex_enter(&softp->ata_mutex);
		if (!(softp->card_state & PCATA_CARD_INSERTED)) {
			kmem_free(rpbp, (sizeof (struct atarpbuf) +
			    sizeof (struct scsi_inquiry)));
			dcount--;
			mutex_exit(&softp->ata_mutex);
			break;
		}

		softp->ab_rpbp[drive] = rpbp;

		/*
		 * We need to swap the strings on both platforms.
		 */
#ifdef _BIG_ENDIAN
		pcata_byte_swap((char *)rpbp, sizeof (*rpbp));
#else
		pcata_byte_swap(rpbp->atarp_drvser,
		    sizeof (rpbp->atarp_drvser));
		pcata_byte_swap(rpbp->atarp_fw, sizeof (rpbp->atarp_fw));
		pcata_byte_swap(rpbp->atarp_model, sizeof (rpbp->atarp_model));
#endif

		mutex_exit(&softp->ata_mutex);

#ifdef	ATA_DEBUG
		if (pcata_debug & DINIT) {
			(void) strncpy(buf,
			    rpbp->atarp_model, sizeof (rpbp->atarp_model));
		buf[sizeof (rpbp->atarp_model)-1] = '\0';

		/* truncate model */
		for (i = sizeof (rpbp->atarp_model) - 2; i && buf[i] == ' ';
		    i--) {
			buf[i] = '\0';
		}
		cmn_err(CE_CONT, "_getedt model %s, targ %d, stat %x, err %x\n",
		    buf,
		    drive,
		    csx_Get8(softp->handle, AT_STATUS),
		    csx_Get8(softp->handle, AT_ERROR));
		cmn_err(CE_CONT, "	cfg 0x%x, cyl %d, hd %d, sec/trk %d\n",
		    rpbp->atarp_config,
		    rpbp->atarp_fixcyls,
		    rpbp->atarp_heads,
		    rpbp->atarp_sectors);
		cmn_err(CE_CONT, "	mult1 0x%x, mult2 0x%x, dwcap 0x%x,"
		    " cap 0x%x\n",
		    rpbp->atarp_mult1,
		    rpbp->atarp_mult2,
		    rpbp->atarp_dwcap,
		    rpbp->atarp_cap);
		cmn_err(CE_CONT, "	piomode 0x%x, dmamode 0x%x,"
		    " advpiomode 0x%x\n",
		    rpbp->atarp_piomode,
		    rpbp->atarp_dmamode,
		    rpbp->atarp_advpiomode);
		cmn_err(CE_CONT, "	minpio %d, minpioflow %d",
		    rpbp->atarp_minpio,
		    rpbp->atarp_minpioflow);
		cmn_err(CE_CONT, " valid 0x%x, dwdma 0x%x\n",
		    rpbp->atarp_validinfo,
		    rpbp->atarp_dworddma);
		}
#endif

		if (!(CARD_PRESENT_VALID(softp)))
			return (DDI_FAILURE);
		(void) csx_Get8(softp->handle, AT_STATUS);
		(void) csx_Get8(softp->handle, AT_ERROR);
	}

	kmem_free(secbuf, NBPSCTR);
	if (dcount == 0)
		return (DDI_FAILURE);

	for (dcount = drive = 0; drive < dmax; drive++) {

		if ((rpbp = softp->ab_rpbp[drive]) == NULL) {
			continue; /* no drive here */
		}

		if (softp->ab_dev_type[drive] != ATA_DEV_DISK) {
			cmn_err(CE_CONT, "Unknown IDE attachment at 0x%x.\n",
			    softp->ab_cmd - AT_CMD);
			continue;
		}

		/*
		 * feed some of the info back in a set_params call.
		 */
		mutex_enter(&softp->ata_mutex);
		if (pcata_setpar(drive, rpbp->atarp_heads,
		    rpbp->atarp_sectors, softp)
		    == DDI_FAILURE) {
			/*
			 * there should have been a drive here but it
			 * didn't respond properly. It stayed BUSY.
			 */
			if (softp->ab_rpbp[drive]) {
				kmem_free(rpbp,
				    (sizeof (struct atarpbuf) +
				    sizeof (struct scsi_inquiry)));
			}
			softp->ab_rpbp[drive] = NULL;
			softp->ab_dev_type[drive] = ATA_DEV_NONE;
			mutex_exit(&softp->ata_mutex);
			continue;
		}
		mutex_exit(&softp->ata_mutex);
		dcount++;
	}

#ifdef ATA_DEBUG
	if (pcata_debug)
		cmn_err(CE_CONT, "**** probed %d device%s 0x%x\n",
		    dcount, dcount == 1 ? "." : "s.",
		    softp->ab_cmd - AT_CMD);
#endif

	return (dcount ? DDI_SUCCESS : DDI_FAILURE);
}

/*
 * pcata_drive_type()
 */
static uchar_t
pcata_drive_type(ata_soft_t *softp, ushort_t *buf)
{
	struct atarpbuf	*rpbp = (struct atarpbuf *)buf;

	if (pcata_wait1(AT_ALTSTATUS,
	    (ATS_DRDY | ATS_DSC), (ATS_BSY | ATS_ERR), 100000, softp))
		return (ATA_DEV_NONE);

	pcata_wait_complete(softp);

	/*
	 * note: pcata_drive_type is only called by pcata_getedt()
	 * the drive (master/slave) is selected there
	 */
	/* command also known as IDENTIFY DEVICE */
	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	csx_Put8(softp->handle, AT_CMD, ATC_READPARMS);
	mutex_exit(&softp->hi_mutex);

	if (pcata_wait1(AT_ALTSTATUS, ATS_DRQ, ATS_BSY, 1000000, softp)) {

#ifdef ATA_DEBUG
		if (pcata_debug) {
			cmn_err(CE_NOTE, "failed drive did not settle:");
			pcata_print_sttflag(csx_Get8(softp->handle, AT_STATUS));
		}
#endif
		return (ATA_DEV_NONE);
	}

	csx_RepGet16(softp->handle, (ushort_t *)buf, AT_DATA, NBPSCTR >> 1,
	    DDI_DEV_NO_AUTOINCR);

#ifdef ATA_DEBUG
	if (pcata_debug) {
		if ((csx_Get8(softp->handle, AT_STATUS) & ATS_ERR) == 0) {
			pcata_byte_swap(rpbp->atarp_model,
			    sizeof (rpbp->atarp_model));
			rpbp->atarp_model[sizeof (rpbp->atarp_model)-1] = '\0';
			cmn_err(CE_CONT, "succeeded: %s\n",
			    rpbp->atarp_model);
			pcata_byte_swap(rpbp->atarp_model,
			    sizeof (rpbp->atarp_model));
		} else {
			cmn_err(CE_CONT, "failed drive drive read error.\n");
		}
	}
#endif

	/*
	 * wait for the drive to recognize I've read all the data.  some
	 * drives have been observed to take as much as 3msec to finish
	 * sending the data; allow 5 msec just in case.
	 */
	if (pcata_wait1(AT_ALTSTATUS, ATS_DRDY, ATS_BSY | ATS_DRQ, 500, softp))
		return (ATA_DEV_NONE);

	if (!CARD_PRESENT_VALID(softp))
		return (ATA_DEV_NONE);

	if (csx_Get8(softp->handle, AT_ALTSTATUS) & ATS_ERR)
		return (ATA_DEV_NONE);

	return (ATA_DEV_DISK);
}


/*
 * Drive set params command.
 */
static int
pcata_setpar(int drive, int heads, int sectors, ata_soft_t *softp)
{

#ifdef ATA_DEBUG
	if (pcata_debug & DINIT)
		cmn_err(CE_CONT, "_setpar status=0x%x drive=%d heads=%d\n",
		    csx_Get8(softp->handle, AT_STATUS), drive, heads);
#endif
	if (!CARD_PRESENT_VALID(softp))
		return (DDI_FAILURE);

	if (pcata_wait(AT_ALTSTATUS, ATS_DRDY, ATS_BSY, softp))
		return (DDI_FAILURE);

	pcata_wait_complete(softp);

	PCIDE_OUTB(softp->handle, AT_DRVHD, (heads - 1) |
	    (drive == 0 ? ATDH_DRIVE0 : ATDH_DRIVE1));
	PCIDE_OUTB(softp->handle, AT_COUNT, sectors);

	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	csx_Put8(softp->handle, AT_CMD, ATC_SETPARAM);
	mutex_exit(&softp->hi_mutex);

	if (pcata_wait(AT_ALTSTATUS, 0, ATS_BSY, softp))
		return (DDI_FAILURE);
	return (DDI_SUCCESS);
}

void
pcata_byte_swap(char *buf, int n)
{
	int	i;
	char	c;

	n &= ~1;
	for (i = 0; i < n; i += 2) {
		c = buf[i];
		buf[i] = buf[i + 1];
		buf[i + 1] = c;
	}
}


int
pcata_set_rw_multiple(ata_soft_t *softp, int drive)
{
	int	i;
	int	laststat;
	char	size;
	char	accepted_size = -1;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_set_rw_multiple (%p, %d)\n",
		    (void *)softp, drive);
	}
#endif

	if (!CARD_PRESENT_VALID(softp))
		return (DDI_FAILURE);
	/*
	 * Assume we're going to use read/write multiple until the controller
	 * says it doesn't understand them.
	 */
	softp->ab_rd_cmd[drive] = ATC_RDMULT;
	softp->ab_wr_cmd[drive] = ATC_WRMULT;

	/*
	 * set drive number
	 */
	PCIDE_OUTB(softp->handle, AT_DRVHD, drive == 0 ? ATDH_DRIVE0 :
	    ATDH_DRIVE1);

	for (size = 32; size > 0 && accepted_size == -1 &&
	    CARD_PRESENT_VALID(softp); size >>= 1) {

		if (pcata_wait(AT_ALTSTATUS, ATS_DRDY, ATS_BSY, softp))
			return (DDI_FAILURE);

		pcata_wait_complete(softp);

		/*
		 * send the command
		 */
		PCIDE_OUTB(softp->handle, AT_COUNT, size);

		mutex_enter(&softp->hi_mutex);
		softp->intr_pending++;
		csx_Put8(softp->handle, AT_CMD, ATC_SETMULT);
		mutex_exit(&softp->hi_mutex);

		if (pcata_wait(AT_ALTSTATUS, 0, ATS_BSY, softp))
			/*
			 * there should have been a drive here but it
			 * didn't respond properly. It stayed BUSY.
			 * complete failure!
			 */
			return (DDI_FAILURE);
		/*
		 * Wait for DRDY or error status
		 */
		for (i = 0; i < ATA_LOOP_CNT && CARD_PRESENT_VALID(softp);
		    i++) {
			if (((laststat = csx_Get8(softp->handle, AT_ALTSTATUS))
			    & (ATS_DRDY | ATS_ERR)) != 0)
				break;
			drv_usecwait(10);
		}
		if (i == ATA_LOOP_CNT)
			/*
			 * Didn't get ready OR error...  complete failure!
			 * there should have been a drive here but it
			 * didn't respond properly. It didn't set ERR or DRQ.
			 */
			return (DDI_FAILURE);

		/*
		 * See if DRQ or error
		 */
		if (laststat & ATS_ERR) {
			/*
			 * there should have been a drive here but it
			 * didn't respond properly. There was an error.
			 * Try the next value.
			 */
			continue;
		}
		/*
		 * Got ready.. use the value that worked.
		 */
		accepted_size = size;
	}
	if (accepted_size == -1) {
		/*
		 * None of the values worked...
		 * the controller responded correctly though so it probably
		 * doesn't support the read/write multiple commands.
		 */

#ifdef ATA_DEBUG
		if (pcata_debug & DENT) {
			cmn_err(CE_CONT, "Using STD R/W cmds and setting"
			    "block factor to 1\n");
		}
#endif
		softp->ab_rd_cmd[drive] = ATC_RDSEC;
		softp->ab_wr_cmd[drive] = ATC_WRSEC;
		softp->ab_block_factor[drive] = 1;
		softp->ab_max_transfer = 1;
		return (DDI_SUCCESS);
	}
	if (accepted_size == 1) {
		/*
		 * OK... Leave it at 1
		 */
#ifdef ATA_DEBUG
		if (pcata_debug & DENT) {
			cmn_err(CE_CONT, "setting block factor to 1\n");
		}
#endif
		softp->ab_block_factor[drive] = accepted_size;
		softp->ab_max_transfer = accepted_size;
		return (DDI_SUCCESS);
	}
	accepted_size >>= 1;
	/*
	 * Allow a user specified block factor to override the system chosen
	 * value.  Only allow the user to reduce the value.
	 * -1 indicates the user didn't specify anything
	 */
	if ((softp->ab_block_factor[drive] != -1) &&
	    (softp->ab_block_factor[drive] < accepted_size))
		accepted_size = softp->ab_block_factor[drive];

	if (pcata_wait(AT_ALTSTATUS, ATS_DRDY, ATS_BSY, softp))
		return (DDI_FAILURE);

	pcata_wait_complete(softp);

	PCIDE_OUTB(softp->handle, AT_COUNT, accepted_size);

	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	csx_Put8(softp->handle, AT_CMD, ATC_SETMULT);
	mutex_exit(&softp->hi_mutex);

	if (pcata_wait(AT_ALTSTATUS, 0, ATS_BSY, softp))
		/*
		 * there should have been a drive here but it
		 * didn't respond properly. It stayed BUSY.
		 */
		return (DDI_FAILURE);

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "setting block factor for drive %d to %d\n",
		    drive, accepted_size);
	}
#endif

	softp->ab_block_factor[drive] = accepted_size;
	return (DDI_SUCCESS);
}

static int
pcata_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	ata_soft_t *softp;
	buf_t *bp;
	void *instance;


	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)dev,
	    &instance) != DDI_SUCCESS)
		return (ENODEV);

	softp = ddi_get_soft_state(pcata_soft, (int)(uintptr_t)instance);
	if (!softp) {
		return (ENXIO);
	}

	if (!CARD_PRESENT_VALID(softp))
		return (ENODEV);

	bp = softp->crashbuf;
	bp->b_un.b_addr = addr;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_bcount = nblk * DEV_BSIZE;
	bp->b_flags |= B_WRITE | B_PHYS;
	bp->b_blkno = blkno;
	bp->b_private = 0;

	/*
	 * If pcata_strategy() encounters an exception, or card_removal
	 * is called, before this is complete, it is possible that
	 * biodone will be called but the buffer (bp) wont
	 * be released unless B_ASYNC flag is set. So
	 * don't set B_ASYNC flag unless you mean it.
	 */
	(void) pcata_strategy(bp);
	if (bp->b_error)
		return (bp->b_error);

	for (;;) {
		if (!CARD_PRESENT_VALID(softp))
			return (ENODEV);
		if (bp->b_flags & B_DONE) {
			if (bp->b_flags & B_ERROR)
				return (bp->b_error);
			else
				return (0);
		}
		drv_usecwait(1000);
	}
}

/* ddi print */
static int
pcata_print(dev_t dev, char *str)
{
	void	*instance;
	ata_soft_t *softp;


	/* get instance number */
	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)dev,
	    &instance) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "_print: pcata_getinfo"
		    "return ENODEV\n");
		return (ENODEV);
	}

	if (!(softp = ddi_get_soft_state(pcata_soft,
	    (int)(uintptr_t)instance))) {
		return (ENXIO);
	}

	cmn_err(CE_NOTE, "_print: socket %d %s", softp->sn, str);
	return (0);

}

static int
pcata_rdrw(dev_t dev, struct uio *uio, int flag)
{
	return (physio(pcata_strategy, (buf_t *)0, dev, flag, pcata_min, uio));
}



/* ARGSUSED2 */
static int
pcata_read(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (pcata_rdrw(dev, uio, B_READ));
}



/* ARGSUSED2 */
static int
pcata_write(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (pcata_rdrw(dev, uio, B_WRITE));
}


void
pcata_min(buf_t *bp)
{
	ata_soft_t *softp;
	void *instance;

	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)bp->b_edev,
	    &instance) != DDI_SUCCESS)
		cmn_err(CE_CONT, "Error in pcata_min\n");

	softp = ddi_get_soft_state(pcata_soft, (int)(uintptr_t)instance);

	if ((ROUNDUP(bp->b_bcount, NBPSCTR) >> SCTRSHFT) >
	    softp->ab_max_transfer)

		bp->b_bcount = softp->ab_max_transfer << SCTRSHFT;
}

static void
pcata_iosetup(ata_unit_t *unitp, struct ata_cmpkt *pktp)
{
	uint32_t	sec_count;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_iosetup (%p, %p)\n",
		    (void *)unitp, (void *)pktp);
	}
#endif

	/* check for error retry */
	if (pktp->ac_flags & CFLAG_ERROR) {
		pktp->ac_bytes_per_block = NBPSCTR;
		sec_count = 1;
	} else {
		/*
		 * Limit requetst to ab_max_transfer sectors.
		 * The value is specified by the user in the
		 * max_transfer property. It must be in the range 1 to 256.
		 * When max_transfer is 0x100 it is bigger than 8 bits.
		 * The spec says 0 represents 256 so it should be OK.
		 */
		sec_count = min((pktp->cp_bytexfer >> SCTRSHFT),
		    unitp->a_blkp->ab_max_transfer);
	}
	pktp->ac_v_addr = pktp->ac_start_v_addr;
	pktp->cp_resid = pktp->cp_bytexfer;
	pktp->cp_bytexfer = sec_count << SCTRSHFT;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT,
		    "_iosetup: asking for start 0x%lx count 0x%x\n",
		    pktp->cp_srtsec, pktp->cp_bytexfer >> SCTRSHFT);
	}
#endif
	/*
	 * setup the task file registers
	 */

	if (pktp->cp_passthru) {
		switch (((struct dadkio_rwcmd *)(pktp->cp_passthru))->cmd) {
		case DADKIO_RWCMD_READ:
			pktp->ac_cmd = unitp->au_rd_cmd;
			pktp->ac_direction = AT_IN;
			break;
		case DADKIO_RWCMD_WRITE:
			pktp->ac_cmd = unitp->au_wr_cmd;
			pktp->ac_direction = AT_OUT;
			break;
		}
	} else {
		switch (pktp->ac_cdb) {
		case DCMD_READ:
		case DCMD_WRITE:
		case DCMD_RECAL:
		case DCMD_SEEK:
		case DCMD_RDVER:
			switch (pktp->ac_cdb) {
			case DCMD_READ:
				pktp->ac_cmd = unitp->au_rd_cmd;
				pktp->ac_direction = AT_IN;
				break;
			case DCMD_WRITE:
				pktp->ac_cmd = unitp->au_wr_cmd;
				pktp->ac_direction = AT_OUT;
				break;
			case DCMD_RECAL:
				pktp->ac_cmd = ATC_RECAL;
				pktp->ac_direction = AT_NO_DATA;
				break;
			case DCMD_SEEK:
				pktp->ac_cmd = ATC_SEEK;
				pktp->ac_direction = AT_NO_DATA;
				break;
			case DCMD_RDVER:
				pktp->ac_cmd = ATC_RDVER;
				pktp->ac_direction = AT_NO_DATA;
				break;
			}
			break;
		default:
			cmn_err(CE_CONT, "_iosetup: "
			    "unrecognized cmd 0x%x\n",
			    pktp->ac_cdb);
			break;
		}
	}
}


/* ARGSUSED */
int
pcata_spinup(ata_soft_t *softp, int slot)
{

	if (!(CARD_PRESENT_VALID(softp)))
		return (DDI_FAILURE);

	if (pcata_wait(AT_ALTSTATUS, ATS_DRDY, ATS_BSY, softp))
		return (DDI_FAILURE);

	pcata_wait_complete(softp);

	/* spin up the drive */
	PCIDE_OUTB(softp->handle, AT_DRVHD, ATDH_DRIVE0);

	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	csx_Put8(softp->handle, AT_CMD, ATC_IDLE_IMMED);
	mutex_exit(&softp->hi_mutex);

	if (pcata_wait(AT_ALTSTATUS,
	    (ATS_DRDY | ATS_DSC), (ATS_BSY | ATS_ERR), softp)) {
#ifdef	ATA_DEBUG
		cmn_err(CE_NOTE, "TIMEOUT SPINNING UP: ");
		pcata_print_sttflag(csx_Get8(softp->handle, AT_ALTSTATUS));
#endif
		return (DDI_FAILURE);
	}

	pcata_wait_complete(softp);

	/* set the R/W multiple value decided at first init  time */

	PCIDE_OUTB(softp->handle, AT_COUNT, softp->ab_block_factor[0]);

	mutex_enter(&softp->hi_mutex);
	softp->intr_pending++;
	csx_Put8(softp->handle, AT_CMD, ATC_SETMULT);
	mutex_exit(&softp->hi_mutex);

	if (pcata_wait(AT_STATUS, 0, ATS_BSY, softp)) {
		/*
		 * there should have been a drive here but it
		 * didn't respond properly. It stayed BUSY.
		 */
#ifdef	ATA_DEBUG
		cmn_err(CE_NOTE, "Error Spinning up ATA drive (after CPR)\n");
#endif
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

#ifdef  ATA_DEBUG
static char	*
ata_sttvals[] = { "err", "idx", "corr", "drq", "dsc", "dwf", "drdy", "bsy" };


static void
pcata_print_sttflag(int svalue)
{
	int	i;
	char	buf[80];

	(void) sprintf(buf, "_sttflag = 0x%x [ ", svalue);

	for (i = 7; i >= 0; i--,  svalue <<= 1) {
		if (svalue & 0x80) {
			(void) strcat(buf, ata_sttvals[i]);
			(void) strcat(buf, " ");
		}
	}
	cmn_err(CE_CONT, "%s ]\n", buf);
}
#endif
