/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <sys/dklabel.h>

#include <sys/vtoc.h>

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/dktp/cm.h>

#include <sys/dktp/fdisk.h>

#include <sys/fs/pc_label.h>

/*
 * PCMCIA and DDI related header files
 */
#include <sys/pccard.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/pcmcia/pcata.h>

int pcata_event(event_t event, int priority, event_callback_args_t *eca);
static int pcata_create_device_node(ata_soft_t *softp);
static int pcata_initchild(ata_soft_t *softp, int targ);
static int pcata_drive_setup(ata_soft_t *softp);
static void pcata_drive_unsetup(ata_soft_t *softp);
static int pcata_card_insertion(ata_soft_t *softp);

event2text_t event2text = {
	0, 0, 0, NULL };

char	*pcata_name = PCATA_NAME;		/* Global not local */


/*
 * pcata_event - this is the event handler
 */

int
pcata_event(event_t event, int priority, event_callback_args_t *eca)
{
	ata_soft_t *softp = eca->client_data;
	int	retcode = CS_UNSUPPORTED_EVENT;

#ifdef  ATA_DEBUG
	if (pcata_debug & DPCM) {
		event2text.event = event;

		(void) csx_Event2Text(&event2text);
		cmn_err(CE_CONT, "_event (0x%x) %s priority 0x%x\n",
		    event,
		    event2text.text,
		    priority);
	}
#endif


	/*
	 * Find out which event we got and do the appropriate thing
	 */
	switch (event) {
	case CS_EVENT_REGISTRATION_COMPLETE:
		retcode = CS_SUCCESS;
		break;
	case CS_EVENT_CARD_INSERTION:
		/* if this is NOT low priority, ignore it */
		if ((priority & CS_EVENT_PRI_LOW) == 0)
			break;

		mutex_enter(&softp->event_hilock);
		softp->card_state = PCATA_WAITINIT;
		mutex_exit(&softp->event_hilock);

		retcode = pcata_card_insertion(softp);
		if (retcode == CS_SUCCESS) {
			if (pcata_drive_setup(softp) != DDI_SUCCESS) {
				retcode = CS_GENERAL_FAILURE;
			}
		}
		mutex_enter(&softp->event_hilock);
		softp->card_state &= ~PCATA_WAITINIT;
		/* kick start any threads that were blocked */
		cv_broadcast(&softp->readywait_cv);
		mutex_exit(&softp->event_hilock);

		break;
		/*
		 * Note that we get two CS_EVENT_CARD_REMOVAL events -
		 * one at high priority and the other at low priority.
		 * This is determined by the setting of the
		 * CS_EVENT_CARD_REMOVAL_LOWP bit in either of the
		 * event masks.
		 * (See the call to RegisterClient).
		 * We handle the CS_EVENT_PM_SUSPEND event the same
		 * way that we handle a CS_EVENT_CARD_REMOVAL event
		 * since if we're being asked to suspend, then we
		 * can't tell if the same card is inserted after
		 * a resume.
		 */
	case CS_EVENT_CARD_REMOVAL:
		retcode = pcata_card_removal(softp, priority);
		break;

	case CS_EVENT_PM_SUSPEND:
		break;
	}

	return (retcode);
}


/*
 * at card insertion allocate I/O addresses
 */
int
pcata_ci_ioaddr(ata_soft_t *softp)
{
	pcata_cis_vars_t	*cis_vars = &softp->cis_vars;
	pcata_cftable_t		*cftable = NULL;
	pcata_cftable_t		*cft;
	io_req_t		io_req;
	int			ret;

	/*
	 * Read CIS and setup the variables.
	 */
	ret = pcata_parse_cis(softp, &cftable);
	if (ret != CS_SUCCESS) {
		cmn_err(CE_CONT, "_ci_ioaddr "
			"socket %d unable to get CIS information\n",
			softp->sn);
		pcata_destroy_cftable_list(&cftable);
		return (ret);
	}

	/*
	 * Parse CIS data
	 */
	cft = cftable;
	while (cft) {
		/* skip config index 0 (memory mapped config) */
		if (cft->p.config_index) {
			/*
			 * Allocate IO resources.
			 */
			io_req.Attributes1	= IO_DATA_PATH_WIDTH_16;
			io_req.IOAddrLines	= cft->p.addr_lines;
			io_req.BasePort1.base	= (cft->p.ata_base[0] & 0xfff0);
			io_req.NumPorts1	= cft->p.ata_length[0];

			io_req.Attributes2	= 0;
			io_req.NumPorts2	= 0;
			if (cft->p.ranges == 2) {
				io_req.Attributes2	= IO_DATA_PATH_WIDTH_16;
				io_req.NumPorts2	= cft->p.ata_length[1];
				io_req.BasePort2.base	=
				    (cft->p.ata_base[1] & 0xfff0);
			}

			ret = csx_RequestIO(softp->client_handle, &io_req);
			if (ret == CS_SUCCESS) {
				/* found a good IO range */
				break;
			}
		}
		cft = cft->next;
	}


	/*
	 * save all the CIS data
	 */
	if (cft) {
		cis_vars->ata_base[0]	= cft->p.ata_base[0] & 0xfff0;
		cis_vars->ata_length[0]	= cft->p.ata_length[0];
		cis_vars->addr_lines	= cft->p.addr_lines;
		cis_vars->ata_vcc	= cft->p.ata_vcc;
		cis_vars->ata_vpp1	= cft->p.ata_vpp1;
		cis_vars->ata_vpp2	= cft->p.ata_vpp2;
		cis_vars->pin		= cft->p.pin;
		cis_vars->config_index	= cft->p.config_index;
		if (cft->p.ranges == 2) {
			cis_vars->ata_base[1]	= cft->p.ata_base[1] & 0xfff0;
			cis_vars->ata_length[1]	= cft->p.ata_length[1];
		}
	}

	/* release config table entries list */
	pcata_destroy_cftable_list(&cftable);

	/*
	 * if we could not find a usable set of address
	 */
	if (!cft) {
		cmn_err(CE_CONT, "socket %d RequestIO failed %s\n",
			softp->sn, pcata_CS_etext(ret));
		return (CS_GENERAL_FAILURE);
	}

	softp->handle = io_req.BasePort1.handle;
	softp->flags |= PCATA_REQUESTIO;

#ifdef	ATA_DEBUG
	if (pcata_debug & DINIT) {
		cmn_err(CE_CONT,
			"\npresent mask: 0x%x\n"
			"PRR pin mask: 0x%x\n"
			"major_revision: 0x%x\n"
			"minor_revision: 0x%x\n"
			"manufacturer_id: 0x%x\n"
			"card_id: 0x%x\n"
			"config_base: 0x%x\n"
			"config_index: 0x%x\n",
			cis_vars->present, cis_vars->pin,
			cis_vars->major_revision,
			cis_vars->minor_revision,
			cis_vars->manufacturer_id,
			cis_vars->card_id,
			cis_vars->config_base,
			cis_vars->config_index);

		cmn_err(CE_CONT,
			"\nata_vcc: %u\n"
			"ata_vpp1: %u\n"
			"ata_vpp2: %u\n"
			"addr_lines: %u\n"
			"ata_base[0]:   %u\n"
			"ata_length[0]: %u\n"
			"ata_base[1]:   %u\n"
			"ata_length[1]: %u\n",
			cis_vars->ata_vcc,
			cis_vars->ata_vpp1,
			cis_vars->ata_vpp2,
			cis_vars->addr_lines,
			cis_vars->ata_base[0],
			cis_vars->ata_length[0],
			cis_vars->ata_base[1],
			cis_vars->ata_length[1]);
	}
#endif
#ifdef ATA_DEBUG
	if (pcata_debug & DPCM) {
		cmn_err(CE_CONT, "ports assigned: 0x%p+%u & 0x%p+%u\n",
			(void *)io_req.BasePort1.handle,
			io_req.NumPorts1,
			(void *)io_req.BasePort2.handle,
			io_req.NumPorts2);
		cmn_err(CE_CONT,
			"_ci_ioaddr: socket %d base_0 0x%x len_0 0x%x"
			" base_1 0x%x len_1 0x%x\n",
			softp->sn,
			cis_vars->ata_base[0], cis_vars->ata_length[0],
			cis_vars->ata_base[0], cis_vars->ata_length[1]);
	}
#endif
	return (CS_SUCCESS);
}

/*
 * The card must be inserted before some things can be done
 * 1) determine the I/O address space
 * 2) determine the IRQ
 * 3) configure the card
 */
static int
pcata_card_insertion(ata_soft_t *softp)
{
	get_status_t		get_status;
	pcata_cis_vars_t	*cis_vars = &softp->cis_vars;
	irq_req_t		irq_req;
	config_req_t		config_req;
	modify_config_t		modify_config;
	int			ret;
	int			i;

#ifdef  ATA_DEBUG
	if (pcata_debug & DPCM)
		cmn_err(CE_CONT, "_card_insertion: socket %d\n",
			softp->sn);
#endif

	mutex_enter(&softp->ata_mutex);

	/*
	 * Allocate io address space
	 */
	if ((softp->flags & PCATA_REQUESTIO) == 0) {
		ret = pcata_ci_ioaddr(softp);
		if (ret != CS_SUCCESS) {
			mutex_exit(&softp->ata_mutex);
			return (ret);
		}
	}

	/*
	 * Allocate an IRQ.
	 */
	softp->intr_pending = 0;
	irq_req.Attributes = IRQ_TYPE_EXCLUSIVE;
	irq_req.irq_handler = (csfunction_t *)pcata_intr_hi;
	irq_req.irq_handler_arg = (caddr_t)softp;
	if (!(softp->flags & PCATA_REQUESTIRQ)) {
		ret = csx_RequestIRQ(softp->client_handle, &irq_req);
		if (ret != CS_SUCCESS) {
#ifdef  ATA_DEBUG
			cmn_err(CE_CONT, "socket %d RequestIRQ failed %s\n",
				softp->sn, pcata_CS_etext(ret));
#endif
			mutex_exit(&softp->ata_mutex);
			return (ret);
		}
		softp->flags |= PCATA_REQUESTIRQ;
	}

	/*
	 * Initialize high level interrupt mutex.
	 */
	if (!(softp->flags & PCATA_DIDLOCKS2)) {
		mutex_init(&softp->hi_mutex, NULL,
		    MUTEX_DRIVER, *(irq_req.iblk_cookie));
		softp->flags |= PCATA_DIDLOCKS2;
	}

	/*
	 * Configure the card.
	 */
	config_req.Attributes	= 0;
	config_req.Vcc		= cis_vars->ata_vcc;
	config_req.Vpp1		= cis_vars->ata_vpp1;
	config_req.Vpp2		= cis_vars->ata_vpp2;
	config_req.IntType	= SOCKET_INTERFACE_MEMORY_AND_IO;
	config_req.ConfigBase	= cis_vars->config_base;
	config_req.Status	= 0;
	config_req.Pin		= cis_vars->pin;
	config_req.Copy		= 0;
	config_req.ConfigIndex	= cis_vars->config_index;
	config_req.Present	= cis_vars->present;

	if (!(softp->flags & PCATA_REQUESTCONFIG)) {

		ret = csx_RequestConfiguration(
			softp->client_handle,
			&config_req);
		if (ret != CS_SUCCESS) {
#ifdef  ATA_DEBUG
			cmn_err(CE_CONT,
				"socket %d RequestConfiguration failed %s\n",
				softp->sn,
				pcata_CS_etext(ret));
#endif
			mutex_exit(&softp->ata_mutex);
			return (ret);
		}
		softp->flags |= PCATA_REQUESTCONFIG;
	}

#ifdef  ATA_DEBUG
	if (pcata_debug & DPCM)
		cmn_err(CE_CONT, "_card_insertion: configuration complete\n");
#endif

	mutex_exit(&softp->ata_mutex);
	mutex_enter(&softp->event_hilock);
	softp->card_state = PCATA_WAIT_FOR_READY;
	mutex_exit(&softp->event_hilock);

	/*
	 * check the disk (every .05 sec) to see if it is ready
	 */
	for (i = 0; i < PCATA_READY_TIMEOUT; i += 50000) {
		(void) csx_GetStatus(softp->client_handle, &get_status);
		if (get_status.CardState & CS_EVENT_CARD_READY)
			break;
		drv_usecwait(50000);
	}

	if ((get_status.CardState & CS_EVENT_CARD_READY) == 0) {
		/* the disk is NOT ready */
		return (CS_GENERAL_FAILURE);
	}

	mutex_enter(&softp->ata_mutex);

	/*
	 * create the device tree
	 */
	if (!(softp->flags & PCATA_MAKEDEVICENODE)) {
		if (pcata_create_device_node(softp) != CS_SUCCESS) {
			mutex_enter(&softp->event_hilock);
			cv_broadcast(&softp->readywait_cv);
			mutex_exit(&softp->event_hilock);
			mutex_exit(&softp->ata_mutex);
			return (CS_GENERAL_FAILURE);
		}
		softp->flags |= PCATA_MAKEDEVICENODE;
	}

	/*
	 * enable interrupts thru the CSX context
	 */
	bzero((caddr_t)&modify_config, sizeof (modify_config_t));
	modify_config.Socket = softp->sn;
	modify_config.Attributes =
	    CONF_IRQ_CHANGE_VALID | CONF_ENABLE_IRQ_STEERING;
	ret = csx_ModifyConfiguration(softp->client_handle, &modify_config);
	if (ret != CS_SUCCESS) {
		cmn_err(CE_CONT, "ModifyConfiguration failed %s\n",
		    pcata_CS_etext(ret));
		mutex_exit(&softp->ata_mutex);
		return (CS_GENERAL_FAILURE);
	}

	mutex_enter(&softp->event_hilock);
	softp->card_state &= ~PCATA_WAIT_FOR_READY;
	softp->card_state |= PCATA_CARD_IS_READY;
	softp->card_state |= PCATA_CARD_INSERTED;
	cv_broadcast(&softp->readywait_cv);
	mutex_exit(&softp->event_hilock);

	/* XXXX - for Volume Manager */
	if (softp->checkmedia_flag) {
		softp->checkmedia_flag = 0;
		softp->media_state = DKIO_INSERTED;
		cv_broadcast(&softp->condvar_mediastate);
#ifdef	ATA_DEBUG
		if (pcata_debug & DVOLD) {
			cmn_err(CE_CONT, "pcata_card_insertion: socket %d \n"
			    "\tdoing cv_broadcast - "
			    "softp->media_state of DKIO_INSERTED\n", softp->sn);
		}
#endif
	}

	mutex_exit(&softp->ata_mutex);
	return (CS_SUCCESS);
}

/*
 * this function may be called by several different threads simultaneously
 * the normal calling sequence is
 */
int
pcata_readywait(ata_soft_t *softp)
{
	mutex_enter(&softp->event_hilock);

	if (softp->card_state & PCATA_WAITINIT)
		cv_wait(&softp->readywait_cv, &softp->event_hilock);

	mutex_exit(&softp->event_hilock);
	return (softp->card_state & PCATA_CARD_IS_READY);
}

/*
 * Wait for minor nodes to be created before returning from attach,
 * with a 5 sec. timeout to avoid hangs should an error occur.
 */
void
pcata_minor_wait(ata_soft_t *softp)
{
	clock_t	timeout;

	timeout = ddi_get_lbolt() + drv_usectohz(5000000);
	mutex_enter(&softp->event_hilock);
	while ((softp->flags & PCATA_MAKEDEVICENODE) == 0) {
		if (cv_timedwait(&softp->readywait_cv, &softp->event_hilock,
		    timeout) == (clock_t)-1)
			break;
	}
	mutex_exit(&softp->event_hilock);
}


int
pcata_card_removal(ata_soft_t *softp, int priority)
{
	int	ret;

#ifdef ATA_DEBUG
	if (pcata_debug & DENT)
		cmn_err(CE_CONT, "_card_removal: priority=%x\n",
		    priority);
#endif

	mutex_enter(&softp->event_hilock);
	softp->card_state &= ~(PCATA_CARD_INSERTED | PCATA_WAIT_FOR_READY);
	softp->flags &= ~PCATA_READY;
	mutex_exit(&softp->event_hilock);

	/*
	 * If we're being called at high priority, we can't do much more
	 * than note that the card went away.
	 */
	if (priority & CS_EVENT_PRI_HIGH)
		return (CS_SUCCESS);

	mutex_enter(&softp->ata_mutex);

	/*
	 * If the device was open at the time the card was removed
	 * we set the ejected_while_mounted flag until all instances of the
	 * device are closed.
	 * If the device is mounted by vold it will remain open when
	 * the card is removed. If the card is inserted again it will
	 * be mounted again by vold.
	 */
	if ((softp->blk_open) || (softp->chr_open))
		softp->ejected_while_mounted = 1;
	else {
		int i;
		for (i = 0; i < NUM_PARTS; i++) {
			if (softp->lyr_open[i] != 0)
				softp->ejected_while_mounted = 1;
		}
	}

	if (softp->ejected_while_mounted) {
		cmn_err(CE_WARN, "socket%d "
				"Card is ejected & "
				"Data integrity is not guaranteed",
				softp->sn);
	}

	/* XXXX - for Volume Manager */
	if (softp->checkmedia_flag) {
		softp->checkmedia_flag = 0;
		softp->media_state = DKIO_EJECTED;
		cv_broadcast(&softp->condvar_mediastate);
#ifdef	ATA_DEBUG
		if (pcata_debug & DVOLD) {
			cmn_err(CE_CONT,
			    "pcata_card_removal: socket %d \n"
			    "\tdoing cv_broadcast - "
			    "softp->media_state of DKIO_EJECTED\n",
			    softp->sn);
		}
#endif
	}

	if (softp->flags & PCATA_REQUESTCONFIG) {
		/*
		 * Release card configuration.
		 */
		release_config_t release_config;
		if ((ret = csx_ReleaseConfiguration(softp->client_handle,
			&release_config)) != CS_SUCCESS) {

			cmn_err(CE_CONT, "socket %d ReleaseConfiguration failed"
				"%s\n",
				softp->sn, pcata_CS_etext(ret));
		} /* ReleaseConfiguration */

		softp->flags &= ~PCATA_REQUESTCONFIG;
	} /* PCATA_REQUESTCONFIG */

	if (softp->flags & PCATA_REQUESTIRQ) {
		irq_req_t irq_req;
		/*
		 * Release allocated IRQ resources.
		 */
		ret = csx_ReleaseIRQ(softp->client_handle, &irq_req);
		if (ret != CS_SUCCESS) {
			cmn_err(CE_CONT, "socket %d ReleaseIRQ failed %s\n",
				softp->sn, pcata_CS_etext(ret));
		} /* ReleaseIRQ */
		softp->flags &= ~PCATA_REQUESTIRQ;

	} /* PCATA_REQUESTIRQ */

	if (softp->flags & PCATA_DIDLOCKS2) {
		mutex_destroy(&softp->hi_mutex);
		softp->flags &= ~PCATA_DIDLOCKS2;
	}


	if (softp->flags & PCATA_REQUESTIO) {
		/*
		 * Release allocated IO resources.
		 */
		io_req_t io_req;
		if ((ret = csx_ReleaseIO(softp->client_handle,
			&io_req)) != CS_SUCCESS) {
			cmn_err(CE_CONT, "socket %d"
				"ReleaseIO failed %s\n",
				softp->sn, pcata_CS_etext(ret));
		} /* ReleaseIO */
		softp->flags &= ~PCATA_REQUESTIO;
	} /* PCATA_REQUESTIO */

	/*
	 * Remove all the device nodes.  We don't have to explictly
	 * specify the names if we want Card Services to remove
	 * all of the devices.
	 * Note that when you call RemoveDeviceNode with the Action
	 * argument set to REMOVE_ALL_DEVICE_NODES, the
	 * NumDevNodes must be zero.
	 */
	if (softp->flags & PCATA_MAKEDEVICENODE) {
		remove_device_node_t remove_device_node;

		remove_device_node.Action = REMOVE_ALL_DEVICE_NODES;
		remove_device_node.NumDevNodes = 0;

		if ((ret = csx_RemoveDeviceNode(softp->client_handle,
		    &remove_device_node)) != CS_SUCCESS) {
			cmn_err(CE_CONT, "_card_removal: socket %d "
			    "RemoveDeviceNode failed %s\n",
			    softp->sn, pcata_CS_etext(ret));
		} /* RemoveDeviceNode */
		softp->flags &= ~PCATA_MAKEDEVICENODE;
	} /* PCATA_MAKEDEVICENODE */

	pcata_drive_unsetup(softp);
	mutex_exit(&softp->ata_mutex);

	mutex_enter(&softp->event_hilock);
	cv_broadcast(&softp->readywait_cv);
	mutex_exit(&softp->event_hilock);
	return (CS_SUCCESS);
}

static void
pcata_drive_unsetup(ata_soft_t *softp)
{
	ata_unit_t	*unitp;
	struct ata_cmpkt *pktp;
	int drive;
	buf_t		*bp;

	/*
	 * free ab_active
	 */
	if ((pktp = softp->ab_active) != NULL) {
		bp = pktp->cp_bp;
		if (bp && ((bp->b_flags & B_DONE) == 0)) {
			bioerror(bp, ENXIO);
			biodone(bp);
		}
		kmem_free((void *)pktp, sizeof (*pktp));
		softp->ab_active = NULL;
	}

	/* release any packets queued on the controller */
	while ((pktp = softp->ab_head) != NULL) {
		softp->ab_head = pktp->pkt_forw;
		bp = pktp->cp_bp;
		if (bp && ((bp->b_flags & B_DONE) == 0)) {
			/* first free the packets */
			bioerror(bp, ENXIO);
			biodone(bp);
		}
		kmem_free((void *)pktp, sizeof (*pktp));
	}

	/* release the unit structures */
	while ((unitp = softp->ab_link) != NULL) {
		softp->ab_link = unitp->a_forw;
		kmem_free(unitp, sizeof (ata_unit_t));
	}

	/*
	 * now free the atarpbuf memory
	 * It is poor code practice to use artificial number of drives,
	 * but we need to be consistant with the rest of the code, hence the
	 * drive=1 value.
	 */
	for (drive = 0; drive < 1; drive++) {
		if (softp->ab_rpbp[drive]) {
			kmem_free(softp->ab_rpbp[drive],
				(sizeof (struct atarpbuf) +
				sizeof (struct scsi_inquiry)));
			softp->ab_rpbp[drive] = NULL;
		}
	}
}


/*
 * pcata_parse_cis - gets CIS information to configure the card.
 *
 * returns: CS_SUCCESS - if CIS information retreived correctly
 *	    CS_OUT_OF_RESOURCE - if no memory for cftable entry
 *	    {various CS return codes} - if problem getting CIS information
 */
int
pcata_parse_cis(ata_soft_t *softp, pcata_cftable_t **cftable)
{


	pcata_cis_vars_t *cis_vars = &softp->cis_vars;
	cistpl_config_t cistpl_config;
	cistpl_cftable_entry_t cistpl_cftable_entry;
	struct cistpl_cftable_entry_io_t *io = &cistpl_cftable_entry.io;
	cistpl_vers_1_t cistpl_vers_1;
	tuple_t tuple;
	pcata_cftable_t *cft, *ocft, *dcft, default_cftable;
	int ret, last_config_index;
	cistpl_manfid_t cistpl_manfid;

	dcft = &default_cftable;

	/*
	 * Clear the PCATA_VALID_IO_INFO flags here.
	 * These will be set if necessary as we parse the CIS and
	 * check the manufacturer specific overrides later on.
	 */
	softp->flags &= ~PCATA_VALID_IO_INFO;


	/*
	 * Clear the CIS information structure.
	 */
	bzero((caddr_t)cis_vars, sizeof (pcata_cis_vars_t));

	/*
	 * CISTPL_CONFIG processing. Search for the first config tuple
	 * so that we can get a pointer to the card's configuration
	 * registers. If this tuple is not found, there's no point
	 * in searching for anything else.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_CONFIG;
	if ((ret = csx_GetFirstTuple(softp->client_handle,
	    &tuple)) != CS_SUCCESS) {
		cmn_err(CE_CONT, "_parse_cis: socket %d CISTPL_CONFIG "
		    "tuple not found\n", softp->sn);
		return (ret);
	} /* GetFirstTuple */

	/*
	 * We shouldn't ever fail parsing this tuple.  If we do,
	 * there's probably an internal error in the CIS parser.
	 */
	ret = csx_Parse_CISTPL_CONFIG(softp->client_handle, &tuple,
		&cistpl_config);
	if (ret != CS_SUCCESS) {
		return (ret);
	}

	/*
	 * This is the last CISTPL_CFTABLE_ENTRY tuple index that
	 * we need to look at.
	 */
	last_config_index = cistpl_config.last;

	if (cistpl_config.nr) {
		cis_vars->config_base = cistpl_config.base;
		cis_vars->present = cistpl_config.present;
	} else {
		cmn_err(CE_CONT, "_parse_cis: socket %d"
			"CISTPL_CONFIG no configuration registers"
			"found\n", softp->sn);
		return (CS_BAD_CIS);
	} /* if (cistpl_config.nr) */

	/*
	 * CISTPL_VERS_1 processing. The information from this tuple is
	 * mainly used for display purposes.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_VERS_1;
	ret = csx_GetFirstTuple(softp->client_handle, &tuple);
	if (ret != CS_SUCCESS) {
		/*
		 * It's OK not to find the tuple if it's not in the CIS, but
		 *	this test will catch other errors.
		 */
		if (ret != CS_NO_MORE_ITEMS) {
			return (ret);
		}
	} else {
		/*
		 * We shouldn't ever fail parsing this tuple.  If we do,
		 * there's probably an internal error in the CIS parser.
		 */
		if ((ret = csx_Parse_CISTPL_VERS_1(softp->client_handle,
		    &tuple, &cistpl_vers_1)) != CS_SUCCESS) {

			return (ret);
		} else {
			int	i;

			cis_vars->major_revision = cistpl_vers_1.major;
			cis_vars->minor_revision = cistpl_vers_1.minor;


			/*
			 * The first byte of the unused prod_strings will be
			 * NULL since we did a bzero(cis_vars) above.
			 */
			for (i = 0; i < cistpl_vers_1.ns; i++)
				(void) strcpy(cis_vars->prod_strings[i],
					cistpl_vers_1.pi[i]);

		} /* csx_Parse_CISTPL_VERS_1 */
	} /* GetFirstTuple */

	/*
	 * CISTPL_CFTABLE_ENTRY processing. Search for the first config tuple
	 * so that we can get a card configuration. If this tuple is not
	 * found, there's no point in searching for anything else.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	if ((ret = csx_GetFirstTuple(softp->client_handle,
	    &tuple)) != CS_SUCCESS) {
		cmn_err(CE_CONT,
			"_parse_cis: socket %d CISTPL_CFTABLE_ENTRY "
				"tuple not found\n", softp->sn);
		return (ret);
	} /* GetFirstTuple */

	/*
	 * Clear the default values.
	 */
	bzero((caddr_t)dcft, sizeof (pcata_cftable_t));


	/*
	 * Some cards don't provide enough information
	 * in their CIS to allow us to configure them
	 * using CIS information alone, so we have to
	 * set some default values here.
	 */
	dcft->p.ata_vcc = 50;


	/*
	 * Loop through the CISTPL_CFTABLE_ENTRY tuple until we find a
	 * valid configuration.
	 */
	do {

		ocft = kmem_zalloc(sizeof (pcata_cftable_t), KM_NOSLEEP);
		if (!ocft) {
			return (CS_OUT_OF_RESOURCE);
		}
		bzero((caddr_t)ocft, sizeof (pcata_cftable_t));

		if (!*cftable) {
			*cftable = ocft;
			cft = ocft;
			cft->prev = NULL;
		} else {
			cft->next = ocft;
			cft->next->prev = cft;
			cft = cft->next;
		}

		cft->next = NULL;

		bzero((caddr_t)&cistpl_cftable_entry,
			sizeof (struct cistpl_cftable_entry_t));

		/*
		 * We shouldn't ever fail parsing this tuple.  If we do,
		 * there's probably an internal error in the CIS parser.
		 */
		if ((ret = csx_Parse_CISTPL_CFTABLE_ENTRY(
			softp->client_handle, &tuple,
			&cistpl_cftable_entry)) != CS_SUCCESS) {
			return (ret);

		} else {
			int default_cftable;

			/*
			 * See if this tuple has default values that we
			 * should save. If so, copy the default values
			 * that we've seen so far into the current cftable
			 * structure.
			 */
			if (cistpl_cftable_entry.flags &
				CISTPL_CFTABLE_TPCE_DEFAULT) {
				default_cftable = 1;
			} else {
				default_cftable = 0;
			}

			bcopy((caddr_t)&dcft->p, (caddr_t)&cft->p,
				sizeof (pcata_cftable_params_t));

			cft->p.config_index = cistpl_cftable_entry.index;


			if (cistpl_cftable_entry.flags &
				CISTPL_CFTABLE_TPCE_IF) {
				cft->p.pin = cistpl_cftable_entry.pin;
			if (default_cftable)
				dcft->p.pin = cistpl_cftable_entry.pin;
			}


			if (cistpl_cftable_entry.flags &
				CISTPL_CFTABLE_TPCE_FS_PWR) {
				struct cistpl_cftable_entry_pd_t *pd;

				pd = &cistpl_cftable_entry.pd;

				if (pd->flags &
					CISTPL_CFTABLE_TPCE_FS_PWR_VCC) {
					if (pd->pd_vcc.nomV_flags &
						CISTPL_CFTABLE_PD_EXISTS) {
						cft->p.ata_vcc =
							pd->pd_vcc.nomV;
						if (default_cftable)
							dcft->p.ata_vcc =
								pd->pd_vcc.nomV;
					} /* CISTPL_CFTABLE_PD_EXISTS */
				} /* CISTPL_CFTABLE_TPCE_FS_PWR_VCC */

				if (pd->flags &
					CISTPL_CFTABLE_TPCE_FS_PWR_VPP1) {
					if (pd->pd_vpp1.nomV_flags &
						CISTPL_CFTABLE_PD_EXISTS) {
						cft->p.ata_vpp1 =
							pd->pd_vpp1.nomV;
						if (default_cftable)
							dcft->p.ata_vpp1 =
							    pd->pd_vpp1.nomV;
					} /* CISTPL_CFTABLE_PD_EXISTS */
				} /* CISTPL_CFTABLE_TPCE_FS_PWR_VPP1 */

				if (pd->flags &
					CISTPL_CFTABLE_TPCE_FS_PWR_VPP2) {
					if (pd->pd_vpp2.nomV_flags &
						CISTPL_CFTABLE_PD_EXISTS) {
						cft->p.ata_vpp2 =
							pd->pd_vpp2.nomV;
						if (default_cftable)
							dcft->p.ata_vpp2 =
							    pd->pd_vpp2.nomV;
					} /* CISTPL_CFTABLE_PD_EXISTS */
				} /* CISTPL_CFTABLE_TPCE_FS_PWR_VPP2 */

			} /* CISTPL_CFTABLE_TPCE_FS_PWR */

			if (cistpl_cftable_entry.flags &
				CISTPL_CFTABLE_TPCE_FS_IO) {
				softp->flags |= PCATA_VALID_IO_INFO;
				cft->p.addr_lines = io->addr_lines;
				if (default_cftable)
					dcft->p.addr_lines = io->addr_lines;

				if (io->ranges) {

					cft->p.ranges = io->ranges;
#ifdef ATA_DEBUG
					if (pcata_debug & DPCM)
						cmn_err(CE_CONT,
						"CS says ranges present: %d\n",
						io->ranges);
#endif

					cft->p.ata_base[0] =
						(uint32_t)io->range[0].addr;
					cft->p.ata_length[0] =
						(uint32_t)io->range[0].length;

					if (io->ranges == 2) {
						cft->p.ata_base[1] =
						    (uint32_t)io->range[1].addr;
						cft->p.ata_length[1] =
						    (uint32_t)io->range[1].
						    length;
					}
					if (default_cftable) {
						dcft->p.ata_base[0] =
						(uint32_t)io->range[0].addr;
						dcft->p.ata_length[0] =
						(uint32_t)io->range[0].length;
						if (io->ranges == 2) {
							dcft->p.ata_base[1] =
							(uint32_t)
							    io->range[1].addr;
							dcft->p.ata_length[1] =
							(uint32_t)
							    io->range[1].length;
						}
					}
#ifdef ATA_DEBUG
					if (pcata_debug & DPCM) {
						cmn_err(CE_CONT,
						"CS 1st io range: 0x%x+%d\n",
						(uint32_t)io->range[0].addr,
						(uint32_t)io->range[0].length);
						cmn_err(CE_CONT,
						"CS 2nd io range: 0x%x+%d\n",
						(uint32_t)io->range[1].addr,
						(uint32_t)io->range[1].length);
					}
#endif
				} else {
				/*
				 * If there's no IO ranges for this
				 * configuration, then we need to calculate
				 * the length of the IO space by using the
				 * number of IO address lines value.
				 * Or we can set the base to zero and the
				 * length to 0xf.
				 */

					if (!(cistpl_cftable_entry.io.flags &
					    CISTPL_CFTABLE_TPCE_FS_IO_RANGE)) {
						cft->p.ata_length[0] =
						    (1 << cft->p.addr_lines);
					} /* CISTPL_CFTABLE_TPCE_FS_IO_RANGE */
				} /* io->ranges */
			} /* CISTPL_CFTABLE_TPCE_FS_IO */

		} /* csx_Parse_CISTPL_CFTABLE_ENTRY */
	} while ((cistpl_cftable_entry.index != last_config_index) &&
		((ret = csx_GetNextTuple(softp->client_handle,
	    &tuple)) == CS_SUCCESS));

#ifdef	ATA_DEBUG
if (pcata_debug) {
	pcata_cftable_t *cft;

	cmn_err(CE_CONT, "====== socket %d unsorted cftable ======\n",
		(int)softp->sn);
	for (cft = *cftable; cft; cft = cft->next) {
		cmn_err(CE_CONT,
			"\n====== cftable entry ======\n"
			"desireability: 0x%x\n"
			" config_index: 0x%x\n"
			"   addr_lines: 0x%x\n"
			"    length[0]: 0x%x\n"
			"    length[1]: 0x%x\n"
			"          pin: 0x%x\n",
			(int)cft->desireability, (int)cft->p.config_index,
			(int)cft->p.addr_lines, cft->p.ata_length[0],
			cft->p.ata_length[1], (int)cft->p.pin);

		cmn_err(CE_CONT,
			"\n      ata_vcc: %d\n"
			"     ata_vpp1: %d\n"
			"     ata_vpp2: %d\n"
			"  ata_base[0]: 0x%p\n"
			"  ata_base[1]: 0x%p\n"
			"====\n",
			(int)cft->p.ata_vcc, (int)cft->p.ata_vpp1,
			(int)cft->p.ata_vpp2,
			(void *)(uintptr_t)cft->p.ata_base[0],
			(void *)(uintptr_t)cft->p.ata_base[1]);
	}

}
#endif

	/*
	 * If GetNextTuple gave us any error code other than
	 * CS_NO_MORE_ITEMS, it means that there is probably
	 * an internal error in the CIS parser.
	 */
	if ((ret != CS_SUCCESS) && (ret != CS_NO_MORE_ITEMS)) {

		return (ret);	/* this is a real error */

	}
	/*
	 * CISTPL_FUNCID and CISTPL_FUNCE processing
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_FUNCID;
	if ((ret = csx_GetFirstTuple(softp->client_handle,
	    &tuple)) != CS_SUCCESS) {
		/*
		 * It's OK not to find the tuple if it's not in the CIS, but
		 * this test will catch other errors.
		 */
		if (ret != CS_NO_MORE_ITEMS) {
			return (ret);
		}
	} else {

		do {
			cistpl_funcid_t cistpl_funcid;
			cistpl_funce_t cistpl_funce;

			bzero((caddr_t)&cistpl_funcid,
				sizeof (struct cistpl_funcid_t));

			if ((ret = csx_Parse_CISTPL_FUNCID(
				softp->client_handle,
				&tuple, &cistpl_funcid)) != CS_SUCCESS) {
				return (ret);
			}


			tuple.DesiredTuple = CISTPL_FUNCE;
			while ((ret = csx_GetNextTuple(softp->client_handle,
				&tuple)) == CS_SUCCESS) {
				bzero((caddr_t)&cistpl_funce,
					sizeof (cistpl_funce_t));

				/*
				 * Function extention parsing needs to be added
				 * for pcata in cardservices.  Function
				 * extention is required by spec but not used
				 * in the code.
				 */

				if ((ret = csx_Parse_CISTPL_FUNCE(
					softp->client_handle,
					&tuple, &cistpl_funce,
					cistpl_funcid.function)) ==
						CS_SUCCESS) {
					cmn_err(CE_WARN, "have funce!!!!!\n");

					}
			}
			tuple.DesiredTuple = CISTPL_FUNCID;
		} while ((ret = csx_GetNextTuple(softp->client_handle,
			&tuple)) == CS_SUCCESS);
	} /* GetFirstTuple */

	/*
	 * CISTPL_MANFID processing. The information from this tuple is
	 *	used to augment the information we get from the
	 *	CISTPL_FUNCID and CISTPL_FUNCE tuples.
	 */
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_MANFID;
	if ((ret = csx_GetFirstTuple(softp->client_handle,
	    &tuple)) != CS_SUCCESS) {
		/*
		 * It's OK not to find the tuple if it's not in the CIS, but
		 *	this test will catch other errors.
		 */
		if (ret != CS_NO_MORE_ITEMS) {
			cmn_err(CE_CONT, " %x \n", ret);
			return (ret);
		}
	} else {
		if ((ret = csx_Parse_CISTPL_MANFID(softp->client_handle,
			&tuple, &cistpl_manfid)) != CS_SUCCESS) {
			return (ret);
		} else {
			cis_vars->manufacturer_id = cistpl_manfid.manf;
			cis_vars->card_id = cistpl_manfid.card;
		} /* csx_Parse_CISTPL_MANFID */



	} /* GetFirstTuple */

	return (CS_SUCCESS);
}


void
pcata_destroy_cftable_list(pcata_cftable_t **cftable)
{
	pcata_cftable_t *cft, *ocft = NULL;

	cft = *cftable;

	while (cft) {
	    ocft = cft;
	    cft = cft->next;
	}

	while (ocft) {
	    cft = ocft->prev;
	    kmem_free(ocft, sizeof (pcata_cftable_t));
	    ocft = cft;
	}

	*cftable = NULL;
}



char	*
pcata_CS_etext(int ret)
{
	static error2text_t cft;

	cft.item = ret;
	(void) csx_Error2Text(&cft);

	return (cft.text);
}


/*
 * pcata_getinfo() - this routine translates the dip info dev_t and
 * 	vice versa.
 *
 *	Returns:	DDI_SUCCESS, if successful.
 *			DDI_FAILURE, if unsuccessful.
 */
/* ARGSUSED */
int
pcata_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	ata_soft_t *softp;
	int		ret;
	cs_ddi_info_t cs_ddi_info;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
	case DDI_INFO_DEVT2INSTANCE:

		cs_ddi_info.Socket = PCATA_SOCKET((dev_t)arg);
		cs_ddi_info.driver_name = pcata_name;
		ret = csx_CS_DDI_Info(&cs_ddi_info);
		if (ret != CS_SUCCESS) {
#ifdef ATA_DEBUG
			cmn_err(CE_CONT, "_getinfo: "
				"socket %d CS_DD_Info failed %s (0x%x)\n",
				cs_ddi_info.Socket,
				pcata_CS_etext(ret),
				ret);
#endif
			return (DDI_FAILURE);
		}

		switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			softp = ddi_get_soft_state(pcata_soft,
				cs_ddi_info.instance);
			*result = NULL;
			if (softp) {
				*result = softp->dip;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)cs_ddi_info.instance;
			break;
		} /* switch */
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
pcata_initchild(ata_soft_t *softp, int targ)
{
	ata_unit_t	*unitp;

	ASSERT(mutex_owned(&softp->ata_mutex));

#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		cmn_err(CE_CONT, "_initchild(%p, %d)\n",
			(void *)softp, targ);
	}
#endif

	if (softp->ab_rpbp[targ] == NULL)
		return (DDI_NOT_WELL_FORMED);

	unitp = (ata_unit_t *)kmem_zalloc(sizeof (*unitp), KM_NOSLEEP);
	if (!unitp) {
		return (DDI_NOT_WELL_FORMED);
	}

	unitp->a_blkp		= softp;
	unitp->a_forw		= softp->ab_link;
	softp->ab_link		= unitp;

	unitp->au_targ		= (char)targ;
	unitp->au_drive_bits	= (targ == 0 ? ATDH_DRIVE0 : ATDH_DRIVE1);
	unitp->au_rpbuf		= softp->ab_rpbp[targ];
	unitp->au_acyl		= 2;
	unitp->au_cyl		= unitp->au_rpbuf->atarp_fixcyls +
	    unitp->au_rpbuf->atarp_remcyls -
	    unitp->au_acyl;
	unitp->au_hd		= unitp->au_rpbuf->atarp_heads;
	unitp->au_sec		= unitp->au_rpbuf->atarp_sectors;
	unitp->au_ctl_bits	= AT_DEVCTL_D3;
	unitp->au_block_factor	= softp->ab_block_factor[targ];
	unitp->au_rd_cmd	= softp->ab_rd_cmd[targ];
	unitp->au_wr_cmd	= softp->ab_wr_cmd[targ];

	unitp->au_bytes_per_block = unitp->au_block_factor << SCTRSHFT;

#ifdef	ATA_DEBUG
	if (pcata_debug & DINIT)
		cmn_err(CE_CONT, "_initchild: "
			"targ = %d cyl = %d acyl = %d head = %d sec = %d\n",
			targ,
			unitp->au_cyl,
			unitp->au_acyl,
			unitp->au_hd,
			unitp->au_sec);
#endif

	return (DDI_SUCCESS);
}

static int
pcata_drive_setup(ata_soft_t *softp)
{
	major_t		devmajor;
	int		ret;

	devmajor = ddi_name_to_major(pcata_name);

#ifdef ATA_DEBUG
	if (pcata_debug & DPCM) {
		cmn_err(CE_CONT, "_drive_setup(%p)\n", (void *)softp);
	}
#endif

	if (!(CARD_PRESENT_VALID(softp))) {
		goto err;
	}

	/* setup card */
	softp->ab_block_factor[0]	= 1;
	softp->ab_block_factor[1]	= 1;
	softp->ab_max_transfer		= 0x100;
	softp->ab_status_flag		= 0;

	/*
	 * port addresses
	 */
	softp->ab_data			= AT_DATA;
	softp->ab_error			= AT_ERROR;
	softp->ab_feature		= AT_FEATURE;
	softp->ab_count			= AT_COUNT;
	softp->ab_sect			= AT_SECT;
	softp->ab_lcyl			= AT_LCYL;
	softp->ab_hcyl			= AT_HCYL;
	softp->ab_drvhd			= AT_DRVHD;
	softp->ab_status		= AT_STATUS;
	softp->ab_cmd			= AT_CMD;

	softp->ab_altstatus		= AT_ALTSTATUS;
	softp->ab_devctl		= AT_DEVCTL;
	softp->ab_drvaddr		= AT_DRVADDR;

	/*
	 * Future work second arg should not be hard coded (# of drives per
	 * socket).
	 * Right now in PCMCIA we have one disk per target,
	 * if and when we have disks that have multiple targets
	 * in the same socket (unlikely) then we will have multiple
	 * disks per socket.
	 */

	if (pcata_getedt(softp, 1) == DDI_FAILURE) {
		goto err;
	}

	softp->ab_block_factor[0] = (-1);
	if (pcata_set_rw_multiple(softp, 0)) {
		goto err;
	}

	mutex_enter(&softp->ata_mutex);
	ret = pcata_initchild(softp, 0);
	mutex_exit(&softp->ata_mutex);
	if (ret != DDI_SUCCESS)
		goto err;

	if (pcata_spinup(softp, 0) != DDI_SUCCESS) {
		goto err;
	}

	if (!(softp->ab_link)) {
		goto err;
	}
	/*
	 * Initialise the Partition table so that pcata_strategy can
	 * successfully read the actual vtoc information.
	 */
	pcinit_pmap(softp->ab_link);

	if (pcata_update_vtoc(softp, makedevice(devmajor,
	    PCATA_SETMINOR(softp->sn, FDISK_OFFSET)))) {
		goto err;
	}

	mutex_enter(&softp->event_hilock);
	softp->flags |= PCATA_READY;
	cv_broadcast(&softp->readywait_cv);
	mutex_exit(&softp->event_hilock);
	return (DDI_SUCCESS);
err:
	mutex_enter(&softp->event_hilock);
	cv_broadcast(&softp->readywait_cv);
	mutex_exit(&softp->event_hilock);
	return (DDI_FAILURE);
}

/* probably want to replace this with struct devnode_desc */

static struct driver_minor_data {
	char	*name;
	int	minor;
	int	type;
} id_minor_data[] = {
		{ "a",		0,	S_IFBLK},
		{ "b",		1,	S_IFBLK},
		{ "c",		2,	S_IFBLK},
		{ "d",		3,	S_IFBLK},
		{ "e",		4,	S_IFBLK},
		{ "f",		5,	S_IFBLK},
		{ "g",		6,	S_IFBLK},
		{ "h",		7,	S_IFBLK},
		{ "i",		8,	S_IFBLK},
		{ "j",		9,	S_IFBLK},
		{ "k",		10,	S_IFBLK},
		{ "l",		11,	S_IFBLK},
		{ "m",		12,	S_IFBLK},
		{ "n",		13,	S_IFBLK},
		{ "o",		14,	S_IFBLK},
		{ "p",		15,	S_IFBLK},
		{ "q",		16,	S_IFBLK},
		{ "r",		17,	S_IFBLK},
		{ "s",		18,	S_IFBLK},
		{ "t",		19,	S_IFBLK},
		{ "u",		20,	S_IFBLK},

		{ "a,raw",	0,	S_IFCHR},
		{ "b,raw",	1,	S_IFCHR},
		{ "c,raw",	2,	S_IFCHR},
		{ "d,raw",	3,	S_IFCHR},
		{ "e,raw",	4,	S_IFCHR},
		{ "f,raw",	5,	S_IFCHR},
		{ "g,raw",	6,	S_IFCHR},
		{ "h,raw",	7,	S_IFCHR},
		{ "i,raw",	8,	S_IFCHR},
		{ "j,raw",	9,	S_IFCHR},
		{ "k,raw",	10,	S_IFCHR},
		{ "l,raw",	11,	S_IFCHR},
		{ "m,raw",	12,	S_IFCHR},
		{ "n,raw",	13,	S_IFCHR},
		{ "o,raw",	14,	S_IFCHR},
		{ "p,raw",	15,	S_IFCHR},
		{ "q,raw",	16,	S_IFCHR},
		{ "r,raw",	17,	S_IFCHR},
		{ "s,raw",	18,	S_IFCHR},
		{ "t,raw",	19,	S_IFCHR},
		{ "u,raw",	20,	S_IFCHR},
};


/*
 * create the device nodes
 */
static int
pcata_create_device_node(ata_soft_t *softp)
{
	struct driver_minor_data *dmdp;
	devnode_desc_t		*dnd;
	make_device_node_t	make_device_node;
	int			ret;

	make_device_node.Action = CREATE_DEVICE_NODE;


	make_device_node.NumDevNodes =
	    sizeof (id_minor_data)/sizeof (*id_minor_data);

	make_device_node.devnode_desc =
		kmem_zalloc(sizeof (devnode_desc_t) *
		make_device_node.NumDevNodes, KM_SLEEP);


#ifdef ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_create_device_nodes socket=%d\n",
			softp->sn);
	}
#endif

	for (dnd = make_device_node.devnode_desc, dmdp = id_minor_data;
			dmdp < (id_minor_data +
			    sizeof (id_minor_data) / sizeof (id_minor_data[0]));
			dmdp++, dnd++) {
		dnd->name = dmdp->name;

		/*
		 * Later on need to incorporate the target number
		 * Right now in PCMCIA we have one disk per target,
		 * if and when we have disks that have multiple targets
		 * in the same socket (unlikely) then we will have multiple
		 * disks per socket.
		 */

		dnd->minor_num = PCATA_SETMINOR(softp->sn, dmdp->minor);

#ifdef ATA_DEBUG
		if (pcata_debug & DMKDEV) {
			cmn_err(CE_CONT,
				"_create_device_node: "
				"socket %d minor = %d minor_num = %d\n",
				    softp->sn, dmdp->minor, dnd->minor_num);
		}
#endif
		dnd->node_type = DDI_NT_BLOCK;
		dnd->spec_type = dmdp->type;
	}


	ret = csx_MakeDeviceNode(softp->client_handle, &make_device_node);
	if (ret != CS_SUCCESS) {
		cmn_err(CE_CONT, "_create_device_node "
			"socket %d MakeDeviceNode failed %s (0x%x)\n",
			    softp->sn, pcata_CS_etext(ret), ret);
	}

	/*
	 * We don't need this structure anymore since we've
	 * created the devices.  If we need to keep
	 * track of the devices that we've created
	 * for some reason, then you' want to keep
	 * this structure and the make_device_node_t
	 * structure around in a global data area.
	 */
	kmem_free(make_device_node.devnode_desc,
		sizeof (devnode_desc_t) * make_device_node.NumDevNodes);

	make_device_node.devnode_desc = NULL;
	return (ret);
}
