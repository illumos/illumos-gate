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
 * Copyright 2023 Nexenta by DDN, Inc. All rights reserved.
 */

#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>

#include <smartpqi.h>
#include <smartpqi_hw.h>

#include <sys/scsi/scsi_types.h>
#include <sys/disp.h>
#include <sys/types.h>
#include <sys/mdb_modapi.h>

#define	INVALID_OPT_VAL ((uintptr_t)(-1))

/* ---- Forward references ---- */
static int smartpqi(uintptr_t, uint_t, int, const mdb_arg_t *);
static void smartpqi_help(void);

static const mdb_dcmd_t dcmds[] = {
	{
		"smartpqi", "-c <controller number> [-v]",
		"display smartpqi state",
		smartpqi,
		smartpqi_help
	},
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

static void smartpqi_help(void)
{
	mdb_printf("%s",
	    "-c <cntlr> display the state for <cntlr> and the no."
	    " of devices attached.\n"
	    "-v provide detailed information about each device attached.\n");
}

char *
bool_to_str(int v)
{
	return (v ? "TRUE" : "FALSE");
}

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

static void
display_sense_data(struct scsi_extended_sense data)
{
	mdb_printf("    SCSI sense data es_key 0x%x  ", data.es_key);
	mdb_printf("    es_add_code 0x%x  ", data.es_add_code);
	mdb_printf("    es_qual_code 0x%x\n", data.es_qual_code);
}

static void
display_scsi_status(struct scsi_arq_status scsi_status)
{
	mdb_printf("    req pkt status\t\t\t0x%x\n",
	    *(int8_t *)&scsi_status.sts_rqpkt_status);
	mdb_printf("    req pkt resid\t\t\t0x%x\n",
	    scsi_status.sts_rqpkt_resid);
	mdb_printf("    req pkt state\t\t\t%d\n", scsi_status.sts_rqpkt_state);
	mdb_printf("    req pkt state\t\t\t%d\n",
	    scsi_status.sts_rqpkt_statistics);
	if (scsi_status.sts_status.sts_chk)
		display_sense_data(scsi_status.sts_sensedata);
}

static char *
cmd_action_str(pqi_cmd_action_t action, char *tmpstr, int tmplen)
{
	switch (action) {
	case PQI_CMD_UNINIT:
		return ("UNINIT");
	case PQI_CMD_QUEUE:
		return ("QUEUE");
	case PQI_CMD_START:
		return ("START");
	case PQI_CMD_CMPLT:
		return ("COMPLETE");
	case PQI_CMD_TIMEOUT:
		return ("TIMEOUT");
	case PQI_CMD_FAIL:
		return ("FAIL");
	default:
		(void) mdb_snprintf(tmpstr, tmplen, "BAD ACTION <0x%x>",
		    action);
		return (tmpstr);
	}
}

struct scsi_key_strings pqi_cmds[] = {
	SCSI_CMDS_KEY_STRINGS,
	BMIC_READ,	"BMIC Read",
	BMIC_WRITE,	"BMIC Write",
	CISS_REPORT_LOG,	"CISS Report Logical",
	CISS_REPORT_PHYS,	"CISS Report Physical",
	-1,	NULL
};

static char *
mdb_cdb_to_str(uint8_t scsi_cmd, char *tmpstr, int tmplen)
{
	int	i = 0;

	while (pqi_cmds[i].key != -1) {
		if (scsi_cmd == pqi_cmds[i].key)
			return ((char *)pqi_cmds[i].message);
		i++;
	}
	(void) mdb_snprintf(tmpstr, tmplen, "<undecoded cmd 0x%x>", scsi_cmd);
	return (tmpstr);
}

static void
display_cdb(uint8_t *cdb)
{
	int	i, tmplen;
	char	tmpstr[64];

	tmplen = sizeof (tmpstr);
	mdb_printf("CDB %s", mdb_cdb_to_str(cdb[0], tmpstr, tmplen));
	for (i = 1; i < SCSI_CDB_SIZE; i++)
		mdb_printf(":%02x", cdb[i]);

	mdb_printf("\n");
}

static char *
pqi_iu_type_to_str(int val)
{
	switch (val) {
	case PQI_RESPONSE_IU_RAID_PATH_IO_SUCCESS: return ("Success");
	case PQI_RESPONSE_IU_AIO_PATH_IO_SUCCESS: return ("AIO Success");
	case PQI_RESPONSE_IU_GENERAL_MANAGEMENT: return ("General");
	case PQI_RESPONSE_IU_TASK_MANAGEMENT: return ("Task");
	case PQI_RESPONSE_IU_RAID_PATH_IO_ERROR: return ("IO Error");
	case PQI_RESPONSE_IU_AIO_PATH_IO_ERROR: return ("AIO IO Error");
	case PQI_RESPONSE_IU_AIO_PATH_DISABLED: return ("AIO Path Disabled");
	default: return ("UNHANDLED");
	}
}

static void
display_raid_error_info(uintptr_t error_info)
{
	struct pqi_raid_error_info info;
	int cnt;

	if (error_info == 0)
		return;
	if ((cnt = mdb_vread((void *)&info, sizeof (struct pqi_raid_error_info),
	    (uintptr_t)error_info)) !=
	    sizeof (struct pqi_raid_error_info)) {
		mdb_warn(" Unable to read Raid error info(%d,%p)\n",
		    cnt, error_info);
		return;
	}

	mdb_printf("    ---- Raid error info ----\n");
	mdb_printf("    data_in_result       %d\n", info.data_in_result);
	mdb_printf("    data_out_result      %d\n", info.data_out_result);
	mdb_printf("    status               %d\n", info.status);
	mdb_printf("    status_qualifier     %d\n", info.status_qualifier);
	mdb_printf("    sense_data_length    %d\n", info.sense_data_length);
	mdb_printf("    response_data_length %d\n", info.response_data_length);
	mdb_printf("    data_in_transferred  %d\n", info.data_in_transferred);
	mdb_printf("    data_out_transferred %d\n", info.data_out_transferred);
}

static void
display_io_request(pqi_io_request_t *io)
{
	if (io == (pqi_io_request_t *)0)
		return;

	mdb_printf("    ---- Command IO request ----\n");
	mdb_printf("    io_refcount\t\t\t\t%d\n", io->io_refcount);
	mdb_printf("    io_index\t\t\t\t%d\n", io->io_index);
	mdb_printf("    io_gen\t\t\t\t%d\n", io->io_gen);
	mdb_printf("    io_serviced\t\t\t\t%s\n", bool_to_str(io->io_serviced));
	mdb_printf("    io_raid_bypass\t\t\t%d\n", io->io_raid_bypass);
	mdb_printf("    io_status\t\t\t\t%d\n", io->io_status);
	mdb_printf("    io_iu\t\t\t\t0x%p\n", io->io_iu);
	mdb_printf("    io_pi\t\t\t\t%d\n", io->io_pi);
	mdb_printf("    io_iu_type\t\t\t\t%s\n",
	    pqi_iu_type_to_str(io->io_iu_type));
	display_raid_error_info((uintptr_t)io->io_error_info);
}

static int
display_cmd(pqi_cmd_t *cmdp)
{
	int			read_cnt, tmplen;
	char			tmpstr[64];
	pqi_io_request_t	pqi_io;

	tmplen = sizeof (tmpstr);
	display_cdb(cmdp->pc_cdb);
	mdb_printf("    cur action\t\t\t%s\n",
	    cmd_action_str(cmdp->pc_cur_action, tmpstr, tmplen));
	mdb_printf("    last action\t\t\t%s\n",
	    cmd_action_str(cmdp->pc_last_action, tmpstr, tmplen));
	display_scsi_status(cmdp->pc_cmd_scb);
	mdb_printf("    pc_dma_count\t\t\t%d\n", cmdp->pc_dma_count);
	mdb_printf("    pc_flags\t\t\t\t0x%x\n", cmdp->pc_flags);
	mdb_printf("    pc_statuslen\t\t\t%d\n", cmdp->pc_statuslen);
	mdb_printf("    pc_cmdlen\t\t\t\t%d\n", cmdp->pc_cmdlen);

	if (cmdp->pc_io_rqst == (pqi_io_request_t *)0)
		return (DCMD_OK);

	read_cnt = mdb_vread(&pqi_io, sizeof (pqi_io_request_t),
	    (uintptr_t)cmdp->pc_io_rqst);
	if (read_cnt == -1) {
		mdb_warn(" Error reading IO structure address 0x%p - "
		    "skipping diplay of IO commands\n",
		    cmdp->pc_io_rqst);
		return (DCMD_ERR);
	} else if (read_cnt != sizeof (pqi_io_request_t)) {
		mdb_warn(" cannot read IO structure count %d at0x%p - "
		    "skipping diplay of IO commands\n",
		    read_cnt, cmdp->pc_io_rqst);
		return (DCMD_ERR);
	} else {
		display_io_request(&pqi_io);
	}
	return (DCMD_OK);
}

/*
 * listp  - the pointer to the head of the linked list
 * sz     - size of the lest element to be read
 * current - pointer to current list_node structure in local storage
 */
static list_node_t *
pqi_list_next(list_node_t *listp, size_t sz, void *structp,
    list_node_t *current)
{
	int rval;

	if (current->list_next == (list_node_t *)listp)
		return ((list_node_t *)NULL);

	if (current->list_next == (list_node_t *)NULL)
		return ((list_node_t *)NULL);

	if (current->list_next == current->list_prev)
		return ((list_node_t *)NULL);

	rval = mdb_vread(structp, sz, (uintptr_t)current->list_next);
	if (rval == -1 || (size_t)rval != sz) {
		mdb_warn("Error reading a next list element so "
		    "skipping display of remaining elements\n");
		return ((list_node_t *)NULL);
	}
	return (current);
}

static void
pqi_list_head(list_t list, uint8_t *drvp, size_t offset,
    list_node_t **list_anchor)
{
	*list_anchor = (list_node_t *)(drvp +
	    offset + offsetof(list_t, list_head));
	if (*list_anchor == list.list_head.list_next) {
		*list_anchor = NULL;
	}
}

static int
pqi_device_list_head(list_t s_devnodes, uint8_t *addr,
    list_node_t **dev_head, struct pqi_device *dev)
{
	int rval;

	pqi_list_head(s_devnodes, addr, offsetof(struct pqi_state, s_devnodes),
	    dev_head);
	if (*dev_head == NULL)
		return (DCMD_ERR);

	rval = mdb_vread((void *)dev, sizeof (struct pqi_device),
	    (uintptr_t)s_devnodes.list_head.list_next);
	if (rval == -1) {
		mdb_warn(" cannot read device list head (0x%p)\n",
		    *dev_head);
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static int
pqi_cmd_list_head(list_t cmds, uint8_t *addr,
    list_node_t **cmd_head, struct pqi_cmd *cmdp)
{
	int rval;

	pqi_list_head(cmds, (uint8_t *)addr,
	    offsetof(struct pqi_device, pd_cmd_list),
	    cmd_head);
	/* Read in the first entry of the command list */
	rval = mdb_vread(cmdp, sizeof (struct pqi_cmd),
	    (uintptr_t)cmds.list_head.list_next);
	if (rval == -1) {
		mdb_warn(" cannot read initial entry in "
		    "command list (0x%p)\n", cmds.list_head.list_next);
	}
	return (rval);
}

static char *
pqi_get_guid(char *pd_guid)
{
	static char myguid[41];

	if (mdb_vread(myguid, sizeof (myguid) - 1, (uintptr_t)pd_guid) == -1)
		myguid[0] = '\0';

	return (myguid);
}

static void
display_device_info(pqi_device_t *dev)
{
	char str[40];

	mdb_printf("-- Device pd_target %d --\n", dev->pd_target);

	mdb_printf("pd_devtype\t\t\t\t%d\n", dev->pd_devtype);
	mdb_printf("device pd_flags\t\t\t\t0x%x\n", dev->pd_flags);
	mdb_printf("pd_active_cmds\t\t\t\t%d\n", dev->pd_active_cmds);

	mdb_printf("pd_dip\t\t\t\t\t0x%p\n", dev->pd_dip);
	mdb_printf("pd_pip\t\t\t\t\t0x%p\n", dev->pd_pip);
	mdb_printf("pd_pip_offlined\t\t\t\t0x%p\n", dev->pd_pip_offlined);

	mdb_printf("pd_online\t\t\t\t%s\n", bool_to_str(dev->pd_online));
	mdb_printf("pd_scanned\t\t\t\t%s\n", bool_to_str(dev->pd_scanned));
	mdb_printf("pd_phys_dev\t\t\t\t%s\n", bool_to_str(dev->pd_phys_dev));
	mdb_printf("pd_external_raid\t\t\t%s\n",
	    bool_to_str(dev->pd_external_raid));
	mdb_printf("pd_pd_aio_enabled\t\t\t%s\n",
	    bool_to_str(dev->pd_aio_enabled));

	mdb_printf("GUID\t\t\t\t\t%s\n", pqi_get_guid(dev->pd_guid));

	(void) strncpy(str, (char *)(dev->pd_vendor), sizeof (dev->pd_vendor));
	str[sizeof (dev->pd_vendor)] = '\0';
	mdb_printf("pd_vendor\t\t\t\t%s\n", str);
	(void) strncpy(str, (char *)(dev->pd_model), sizeof (dev->pd_model));
	str[sizeof (dev->pd_model)] = '\0';
	mdb_printf("pd_model\t\t\t\t%s\n", str);
}

/*
 * display device info: number of drives attached, number of commands running on
 * each device, drive data and command data.
 */
static void
pqi_display_devices(list_t s_devnodes, pqi_state_t *drvp, uint_t dev_verbose)
{
	int rval;
	int dev_count = 0;
	struct pqi_device d;
	pqi_device_t *next_dp;
	pqi_cmd_t *cmdp;

	struct list_node *list_head;
	struct list_node *d_list_head;
	struct list_node *dev_current;
	struct list_node *cmd_current;
	struct pqi_device *d_drvrp; /* driver addr of device list entry */

	mdb_printf("---- Devices for controller (0x%p) ----\n",
	    ((uint8_t *)drvp) +
	    offsetof(struct pqi_state, s_devnodes));

	rval = pqi_device_list_head(s_devnodes,
	    (uint8_t *)drvp, &d_list_head, &d);
	if (d_list_head == NULL) {
		mdb_printf("Number of devices %d\n", dev_count);
		return;
	}
	cmdp = (pqi_cmd_t *)mdb_alloc(sizeof (struct pqi_cmd), UM_SLEEP|UM_GC);

	next_dp = &d;

	dev_current = (list_node_t *)((uint8_t *)(&d) +
	    offsetof(struct pqi_device, pd_list));
	d_drvrp = (pqi_device_t *)(s_devnodes.list_head.list_next);
	while (dev_current != NULL) {
		if (dev_verbose) {
			display_device_info((pqi_device_t *)&d);

			/* now display command information */
			rval = pqi_cmd_list_head(d.pd_cmd_list,
			    (uint8_t *)d_drvrp, &list_head, cmdp);
			if (rval == -1) {
				mdb_warn("unable to read the command list head"
				    " for device %d\n", d.pd_target);
				list_head = NULL;
			}
			if (list_head != NULL) {
				mdb_printf("    ---- Commands for device %d"
				    " (0x%p) ----\n",
				    next_dp->pd_target, list_head);

				cmd_current =
				    (list_node_t *)((uint8_t *)(cmdp) +
				    offsetof(struct pqi_cmd, pc_list));

				while (cmd_current != NULL) {
					rval = display_cmd(cmdp);
					if (rval != DCMD_OK) {
						mdb_warn("Display of commands"
						    " aborted (%d)\n",
						    rval);
						break;
					}

					cmd_current = pqi_list_next(list_head,
					    sizeof (struct pqi_cmd),
					    (void *)cmdp, cmd_current);
				}
			}
		}
		d_drvrp = (pqi_device_t *)(next_dp->pd_list.list_next);
		dev_current = pqi_list_next(
		    d_list_head,
		    sizeof (struct pqi_device),
		    (void*)next_dp,
		    dev_current);
		dev_count++;
	}

	if (!dev_verbose)
		mdb_printf("Number of devices\t\t\t%d\n", dev_count);
}

static void
pqi_display_instance(pqi_state_t *pqi_statep)
{
	mdb_printf("s_dip\t\t\t\t\t0x%p\n", pqi_statep->s_dip);
	mdb_printf("s_flags\t\t\t\t\t0x%x\n", pqi_statep->s_flags);
	mdb_printf("s_firmware_version\t\t\t%s\n",
	    pqi_statep->s_firmware_version);

	mdb_printf("s_offline\t\t\t\t%s\ns_disable_mpxio\t\t\t\t%s\n",
	    bool_to_str(pqi_statep->s_offline),
	    bool_to_str(pqi_statep->s_disable_mpxio));
	mdb_printf("s_debug level\t\t\t\t%d\n", pqi_statep->s_debug_level);

	mdb_printf("---- State for watchdog----\n");
	mdb_printf("s_intr_count\t\t\t\t%d\n", pqi_statep->s_intr_count);
	mdb_printf("s_last_intr_count\t\t\t%d\n",
	    pqi_statep->s_last_intr_count);
	mdb_printf("s_last_heartbeat_count\t\t\t%d\n",
	    pqi_statep->s_last_heartbeat_count);

	mdb_printf("---- PQI cpabilities from controller ----\n");
	mdb_printf("s_max_inbound_queues\t\t\t%d\n",
	    pqi_statep->s_max_inbound_queues);
	mdb_printf("s_max_elements_per_iq\t\t\t%d\n",
	    pqi_statep->s_max_elements_per_iq);
	mdb_printf("s_max_iq_element_length\t\t\t%d\n",
	    pqi_statep->s_max_iq_element_length);
	mdb_printf("s_max_outbound_queues\t\t\t%d\n",
	    pqi_statep->s_max_outbound_queues);
	mdb_printf("s_max_elements_per_oq\t\t\t%d\n",
	    pqi_statep->s_max_elements_per_oq);
	mdb_printf("s_max_elements_per_oq\t\t\t%d\n",
	    pqi_statep->s_max_elements_per_oq);
	mdb_printf("s_max_oq_element_length\t\t\t%d\n",
	    pqi_statep->s_max_oq_element_length);
	mdb_printf("s_max_inbound_iu_length_per_firmware\t%d\n",
	    pqi_statep->s_max_inbound_iu_length_per_firmware);
	mdb_printf("s_max_inbound_queues\t\t\t%d\n",
	    pqi_statep->s_max_inbound_queues);
	mdb_printf("s_inbound_spanning_supported:\t\t%d\n",
	    pqi_statep->s_inbound_spanning_supported);
	mdb_printf("s_outbound_spanning_supported:\t\t%dk\n",
	    pqi_statep->s_outbound_spanning_supported);
	mdb_printf("s_outbound_spanning_supported:\t\t%d\n",
	    pqi_statep->s_outbound_spanning_supported);
	mdb_printf("s_pqi_mode_enabled:\t\t\t%d\n",
	    pqi_statep->s_pqi_mode_enabled);
	mdb_printf("s_cmd_queue_len\t\t\t\t%d\n", pqi_statep->s_cmd_queue_len);

	mdb_printf("---- SIS capabilities from controller ----\n");
	mdb_printf("s_max_sg_entries\t\t\t%d\n", pqi_statep->s_max_sg_entries);
	mdb_printf("s_max_xfer_size\t\t\t\t%d\n", pqi_statep->s_max_xfer_size);
	mdb_printf("s_max_outstainding_requests\t\t%d\n",
	    pqi_statep->s_max_sg_entries);

	mdb_printf("---- Computed values from config ----\n");
	mdb_printf("s_max_sg_per_iu\t\t\t\t%d\n", pqi_statep->s_max_sg_per_iu);
	mdb_printf("s_num_elements_per_iq\t\t\t%d\n",
	    pqi_statep->s_num_elements_per_iq);
	mdb_printf("s_num_elements_per_oq\t\t\t%d\n",
	    pqi_statep->s_num_elements_per_oq);
	mdb_printf("s_max_inbound_iu_length\t\t\t%d\n",
	    pqi_statep->s_max_inbound_iu_length);
	mdb_printf("s_num_queue_groups\t\t\t%d\n",
	    pqi_statep->s_num_queue_groups);
	mdb_printf("s_max_io_slots\t\t\t\t%d\n", pqi_statep->s_max_io_slots);
	mdb_printf("s_sg_chain_buf_length\t\t\t%d\n",
	    pqi_statep->s_sg_chain_buf_length);
	mdb_printf("s_max_sectors\t\t\t\t%d\n", pqi_statep->s_max_sectors);

	mdb_printf("---- IO slot information ----\n");
	mdb_printf("s_io_rqst_pool\t\t\t\t0x%p\n", pqi_statep->s_io_rqst_pool);
	mdb_printf("s_io_wait_cnt\t\t\t\t%d\n", pqi_statep->s_io_wait_cnt);
	mdb_printf("s_next_io_slot\t\t\t\t%d\n", pqi_statep->s_next_io_slot);
	mdb_printf("s_io_need\t\t\t\t%d\n", pqi_statep->s_io_need);
	mdb_printf("s_io_had2wait\t\t\t\t%d\n", pqi_statep->s_io_had2wait);
	mdb_printf("s_io_sig\t\t\t\t%d\n", pqi_statep->s_io_sig);
}

static int
pqi_getopts(uintptr_t addr, int argc, const mdb_arg_t *argv, uintptr_t *cntlr,
    uint_t *print_devices)
{
	uintptr_t device = INVALID_OPT_VAL;

	*cntlr = INVALID_OPT_VAL;
	*print_devices = FALSE;
	mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, print_devices,
	    'c', MDB_OPT_UINTPTR, (uintptr_t)cntlr,
	    'd', MDB_OPT_UINTPTR, (uintptr_t)&device,
	    NULL);

	if (*cntlr == INVALID_OPT_VAL) {
		mdb_warn("-c <controller> required\n");
		return (DCMD_USAGE);
	}

	return (DCMD_OK);
}

static int
smartpqi(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int array_size;
	int rval;
	int pqi_statesz = sizeof (struct pqi_state);
	uintptr_t instance = INVALID_OPT_VAL;
	uintptr_t adr;
	void   **array_vaddr;
	void   **pqi_array;
	pqi_state_t *pqi_drvp;
	struct i_ddi_soft_state ss;
	pqi_state_t *pqi_statep;
	uint_t print_devices = 0;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		/*
		 * MDB has this peculiarity that addr can be non-null
		 * from a previous invocation:
		 * e.g. 0xfffffef49cd64000::smartpqi,
		 * but flags shows that
		 * the command line is ::spamrtpqi or ::smartpai <options>
		 * To make sure the desired command line options are
		 * honored, we set addr to 0 and proceed with evaluating
		 * these command as entered.
		 */
		addr = (uintptr_t)0;
	}
	rval = pqi_getopts(addr, argc, argv, &instance, &print_devices);
	if (rval != DCMD_OK) {
		return (rval);
	}

	/* read the address of the pqi_state variable in the smartpqi driver */
	if (mdb_readvar((void *)&adr, "pqi_state") == -1) {
		mdb_warn("Cannot read pqi driver variable pqi_softstate.\n");
		return (DCMD_ERR);
	}
	/* now read the i_ddi_soft_state structure pointer */
	if (mdb_vread((void *)&ss, sizeof (ss), adr) != sizeof (ss)) {
		mdb_warn("Cannot read smartpqi softstate struct"
		    " pqi_state (Invalid pointer?(0x%p)).\n",
		    (uintptr_t)adr);
		return (DCMD_ERR);
	}
	/*
	 * now allocate space for the array containing the pqi_state
	 * pointers and read in this array
	 */
	array_size = ss.n_items * (sizeof (void*));
	array_vaddr = ss.array;
	pqi_array = (void **)mdb_alloc(array_size, UM_SLEEP|UM_GC);
	if (mdb_vread(pqi_array, array_size, (uintptr_t)array_vaddr) !=
	    array_size) {
		mdb_warn("Corrupted softstate struct\n");
		return (DCMD_ERR);
	}

	if (instance >= ss.n_items || pqi_array[instance] == NULL) {
		mdb_warn("smartpqi - no information available for %d\n",
		    instance);
		return (DCMD_USAGE);
	}

	pqi_statep = mdb_alloc(sizeof (struct pqi_state), UM_SLEEP|UM_GC);
	adr = (uintptr_t)pqi_array[instance];

	pqi_drvp = (pqi_state_t *)adr;
	if (mdb_vread(pqi_statep, pqi_statesz, adr) != pqi_statesz) {
		mdb_warn("Cannot read pqi_state. adr 0x%p, size %d\n",
		    adr, pqi_statesz);
		return (DCMD_ERR);
	}
	mdb_printf("-------- Controller %d  pqi_state (0x%p) --------\n",
	    instance, adr);
	pqi_display_instance(pqi_statep);

	pqi_display_devices(pqi_statep->s_devnodes, pqi_drvp, print_devices);

	return (DCMD_OK);
}
