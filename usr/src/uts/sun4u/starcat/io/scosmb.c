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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the Starcat Solaris Mailbox Client module.  This module
 * handles mailbox messages from the SC to the OS (as opposed to messages sent
 * to specific drivers) and vice versa.  Two task queues are created upon
 * startup; one handles reading and processing of all incoming messages, while
 * the other handles transmission of all outgoing messages.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/condvar.h>
#include <sys/mutex.h>
#include <sys/disp.h>
#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/iosramio.h>
#include <sys/mboxsc.h>
#include <sys/promif.h>
#include <sys/uadmin.h>
#include <sys/cred.h>
#include <sys/taskq.h>
#include <sys/utsname.h>
#include <sys/plat_ecc_unum.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/starcat.h>
#include <sys/plat_ecc_dimm.h>
#include <sys/plat_datapath.h>

/* mailbox keys */
#define	SCDM_KEY	0x5343444d	/* 'S', 'C', 'D', 'M' */
#define	DMSC_KEY	0x444d5343	/* 'D', 'M', 'S', 'C' */

/* mailbox commands */
#define	SCDM_CMD		('S' << 8)	/* generic SSP */
#define	SCDM_CMD_SUCCESS	(SCDM_CMD | 0x1)
#define	SCDM_GOTO_OBP		(SCDM_CMD | 0x2)
#define	SCDM_GOTO_PANIC		(SCDM_CMD | 0x3)
#define	SCDM_ENVIRON		(SCDM_CMD | 0x4) /* environmental intr */
#define	SCDM_SHUTDOWN		(SCDM_CMD | 0x5) /* setkeyswitch STANDBY */
#define	SCDM_GET_NODENAME	(SCDM_CMD | 0x6) /* get domain nodename */
#define	SCDM_LOG_ECC_ERROR	(SCDM_CMD | 0x7) /* ECC error logging */
#define	SCDM_LOG_ECC_INDICTMENT	(SCDM_CMD | 0x8) /* ECC indictment logging */
#define	SCDM_LOG_ECC		(SCDM_CMD | 0x9) /* ECC info */
#define	SCDM_LOG_ECC_CAP_INIT	(SCDM_CMD | 0xa) /* ECC Capability Init */
#define	SCDM_LOG_ECC_CAP_RESP	(SCDM_CMD | 0xb) /* ECC Capability Response */
#define	SCDM_DIMM_SERIAL_ID	(SCDM_CMD | 0xc) /* DIMM ser# req/resp */
#define	SCDM_DP_ERROR_MSG	(SCDM_CMD | 0xd) /* datapath error */
#define	SCDM_DP_FAULT_MSG	(SCDM_CMD | 0xe) /* datapath fault */

/* general constants */
#define	GETMSG_TIMEOUT_MS	500
#define	PUTMSG_TIMEOUT_MS	6000
#define	MIN_INPUTQ_TASKS	2
#define	MAX_INPUTQ_TASKS	4
#define	MIN_OUTPUTQ_TASKS	2
#define	MAX_OUTPUTQ_TASKS	512
#ifndef TRUE
#define	TRUE	1
#endif
#ifndef FALSE
#define	FALSE	0
#endif

clock_t ecc_message_timeout_ms = PUTMSG_TIMEOUT_MS;

/*
 * When a message needs to be sent to the SC, an scosmb_msgdata_t should be
 * populated with the data to be used for the message, and a call to
 * scosmb_process_output should be dispatched on the scosmb_output_taskq, with
 * the address of the scosmb_msgdata_t structure as its arg.  The "length" and
 * "data" fields can be used if the message needs to include data beyond the
 * header fields (type, cmd, and transid) and that information must be recorded
 * when the message is placed on the taskq.  If appropriate for the message type
 * (e.g. nodename info that should always be the most recent available), the
 * "data" field can be set to NULL and the additional data can be assembled
 * immediately prior to sending the message in scosmb_process_output().
 *
 * If log_error is set, any errors in delivering the message cause a
 * cmn_err() message to be issued.  If it is zero, the error is expressed
 * only through return values.
 */
typedef struct {
	uint32_t	type;
	uint32_t	cmd;
	uint64_t	transid;
	uint32_t	length;
	int		log_error;
	void		*data;
} scosmb_msgdata_t;

/*
 * Datapath error and fault messages arrive unsolicited.  The message data
 * is contained in a plat_datapath_info_t structure.
 */
typedef struct {
	uint8_t		type;		/* CDS, DX, EX, CP */
	uint8_t		pad;		/* for alignment */
	uint16_t	cpuid;		/* Safari ID of base CPU */
	uint32_t	t_value;	/* SERD timeout threshold (seconds) */
} plat_datapath_info_t;

/* externally visible routines */
void scosmb_update_nodename(uint64_t transid);

/* local routines */
static void scosmb_inbox_handler();
static void scosmb_process_input(void *unused);
static int scosmb_process_output(scosmb_msgdata_t *arg);

/* local variables */
static uint8_t	scosmb_mboxsc_failed = FALSE;
static uint8_t	scosmb_mboxsc_timedout = FALSE;
static uint8_t	scosmb_nodename_event_pending = FALSE;
static char	scosmb_hdr[] = "SCOSMB:";
static kmutex_t scosmb_mutex;
static taskq_t	*scosmb_input_taskq = NULL;
static taskq_t	*scosmb_output_taskq = NULL;

static char *dperrtype[] = {
	DP_ERROR_CDS,
	DP_ERROR_DX,
	DP_ERROR_EX,
	DP_ERROR_CP
};

/*
 * Structures from modctl.h used for loadable module support.
 * SCOSMB is a "miscellaneous" module.
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Sun Fire 15000 OS Mbox Client v1.10",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};


/*
 * _init
 *
 * Loadable module support routine.  Initializes mutex and condition variables
 * and starts thread.
 */
int
_init(void)
{
	int error;

	/*
	 * Initialize the mailboxes
	 */
	if ((error = mboxsc_init(SCDM_KEY, MBOXSC_MBOX_IN,
	    scosmb_inbox_handler)) != 0) {
		cmn_err(CE_WARN, "%s mboxsc_init failed (0x%x)\n", scosmb_hdr,
		    error);
		return (error);
	}

	if ((error = mboxsc_init(DMSC_KEY, MBOXSC_MBOX_OUT, NULL)) != 0) {
		cmn_err(CE_WARN, "%s mboxsc_init failed (0x%x)\n", scosmb_hdr,
		    error);
		(void) mboxsc_fini(SCDM_KEY);
		return (error);
	}

	/*
	 * Initialize the global lock
	 */
	mutex_init(&scosmb_mutex, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Create the task queues used for processing input and output messages
	 */
	scosmb_input_taskq = taskq_create("scosmb_input_taskq", 1,
	    minclsyspri, MIN_INPUTQ_TASKS, MAX_INPUTQ_TASKS, TASKQ_PREPOPULATE);
	scosmb_output_taskq = taskq_create("scosmb_output_taskq", 1,
	    minclsyspri, MIN_OUTPUTQ_TASKS, MAX_OUTPUTQ_TASKS,
	    TASKQ_PREPOPULATE);

	/*
	 * Attempt to install the module.  If unsuccessful, uninitialize
	 * everything.
	 */
	error = mod_install(&modlinkage);
	if (error != 0) {
		taskq_destroy(scosmb_output_taskq);
		taskq_destroy(scosmb_input_taskq);
		mutex_destroy(&scosmb_mutex);
		(void) mboxsc_fini(DMSC_KEY);
		(void) mboxsc_fini(SCDM_KEY);
	}

	return (error);
}

/*
 * _fini
 *
 * Loadable module support routine. Since this routine shouldn't be unloaded (it
 * provides a critical service, and its symbols may be referenced externally),
 * EBUSY is returned to prevent unloading.
 */
int
_fini(void)
{
	return (EBUSY);
}

/*
 * _info
 *
 * Loadable module support routine.
 */
int
_info(struct modinfo *modinfop)
{
	int		error = 0;

	error = mod_info(&modlinkage, modinfop);
	return (error);
}

/*
 * scosmb_inbox_handler() - mbox API event handler.
 *
 * This routine adds an entry to the scosmb_input_taskq that will cause the
 * scosmb_process_input() routine to be called to service the SCDM mailbox.  The
 * possibility that taskq_dispatch may fail when given KM_NOSLEEP is safely
 * ignored because there can only be one message waiting in the mailbox at any
 * given time, so the current message will end up being handled by one of the
 * previously queued jobs (and a previous message presumably timed out before we
 * got around to reading it).
 */
static void
scosmb_inbox_handler()
{
	(void) taskq_dispatch(scosmb_input_taskq, scosmb_process_input, NULL,
	    KM_NOSLEEP);
}

/*
 * dp_get_cores()
 *
 * Checks cpu implementation for the input cpuid and returns
 * the number of cores.
 * If implementation cannot be determined, returns 1
 */
static int
dp_get_cores(uint16_t cpuid)
{
	int	exp, ii, impl = 0, nc, slot;

	exp = STARCAT_CPUID_TO_EXPANDER(cpuid);
	slot = STARCAT_CPUID_TO_BOARDSLOT(cpuid);
	if (slot == 1)
		nc = STARCAT_SLOT1_CPU_MAX;
	else
		nc = plat_max_cpu_units_per_board();

	/* find first with valid implementation */
	for (ii = 0; ii < nc; ii++)
		if (cpu[MAKE_CPUID(exp, slot, ii)]) {
			impl = cpunodes[MAKE_CPUID(exp, slot, ii)].
			    implementation;
			break;
		}

	if (IS_JAGUAR(impl) || IS_PANTHER(impl))
		return (2);
	else
		return (1);

}

/*
 * dp_payload_add_cpus()
 *
 * From datapath mailbox message, determines the number of and safari IDs
 * for affected cpus, then adds this info to the datapath ereport.
 *
 * Input maxcat (if set) is a count of maxcat cpus actually present - it is
 * a count of cpuids, which takes into account multi-core architecture.
 */
static int
dp_payload_add_cpus(plat_datapath_info_t *dpmsg, nvlist_t *erp, int maxcat)
{
	int		jj = 0, numcpus = 0, nummaxcpus = 0;
	int		count, exp, ii, num, ncores, ret, slot, port;
	uint16_t	*dparray, cpuid;
	uint64_t	*snarray;

	/* check for multiple core architectures */
	ncores = dp_get_cores(dpmsg->cpuid);

	/*
	 * Determine the number of cpu cores impacted
	 */
	switch (dpmsg->type) {
		case DP_CDS_TYPE:
			if (maxcat)
				nummaxcpus = ncores;
			else
				numcpus = ncores;
			break;

		case DP_DX_TYPE:
			if (maxcat)
				nummaxcpus = 2 * ncores;
			else
				numcpus = 2 * ncores;
			break;

		case DP_EX_TYPE:
			if (maxcat)
				nummaxcpus = STARCAT_SLOT1_CPU_MAX;
			else
				numcpus = plat_max_cpu_units_per_board();
			break;

		case DP_CP_TYPE:
			/*
			 * SC-DE supplies the base cpuid affected, if
			 * maxcat id was given, there's no slot 0 board
			 * present.
			 */

			if (!maxcat) {
				/* Slot 0 id was given - set numcpus */
				numcpus = plat_max_cpu_units_per_board();
			}

			/* there may/may not be maxcats. set a count anyway */
			nummaxcpus = STARCAT_SLOT1_CPU_MAX;

			break;

		default:
			ASSERT(0);
			return (-1);
	}

	/* Allocate space for cores */
	num = numcpus + nummaxcpus;
	dparray = kmem_zalloc(num * sizeof (uint16_t *), KM_SLEEP);

	/*
	 * populate dparray with impacted cores (only those present)
	 */
	exp = STARCAT_CPUID_TO_EXPANDER(dpmsg->cpuid);
	slot = STARCAT_CPUID_TO_BOARDSLOT(dpmsg->cpuid);
	port = STARCAT_CPUID_TO_LPORT(dpmsg->cpuid);

	mutex_enter(&cpu_lock);

	switch (dpmsg->type) {
		case DP_CDS_TYPE:
			/*
			 * For a CDS error, it's the reporting cpuid
			 * and it's other core (if present)
			 */
			cpuid = dpmsg->cpuid & 0xFFFB; 	/* core 0 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid = dpmsg->cpuid | 0x4; 	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;
			break;

		case DP_DX_TYPE:
			/*
			 * For a DX error, it's the reporting cpuid (all
			 * cores), and the other CPU sharing the same
			 * DX<-->DCDS interface (all cores)
			 */

			/* reporting cpuid */
			cpuid = dpmsg->cpuid & 0xFFFB; 	/* core 0 */

			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid = dpmsg->cpuid | 0x4; 	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			/* find partner cpuid */
			if (port == 0 || port == 2)
				cpuid = dpmsg->cpuid | 0x1;
			else
				cpuid = dpmsg->cpuid & 0xFFFE;

			/* add partner cpuid */
			cpuid &= 0xFFFB; 	/* core 0 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid |= 0x4; 	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;
			break;

		case DP_EX_TYPE:
			/*
			 * For an EX error, it is all cpuids (all cores)
			 * on the reporting board
			 */

			if (slot == 1) 			/* maxcat */
				count = nummaxcpus;
			else
				count = numcpus;

			for (ii = 0; ii < count; ii++) {
				cpuid = MAKE_CPUID(exp, slot, ii);
				if (cpu[cpuid])
					dparray[jj++] = cpuid;
			}
			break;

		case DP_CP_TYPE:
			/*
			 * For a CP error, it is all cpuids (all cores)
			 * on both boards (SB & IO) in the boardset
			 */

			/* Do slot 0 */
			for (ii = 0; ii < numcpus; ii++) {
				cpuid = MAKE_CPUID(exp, 0, ii);
				if (cpu[cpuid])
					dparray[jj++] = cpuid;
			}

			/* Do slot 1 */
			for (ii = 0; ii < nummaxcpus; ii++) {
				cpuid = MAKE_CPUID(exp, 1, ii);
				if (cpu[cpuid])
					dparray[jj++] = cpuid;
			}
			break;
	}

	mutex_exit(&cpu_lock);

	/*
	 * The datapath message could not be associated with any
	 * configured CPU.
	 */
	if (!jj) {
		kmem_free(dparray, num * sizeof (uint16_t *));
		ret = nvlist_add_uint32(erp, DP_LIST_SIZE, jj);
		ASSERT(ret == 0);
		return (-1);
	}

	snarray = kmem_zalloc(jj * sizeof (uint64_t *), KM_SLEEP);
	for (ii = 0; ii < jj; ii++)
		snarray[ii] = cpunodes[dparray[ii]].device_id;

	ret = nvlist_add_uint32(erp, DP_LIST_SIZE, jj);
	ret |= nvlist_add_uint16_array(erp, DP_LIST, dparray, jj);
	ret |= nvlist_add_uint64_array(erp, SN_LIST, snarray, jj);
	ASSERT(ret == 0);

	kmem_free(dparray, num * sizeof (uint16_t *));
	kmem_free(snarray, jj * sizeof (uint64_t *));

	return (0);
}

/*
 * dp_trans_event() - datapath message handler.
 *
 * Process datapath error and fault messages received from the SC.  Checks
 * for, and disregards, messages associated with I/O boards.  Otherwise,
 * extracts message info to produce a datapath ereport.
 */
static void
dp_trans_event(plat_datapath_info_t *dpmsg, int msgtype)
{
	nvlist_t	*erp, *detector, *hcelem;
	char		buf[FM_MAX_CLASS];
	int		exp, slot, i, maxcat = 0;

	/* check for I/O board message */
	exp = STARCAT_CPUID_TO_EXPANDER(dpmsg->cpuid);
	slot = STARCAT_CPUID_TO_BOARDSLOT(dpmsg->cpuid);

	if (slot) {
		mutex_enter(&cpu_lock);
		for (i = 0; i < STARCAT_SLOT1_CPU_MAX; i++) {
			if (cpu[MAKE_CPUID(exp, slot, i)]) {
				/* maxcat cpu present */
				maxcat++;
			}
		}
		mutex_exit(&cpu_lock);

		/*
		 * Ignore I/O board msg
		 */
		if (maxcat == 0)
			return;
	}

	/* allocate space for ereport */
	erp = fm_nvlist_create(NULL);

	/*
	 *
	 * Member Name	Data Type	   Comments
	 * -----------	---------	   -----------
	 * version	uint8		   0
	 * class	string		   "asic"
	 * ENA		uint64		   ENA Format 1
	 * detector	fmri		   aggregated ID data for SC-DE
	 *
	 * Datapath ereport subclasses and data payloads:
	 * There will be two types of ereports (error and fault) which will be
	 * identified by the "type" member.
	 *
	 * ereport.asic.starcat.cds.cds-dp
	 * ereport.asic.starcat.dx.dx-dp
	 * ereport.asic.starcat.sdi.sdi-dp
	 * ereport.asic.starcat.cp.cp-dp
	 *
	 * Member Name	Data Type	Comments
	 * -----------	---------	-----------
	 * erptype	uint16		derived from message type: error or
	 *				fault
	 * t-value	uint32		SC's datapath SERD timeout threshold
	 * dp-list-sz	uint8		number of dp-list array elements
	 * dp-list	array of uint16	Safari IDs of affected cpus
	 * sn-list	array of uint64	Serial numbers of affected cpus
	 *
	 */

	/* compose common ereport elements */
	detector = fm_nvlist_create(NULL);

	/*
	 * Create legacy FMRI for the detector
	 */
	switch (dpmsg->type) {
		case DP_CDS_TYPE:
		case DP_DX_TYPE:
			if (slot == 1)
				(void) snprintf(buf, FM_MAX_CLASS, "IO%d", exp);
			else
				(void) snprintf(buf, FM_MAX_CLASS, "SB%d", exp);
			break;

		case DP_EX_TYPE:
			(void) snprintf(buf, FM_MAX_CLASS, "EX%d", exp);
			break;

		case DP_CP_TYPE:
			(void) snprintf(buf, FM_MAX_CLASS, "CP");
			break;

		default:
			(void) snprintf(buf, FM_MAX_CLASS, "UNKNOWN");
			break;
	}

	hcelem = fm_nvlist_create(NULL);

	(void) nvlist_add_string(hcelem, FM_FMRI_HC_NAME, FM_FMRI_LEGACY_HC);
	(void) nvlist_add_string(hcelem, FM_FMRI_HC_ID, buf);

	(void) nvlist_add_uint8(detector, FM_VERSION, FM_HC_SCHEME_VERSION);
	(void) nvlist_add_string(detector, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	(void) nvlist_add_string(detector, FM_FMRI_HC_ROOT, "");
	(void) nvlist_add_uint32(detector, FM_FMRI_HC_LIST_SZ, 1);
	(void) nvlist_add_nvlist_array(detector, FM_FMRI_HC_LIST, &hcelem, 1);

	/* build ereport class name */
	(void) snprintf(buf, FM_MAX_CLASS, "asic.starcat.%s.%s-%s",
	    dperrtype[dpmsg->type], dperrtype[dpmsg->type],
	    FM_ERROR_DATAPATH);

	fm_ereport_set(erp, FM_EREPORT_VERSION, buf,
	    fm_ena_generate(0, FM_ENA_FMT1), detector, NULL);

	/* add payload elements */
	if (msgtype == SCDM_DP_ERROR_MSG) {
		fm_payload_set(erp,
		    DP_EREPORT_TYPE, DATA_TYPE_UINT16, DP_ERROR, NULL);
	} else {
		fm_payload_set(erp,
		    DP_EREPORT_TYPE, DATA_TYPE_UINT16, DP_FAULT, NULL);
	}

	fm_payload_set(erp, DP_TVALUE, DATA_TYPE_UINT32, dpmsg->t_value, NULL);

	if (dp_payload_add_cpus(dpmsg, erp, maxcat) == 0) {
		/* post ereport */
		fm_ereport_post(erp, EVCH_SLEEP);
	}

	/* free ereport memory */
	fm_nvlist_destroy(erp, FM_NVA_FREE);
	fm_nvlist_destroy(detector, FM_NVA_FREE);

}

/*
 * scosmb_process_input() - incoming message processing routine
 *
 * this routine attempts to read a message from the SCDM mailbox and, if
 * successful, processes the command.  if an unrecoverable error is encountered,
 * the scosmb_task thread will be terminated.
 */
/* ARGSUSED0 */
static void
scosmb_process_input(void *unused)
{
	int 			error;
	scosmb_msgdata_t	 msg;
	proc_t			*initpp;
	plat_capability_data_t	*cap;	/* capability msg contents ptr */
	int			cap_size;
	int			cap_ver_len;
	scosmb_msgdata_t	*cap_msgdatap; /* capability msg response */
	int			max_size;

	/*
	 * Attempt to read a message from the SCDM mailbox.
	 *
	 * Setup a local buffer to read incoming messages from the SC.
	 */
	cap_ver_len = strlen(utsname.release) + strlen(utsname.version) + 2;
	cap_size = sizeof (plat_capability_data_t) + cap_ver_len;
	max_size = MAX(cap_size, sizeof (plat_dimm_sid_board_data_t));

	msg.type = 0;
	msg.cmd = 0;
	msg.transid = 0;
	msg.length = max_size;
	msg.log_error = 0;
	msg.data = kmem_zalloc(max_size, KM_SLEEP);

	error = mboxsc_getmsg(SCDM_KEY, &msg.type, &msg.cmd, &msg.transid,
	    &msg.length, msg.data, GETMSG_TIMEOUT_MS);

	/*
	 * If EAGAIN or ETIMEDOUT was received, give up.  The SC can just try
	 * again if it was important.  If any other non-zero error was
	 * encountered, the mailbox service is broken, and there's nothing more
	 * we can do.
	 */
	mutex_enter(&scosmb_mutex);
	if ((error == EAGAIN) || (error == ETIMEDOUT)) {
		mutex_exit(&scosmb_mutex);
		return;
	} else if (error != 0) {
		/*
		 * The mailbox service appears to be badly broken.  If it was
		 * working previously, generate a warning and set a flag to
		 * avoid repeating the warning on subsequent failures.
		 */
		if (!scosmb_mboxsc_failed) {
			scosmb_mboxsc_failed = TRUE;
			cmn_err(CE_WARN, "%s mboxsc error (0x%x)\n", scosmb_hdr,
			    error);
		}
		mutex_exit(&scosmb_mutex);
		return;
	} else {
		/*
		 * If the mailbox module failed previously, it appears to have
		 * recovered, so we'll want to generate a warning if it fails
		 * again.
		 */
		scosmb_mboxsc_failed = FALSE;
	}
	mutex_exit(&scosmb_mutex);

	/*
	 * A message was successfully received, so go ahead and process it.
	 */
	switch (msg.cmd) {

	case SCDM_GOTO_OBP:	/* jump to OBP */
		debug_enter("SC requested jump to OBP");
		break;

	case SCDM_GOTO_PANIC:	/* Panic the domain */
		cmn_err(CE_PANIC, "%s SC requested PANIC\n", scosmb_hdr);
		break;

	case SCDM_SHUTDOWN:	/* graceful shutdown */
		cmn_err(CE_WARN, "%s SC requested a shutdown ", scosmb_hdr);
		(void) kadmin(A_SHUTDOWN, AD_HALT, NULL, kcred);
		/*
		 * In the event kadmin does not bring down the
		 * domain, environmental shutdown is forced
		 */
		/*FALLTHROUGH*/
	case SCDM_ENVIRON:	/* environmental shutdown */
		/*
		 * Send SIGPWR to init(1) it will run rc0,
		 * which will uadmin to power down.
		 */
		mutex_enter(&pidlock);
		initpp = prfind(P_INITPID);
		mutex_exit(&pidlock);


		/*
		 * If we're still booting and init(1) isn't set up yet,
		 * simply halt.
		 */
		if (initpp == NULL) {
			extern void halt(char *);
			cmn_err(CE_WARN, "%s Environmental Interrupt",
			    scosmb_hdr);
			power_down((char *)NULL);
			halt("Power off the System!\n");
		}

		/*
		 * else, graceful shutdown with inittab and all
		 * getting involved
		 */
		psignal(initpp, SIGPWR);
		break;

	case SCDM_GET_NODENAME:
		scosmb_update_nodename(msg.transid);
		break;

	case SCDM_LOG_ECC_CAP_RESP:
		/*
		 * The SC has responded to our initiator capability message
		 * issued during the boot flow via scosmb_update_nodename().
		 *
		 * Parse the incoming data, and appropriately set SC
		 * capabilities...
		 */
		cap = (plat_capability_data_t *)msg.data;
		plat_ecc_capability_sc_set(cap->capd_capability);
		break;

	case SCDM_LOG_ECC_CAP_INIT:
		/*
		 * The SC has initiated a capability messaging exchange with
		 * the OS.
		 *
		 * We start out just as we do for an SC response capability
		 * message, a parse of incoming data to appropriately set SC
		 * described capabilities...
		 */
		cap = (plat_capability_data_t *)msg.data;
		plat_ecc_capability_sc_set(cap->capd_capability);
		/*
		 * The next step is setting up our Response to the SC.
		 *
		 * Allocate memory for message data, initialize appropriately,
		 * and place a new job on the scosmb_output_taskq for
		 * SCDM_LOG_ECC_CAP_RESP, our OS capability messaging response
		 * to the SC initiated sequence detected here.
		 */
		cap_msgdatap = kmem_zalloc(sizeof (scosmb_msgdata_t), KM_SLEEP);
		cap_msgdatap->type = MBOXSC_MSG_EVENT;
		cap_msgdatap->cmd = SCDM_LOG_ECC_CAP_RESP;
		cap_msgdatap->transid = 0;
		(void) taskq_dispatch(scosmb_output_taskq,
		    (task_func_t *)scosmb_process_output, cap_msgdatap,
		    KM_SLEEP);
		break;

	case SCDM_DP_ERROR_MSG:
	case SCDM_DP_FAULT_MSG:
		dp_trans_event(msg.data, msg.cmd);
		break;

	case SCDM_DIMM_SERIAL_ID:
		(void) plat_store_mem_sids(msg.data);
		break;

	default:
		cmn_err(CE_WARN, "%s invalid command (0x%x)\n", scosmb_hdr,
		    msg.cmd);
		break;
	}

	/*
	 * Free up buffer for incoming messasge data that we allocated earlier
	 */
	kmem_free(msg.data, max_size);
}

/*
 * scosmb_process_output() - outgoing message processing routine
 *
 * This routine handles jobs that are queued on the scosmb_output_taskq, or
 * sent directly from scosmb_log_ecc_error.  Each job corresponds to a single
 * mailbox message that needs to be sent to the SC via the DMSC mailbox.  Some
 * processing of the message may be performed before it is sent to the SC,
 * depending on the value of the command field.
 */
static int
scosmb_process_output(scosmb_msgdata_t *msgdatap)
{
	int 			error;
	int			length;
	char			nodename[_SYS_NMLN];
	void			*free_data;
	int			free_data_len;
	int			cap_size;
	int			cap_ver_len;
	plat_capability_data_t	*cap = NULL;

	/*
	 * This shouldn't ever happen, but it can't hurt to check anyway.
	 */
	if (msgdatap == NULL) {
		return (EINVAL);
	}

	/*
	 * If data was passed in, we'll need to free it before returning.
	 */
	free_data = msgdatap->data;
	free_data_len = msgdatap->length;

	/*
	 * Some commands may need additional processing prior to transmission.
	 */
	switch (msgdatap->cmd) {
		/*
		 * Since the SC is only interested in the most recent value of
		 * utsname.nodename, we wait until now to collect that data.  We
		 * also use a global flag to prevent multiple event-type
		 * nodename messages from being queued at the same time for the
		 * same reason.
		 */
		case SCDM_GET_NODENAME:
			mutex_enter(&scosmb_mutex);
			length = strlen(utsname.nodename);
			ASSERT(length < _SYS_NMLN);
			if (length == 0) {
				msgdatap->length = 0;
				msgdatap->data = NULL;
			} else {
				bcopy(utsname.nodename, nodename, length);
				nodename[length++] = '\0';
				msgdatap->data = nodename;
				msgdatap->length = length;
			}
			if (msgdatap->transid == 0) {
				scosmb_nodename_event_pending = FALSE;
			}
			mutex_exit(&scosmb_mutex);
			break;

		/*
		 * SCDM_LOG_ECC_CAP_INIT
		 * Initiator Capability message from OS to SC
		 *
		 * We construct and send an initiator capability message
		 * every time we go through scosmb_update_nodename(), which
		 * works out to getting an "initiator" capability message
		 * sent from the OS to the SC during the OS boot flow.
		 *
		 * The SC also issues a request to scosmb_update_nodename()
		 * during an SC reboot.  Which results in an additional
		 * capability message exchange during SC reboot scenarios.
		 *
		 * SCDM_LOG_ECC_CAP_RESP
		 * Response Capability message from SC to OS
		 *
		 * In certain scenarios, the SC could initiate a capability
		 * messaging exchange with the OS.  Processing starts in
		 * scosmb_process_input(), where we detect an incoming
		 * initiator capability message from the SC.  We finish
		 * processing here, by sending a response capability message
		 * back to the SC that reflects OS capabilities.
		 */
		case SCDM_LOG_ECC_CAP_INIT:
			/*FALLTHROUGH*/
		case SCDM_LOG_ECC_CAP_RESP:
			mutex_enter(&scosmb_mutex);

			cap_ver_len = strlen(utsname.release) +
			    strlen(utsname.version) + 2;

			cap_size = sizeof (plat_capability_data_t) +
			    cap_ver_len;

			cap =  kmem_zalloc(cap_size, KM_SLEEP);

			cap->capd_major_version = PLAT_ECC_CAP_VERSION_MAJOR;
			cap->capd_minor_version = PLAT_ECC_CAP_VERSION_MINOR;
			cap->capd_msg_type = PLAT_ECC_CAPABILITY_MESSAGE;
			cap->capd_msg_length =  cap_size;

			cap->capd_capability =
			    PLAT_ECC_CAPABILITY_DOMAIN_DEFAULT;

			/*
			 * Build the capability solaris_version string:
			 * utsname.release + " " + utsname.version
			 */
			(void) snprintf(cap->capd_solaris_version,
			    cap_ver_len, "%s %s", utsname.release,
			    utsname.version);

			/*
			 * The capability message is constructed, now plug it
			 * into the starcat msgdatap:
			 */
			msgdatap->data   = (plat_capability_data_t *)cap;
			msgdatap->length = cap_size;

			/*
			 * Finished with initiator/response capability
			 * message set up.
			 *
			 * Note that after sending an "initiator" capability
			 * message, we can expect a subsequent "response"
			 * capability message from the SC, which we will
			 * pick up and minimally handle later,
			 * in scosmb_process_input().
			 *
			 * If we're sending a "response" capability message
			 * to the SC, then we're done once the message is sent.
			 */

			if (msgdatap->transid == 0) {
				scosmb_nodename_event_pending = FALSE;
			}
			mutex_exit(&scosmb_mutex);
			break;

		default:
			break;
	}

	/*
	 * Attempt to send the message.
	 */
	error = mboxsc_putmsg(DMSC_KEY, msgdatap->type, msgdatap->cmd,
	    &msgdatap->transid, msgdatap->length, msgdatap->data,
	    ecc_message_timeout_ms);

	/*
	 * Free any allocated memory that was passed in.
	 */
	if (free_data != NULL) {
		kmem_free(free_data, free_data_len);
	}

	if (cap != NULL) {
		kmem_free(cap, cap_size);
	}

	kmem_free(msgdatap, sizeof (scosmb_msgdata_t));

	/*
	 * If EAGAIN or ETIMEDOUT was received, give up.  The sender can try
	 * again if it was important.  If any other non-zero error was
	 * encountered, the mailbox service is broken, and there's nothing more
	 * we can do.
	 */
	mutex_enter(&scosmb_mutex);
	if ((error == EAGAIN) || (error == ETIMEDOUT)) {
		if (msgdatap->log_error && !scosmb_mboxsc_timedout) {
			/*
			 * Indictment mailbox messages use the return value to
			 * indicate a problem in the mailbox.  For Error
			 * mailbox messages, we'll have to use a syslog message.
			 */
			scosmb_mboxsc_timedout = TRUE;
			cmn_err(CE_NOTE, "!Solaris failed to send a message "
			    "(0x%x/0x%x) to the System Controller. Error: %d",
			    msgdatap->type, msgdatap->cmd, error);
		}
	} else if (error != 0) {
		/*
		 * The mailbox service appears to be badly broken.  If it was
		 * working previously, generate a warning and set a flag to
		 * avoid repeating the warning on subsequent failures.
		 */
		if (msgdatap->log_error && !scosmb_mboxsc_failed) {
			scosmb_mboxsc_failed = TRUE;
			cmn_err(CE_NOTE, "!An internal error (%d) occurred "
			    "while processing this message (0x%x/0x%x)",
			    error, msgdatap->type, msgdatap->cmd);
		}
	} else {
		/*
		 * If the mailbox module failed previously, it appears to have
		 * recovered, so we'll want to generate a warning if it fails
		 * again.
		 */
		scosmb_mboxsc_failed = scosmb_mboxsc_timedout = FALSE;
	}
	mutex_exit(&scosmb_mutex);
	return (error);
}

/*
 * scosmb_update_nodename() - nodename update routine
 *
 * this routine, which may be invoked from outside of the scosmb module, will
 * cause the current nodename to be sent to the SC.  The mailbox message sent to
 * the SC will use the indicated transaction ID, and will either be a reply
 * message if the ID is non-zero or an event message if it is 0.
 *
 * Capability messaging enhancements:
 *    Every time we move through this code flow, we put an "initiator
 *    capability message" on the message output taskq.  This action will
 *    get a capability message sent to the SC from the OS during boot
 *    scenarios.  A capability message exchange will also happen for
 *    SC reboot scenarios, as the SC will initiate a nodename update
 *    as a matter of course while coming back up.
 *
 *    We'll also get an extraneous capability message sent
 *    to the SC from time to time, but that won't hurt anything.
 */
void
scosmb_update_nodename(uint64_t transid)
{
	scosmb_msgdata_t	*msgdatap, *cap_msgdatap;

	/*
	 * If we're generating an unsolicited nodename update (presumably having
	 * been called from platmod:plat_nodename_set()), there's no need to add
	 * a new job to the queue if there is already one on it that will be
	 * sending the latest nodename data.
	 */
	mutex_enter(&scosmb_mutex);
	if (transid == 0) {
		if (scosmb_nodename_event_pending) {
			mutex_exit(&scosmb_mutex);
			return;
		} else {
			scosmb_nodename_event_pending = TRUE;
		}
	}
	mutex_exit(&scosmb_mutex);

	/*
	 * Allocate memory for the message data, initialize it, and place a new
	 * job on the scosmb_output_taskq for SCDM_GET_NODENAME.
	 */
	msgdatap = (scosmb_msgdata_t *)kmem_zalloc(sizeof (scosmb_msgdata_t),
	    KM_SLEEP);

	msgdatap->type = (transid == 0) ? MBOXSC_MSG_EVENT : MBOXSC_MSG_REPLY;
	msgdatap->cmd = SCDM_GET_NODENAME;
	msgdatap->transid = transid;
	msgdatap->log_error = 1;

	(void) taskq_dispatch(scosmb_output_taskq,
	    (task_func_t *)scosmb_process_output, msgdatap, KM_SLEEP);

	/*
	 * Next, allocate memory, initialize, and place a new job on the
	 * scosmb_output_taskq for SCDM_LOG_ECC_CAP_INIT.  That's a
	 * capability message, where we're the initiator.
	 */
	cap_msgdatap = kmem_zalloc(sizeof (scosmb_msgdata_t), KM_SLEEP);

	cap_msgdatap->type = (transid == 0) ?
	    MBOXSC_MSG_EVENT : MBOXSC_MSG_REPLY;
	cap_msgdatap->cmd = SCDM_LOG_ECC_CAP_INIT;
	cap_msgdatap->transid = transid;
	cap_msgdatap->log_error = 1;

	(void) taskq_dispatch(scosmb_output_taskq,
	    (task_func_t *)scosmb_process_output, cap_msgdatap, KM_SLEEP);
}

/*
 * scosmb_log_ecc_error() - Record ECC error information to SC
 * For ECC error messages, send the messages through a taskq mechanism
 * to prevent impaired system performance during ECC floods.  Indictment
 * messages have already passed through a taskq, so directly call the
 * output function.
 */
int
scosmb_log_ecc_error(plat_ecc_message_type_t msg_type, void *datap)
{
	scosmb_msgdata_t	*msg_header_ptr;
	uint32_t		msg_cmd, msg_length;
	int			sleep_flag, log_error;
	int			do_queue;	/* Set to 1 if taskq needed */

	/*
	 * Set header type and length for message
	 */
	switch (msg_type) {
	case PLAT_ECC_ERROR_MESSAGE:
		/*
		 * We do not want to sleep in an error logging thread.  So,
		 * we set the NOSLEEP flag and go through a taskq before we
		 * send the message.
		 */
		msg_cmd = SCDM_LOG_ECC_ERROR;
		msg_length = sizeof (plat_ecc_error_data_t);
		sleep_flag = KM_NOSLEEP;
		log_error = 1;
		do_queue = 1;
		break;
	case PLAT_ECC_ERROR2_MESSAGE:
		msg_cmd = SCDM_LOG_ECC;
		msg_length = sizeof (plat_ecc_error2_data_t);
		sleep_flag = KM_NOSLEEP;
		log_error = 1;
		do_queue = 1;
		break;
	case PLAT_ECC_INDICTMENT_MESSAGE:
		/*
		 * For indictment messages, we're allowed to sleep, and we
		 * can directly call the output function, since we've already
		 * gone through a taskq
		 */
		msg_cmd = SCDM_LOG_ECC_INDICTMENT;
		msg_length = sizeof (plat_ecc_indictment_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		do_queue = 0;
		break;
	case PLAT_ECC_INDICTMENT2_MESSAGE:
		/*
		 * For indictment2 messages, we're allowed to sleep, and we
		 * can directly call the output function, since we've already
		 * gone through a taskq
		 */
		msg_cmd = SCDM_LOG_ECC;
		msg_length = sizeof (plat_ecc_indictment2_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		do_queue = 0;
		break;

	case PLAT_ECC_DIMM_SID_MESSAGE:
		/*
		 * For DIMM sid request messages, we're allowed to sleep, and we
		 * can directly call the output function, since we've already
		 * gone through a taskq
		 */
		msg_cmd = SCDM_DIMM_SERIAL_ID;
		msg_length = sizeof (plat_dimm_sid_request_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		do_queue = 0;
		break;

	default:
		return (EINVAL);
	}

	/*
	 * Allocate memory for the mailbox message header.
	 */
	msg_header_ptr =
	    (scosmb_msgdata_t *)kmem_zalloc(sizeof (scosmb_msgdata_t),
	    sleep_flag);

	if (msg_header_ptr == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "failed to allocate space for scosmb "
		    "message header.");
#endif	/* DEBUG */
		return (ENOMEM);
	}

	msg_header_ptr->type = MBOXSC_MSG_EVENT;
	msg_header_ptr->cmd = msg_cmd;
	msg_header_ptr->transid = 0;
	msg_header_ptr->log_error = log_error;

	/*
	 * Allocate memory for the mailbox message payload.
	 */
	msg_header_ptr->length = msg_length;
	msg_header_ptr->data = kmem_zalloc((size_t)msg_length, sleep_flag);

	if (msg_header_ptr->data == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "failed to allocate space for scosmb "
		    "message data.");
#endif	/* DEBUG */
		kmem_free(msg_header_ptr, sizeof (scosmb_msgdata_t));
		return (ENOMEM);
	}

	bcopy(datap, msg_header_ptr->data, (size_t)msg_length);

	/*
	 * Based on our earlier look at the message type, we either go through
	 * a taskq or directly call the output function.
	 */
	if (do_queue != 0) {
		/*
		 * Place a new job on the scosmb_output_taskq.
		 */
		if (taskq_dispatch(scosmb_output_taskq,
		    (task_func_t *)scosmb_process_output,
		    (void *)msg_header_ptr, TQ_NOSLEEP) == TASKQID_INVALID) {
#ifdef DEBUG
			cmn_err(CE_WARN, "failed to dispatch a task to send "
			    "ECC mailbox message.");
#endif	/* DEBUG */
			kmem_free(msg_header_ptr->data, msg_header_ptr->length);
			kmem_free(msg_header_ptr, sizeof (scosmb_msgdata_t));
			return (ENOMEM);
		}
		return (0);
	} else {
		return (scosmb_process_output(msg_header_ptr));
	}
}
