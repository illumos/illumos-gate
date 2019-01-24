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

/* Copyright 2010 QLogic Corporation */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) qlc mdb source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#pragma ident	"Copyright 2010 QLogic Corporation; ql_mdb.c"

#include <sys/mdb_modapi.h>
#include <ql_apps.h>
#include <ql_api.h>
#include <ql_init.h>
#include <ql_debug.h>

/*
 * local prototypes
 */
static int32_t ql_doprint(uintptr_t, int8_t *);
static void ql_dump_flags(uint64_t, int8_t **);
static int qlclinks_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlcstate_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlc_osc_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlc_wdog_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlc_getdump_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlc_gettrace_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
#if 0
static int qlc_triggerdump_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
#endif
static int qlcver_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int qlstates_walk_init(mdb_walk_state_t *);
static int qlstates_walk_step(mdb_walk_state_t *);
static void qlstates_walk_fini(mdb_walk_state_t *);
static int qlsrb_walk_init(mdb_walk_state_t *);
static int qlsrb_walk_step(mdb_walk_state_t *);
static void qlsrb_walk_fini(mdb_walk_state_t *);
static int get_next_link(ql_link_t *);
static int get_first_link(ql_head_t *, ql_link_t *);

static int ql_24xx_dump_dcmd(ql_adapter_state_t *, uint_t, int,
    const mdb_arg_t *);
static int ql_23xx_dump_dcmd(ql_adapter_state_t *, uint_t, int,
    const mdb_arg_t *);
static int ql_25xx_dump_dcmd(ql_adapter_state_t *, uint_t, int,
    const mdb_arg_t *);
static int ql_81xx_dump_dcmd(ql_adapter_state_t *, uint_t, int,
    const mdb_arg_t *);
static void ql_elog_common(ql_adapter_state_t *, boolean_t);

/*
 * local adapter state flags strings
 */
int8_t *adapter_state_flags[] = {
	"FCA_BOUND",
	"QL_OPENED",
	"ONLINE",
	"INTERRUPTS_ENABLED",
	"ABORT_CMDS_LOOP_DOWN_TMO",
	"POINT_TO_POINT",
	"IP_ENABLED",
	"IP_INITIALIZED",
	"MENLO_LOGIN_OPERATIONAL",
	"ADAPTER_SUSPENDED",
	"ADAPTER_TIMER_BUSY",
	"PARITY_ERROR",
	"FLASH_ERRLOG_MARKER",
	"VP_ENABLED",
	"FDISC_ENABLED",
	"FUNCTION_1",
	"MPI_RESET_NEEDED",
	NULL
};

int8_t *adapter_config_flags[] = {
	"ENABLE_HARD_ADDRESS",
	"ENABLE_64BIT_ADDRESSING",
	"ENABLE_LIP_RESET",
	"ENABLE_FULL_LIP_LOGIN",
	"ENABLE_TARGET_RESET",
	"ENABLE_LINK_DOWN_REPORTING",
	"DISABLE_EXTENDED_LOGGING_TRACE",
	"ENABLE_FCP_2_SUPPORT",
	"MULTI_CHIP_ADAPTER",
	"SBUS_CARD",
	"CTRL_2300",
	"CTRL_6322",
	"CTRL_2200",
	"CTRL_2422",
	"CTRL_25XX",
	"ENABLE_EXTENDED_LOGGING",
	"DISABLE_RISC_CODE_LOAD",
	"SET_CACHE_LINE_SIZE_1",
	"CTRL_MENLO",
	"EXT_FW_INTERFACE",
	"LOAD_FLASH_FW",
	"DUMP_MAILBOX_TIMEOUT",
	"DUMP_ISP_SYSTEM_ERROR",
	"DUMP_DRIVER_COMMAND_TIMEOUT",
	"DUMP_LOOP_OFFLINE_TIMEOUT",
	"ENABLE_FWEXTTRACE",
	"ENABLE_FWFCETRACE",
	"FW_MISMATCH",
	"CTRL_81XX",
	"CTRL_8021",
	"ENABLE_FAST_TIMEOUT",
	"LR_SUPPORT",
	NULL
};

/*
 * local task daemon flags strings
 */
int8_t *task_daemon_flags[] = {
	"TASK_DAEMON_STOP_FLG",
	"TASK_DAEMON_SLEEPING_FLG",
	"TASK_DAEMON_ALIVE_FLG",
	"TASK_DAEMON_IDLE_CHK_FLG",
	"SUSPENDED_WAKEUP_FLG",
	"FC_STATE_CHANGE",
	"NEED_UNSOLICITED_BUFFERS",
	"RESET_MARKER_NEEDED",
	"RESET_ACTIVE",
	"ISP_ABORT_NEEDED",
	"ABORT_ISP_ACTIVE",
	"LOOP_RESYNC_NEEDED",
	"LOOP_RESYNC_ACTIVE",
	"LOOP_DOWN",
	"DRIVER_STALL",
	"COMMAND_WAIT_NEEDED",
	"COMMAND_WAIT_ACTIVE",
	"STATE_ONLINE",
	"ABORT_QUEUES_NEEDED",
	"TASK_DAEMON_STALLED_FLG",
	"TASK_THREAD_CALLED",
	"FIRMWARE_UP",
	"LIP_RESET_PENDING",
	"FIRMWARE_LOADED",
	"RSCN_UPDATE_NEEDED",
	"HANDLE_PORT_BYPASS_CHANGE",
	"PORT_RETRY_NEEDED",
	"TASK_DAEMON_POWERING_DOWN",
	"TD_IIDMA_NEEDED",
	"SEND_PLOGI",
	"IDC_EVENT",
	NULL
};

/*
 * local interrupt aif flags
 */
int8_t *aif_flags[] = {
	"IFLG_INTR_LEGACY",
	"IFLG_INTR_FIXED",
	"IFLG_INTR_MSI",
	"IFLG_INTR_MSIX",
	NULL
};

int8_t *qlsrb_flags[] = {
	"SRB_ISP_STARTED",
	"SRB_ISP_COMPLETED",
	"SRB_RETRY",
	"SRB_POLL",
	"SRB_WATCHDOG_ENABLED",
	"SRB_ABORT",
	"SRB_UB_IN_FCA",
	"SRB_UB_IN_ISP",
	"SRB_UB_CALLBACK",
	"SRB_UB_RSCN",
	"SRB_UB_FCP",
	"SRB_FCP_CMD_PKT",
	"SRB_FCP_DATA_PKT",
	"SRB_FCP_RSP_PKT",
	"SRB_IP_PKT",
	"SRB_GENERIC_SERVICES_PKT",
	"SRB_COMMAND_TIMEOUT",
	"SRB_ABORTING",
	"SRB_IN_DEVICE_QUEUE",
	"SRB_IN_TOKEN_ARRAY",
	"SRB_UB_FREE_REQUESTED",
	"SRB_UB_ACQUIRED",
	"SRB_MS_PKT",
	NULL
};

int8_t *qllun_flags[] = {
	"LQF_UNTAGGED_PENDING",
	NULL
};

int8_t *qltgt_flags[] = {
	"TQF_TAPE_DEVICE",
	"TQF_QUEUE_SUSPENDED",
	"TQF_FABRIC_DEVICE",
	"TQF_INITIATOR_DEVICE",
	"TQF_RSCN_RCVD",
	"TQF_NEED_AUTHENTICATION",
	"TQF_PLOGI_PROGRS",
	"TQF_IIDMA_NEEDED",
	NULL
};

int8_t *qldump_flags[] = {
	"QL_DUMPING",
	"QL_DUMP_VALID",
	"QL_DUMP_UPLOADED",
	NULL
};

/*
 * qlclinks_dcmd
 *	mdb dcmd which prints out the ql_hba pointers
 *
 * Input:
 *	addr  = User supplied address -- error if supplied.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args -- error if non-zero.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_ERR, DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
qlclinks_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_head_t		ql_hba;
	ql_adapter_state_t	*qlstate;
	uintptr_t		hbaptr = 0;

	if ((flags & DCMD_ADDRSPEC) || argc != 0) {
		return (DCMD_USAGE);
	}

	if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
		mdb_warn("failed to read ql_hba structure");
		return (DCMD_ERR);
	}

	if (&ql_hba == NULL) {
		mdb_warn("failed to read ql_hba structure -- is qlc loaded?");
		return (DCMD_ERR);
	}

	mdb_printf("\nqlc adapter state linkages (f=0x%llx, l=0x%llx)\n\n",
	    ql_hba.first, ql_hba.last);

	if ((qlstate = (ql_adapter_state_t *)mdb_alloc(
	    sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
		mdb_warn("Unable to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}

	(void) mdb_inc_indent((ulong_t)4);
	mdb_printf("%<u>%-?s\t%-45s%</u>\n\n", "baseaddr", "instance");

	hbaptr = (uintptr_t)ql_hba.first;
	while (hbaptr != 0) {

		if (mdb_vread(qlstate, sizeof (ql_adapter_state_t),
		    hbaptr) == -1) {
			mdb_free(qlstate, sizeof (ql_adapter_state_t));
			mdb_warn("failed to read ql_adapter_state at %p",
			    hbaptr);
			return (DCMD_OK);
		}

		mdb_printf("%<b>0x%016p%t%d%</b>\n",
		    qlstate->hba.base_address, qlstate->instance);

		/*
		 * If vp exists, loop through those
		 */

		if ((qlstate->flags & VP_ENABLED) &&
		    (qlstate->vp_next != NULL)) {

			ql_adapter_state_t	*vqlstate;
			uintptr_t		vhbaptr = 0;

			vhbaptr = (uintptr_t)qlstate->vp_next;

			if ((vqlstate = (ql_adapter_state_t *)mdb_alloc(
			    sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
				mdb_warn("Unable to allocate memory for "
				    "ql_adapter_state vp\n");
				mdb_free(qlstate, sizeof (ql_adapter_state_t));
				return (DCMD_OK);
			}

			(void) mdb_inc_indent((ulong_t)30);

			mdb_printf("%<u>vp baseaddr\t\tvp index%</u>\n");

			while (vhbaptr != 0) {

				if (mdb_vread(vqlstate,
				    sizeof (ql_adapter_state_t), vhbaptr) ==
				    -1) {
					mdb_free(vqlstate,
					    sizeof (ql_adapter_state_t));
					mdb_free(qlstate,
					    sizeof (ql_adapter_state_t));
					mdb_warn("failed to read vp "
					    "ql_adapter_state at %p", vhbaptr);
					return (DCMD_OK);
				}

				mdb_printf("%<b>0x%016p%t%d%</b>\n",
				    vqlstate->hba.base_address,
				    vqlstate->vp_index);

				vhbaptr = (uintptr_t)vqlstate->vp_next;
			}

			mdb_free(vqlstate, sizeof (ql_adapter_state_t));

			(void) mdb_dec_indent((ulong_t)30);

			mdb_printf("\n");
		}

		hbaptr = (uintptr_t)qlstate->hba.next;
	}

	(void) mdb_dec_indent((ulong_t)4);

	mdb_free(qlstate, sizeof (ql_adapter_state_t));

	return (DCMD_OK);
}

/*
 * qlcver_dcmd
 *	mdb dcmd which prints out the qlc driver version the mdb
 *	module was compiled with, and the verison of qlc which is
 *	currently loaded on the machine.
 *
 * Input:
 *	addr  = User supplied address -- error if supplied.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args -- error if non-zero.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
qlcver_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int8_t		qlcversion[100];
	struct fw_table	fw_table[10], *fwt = NULL;
	uint8_t		*fwverptr = NULL;
	ql_head_t	ql_hba;
	uint32_t	found = 0;

	if ((flags & DCMD_ADDRSPEC) || argc != 0) {
		return (DCMD_USAGE);
	}

	if (mdb_readvar(&qlcversion, "qlc_driver_version") == -1) {
		mdb_warn("unable to read qlc driver version\n");
	} else {
		mdb_printf("\n%s version currently loaded is: %s\n",
		    QL_NAME, qlcversion);
	}

	mdb_printf("qlc mdb library compiled with %s version: %s\n",
	    QL_NAME, QL_VERSION);

	if ((fwverptr = (uint8_t *)(mdb_alloc(50, UM_SLEEP))) == NULL) {
		mdb_warn("unable to alloc fwverptr\n");
		return (DCMD_OK);
	}

	if (mdb_readvar(&fw_table, "fw_table") == -1) {
		mdb_warn("unable to read firmware table\n");
	} else {
		ql_adapter_state_t	*qlstate;
		uintptr_t		hbaptr = 0;

		if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
			mdb_warn("failed to read ql_hba structure");
			return (DCMD_ERR);
		}

		if ((qlstate = (ql_adapter_state_t *)mdb_alloc(
		    sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
			mdb_warn("Unable to allocate memory for "
			    "ql_adapter_state\n");
			return (DCMD_OK);
		}

		mdb_printf("\n%-8s%-11s%s\n", "f/w", "compiled", "loaded");
		mdb_printf("%<u>%-8s%-11s%-13s%s%</u>\n\n", "class", "version",
		    "version", "instance list");

		for (fwt = &fw_table[0]; fwt->fw_class; fwt++) {

			if (mdb_vread(fwverptr, sizeof (void *),
			    (uintptr_t)fwt->fw_version) == -1) {
				mdb_warn("unable to read fwverptr\n");
				mdb_free(fwverptr, sizeof (void *));
				mdb_free(qlstate, sizeof (ql_adapter_state_t));
				return (DCMD_OK);
			}

			mdb_printf("%x\t%-11s", fwt->fw_class, fwverptr);

			if (&ql_hba == NULL) {
				mdb_warn("failed to read ql_hba structure");
				hbaptr = 0;
			} else {
				hbaptr = (uintptr_t)ql_hba.first;
			}

			found = 0;
			while (hbaptr != 0) {

				if (mdb_vread(qlstate,
				    sizeof (ql_adapter_state_t), hbaptr) ==
				    -1) {
					mdb_warn("failed to read "
					    "ql_adapter_state at %p", hbaptr);
					break;
				}

				if (qlstate->fw_class == fwt->fw_class) {
					if (found == 0) {
						mdb_printf("%x.%02x.%02x\t",
						    qlstate->fw_major_version,
						    qlstate->fw_minor_version,
						    qlstate->
						    fw_subminor_version);
						mdb_printf("%d",
						    qlstate->instance);
					} else {
						mdb_printf(", %d",
						    qlstate->instance);
					}
					found = 1;
				}

				hbaptr = (uintptr_t)qlstate->hba.next;
			}

			if (found == 1) {
				mdb_printf("\n");
			} else {
				mdb_printf("not loaded\n");
			}
		}

		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_free(fwverptr, sizeof (void *));
	}

	return (DCMD_OK);
}

/*
 * qlc_el_dcmd
 *	mdb dcmd which turns the extended logging bit on or off
 *	for the specificed qlc instance(s).
 *
 * Input:
 *	addr  = User supplied address -- error if supplied.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args -- error if non-zero.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
qlc_el_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int8_t			qlcversion[100];
	boolean_t		elswitch;
	uint32_t		argcnt;
	int			mdbs;
	uint32_t		instance;
	uint32_t		qlsize = sizeof (ql_adapter_state_t);
	ql_adapter_state_t	*qlstate;
	uintptr_t		hbaptr = 0;
	ql_head_t		ql_hba;

	if ((mdbs = mdb_get_state()) == MDB_STATE_DEAD) {
		mdb_warn("Cannot change core file data (state=%xh)\n", mdbs);
		return (DCMD_OK);
	}

	if ((flags & DCMD_ADDRSPEC) || argc < 2) {
		return (DCMD_USAGE);
	}

	/*
	 * Check and make sure the driver version and the mdb versions
	 * match so all the structures and flags line up
	 */

	if (mdb_readvar(&qlcversion, "qlc_driver_version") == -1) {
		mdb_warn("unable to read qlc driver version\n");
		return (DCMD_OK);
	}

	if ((strcmp(QL_VERSION, (const char *)&qlcversion)) != 0) {
		mdb_warn("Error: qlc driver/qlc mdb version mismatch\n");
		mdb_printf("\tqlc mdb library compiled version is: %s\n",
		    QL_VERSION);
		mdb_printf("\tqlc driver version is: %s\n", qlcversion);

		return (DCMD_OK);
	}

	if ((strcasecmp(argv[0].a_un.a_str, "on")) == 0) {
		elswitch = TRUE;
	} else if ((strcasecmp(argv[0].a_un.a_str, "off")) == 0) {
		elswitch = FALSE;
	} else {
		return (DCMD_USAGE);
	}

	if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
		mdb_warn("failed to read ql_hba structure");
		return (DCMD_ERR);
	}

	if (&ql_hba == NULL) {
		mdb_warn("failed to read ql_hba structure - is qlc loaded?");
		return (DCMD_ERR);
	}

	if ((qlstate = (ql_adapter_state_t *)mdb_alloc(qlsize,
	    UM_SLEEP)) == NULL) {
		mdb_warn("Unable to allocate memory for "
		    "ql_adapter_state\n");
		return (DCMD_OK);
	}

	if ((strcasecmp(argv[1].a_un.a_str, "all")) == 0) {

		if (argc != 2) {
			mdb_free(qlstate, qlsize);
			return (DCMD_USAGE);
		}

		hbaptr = (uintptr_t)ql_hba.first;

		while (hbaptr != 0) {

			if (mdb_vread(qlstate, qlsize, hbaptr) == -1) {
				mdb_free(qlstate, qlsize);
				mdb_warn("failed to read ql_adapter_state "
				    "at %p", hbaptr);
				return (DCMD_OK);
			}

			ql_elog_common(qlstate, elswitch);

			hbaptr = (uintptr_t)qlstate->hba.next;
		}
	} else {
		for (argcnt = 1; argcnt < argc; argcnt++) {

			instance = (uint32_t)mdb_strtoull(
			    argv[argcnt].a_un.a_str);

			/* find the correct instance to change */
			hbaptr = (uintptr_t)ql_hba.first;
			while (hbaptr != 0) {

				if (mdb_vread(qlstate, qlsize, hbaptr) == -1) {
					mdb_free(qlstate, qlsize);
					mdb_warn("failed to read "
					    "ql_adapter_state at %p", hbaptr);
					return (DCMD_OK);
				}

				if (qlstate->instance == instance) {
					break;
				}

				hbaptr = (uintptr_t)qlstate->hba.next;
			}

			if (hbaptr == 0) {
				mdb_printf("instance %d is not loaded",
				    instance);
				continue;
			}

			ql_elog_common(qlstate, elswitch);
		}
	}

	mdb_free(qlstate, qlsize);

	return (DCMD_OK);
}

/*
 * qlc_elog_common
 *	mdb helper function which set/resets the extended logging bit
 *
 * Input:
 *	qlstate  = adapter state structure
 *	elswitch = boolean which specifies to reset (0) or set (1) the
 *		   extended logging bit.
 *
 * Returns:
 *
 * Context:
 *	User context.
 *
 */
static void
ql_elog_common(ql_adapter_state_t *qlstate, boolean_t elswitch)
{
	uintptr_t	hbaptr = (uintptr_t)qlstate->hba.base_address;
	size_t		qlsize = sizeof (ql_adapter_state_t);

	if (elswitch) {
		if ((qlstate->cfg_flags & CFG_ENABLE_EXTENDED_LOGGING) == 0) {

			qlstate->cfg_flags |= CFG_ENABLE_EXTENDED_LOGGING;

			if ((mdb_vwrite((const void *)qlstate, qlsize,
			    hbaptr)) != (ssize_t)qlsize) {
				mdb_warn("instance %d - unable to update",
				    qlstate->instance);
			} else {
				mdb_printf("instance %d extended logging is "
				    "now on\n", qlstate->instance);
			}
		} else {
			mdb_printf("instance %d extended logging is "
			    "already on\n", qlstate->instance);
		}
	} else {
		if ((qlstate->cfg_flags & CFG_ENABLE_EXTENDED_LOGGING) != 0) {

			qlstate->cfg_flags &= ~CFG_ENABLE_EXTENDED_LOGGING;

			if ((mdb_vwrite((const void *)qlstate, qlsize,
			    hbaptr)) != (ssize_t)qlsize) {
				mdb_warn("instance %d - unable to update",
				    qlstate->instance);
			} else {
				mdb_printf("instance %d extended logging is "
				    "now off\n", qlstate->instance);
			}
		} else {
			mdb_printf("instance %d extended logging is "
			    "already off\n", qlstate->instance);
		}
	}
}

/*
 * qlc_ocs_dcmd
 *	mdb dcmd which prints out the outstanding command array using
 *	caller supplied address (which sb the ha structure).
 *
 * Input:
 *	addr  = User supplied ha address.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 *
 */
static int
/*ARGSUSED*/
qlc_osc_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*qlstate;
	uintptr_t		qlosc, ptr1;
	uint32_t		indx, found = 0;
	ql_srb_t		*qlsrb;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if ((qlstate = (ql_adapter_state_t *)
	    mdb_alloc(sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
		mdb_warn("Unable to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}
	if (mdb_vread(qlstate, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		return (DCMD_OK);
	}

	qlosc = (uintptr_t)qlstate->outstanding_cmds;
	mdb_printf("qlc instance: %d, base addr = %llx, osc base = %p\n",
	    qlstate->instance, qlstate->hba.base_address, qlosc);

	if ((qlsrb = (ql_srb_t *)mdb_alloc(sizeof (ql_srb_t), UM_SLEEP)) ==
	    NULL) {
		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_warn("failed to allocate space for srb_t\n");
		return (DCMD_OK);
	}
	for (indx = 0; indx < MAX_OUTSTANDING_COMMANDS; indx++, qlosc += 8) {
		if (mdb_vread(&ptr1, 8, qlosc) == -1) {
			mdb_warn("failed to read ptr1, indx=%d", indx);
			break;
		}
		if (ptr1 == 0) {
			continue;
		}

		mdb_printf("osc ptr = %p, indx = %xh\n", ptr1, indx);

		if (mdb_vread(qlsrb, sizeof (ql_srb_t), ptr1) == -1) {
			mdb_warn("failed to read ql_srb_t at %p", ptr1);
			break;
		}
		(void) ql_doprint(ptr1, "struct ql_srb");
		found++;
	}

	mdb_free(qlsrb, sizeof (ql_srb_t));
	mdb_free(qlstate, sizeof (ql_adapter_state_t));

	mdb_printf("number of outstanding command srb's is: %d\n", found);

	return (DCMD_OK);
}

/*
 * qlc_wdog_dcmd
 *	mdb dcmd which prints out the commands which are linked
 *	on the watchdog linked list. Caller supplied address (which
 *	sb the ha structure).
 *
 * Input:
 *	addr  = User supplied ha address.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 *
 */
static int
/*ARGSUSED*/
qlc_wdog_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*qlstate;
	uint16_t		index, count;
	ql_head_t		*dev;
	ql_srb_t		*srb;
	ql_tgt_t		*tq;
	ql_lun_t		*lq;
	ql_link_t		*tqlink, *srblink, *lqlink;
	int			nextlink;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("Address required\n", addr);
		return (DCMD_USAGE);
	}

	if ((qlstate = (ql_adapter_state_t *)
	    mdb_alloc(sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
		mdb_warn("Unable to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}

	if (mdb_vread(qlstate, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		return (DCMD_OK);
	}

	/*
	 * Read in the device array
	 */
	dev = (ql_head_t *)
	    mdb_alloc(sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE, UM_SLEEP);

	if (mdb_vread(dev, sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE,
	    (uintptr_t)qlstate->dev) == -1) {
		mdb_warn("failed to read ql_head_t (dev) at %p", qlstate->dev);
		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_free(dev, sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE);
		return (DCMD_OK);
	}

	tqlink = (ql_link_t *)mdb_alloc(sizeof (ql_link_t), UM_SLEEP);
	tq = (ql_tgt_t *)mdb_alloc(sizeof (ql_tgt_t), UM_SLEEP);
	lqlink = (ql_link_t *)mdb_alloc(sizeof (ql_link_t), UM_SLEEP);
	lq = (ql_lun_t *)mdb_alloc(sizeof (ql_lun_t), UM_SLEEP);
	srblink = (ql_link_t *)mdb_alloc(sizeof (ql_link_t), UM_SLEEP);
	srb = (ql_srb_t *)mdb_alloc(sizeof (ql_srb_t), UM_SLEEP);

	/*
	 * Validate the devices watchdog queue
	 */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {

		/* Skip empty ones */
		if (dev[index].first == NULL) {
			continue;
		}

		mdb_printf("dev array index = %x\n", index);

		/* Loop through targets on device linked list */
		/* get the first link */

		nextlink = get_first_link(&dev[index], tqlink);

		/*
		 * traverse the targets linked list at this device array index.
		 */
		while (nextlink == DCMD_OK) {
			/* Get the target */
			if (mdb_vread(tq, sizeof (ql_tgt_t),
			    (uintptr_t)(tqlink->base_address)) == -1) {
				mdb_warn("failed to read ql_tgt at %p",
				    tqlink->base_address);
				break;
			}
			mdb_printf("tgt q base = %llx, ",
			    tqlink->base_address);

			mdb_printf("flags: (%xh)", tq->flags);

			if (tq->flags) {
				ql_dump_flags((uint64_t)tq->flags, qltgt_flags);
			}

			mdb_printf("tgt: %02x%02x%02x%02x%02x%02x%02x%02x ",
			    tq->node_name[0], tq->node_name[1],
			    tq->node_name[2], tq->node_name[3],
			    tq->node_name[4], tq->node_name[5],
			    tq->node_name[6], tq->node_name[7]);

			/*
			 * Loop through commands on this targets watchdog queue.
			 */

			/* Get the first link on the targets cmd wdg q. */
			if (tq->wdg.first == NULL) {
				mdb_printf(" watchdog list empty ");
				break;
			} else {
				if (mdb_vread(srblink, sizeof (ql_link_t),
				    (uintptr_t)tq->wdg.first) == -1) {
					mdb_warn("failed to read ql_link_t"
					    " at %p", tq->wdg.first);
					break;
				}
				/* There is aleast one. */
				count = 1;
				/*
				 * Count the remaining items in the
				 * cmd watchdog list.
				 */
				while (srblink->next != NULL) {
					/* Read in the next ql_link_t header */
					if (mdb_vread(srblink,
					    sizeof (ql_link_t),
					    (uintptr_t)srblink->next) == -1) {
						mdb_warn("failed to read"
						    " ql_link_t next at %p",
						    srblink->next);
						break;
					}
					count = (uint16_t)(count + 1);
				}
				mdb_printf(" watchdog list: %d entries\n",
				    count);
				/* get the first one again */
				if (mdb_vread(srblink, sizeof (ql_link_t),
				    (uintptr_t)tq->wdg.first) == -1) {
					mdb_warn("failed to read ql_link_t"
					    " at %p", tq->wdg.first);
					break;
				}
			}
			/*
			 * Traverse the targets cmd watchdog linked list
			 * verifying srb's from the list are on a lun cmd list.
			 */
			while (nextlink == DCMD_OK) {
				int	found = 0;
				/* get the srb */
				if (mdb_vread(srb, sizeof (ql_srb_t),
				    (uintptr_t)srblink->base_address) == -1) {
					mdb_warn("failed to read ql_srb_t"
					" at %p", srblink->base_address);
					break;
				}
				mdb_printf("ql_srb %llx ",
				    srblink->base_address);

				/*
				 * Get the lun q the srb is on
				 */
				if (mdb_vread(lq, sizeof (ql_lun_t),
				    (uintptr_t)srb->lun_queue) == -1) {
					mdb_warn("failed to read ql_srb_t"
					    " at %p", srb->lun_queue);
					break;
				}
				nextlink = get_first_link(&lq->cmd, lqlink);
				/*
				 * traverse the lun cmd linked list looking
				 * for the srb from the targets watchdog list
				 */
				while (nextlink == DCMD_OK) {
					if (srblink->base_address ==
					    lqlink->base_address) {
						mdb_printf("on lun %d cmd q\n",
						    lq->lun_no);
						found = 1;
						break;
					}
					/* get next item on lun cmd list */
					nextlink = get_next_link(lqlink);
				}
				if (!found) {
					mdb_printf("not found on lun cmd q\n");
				}
				/* get next item in the watchdog list */
				nextlink = get_next_link(srblink);
			} /* End targets command watchdog list */
			/* get next item in this target list */
			nextlink = get_next_link(tqlink);
		} /* End traverse the device targets linked list */
		mdb_printf("\n");
	} /* End device array */

	mdb_free(tq, sizeof (ql_tgt_t));
	mdb_free(lq, sizeof (ql_lun_t));
	mdb_free(srb, sizeof (ql_srb_t));
	mdb_free(tqlink, sizeof (ql_link_t));
	mdb_free(srblink, sizeof (ql_link_t));
	mdb_free(lqlink, sizeof (ql_link_t));
	mdb_free(qlstate, sizeof (ql_adapter_state_t));
	mdb_free(dev, sizeof (ql_head_t)*DEVICE_HEAD_LIST_SIZE);

	return (DCMD_OK);
}

/*
 * get_first_link
 *	Gets the first ql_link_t header on ql_head.
 *
 * Input:
 *	ql_head  = pointer to a ql_head_t structure.
 *	ql_link  = pointer to a ql_link_t structure.
 *
 * Returns:
 *	DCMD_ABORT, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
static int
get_first_link(ql_head_t *qlhead, ql_link_t *qllink)
{
	int	rval = DCMD_ABORT;

	if (qlhead != NULL) {
		if (qlhead->first != NULL) {
			/* Read in the first ql_link_t header */
			if (mdb_vread(qllink, sizeof (ql_link_t),
			    (uintptr_t)(qlhead->first)) == -1) {
				mdb_warn("failed to read ql_link_t "
				    "next at %p", qlhead->first);
			} else {
				rval = DCMD_OK;
			}
		}
	}
	return (rval);
}

/*
 * get_next_link
 *	Gets the next ql_link_t structure.
 *
 * Input:
 *	ql_link  = pointer to a ql_link_t structure.
 *
 * Returns:
 *	DCMD_ABORT, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
static int
get_next_link(ql_link_t *qllink)
{
	int	rval = DCMD_ABORT;

	if (qllink != NULL) {
		if (qllink->next != NULL) {
			/* Read in the next ql_link_t header */
			if (mdb_vread(qllink, sizeof (ql_link_t),
			    (uintptr_t)(qllink->next)) == -1) {
				mdb_warn("failed to read ql_link_t "
				    "next at %p", qllink->next);
			} else {
				rval = DCMD_OK;
			}
		}
	}
	return (rval);
}

/*
 * qlcstate_dcmd
 *	mdb dcmd which prints out the ql_state info using
 *	caller supplied address.
 *
 * Input:
 *	addr  = User supplied address.
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
static int
qlcstate_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*qlstate;
	int			verbose = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose) !=
	    argc) {
		return (DCMD_USAGE);
	}

	if ((qlstate = (ql_adapter_state_t *)
	    mdb_alloc(sizeof (ql_adapter_state_t), UM_SLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}
	if (mdb_vread(qlstate, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_free(qlstate, sizeof (ql_adapter_state_t));
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		return (DCMD_OK);
	}

	mdb_printf("qlc instance: %d, base addr = %llx\n", qlstate->instance,
	    addr);

	mdb_printf("\nadapter state flags:\n");
	ql_dump_flags((uint64_t)qlstate->flags, adapter_state_flags);
	mdb_printf("\nadapter cfg flags:\n");
	ql_dump_flags((uint64_t)qlstate->cfg_flags, adapter_config_flags);
	mdb_printf("\ntask daemon state flags:\n");
	ql_dump_flags((uint64_t)qlstate->task_daemon_flags,
	    task_daemon_flags);

	if (verbose) {
		(void) ql_doprint(addr, "struct ql_adapter_state");
	}

	mdb_free(qlstate, sizeof (ql_adapter_state_t));

	return (DCMD_OK);
}

/*
 * qlcstates_walk_init
 *	mdb walker init which prints out all qlc states info.
 *
 * Input:
 *	wsp - Pointer to walker state struct
 *
 * Returns:
 *	WALK_ERR, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qlstates_walk_init(mdb_walk_state_t *wsp)
{
	ql_head_t	ql_hba;

	if (wsp->walk_addr == 0) {
		if ((mdb_readvar(&ql_hba, "ql_hba") == -1) ||
		    (&ql_hba == NULL)) {
			mdb_warn("failed to read ql_hba structure");
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)ql_hba.first;
		wsp->walk_data = mdb_alloc(sizeof (ql_adapter_state_t),
		    UM_SLEEP);
		return (WALK_NEXT);
	} else {
		return (ql_doprint(wsp->walk_addr, "struct ql_adapter_state"));
	}
}

/*
 * qlstates_walk_step
 *	mdb walker step which prints out all qlc states info.
 *
 * Input:
 *	wsp - Pointer to walker state struct
 *
 * Returns:
 *	WALK_DONE, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qlstates_walk_step(mdb_walk_state_t *wsp)
{
	ql_adapter_state_t	*qlstate;

	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (ql_adapter_state_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ql_adapter_state at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}

	qlstate = (ql_adapter_state_t *)(wsp->walk_data);
	mdb_printf("qlc instance: %d, base addr = %llx\n",
	    qlstate->instance, wsp->walk_addr);

	mdb_printf("\nadapter state flags:\n");
	ql_dump_flags((uint64_t)qlstate->flags, adapter_state_flags);
	mdb_printf("\nadapter cfg flags:\n");
	ql_dump_flags((uint64_t)qlstate->cfg_flags, adapter_config_flags);
	mdb_printf("\ntask daemon state flags:\n");
	ql_dump_flags((uint64_t)qlstate->task_daemon_flags,
	    task_daemon_flags);

	mdb_printf("\nadapter state:\n");
	(void) ql_doprint(wsp->walk_addr, "struct ql_adapter_state");

	mdb_printf("\n");

	wsp->walk_addr = (uintptr_t)
	    (((ql_adapter_state_t *)wsp->walk_data)->hba.next);

	return (WALK_NEXT);
}

/*
 * qlstates_walk_fini
 *	mdb walker fini which wraps up the walker
 *
 * Input:
 *	wsp - Pointer to walker state struct
 *
 * Returns:
 *
 * Context:
 *	User context.
 *
 */
static void
qlstates_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ql_adapter_state_t));
}

/*
 * qlsrb_walk_init
 *	mdb walker init which prints out linked srb's
 *
 * Input:
 *	wsp - Pointer to walker ql_srb struct
 *
 * Returns:
 *	WALK_ERR, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qlsrb_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("failed to read ql_srb addr at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (ql_srb_t), UM_SLEEP);

	return (WALK_NEXT);
}

/*
 * qlcsrb_walk_step
 *	mdb walker step which prints out linked ql_srb structures
 *
 * Input:
 *	wsp - Pointer to walker srb struct
 *
 * Returns:
 *	WALK_DONE, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qlsrb_walk_step(mdb_walk_state_t *wsp)
{
	ql_srb_t	*qlsrb;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (ql_srb_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ql_srb at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	qlsrb = (ql_srb_t *)(wsp->walk_data);
	mdb_printf("ql_srb base addr = %llx\n", wsp->walk_addr);

	mdb_printf("\nql_srb flags:\n");
	ql_dump_flags((uint64_t)qlsrb->flags, qlsrb_flags);

	mdb_printf("\nql_srb:\n");
	(void) ql_doprint(wsp->walk_addr, "struct ql_srb");

	mdb_printf("\n");

	wsp->walk_addr = (uintptr_t)
	    (((ql_srb_t *)wsp->walk_data)->cmd.next);

	return (WALK_NEXT);
}

/*
 * qlsrb_walk_fini
 *	mdb walker fini which wraps up the walker
 *
 * Input:
 *	wsp - Pointer to walker state struct
 *
 * Returns:
 *
 * Context:
 *	User context.
 *
 */
static void
qlsrb_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ql_srb_t));
}

/*
 * qllunq_dcmd
 *	mdb walker which prints out lun q's
 *
 * Input:
 *	wsp - Pointer to walker ql_lun struct
 *
 * Returns:
 *	WALK_ERR, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qllunq_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("failed to read ql_lun addr at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (ql_lun_t), UM_SLEEP);

	return (WALK_NEXT);
}

/*
 * qlclunq_walk_step
 *	mdb walker step which prints out linked ql_lun structures
 *
 * Input:
 *	wsp - Pointer to walker srb struct
 *
 * Returns:
 *	WALK_DONE, or WALK_NEXT
 *
 * Context:
 *	User context.
 *
 */
static int
qllunq_walk_step(mdb_walk_state_t *wsp)
{
	ql_lun_t	*qllun;
	ql_link_t	ql_link;
	ql_link_t	*qllink;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (ql_lun_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ql_lun at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	qllun = (ql_lun_t *)(wsp->walk_data);
	mdb_printf("ql_lun base addr = %llx\n", wsp->walk_addr);

	mdb_printf("\nql_lun flags:\n");
	ql_dump_flags((uint64_t)qllun->flags, qllun_flags);

	mdb_printf("\nql_lun:\n");
	(void) ql_doprint(wsp->walk_addr, "struct ql_lun");

	mdb_printf("\n");

	qllink = (ql_link_t *)
	    (((ql_lun_t *)wsp->walk_data)->link.next);

	if (qllink == NULL) {
		return (WALK_DONE);
	} else {
		/*
		 * Read in the next link_t header
		 */
		if (mdb_vread(&ql_link, sizeof (ql_link_t),
		    (uintptr_t)qllink) == -1) {
			mdb_warn("failed to read ql_link_t "
			    "next at %p", qllink->next);
			return (WALK_DONE);
		}
		qllink = &ql_link;
	}

	wsp->walk_addr = (uintptr_t)qllink->base_address;

	return (WALK_NEXT);
}

/*
 * qllunq_walk_fini
 *	mdb walker fini which wraps up the walker
 *
 * Input:
 *	wsp - Pointer to walker state struct
 *
 * Returns:
 *
 * Context:
 *	User context.
 *
 */
static void
qllunq_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ql_lun_t));
}

/*
 * qltgtq_dcmd
 *	mdb dcmd which prints out an hs's tq struct info.
 *
 * Input:
 *	addr  = User supplied address. (NB: nust be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_USAGE, or DCMD_OK
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
qltgtq_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*ha;
	ql_link_t		*link;
	ql_tgt_t		*tq;
	uint32_t		index;
	ql_head_t		*dev;

	if ((!(flags & DCMD_ADDRSPEC)) || addr == 0) {
		mdb_warn("ql_hba structure addr is required");
		return (DCMD_USAGE);
	}

	/*
	 * Get the adapter state struct which was passed
	 */

	ha = (ql_adapter_state_t *)mdb_alloc(sizeof (ql_adapter_state_t),
	    UM_SLEEP);

	if (mdb_vread(ha, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	if (ha->dev == NULL) {
		mdb_warn("dev ptr is NULL for ha: %p", addr);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	/*
	 * Read in the device array
	 */
	dev = (ql_head_t *)
	    mdb_alloc(sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE, UM_SLEEP);

	if (mdb_vread(dev, sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE,
	    (uintptr_t)ha->dev) == -1) {
		mdb_warn("failed to read ql_head_t (dev) at %p", ha->dev);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		mdb_free(dev, sizeof (ql_head_t) * DEVICE_HEAD_LIST_SIZE);
	}

	tq = (ql_tgt_t *)mdb_alloc(sizeof (ql_tgt_t), UM_SLEEP);
	link = (ql_link_t *)mdb_alloc(sizeof (ql_link_t), UM_SLEEP);

	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {

		if (dev[index].first == NULL) {
			continue;
		}

		if (mdb_vread(link, sizeof (ql_link_t),
		    (uintptr_t)dev[index].first) == -1) {
			mdb_warn("failed to read ql_link_t at %p",
			    dev[index].first);
			break;
		}

		while (link != NULL) {
			if (mdb_vread(tq, sizeof (ql_tgt_t),
			    (uintptr_t)(link->base_address)) == -1) {
				mdb_warn("failed to read ql_tgt at %p",
				    link->base_address);
				break;
			}

			mdb_printf("tgt queue base addr = %llx\n",
			    link->base_address);

			mdb_printf("\ntgt queue flags: (%xh)\n", tq->flags);
			ql_dump_flags((uint64_t)tq->flags, qltgt_flags);

			mdb_printf("\ntgt queue:\n");

			(void) ql_doprint((uintptr_t)link->base_address,
			    "struct ql_target");

			mdb_printf("\n");

			if (get_next_link(link) != DCMD_OK) {
				break;
			}
		}
	}

	mdb_free(ha, sizeof (ql_adapter_state_t));
	mdb_free(tq, sizeof (ql_tgt_t));
	mdb_free(link, sizeof (ql_link_t));
	mdb_free(dev, sizeof (ql_head_t)*DEVICE_HEAD_LIST_SIZE);

	return (DCMD_OK);
}

/*
 * ql_triggerdump_dcmd
 *	Triggers the driver to take a firmware dump
 *
 * Input:
 *	addr  = User supplied address (optional)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array (instance #, optional).
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */

#if 0

/*ARGSUSED*/
static int
qlc_triggerdump_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ql_adapter_state_t	*qlstate;
	uintptr_t		hbaptr = NULL;
	ql_head_t		ql_hba;
	uint32_t		qlsize = sizeof (ql_adapter_state_t);
	int			mdbs;

	if ((mdbs = mdb_get_state()) == MDB_STATE_DEAD) {
		mdb_warn("Cannot change core file data (state=%xh)\n", mdbs);
		return (DCMD_OK);
	}

	if ((qlstate = (ql_adapter_state_t *)mdb_alloc(qlsize,
	    UM_SLEEP)) == NULL) {
		mdb_warn("Unable to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}

	if (addr == NULL) {
		char		*tptr;
		uint32_t	instance;

		if (argc == 0) {
			mdb_warn("must specify either the ha addr or "
			    "the instance number\n");
			mdb_free(qlstate, qlsize);
			return (DCMD_OK);
		}

		/*
		 * find the specified instance in the ha list
		 */

		instance = (uint32_t)strtol(argv[1].a_un.a_str, &tptr, 16);
		if (tptr == argv[1].a_un.a_str) {
			mdb_printf("instance # is illegal: '%s'\n",
			    argv[1].a_un.a_str);
			mdb_free(qlstate, qlsize);
			return (DCMD_OK);
		}

		if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
			mdb_warn("failed to read ql_hba structure");
			mdb_free(qlstate, qlsize);
			return (DCMD_ERR);
		}

		if (&ql_hba == NULL) {
			mdb_warn("failed to read ql_hba structure - "
			    "is qlc loaded?");
			mdb_free(qlstate, qlsize);
			return (DCMD_ERR);
		}

		hbaptr = (uintptr_t)ql_hba.first;
		while (hbaptr != NULL) {

			if (mdb_vread(qlstate, qlsize, hbaptr) == -1) {
				mdb_free(qlstate, qlsize);
				mdb_warn("failed to read "
				    "ql_adapter_state at %p", hbaptr);
				return (DCMD_OK);
			}

			if (qlstate->instance == instance) {
				break;
			}

			hbaptr = (uintptr_t)qlstate->hba.next;
		}
	} else {

		/*
		 * verify the addr specified
		 */

		if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
			mdb_warn("failed to read ql_hba structure");
			mdb_free(qlstate, qlsize);
			return (DCMD_ERR);
		}

		if (&ql_hba == NULL) {
			mdb_warn("failed to read ql_hba structure - "
			    "is qlc loaded?");
			mdb_free(qlstate, qlsize);
			return (DCMD_ERR);
		}

		hbaptr = (uintptr_t)ql_hba.first;
		while (hbaptr != NULL) {

			if (mdb_vread(qlstate, qlsize, hbaptr) == -1) {
				mdb_free(qlstate, qlsize);
				mdb_warn("failed to read "
				    "ql_adapter_state at %p", hbaptr);
				return (DCMD_OK);
			}

			if (hbaptr == addr) {
				break;
			}

			hbaptr = (uintptr_t)qlstate->hba.next;
		}
	}

	if (hbaptr == NULL) {
		mdb_free(qlstate, qlsize);
		if (argc == 0) {
			mdb_warn("addr specified is not in the hba list\n");
		} else {
			mdb_warn("instance specified does not exist\n");
		}
		return (DCMD_OK);
	}

	if (((qlstate->ql_dump_state & QL_DUMP_VALID) != 0) ||
	    (qlstate->ql_dump_ptr != NULL)) {
		mdb_warn("instance %d already has a valid dump\n",
		    qlstate->instance);
		mdb_free(qlstate, qlsize);
		return (DCMD_OK);
	}
}
#endif

/*
 * ql_getdump_dcmd
 *	prints out the firmware dump buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: must be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
static int
qlc_getdump_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*ha;
	ql_head_t		ql_hba;
	uintptr_t		hbaptr = 0;
	int			verbose = 0;

	if ((!(flags & DCMD_ADDRSPEC)) || addr == 0) {
		mdb_warn("ql_adapter_state structure addr is required");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose) !=
	    argc) {
		return (DCMD_USAGE);
	}

	/*
	 * Get the adapter state struct which was passed
	 */
	if ((ha = (ql_adapter_state_t *)mdb_alloc(sizeof (ql_adapter_state_t),
	    UM_SLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}

	/*
	 * show user which instances have valid f/w dumps available if
	 * user has specified verbose option
	 */
	if (mdb_readvar(&ql_hba, "ql_hba") == -1) {
		mdb_warn("failed to read ql_hba structure");
	} else if (&ql_hba == NULL) {
		mdb_warn("failed to read ql_hba structure -- is qlc loaded?");
	} else if (verbose) {
		hbaptr = (uintptr_t)ql_hba.first;
		while (hbaptr != 0) {

			if (mdb_vread(ha, sizeof (ql_adapter_state_t),
			    hbaptr) == -1) {
				mdb_free(ha, sizeof (ql_adapter_state_t));
				mdb_warn("failed read ql_adapter_state at %p",
				    hbaptr);
				return (DCMD_OK);
			}

			mdb_printf("instance %d:\n", ha->instance);
			(void) mdb_inc_indent((ulong_t)4);

			if (ha->ql_dump_state == 0) {
				mdb_printf("no dump flags\n");
			} else {
				ql_dump_flags((uint64_t)ha->ql_dump_state,
				    qldump_flags);
			}

			if (ha->ql_dump_ptr == NULL) {
				mdb_printf("no dump address\n");
			} else {
				mdb_printf("dump address is: %p\n",
				    ha->ql_dump_ptr);
			}

			(void) mdb_dec_indent((ulong_t)4);

			hbaptr = (uintptr_t)ha->hba.next;
		}
		mdb_printf("\n");
	}

	if (mdb_vread(ha, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	/*
	 * If its not a valid dump or there's not a f/w dump binary (???)
	 * then bail out
	 */
	if (((ha->ql_dump_state & QL_DUMP_VALID) == 0) ||
	    (ha->ql_dump_ptr == NULL)) {
		mdb_warn("dump does not exist for instance %d (%x, %p)\n",
		    ha->instance, ha->ql_dump_state, ha->ql_dump_ptr);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	if (CFG_IST(ha, CFG_CTRL_2422)) {
		(void) ql_24xx_dump_dcmd(ha, flags, argc, argv);
	} else if (CFG_IST(ha, CFG_CTRL_25XX))  {
		(void) ql_25xx_dump_dcmd(ha, flags, argc, argv);
	} else if (CFG_IST(ha, CFG_CTRL_81XX))  {
		(void) ql_81xx_dump_dcmd(ha, flags, argc, argv);
	} else if (!(CFG_IST(ha, CFG_CTRL_8021)))  {
		(void) ql_23xx_dump_dcmd(ha, flags, argc, argv);
	}

	mdb_free(ha, sizeof (ql_adapter_state_t));

	return (DCMD_OK);
}

/*
 * ql_23xx_dump_dcmd
 *	prints out a firmware dump buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: nust be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
ql_23xx_dump_dcmd(ql_adapter_state_t *ha, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ql_fw_dump_t	*fw;
	uint32_t	cnt = 0;
	int		mbox_cnt;

	fw = (ql_fw_dump_t *)mdb_alloc(ha->ql_dump_size, UM_SLEEP);

	if (mdb_vread(fw, ha->ql_dump_size,
	    (uintptr_t)ha->ql_dump_ptr) == -1) {
		mdb_warn("failed to read ql_dump_ptr (no f/w dump active?)");
		mdb_free(fw, ha->ql_dump_size);
		return (DCMD_OK);
	}

	if (ha->cfg_flags & CFG_CTRL_2300) {
		mdb_printf("\nISP 2300IP ");
	} else if (ha->cfg_flags & CFG_CTRL_6322) {
		mdb_printf("\nISP 6322FLX ");
	} else {
		mdb_printf("\nISP 2200IP ");
	}

	mdb_printf("Firmware Version %d.%d.%d\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version);

	mdb_printf("\nPBIU Registers:");
	for (cnt = 0; cnt < sizeof (fw->pbiu_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->pbiu_reg[cnt]);
	}

	if (ha->cfg_flags & (CFG_CTRL_2300 | CFG_CTRL_6322)) {
		mdb_printf("\n\nReqQ-RspQ-Risc2Host Status registers:");
		for (cnt = 0; cnt < sizeof (fw->risc_host_reg) / 2; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n");
			}
			mdb_printf("%04x  ", fw->risc_host_reg[cnt]);
		}
	}

	mdb_printf("\n\nMailbox Registers:");
	mbox_cnt = (ha->cfg_flags & (CFG_CTRL_2300 | CFG_CTRL_6322)) ? 16 : 8;
	for (cnt = 0; cnt < mbox_cnt; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->mailbox_reg[cnt]);
	}

	if (ha->cfg_flags & (CFG_CTRL_2300 | CFG_CTRL_6322)) {
		mdb_printf("\n\nAuto Request Response DMA Registers:");
		for (cnt = 0; cnt < sizeof (fw->resp_dma_reg) / 2; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n");
			}
			mdb_printf("%04x  ", fw->resp_dma_reg[cnt]);
		}
	}

	mdb_printf("\n\nDMA Registers:");
	for (cnt = 0; cnt < sizeof (fw->dma_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->dma_reg[cnt]);
	}

	mdb_printf("\n\nRISC Hardware Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_hdw_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_hdw_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP0 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp0_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp0_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP1 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp1_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp1_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP2 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp2_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp2_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP3 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp3_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp3_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP4 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp4_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp4_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP5 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp5_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp5_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP6 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp6_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp6_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP7 Registers:");
	for (cnt = 0; cnt < sizeof (fw->risc_gp7_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->risc_gp7_reg[cnt]);
	}

	mdb_printf("\n\nFrame Buffer Hardware Registers:");
	for (cnt = 0; cnt < sizeof (fw->frame_buf_hdw_reg) / 2; cnt++) {
		if ((cnt == 16) &&
		    ((ha->cfg_flags & (CFG_CTRL_2300 | CFG_CTRL_6322)) == 0)) {
			break;
		}
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->frame_buf_hdw_reg[cnt]);
	}

	mdb_printf("\n\nFPM B0 Registers:");
	for (cnt = 0; cnt < sizeof (fw->fpm_b0_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->fpm_b0_reg[cnt]);
	}

	mdb_printf("\n\nFPM B1 Registers:");
	for (cnt = 0; cnt < sizeof (fw->fpm_b1_reg) / 2; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x  ", fw->fpm_b1_reg[cnt]);
	}

	if (ha->cfg_flags & (CFG_CTRL_2300 | CFG_CTRL_6322)) {
		mdb_printf("\n\nCode RAM Dump:");
		for (cnt = 0; cnt < sizeof (fw->risc_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%05x: ", cnt + 0x0800);
			}
			mdb_printf("%04x  ", fw->risc_ram[cnt]);
		}

		mdb_printf("\n\nStack RAM Dump:");
		for (cnt = 0; cnt < sizeof (fw->stack_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%05x: ", cnt + 0x010000);
			}
			mdb_printf("%04x  ", fw->stack_ram[cnt]);
		}

		mdb_printf("\n\nData RAM Dump:");
		for (cnt = 0; cnt < sizeof (fw->data_ram) / 2; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%05x: ", cnt + 0x010800);
			}
			mdb_printf("%04x  ", fw->data_ram[cnt]);
		}

		mdb_printf("\n\n[<==END] ISP Debug Dump.\n");

		mdb_printf("\n\nRequest Queue");

		for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%08x: ", cnt);
			}
			mdb_printf("%08x ", fw->req_q[cnt]);
		}

		mdb_printf("\n\nResponse Queue");

		for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%08x: ", cnt);
			}
			mdb_printf("%08x ", fw->rsp_q[cnt]);
		}

		mdb_printf("\n");

	} else {
		mdb_printf("\n\nRISC SRAM:");
		for (cnt = 0; cnt < 0xf000; cnt++) {
			if (cnt % 8 == 0) {
				mdb_printf("\n%04x: ", cnt + 0x1000);
			}
			mdb_printf("%04x  ", fw->risc_ram[cnt]);
		}
	}

	mdb_free(fw, ha->ql_dump_size);

	return (DCMD_OK);
}

/*
 * ql_24xx_dump_dcmd
 *	prints out a firmware dump buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: nust be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
ql_24xx_dump_dcmd(ql_adapter_state_t *ha, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ql_24xx_fw_dump_t	*fw;
	uint32_t		cnt = 0;

	fw = (ql_24xx_fw_dump_t *)mdb_alloc(ha->ql_dump_size, UM_SLEEP);

	if (mdb_vread(fw, ha->ql_dump_size,
	    (uintptr_t)ha->ql_dump_ptr) == -1) {
		mdb_warn("failed to read ql_dump_ptr (no f/w dump active?)");
		mdb_free(fw, ha->ql_dump_size);
		return (DCMD_OK);
	}

	mdb_printf("ISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);

	mdb_printf("\nHCCR Register\n%08x\n", fw->hccr);

	mdb_printf("\nHost Interface Registers");
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->host_reg[cnt]);
	}

	mdb_printf("\n\nMailbox Registers");
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x ", fw->mailbox_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_0_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_0_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-2 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_2_reg[cnt]);
	}

	mdb_printf("\n\nCommand DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->cmd_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req0_dma_reg[cnt]);
	}

	mdb_printf("\n\nResponse0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->resp0_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest1 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt0_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT2 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt2_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT3 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt3_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT4 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt4_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT Data DMA Common Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt0_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt1_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP Registers");
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->risc_gp_reg[cnt]);
	}

	mdb_printf("\n\nShadow Registers");
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->shadow_reg[cnt]);
	}

	mdb_printf("\n\nLMC Registers");
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->lmc_reg[cnt]);
	}

	mdb_printf("\n\nFPM Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fpm_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fpm_hdw_reg[cnt]);
	}

	mdb_printf("\n\nFB Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fb_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fb_hdw_reg[cnt]);
	}

	mdb_printf("\n\nCode RAM");
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x20000);
		}
		mdb_printf("%08x ", fw->code_ram[cnt]);
	}

	mdb_printf("\n\nExternal Memory");
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x100000);
		}
		mdb_printf("%08x ", fw->ext_mem[cnt]);
	}

	mdb_printf("\n[<==END] ISP Debug Dump");

	mdb_printf("\n\nRequest Queue");

	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->req_q[cnt]);
	}

	mdb_printf("\n\nResponse Queue");

	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->rsp_q[cnt]);
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWEXTTRACE) &&
	    (ha->fwexttracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwexttracebuf.bp;

		mdb_printf("\n\nExtended Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->ext_trace_buf[cnt]);
		}
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWFCETRACE) &&
	    (ha->fwfcetracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwfcetracebuf.bp;

		mdb_printf("\n\nFC Event Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->fce_trace_buf[cnt]);
		}
	}
	mdb_free(fw, ha->ql_dump_size);

	return (DCMD_OK);
}

/*
 * ql_25xx_dump_dcmd
 *	prints out a firmware dump buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: nust be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
ql_25xx_dump_dcmd(ql_adapter_state_t *ha, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ql_25xx_fw_dump_t	*fw;
	uint32_t		cnt = 0;

	fw = (ql_25xx_fw_dump_t *)mdb_alloc(ha->ql_dump_size, UM_SLEEP);

	if (mdb_vread(fw, ha->ql_dump_size,
	    (uintptr_t)ha->ql_dump_ptr) == -1) {
		mdb_warn("failed to read ql_dump_ptr (no f/w dump active?)");
		mdb_free(fw, ha->ql_dump_size);
		return (DCMD_OK);
	}

	mdb_printf("\nISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);

	mdb_printf("\nR2H Register\n%08x\n", fw->r2h_status);

	mdb_printf("\n\nHostRisc Registers");
	for (cnt = 0; cnt < sizeof (fw->hostrisc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->hostrisc_reg[cnt]);
	}

	mdb_printf("\n\nPCIe Registers");
	for (cnt = 0; cnt < sizeof (fw->pcie_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->pcie_reg[cnt]);
	}

	mdb_printf("\n\nHost Interface Registers");
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->host_reg[cnt]);
	}

	mdb_printf("\n\nShadow Registers");
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->shadow_reg[cnt]);
	}

	mdb_printf("\n\nMailbox Registers");
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x ", fw->mailbox_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_0_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_0_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-2 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_2_reg[cnt]);
	}

	mdb_printf("\n\nASEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->aseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-0 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->aseq_0_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-1 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->aseq_1_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-2 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->aseq_2_reg[cnt]);
	}

	mdb_printf("\n\nCommand DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->cmd_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req0_dma_reg[cnt]);
	}

	mdb_printf("\n\nResponse0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->resp0_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest1 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt0_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT2 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt2_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT3 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt3_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT4 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt4_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT Data DMA Common Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt0_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt1_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP Registers");
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->risc_gp_reg[cnt]);
	}

	mdb_printf("\n\nRISC IO Register\n%08x", fw->risc_io);

	mdb_printf("\n\nLMC Registers");
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->lmc_reg[cnt]);
	}

	mdb_printf("\n\nFPM Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fpm_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fpm_hdw_reg[cnt]);
	}

	mdb_printf("\n\nFB Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fb_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fb_hdw_reg[cnt]);
	}

	mdb_printf("\n\nCode RAM");
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x20000);
		}
		mdb_printf("%08x ", fw->code_ram[cnt]);
	}

	mdb_printf("\n\nExternal Memory");
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x100000);
		}
		mdb_printf("%08x ", fw->ext_mem[cnt]);
	}

	mdb_printf("\n[<==END] ISP Debug Dump");

	mdb_printf("\n\nRequest Queue");

	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->req_q[cnt]);
	}

	mdb_printf("\n\nResponse Queue");

	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->rsp_q[cnt]);
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWEXTTRACE) &&
	    (ha->fwexttracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwexttracebuf.bp;

		mdb_printf("\n\nExtended Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->ext_trace_buf[cnt]);
		}
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWFCETRACE) &&
	    (ha->fwfcetracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwfcetracebuf.bp;

		mdb_printf("\n\nFC Event Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->fce_trace_buf[cnt]);
		}
	}

	mdb_free(fw, ha->ql_dump_size);

	mdb_printf("\n\nreturn exit\n");

	return (DCMD_OK);
}

/*
 * ql_81xx_dump_dcmd
 *	prints out a firmware dump buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: nust be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
/*ARGSUSED*/
static int
ql_81xx_dump_dcmd(ql_adapter_state_t *ha, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	ql_81xx_fw_dump_t	*fw;
	uint32_t		cnt = 0;

	fw = (ql_81xx_fw_dump_t *)mdb_alloc(ha->ql_dump_size, UM_SLEEP);

	if (mdb_vread(fw, ha->ql_dump_size,
	    (uintptr_t)ha->ql_dump_ptr) == -1) {
		mdb_warn("failed to read ql_dump_ptr (no f/w dump active?)");
		mdb_free(fw, ha->ql_dump_size);
		return (DCMD_OK);
	}

	mdb_printf("\nISP FW Version %d.%02d.%02d Attributes %X\n",
	    ha->fw_major_version, ha->fw_minor_version,
	    ha->fw_subminor_version, ha->fw_attributes);

	mdb_printf("\nR2H Register\n%08x\n", fw->r2h_status);

	mdb_printf("\n\nHostRisc Registers");
	for (cnt = 0; cnt < sizeof (fw->hostrisc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->hostrisc_reg[cnt]);
	}

	mdb_printf("\n\nPCIe Registers");
	for (cnt = 0; cnt < sizeof (fw->pcie_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->pcie_reg[cnt]);
	}

	mdb_printf("\n\nHost Interface Registers");
	for (cnt = 0; cnt < sizeof (fw->host_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->host_reg[cnt]);
	}

	mdb_printf("\n\nShadow Registers");
	for (cnt = 0; cnt < sizeof (fw->shadow_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->shadow_reg[cnt]);
	}

	mdb_printf("\n\nMailbox Registers");
	for (cnt = 0; cnt < sizeof (fw->mailbox_reg) / 2; cnt++) {
		if (cnt % 16 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%04x ", fw->mailbox_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_0_reg[cnt]);
	}

	mdb_printf("\n\nXSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->xseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-0 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_0_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-1 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_1_reg[cnt]);
	}

	mdb_printf("\n\nRSEQ-2 Registers");
	for (cnt = 0; cnt < sizeof (fw->rseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rseq_2_reg[cnt]);
	}

	mdb_printf("\n\nASEQ GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->aseq_gp_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-0 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_0_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->aseq_0_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-1 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_1_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}

		mdb_printf("%08x ", fw->aseq_1_reg[cnt]);
	}

	mdb_printf("\n\nASEQ-2 GP Registers");
	for (cnt = 0; cnt < sizeof (fw->aseq_2_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->aseq_2_reg[cnt]);
	}

	mdb_printf("\n\nCommand DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->cmd_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->cmd_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req0_dma_reg[cnt]);
	}

	mdb_printf("\n\nResponse0 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->resp0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->resp0_dma_reg[cnt]);
	}

	mdb_printf("\n\nRequest1 Queue DMA Channel Registers");
	for (cnt = 0; cnt < sizeof (fw->req1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->req1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt0_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt0_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt1_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt1_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT2 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt2_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt2_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT3 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt3_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt3_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT4 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt4_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt4_dma_reg[cnt]);
	}

	mdb_printf("\n\nXMT Data DMA Common Registers");
	for (cnt = 0; cnt < sizeof (fw->xmt_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->xmt_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 0 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt0_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt0_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRCV Thread 1 Data DMA Registers");
	for (cnt = 0; cnt < sizeof (fw->rcvt1_data_dma_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->rcvt1_data_dma_reg[cnt]);
	}

	mdb_printf("\n\nRISC GP Registers");
	for (cnt = 0; cnt < sizeof (fw->risc_gp_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->risc_gp_reg[cnt]);
	}

	mdb_printf("\n\nRISC IO Register\n%08x", fw->risc_io);

	mdb_printf("\n\nLMC Registers");
	for (cnt = 0; cnt < sizeof (fw->lmc_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->lmc_reg[cnt]);
	}

	mdb_printf("\n\nFPM Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fpm_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fpm_hdw_reg[cnt]);
	}

	mdb_printf("\n\nFB Hardware Registers");
	for (cnt = 0; cnt < sizeof (fw->fb_hdw_reg) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n");
		}
		mdb_printf("%08x ", fw->fb_hdw_reg[cnt]);
	}

	mdb_printf("\n\nCode RAM");
	for (cnt = 0; cnt < sizeof (fw->code_ram) / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x20000);
		}
		mdb_printf("%08x ", fw->code_ram[cnt]);
	}

	mdb_printf("\n\nExternal Memory");
	for (cnt = 0; cnt < ha->fw_ext_memory_size / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt + 0x100000);
		}
		mdb_printf("%08x ", fw->ext_mem[cnt]);
	}

	mdb_printf("\n[<==END] ISP Debug Dump");

	mdb_printf("\n\nRequest Queue");

	for (cnt = 0; cnt < REQUEST_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->req_q[cnt]);
	}

	mdb_printf("\n\nResponse Queue");

	for (cnt = 0; cnt < RESPONSE_QUEUE_SIZE / 4; cnt++) {
		if (cnt % 8 == 0) {
			mdb_printf("\n%08x: ", cnt);
		}
		mdb_printf("%08x ", fw->rsp_q[cnt]);
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWEXTTRACE) &&
	    (ha->fwexttracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwexttracebuf.bp;

		mdb_printf("\n\nExtended Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWEXTSIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->ext_trace_buf[cnt]);
		}
	}

	if ((ha->cfg_flags & CFG_ENABLE_FWFCETRACE) &&
	    (ha->fwfcetracebuf.bp != NULL)) {
		uint32_t cnt_b = 0;
		uint32_t *w32 = ha->fwfcetracebuf.bp;

		mdb_printf("\n\nFC Event Trace Buffer Memory");
		/* show data address as a byte address, data as long words */
		for (cnt = 0; cnt < FWFCESIZE / 4; cnt++) {
			cnt_b = cnt * 4;
			if (cnt_b % 32 == 0) {
				mdb_printf("\n%08x: ", w32 + cnt_b);
			}
			mdb_printf("%08x ", fw->fce_trace_buf[cnt]);
		}
	}

	mdb_free(fw, ha->ql_dump_size);

	mdb_printf("\n\nreturn exit\n");

	return (DCMD_OK);
}

/*
 * ql_gettrace_dcmd
 *	prints out the Extended Logging trace buffer
 *
 * Input:
 *	addr  = User supplied address. (NB: must be an ha)
 *	flags = mdb flags.
 *	argc  = Number of user supplied args.
 *	argv  = Arg array.
 *
 * Returns:
 *	DCMD_OK or DCMD_ERR
 *
 * Context:
 *	User context.
 *
 */
static int
qlc_gettrace_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ql_adapter_state_t	*ha;
	int			verbose = 0;
	int			wrapped = 0;
	char			*trace_start;
	char			*trace_end;
	char			*dump_start = 0;
	char			*trace_next  = 0;
	char			*dump_current  = 0;
	el_trace_desc_t		*trace_desc;

	if ((!(flags & DCMD_ADDRSPEC)) || addr == 0) {
		mdb_warn("ql_adapter_state structure addr is required");
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose) !=
	    argc) {
		return (DCMD_USAGE);
	}

	/*
	 * Get the adapter state struct which was passed
	 */
	if ((ha = (ql_adapter_state_t *)mdb_alloc(sizeof (ql_adapter_state_t),
	    UM_SLEEP)) == NULL) {
		mdb_warn("failed to allocate memory for ql_adapter_state\n");
		return (DCMD_OK);
	}

	if (mdb_vread(ha, sizeof (ql_adapter_state_t), addr) == -1) {
		mdb_warn("failed to read ql_adapter_state at %p", addr);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	/*
	 * If its not a valid trace descriptor then bail out
	 */
	if (ha->el_trace_desc == NULL) {
		mdb_warn("trace descriptor does not exist for instance %d\n",
		    ha->instance);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	} else {
		trace_desc = (el_trace_desc_t *)
		    mdb_alloc(sizeof (el_trace_desc_t), UM_SLEEP);
		if (mdb_vread(trace_desc, sizeof (el_trace_desc_t),
		    (uintptr_t)ha->el_trace_desc) == -1) {
			mdb_warn("failed to read ql_adapter_state at %p",
			    addr);
			mdb_free(trace_desc, sizeof (el_trace_desc_t));
			mdb_free(ha, sizeof (ql_adapter_state_t));
			return (DCMD_OK);
		}
		if (trace_desc->trace_buffer == NULL) {
			mdb_warn("trace buffer does not exist for "
			    "instance %d\n", ha->instance);
			mdb_free(trace_desc, sizeof (el_trace_desc_t));
			mdb_free(ha, sizeof (ql_adapter_state_t));
			return (DCMD_OK);
		}
	}

	/* Get the trace buffer */

	trace_start = (char *)
	    mdb_zalloc(trace_desc->trace_buffer_size, UM_SLEEP);

	if (mdb_vread(trace_start, trace_desc->trace_buffer_size,
	    (uintptr_t)trace_desc->trace_buffer) == -1) {
		mdb_warn("failed to read trace buffer?)");
		mdb_free(trace_start, trace_desc->trace_buffer_size);
		mdb_free(ha, sizeof (ql_adapter_state_t));
		return (DCMD_OK);
	}

	/* set the end of the trace buffer. */
	trace_end = trace_start + trace_desc->trace_buffer_size;

	/* Find the start point of trace. */
	trace_next = trace_start + trace_desc->next;

	/*
	 * If the buffer has not wrapped next will point at a null so
	 * start is the begining of the buffer.  If next points at a char
	 * then we must traverse the buffer further until a null is detected.
	 * The location after the null will be the beginning of the oldest
	 * whole object in the buffer, which we use as the start.
	 */

	if ((trace_next + EL_BUFFER_RESERVE) >= trace_end) {
		dump_start = trace_start;
	} else if (*trace_next != '\0') {
		dump_start = trace_next + (strlen(trace_next) + 1);
	} else {
		dump_start = trace_start;
	}

	dump_current = dump_start;

	mdb_printf("\nExtended Logging trace buffer @%x, start @%x, "
	    "size=%d\n\n", trace_start, dump_current,
	    trace_desc->trace_buffer_size);

	/* Don't run off the end, no matter what. */
	while (((uintptr_t)dump_current - (uintptr_t)trace_start) <=
	    (uintptr_t)trace_desc->trace_buffer_size) {
		/* Show it... */
		mdb_printf("%s", dump_current);
		/* Calculate the next and make it the current */
		dump_current += (strlen(dump_current) + 1);
		/* check for wrap */
		if ((dump_current + EL_BUFFER_RESERVE) >= trace_end) {
			mdb_printf("Wraping %x\n", dump_current);
			dump_current = trace_start;
			wrapped = 1;
		} else if (wrapped) {
			/*   Don't go past next. */
			if ((trace_start + trace_desc->next) <= dump_current) {
				mdb_printf("Done %x", dump_current);
				break;
			}
		} else if (*dump_current == '\0') {
			mdb_printf("Done %x(null)", dump_current);
			break;
		}
	}

	mdb_free(ha, sizeof (ql_adapter_state_t));
	mdb_free(trace_start, trace_desc->trace_buffer_size);
	mdb_free(trace_desc, sizeof (el_trace_desc_t));

	return (DCMD_OK);
}
/*
 * ql_doprint
 *	ql generic function to call the print dcmd
 *
 * Input:
 *	addr - address to struct
 *	prtsting - address to string
 *
 * Returns:
 *	WALK_DONE
 *
 * Context:
 *	User context.
 *
 */
static int32_t
ql_doprint(uintptr_t addr, int8_t *prtstring)
{
	struct	mdb_arg		printarg;

	printarg.a_un.a_str = (int8_t *)(mdb_zalloc(strlen(prtstring),
	    UM_SLEEP));
	printarg.a_type = MDB_TYPE_STRING;
	(void) strcpy((int8_t *)(printarg.a_un.a_str), prtstring);

	if ((mdb_call_dcmd("print", addr, DCMD_ADDRSPEC, 1,
	    &printarg)) == -1) {
		mdb_warn("ql_doprint: failed print dcmd: %s"
		    "at addr: %llxh", prtstring, addr);
	}

	mdb_free((void *)(printarg.a_un.a_str), strlen(prtstring));
	return (WALK_DONE);
}

/*
 * ql_dump_flags
 *	mdb utility to print the flag string
 *
 * Input:
 *	flags - flags to print
 *	strings - text to print when flag is set
 *
 * Returns:
 *
 *
 * Context:
 *	User context.
 *
 */
static void
ql_dump_flags(uint64_t flags, int8_t **strings)
{
	int		i, linel, first = 1;
	uint64_t	mask = 1;

	linel = 8;
	mdb_printf("\t");
	for (i = 0; i < 64; i++) {
		if (strings[i] == NULL)
			break;
		if (flags & mask) {
			if (!first) {
				mdb_printf(" | ");
			} else {
				first = 0;
			}
			linel += (int32_t)strlen(strings[i]) + 3;
			if (linel > 80) {
				mdb_printf("\n\t");
				linel = (int32_t)strlen(strings[i]) + 1 + 8;
			}
			mdb_printf("%s", strings[i]);
		}
		mask <<= 1;
	}
	mdb_printf("\n");
}

/*
 * MDB module linkage information
 *
 *
 * dcmd structures for the _mdb_init function
 */
static const mdb_dcmd_t dcmds[] = {
	{ "qlclinks", NULL, "Prints qlc link information", qlclinks_dcmd },
	{ "qlcosc", NULL, "Prints outstanding cmd info", qlc_osc_dcmd },
	{ "qlcver", NULL, "Prints driver/mdb version", qlcver_dcmd },
	{ "qlc_elog", "[on|off] [<inst #>|all]", "Turns qlc extended logging "
	    "on / off", qlc_el_dcmd },
	{ "qlcstate", ":[-v]", "Prints qlc adapter state information",
	    qlcstate_dcmd },
	{ "qlctgtq", NULL, "Prints qlc target queues", qltgtq_dcmd },
	{ "qlcwdog", NULL, "Prints out watchdog linked list", qlc_wdog_dcmd},
	{ "qlcgetdump", ":[-v]", "Retrieves the ASCII f/w dump",
	    qlc_getdump_dcmd },
	{ "qlcgettrace", ":[-v]", "Retrieves the ASCII Extended Logging trace",
	    qlc_gettrace_dcmd },
	{ NULL }
};

/*
 * walker structures for the _mdb_init function
 */
static const mdb_walker_t walkers[] = {
	{ "qlcstates", "walk list of qlc ql_state_t structures",
	    qlstates_walk_init, qlstates_walk_step, qlstates_walk_fini },
	{ "qlcsrbs", "walk list of qlc ql_srb_t strctures",
	    qlsrb_walk_init, qlsrb_walk_step, qlsrb_walk_fini },
	{ "qlclunq", "walk list of qlc ql_lun_t strctures",
	    qllunq_walk_init, qllunq_walk_step, qllunq_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t ql_mdb_modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

/*
 * Registration function which lists the dcmds and walker structures
 */
const mdb_modinfo_t *
_mdb_init(void)
{
	return (&ql_mdb_modinfo);
}
