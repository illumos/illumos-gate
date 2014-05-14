/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_FCF_C);

/*
 * STATE MACHINE RULES:
 *
 * - State change requests to an XXXX object when operating within
 * an emlxs_XXXX state management function must be made
 * using the emlxs_XXXX_state() call.
 *
 * - State change requests to an XXXX object when operating outside
 * an emlxs_XXXX state management function must be made
 * using the emlxs_XXXX_alloc(), emlxs_XXXX_free(), emlxs_XXXX_event()
 * or emlxs_XXXX_..._notify() calls.
 *
 * - emlxs_XXXX_..._notify() calls are used by routines outside
 * this fcf module to enter the state machine.
 *
 * - It is forbidden to make direct calls to emlxs_XXXX_...._action()
 * functions.  Only emlxs_XXXX_action() routines may make calls to
 * emlxs_XXXX_...._action() functions.
 *
 * - Its is forbidden to make direct calls to emlxs_XXXX_action().
 * Only emlxs_XXXX_state() and emlxs_XXXX_event() routines may make
 * calls to emlxs_XXXX_action().
 *
 * - The EMLXS_FCF_LOCK must be held before calling:
 * emlxs_XXXX_state(), emlxs_XXXX_event() and emlxs_XXXX_action().
 *
 * - All other calls touching fcftab, fcfi, vfi, vpi, rpi objects
 * must hold the EMLXS_FCF_LOCK to protect these objects.
 */

/*
 * DEBUG MESSAGE TERMINATION RULES:
 *
 * - A message should end in ">" if a thread operating outside the
 * XXXX state machine enters the XXXX state machine with a call to
 * emlxs_XXXX_event() or emlxs_XXXX_state().  This includes calls made
 * from emlxs_..._notify(), emlxs_..._mbcmpl() and emlxs_..._timer()
 * routines since they represent the beginnning of new threads.
 *
 * - A message should end in "<" if the thread is about exit
 * an emlxs_XXXX_..._action() without previously calling the
 * next emlxs_XXXX_state().  This includes the emlxs_XXXX_action()
 * and emlxs_XXXX_state() routines themselves since errors
 * in these routines represent the termination of state change
 * thread.
 *
 * - A message should end in "." if none of the previous
 * conditions apply.
 */

/* ************************************************************************** */
/* FCF Generic */
/* ************************************************************************** */

/*
 * EVENT			ARG1
 * --------------------------------------------
 * FCF_EVENT_STATE_ENTER	None
 *
 * FCF_EVENT_LINKUP		None
 * FCF_EVENT_LINKDOWN		None
 * FCF_EVENT_CVL		vpi
 * FCF_EVENT_FCFTAB_FULL	None
 * FCF_EVENT_FCF_FOUND		fcf_index
 * FCF_EVENT_FCF_LOST		fcf_index
 * FCF_EVENT_FCF_CHANGED	fcf_index
 *
 * FCF_EVENT_FCFI_ONLINE	FCFIobj_t*
 * FCF_EVENT_FCFI_OFFLINE	FCFIobj_t*
 * FCF_EVENT_FCFI_PAUSE		FCFIobj_t*
 *
 * FCF_EVENT_VFI_ONLINE		VFIobj_t*
 * FCF_EVENT_VFI_OFFLINE	VFIobj_t*
 * FCF_EVENT_VFI_PAUSE		VFIobj_t*
 *
 * FCF_EVENT_VPI_ONLINE		VPIobj_t*
 * FCF_EVENT_VPI_OFFLINE	VPIobj_t*
 * FCF_EVENT_VPI_PAUSE		VPIobj_t*
 *
 * FCF_EVENT_RPI_ONLINE		RPIobj_t*
 * FCF_EVENT_RPI_OFFLINE	RPIobj_t*
 * FCF_EVENT_RPI_PAUSE		RPIobj_t*
 * FCF_EVENT_RPI_RESUME		RPIobj_t*
 * FCF_EVENT_RPI_TIMEOUT	RPIobj_t*
 */

/* Order does not matter */
emlxs_table_t emlxs_fcf_event_table[] =
{
	{FCF_EVENT_STATE_ENTER, "E_ENTER"},

	{FCF_EVENT_SHUTDOWN, "E_SHUTDOWN"},
	{FCF_EVENT_LINKUP, "E_LINKUP"},
	{FCF_EVENT_LINKDOWN, "E_LINKDOWN"},
	{FCF_EVENT_CVL, "E_CVL"},
	{FCF_EVENT_FCFTAB_FULL, "E_TABLE_FULL"},
	{FCF_EVENT_FCF_FOUND, "E_FCF_FOUND"},
	{FCF_EVENT_FCF_LOST, "E_FCF_LOST"},
	{FCF_EVENT_FCF_CHANGED, "E_FCF_CHANGED"},

	{FCF_EVENT_FCFI_ONLINE, "E_FCFI_ONLINE"},
	{FCF_EVENT_FCFI_OFFLINE, "E_FCFI_OFFLINE"},
	{FCF_EVENT_FCFI_PAUSE, "E_FCFI_PAUSE"},

	{FCF_EVENT_VFI_ONLINE, "E_VFI_ONLINE"},
	{FCF_EVENT_VFI_OFFLINE, "E_VFI_OFFLINE"},
	{FCF_EVENT_VFI_PAUSE, "E_VFI_PAUSE"},

	{FCF_EVENT_VPI_ONLINE, "E_VPI_ONLINE"},
	{FCF_EVENT_VPI_OFFLINE, "E_VPI_OFFLINE"},
	{FCF_EVENT_VPI_PAUSE, "E_VPI_PAUSE"},

	{FCF_EVENT_RPI_ONLINE, "E_RPI_ONLINE"},
	{FCF_EVENT_RPI_OFFLINE, "E_RPI_OFFLINE"},
	{FCF_EVENT_RPI_PAUSE, "E_RPI_PAUSE"},
	{FCF_EVENT_RPI_RESUME, "E_RPI_RESUME"},

}; /* emlxs_fcf_event_table */


/* Order does not matter */
emlxs_table_t emlxs_fcf_reason_table[] =
{
	{FCF_REASON_NONE, "R_NONE"},
	{FCF_REASON_REENTER, "R_REENTER"},
	{FCF_REASON_EVENT, "R_EVENT"},
	{FCF_REASON_REQUESTED, "R_REQUESTED"},
	{FCF_REASON_NO_MBOX, "R_NO_MBOX"},
	{FCF_REASON_NO_BUFFER, "R_NO_BUFFER"},
	{FCF_REASON_SEND_FAILED, "R_SEND_FAILED"},
	{FCF_REASON_MBOX_FAILED, "R_MBOX_FAILED"},
	{FCF_REASON_MBOX_BUSY, "R_MBOX_BUSY"},
	{FCF_REASON_NO_FCFI, "R_NO_FCFI"},
	{FCF_REASON_NO_VFI, "R_NO_VFI"},
	{FCF_REASON_ONLINE_FAILED, "R_ONLINE_FAILED"},
	{FCF_REASON_OFFLINE_FAILED, "R_OFFLINE_FAILED"},
	{FCF_REASON_OP_FAILED, "R_OP_FAILED"},
	{FCF_REASON_NO_PKT, "R_NO_PKT"},
	{FCF_REASON_NO_NODE, "R_NO_NODE"},
	{FCF_REASON_NOT_ALLOWED, "R_NOT_ALLOWED"},
	{FCF_REASON_UNUSED, "R_UNUSED"},
	{FCF_REASON_INVALID, "R_INVALID"},

}; /* emlxs_fcf_reason_table */


/* ********************************************************************** */
/* FCFTAB Generic */
/* ********************************************************************** */
static char 		*emlxs_fcftab_state_xlate(emlxs_port_t *port,
				uint32_t state);
static uint32_t		emlxs_fcftab_event(emlxs_port_t *port, uint32_t evt,
				void *arg1);
static uint32_t		emlxs_fcftab_shutdown_action(emlxs_port_t *port,
				uint32_t evt, void *arg1);

/* ********************************************************************** */
/* FC FCFTAB */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_fc_fcftab_state_table[] =
{
	{FC_FCFTAB_STATE_SHUTDOWN, "FCFTAB_SHUTDOWN"},
	{FC_FCFTAB_STATE_OFFLINE, "FCFTAB_OFFLINE"},

	{FC_FCFTAB_STATE_TOPO, "FCFTAB_TOPO"},
	{FC_FCFTAB_STATE_TOPO_FAILED, "FCFTAB_TOPO_FAILED"},
	{FC_FCFTAB_STATE_TOPO_CMPL, "FCFTAB_TOPO_CMPL"},

	{FC_FCFTAB_STATE_CFGLINK, "FCFTAB_CFGLINK"},
	{FC_FCFTAB_STATE_CFGLINK_FAILED, "FCFTAB_CFGLINK_FAILED"},
	{FC_FCFTAB_STATE_CFGLINK_CMPL, "FCFTAB_CFGLINK_CMPL"},

	{FC_FCFTAB_STATE_SPARM, "FCFTAB_SPARM"},
	{FC_FCFTAB_STATE_SPARM_FAILED, "FCFTAB_SPARM_FAILED"},
	{FC_FCFTAB_STATE_SPARM_CMPL, "FCFTAB_SPARM_CMPL"},

	{FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL,
	    "FCFTAB_FCFI_OFFLINE_CMPL"},
	{FC_FCFTAB_STATE_FCFI_OFFLINE, "FCFTAB_FCFI_OFFLINE"},

	{FC_FCFTAB_STATE_FCFI_ONLINE, "FCFTAB_FCFI_ONLINE"},
	{FC_FCFTAB_STATE_FCFI_ONLINE_CMPL, "FCFTAB_FCFI_ONLINE_CMPL"},

	{FC_FCFTAB_STATE_ONLINE, "FCFTAB_ONLINE"},

}; /* emlxs_fc_fcftab_state_table */

static void emlxs_fc_fcftab_online_timer(emlxs_hba_t *hba);

static uint32_t emlxs_fc_fcftab_offline_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_online_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_topo_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_topo_failed_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_topo_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_cfglink_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_cfglink_failed_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_cfglink_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_sparm_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_sparm_failed_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_sparm_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_linkup_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_linkdown_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_fcfi_online_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_fcfi_offline_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static uint32_t emlxs_fc_fcftab_shutdown_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_fcfi_offline_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_fcfi_offline_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_fcfi_online_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_fcfi_online_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static char *emlxs_fc_fcftab_state_xlate(uint32_t state);
static uint32_t emlxs_fc_fcftab_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fc_fcftab_req_handler(emlxs_port_t *port, void *arg1);

/*
 * - Online sequencing can start from FC_FCFTAB_STATE_OFFLINE state
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * LINK_UP event <-- Adapter
 * FC_FCFTAB_STATE_OFFLINE
 * FC_FCFTAB_STATE_TOPO
 *     FC_FCFTAB_STATE_TOPO_CMPL
 * FC_FCFTAB_STATE_CFGLINK
 *     FC_FCFTAB_STATE_CFGLINK_CMPL
 * FC_FCFTAB_STATE_SPARM
 *     FC_FCFTAB_STATE_SPARM_CMPL
 * FC_FCFTAB_STATE_FCFI_ONLINE
 *     FC_FCFTAB_STATE_FCFI_ONLINE_CMPL
 * FC_FCFTAB_STATE_ONLINE
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * LINK_DOWN event <-- Adapter
 * FC_FCFTAB_STATE_ONLINE
 * FC_FCFTAB_STATE_FCFI_OFFLINE
 *     FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL
 * FC_FCFTAB_STATE_OFFLINE
 *
 */
/* Order does matter */
static void *emlxs_fc_fcftab_action_table[] =
{
	/* Action routine				Event */
/* FC_FCFTAB_STATE_SHUTDOWN  0			(Requires adapter reset) */
	(void *) emlxs_fcftab_shutdown_action,		/* STATE_ENTER */
	(void *) NULL,					/* SHUTDOWN */
	(void *) NULL,					/* LINK_UP */
	(void *) NULL,					/* LINK_DOWN */
	(void *) NULL,					/* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_OFFLINE  1			(Wait for LINK_UP event) */
	(void *) emlxs_fc_fcftab_offline_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_TOPO  2			(Wait for topo mbcmpl) */
	(void *) emlxs_fc_fcftab_topo_action,		/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_TOPO_FAILED  3		(Transitional) */
	(void *) emlxs_fc_fcftab_topo_failed_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_TOPO_CMPL  4			(Transitional) */
	(void *) emlxs_fc_fcftab_topo_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_CFGLINK  5			(Wait for cfglink mbcmpl) */
	(void *) emlxs_fc_fcftab_cfglink_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_CFGLINK_FAILED  6		(Transitional) */
	(void *) emlxs_fc_fcftab_cfglink_failed_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_CFGLINK_CMPL  7			(Transitional) */
	(void *) emlxs_fc_fcftab_cfglink_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_SPARM  8			(Wait for sparm mbcmpl) */
	(void *) emlxs_fc_fcftab_sparm_action,		/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_SPARM_FAILED  9		(Transitional) */
	(void *) emlxs_fc_fcftab_sparm_failed_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_SPARM_CMPL  10		(Transitional) */
	(void *) emlxs_fc_fcftab_sparm_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL  11	(Transitional) */
	(void *) emlxs_fc_fcftab_fcfi_offline_cmpl_action, /* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_FCFI_OFFLINE  12		(Wait for FCFI_OFFLINE event) */
	(void *) emlxs_fc_fcftab_fcfi_offline_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_FCFI_ONLINE  13		(Wait for FCFI_ONLINE event) */
	(void *) emlxs_fc_fcftab_fcfi_online_action,	/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FC_FCFTAB_STATE_FCFI_ONLINE_CMPL  14		(Transitional) */
	(void *) emlxs_fc_fcftab_fcfi_online_cmpl_action, /* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FC_FCFTAB_STATE_ONLINE  15			(Wait for LINK_DOWN evt) */
	(void *) emlxs_fc_fcftab_online_action,		/* STATE_ENTER */
	(void *) emlxs_fc_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fc_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fc_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fc_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fc_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

}; /* emlxs_fc_fcftab_action_table[] */
#define	FC_FCFTAB_ACTION_EVENTS			6
#define	FC_FCFTAB_ACTION_STATES			\
	(sizeof (emlxs_fc_fcftab_action_table)/ \
	(FC_FCFTAB_ACTION_EVENTS * sizeof (void *)))


/* ********************************************************************** */
/* FCOE FCFTAB */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_fcoe_fcftab_state_table[] =
{
	{FCOE_FCFTAB_STATE_SHUTDOWN, "FCFTAB_SHUTDOWN"},
	{FCOE_FCFTAB_STATE_OFFLINE, "FCFTAB_OFFLINE"},

	{FCOE_FCFTAB_STATE_SOLICIT, "FCFTAB_SOLICIT"},
	{FCOE_FCFTAB_STATE_SOLICIT_FAILED, "FCFTAB_SOLICIT_FAILED"},
	{FCOE_FCFTAB_STATE_SOLICIT_CMPL, "FCFTAB_SOLICIT_CMPL"},

	{FCOE_FCFTAB_STATE_READ, "FCFTAB_READ"},
	{FCOE_FCFTAB_STATE_READ_FAILED, "FCFTAB_READ_FAILED"},
	{FCOE_FCFTAB_STATE_READ_CMPL, "FCFTAB_READ_CMPL"},

	{FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL,
	    "FCFTAB_FCFI_OFFLINE_CMPL"},
	{FCOE_FCFTAB_STATE_FCFI_OFFLINE, "FCFTAB_FCFI_OFFLINE"},

	{FCOE_FCFTAB_STATE_FCFI_ONLINE, "FCFTAB_FCFI_ONLINE"},
	{FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL,
	    "FCFTAB_FCFI_ONLINE_CMPL"},

	{FCOE_FCFTAB_STATE_ONLINE, "FCFTAB_ONLINE"},

}; /* emlxs_fcoe_fcftab_state_table */

static uint32_t emlxs_fcoe_fcftab_sol_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_sol_failed_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_sol_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_shutdown_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_linkdown_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_read_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_read_failed_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_read_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_online_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_online_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_offline_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_offline_cmpl_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_found_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_lost_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_changed_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_full_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_linkup_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_cvl_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_online_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_offline_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_offline_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_fcfi_online_evt_action(emlxs_port_t *port,
			uint32_t evt, void *arg1);

static void emlxs_fcoe_fcftab_read_timer(emlxs_hba_t *hba);
static void emlxs_fcoe_fcftab_sol_timer(emlxs_hba_t *hba);
static void emlxs_fcoe_fcftab_offline_timer(emlxs_hba_t *hba);
static char *emlxs_fcoe_fcftab_state_xlate(uint32_t state);
static uint32_t emlxs_fcoe_fcftab_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_fcoe_fcftab_state(emlxs_port_t *port, uint16_t state,
	uint16_t reason, uint32_t explain, void *arg1);

/*
 * - Online sequencing can start from FCOE_FCFTAB_STATE_OFFLINE state
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * LINK_UP event <-- Adapter
 * FCOE_FCFTAB_STATE_OFFLINE
 * FCOE_FCFTAB_STATE_SOLICIT
 *     FCOE_FCFTAB_STATE_SOLICIT_CMPL
 * FCOE_FCFTAB_STATE_READ
 *     FCOE_FCFTAB_STATE_READ_CMPL
 * FCOE_FCFTAB_STATE_FCFI_OFFLINE
 *     FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL
 * FCOE_FCFTAB_STATE_FCFI_ONLINE
 *     FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL
 * FCOE_FCFTAB_STATE_ONLINE
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * LINK_DOWN event <-- Adapter
 * FCOE_FCFTAB_STATE_ONLINE
 * FCOE_FCFTAB_STATE_FCFI_OFFLINE
 *     FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL
 * FCOE_FCFTAB_STATE_OFFLINE
 *
 */
/* Order does matter */
static void *emlxs_fcoe_fcftab_action_table[] =
{
	/* Action routine				Event */
/* FCOE_FCFTAB_STATE_SHUTDOWN  0		(Requires adapter reset) */
	(void *) emlxs_fcftab_shutdown_action,		/* STATE_ENTER */
	(void *) NULL,					/* SHUTDOWN */
	(void *) NULL,					/* LINK_UP */
	(void *) NULL,					/* LINK_DOWN */
	(void *) NULL,					/* CVL_RECD */
	(void *) NULL,					/* FCF_FOUND */
	(void *) NULL,					/* FCF_LOST */
	(void *) NULL,					/* FCF_CHANGED */
	(void *) NULL,					/* TABLE_FULL */
	(void *) NULL,					/* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_OFFLINE  1			(Wait for LINK_UP event) */
	(void *) emlxs_fcoe_fcftab_offline_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FCOE_FCFTAB_STATE_SOLICIT  2			(Wait on fcf_solicit cmpl) */
	(void *) emlxs_fcoe_fcftab_sol_action,		/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_SOLICIT_FAILED  3		(Transitional) */
	(void *) emlxs_fcoe_fcftab_sol_failed_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_SOLICIT_CMPL  4		(Wait on fcf timer cmpl) */
	(void *) emlxs_fcoe_fcftab_sol_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FCOE_FCFTAB_STATE_READ  5			(Wait on fcf_read cmpl) */
	(void *) emlxs_fcoe_fcftab_read_action,		/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_READ_FAILED  6		(Transitional) */
	(void *) emlxs_fcoe_fcftab_read_failed_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_READ_CMPL  7		(Transitional) */
	(void *) emlxs_fcoe_fcftab_read_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL  8	(Transitional) */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_cmpl_action, /* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_FCFI_OFFLINE  9		(Wait for FCFI_OFFLINE event) */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FCOE_FCFTAB_STATE_FCFI_ONLINE  10		(Wait on FCFI_ONLINE event) */
	(void *) emlxs_fcoe_fcftab_fcfi_online_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

/* FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL  11	(Transitional) */
	(void *) emlxs_fcoe_fcftab_fcfi_online_cmpl_action, /* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */


/* FCOE_FCFTAB_STATE_ONLINE  12			(Wait for LINK_DOWN event) */
	(void *) emlxs_fcoe_fcftab_online_action,	/* STATE_ENTER */
	(void *) emlxs_fcoe_fcftab_shutdown_evt_action,	/* SHUTDOWN */
	(void *) emlxs_fcoe_fcftab_linkup_evt_action,	/* LINK_UP */
	(void *) emlxs_fcoe_fcftab_linkdown_evt_action,	/* LINK_DOWN */
	(void *) emlxs_fcoe_fcftab_cvl_evt_action,	/* CVL_RECD */
	(void *) emlxs_fcoe_fcftab_found_evt_action,	/* FCF_FOUND */
	(void *) emlxs_fcoe_fcftab_lost_evt_action,	/* FCF_LOST */
	(void *) emlxs_fcoe_fcftab_changed_evt_action,	/* FCF_CHANGED */
	(void *) emlxs_fcoe_fcftab_full_evt_action,	/* TABLE_FULL */
	(void *) emlxs_fcoe_fcftab_fcfi_online_evt_action, /* FCFI_ONLINE */
	(void *) emlxs_fcoe_fcftab_fcfi_offline_evt_action, /* FCFI_OFFLINE */

}; /* emlxs_fcoe_fcftab_action_table[] */
#define	FCOE_FCFTAB_ACTION_EVENTS			11
#define	FCOE_FCFTAB_ACTION_STATES			\
	(sizeof (emlxs_fcoe_fcftab_action_table)/ \
	(FCOE_FCFTAB_ACTION_EVENTS * sizeof (void *)))




/* ********************************************************************** */
/* FCFI */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_fcfi_state_table[] =
{
	{FCFI_STATE_FREE, "FCFI_FREE"},

	{FCFI_STATE_OFFLINE, "FCFI_OFFLINE"},

	{FCFI_STATE_UNREG_CMPL, "FCFI_UNREG_CMPL"},
	{FCFI_STATE_UNREG_FAILED, "FCFI_UNREG_FAILED"},
	{FCFI_STATE_UNREG, "FCFI_UNREG"},

	{FCFI_STATE_REG, "FCFI_REG"},
	{FCFI_STATE_REG_FAILED, "FCFI_REG_FAILED"},
	{FCFI_STATE_REG_CMPL, "FCFI_REG_CMPL"},

	{FCFI_STATE_VFI_OFFLINE_CMPL, "FCFI_VFI_OFFLINE_CMPL"},
	{FCFI_STATE_VFI_OFFLINE, "FCFI_VFI_OFFLINE"},

	{FCFI_STATE_VFI_ONLINE, "FCFI_VFI_ONLINE"},
	{FCFI_STATE_VFI_ONLINE_CMPL, "FCFI_VFI_ONLINE_CMPL"},

	{FCFI_STATE_PAUSED, "FCFI_PAUSED"},
	{FCFI_STATE_ONLINE, "FCFI_ONLINE"},

}; /* emlxs_fcfi_state_table */


static uint32_t emlxs_fcfi_free_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_online_evt_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_offline_evt_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_pause_evt_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_reg_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_unreg_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_reg_cmpl_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_unreg_cmpl_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_online_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_online_cmpl_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_reg_failed_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_unreg_failed_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_offline_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_offline_cmpl_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_online_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_paused_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_offline_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_online_evt_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);
static uint32_t emlxs_fcfi_vfi_offline_evt_action(emlxs_port_t *port,
			FCFIobj_t *fcfp, uint32_t evt, void *arg1);

static uint32_t emlxs_fcfi_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static FCFIobj_t *emlxs_fcfi_find(emlxs_port_t *port, FCF_RECORD_t *fcfrec,
			uint32_t *fcf_index);
static FCFIobj_t *emlxs_fcfi_alloc(emlxs_port_t *port);
static uint32_t emlxs_fcfi_free(emlxs_port_t *port, FCFIobj_t *fcfp);
static void emlxs_fcfi_update(emlxs_port_t *port, FCFIobj_t *fcfp,
			FCF_RECORD_t *fcf_rec, uint32_t event_tag);
static char *emlxs_fcfi_state_xlate(uint32_t state);

/*
 * - Online sequencing can start from FCFI_STATE_OFFLINE state or
 * the FCFI_STATE_VFI_OFFLINE state.
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * FCFI_ONLINE event <-- FCFTAB
 * FCFI_STATE_OFFLINE
 * FCFI_STATE_REG
 *     FCFI_STATE_REG_CMPL
 * FCFI_STATE_VFI_ONLINE
 *     FCFI_STATE_VFI_ONLINE_CMPL
 * FCFI_STATE_ONLINE
 * FCFI_ONLINE event-->FCFTAB
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * FCFI_OFFLINE event <-- FCFTAB
 * FCFI_STATE_ONLINE
 * FCFI_STATE_VFI_OFFLINE
 *     FCFI_STATE_VFI_OFFLINE_CMPL
 * FCFI_STATE_UNREG
 *     FCFI_STATE_UNREG_CMPL
 * FCFI_STATE_OFFLINE
 * FCFI_OFFLINE event-->FCFTAB
 *
 *
 * NORMAL PAUSE SEQ
 * ---------------------------
 * FCFI_PAUSE event <-- FCFTAB
 * FCFI_STATE_ONLINE
 * FCFI_STATE_PAUSED
 *
 */
/* Order does matter */
static void *emlxs_fcfi_action_table[] =
{
	/* Action routine				Event */
/* FCFI_STATE_FREE  0			(Wait for allocation) */
	(void *) emlxs_fcfi_free_action,		/* STATE_ENTER */
	(void *) NULL,					/* FCFI_ONLINE */
	(void *) NULL,					/* FCFI_OFFLINE */
	(void *) NULL,					/* FCFI_PAUSE */
	(void *) NULL,					/* VFI_ONLINE */
	(void *) NULL,					/* VFI_OFFLINE */

/* FCFI_STATE_OFFLINE  1		(Wait for FCFI_ONLINE event) */
	(void *) emlxs_fcfi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_UNREG_CMPL  2		(Transitional)  */
	(void *) emlxs_fcfi_unreg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,  	/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action, 	/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_UNREG_FAILED  3		(Transitional) */
	(void *) emlxs_fcfi_unreg_failed_action, 	/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_UNREG  4			(Wait for unreg_fcfi cmpl) */
	(void *) emlxs_fcfi_unreg_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_REG  5			(Wait for reg_fcfi cmpl) */
	(void *) emlxs_fcfi_reg_action,			/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action, 	/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_REG_FAILED  6		(Transitional) */
	(void *) emlxs_fcfi_reg_failed_action,		/*  STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_REG_CMPL  7		(Transitional) */
	(void *) emlxs_fcfi_reg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,  	/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action, 	/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_VFI_OFFLINE_CMPL  8 	(Transitional) */
	(void *) emlxs_fcfi_vfi_offline_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_VFI_OFFLINE  9		(Wait for VFI_OFFLINE event) */
	(void *) emlxs_fcfi_vfi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action, 	/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE * */

/* FCFI_STATE_VFI_ONLINE  10		(Wait for VFI_ONLINE event) */
	(void *) emlxs_fcfi_vfi_online_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_VFI_ONLINE_CMPL  11	(Transitional) */
	(void *) emlxs_fcfi_vfi_online_cmpl_action, 	/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */


/* FCFI_STATE_PAUSED 12			(Wait for FCFI_ONLINE event) */
	(void *) emlxs_fcfi_paused_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

/* FCFI_STATE_ONLINE 13			(Wait for FCFI_OFFLINE event) */
	(void *) emlxs_fcfi_online_action,		/* STATE_ENTER */
	(void *) emlxs_fcfi_online_evt_action,		/* FCFI_ONLINE */
	(void *) emlxs_fcfi_offline_evt_action,		/* FCFI_OFFLINE */
	(void *) emlxs_fcfi_pause_evt_action,		/* FCFI_PAUSE */
	(void *) emlxs_fcfi_vfi_online_evt_action,	/* VFI_ONLINE */
	(void *) emlxs_fcfi_vfi_offline_evt_action,	/* VFI_OFFLINE */

}; /* emlxs_fcfi_action_table[] */
#define	FCFI_ACTION_EVENTS			6
#define	FCFI_ACTION_STATES			\
	(sizeof (emlxs_fcfi_action_table)/ \
	(FCFI_ACTION_EVENTS * sizeof (void *)))


/* ********************************************************************** */
/* VFI */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_vfi_state_table[] =
{
	{VFI_STATE_OFFLINE, "VFI_OFFLINE"},

	{VFI_STATE_INIT, "VFI_INIT"},
	{VFI_STATE_INIT_FAILED, "VFI_INIT_FAILED"},
	{VFI_STATE_INIT_CMPL, "VFI_INIT_CMPL"},

	{VFI_STATE_VPI_OFFLINE_CMPL, "VFI_VPI_OFFLINE_CMPL"},
	{VFI_STATE_VPI_OFFLINE, "VFI_VPI_OFFLINE"},

	{VFI_STATE_VPI_ONLINE, "VFI_VPI_ONLINE"},
	{VFI_STATE_VPI_ONLINE_CMPL, "VFI_VPI_ONLINE_CMPL"},

	{VFI_STATE_UNREG_CMPL, "VFI_UNREG_CMPL"},
	{VFI_STATE_UNREG_FAILED, "VFI_UNREG_FAILED"},
	{VFI_STATE_UNREG, "VFI_UNREG"},

	{VFI_STATE_REG, "VFI_REG"},
	{VFI_STATE_REG_FAILED, "VFI_REG_FAILED"},
	{VFI_STATE_REG_CMPL, "VFI_REG_CMPL"},

	{VFI_STATE_PAUSED, "VFI_PAUSED"},
	{VFI_STATE_ONLINE, "VFI_ONLINE"},

}; /* emlxs_vfi_state_table */


static uint32_t emlxs_vfi_pause_evt_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_online_evt_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_offline_evt_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_init_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_init_failed_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_init_cmpl_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_offline_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_online_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_paused_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_online_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_online_cmpl_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_offline_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_offline_cmpl_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_reg_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_reg_failed_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_reg_cmpl_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_unreg_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_unreg_failed_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_unreg_cmpl_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_online_evt_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);
static uint32_t emlxs_vfi_vpi_offline_evt_action(emlxs_port_t *port,
			VFIobj_t *vfip, uint32_t evt, void *arg1);

static uint32_t emlxs_vfi_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);


/*
 * - Online sequencing can start from VFI_STATE_OFFLINE state or
 * the VFI_STATE_VPI_OFFLINE state.
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * VFI_ONLINE event <-- FCFI
 * VFI_STATE_OFFLINE
 * VFI_STATE_INIT
 *     VFI_STATE_INIT_CMPL
 * VFI_STATE_VPI_ONLINE
 *     VFI_STATE_VPI_ONLINE_CMPL
 * VFI_STATE_REG
 *     VFI_STATE_REG_CMPL
 * VFI_STATE_ONLINE
 * VFI_ONLINE event-->FCFI
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * VFI_OFFLINE event <-- FCFI
 * VFI_STATE_ONLINE
 * VFI_STATE_VPI_OFFLINE
 *     VFI_STATE_VPI_OFFLINE_CMPL
 * VFI_STATE_UNREG
 *     VFI_STATE_UNREG_CMPL
 * VFI_STATE_OFFLINE
 * VFI_OFFLINE event-->FCFI
 *
 *
 * NORMAL PAUSE SEQ
 * ---------------------------
 * VFI_PAUSE event <-- FCFI
 * VFI_STATE_ONLINE
 * VFI_STATE_PAUSED
 *
 */
/* Order does matter */
static void *emlxs_vfi_action_table[] =
{
	/* Action routine				Event */
/* VFI_STATE_OFFLINE  0			(Wait for VFI_ONLINE event) */
	(void *) emlxs_vfi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_INIT  1			(Wait for init_vfi cmpl) */
	(void *) emlxs_vfi_init_action,			/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_INIT_FAILED  2		(Transitional) */
	(void *) emlxs_vfi_init_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_INIT_CMPL  3		(Transitional) */
	(void *) emlxs_vfi_init_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_VPI_OFFLINE_CMPL  4	(Wait for VPI_OFFLINE event) */
	(void *) emlxs_vfi_vpi_offline_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_VPI_OFFLINE  5		(Wait for VPI_OFFLINE event) */
	(void *) emlxs_vfi_vpi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_VPI_ONLINE 6		(Wait for VPI_ONLINE event) */
	(void *) emlxs_vfi_vpi_online_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_VPI_ONLINE_CMPL  7		(Transitional) */
	(void *) emlxs_vfi_vpi_online_cmpl_action,	/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_UNREG_CMPL  8		(Transitional) */
	(void *) emlxs_vfi_unreg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_UNREG_FAILED  9		(Transitional) */
	(void *) emlxs_vfi_unreg_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_UNREG  10			(Wait for unreg_vfi cmpl) */
	(void *) emlxs_vfi_unreg_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_REG  11			(Wait for reg_vfi cmpl) */
	(void *) emlxs_vfi_reg_action,			/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_REG_FAILED  12		(Transitional) */
	(void *) emlxs_vfi_reg_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_REG_CMPL  13		(Transitional) */
	(void *) emlxs_vfi_reg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */


/* VFI_STATE_PAUSED  14			(Wait for VFI_OFFLINE event) */
	(void *) emlxs_vfi_paused_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

/* VFI_STATE_ONLINE  14			(Wait for VFI_OFFLINE event) */
	(void *) emlxs_vfi_online_action,		/* STATE_ENTER */
	(void *) emlxs_vfi_online_evt_action,		/* VFI_ONLINE */
	(void *) emlxs_vfi_offline_evt_action,		/* VFI_OFFLINE */
	(void *) emlxs_vfi_pause_evt_action,		/* VFI_PAUSE */
	(void *) emlxs_vfi_vpi_online_evt_action,	/* VPI_ONLINE */
	(void *) emlxs_vfi_vpi_offline_evt_action,	/* VPI_OFFLINE */

}; /* emlxs_vfi_action_table[] */
#define	VFI_ACTION_EVENTS			6
#define	VFI_ACTION_STATES			\
	(sizeof (emlxs_vfi_action_table)/ \
	(VFI_ACTION_EVENTS * sizeof (void *)))


/* ********************************************************************** */
/* VPI */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_vpi_state_table[] =
{
	{VPI_STATE_OFFLINE, "VPI_OFFLINE"},

	{VPI_STATE_INIT, "VPI_INIT"},
	{VPI_STATE_INIT_FAILED, "VPI_INIT_FAILED"},
	{VPI_STATE_INIT_CMPL, "VPI_INIT_CMPL"},

	{VPI_STATE_UNREG_CMPL, "VPI_UNREG_CMPL"},
	{VPI_STATE_UNREG_FAILED, "VPI_UNREG_FAILED"},
	{VPI_STATE_UNREG, "VPI_UNREG"},

	{VPI_STATE_LOGO_CMPL, "VPI_LOGO_CMPL"},
	{VPI_STATE_LOGO_FAILED, "VPI_LOGO_FAILED"},
	{VPI_STATE_LOGO, "VPI_LOGO"},

	{VPI_STATE_PORT_OFFLINE, "VPI_PORT_OFFLINE"},
	{VPI_STATE_PORT_ONLINE, "VPI_PORT_ONLINE"},

	{VPI_STATE_LOGI, "VPI_LOGI"},
	{VPI_STATE_LOGI_FAILED, "VPI_LOGI_FAILED"},
	{VPI_STATE_LOGI_CMPL, "VPI_LOGI_CMPL"},

	{VPI_STATE_REG, "VPI_REG"},
	{VPI_STATE_REG_FAILED, "VPI_REG_FAILED"},
	{VPI_STATE_REG_CMPL, "VPI_REG_CMPL"},

	{VPI_STATE_PAUSED, "VPI_PAUSED"},
	{VPI_STATE_ONLINE, "VPI_ONLINE"},

}; /* emlxs_vpi_state_table */


static uint32_t emlxs_vpi_online_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_offline_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_pause_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_rpi_online_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_rpi_offline_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_rpi_pause_evt_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_init_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_init_failed_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_init_cmpl_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_offline_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_online_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_paused_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_port_online_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_port_offline_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_logi_cmpl_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_logi_failed_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_logi_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_reg_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_reg_failed_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_reg_cmpl_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_unreg_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_unreg_failed_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_unreg_cmpl_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_logo_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_logo_failed_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_logo_cmpl_action(emlxs_port_t *port,
			VPIobj_t *vpip, uint32_t evt, void *arg1);

static uint32_t emlxs_vpi_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static uint32_t emlxs_vpi_logi_cmpl_notify(emlxs_port_t *port,
			RPIobj_t *rpip);
static void emlxs_vpi_logo_handler(emlxs_port_t *port,
			VPIobj_t *vpip);

/*
 * - Online sequencing can only start from VPI_STATE_OFFLINE or
 * VPI_STATE_PORT_OFFLINE state.
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * VPI_ONLINE event <-- VFI
 * VPI_STATE_OFFLINE
 * VPI_STATE_INIT
 *     VPI_STATE_INIT_CMPL
 * VPI_STATE_PORT_ONLINE
 * VPI_STATE_LOGI
 *     VPI_STATE_LOGI_CMPL
 * VPI_STATE_REG
 *     VPI_STATE_REG_CMPL
 * VPI_STATE_ONLINE
 * VPI_ONLINE event-->VFI
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * VPI_OFFLINE event <-- VFI
 * VPI_STATE_ONLINE
 * VPI_STATE_PORT_OFFLINE
 * VPI_STATE_LOGO
 *     VPI_STATE_LOGO_CMPL
 * VPI_STATE_UNREG
 *     VPI_STATE_UNREG_CMPL
 * VPI_STATE_OFFLINE
 * VPI_OFFLINE event-->VFI
 *
 *
 * NORMAL PAUSE SEQ
 * ---------------------------
 * VPI_PAUSE event <-- VFI
 * VPI_STATE_ONLINE
 * VPI_STATE_PORT_OFFLINE
 * VPI_STATE_PAUSED
 *
 */
/* Order does matter */
static void *emlxs_vpi_action_table[] =
{
	/* Action routine				Event */
/* VPI_STATE_OFFLINE  0 		(Wait for VPI_ONLINE event) */
	(void *) emlxs_vpi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_INIT  1 			(Wait for init_vpi cmpl) */
	(void *) emlxs_vpi_init_action,			/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_INIT_FAILED  2  		(Transitional) */
	(void *) emlxs_vpi_init_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_INIT_CMPL  3 		(Transitional) */
	(void *) emlxs_vpi_init_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_UNREG_CMPL  4 		(Transitional) */
	(void *) emlxs_vpi_unreg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_UNREG_FAILED  5  		(Transitional) */
	(void *) emlxs_vpi_unreg_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_UNREG  6 			(Wait for unreg_vpi cmpl) */
	(void *) emlxs_vpi_unreg_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_LOGO_CMPL  7 		(Transitional) */
	(void *) emlxs_vpi_logo_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_LOGO_FAILED  8  		(Transitional) */
	(void *) emlxs_vpi_logo_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_LOGO  9 			(Transitional) */
	(void *) emlxs_vpi_logo_action,			/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_PORT_OFFLINE  10	(Wait for RPI_OFFLINE or VPI_ONLINE) */
	(void *) emlxs_vpi_port_offline_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_PORT_ONLINE  11 	(Wait for emlxs_vpi_logi_notify() ) */
	(void *) emlxs_vpi_port_online_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_LOGI  12 		(Wait for emlxs_vpi_logi_cmpl_notify() ) */
	(void *) emlxs_vpi_logi_action,			/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_LOGI_FAILED  13  		(Transitional) */
	(void *) emlxs_vpi_logi_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_LOGI_CMPL  14 		(Transitional) */
	(void *) emlxs_vpi_logi_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_REG  15 			(Wait for reg_vpi cmpl) */
	(void *) emlxs_vpi_reg_action,			/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_REG_FAILED  16  		(Transitional) */
	(void *) emlxs_vpi_reg_failed_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_REG_CMPL  17 		(Transitional) */
	(void *) emlxs_vpi_reg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */


/* VPI_STATE_PAUSED 18			(Wait for VPI_ONLINE() ) */
	(void *) emlxs_vpi_paused_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

/* VPI_STATE_ONLINE  19 		(Wait for VPI_OFFLINE event) */
	(void *) emlxs_vpi_online_action,		/* STATE_ENTER */
	(void *) emlxs_vpi_online_evt_action,		/* VPI_ONLINE */
	(void *) emlxs_vpi_offline_evt_action,		/* VPI_OFFLINE */
	(void *) emlxs_vpi_pause_evt_action,		/* VPI_PAUSE */
	(void *) emlxs_vpi_rpi_online_evt_action,	/* RPI_ONLINE */
	(void *) emlxs_vpi_rpi_offline_evt_action,	/* RPI_OFFLINE */
	(void *) emlxs_vpi_rpi_pause_evt_action,	/* RPI_PAUSE */

}; /* emlxs_vpi_action_table() */
#define	VPI_ACTION_EVENTS			7
#define	VPI_ACTION_STATES			\
	(sizeof (emlxs_vpi_action_table)/ \
	(VPI_ACTION_EVENTS * sizeof (void *)))


/* ********************************************************************** */
/* RPI */
/* ********************************************************************** */

/* Order does not matter */
emlxs_table_t emlxs_rpi_state_table[] =
{
	{RPI_STATE_FREE, "RPI_FREE"},

	{RPI_STATE_RESERVED, "RPI_RESERVED"},
	{RPI_STATE_OFFLINE, "RPI_OFFLINE"},

	{RPI_STATE_UNREG_CMPL, "RPI_UNREG_CMPL"},
	{RPI_STATE_UNREG_FAILED, "RPI_UNREG_FAILED"},
	{RPI_STATE_UNREG, "RPI_UNREG"},

	{RPI_STATE_REG, "RPI_REG"},
	{RPI_STATE_REG_FAILED, "RPI_REG_FAILED"},
	{RPI_STATE_REG_CMPL, "RPI_REG_CMPL"},

	{RPI_STATE_PAUSED, "RPI_PAUSED"},

	{RPI_STATE_RESUME, "RPI_RESUME"},
	{RPI_STATE_RESUME_FAILED, "RPI_RESUME_FAILED"},
	{RPI_STATE_RESUME_CMPL, "RPI_RESUME_CMPL"},

	{RPI_STATE_ONLINE, "RPI_ONLINE"},

}; /* emlxs_rpi_state_table */

static uint32_t emlxs_rpi_free_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_online_evt_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_offline_evt_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_pause_evt_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_resume_evt_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_reg_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_reg_cmpl_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_reg_failed_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_unreg_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_unreg_cmpl_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_unreg_failed_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_online_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_paused_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_offline_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_reserved_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_resume_failed_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_resume_cmpl_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);
static uint32_t emlxs_rpi_resume_action(emlxs_port_t *port,
			RPIobj_t *rpip, uint32_t evt, void *arg1);

static uint32_t emlxs_rpi_event(emlxs_port_t *port,
			uint32_t evt, void *arg1);
static RPIobj_t *emlxs_rpi_alloc(emlxs_port_t *port, uint32_t did);
static uint32_t emlxs_rpi_free(emlxs_port_t *port, RPIobj_t *rpip);
static RPIobj_t *emlxs_rpi_find_did(emlxs_port_t *port, uint32_t did);

static void emlxs_rpi_resume_handler(emlxs_port_t *port,
			RPIobj_t *rpip);
static void emlxs_rpi_unreg_handler(emlxs_port_t *port,
			RPIobj_t *rpip);
static uint32_t emlxs_rpi_reg_handler(emlxs_port_t *port,
			RPIobj_t *rpip);

static void emlxs_rpi_idle_timer(emlxs_hba_t *hba);

static uint32_t emlxs_rpi_state(emlxs_port_t *port, RPIobj_t *rpip,
			uint16_t state, uint16_t reason, uint32_t explain,
			void *arg1);

static void emlxs_rpi_alloc_fabric_rpi(emlxs_port_t *port);

static void emlxs_rpi_deferred_cmpl(emlxs_port_t *port, RPIobj_t *rpip,
			uint32_t status);

/*
 * - Online sequencing can start from RPI_STATE_RESERVED state or
 * the RPI_STATE_PAUSED state.
 *
 * - Offline sequencing can interrupt the online sequencing at the
 * entry of the next wait state.
 *
 * NORMAL ONLINE SEQ
 * ---------------------------
 * RPI_ONLINE event <-- VPI
 * RPI_STATE_RESERVED
 * RPI_STATE_REG
 *     RPI_STATE_REG_CMPL
 * RPI_STATE_ONLINE
 * RPI_ONLINE event-->VPI
 *
 *
 * NORMAL OFFLINE SEQ
 * ---------------------------
 * RPI_OFFLINE event <-- VPI
 * RPI_STATE_ONLINE
 * RPI_STATE_UNREG
 *     RPI_STATE_UNREG_CMPL
 * RPI_STATE_OFFLINE
 * RPI_OFFLINE event-->VPI
 *
 *
 * NORMAL PAUSE SEQ
 * ---------------------------
 * RPI_PAUSE event <-- VPI
 * RPI_STATE_ONLINE
 * RPI_STATE_PAUSED
 *
 */
/* Order does matter */
static void *emlxs_rpi_action_table[] =
{
	/* Action routine				Event */
/* RPI_STATE_FREE  0			(Wait for allocation) */
	(void *) emlxs_rpi_free_action,			/* STATE_ENTER */
	(void *) NULL,					/* RPI_ONLINE */
	(void *) NULL,					/* RPI_OFFLINE */
	(void *) NULL,					/* RPI_PAUSE */
	(void *) NULL,					/* RPI_RESUME */

/* RPI_STATE_RESERVED  1		(Wait for RPI_ONLINE event) */
	(void *) emlxs_rpi_reserved_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_OFFLINE  2			(Transitional) */
	(void *) emlxs_rpi_offline_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_UNREG_CMPL  3		(Transitional)  */
	(void *) emlxs_rpi_unreg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_UNREG_FAILED  4		(Transitional) */
	(void *) emlxs_rpi_unreg_failed_action, 	/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_UNREG  5			(Wait for unreg_rpi cmpl) */
	(void *) emlxs_rpi_unreg_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */


/* RPI_STATE_REG  6			(Wait for reg_rpi cmpl) */
	(void *) emlxs_rpi_reg_action,			/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_REG_FAILED  7		(Transitional) */
	(void *) emlxs_rpi_reg_failed_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_REG_CMPL  8		(Transitional) */
	(void *) emlxs_rpi_reg_cmpl_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,  		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action, 		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */


/* RPI_STATE_PAUSED  9			(Wait for RPI_ONLINE) */
	(void *) emlxs_rpi_paused_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */


/* RPI_STATE_RESUME  10			(Wait for resume_rpi mbcmpl) */
	(void *) emlxs_rpi_resume_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_RESUME_FAILED  11		(Transitional) */
	(void *) emlxs_rpi_resume_failed_action,	/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

/* RPI_STATE_RESUME_CMPL  12		(Transitional) */
	(void *) emlxs_rpi_resume_cmpl_action, 		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */


/* RPI_STATE_ONLINE 13			(Wait for RPI_OFFLINE event) */
	(void *) emlxs_rpi_online_action,		/* STATE_ENTER */
	(void *) emlxs_rpi_online_evt_action,		/* RPI_ONLINE */
	(void *) emlxs_rpi_offline_evt_action,		/* RPI_OFFLINE */
	(void *) emlxs_rpi_pause_evt_action,		/* RPI_PAUSE */
	(void *) emlxs_rpi_resume_evt_action,		/* RPI_RESUME */

}; /* emlxs_rpi_action_table[] */
#define	RPI_ACTION_EVENTS			5
#define	RPI_ACTION_STATES			\
	(sizeof (emlxs_rpi_action_table)/ \
	(RPI_ACTION_EVENTS * sizeof (void *)))


/* ************************************************************************** */
/* FCF Generic */
/* ************************************************************************** */
static void
emlxs_fcf_linkdown(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;

	if (hba->state <= FC_LINK_DOWN) {
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->state <= FC_LINK_DOWN) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	HBASTATS.LinkDown++;
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_LINK_DOWN);

	hba->flag &= FC_LINKDOWN_MASK;
	hba->discovery_timer = 0;
	hba->linkup_timer = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	emlxs_log_link_event(port);

	return;

} /* emlxs_fcf_linkdown() */


static void
emlxs_fcf_linkup(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;

	if (hba->state >= FC_LINK_UP) {
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->state >= FC_LINK_UP) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* Check for any mode changes */
	emlxs_mode_set(hba);

	HBASTATS.LinkUp++;
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_LINK_UP);

	hba->discovery_timer = hba->timer_tics +
	    cfg[CFG_LINKUP_TIMEOUT].current +
	    cfg[CFG_DISC_TIMEOUT].current;

	mutex_exit(&EMLXS_PORT_LOCK);

	emlxs_log_link_event(port);

	return;

} /* emlxs_fcf_linkup() */


extern void
emlxs_fcf_fini(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	uint32_t	i;
	RPIobj_t	*rpip;

	if (!(hba->sli.sli4.flag & EMLXS_SLI4_FCF_INIT)) {
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_fini: %s flag=%x fcfi_online=%d.",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	if (!(fcftab->flag & EMLXS_FCFTAB_SHUTDOWN)) {
		(void) emlxs_fcf_shutdown_notify(port, 1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);
	hba->sli.sli4.flag &= ~EMLXS_SLI4_FCF_INIT;

	/* Free the FCF memory */

	kmem_free(fcftab->table,
	    (sizeof (FCFIobj_t) * fcftab->table_count));

	fcftab->table = NULL;
	fcftab->table_count = 0;

	/* Free the VFI memory */

	kmem_free(hba->sli.sli4.VFI_table,
	    (sizeof (VFIobj_t) * hba->sli.sli4.VFICount));

	hba->sli.sli4.VFI_table = NULL;
	hba->sli.sli4.VFICount = 0;

	/* Free the VPI Fabric RPI's */

	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		rpip = vport->vpip->fabric_rpip;

		if (rpip->state == RPI_STATE_FREE) {
			continue;
		}

		(void) emlxs_rpi_free(port, rpip);
	}

	/* Free the RPI memory */

	rpip = hba->sli.sli4.RPIp;
	for (i = 0; i < hba->sli.sli4.RPICount; i++, rpip++) {
		if (rpip->state == RPI_STATE_FREE) {
			continue;
		}

		(void) emlxs_rpi_free(port, rpip);
	}

	kmem_free(hba->sli.sli4.RPIp,
	    (sizeof (RPIobj_t) * hba->sli.sli4.RPICount));

	hba->sli.sli4.RPIp = NULL;
	hba->sli.sli4.RPICount = 0;

	/* Free the mutex */
	mutex_exit(&EMLXS_FCF_LOCK);
	mutex_destroy(&EMLXS_FCF_LOCK);

	return;

} /* emlxs_fcf_fini() */


extern void
emlxs_fcf_init(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_port_t	*vport;
	uint16_t	i;
	FCFIobj_t	*fcfp;
	VPIobj_t	*vpip;
	VFIobj_t	*vfip;
	RPIobj_t	*rpip;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;

	if (hba->sli.sli4.flag & EMLXS_SLI4_FCF_INIT) {
		return;
	}

	mutex_init(&EMLXS_FCF_LOCK, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&EMLXS_FCF_LOCK);

	/* FCFTAB */

	bzero(fcftab, sizeof (FCFTable_t));
	fcftab->state = FCFTAB_STATE_OFFLINE;

	/* FCFI */

	fcftab->table_count = hba->sli.sli4.FCFICount;
	fcftab->table = (FCFIobj_t *)kmem_zalloc(
	    (sizeof (FCFIobj_t) * fcftab->table_count), KM_SLEEP);

	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {
		fcfp->index = i;
		fcfp->FCFI  = 0xFFFF;
		fcfp->state = FCFI_STATE_FREE;
	}

	/* VFI */

	hba->sli.sli4.VFI_table = (VFIobj_t *)kmem_zalloc(
	    (sizeof (VFIobj_t) * hba->sli.sli4.VFICount), KM_SLEEP);

	vfip = hba->sli.sli4.VFI_table;
	for (i = 0; i < hba->sli.sli4.VFICount; i++, vfip++) {
		vfip->VFI = emlxs_sli4_index_to_vfi(hba, i);
		vfip->index = i;
		vfip->state = VFI_STATE_OFFLINE;
	}

	/* VPI */

	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vpip = &vport->VPIobj;

		bzero(vpip, sizeof (VPIobj_t));
		vpip->index = i;
		vpip->VPI = emlxs_sli4_index_to_vpi(hba, i);
		vpip->port = vport;
		vpip->state = VPI_STATE_OFFLINE;
		vport->vpip = vpip;

		/* Init the Fabric RPI's */
		rpip = &vpip->fabric_rpi;
		rpip->state = RPI_STATE_FREE;
		rpip->index = 0xffff;
		rpip->RPI   = FABRIC_RPI;
		rpip->did   = FABRIC_DID;
		rpip->vpip  = vpip;
		vpip->fabric_rpip = rpip;
	}

	/* RPI */

	hba->sli.sli4.RPIp = (RPIobj_t *)kmem_zalloc(
	    (sizeof (RPIobj_t) * hba->sli.sli4.RPICount), KM_SLEEP);

	rpip = hba->sli.sli4.RPIp;
	for (i = 0; i < hba->sli.sli4.RPICount; i++, rpip++) {
		rpip->state = RPI_STATE_FREE;
		rpip->RPI = emlxs_sli4_index_to_rpi(hba, i);
		rpip->index = i;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_init: %s flag=%x fcfi=%d vfi=%d vpi=%d rpi=%d.",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag,
	    fcftab->table_count,
	    hba->sli.sli4.VFICount,
	    MAX_VPORTS,
	    hba->sli.sli4.RPICount);

	hba->sli.sli4.flag |= EMLXS_SLI4_FCF_INIT;
	mutex_exit(&EMLXS_FCF_LOCK);

	return;

} /* emlxs_fcf_init() */


static char *
emlxs_fcf_event_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_fcf_event_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_fcf_event_table[i].code) {
			return (emlxs_fcf_event_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "event=0x%x", state);
	return (buffer);

} /* emlxs_fcf_event_xlate() */


static char *
emlxs_fcf_reason_xlate(uint32_t reason)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_fcf_reason_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (reason == emlxs_fcf_reason_table[i].code) {
			return (emlxs_fcf_reason_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "reason=0x%x", reason);
	return (buffer);

} /* emlxs_fcf_reason_xlate() */


extern void
emlxs_fcf_timer_notify(emlxs_hba_t *hba)
{
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return;
	}

	if (fcftab->table == 0) {
		return;
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (SLI4_FCOE_MODE) {
		emlxs_fcoe_fcftab_sol_timer(hba);

		emlxs_fcoe_fcftab_read_timer(hba);

		emlxs_fcoe_fcftab_offline_timer(hba);
	} else {
		emlxs_fc_fcftab_online_timer(hba);
	}

	emlxs_rpi_idle_timer(hba);

	mutex_exit(&EMLXS_FCF_LOCK);

	return;

} /* emlxs_fcf_timer_notify() */


extern uint32_t
emlxs_fcf_shutdown_notify(emlxs_port_t *port, uint32_t wait)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	uint32_t i;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_SHUTDOWN) {
		return (0);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_shutdown_notify: %s flag=%x "
	    "fcfi_online=%d. Shutting down FCFTAB. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_SHUTDOWN, 0);

	if (wait && (rval == 0)) {
		/* Wait for shutdown flag */
		i = 0;
		while (!(fcftab->flag & EMLXS_FCFTAB_SHUTDOWN) && (i++ < 120)) {
			mutex_exit(&EMLXS_FCF_LOCK);
			BUSYWAIT_MS(1000);
			mutex_enter(&EMLXS_FCF_LOCK);
		}

		if (!(fcftab->flag & EMLXS_FCFTAB_SHUTDOWN)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
			    "fcf_shutdown_notify: %s flag=%x "
			    "fcfi_online=%d. Shutdown timeout.",
			    emlxs_fcftab_state_xlate(port, fcftab->state),
			    fcftab->flag, fcftab->fcfi_online);
			rval = 1;
		}
	}

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_shutdown_notify() */


extern uint32_t
emlxs_fcf_linkup_notify(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_linkup_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB Link up. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_LINKUP, 0);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_linkup_notify() */


extern uint32_t
emlxs_fcf_linkdown_notify(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_linkdown_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB Link down. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_LINKDOWN, 0);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_linkdown_notify() */


extern uint32_t
emlxs_fcf_cvl_notify(emlxs_port_t *port, uint32_t vpi)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_cvl_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB FCF CVL. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_CVL,
	    (void *)((unsigned long)vpi));

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_cvl_notify() */


extern uint32_t
emlxs_fcf_full_notify(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_full_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB FCF full. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_FCFTAB_FULL, 0);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_full_notify() */


extern uint32_t
emlxs_fcf_found_notify(emlxs_port_t *port, uint32_t fcf_index)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_found_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB FCF found. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_FCF_FOUND,
	    (void *)((unsigned long)fcf_index));

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_found_notify() */


extern uint32_t
emlxs_fcf_changed_notify(emlxs_port_t *port, uint32_t fcf_index)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_changes_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB FCF changed. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_FCF_CHANGED,
	    (void *)((unsigned long)fcf_index));

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_changed_notify() */


extern uint32_t
emlxs_fcf_lost_notify(emlxs_port_t *port, uint32_t fcf_index)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(pport->flag & EMLXS_PORT_BOUND) ||
	    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcf_lost_notify: %s flag=%x "
	    "fcfi_online=%d. FCFTAB FCF lost. >",
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    fcftab->flag, fcftab->fcfi_online);

	rval = emlxs_fcftab_event(port, FCF_EVENT_FCF_LOST,
	    (void *)((unsigned long)fcf_index));

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_fcf_lost_notify() */


/* ************************************************************************** */
/* FCFTAB Generic */
/* ************************************************************************** */

static char *
emlxs_fcftab_state_xlate(emlxs_port_t *port, uint32_t state)
{
	emlxs_hba_t *hba = HBA;

	if (SLI4_FCOE_MODE) {
		return (emlxs_fcoe_fcftab_state_xlate(state));
	} else {
		return (emlxs_fc_fcftab_state_xlate(state));
	}

} /* emlxs_fcftab_state_xlate() */

static uint32_t
emlxs_fcftab_event(emlxs_port_t *port, uint32_t evt, void *arg1)
{
	emlxs_hba_t *hba = HBA;

	if (SLI4_FCOE_MODE) {
		return (emlxs_fcoe_fcftab_event(port, evt, arg1));
	} else {
		return (emlxs_fc_fcftab_event(port, evt, arg1));
	}

} /* emlxs_fcftab_event() */


/*ARGSUSED*/
static uint32_t
emlxs_fcftab_shutdown_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t i;
	uint32_t online;

	if (fcftab->state != FCFTAB_STATE_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcftab_shutdown_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcftab_state_xlate(port, fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;

	if (fcftab->prev_state != FCFTAB_STATE_SHUTDOWN) {
		/* Offline all FCF's */
		online = 0;
		fcfp = fcftab->table;
		for (i = 0; i < fcftab->table_count; i++, fcfp++) {

			if (fcfp->state <= FCFI_STATE_OFFLINE) {
				continue;
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcftab_shutdown_action:%x fcfi_online=%d. "
			    "Offlining FCFI:%d. >",
			    fcftab->TID,
			    fcftab->fcfi_online,
			    fcfp->fcf_index);

			(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_OFFLINE,
			    fcfp);

			online++;
		}

		if (!online) {
			goto done;
		}

		return (0);
	}

	/* Check FCF states */
	online = 0;
	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {

		if (fcfp->state <= FCFI_STATE_OFFLINE) {
			continue;
		}

		online++;
	}

	if (online) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcftab_shutdown_action:%x %s:%s arg=%p. "
		    "fcfi_online=%d,%d <",
		    fcftab->TID,
		    emlxs_fcftab_state_xlate(port, fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    online, fcftab->fcfi_online);

		return (0);
	}

done:
	/* Free FCF table */
	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {

		if (fcfp->state == FCFI_STATE_FREE) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcftab_shutdown_action:%x. Freeing FCFI:%d. >",
		    fcftab->TID,
		    fcfp->fcf_index);

		(void) emlxs_fcfi_free(port, fcfp);
	}

	/* Clean the selection table */
	bzero(fcftab->fcfi, sizeof (fcftab->fcfi));
	fcftab->fcfi_count = 0;

	fcftab->flag |= EMLXS_FCFTAB_SHUTDOWN;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcftab_shutdown_action:%x %s:%s arg=%p flag=%x fcfi_online=%d. "
	    "Shutdown. <",
	    fcftab->TID,
	    emlxs_fcftab_state_xlate(port, fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->flag, fcftab->fcfi_online);

	return (0);

} /* emlxs_fcftab_shutdown_action() */


/* ************************************************************************** */
/* FC FCFTAB */
/* ************************************************************************** */

static char *
emlxs_fc_fcftab_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_fc_fcftab_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_fc_fcftab_state_table[i].code) {
			return (emlxs_fc_fcftab_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_fc_fcftab_state_xlate() */


static uint32_t
emlxs_fc_fcftab_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_SHUTDOWN:
		index = 1;
		break;
	case FCF_EVENT_LINKUP:
		index = 2;
		break;
	case FCF_EVENT_LINKDOWN:
		index = 3;
		break;
	case FCF_EVENT_FCFI_ONLINE:
		index = 4;
		break;
	case FCF_EVENT_FCFI_OFFLINE:
		index = 5;
		break;
	default:
		return (1);
	}

	events = FC_FCFTAB_ACTION_EVENTS;
	state  = fcftab->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, uint32_t, void *))
	    emlxs_fc_fcftab_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "fc_fcftab_action:%x %s:%s arg=%p. No action. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_action() */


static uint32_t
emlxs_fc_fcftab_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	/* Filter events */
	switch (evt) {
	case FCF_EVENT_SHUTDOWN:
	case FCF_EVENT_LINKUP:
	case FCF_EVENT_LINKDOWN:
	case FCF_EVENT_FCFI_ONLINE:
	case FCF_EVENT_FCFI_OFFLINE:
		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "fc_fcftab_event:%x %s:%s arg=%p.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fc_fcftab_action(port, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_event() */


/* EMLXS_FCF_LOCK must be held to enter */
/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_state(emlxs_port_t *port, uint16_t state, uint16_t reason,
    uint32_t explain, void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (state >= FC_FCFTAB_ACTION_STATES) {
		return (1);
	}

	if ((fcftab->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcftab_state:%x %s:%s:0x%x arg=%p. "
		    "State not changed. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s arg=%p",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fc_fcftab_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s:%s arg=%p",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fc_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s:0x%x arg=%p",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fc_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s arg=%p",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fc_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	fcftab->prev_state = fcftab->state;
	fcftab->prev_reason = fcftab->reason;
	fcftab->state = state;
	fcftab->reason = reason;

	rval = emlxs_fc_fcftab_action(port, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_fc_fcftab_state() */


static void
emlxs_fc_fcftab_online_timer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;

	/* Check FCF timer */
	if (!fcftab->online_timer ||
	    (hba->timer_tics < fcftab->online_timer)) {
		return;
	}
	fcftab->online_timer = 0;

	switch (fcftab->state) {
	case FC_FCFTAB_STATE_ONLINE:
		emlxs_fcf_linkup(port);

		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FC_FCFTAB_TOPO_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_online_timer:%x %s gen=%x. Read topology. >",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		(void) emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO,
		    FCF_REASON_EVENT, 0, 0);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_online_timer:%x %s",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state));
		break;
	}

	return;

}  /* emlxs_fc_fcftab_online_timer() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_offline_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_offline_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	fcftab->flag &= ~EMLXS_FC_FCFTAB_OFFLINE_REQ;

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_offline_action:%x %s:%s arg=%p flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_offline_action:%x %s:%s arg=%p fcfi_online=%d. "
	    "Offline. <",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->fcfi_online);

	return (0);

} /* emlxs_fc_fcftab_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_online_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *pport = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_online_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_online_action:%x flag=%x. "
		    "Handling requested.",
		    fcftab->TID,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->fcfi_online == 0) {
		if (!(pport->flag & EMLXS_PORT_BOUND) ||
		    (pport->vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fc_fcftab_online_action:%x %s:%s "
			    "fcfi_online=0. Pport not bound. <",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt));
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fc_fcftab_online_action:%x %s:%s "
			    "fcfi_online=0. Starting online timer. <",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt));

			/* Start the online timer */
			fcftab->online_timer = hba->timer_tics + 1;
		}

		emlxs_fcf_linkdown(port);

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_online_action:%x flag=%x fcfi_online=%d. "
	    "Online. <",
	    fcftab->TID,
	    fcftab->flag,
	    fcftab->fcfi_online);

	emlxs_fcf_linkup(port);

	return (0);

} /* emlxs_fc_fcftab_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_topo_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	MATCHMAP *mp;
	uint8_t *alpa_map;
	uint32_t j;
	uint16_t TID;

	mutex_enter(&EMLXS_FCF_LOCK);
	TID = (uint16_t)((unsigned long)mbq->context);

	if (fcftab->state != FC_FCFTAB_STATE_TOPO) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_mbcmpl:%x state=%s.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (TID != fcftab->generation) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_mbcmpl:%x %s. "
		    "Incorrect generation %x. Dropping.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_mbcmpl:%x failed. %s. >",
		    fcftab->TID,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		if (mb4->mbxStatus == MBXERR_NO_RESOURCES) {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_TOPO_FAILED,
			    FCF_REASON_MBOX_BUSY, mb4->mbxStatus, 0);
		} else {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_TOPO_FAILED,
			    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);
		}

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->un.varReadLA.attType == AT_LINK_DOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_mbcmpl:%x  Linkdown attention. "
		    "Offline requested.",
		    fcftab->TID);

		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FC_FCFTAB_OFFLINE_REQ;
		(void) emlxs_fc_fcftab_req_handler(port, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (hba->link_event_tag != mb4->un.varReadLA.eventTag) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_mbcmpl:%x Event tag invalid. %x != %x",
		    fcftab->TID,
		    hba->link_event_tag, mb4->un.varReadLA.eventTag);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_topo_mbcmpl:%x state=%s type=%s iotag=%d "
	    "alpa=%x. >",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    (mb4->un.varReadLA.attType == AT_LINK_UP)?"linkup":"linkdown",
	    hba->link_event_tag,
	    (uint32_t)mb4->un.varReadLA.granted_AL_PA);

	/* Link is up */

	/* Save the linkspeed & topology */
	hba->linkspeed = mb4->un.varReadLA.UlnkSpeed;
	hba->topology = mb4->un.varReadLA.topology;

	if (hba->topology != TOPOLOGY_LOOP) {
		port->did = 0;
		port->lip_type = 0;
		hba->flag &= ~FC_BYPASSED_MODE;
		bzero((caddr_t)port->alpa_map, 128);

		goto done;
	}

	/* TOPOLOGY_LOOP */

	port->lip_type = mb4->un.varReadLA.lipType;

	if (mb4->un.varReadLA.pb) {
		hba->flag |= FC_BYPASSED_MODE;
	} else {
		hba->flag &= ~FC_BYPASSED_MODE;
	}

	/* Save the granted_alpa and alpa_map */

	port->granted_alpa = mb4->un.varReadLA.granted_AL_PA;
	mp = (MATCHMAP *)mbq->bp;
	alpa_map = (uint8_t *)port->alpa_map;

	bcopy((caddr_t)mp->virt, (caddr_t)alpa_map, 128);

	/* Check number of devices in map */
	if (alpa_map[0] > 127) {
		alpa_map[0] = 127;
	}

	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_link_atten_msg,
	    "alpa_map: %d device(s): "
	    "%02x %02x %02x %02x %02x %02x %02x %02x",
	    alpa_map[0], alpa_map[1],
	    alpa_map[2], alpa_map[3],
	    alpa_map[4], alpa_map[5],
	    alpa_map[6], alpa_map[7],
	    alpa_map[8]);

	for (j = 9; j <= alpa_map[0]; j += 8) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_link_atten_msg,
		    "alpa_map:               "
		    "%02x %02x %02x %02x %02x %02x %02x %02x",
		    alpa_map[j],
		    alpa_map[j + 1],
		    alpa_map[j + 2],
		    alpa_map[j + 3],
		    alpa_map[j + 4],
		    alpa_map[j + 5],
		    alpa_map[j + 6],
		    alpa_map[j + 7]);
	}

done:

	(void) emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fc_fcftab_topo_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_topo_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	uint32_t rval = 0;
	MATCHMAP *mp;

	if (fcftab->state != FC_FCFTAB_STATE_TOPO) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_topo_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcftab->prev_state != FC_FCFTAB_STATE_TOPO_FAILED) ||
	    (fcftab->flag & EMLXS_FC_FCFTAB_TOPO_REQ)) {
		fcftab->flag &= ~EMLXS_FC_FCFTAB_TOPO_REQ;
		fcftab->attempts = 0;
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->attempts == 0) {
		fcftab->TID = fcftab->generation;
	}

	if (hba->topology != TOPOLOGY_LOOP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
		    "Fabric Topology. Skipping READ_TOPO.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		port->did = 0;
		port->lip_type = 0;
		hba->flag &= ~FC_BYPASSED_MODE;
		bzero((caddr_t)port->alpa_map, 128);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
	    "Sending READ_TOPO. <",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation,
	    fcftab->flag);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO_FAILED,
		    FCF_REASON_NO_BUFFER, 0, arg1);
		return (rval);
	}
	bzero(mp->virt, mp->size);

	mbq->nonembed = NULL;
	mbq->bp = (void *)mp;
	mbq->mbox_cmpl = emlxs_fc_fcftab_topo_mbcmpl;
	mbq->context = (void *)((unsigned long)fcftab->TID);
	mbq->port = (void *)port;

	mb4->un.varSLIConfig.be.embedded = 0;
	mb4->mbxCommand = MBX_READ_TOPOLOGY;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varReadLA.un.lilpBde64.tus.f.bdeSize = 128;
	mb4->un.varReadLA.un.lilpBde64.addrHigh = PADDR_HI(mp->phys);
	mb4->un.varReadLA.un.lilpBde64.addrLow = PADDR_LO(mp->phys);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fc_fcftab_topo_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_topo_failed_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	fcftab->attempts++;

	if (fcftab->state != FC_FCFTAB_STATE_TOPO_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_topo_failed_action:%x %s:%s arg=%p "
		    "attempt=%d. Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcftab->attempts);
		return (1);
	}

	if ((fcftab->reason == FCF_REASON_MBOX_FAILED) ||
	    (fcftab->reason == FCF_REASON_SEND_FAILED) ||
	    (fcftab->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Giving up.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO_CMPL,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_topo_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Retrying.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);
	}

	return (rval);

} /* emlxs_fc_fcftab_topo_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_topo_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_TOPO_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_topo_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_topo_cmpl_action:%x attempts=%d. "
	    "Config link.",
	    fcftab->TID,
	    fcftab->attempts);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_topo_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_cfglink_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	uint16_t TID;

	mutex_enter(&EMLXS_FCF_LOCK);
	TID = (uint16_t)((unsigned long)mbq->context);

	if (fcftab->state != FC_FCFTAB_STATE_CFGLINK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_cfglink_mbcmpl:%x state=%s.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (TID != fcftab->generation) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_cfglink_mbcmpl:%x %s. "
		    "Incorrect generation %x. Dropping.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_cfglink_mbcmpl:%x failed. %s. >",
		    fcftab->TID,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		if (mb4->mbxStatus == MBXERR_NO_RESOURCES) {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_CFGLINK_FAILED,
			    FCF_REASON_MBOX_BUSY, mb4->mbxStatus, 0);
		} else {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_CFGLINK_FAILED,
			    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);
		}

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "fc_fcftab_cfglink_mbcmpl:%x. >",
	    fcftab->TID);

	(void) emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fc_fcftab_cfglink_mbcmpl() */



/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_cfglink_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_CFGLINK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_cfglink_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcftab->prev_state != FC_FCFTAB_STATE_CFGLINK_FAILED) ||
	    (fcftab->flag & EMLXS_FC_FCFTAB_CFGLINK_REQ)) {
		fcftab->flag &= ~EMLXS_FC_FCFTAB_CFGLINK_REQ;
		fcftab->attempts = 0;
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->attempts == 0) {
		fcftab->TID = fcftab->generation;
	}

	if (hba->topology != TOPOLOGY_LOOP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
		    "Fabric Topology. Skipping CONFIG_LINK.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
	    "Sending CONFIG_LINK. <",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation,
	    fcftab->flag);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fc_fcftab_state(port,
		    FC_FCFTAB_STATE_CFGLINK_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_fc_fcftab_cfglink_mbcmpl;
	mbq->context = (void *)((unsigned long)fcftab->TID);
	mbq->port = (void *)port;

	mb4->un.varSLIConfig.be.embedded = 0;
	mb4->mbxCommand = MBX_CONFIG_LINK;
	mb4->mbxOwner = OWN_HOST;

	if (cfg[CFG_CR_DELAY].current) {
		mb4->un.varCfgLnk.cr = 1;
		mb4->un.varCfgLnk.ci = 1;
		mb4->un.varCfgLnk.cr_delay = cfg[CFG_CR_DELAY].current;
		mb4->un.varCfgLnk.cr_count = cfg[CFG_CR_COUNT].current;
	}

	if (cfg[CFG_ACK0].current) {
		mb4->un.varCfgLnk.ack0_enable = 1;
	}

	mb4->un.varCfgLnk.myId = port->did;
	mb4->un.varCfgLnk.edtov = hba->fc_edtov;
	mb4->un.varCfgLnk.arbtov = hba->fc_arbtov;
	mb4->un.varCfgLnk.ratov = hba->fc_ratov;
	mb4->un.varCfgLnk.rttov = hba->fc_rttov;
	mb4->un.varCfgLnk.altov = hba->fc_altov;
	mb4->un.varCfgLnk.crtov = hba->fc_crtov;
	mb4->un.varCfgLnk.citov = hba->fc_citov;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fc_fcftab_state(port,
		    FC_FCFTAB_STATE_CFGLINK_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fc_fcftab_cfglink_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_cfglink_failed_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	fcftab->attempts++;

	if (fcftab->state != FC_FCFTAB_STATE_CFGLINK_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_cfglink_failed_action:%x %s:%s arg=%p "
		    "attempt=%d. Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcftab->attempts);
		return (1);
	}

	if ((fcftab->reason == FCF_REASON_MBOX_FAILED) ||
	    (fcftab->reason == FCF_REASON_SEND_FAILED) ||
	    (fcftab->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_cfglink_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Giving up.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK_CMPL,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_cfglink_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Retrying.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);
	}

	return (rval);

} /* emlxs_fc_fcftab_cfglink_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_cfglink_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_CFGLINK_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_cfglink_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_cfglink_cmpl_action:%x attempts=%d. "
	    "Read SPARM.",
	    fcftab->TID,
	    fcftab->attempts);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_cfglink_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_sparm_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	MATCHMAP *mp;
	emlxs_port_t *vport;
	VPIobj_t *vpip;
	int32_t i;
	uint8_t null_wwn[8];
	uint16_t TID;

	mutex_enter(&EMLXS_FCF_LOCK);
	TID = (uint16_t)((unsigned long)mbq->context);

	if (fcftab->state != FC_FCFTAB_STATE_SPARM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sparm_mbcmpl:%x state=%s.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (TID != fcftab->generation) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sparm_mbcmpl:%x %s. "
		    "Incorrect generation %x. Dropping.",
		    TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_sparm_mbcmpl:%x failed. %s. >",
		    fcftab->TID,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		if (mb4->mbxStatus == MBXERR_NO_RESOURCES) {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_SPARM_FAILED,
			    FCF_REASON_MBOX_BUSY, mb4->mbxStatus, 0);
		} else {
			(void) emlxs_fc_fcftab_state(port,
			    FC_FCFTAB_STATE_SPARM_FAILED,
			    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);
		}

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	/* Save the parameters */
	mp = (MATCHMAP *)mbq->bp;
	bcopy((caddr_t)mp->virt, (caddr_t)&hba->sparam, sizeof (SERV_PARM));

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "fc_fcftab_sparm_mbcmpl:%x edtov=%x,%x bbc=%x. >",
	    fcftab->TID,
	    hba->fc_edtov, hba->sparam.cmn.e_d_tov,
	    hba->sparam.cmn.bbCreditlsb);

	/* Initialize the node name and port name only once */
	bzero(null_wwn, 8);
	if ((bcmp((caddr_t)&hba->wwnn, (caddr_t)null_wwn, 8) == 0) &&
	    (bcmp((caddr_t)&hba->wwpn, (caddr_t)null_wwn, 8) == 0)) {
		bcopy((caddr_t)&hba->sparam.nodeName,
		    (caddr_t)&hba->wwnn, sizeof (NAME_TYPE));

		bcopy((caddr_t)&hba->sparam.portName,
		    (caddr_t)&hba->wwpn, sizeof (NAME_TYPE));
	} else {
		bcopy((caddr_t)&hba->wwnn,
		    (caddr_t)&hba->sparam.nodeName, sizeof (NAME_TYPE));

		bcopy((caddr_t)&hba->wwpn,
		    (caddr_t)&hba->sparam.portName, sizeof (NAME_TYPE));
	}

	/* Update all bound ports */
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vpip = vport->vpip;

		if (!(vport->flag & EMLXS_PORT_BOUND) ||
		    (vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
			continue;
		}

		bcopy((caddr_t)&hba->sparam,
		    (caddr_t)&vport->sparam,
		    sizeof (SERV_PARM));

		bcopy((caddr_t)&vport->wwnn,
		    (caddr_t)&vport->sparam.nodeName,
		    sizeof (NAME_TYPE));

		bcopy((caddr_t)&vport->wwpn,
		    (caddr_t)&vport->sparam.portName,
		    sizeof (NAME_TYPE));
	}

	(void) emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fc_fcftab_sparm_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_sparm_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	uint32_t rval = 0;
	MATCHMAP *mp;

	if (fcftab->state != FC_FCFTAB_STATE_SPARM) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_sparm_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcftab->prev_state != FC_FCFTAB_STATE_SPARM_FAILED) ||
	    (fcftab->flag & EMLXS_FC_FCFTAB_SPARM_REQ)) {
		fcftab->flag &= ~EMLXS_FC_FCFTAB_SPARM_REQ;
		fcftab->attempts = 0;
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_read_action:%x %s:%s arg=%p flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->attempts == 0) {
		fcftab->TID = fcftab->generation;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_read_action:%x %s:%s arg=%p attempts=%d. "
	    "Reading SPARM. <",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fc_fcftab_state(port,
		    FC_FCFTAB_STATE_SPARM_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fc_fcftab_state(port,
		    FC_FCFTAB_STATE_SPARM_FAILED,
		    FCF_REASON_NO_BUFFER, 0, arg1);
		return (rval);
	}
	bzero(mp->virt, mp->size);

	mbq->nonembed = NULL;
	mbq->bp = (void *)mp;
	mbq->mbox_cmpl = emlxs_fc_fcftab_sparm_mbcmpl;
	mbq->context = (void *)((unsigned long)fcftab->TID);
	mbq->port = (void *)port;

	mb4->un.varSLIConfig.be.embedded = 0;
	mb4->mbxCommand = MBX_READ_SPARM64;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varRdSparm.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb4->un.varRdSparm.un.sp64.addrHigh = PADDR_HI(mp->phys);
	mb4->un.varRdSparm.un.sp64.addrLow = PADDR_LO(mp->phys);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fc_fcftab_state(port,
		    FC_FCFTAB_STATE_SPARM_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fc_fcftab_sparm_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_sparm_failed_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	fcftab->attempts++;

	if (fcftab->state != FC_FCFTAB_STATE_SPARM_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_sparm_failed_action:%x %s:%s arg=%p "
		    "attempt=%d. Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcftab->attempts);
		return (1);
	}

	if ((fcftab->reason == FCF_REASON_MBOX_FAILED) ||
	    (fcftab->reason == FCF_REASON_SEND_FAILED) ||
	    (fcftab->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_read_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Giving up.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM_CMPL,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_read_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Retrying.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);
	}

	return (rval);

} /* emlxs_fc_fcftab_sparm_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_sparm_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_SPARM_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_sparm_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_sparm_cmpl_action:%x attempts=%d. "
	    "Bring FCFTAB online.",
	    fcftab->TID,
	    fcftab->attempts);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_sparm_cmpl_action() */


/*ARGSUSED*/
static void
emlxs_fc_fcftab_process(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	FCF_RECORD_t fcf_record;
	FCF_RECORD_t *fcf_rec;
	uint8_t bitmap[512];
	uint16_t i;

	/* Get the FCFI */
	fcfp = fcftab->fcfi[0];

	if (!fcfp) {
		/* Allocate an fcfi */
		fcfp = emlxs_fcfi_alloc(port);
	}

	if (!fcfp) {
		fcftab->fcfi_count = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_process:%x No FCF available.",
		    fcftab->TID);
		return;
	}

	if (fcfp->flag & EMLXS_FCFI_SELECTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_process:%x fcfi=%d %s. "
		    "FCF still selected.",
		    fcftab->TID,
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state));
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_process:%x fcfi=%d %s. "
		    "New FCF selected.",
		    fcftab->TID,
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state));
	}

	/* Initalize an fcf_rec */
	fcf_rec = &fcf_record;
	bzero(fcf_rec, sizeof (FCF_RECORD_t));

	fcf_rec->max_recv_size = EMLXS_FCOE_MAX_RCV_SZ;
	fcf_rec->fka_adv_period = 0;
	fcf_rec->fip_priority = 128;

#ifdef EMLXS_BIG_ENDIAN
	fcf_rec->fcf_mac_address_hi[0] = FCOE_FCF_MAC3;
	fcf_rec->fcf_mac_address_hi[1] = FCOE_FCF_MAC2;
	fcf_rec->fcf_mac_address_hi[2] = FCOE_FCF_MAC1;
	fcf_rec->fcf_mac_address_hi[3] = FCOE_FCF_MAC0;
	fcf_rec->fcf_mac_address_low[0] = FCOE_FCF_MAC5;
	fcf_rec->fcf_mac_address_low[1] = FCOE_FCF_MAC4;
	fcf_rec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[2];
	fcf_rec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
	fcf_rec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[0];
#endif /* EMLXS_BIG_ENDIAN */
#ifdef EMLXS_LITTLE_ENDIAN
	fcf_rec->fcf_mac_address_hi[0] = FCOE_FCF_MAC0;
	fcf_rec->fcf_mac_address_hi[1] = FCOE_FCF_MAC1;
	fcf_rec->fcf_mac_address_hi[2] = FCOE_FCF_MAC2;
	fcf_rec->fcf_mac_address_hi[3] = FCOE_FCF_MAC3;
	fcf_rec->fcf_mac_address_low[0] = FCOE_FCF_MAC4;
	fcf_rec->fcf_mac_address_low[1] = FCOE_FCF_MAC5;
	fcf_rec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[0];
	fcf_rec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
	fcf_rec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[2];
#endif /* EMLXS_LITTLE_ENDIAN */

	if (hba->sli.sli4.cfgFCOE.fip_flags & TLV_FCOE_VLAN) {
		bzero((void *) bitmap, 512);
		i = hba->sli.sli4.cfgFCOE.VLanId;
		bitmap[i / 8] = (1 << (i % 8));
		BE_SWAP32_BCOPY(bitmap, fcf_rec->vlan_bitmap, 512);
	} else {
		bzero((void *) bitmap, 512);
		bitmap[0] = 1; /* represents bit 0 */
		BE_SWAP32_BCOPY(bitmap, fcf_rec->vlan_bitmap, 512);
	}

	fcf_rec->fcf_valid = 1;
	fcf_rec->fcf_available = 1;

	/* Update the FCFI */
	emlxs_fcfi_update(port, fcfp, fcf_rec, hba->link_event_tag);

	/* Select the FCFI */
	fcfp->flag &= ~EMLXS_FCFI_FAILED;
	fcfp->flag |= EMLXS_FCFI_SELECTED;
	fcftab->fcfi[0] = fcfp;
	fcftab->fcfi_count = 1;

	return;

} /* emlxs_fc_fcftab_process() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_online_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (fcftab->state != FC_FCFTAB_STATE_FCFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcfi_online_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_online_action:%x flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	emlxs_fc_fcftab_process(port);

	fcfp = fcftab->fcfi[0];
	if (!fcfp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_online_action:%x. "
		    "No FCF available. Offlining.",
		    fcftab->TID);

		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FC_FCFTAB_OFFLINE_REQ;
		rval = emlxs_fc_fcftab_req_handler(port, arg1);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_fcfi_online_action:%x fcfi_count=%d. "
	    "Onlining FCFI:%d. >",
	    fcftab->TID,
	    fcftab->fcfi_count,
	    fcfp->fcf_index);

	(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_ONLINE, fcfp);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_ONLINE_CMPL,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_fcfi_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_online_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_FCFI_ONLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcfi_online_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_online_cmpl_action:%x %s:%s arg=%p "
		    "flag=%x. Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_fcfi_online_cmpl_action:%x %s:%s arg=%p. "
	    "Going online.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_fcfi_online_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_offline_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (fcftab->state != FC_FCFTAB_STATE_FCFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcftab_offline_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->fcfi_online) {
		fcfp = fcftab->fcfi[0];

		if (!(fcfp->flag & EMLXS_FCFI_OFFLINE_REQ)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fc_fcftab_fcfi_offline_action:%d. "
			    "Offlining FCFI:%d. >",
			    fcftab->TID,
			    fcfp->fcf_index);

			rval = emlxs_fcfi_event(port,
			    FCF_EVENT_FCFI_OFFLINE, fcfp);

			return (rval);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_action:%x  fcfi_online=%d. "
		    "Waiting on FCF. <",
		    fcftab->TID,
		    fcftab->fcfi_online);

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_fcfi_offline_action:%x %s:%s arg=%p.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_fcfi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_offline_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcftab_offline_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_cmpl_action:%x %s:%s arg=%p. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		rval = emlxs_fc_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_fcftab_offline_cmpl_action:%x %s:%s arg=%p. "
	    "Returning FCF(s) online.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_fcfi_offline_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_linkup_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_LINKUP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_linkup_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_linkup_evt_action:%x %s:%s arg=%p gen=%x. Link up.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation);

	emlxs_fcf_linkup(port);

	fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
	fcftab->flag |= EMLXS_FC_FCFTAB_TOPO_REQ;
	fcftab->generation++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_linkup_evt_action:%x %s gen=%x. "
	    "Read topology.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    fcftab->generation);

	switch (fcftab->state) {
	case FC_FCFTAB_STATE_TOPO:
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fc_fcftab_linkup_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_linkdown_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	uint32_t i;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_LINKDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_linkdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
	fcftab->flag |= EMLXS_FC_FCFTAB_OFFLINE_REQ;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_linkdown_evt_action:%x %s:%s arg=%p flag=%x. Linkdown.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->flag);

	emlxs_fcf_linkdown(port);

	/* Pause all active FCFI's */
	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp = fcftab->fcfi[i];

		if ((fcfp->state == FCFI_STATE_OFFLINE) ||
		    (fcfp->state == FCFI_STATE_PAUSED)) {
			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_linkdown_evt_action:%x. "
		    "Pausing FCFI:%d. >",
		    fcftab->TID,
		    fcfp->fcf_index);

		(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_PAUSE, fcfp);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_linkdown_evt_action:%x "
	    "Going offline.",
	    fcftab->TID);

	switch (fcftab->state) {
	case FC_FCFTAB_STATE_OFFLINE:
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fc_fcftab_linkdown_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_offline_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_FCFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcftab_offline_evt_action:%x %s:%s arg=%p "
		    "flag=%x. Invalid event type. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcfp = (FCFIobj_t *)arg1;

	switch (fcftab->state) {
	case FC_FCFTAB_STATE_SHUTDOWN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_evt_action:%x fcfi:%d. "
		    "Shutting down.",
		    fcftab->TID,
		    fcfp->fcf_index);

		/* This will trigger final shutdown */
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SHUTDOWN,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FC_FCFTAB_STATE_FCFI_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_evt_action:%x fcfi:%d. Offlining.",
		    fcftab->TID,
		    fcfp->fcf_index);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_OFFLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FC_FCFTAB_STATE_FCFI_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_evt_action:%x fcfi:%d. "
		    "Retrying FCF.",
		    fcftab->TID,
		    fcfp->fcf_index);

		fcfp->flag |= EMLXS_FCFI_FAILED;

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_FCFI_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FC_FCFTAB_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_evt_action:%x fcfi:%d.",
		    fcftab->TID,
		    fcfp->fcf_index);

		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_fcfi_offline_evt_action:%x %s fcfi:%d.",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    fcfp->fcf_index);
		break;
	}

	return (rval);

} /* emlxs_fc_fcftab_fcfi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_fcfi_online_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_FCFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_fcftab_online_evt_action:%x %s:%s arg=%p "
		    "flag=%x. Invalid event type. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcfp = (FCFIobj_t *)arg1;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_fcfi_online_evt_action:%d fcfi:%d. <",
	    fcftab->TID,
	    fcfp->fcf_index);

	return (rval);

} /* emlxs_fc_fcftab_fcfi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fc_fcftab_shutdown_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fc_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Already shut down. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	if (fcftab->state == FC_FCFTAB_STATE_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fc_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Already shutting down. <",
		    fcftab->TID,
		    emlxs_fc_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fc_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
	    "Shutting down.",
	    fcftab->TID,
	    emlxs_fc_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->flag);

	emlxs_fcf_linkdown(port);

	rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SHUTDOWN,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fc_fcftab_shutdown_evt_action() */


static uint32_t
emlxs_fc_fcftab_req_handler(emlxs_port_t *port, void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (!(fcftab->flag & EMLXS_FCFTAB_REQ_MASK)) {
		return (1);
	}

	if (fcftab->flag & EMLXS_FC_FCFTAB_OFFLINE_REQ) {
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	else if (fcftab->flag & EMLXS_FC_FCFTAB_TOPO_REQ) {
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_TOPO,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	else if (fcftab->flag & EMLXS_FC_FCFTAB_CFGLINK_REQ) {
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_CFGLINK,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	else if (fcftab->flag & EMLXS_FC_FCFTAB_SPARM_REQ) {
		rval = emlxs_fc_fcftab_state(port, FC_FCFTAB_STATE_SPARM,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	return (rval);

} /* emlxs_fc_fcftab_req_handler() */



/* ************************************************************************** */
/* FCOE FCFTAB */
/* ************************************************************************** */

static char *
emlxs_fcoe_fcftab_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_fcoe_fcftab_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_fcoe_fcftab_state_table[i].code) {
			return (emlxs_fcoe_fcftab_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_fcoe_fcftab_state_xlate() */


static uint32_t
emlxs_fcoe_fcftab_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_SHUTDOWN:
		index = 1;
		break;
	case FCF_EVENT_LINKUP:
		index = 2;
		break;
	case FCF_EVENT_LINKDOWN:
		index = 3;
		break;
	case FCF_EVENT_CVL:
		index = 4;
		break;
	case FCF_EVENT_FCF_FOUND:
		index = 5;
		break;
	case FCF_EVENT_FCF_LOST:
		index = 6;
		break;
	case FCF_EVENT_FCF_CHANGED:
		index = 7;
		break;
	case FCF_EVENT_FCFTAB_FULL:
		index = 8;
		break;
	case FCF_EVENT_FCFI_ONLINE:
		index = 9;
		break;
	case FCF_EVENT_FCFI_OFFLINE:
		index = 10;
		break;
	default:
		return (1);
	}

	events = FCOE_FCFTAB_ACTION_EVENTS;
	state  = fcftab->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, uint32_t, void *))
	    emlxs_fcoe_fcftab_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "fcoe_fcftab_action:%x %s:%s arg=%p. No action. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_action() */


static uint32_t
emlxs_fcoe_fcftab_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	/* Filter events */
	switch (evt) {
	case FCF_EVENT_SHUTDOWN:
	case FCF_EVENT_LINKUP:
	case FCF_EVENT_LINKDOWN:
	case FCF_EVENT_CVL:
	case FCF_EVENT_FCF_FOUND:
	case FCF_EVENT_FCF_LOST:
	case FCF_EVENT_FCF_CHANGED:
	case FCF_EVENT_FCFTAB_FULL:
	case FCF_EVENT_FCFI_OFFLINE:
	case FCF_EVENT_FCFI_ONLINE:
		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "fcoe_fcftab_event:%x %s:%s arg=%p.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fcoe_fcftab_action(port, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_event() */


/* EMLXS_FCF_LOCK must be held to enter */
/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_state(emlxs_port_t *port, uint16_t state, uint16_t reason,
    uint32_t explain, void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (state >= FCOE_FCFTAB_ACTION_STATES) {
		return (1);
	}

	if ((fcftab->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcftab_state:%x %s:%s:0x%x arg=%p. "
		    "State not changed. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s arg=%p",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcoe_fcftab_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s:%s arg=%p",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcoe_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s:0x%x arg=%p",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcoe_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcftab_state:%x %s-->%s:%s arg=%p",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcoe_fcftab_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	fcftab->prev_state = fcftab->state;
	fcftab->prev_reason = fcftab->reason;
	fcftab->state = state;
	fcftab->reason = reason;

	rval = emlxs_fcoe_fcftab_action(port, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_state() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_offline_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_FCFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x %s:%s arg=%p "
		    "flag=%x. Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcfp = (FCFIobj_t *)arg1;

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SHUTDOWN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x fcfi:%d. "
		    "Shutting down.",
		    fcftab->TID,
		    fcfp->fcf_index);

		/* This will trigger final shutdown */
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SHUTDOWN,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FCOE_FCFTAB_STATE_FCFI_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x fcfi:%d. "
		    "Offlining.",
		    fcftab->TID,
		    fcfp->fcf_index);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_FCFI_OFFLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FCOE_FCFTAB_STATE_FCFI_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x fcfi:%d. "
		    "Attempting failover.",
		    fcftab->TID,
		    fcfp->fcf_index);

		fcfp->flag |= EMLXS_FCFI_FAILED;

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_FCFI_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FCOE_FCFTAB_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x fcfi:%d.",
		    fcftab->TID,
		    fcfp->fcf_index);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_evt_action:%x %s fcfi:%d.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcfp->fcf_index);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_online_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_FCFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_fcfi_online_evt_action:%x %s:%s arg=%p "
		    "flag=%x. Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcfp = (FCFIobj_t *)arg1;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_fcfi_online_evt_action:%x fcfi:%d. <",
	    fcftab->TID,
	    fcfp->fcf_index);

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_cvl_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	emlxs_port_t *vport;
	uint32_t vpi;
	VPIobj_t *vpip;

	if (evt != FCF_EVENT_CVL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_cvl_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	/* Pause VPI */
	vpi = (uint32_t)((unsigned long)arg1);
	vport = &VPORT(vpi);
	vpip = vport->vpip;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_cvl_evt_action:%x %s gen=%x. Pausing VPI:%d. >",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    fcftab->generation,
	    vpip->VPI);

	rval = emlxs_vpi_event(vport, FCF_EVENT_VPI_PAUSE, vpip);

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_cvl_evt_action:%x %s gen=%x. "
		    "Already soliciting. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);
		break;

	default:
		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_cvl_evt_action:%x %s gen=%x. Soliciting.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_cvl_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_linkup_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_LINKUP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_linkup_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_linkup_evt_action:%x %s:%s arg=%p gen=%x. Link up.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation);

	emlxs_fcf_linkup(port);

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_linkup_evt_action:%x %s gen=%x. "
		    "Already soliciting. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);
		break;

	default:
		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_linkup_evt_action:%x %s gen=%x. Soliciting.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_linkup_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_linkdown_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	int32_t i;
	FCFIobj_t *fcfp;

	if (evt != FCF_EVENT_LINKDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_linkdown_evt_action:%x %s:%s arg=%p "
		    "flag=%x. Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
	fcftab->flag |= EMLXS_FCOE_FCFTAB_OFFLINE_REQ;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_linkdown_evt_action:%x %s:%s arg=%p flag=%x. "
	    "Linkdown.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->flag);

	emlxs_fcf_linkdown(port);

	/* Pause all active FCFI's */
	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp = fcftab->fcfi[i];

		if ((fcfp->state == FCFI_STATE_OFFLINE) ||
		    (fcfp->state == FCFI_STATE_PAUSED)) {
			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_linkdown_evt_action:%x Pausing FCFI:%d. >",
		    fcftab->TID,
		    fcfp->fcf_index);

		(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_PAUSE, fcfp);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_linkdown_evt_action:%x "
	    "Going offline.",
	    fcftab->TID);

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_OFFLINE:
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_linkdown_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_shutdown_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Already shut down. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	if (fcftab->state == FCOE_FCFTAB_STATE_SHUTDOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
		    "Already shutting down. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_shutdown_evt_action:%x %s:%s arg=%p flag=%x. "
	    "Shutting down.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->flag);

	emlxs_fcf_linkdown(port);

	rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SHUTDOWN,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_shutdown_evt_action() */


static uint32_t
emlxs_fcoe_fcftab_req_handler(emlxs_port_t *port, void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (!(fcftab->flag & EMLXS_FCFTAB_REQ_MASK)) {
		return (1);
	}

	if (fcftab->flag & EMLXS_FCOE_FCFTAB_OFFLINE_REQ) {
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	else if (fcftab->flag & EMLXS_FCOE_FCFTAB_SOL_REQ) {
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	else if (fcftab->flag & EMLXS_FCOE_FCFTAB_READ_REQ) {
		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_READ,
		    FCF_REASON_REQUESTED, 0, FCFTAB_READ_ALL);
	}

	return (rval);

} /* emlxs_fcoe_fcftab_req_handler() */


static void
emlxs_fcoe_fcftab_read_timer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;

	/* Check FCF timer */
	if (!fcftab->read_timer ||
	    (hba->timer_tics < fcftab->read_timer)) {
		return;
	}
	fcftab->read_timer = 0;
	fcftab->flag |= EMLXS_FCOE_FCFTAB_READ_REQ;

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT_CMPL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_timer:%x %s >",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state));

		(void) emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_READ,
		    0, 0, FCFTAB_READ_ALL);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_timer:%x %s",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state));
		break;
	}

	return;

}  /* emlxs_fcoe_fcftab_read_timer() */


static void
emlxs_fcoe_fcftab_sol_timer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;

	/* Check FCF timer */
	if (!fcftab->sol_timer ||
	    (hba->timer_tics < fcftab->sol_timer)) {
		return;
	}
	fcftab->sol_timer = 0;

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_ONLINE:
		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_timer:%x %s gen=%x. Soliciting. >",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		(void) emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_EVENT, 0, 0);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_timer:%x %s",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state));
		break;
	}

	return;

}  /* emlxs_fcoe_fcftab_sol_timer() */


static void
emlxs_fcoe_fcftab_offline_timer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t i;
	FCFIobj_t *fcfp;

	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp = fcftab->fcfi[i];

		/* Check offline timer */
		if (!fcfp->offline_timer ||
		    (hba->timer_tics < fcfp->offline_timer)) {
			continue;
		}
		fcfp->offline_timer = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_offline_timer:%x. Offlining FCFI:%d. >",
		    fcftab->TID,
		    fcfp->fcf_index);

		(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_OFFLINE, fcfp);
	}

	return;

}  /* emlxs_fcoe_fcftab_offline_timer() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_sol_failed_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	fcftab->attempts++;

	if (fcftab->state != FCOE_FCFTAB_STATE_SOLICIT_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_sol_failed_action:%x %s:%s arg=%p "
		    "attempt=%d. Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcftab->attempts);
		return (1);
	}

	if ((fcftab->reason == FCF_REASON_MBOX_FAILED) ||
	    (fcftab->reason == FCF_REASON_SEND_FAILED) ||
	    (fcftab->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Giving up.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_SOLICIT_CMPL,
		    FCF_REASON_OP_FAILED, 0, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Retrying.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_OP_FAILED, 0, arg1);
	}

	return (rval);

} /* emlxs_fcoe_fcftab_sol_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_sol_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	uint16_t TID;
	mbox_rsp_hdr_t *hdr_rsp;
	MATCHMAP *mp;
	uint32_t status = MGMT_STATUS_FCF_IN_USE;
	uint32_t xstatus = 0;
	uint32_t fip_mode = 1;

	mutex_enter(&EMLXS_FCF_LOCK);
	TID = (uint16_t)((unsigned long)mbq->context);

	if (mbq->nonembed) {
		fip_mode = 0;

		mp = (MATCHMAP *)mbq->nonembed;
		mbq->nonembed = NULL;

		hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;
		status  = hdr_rsp->status;
		xstatus = hdr_rsp->extra_status;

		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
	}

	if (fcftab->state != FCOE_FCFTAB_STATE_SOLICIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_mbcmpl:%x %s.",
		    TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (TID != fcftab->generation) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_mbcmpl:%x %s. "
		    "Incorrect generation %x. Dropping.",
		    TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		if (fip_mode) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_sol_mbcmpl:%x failed. %s. >",
			    fcftab->TID,
			    emlxs_mb_xlate_status(mb4->mbxStatus));

			(void) emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_SOLICIT_FAILED,
			    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

			mutex_exit(&EMLXS_FCF_LOCK);
			return (0);

		} else if ((status == 0)||(status != MGMT_STATUS_FCF_IN_USE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_sol_mbcmpl:%x failed. %s %x,%x. >",
			    fcftab->TID,
			    emlxs_mb_xlate_status(mb4->mbxStatus),
			    status, xstatus);

			(void) emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_SOLICIT_FAILED,
			    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

			mutex_exit(&EMLXS_FCF_LOCK);
			return (0);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_sol_mbcmpl:%x %s gen=%x. Solicit complete. >",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    fcftab->generation);

	(void) emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fcoe_fcftab_sol_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_sol_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	MATCHMAP *mp = NULL;
	uint32_t rval = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_SOLICIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_sol_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcftab->prev_state != FCOE_FCFTAB_STATE_SOLICIT_FAILED) ||
	    (fcftab->flag & EMLXS_FCOE_FCFTAB_SOL_REQ)) {
		fcftab->flag &= ~EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->attempts = 0;
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_action:%x %s:%s arg=%p gen=%d flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->attempts == 0) {
		fcftab->TID = fcftab->generation;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_sol_action:%x %s:%s arg=%p gen=%x fip=%x. "
	    "Requesting solicit. <",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation,
	    ((hba->flag & FC_FIP_SUPPORTED)? 1:0));

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_SOLICIT_FAILED,
		    FCF_REASON_NO_MBOX, 0, 0);
		return (rval);
	}

	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if (hba->flag & FC_FIP_SUPPORTED) {
		IOCTL_FCOE_REDISCOVER_FCF_TABLE *fcf;

		mbq->nonembed = NULL;
		mbq->mbox_cmpl = emlxs_fcoe_fcftab_sol_mbcmpl;
		mbq->context = (void *)((unsigned long)fcftab->TID);
		mbq->port = (void *)port;

		mb4->un.varSLIConfig.be.embedded = 1;
		mb4->mbxCommand = MBX_SLI_CONFIG;
		mb4->mbxOwner = OWN_HOST;
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_REDISCOVER_FCF_TABLE) +
		    IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_REDISCOVER_FCF_TABLE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_REDISCOVER_FCF_TABLE);

		fcf = (IOCTL_FCOE_REDISCOVER_FCF_TABLE *)
		    &mb4->un.varSLIConfig.payload;
		fcf->params.request.fcf_count = 0; /* invalidate FCF table */

	} else { /* Non-FIP */

		/* Non-FIP uses a persistent FCF entry that */
		/* we must add to the table */

		IOCTL_FCOE_ADD_FCF_TABLE *fcf;
		mbox_req_hdr_t *hdr_req;
		FCF_RECORD_t *fcf_rec;
		uint8_t bitmap[512];
		uint16_t i;

		if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

			rval = emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_SOLICIT_FAILED,
			    FCF_REASON_NO_BUFFER, 0, arg1);
			return (rval);
		}
		bzero(mp->virt, mp->size);

		mbq->nonembed = (void *)mp;
		mbq->mbox_cmpl = emlxs_fcoe_fcftab_sol_mbcmpl;
		mbq->context = (void *)((unsigned long)fcftab->generation);
		mbq->port = (void *)port;

		mb4->un.varSLIConfig.be.embedded = 0;
		mb4->mbxCommand = MBX_SLI_CONFIG;
		mb4->mbxOwner = OWN_HOST;

		hdr_req = (mbox_req_hdr_t *)mp->virt;
		hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
		hdr_req->opcode = FCOE_OPCODE_ADD_FCF_TABLE;
		hdr_req->timeout = 0;
		hdr_req->req_length = sizeof (IOCTL_FCOE_ADD_FCF_TABLE);

		fcf = (IOCTL_FCOE_ADD_FCF_TABLE *)(hdr_req + 1);
		fcf->params.request.fcf_index = 0;

		fcf_rec = &fcf->params.request.fcf_entry;
		fcf_rec->max_recv_size = EMLXS_FCOE_MAX_RCV_SZ;
		fcf_rec->fka_adv_period = 0;
		fcf_rec->fip_priority = 128;

#ifdef EMLXS_BIG_ENDIAN
		fcf_rec->fcf_mac_address_hi[0] = FCOE_FCF_MAC3;
		fcf_rec->fcf_mac_address_hi[1] = FCOE_FCF_MAC2;
		fcf_rec->fcf_mac_address_hi[2] = FCOE_FCF_MAC1;
		fcf_rec->fcf_mac_address_hi[3] = FCOE_FCF_MAC0;
		fcf_rec->fcf_mac_address_low[0] = FCOE_FCF_MAC5;
		fcf_rec->fcf_mac_address_low[1] = FCOE_FCF_MAC4;
		fcf_rec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[2];
		fcf_rec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
		fcf_rec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[0];
#endif /* EMLXS_BIG_ENDIAN */
#ifdef EMLXS_LITTLE_ENDIAN
		fcf_rec->fcf_mac_address_hi[0] = FCOE_FCF_MAC0;
		fcf_rec->fcf_mac_address_hi[1] = FCOE_FCF_MAC1;
		fcf_rec->fcf_mac_address_hi[2] = FCOE_FCF_MAC2;
		fcf_rec->fcf_mac_address_hi[3] = FCOE_FCF_MAC3;
		fcf_rec->fcf_mac_address_low[0] = FCOE_FCF_MAC4;
		fcf_rec->fcf_mac_address_low[1] = FCOE_FCF_MAC5;
		fcf_rec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[0];
		fcf_rec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
		fcf_rec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[2];
#endif /* EMLXS_LITTLE_ENDIAN */

		if (hba->sli.sli4.cfgFCOE.fip_flags & TLV_FCOE_VLAN) {
			bzero((void *) bitmap, 512);
			i = hba->sli.sli4.cfgFCOE.VLanId;
			bitmap[i / 8] = (1 << (i % 8));
			BE_SWAP32_BCOPY(bitmap, fcf_rec->vlan_bitmap, 512);
		} else {
			bzero((void *) bitmap, 512);
			bitmap[0] = 1; /* represents bit 0 */
			BE_SWAP32_BCOPY(bitmap, fcf_rec->vlan_bitmap, 512);
		}

		fcf_rec->fcf_valid = 1;
		fcf_rec->fcf_available = 1;
	}

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		if (mp) {
			emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		}
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_SOLICIT_FAILED,
		    FCF_REASON_SEND_FAILED, rval, 0);

		return (rval);
	}

	return (0);

} /* emlxs_fcoe_fcftab_sol_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_sol_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	emlxs_config_t *cfg = &CFG;

	if (fcftab->state != FCOE_FCFTAB_STATE_SOLICIT_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_sol_cmpl_action:%x %s:%s arg=%p "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_sol_cmpl_action:%x %s:%s arg=%p gen=%d "
		    "flag=%x. Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->generation,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_sol_cmpl_action:%x %s:%s arg=%p gen=%d. "
	    "Starting timer (%d secs).",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->generation,
	    cfg[CFG_FCF_SOLICIT_DELAY].current);

	/* Start the read timer */
	fcftab->read_timer = hba->timer_tics +
	    cfg[CFG_FCF_SOLICIT_DELAY].current;

	return (0);

} /* emlxs_fcoe_fcftab_sol_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_read_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	mbox_rsp_hdr_t	*hdr_rsp;
	IOCTL_FCOE_READ_FCF_TABLE *fcf;
	FCF_RECORD_t *fcfrec;
	FCFIobj_t *fcfp;
	MATCHMAP *mp;
	uint32_t context;
	uint16_t index;
	uint16_t TID;
	uint32_t event_tag;

	mutex_enter(&EMLXS_FCF_LOCK);
	context = (uint32_t)((unsigned long)mbq->context);
	TID =	(uint16_t)(context >> 16);
	index =	(uint16_t)(context & 0xFFFF);

	if (fcftab->state != FCOE_FCFTAB_STATE_READ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x index=%d %s.",
		    TID, index,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (TID != fcftab->generation) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x index=%d %s. "
		    "Incorrect generation %x. Dropping.",
		    TID, index,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	mp = (MATCHMAP *)mbq->nonembed;
	hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;

	if (mb4->mbxStatus || hdr_rsp->status) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x index=%d failed. %s %x,%x. >",
		    fcftab->TID, index,
		    emlxs_mb_xlate_status(mb4->mbxStatus),
		    hdr_rsp->status, hdr_rsp->extra_status);

		(void) emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus,
		    (void*)((unsigned long)index));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_read_mbcmpl:%x index=%d %s",
	    fcftab->TID, index,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state));

	fcf = (IOCTL_FCOE_READ_FCF_TABLE *)(hdr_rsp + 1);
	fcfrec = &fcf->params.response.fcf_entry[0];

#ifdef EMLXS_BIG_ENDIAN
{
	uint32_t *iptr;
	uint32_t i;
	uint8_t  j;
	uint16_t s;
	uint16_t *sptr;

	/* Fix up data in FCF record */
	SWAP32_BUFFER(&fcfrec->fabric_name_identifier[0], 8);
	SWAP32_BUFFER(&fcfrec->switch_name_identifier[0], 8);
	SWAP32_BUFFER(&fcfrec->vlan_bitmap[0], 512);

	iptr = (uint32_t *)&fcfrec->fcf_mac_address_hi[0];
	i = *iptr;
	*iptr = SWAP32(i);

	sptr = (uint16_t *)&fcfrec->fcf_mac_address_low[0];
	s = *sptr;
	*sptr = SWAP16(s);

	j = fcfrec->fc_map[0];
	fcfrec->fc_map[0] = fcfrec->fc_map[2];
	fcfrec->fc_map[2] = j;
}
#endif /* EMLXS_BIG_ENDIAN */

	event_tag = fcf->params.response.event_tag;

	/* Try to find existing fcfrec */
	fcfp = emlxs_fcfi_find(port, fcfrec, 0);

	/* If not found, allocate a new one */
	if (!fcfp) {
		fcfp = emlxs_fcfi_alloc(port);
	}

	if (!fcfp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x index=%d failed. "
		    "Unable to allocate fcfi. >",
		    fcftab->TID, index);

		(void) emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_FAILED,
		    FCF_REASON_NO_FCFI, 0,
		    (void*)((unsigned long)index));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	/* Update the FCFI */
	emlxs_fcfi_update(port, fcfp, fcfrec, event_tag);

	/* Check if another record needs to be acquired */
	if (fcf->params.response.next_valid_fcf_index != 0xffff) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x. Read next. >",
		    fcftab->TID);

		(void) emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_READ,
		    FCF_REASON_REENTER, 0,
		    (void *)((unsigned long)fcf->params.response.
		    next_valid_fcf_index));
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_mbcmpl:%x. Read complete. >",
		    fcftab->TID);

		(void) emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_CMPL,
		    0, 0, (void*)((unsigned long)index));
	}

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fcoe_fcftab_read_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_read_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	IOCTL_FCOE_READ_FCF_TABLE *fcf;
	uint32_t rval = 0;
	MATCHMAP *mp;
	mbox_req_hdr_t	*hdr_req;
	uint16_t index = (uint16_t)((unsigned long)arg1);
	uint32_t context;

	if (fcftab->state != FCOE_FCFTAB_STATE_READ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_read_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcftab->prev_state != FCOE_FCFTAB_STATE_READ_FAILED) ||
	    (fcftab->flag & EMLXS_FCOE_FCFTAB_READ_REQ)) {
		fcftab->flag &= ~EMLXS_FCOE_FCFTAB_READ_REQ;
		fcftab->attempts = 0;
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_action:%x %s:%s arg=%p flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->attempts == 0) {
		fcftab->TID = fcftab->generation;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_read_action:%x %s:%s arg=%p attempts=%d. "
	    "Reading FCF. <",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_FAILED,
		    FCF_REASON_NO_BUFFER, 0, arg1);
		return (rval);
	}
	bzero(mp->virt, mp->size);

	mbq->nonembed = (void *)mp;
	mbq->mbox_cmpl = emlxs_fcoe_fcftab_read_mbcmpl;

	context = ((uint32_t)fcftab->TID << 16) | (uint32_t)index;
	mbq->context = (void *)((unsigned long)context);
	mbq->port = (void *)port;

	mb4->un.varSLIConfig.be.embedded = 0;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
	hdr_req->opcode = FCOE_OPCODE_READ_FCF_TABLE;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_FCOE_READ_FCF_TABLE);

	fcf = (IOCTL_FCOE_READ_FCF_TABLE *)(hdr_req + 1);
	fcf->params.request.fcf_index = index;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fcoe_fcftab_read_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_read_failed_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	fcftab->attempts++;

	if (fcftab->state != FCOE_FCFTAB_STATE_READ_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_read_failed_action:%x %s:%s arg=%p "
		    "attempt=%d. Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcftab->attempts);
		return (1);
	}

	if ((fcftab->reason == FCF_REASON_MBOX_FAILED) ||
	    (fcftab->reason == FCF_REASON_SEND_FAILED) ||
	    (fcftab->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Giving up.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_READ_CMPL,
		    FCF_REASON_OP_FAILED, fcftab->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_read_failed_action:%x %s:%s arg=%p "
		    "attempt=%d reason=%x. Retrying.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->attempts,
		    fcftab->reason);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_READ,
		    FCF_REASON_OP_FAILED, fcftab->attempts, FCFTAB_READ_ALL);
	}

	return (rval);

} /* emlxs_fcoe_fcftab_read_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_read_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	FCFIobj_t *fcfp;
	uint32_t i;

	if (fcftab->state != FCOE_FCFTAB_STATE_READ_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_read_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_read_cmpl_action:%x %s:%s arg=%p attempts=%d. "
	    "Cleaning table.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->attempts);

	/* Clean FCFI table */
	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {
		if (fcfp->state == FCFI_STATE_FREE) {
			continue;
		}

		/* Adjust the freshness flag */
		if (fcfp->generation == fcftab->generation) {
			fcfp->flag |= EMLXS_FCFI_FRESH;
		} else {
			fcfp->flag &= ~EMLXS_FCFI_FRESH;
		}

		/* Clear the failed bit */
		fcfp->flag &= ~EMLXS_FCFI_FAILED;

		/* Free all stale unselected entries now */
		if (!(fcfp->flag & EMLXS_FCFI_FRESH) &&
		    !(fcfp->flag & EMLXS_FCFI_SELECTED)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_read_cmpl_action:%x. FCF stale. "
			    "Freeing FCFI:%d. >",
			    fcftab->TID,
			    fcfp->fcf_index);

			(void) emlxs_fcfi_free(port, fcfp);
			continue;
		}
	}

	rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_FCFI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_read_cmpl_action() */


static FCFIobj_t *
emlxs_fcoe_fcftab_fcfi_select(emlxs_port_t *port, char *fabric_wwn)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	FCFIobj_t *fcfp1;
	uint32_t mask;
	uint32_t viable;
	uint32_t i;
	uint32_t j;
	uint32_t rnum;
	timespec_t time;
	FCFIobj_t **fcf_table;
	uint32_t fcf_table_count;

	mask =   (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED|EMLXS_FCFI_FRESH|
	    EMLXS_FCFI_FAILED|EMLXS_FCFI_SELECTED);
	viable = (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED|EMLXS_FCFI_FRESH);

	/* Tag & count viable entries */
	fcf_table_count = 0;
	fcfp = 0;
	fcfp1 = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp1++) {
		if (fcfp1->state == FCFI_STATE_FREE) {
			fcfp1->flag &= ~EMLXS_FCFI_TAGGED;
			continue;
		}

		if ((fcfp1->flag & mask) != viable) {
			fcfp1->flag &= ~EMLXS_FCFI_TAGGED;
			continue;
		}

		if (fabric_wwn &&
		    bcmp(fabric_wwn,
		    fcfp1->fcf_rec.fabric_name_identifier, 8)) {
			fcfp1->flag &= ~EMLXS_FCFI_TAGGED;
			continue;
		}

		fcfp1->flag |= EMLXS_FCFI_TAGGED;
		fcfp = fcfp1;
		fcf_table_count++;
	}

	if (fcf_table_count == 0) {
		return (NULL);
	}

	if (fcf_table_count == 1) {
		return (fcfp);
	}

	/* We found more than one viable entry */

	fcf_table = (FCFIobj_t **)kmem_zalloc(
	    (sizeof (uintptr_t) * fcf_table_count), KM_SLEEP);

	/* Find the highest priority tagged entry(s) */
	for (i = 0; i < fcf_table_count; i++) {
		fcfp  = 0;
		fcfp1 = fcftab->table;
		for (j = 0; j < fcftab->table_count; j++, fcfp1++) {
			if (!(fcfp1->flag & EMLXS_FCFI_TAGGED)) {
				continue;
			}

			if (!fcfp ||
			    (fcfp1->priority > fcfp->priority)) {
				fcfp = fcfp1;
			}
		}

		if (fcf_table[0] &&
		    (fcf_table[0]->priority > fcfp->priority)) {
			break;
		}

		fcfp->flag &= ~EMLXS_FCFI_TAGGED;
		fcf_table[i] = fcfp;
	}

	/* If more than one entry has the highest priority, */
	/* then randomly select one of the highest. */
	if (i > 1) {
		/* Pick a random number from 0 to (i-1) */
		/* This algorithm uses the lower 16 bits of the nanosecond */
		/* clock to determine the value */
		bzero(&time, sizeof (timespec_t));
		gethrestime(&time);
		rnum = (uint32_t)(time.tv_nsec & 0xFFFF);

		fcfp = fcf_table[(rnum%i)];
	} else {
		fcfp = fcf_table[0];
	}

	/* Free the priority table */
	kmem_free(fcf_table, (sizeof (uintptr_t) * fcf_table_count));

	return (fcfp);

} /* emlxs_fcoe_fcftab_fcfi_select() */


/*ARGSUSED*/
static void
emlxs_fcoe_fcftab_process(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	FCFIobj_t *prev_fcfp;
	uint32_t i;
	uint32_t j;
	uint32_t count;
	uint32_t mask;
	uint32_t viable;
	emlxs_config_t *cfg = &CFG;

	mask =   (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED|EMLXS_FCFI_FRESH|
	    EMLXS_FCFI_FAILED);
	viable = (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED|EMLXS_FCFI_FRESH);

	/* Deselection process */
	for (i = 0; i < FCFTAB_MAX_FCFI_COUNT; i++) {
		fcfp = fcftab->fcfi[i];

		if (!fcfp) {
			continue;
		}

		/* Check if entry is viable */
		if ((fcfp->flag & mask) == viable) {
			if (fcfp->offline_timer) {
				fcfp->offline_timer = 0;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
				    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
				    "FCF viable. Offline timer disabled.",
				    fcftab->TID,
				    i, fcfp->fcf_index,
				    emlxs_fcfi_state_xlate(fcfp->state),
				    cfg[CFG_FCF_FAILOVER_DELAY].current);
			}
			continue;
		}

		/* Previous entry is no longer viable */

		/* If FCF is still online */
		if (fcfp->state > FCFI_STATE_OFFLINE) {
			if (fcfp->offline_timer == 0) {
				/* Set the offline timer */
				fcfp->offline_timer = hba->timer_tics +
				    cfg[CFG_FCF_FAILOVER_DELAY].current;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
				    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
				    "No longer viable. "
				    "Offlining FCF (%d secs).",
				    fcftab->TID,
				    i, fcfp->fcf_index,
				    emlxs_fcfi_state_xlate(fcfp->state),
				    cfg[CFG_FCF_FAILOVER_DELAY].current);
			}
			continue;
		}

		/* Deselect it */
		fcfp->flag &= ~EMLXS_FCFI_SELECTED;

		if (!(fcfp->flag & EMLXS_FCFI_FRESH)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_process:%x %d. "
			    "No longer viable. Freeing FCFI:%d. >",
			    fcftab->TID,
			    i, fcfp->fcf_index);

			(void) emlxs_fcfi_free(port, fcfp);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
			    "No longer viable. FCF deselected.",
			    fcftab->TID,
			    i, fcfp->fcf_index,
			    emlxs_fcfi_state_xlate(fcfp->state));
		}
	}

	/* Reselection process */
	for (i = 0; i < FCFTAB_MAX_FCFI_COUNT; i++) {
		prev_fcfp = fcftab->fcfi[i];
		fcftab->fcfi[i] = NULL;

		/* If no previous selection, then make new one */
		if (!prev_fcfp) {
			/* Select an fcf on any fabric */
			fcfp = emlxs_fcoe_fcftab_fcfi_select(port, 0);

			if (fcfp) {
				fcfp->flag |= EMLXS_FCFI_SELECTED;
				fcftab->fcfi[i] = fcfp;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
				    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
				    "New FCF selected.",
				    fcftab->TID,
				    i, fcfp->fcf_index,
				    emlxs_fcfi_state_xlate(fcfp->state));
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
				    "fcoe_fcftab_process:%x %d. "
				    "No FCF available.",
				    fcftab->TID,
				    i);
			}
			continue;
		}

		/* If previous entry is still selected, keep it */
		if (prev_fcfp->flag & EMLXS_FCFI_SELECTED) {
			fcfp = prev_fcfp;
			fcftab->fcfi[i] = fcfp;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
			    "FCF still selected.",
			    fcftab->TID,
			    i, fcfp->fcf_index,
			    emlxs_fcfi_state_xlate(fcfp->state));
			continue;
		}

		/* Previous entry is no longer selected */

		/* Select a new fcf from same fabric */
		fcfp = emlxs_fcoe_fcftab_fcfi_select(port,
		    (char *)prev_fcfp->fcf_rec.fabric_name_identifier);

		if (fcfp) {
			fcfp->flag |= EMLXS_FCFI_SELECTED;
			fcftab->fcfi[i] = fcfp;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
			    "New FCF, same fabric selected.",
			    fcftab->TID,
			    i, fcfp->fcf_index,
			    emlxs_fcfi_state_xlate(fcfp->state));
			continue;
		}

		/* Select fcf from any fabric */
		fcfp = emlxs_fcoe_fcftab_fcfi_select(port, 0);

		if (fcfp) {
			fcfp->flag |= EMLXS_FCFI_SELECTED;
			fcftab->fcfi[i] = fcfp;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_process:%x %d fcfi=%d %s. "
			    "New FCF, new fabric selected.",
			    fcftab->TID,
			    i, fcfp->fcf_index,
			    emlxs_fcfi_state_xlate(fcfp->state));
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_process:%x %d. No FCF available.",
		    fcftab->TID,
		    i);
	}

	/* Pack entries */
	count = 0;
	for (i = 0; i < FCFTAB_MAX_FCFI_COUNT; i++) {
		if (fcftab->fcfi[i]) {
			count++;
			continue;
		}

		for (j = i+1; j < FCFTAB_MAX_FCFI_COUNT; j++) {
			if (fcftab->fcfi[j] == NULL) {
				continue;
			}

			fcftab->fcfi[i] = fcftab->fcfi[j];
			fcftab->fcfi[j] = NULL;
			count++;
			break;
		}

		if (j == FCFTAB_MAX_FCFI_COUNT) {
			break;
		}
	}
	fcftab->fcfi_count = count;

	return;

} /* emlxs_fcoe_fcftab_process() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_online_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t rval = 0;
	uint32_t i;
	uint32_t offline_count = 0;
	uint32_t online_count = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_FCFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_online_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_online_action:%x flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	emlxs_fcoe_fcftab_process(port);

	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp = fcftab->fcfi[i];

		if (fcfp->offline_timer == 0) {
			online_count++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_fcfi_online_action:%x fcfi_count=%d. "
			    "Onlining FCFI:%d. >",
			    fcftab->TID,
			    fcftab->fcfi_count,
			    fcfp->fcf_index);

			(void) emlxs_fcfi_event(port, FCF_EVENT_FCFI_ONLINE,
			    fcfp);
		} else {
			offline_count++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_fcfi_online_action:%x fcfi_count=%d. "
			    "Offlining fcfi:%d.",
			    fcftab->TID,
			    fcftab->fcfi_count,
			    fcfp->fcf_index);
		}
	}

	if (offline_count) {
		/* Wait for FCF's to go offline */
		rval = emlxs_fcoe_fcftab_state(port,
		    FCOE_FCFTAB_STATE_FCFI_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);

		/* Service timer now */
		emlxs_fcoe_fcftab_offline_timer(hba);

		return (rval);
	}

	if (!online_count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_online_action:%x fcfi_count=%d.",
		    fcftab->TID,
		    fcftab->fcfi_count);
	}

	rval = emlxs_fcoe_fcftab_state(port,
	    FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_online_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_fcfi_online_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_online_cmpl_action:%x %s:%s "
		    "arg=%p flag=%x. Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_fcfi_online_cmpl_action:%x %s:%s arg=%p. "
	    "Going online.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_online_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_offline_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t rval = 0;
	int32_t i;
	uint32_t fcfi_offline;

	if (fcftab->state != FCOE_FCFTAB_STATE_FCFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_fcfi_offline_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	/* Check for FCF's going offline */
	fcfi_offline = 0;
	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp = fcftab->fcfi[i];

		if (fcfp->state <= FCFI_STATE_OFFLINE) {
			continue;
		}

		if (fcfp->offline_timer ||
		    (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ)) {
			fcfi_offline++;
		}
	}

	if (fcfi_offline) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_action:%x %s:%s arg=%p "
		    "fcfi_offline=%d. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcfi_offline);

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_fcfi_offline_action:%x %s:%s arg=%p.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fcoe_fcftab_state(port,
	    FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcfi_offline_cmpl_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_fcfi_offline_cmpl_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcfi_offline_cmpl_action:%x %s:%s arg=%p. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_fcfi_offline_cmpl_action:%x %s:%s arg=%p. "
	    "Returning FCF(s) online.",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_FCFI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcoe_fcftab_fcfi_offline_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_found_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t fcf_index = (uint32_t)((unsigned long)arg1);
	FCFIobj_t *fcfp;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCF_FOUND) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_found_evt_action:%x %s:%s fcf_index=%d. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		return (1);
	}

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
	case FCOE_FCFTAB_STATE_SOLICIT_CMPL:
	case FCOE_FCFTAB_STATE_READ:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_found_evt_action:%x %s:%s "
		    "fcf_index=%d gen=%x. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index, fcftab->generation);
		break;

	/* case FCOE_FCFTAB_STATE_FCFI_OFFLINE: */
	default:

		/* Scan for matching fcf index in table */
		fcfp = emlxs_fcfi_find(port, 0, &fcf_index);

		if (fcfp && (fcfp->flag & EMLXS_FCFI_SELECTED)) {

			/* Trigger table read */
			fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
			fcftab->flag |= EMLXS_FCOE_FCFTAB_READ_REQ;
			fcftab->generation++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_found_evt_action:%x %s:%s "
			    "fcf_index=%d gen=%x. Read FCF table.",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcf_index, fcftab->generation);

			rval = emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_READ,
			    FCF_REASON_EVENT, evt, arg1);

			break;
		}

		/* Check if we need more FCF's */
		if (fcftab->fcfi_online < FCFTAB_MAX_FCFI_COUNT) {

			/* Trigger table read */
			fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
			fcftab->flag |= EMLXS_FCOE_FCFTAB_READ_REQ;
			fcftab->generation++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_found_evt_action:%x %s:%s "
			    "fcf_index=%d gen=%x fcfi_online=%d. "
			    "Read FCF table.",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcf_index, fcftab->generation,
			    fcftab->fcfi_online);

			rval = emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_READ,
			    FCF_REASON_EVENT, evt, arg1);

			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_found_evt_action:%x %s:%s fcfi=%d. "
		    "FCF not needed. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_found_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_lost_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t fcf_index = (uint32_t)((unsigned long)arg1);
	emlxs_port_t *vport;
	VPIobj_t *vpip;
	uint32_t i;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCF_LOST) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_lost_evt_action:%x %s:%s fcf_index=%d. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		return (1);
	}

	/* Scan for matching fcf index in table */
	fcfp = emlxs_fcfi_find(port, 0, &fcf_index);

	if (!fcfp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_lost_evt_action:%x %s:%s fcf_index=%d. "
		    "FCF not found. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		return (0);
	}

	if (!(fcfp->flag & EMLXS_FCFI_SELECTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_changed_evt_action:%x %s:%s fcf_index=%d. "
		    "FCF not selected. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		return (0);
	}

	/* Offline VPI's of this FCFI */
	for (i = 0; i <= hba->vpi_max; i++) {
		vport = &VPORT(i);
		vpip = vport->vpip;

		if ((vpip->state == VPI_STATE_OFFLINE) ||
		    (vpip->vfip->fcfp != fcfp)) {
			continue;
		}

		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_lost_evt_action:%x %s:%s fcf_index=%d gen=%x. "
		    "Offlining VPI:%d. >",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index, fcftab->generation,
		    vpip->VPI);

		(void) emlxs_vpi_event(port, FCF_EVENT_VPI_OFFLINE, vpip);
	}

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_lost_evt_action:%x %s gen=%x. "
		    "Already soliciting. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);
		break;

	default:
		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_lost_evt_action:%x %s gen=%x. Soliciting.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_lost_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_changed_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t fcf_index = (uint32_t)((unsigned long)arg1);
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCF_CHANGED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_changed_evt_action:%x %s:%s fcf_index=%d. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		return (1);
	}

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
	case FCOE_FCFTAB_STATE_SOLICIT_CMPL:
	case FCOE_FCFTAB_STATE_READ:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_changed_evt_action:%x %s:%s "
		    "fcf_index=%d gen=%x. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index, fcftab->generation);
		break;

	/* case FCOE_FCFTAB_STATE_FCFI_OFFLINE: */
	default:

		/* Scan for matching fcf index in table */
		fcfp = emlxs_fcfi_find(port, 0, &fcf_index);

		if (fcfp && (fcfp->flag & EMLXS_FCFI_SELECTED)) {

			/* Trigger table read */
			fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
			fcftab->flag |= EMLXS_FCOE_FCFTAB_READ_REQ;
			fcftab->generation++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_changed_evt_action:%x %s:%s "
			    "fcf_index=%d gen=%x. Read FCF table.",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcf_index, fcftab->generation);

			rval = emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_READ,
			    FCF_REASON_EVENT, evt, arg1);

			break;
		}

		/* Check if we need more FCF's */
		if (fcftab->fcfi_online < FCFTAB_MAX_FCFI_COUNT) {

			/* Trigger table read */
			fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
			fcftab->flag |= EMLXS_FCOE_FCFTAB_READ_REQ;
			fcftab->generation++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_changed_evt_action:%x %s:%s "
			    "fcf_index=%d gen=%x fcfi_online=%d. "
			    "Read FCF table.",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcf_index, fcftab->generation,
			    fcftab->fcfi_online);

			rval = emlxs_fcoe_fcftab_state(port,
			    FCOE_FCFTAB_STATE_READ,
			    FCF_REASON_EVENT, evt, arg1);

			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_changed_evt_action:%x %s:%s fcfi=%d. "
		    "FCF not needed. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt),
		    fcf_index);

		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_changed_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_fcf_delete(emlxs_port_t *port, uint32_t fcf_index)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	MATCHMAP *mp = NULL;
	uint32_t rval = 0;

	IOCTL_FCOE_DELETE_FCF_TABLE *fcf;
	mbox_req_hdr_t *hdr_req;

	if (fcf_index >= fcftab->fcfi_count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcf_delete:%x fcfi:%d failed. "
		    "Out of range.",
		    fcftab->TID,
		    fcf_index);

		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcf_delete:%x fcfi:%d failed. "
		    "Unable to allocate mailbox.",
		    fcftab->TID,
		    fcf_index);

		return (1);
	}

	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcf_delete:%x fcfi:%d failed. "
		    "Unable to allocate buffer.",
		    fcftab->TID,
		    fcf_index);

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		return (1);
	}
	bzero(mp->virt, mp->size);

	mbq->nonembed = (void *)mp;
	mbq->mbox_cmpl = NULL;
	mbq->context = (void *)((unsigned long)fcf_index);
	mbq->port = (void *)port;

	mb4->un.varSLIConfig.be.embedded = 0;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
	hdr_req->opcode = FCOE_OPCODE_DELETE_FCF_TABLE;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_FCOE_DELETE_FCF_TABLE);

	fcf = (IOCTL_FCOE_DELETE_FCF_TABLE *)(hdr_req + 1);
	fcf->params.request.fcf_count = 1;
	fcf->params.request.fcf_indexes[0] = (uint16_t)fcf_index;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_fcf_delete:%x fcfi:%d. <",
	    fcftab->TID,
	    fcf_index);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_fcf_delete:%x fcfi:%d failed. "
		    "Unable to send request.",
		    fcftab->TID,
		    fcf_index);

		if (mp) {
			emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		}
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		return (1);
	}

	return (0);


} /* emlxs_fcoe_fcftab_fcf_delete() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_full_evt_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	FCFIobj_t *fcfp;
	uint32_t rval = 0;
	uint32_t mask;
	uint32_t viable;
	uint32_t i;
	uint32_t count;

	if (evt != FCF_EVENT_FCFTAB_FULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x %s:%s arg=%p. "
		    "Invalid event type. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	if (fcftab->fcfi_online == FCFTAB_MAX_FCFI_COUNT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x %s:%s arg=%p "
		    "fcfi_online=%d. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->fcfi_online);

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_full_evt_action:%x %s:%s arg=%p fcfi_online=%d. "
	    "Cleaning table...",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->fcfi_online);

	mask =   (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED);
	viable = (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
	    EMLXS_FCFI_CONFIGURED);

	count = 0;
	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {
		if (fcfp->state == FCFI_STATE_FREE) {
			continue;
		}

		if (fcfp->flag & EMLXS_FCFI_SELECTED) {
			continue;
		}

		if ((fcfp->flag & mask) == viable) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x. "
		    "Deleting FCFI:%d %x. >",
		    fcftab->TID,
		    fcfp->fcf_index,
		    fcfp->flag);

		(void) emlxs_fcfi_free(port, fcfp);

		(void) emlxs_fcoe_fcftab_fcf_delete(port, fcfp->fcf_index);

		count++;
	}

	if (!count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x %s:%s arg=%p. "
		    "All FCF's are viable. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (0);
	}

	switch (fcftab->state) {
	case FCOE_FCFTAB_STATE_SOLICIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x %s gen=%x. "
		    "Already soliciting. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);
		break;

	default:
		fcftab->flag &= ~EMLXS_FCFTAB_REQ_MASK;
		fcftab->flag |= EMLXS_FCOE_FCFTAB_SOL_REQ;
		fcftab->generation++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_full_evt_action:%x %s gen=%x. Soliciting.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    fcftab->generation);

		rval = emlxs_fcoe_fcftab_state(port, FCOE_FCFTAB_STATE_SOLICIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_fcoe_fcftab_full_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_online_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	emlxs_config_t *cfg = &CFG;
	FCFIobj_t *fcfp;
	uint32_t rval = 0;
	uint32_t mask;
	uint32_t viable;
	uint32_t i;
	uint32_t count = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_online_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_online_action:%x flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	if (fcftab->fcfi_online == 0) {
		mask =   (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
		    EMLXS_FCFI_CONFIGURED);
		viable = (EMLXS_FCFI_VALID|EMLXS_FCFI_AVAILABLE|
		    EMLXS_FCFI_CONFIGURED);

		/* Count viable FCF's in table */
		count = 0;
		fcfp = fcftab->table;
		for (i = 0; i < fcftab->table_count; i++, fcfp++) {
			if (fcfp->state == FCFI_STATE_FREE) {
				continue;
			}

			if ((fcfp->flag & mask) == viable) {
				count++;
			}
		}

		if (count) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_online_action:%x %s:%s "
			    "fcfi_online=0,%d,%d. Starting resolicit timer. <",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcftab->fcfi_count, count);

			/* Start the solicit timer */
			fcftab->sol_timer = hba->timer_tics +
			    cfg[CFG_FCF_RESOLICIT_DELAY].current;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcoe_fcftab_online_action:%x %s:%s "
			    "fcfi_online=0,%d,0. Wait for FCF event. <",
			    fcftab->TID,
			    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
			    emlxs_fcf_event_xlate(evt),
			    fcftab->fcfi_count);
		}

		emlxs_fcf_linkdown(port);

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_online_action:%x flag=%x fcfi_online=%d. "
	    "Online. <",
	    fcftab->TID,
	    fcftab->flag,
	    fcftab->fcfi_online);

	emlxs_fcf_linkup(port);

	return (rval);

} /* emlxs_fcoe_fcftab_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcoe_fcftab_offline_action(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcftab->state != FCOE_FCFTAB_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcoe_fcftab_offline_action:%x %s:%s arg=%p. "
		    "Invalid state. <",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}


	fcftab->flag &= ~EMLXS_FCOE_FCFTAB_OFFLINE_REQ;

	if (fcftab->flag & EMLXS_FCFTAB_REQ_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcoe_fcftab_offline_action:%x %s:%s arg=%p flag=%x. "
		    "Handling request.",
		    fcftab->TID,
		    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcftab->flag);

		rval = emlxs_fcoe_fcftab_req_handler(port, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcoe_fcftab_offline_action:%x %s:%s arg=%p fcfi_online=%d. "
	    "Offline. <",
	    fcftab->TID,
	    emlxs_fcoe_fcftab_state_xlate(fcftab->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcftab->fcfi_online);

	return (rval);

} /* emlxs_fcoe_fcftab_offline_action() */


/* ************************************************************************** */
/* FCFI */
/* ************************************************************************** */

static char *
emlxs_fcfi_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_fcfi_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_fcfi_state_table[i].code) {
			return (emlxs_fcfi_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_fcfi_state_xlate() */


static uint32_t
emlxs_fcfi_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, FCFIobj_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_FCFI_ONLINE:
		index = 1;
		break;
	case FCF_EVENT_FCFI_OFFLINE:
		index = 2;
		break;
	case FCF_EVENT_FCFI_PAUSE:
		index = 3;
		break;
	case FCF_EVENT_VFI_ONLINE:
		index = 4;
		break;
	case FCF_EVENT_VFI_OFFLINE:
		index = 5;
		break;
	default:
		return (1);
	}

	events = FCFI_ACTION_EVENTS;
	state  = fcfp->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, FCFIobj_t *, uint32_t, void *))
	    emlxs_fcfi_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "fcfi_action:%d %s:%s arg=%p. No action. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, fcfp, evt, arg1);

	return (rval);

} /* emlxs_fcfi_action() */


static uint32_t
emlxs_fcfi_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	FCFIobj_t *fcfp = NULL;
	VFIobj_t *vfip = NULL;
	uint32_t rval = 0;

	/* Filter events and acquire fcfi context */
	switch (evt) {
	case FCF_EVENT_VFI_ONLINE:
	case FCF_EVENT_VFI_OFFLINE:
		vfip = (VFIobj_t *)arg1;

		if (!vfip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "fcfi_event: %s arg=%p. Null VFI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}

		fcfp = vfip->fcfp;
		if (!fcfp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "fcfi_event: %s arg=%p. FCF not found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}
		break;

	case FCF_EVENT_FCFI_ONLINE:
	case FCF_EVENT_FCFI_OFFLINE:
	case FCF_EVENT_FCFI_PAUSE:
		fcfp = (FCFIobj_t *)arg1;
		if (!fcfp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "fcfi_event: %s arg=%p. Null FCFI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}
		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "fcfi_event:%d %s:%s arg=%p",
	    fcfp->fcf_index,
	    emlxs_fcfi_state_xlate(fcfp->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_fcfi_action(port, fcfp, evt, arg1);

	return (rval);

} /* emlxs_fcfi_event() */


/* EMLXS_FCF_LOCK must be held to enter */
/*ARGSUSED*/
static uint32_t
emlxs_fcfi_state(emlxs_port_t *port, FCFIobj_t *fcfp, uint16_t state,
    uint16_t reason, uint32_t explain, void *arg1)
{
	uint32_t rval = 0;

	if (state >= FCFI_ACTION_STATES) {
		return (1);
	}

	if ((fcfp->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_state:%d %s:%s:0x%x arg=%p. "
		    "State not changed. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcfi_state:%d %s-->%s arg=%p",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcfi_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcfi_state:%d %s-->%s:%s:%s arg=%p",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcfi_state:%d %s-->%s:%s:0x%x arg=%p",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "fcfi_state:%d %s-->%s:%s arg=%p",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	fcfp->prev_state = fcfp->state;
	fcfp->prev_reason = fcfp->reason;
	fcfp->state = state;
	fcfp->reason = reason;

	rval = emlxs_fcfi_action(port, fcfp, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_fcfi_state() */


static FCFIobj_t *
emlxs_fcfi_alloc(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	FCFTable_t *fcftab = &hba->sli.sli4.fcftab;
	uint16_t	i;
	FCFIobj_t	*fcfp;

	fcfp = fcftab->table;
	for (i = 0; i < fcftab->table_count; i++, fcfp++) {
		if (fcfp->state == FCFI_STATE_FREE) {

			bzero(fcfp, sizeof (FCFIobj_t));
			fcfp->index = i;
			fcfp->FCFI  = 0xFFFF;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_alloc:%d. Allocating FCFI. >",
			    fcfp->index);

			(void) emlxs_fcfi_state(port, fcfp, FCFI_STATE_OFFLINE,
			    0, 0, 0);
			return (fcfp);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_alloc: Out of FCFI objects.",
	    fcfp->index);

	return (NULL);

} /* emlxs_fcfi_alloc() */


static uint32_t
emlxs_fcfi_free(emlxs_port_t *port, FCFIobj_t *fcfp)
{
	uint32_t rval = 0;

	rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_FREE, 0, 0, 0);

	return (rval);

} /* emlxs_fcfi_free() */


static FCFIobj_t *
emlxs_fcfi_find(emlxs_port_t *port, FCF_RECORD_t *fcfrec, uint32_t *fcf_index)
{
	emlxs_hba_t	*hba = HBA;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	uint32_t	i;
	uint32_t	index;
	FCFIobj_t	*fcfp;

	if (fcfrec) {
		/* Check for a matching FCF index, fabric name, */
		/* and mac address */
		fcfp = fcftab->table;
		for (i = 0; i < fcftab->table_count; i++, fcfp++) {
			if (fcfp->state == FCFI_STATE_FREE) {
				continue;
			}

			if ((fcfp->fcf_index == fcfrec->fcf_index) &&
			    (bcmp((char *)fcfrec->fabric_name_identifier,
			    fcfp->fcf_rec.fabric_name_identifier, 8) == 0) &&
			    (bcmp((char *)fcfrec->fcf_mac_address_hi,
			    fcfp->fcf_rec.fcf_mac_address_hi, 4) == 0) &&
			    (bcmp((char *)fcfrec->fcf_mac_address_low,
			    fcfp->fcf_rec.fcf_mac_address_low, 2) == 0)) {
				return (fcfp);
			}
		}

	} else if (fcf_index) {
		/* Check for a matching FCF index only */
		index = *fcf_index;
		fcfp = fcftab->table;
		for (i = 0; i < fcftab->table_count; i++, fcfp++) {
			if (fcfp->state == FCFI_STATE_FREE) {
				continue;
			}

			if (fcfp->fcf_index == index) {
				return (fcfp);
			}
		}
	}

	return (NULL);

} /* emlxs_fcfi_find() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_free_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{

	if (fcfp->state != FCFI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_free_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcfp->vfi_online) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_free_action:%d flag=%x vfi_online=%d",
		    fcfp->fcf_index,
		    fcfp->flag,
		    fcfp->vfi_online);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_free_action:%d flag=%x. FCF freed. <",
	    fcfp->fcf_index,
	    fcfp->flag);

	fcfp->flag = 0;

	return (0);

} /* emlxs_fcfi_free_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_offline_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	fcfp->flag &= ~(EMLXS_FCFI_OFFLINE_REQ | EMLXS_FCFI_PAUSE_REQ);

	if (fcfp->prev_state == FCFI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_action:%d fcfi_online=%d. <",
		    fcfp->fcf_index,
		    fcftab->fcfi_online);

		return (0);
	}

	if (fcfp->vfi_online) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_offline_action:%d vfi_online=%d.",
		    fcfp->fcf_index,
		    fcfp->vfi_online);
	}

	if (fcfp->flag & EMLXS_FCFI_FCFTAB) {
		fcfp->flag &= ~EMLXS_FCFI_FCFTAB;

		if (fcftab->fcfi_online) {
			fcftab->fcfi_online--;
		}
	}

	/* Check if online was requested */
	if (fcfp->flag & EMLXS_FCFI_ONLINE_REQ) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_action:%d fcfi_online=%d. "
		    "Online requested.",
		    fcfp->fcf_index,
		    fcftab->fcfi_online);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG,
		    FCF_REASON_REQUESTED, 0, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_offline_action:%d fcfi_online=%d. "
	    "FCFI offline. Notifying fcftab. >",
	    fcfp->fcf_index,
	    fcftab->fcfi_online);

	/* Notify FCFTAB */
	rval = emlxs_fcftab_event(port, FCF_EVENT_FCFI_OFFLINE, fcfp);

	return (rval);

} /* emlxs_fcfi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_online_evt_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_vfi_online_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcfp->flag);
		return (1);
	}

	switch (fcfp->state) {
	case FCFI_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_online_evt_action:%d flag=%x vfi_online=%d. "
		    "Reentering online.",
		    fcfp->fcf_index,
		    fcfp->flag,
		    fcfp->vfi_online);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case FCFI_STATE_VFI_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_online_evt_action:%d flag=%x vfi_online=%d. "
		    "Online cmpl.",
		    fcfp->fcf_index,
		    fcfp->flag,
		    fcfp->vfi_online);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_ONLINE_CMPL,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_online_evt_action:%d flag=%x vfi_online=%d. <",
		    fcfp->fcf_index,
		    fcfp->flag,
		    fcfp->vfi_online);
		return (0);
	}

	return (rval);

} /* emlxs_fcfi_vfi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_offline_handler(emlxs_port_t *port, FCFIobj_t *fcfp, void *arg1)
{
	uint32_t rval = 0;

	if (!(fcfp->flag & EMLXS_FCFI_OFFLINE_REQ)) {
		return (0);
	}

	if (fcfp->vfi_online) {
		if (fcfp->flag & EMLXS_FCFI_PAUSE_REQ) {
			rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_PAUSED,
			    FCF_REASON_REQUESTED, 0, arg1);
		} else {
			rval = emlxs_fcfi_state(port, fcfp,
			    FCFI_STATE_VFI_OFFLINE, FCF_REASON_REQUESTED,
			    0, arg1);
		}

	} else if (fcfp->flag & EMLXS_FCFI_REG) {
		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else {
		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	return (rval);

} /* emlxs_fcfi_offline_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_offline_evt_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;
	VFIobj_t *vfip;

	if (evt != FCF_EVENT_VFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_vfi_offline_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcfp->flag);
		return (1);
	}

	vfip = (VFIobj_t *)arg1;
	vfip->fcfp = NULL;

	switch (fcfp->state) {
	case FCFI_STATE_VFI_ONLINE:
	case FCFI_STATE_ONLINE:
		if (fcfp->vfi_online == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_vfi_offline_evt_action:%d flag=%x "
			    "vfi_online=%d. Offlining.",
			    fcfp->fcf_index,
			    fcfp->flag, fcfp->vfi_online);

			fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
			fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;

			rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_vfi_offline_evt_action:%d flag=%x "
			    "vfi_online=%d. <",
			    fcfp->fcf_index,
			    fcfp->flag, fcfp->vfi_online);
		}
		break;

	case FCFI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_evt_action:%d flag=%x vfi_online=%d. <",
		    fcfp->fcf_index,
		    fcfp->flag, fcfp->vfi_online);
		break;

	case FCFI_STATE_VFI_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_evt_action:%d flag=%x. Offline cmpl.",
		    fcfp->fcf_index,
		    fcfp->flag);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_OFFLINE_CMPL,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case FCFI_STATE_VFI_OFFLINE_CMPL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_evt_action:%d flag=%x. Offline cmpl.",
		    fcfp->fcf_index,
		    fcfp->flag);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_OFFLINE_CMPL,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		if (fcfp->vfi_online == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_vfi_offline_evt_action:%d flag=%x "
			    "vfi_online=%d. Offline requested. <",
			    fcfp->fcf_index,
			    fcfp->flag, fcfp->vfi_online);

			fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
			fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_vfi_offline_evt_action:%d flag = %x "
			    "vfi_online=%d. <",
			    fcfp->fcf_index,
			    fcfp->flag, fcfp->vfi_online);
		}
		return (0);
	}

	return (rval);

} /* emlxs_fcfi_vfi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_online_evt_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_online_evt_action:%d %s:%s arg=%p. "
		    "Invalid event type. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_ONLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_evt_action:%d. "
		    "Online already requested. <",
		    fcfp->fcf_index);
		return (1);
	}

	fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
	fcfp->flag |= EMLXS_FCFI_ONLINE_REQ;

	switch (fcfp->state) {
	case FCFI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_evt_action:%d flag=%x. Initiating online.",
		    fcfp->fcf_index,
		    fcfp->flag);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case FCFI_STATE_VFI_OFFLINE:
	case FCFI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_evt_action:%d flag=%x. Initiating online.",
		    fcfp->fcf_index,
		    fcfp->flag);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case FCFI_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_evt_action:%d flag=%x. Reentering online.",
		    fcfp->fcf_index,
		    fcfp->flag);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_evt_action:%d flag=%x. <",
		    fcfp->fcf_index,
		    fcfp->flag);
		break;
	}

	return (rval);

} /* emlxs_fcfi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_online_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t i;
	uint32_t rval = 0;
	VFIobj_t *vfip;

	if (fcfp->state != FCFI_STATE_VFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_vfi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_online_action:%d. Offline requested.",
		    fcfp->fcf_index);

		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		return (rval);
	}

	if (fcfp->vfi_online > 0) {
		/* Waking up out after being paused */

		/* Find first VFI of this FCFI */
		vfip = hba->sli.sli4.VFI_table;
		for (i = 0; i < hba->sli.sli4.VFICount; i++, vfip++) {
			if (vfip->fcfp == fcfp) {
				break;
			}
		}

	} else {

		/* Find first available VFI */
		vfip = hba->sli.sli4.VFI_table;
		for (i = 0; i < hba->sli.sli4.VFICount; i++, vfip++) {
			if (vfip->fcfp == NULL) {
				vfip->fcfp = fcfp;
				break;
			}
		}
	}

	if (i == hba->sli.sli4.VFICount) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_online_action:%d vfi_online=%d. "
		    "No VFI found. Offlining.",
		    fcfp->fcf_index,
		    fcfp->vfi_online);

		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;

		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_vfi_online_action:%d vfi_online=%d. Onlining VFI:%d. >",
	    fcfp->fcf_index,
	    fcfp->vfi_online,
	    vfip->VFI);

	rval = emlxs_vfi_event(port, FCF_EVENT_VFI_ONLINE, vfip);

	/* Wait for FCF_EVENT_VFI_ONLINE in return */

	return (rval);

} /* emlxs_fcfi_vfi_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_online_cmpl_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_VFI_ONLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_vfi_online_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_vfi_online_cmpl_action:%d. Going online.",
	    fcfp->fcf_index);

	rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcfi_vfi_online_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_offline_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	VFIobj_t *vfip;
	uint32_t rval = 0;
	int32_t i;

	if (fcfp->state != FCFI_STATE_VFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_action:%d vfi_online=%d. Pausing.",
		    fcfp->fcf_index,
		    fcfp->vfi_online);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_PAUSED,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (fcfp->vfi_online == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_action:%d. "
		    "VFI already offline. Skipping VFI offline.",
		    fcfp->fcf_index);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	/* Offline VFI's of this FCFI */
	for (i = (hba->sli.sli4.VFICount-1); i >= 0; i--) {
		vfip = &hba->sli.sli4.VFI_table[i];

		if ((vfip->fcfp != fcfp) ||
		    (vfip->state == VFI_STATE_OFFLINE) ||
		    (vfip->flag & EMLXS_VFI_OFFLINE_REQ)) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_action:%d. Offlining VFI:%d >",
		    fcfp->fcf_index,
		    vfip->VFI);

		(void) emlxs_vfi_event(port, FCF_EVENT_VFI_OFFLINE, vfip);
	}

	/* Wait for FCF_EVENT_VFI_OFFLINE in return */

	return (0);

} /* emlxs_fcfi_vfi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_paused_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	VFIobj_t *vfip;
	int32_t i;

	if (fcfp->state != FCFI_STATE_PAUSED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_paused_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	fcfp->flag &= ~(EMLXS_FCFI_OFFLINE_REQ | EMLXS_FCFI_PAUSE_REQ);

	/* Pause all VFI's of this FCFI */
	for (i = (hba->sli.sli4.VFICount-1); i >= 0; i--) {
		vfip = &hba->sli.sli4.VFI_table[i];

		if ((vfip->state == VFI_STATE_OFFLINE) ||
		    (vfip->state == VFI_STATE_PAUSED) ||
		    (vfip->fcfp != fcfp)) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_paused_action:%d vfi_online=%d. Pausing VFI:%d. >",
		    fcfp->fcf_index,
		    fcfp->vfi_online,
		    vfip->VFI);

		(void) emlxs_vfi_event(port, FCF_EVENT_VFI_PAUSE, vfip);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_paused_action:%d vfi_online=%d. FCFI paused. <",
	    fcfp->fcf_index,
	    fcfp->vfi_online);

	return (0);

} /* emlxs_fcfi_paused_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_vfi_offline_cmpl_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_VFI_OFFLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_vfi_offline_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcfp->vfi_online == 0) &&
	    (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_cmpl_action:%d vfi_online=%d. "
		    "Unregistering.",
		    fcfp->fcf_index,
		    fcfp->vfi_online);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_vfi_offline_cmpl_action:%d vfi_online=%d. <",
		    fcfp->fcf_index,
		    fcfp->vfi_online);
	}

	return (rval);

} /* emlxs_fcfi_vfi_offline_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_offline_evt_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_offline_evt_action:%d %s:%s arg=%p. "
		    "Invalid event type. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) &&
	    !(fcfp->flag & EMLXS_FCFI_PAUSE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_evt_action:%d. Offline already requested. <",
		    fcfp->fcf_index);
		return (1);
	}

	switch (fcfp->state) {
	case FCFI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_evt_action:%d flag=%x. Already offline. <",
		    fcfp->fcf_index,
		    fcfp->flag);
		break;

	/* Wait states */
	case FCFI_STATE_VFI_ONLINE:
	case FCFI_STATE_VFI_OFFLINE:
	case FCFI_STATE_REG:
	case FCFI_STATE_ONLINE:
	case FCFI_STATE_PAUSED:
		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_evt_action:%d flag=%x.  Handling offline.",
		    fcfp->fcf_index,
		    fcfp->flag);

		/* Handle offline now */
		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		break;

	/* Transitional states */
	default:
		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_offline_evt_action:%d. "
		    "Invalid state. <",
		    fcfp->fcf_index);
		break;
	}

	return (rval);

} /* emlxs_fcfi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_pause_evt_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_FCFI_PAUSE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_pause_evt_action:%d %s:%s arg=%p. "
		    "Invalid event type. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d. Pause already requested. <",
		    fcfp->fcf_index);
		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d. Offline already requested. <",
		    fcfp->fcf_index);
		return (1);
	}

	switch (fcfp->state) {
	case FCFI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d flag=%x. Already offline. <",
		    fcfp->fcf_index,
		    fcfp->flag);
		break;

	case FCFI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d flag=%x. Already paused. <",
		    fcfp->fcf_index,
		    fcfp->flag);
		break;

	/* Wait states */
	case FCFI_STATE_VFI_ONLINE:
	case FCFI_STATE_VFI_OFFLINE:
	case FCFI_STATE_REG:
	case FCFI_STATE_ONLINE:
		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= (EMLXS_FCFI_OFFLINE_REQ | EMLXS_FCFI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d flag=%x. Handle pause request.",
		    fcfp->fcf_index,
		    fcfp->flag);

		/* Handle offline now */
		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		break;

	/* Transitional states */
	default:
		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= (EMLXS_FCFI_OFFLINE_REQ | EMLXS_FCFI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_pause_evt_action:%d. "
		    "Invalid state. <",
		    fcfp->fcf_index);
		break;
	}

	return (rval);

} /* emlxs_fcfi_pause_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_unreg_failed_action(emlxs_port_t *port, FCFIobj_t *fcfp,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	fcfp->attempts++;

	if (fcfp->state != FCFI_STATE_UNREG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_unreg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt),
		    arg1, fcfp->attempts);
		return (1);
	}

	if ((fcfp->reason == FCF_REASON_SEND_FAILED) ||
	    (fcfp->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_unreg_failed_action:%d attempt=%d reason=%x. "
		    "Unreg cmpl.",
		    fcfp->fcf_index,
		    fcfp->attempts,
		    fcfp->reason);

		fcfp->flag &= ~EMLXS_FCFI_REG;

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG_CMPL,
		    FCF_REASON_OP_FAILED, fcfp->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_unreg_failed_action:%d attempt=%d. Unregistering.",
		    fcfp->fcf_index,
		    arg1, fcfp->attempts);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG,
		    FCF_REASON_OP_FAILED, fcfp->attempts, arg1);
	}

	return (rval);

} /* emlxs_fcfi_unreg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_reg_failed_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	fcfp->attempts++;

	if (fcfp->state != FCFI_STATE_REG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_reg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    fcfp->attempts);
		return (1);
	}

	if ((fcfp->reason == FCF_REASON_SEND_FAILED) ||
	    (fcfp->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_failed_action:%d attempt=%d reason=%x. Reg cmpl.",
		    fcfp->fcf_index,
		    fcfp->attempts,
		    fcfp->reason);

		fcfp->flag &= ~EMLXS_FCFI_REQ_MASK;
		fcfp->flag |= EMLXS_FCFI_OFFLINE_REQ;

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG_CMPL,
		    FCF_REASON_OP_FAILED, fcfp->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_failed_action:%d attempt=%d. Registering.",
		    fcfp->fcf_index,
		    fcfp->attempts);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG,
		    FCF_REASON_OP_FAILED, fcfp->attempts, arg1);
	}

	return (rval);

} /* emlxs_fcfi_reg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_reg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	FCFIobj_t *fcfp;

	fcfp = (FCFIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (fcfp->state != FCFI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_mbcmpl:%d state=%s.",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_mbcmpl:%d failed. %s. >",
		    fcfp->fcf_index,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	fcfp->FCFI = mb4->un.varRegFCFI.FCFI;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_reg_mbcmpl:%d FCFI=%d. Reg complete. >",
	    fcfp->fcf_index,
	    fcfp->FCFI);

	fcfp->flag |= EMLXS_FCFI_REG;

	(void) emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG_CMPL,
	    0, 0, 0);
	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fcfi_reg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_reg_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_reg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(fcfp->flag & EMLXS_FCFI_FCFTAB)) {
		fcfp->flag |= EMLXS_FCFI_FCFTAB;
		fcftab->fcfi_online++;
	}

	if (fcfp->prev_state != FCFI_STATE_REG_FAILED) {
		fcfp->attempts = 0;
	}

	if (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_action:%d attempts=%d. Offline requested.",
		    fcfp->fcf_index,
		    fcfp->attempts);

		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		return (rval);
	}

	if (fcfp->flag & EMLXS_FCFI_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_action:%d. Already registered. "
		    "Skipping REG_FCFI update.",
		    fcfp->fcf_index);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_reg_action:%d attempts=%d. Sending REG_FCFI. <",
	    fcfp->fcf_index,
	    fcfp->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->mbox_cmpl = emlxs_fcfi_reg_mbcmpl;
	mbq->context = (void *)fcfp;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_REG_FCFI;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varRegFCFI.FCFI = 0; /* FCFI will be returned by firmware */
	mb4->un.varRegFCFI.InfoIndex = fcfp->fcf_index;

	mb4->un.varRegFCFI.RQId0 = hba->sli.sli4.rq[EMLXS_FCFI_RQ0_INDEX].qid;
	mb4->un.varRegFCFI.Id0_rctl_mask = EMLXS_FCFI_RQ0_RMASK;
	mb4->un.varRegFCFI.Id0_rctl = EMLXS_FCFI_RQ0_RCTL;
	mb4->un.varRegFCFI.Id0_type_mask = EMLXS_FCFI_RQ0_TMASK;
	mb4->un.varRegFCFI.Id0_type = EMLXS_FCFI_RQ0_TYPE;

	mb4->un.varRegFCFI.RQId1 = 0xffff;
	mb4->un.varRegFCFI.RQId2 = 0xffff;
	mb4->un.varRegFCFI.RQId3 = 0xffff;

	if (fcfp->flag & EMLXS_FCFI_VLAN_ID) {
		mb4->un.varRegFCFI.vv = 1;
		mb4->un.varRegFCFI.vlanTag = fcfp->vlan_id;
	}

	/* Ignore the fcf record and force FPMA */
	mb4->un.varRegFCFI.mam = EMLXS_REG_FCFI_MAM_FPMA;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_REG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fcfi_reg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_reg_cmpl_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_REG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_reg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_reg_cmpl_action:%d. Offline requested.",
		    fcfp->fcf_index);

		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_reg_cmpl_action:%d attempts=%d. Reg cmpl.",
	    fcfp->fcf_index,
	    fcfp->attempts);

	rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_VFI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcfi_reg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_unreg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	FCFIobj_t *fcfp;

	fcfp = (FCFIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (fcfp->state != FCFI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_unreg_mbcmpl:%d state=%s.",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_unreg_mbcmpl:%d failed. %s. >",
		    fcfp->fcf_index,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_unreg_mbcmpl:%d. Unreg complete. >",
	    fcfp->fcf_index);

	fcfp->flag &= ~EMLXS_FCFI_REG;
	(void) emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_fcfi_unreg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_unreg_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_unreg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(fcfp->flag & EMLXS_FCFI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_unreg_action:%d. Not registered. "
		    "Skipping UNREG_FCFI.",
		    fcfp->fcf_index);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (fcfp->prev_state != FCFI_STATE_UNREG_FAILED) {
		fcfp->attempts = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_unreg_action:%d attempts=%d. Sending UNREG_FCFI. <",
	    fcfp->fcf_index,
	    fcfp->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->mbox_cmpl = emlxs_fcfi_unreg_mbcmpl;
	mbq->context = (void *)fcfp;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_UNREG_FCFI;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varUnRegFCFI.FCFI = fcfp->FCFI;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_UNREG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_fcfi_unreg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_unreg_cmpl_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (fcfp->state != FCFI_STATE_UNREG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_unreg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_unreg_cmpl_action:%d attempts=%d. Going offline.",
	    fcfp->fcf_index,
	    emlxs_fcfi_state_xlate(fcfp->state),
	    emlxs_fcf_event_xlate(evt), arg1,
	    fcfp->attempts);

	rval = emlxs_fcfi_state(port, fcfp, FCFI_STATE_OFFLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_fcfi_unreg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_fcfi_online_action(emlxs_port_t *port, FCFIobj_t *fcfp, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;
	VFIobj_t *vfip;
	uint32_t i;

	if (fcfp->state != FCFI_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "fcfi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    fcfp->fcf_index,
		    emlxs_fcfi_state_xlate(fcfp->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	fcfp->flag &= ~EMLXS_FCFI_ONLINE_REQ;

	if (fcfp->flag & EMLXS_FCFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_action:%d attempts=%d. Offline requested.",
		    fcfp->fcf_index,
		    fcfp->attempts);

		rval = emlxs_fcfi_offline_handler(port, fcfp, arg1);
		return (rval);
	}

	/* Online remaining VFI's for this FCFI */
	vfip = hba->sli.sli4.VFI_table;
	for (i = 0; i < hba->sli.sli4.VFICount; i++, vfip++) {
		if (vfip->fcfp != fcfp) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "fcfi_online_action:%d vfi_online=%d. Onlining VFI:%d. >",
		    fcfp->fcf_index,
		    fcfp->vfi_online,
		    vfip->VFI);

		(void) emlxs_vfi_event(port, FCF_EVENT_VFI_ONLINE, vfip);
	}

	if (fcfp->prev_state != FCFI_STATE_ONLINE) {
		/* Perform VSAN discovery check when first VFI goes online */
		if (fcfp->vfi_online < FCFI_MAX_VFI_COUNT) {

			/* Perform VSAN Discovery (TBD) */
			/* For now we only need 1 VFI */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "fcfi_online_action:%d vfi_online=%d. "
			    "VSAN discovery required.",
			    fcfp->fcf_index,
			    fcfp->vfi_online);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi_online_action:%d vfi_online=%d. "
	    "FCFI online. Notifying fcftab. >",
	    fcfp->fcf_index,
	    fcfp->vfi_online);

	/* Notify FCFTAB */
	rval = emlxs_fcftab_event(port, FCF_EVENT_FCFI_ONLINE, fcfp);

	return (rval);

} /* emlxs_fcfi_online_action() */


/*ARGSUSED*/
static int
emlxs_fcf_configured(emlxs_port_t *port,  FCFIobj_t *fcfp)
{
	emlxs_hba_t *hba = HBA;
	int i;
	uint32_t entry_count;
	uint32_t valid_entry;
	uint32_t match_found;
	uint16_t VLanId;
	FCF_RECORD_t *fcfrec = &fcfp->fcf_rec;
	uint32_t j;
	uint32_t k;

	/* Init the primary flag, we may set it later */
	fcfp->flag &= ~(EMLXS_FCFI_PRIMARY|EMLXS_FCFI_BOOT);

	if (!(hba->flag & FC_FIP_SUPPORTED)) {
		if (!hba->sli.sli4.cfgFCOE.length) {
			/* Nothing specified, so everything matches */
			/* For nonFIP only use index 0 */
			if (fcfrec->fcf_index == 0) {
				return (1);  /* success */
			}
			return (0);
		}

		/* Just check FCMap for now */
		if (bcmp((char *)fcfrec->fc_map,
		    hba->sli.sli4.cfgFCOE.FCMap, 3) == 0) {
			return (1);  /* success */
		}
		return (0);
	}

	/* For FIP mode, the FCF record must match Config Region 23 */

	entry_count = (hba->sli.sli4.cfgFCF.length * sizeof (uint32_t)) /
	    sizeof (tlv_fcfconnectentry_t);
	valid_entry = 0;
	match_found = 0;

	for (i = 0; i < entry_count; i++) {

		if (!hba->sli.sli4.cfgFCF.entry[i].Valid) {
			continue;
		}

		if (hba->sli.sli4.cfgFCF.entry[i].FabricNameValid) {
			valid_entry = 1;

			if (bcmp((char *)fcfrec->fabric_name_identifier,
			    hba->sli.sli4.cfgFCF.entry[i].FabricName, 8)) {
				match_found = 0;
				continue;
			}

			match_found = 1;
		}

		if (hba->sli.sli4.cfgFCF.entry[i].SwitchNameValid) {
			valid_entry = 1;

			if (bcmp((char *)fcfrec->switch_name_identifier,
			    hba->sli.sli4.cfgFCF.entry[i].SwitchName, 8)) {
				match_found = 0;
				continue;
			}

			match_found = 1;
		}

		if (hba->sli.sli4.cfgFCF.entry[i].VLanValid) {
			valid_entry = 1;

			if (!(fcfp->flag & EMLXS_FCFI_VLAN_ID)) {
				match_found = 0;
				continue;
			}

			VLanId = hba->sli.sli4.cfgFCF.entry[i].VLanId;
			j = VLanId / 8;
			k = 1 << (VLanId % 8);

			if (!(fcfrec->vlan_bitmap[j] & k)) {
				match_found = 0;
				continue;
			}

			/* Assign requested vlan_id to this FCF */
			fcfp->vlan_id = VLanId;

			match_found = 1;
		}

		/* If a match was found */
		if (match_found) {
			if (hba->sli.sli4.cfgFCF.entry[i].Primary) {
				fcfp->flag |= EMLXS_FCFI_PRIMARY;
			}
			if (hba->sli.sli4.cfgFCF.entry[i].Boot) {
				fcfp->flag |= EMLXS_FCFI_BOOT;
			}
			return (1);
		}
	}

	/* If no valid entries found, then allow any fabric */
	if (!valid_entry) {
		return (1);
	}

	return (0);

} /* emlxs_fcf_configured() */


static void
emlxs_fcfi_update(emlxs_port_t *port, FCFIobj_t *fcfp, FCF_RECORD_t *fcf_rec,
    uint32_t event_tag)
{
	emlxs_hba_t	*hba = HBA;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	uint16_t	i;

	bcopy((char *)fcf_rec, &fcfp->fcf_rec, sizeof (FCF_RECORD_t));
	fcfp->fcf_index = fcf_rec->fcf_index;

	/* Clear VLAN info */
	fcfp->vlan_id = 0;
	fcfp->flag &= ~EMLXS_FCFI_VLAN_ID;

	/* Check if fcf is a member of a VLAN */
	for (i = 0; i < 4096; i++) {
		if (fcf_rec->vlan_bitmap[i / 8] & (1 << (i % 8))) {
			/* For now assign the VLAN id of the first VLAN found */
			fcfp->vlan_id = i;
			fcfp->flag |= EMLXS_FCFI_VLAN_ID;
			break;
		}
	}

	if (fcf_rec->fcf_available) {
		fcfp->flag |= EMLXS_FCFI_AVAILABLE;
	} else {
		fcfp->flag &= ~EMLXS_FCFI_AVAILABLE;
	}

	if (fcf_rec->fcf_valid && !fcf_rec->fcf_sol) {
		fcfp->flag |= EMLXS_FCFI_VALID;
	} else {
		fcfp->flag &= ~EMLXS_FCFI_VALID;
	}

	/* Check config region 23 */
	/* Also sets BOOT and PRIMARY cfg bits as needed */
	if (emlxs_fcf_configured(port, fcfp)) {
		fcfp->flag |= EMLXS_FCFI_CONFIGURED;
	} else {
		fcfp->flag &= ~EMLXS_FCFI_CONFIGURED;
	}

	/* Set fcfp priority.  Used by selection alogithm */
	/* Combination of BOOT:PRIMARY:~fip_priority */
	fcfp->priority  = (fcfp->flag & EMLXS_FCFI_BOOT)? 0x200:0;
	fcfp->priority |= (fcfp->flag & EMLXS_FCFI_PRIMARY)? 0x100:0;
	fcfp->priority |= ~(fcf_rec->fip_priority & 0xff);

	fcfp->event_tag  = event_tag;
	fcfp->generation = fcftab->generation;
	fcfp->flag |= EMLXS_FCFI_FRESH;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi:%d gen=%x iotag=%d flag=%x sol=%x avl=%x val=%x state=%x "
	    "map=%x pri=%x vid=%x",
	    fcf_rec->fcf_index,
	    fcfp->generation,
	    fcfp->event_tag,
	    fcfp->flag,
	    fcf_rec->fcf_sol,
	    fcf_rec->fcf_available,
	    fcf_rec->fcf_valid,
	    fcf_rec->fcf_state,
	    fcf_rec->mac_address_provider,
	    fcfp->priority,
	    fcfp->vlan_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "fcfi:%d mac=%02x:%02x:%02x:%02x:%02x:%02x "
	    "fabric=%02x%02x%02x%02x%02x%02x%02x%02x "
	    "switch=%02x%02x%02x%02x%02x%02x%02x%02x",
	    fcfp->fcf_index,
	    fcf_rec->fcf_mac_address_hi[0],
	    fcf_rec->fcf_mac_address_hi[1],
	    fcf_rec->fcf_mac_address_hi[2],
	    fcf_rec->fcf_mac_address_hi[3],
	    fcf_rec->fcf_mac_address_low[0],
	    fcf_rec->fcf_mac_address_low[1],

	    fcf_rec->fabric_name_identifier[0],
	    fcf_rec->fabric_name_identifier[1],
	    fcf_rec->fabric_name_identifier[2],
	    fcf_rec->fabric_name_identifier[3],
	    fcf_rec->fabric_name_identifier[4],
	    fcf_rec->fabric_name_identifier[5],
	    fcf_rec->fabric_name_identifier[6],
	    fcf_rec->fabric_name_identifier[7],

	    fcf_rec->switch_name_identifier[0],
	    fcf_rec->switch_name_identifier[1],
	    fcf_rec->switch_name_identifier[2],
	    fcf_rec->switch_name_identifier[3],
	    fcf_rec->switch_name_identifier[4],
	    fcf_rec->switch_name_identifier[5],
	    fcf_rec->switch_name_identifier[6],
	    fcf_rec->switch_name_identifier[7]);

	return;

} /* emlxs_fcfi_update() */


/* ************************************************************************** */
/* VFI */
/* ************************************************************************** */

static char *
emlxs_vfi_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_vfi_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_vfi_state_table[i].code) {
			return (emlxs_vfi_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_vfi_state_xlate() */


static uint32_t
emlxs_vfi_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, VFIobj_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_VFI_ONLINE:
		index = 1;
		break;
	case FCF_EVENT_VFI_OFFLINE:
		index = 2;
		break;
	case FCF_EVENT_VFI_PAUSE:
		index = 3;
		break;
	case FCF_EVENT_VPI_ONLINE:
		index = 4;
		break;
	case FCF_EVENT_VPI_OFFLINE:
		index = 5;
		break;
	default:
		return (1);
	}

	events = VFI_ACTION_EVENTS;
	state  = vfip->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, VFIobj_t *, uint32_t, void *))
	    emlxs_vfi_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "vfi_action:%d %s:%s arg=%p. No action. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, vfip, evt, arg1);

	return (rval);

} /* emlxs_vfi_action() */


static uint32_t
emlxs_vfi_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	VPIobj_t *vpip = NULL;
	VFIobj_t *vfip = NULL;
	uint32_t rval = 0;

	/* Filter events and acquire fcfi context */
	switch (evt) {
	case FCF_EVENT_VPI_ONLINE:
	case FCF_EVENT_VPI_OFFLINE:
		vpip = (VPIobj_t *)arg1;

		if (!vpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "vfi_event: %s arg=%p. Null VPI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}

		vfip = vpip->vfip;

		if (!vfip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "vfi_event: %s arg=%p. VFI not found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}
		break;

	case FCF_EVENT_VFI_ONLINE:
	case FCF_EVENT_VFI_OFFLINE:
	case FCF_EVENT_VFI_PAUSE:
		vfip = (VFIobj_t *)arg1;

		if (!vfip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "vfi_event: %s arg=%p. VFI not found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}
		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "vfi_event:%d %s:%s arg=%p",
	    vfip->VFI,
	    emlxs_vfi_state_xlate(vfip->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_vfi_action(port, vfip, evt, arg1);

	return (rval);

} /* emlxs_vfi_event() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_state(emlxs_port_t *port, VFIobj_t *vfip, uint16_t state,
    uint16_t reason, uint32_t explain, void *arg1)
{
	uint32_t rval = 0;

	if (state >= VFI_ACTION_STATES) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_state:%d %s. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state));
		return (1);
	}

	if ((vfip->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_state:%d %s:%s:0x%x arg=%p. "
		    "State not changed. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);

		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vfi_state:%d %s-->%s arg=%p",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_vfi_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vfi_state:%d %s-->%s:%s:%s arg=%p",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_vfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vfi_state:%d %s-->%s:%s:0x%x arg=%p",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_vfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vfi_state:%d %s-->%s:%s arg=%p",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_vfi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	vfip->prev_state = vfip->state;
	vfip->prev_reason = vfip->reason;
	vfip->state = state;
	vfip->reason = reason;

	rval = emlxs_vfi_action(port, vfip, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_vfi_state() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_online_evt_action(emlxs_port_t *port, VFIobj_t *vfip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VPI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_vpi_online_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	switch (vfip->state) {
	case VFI_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_evt_action:%d flag=%x vpi_online=%d. "
		    "Reentering online.",
		    vfip->VFI,
		    vfip->flag,
		    vfip->vpi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_ONLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case VFI_STATE_VPI_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_evt_action:%d flag=%x vpi_online=%d. "
		    "Online cmpl.",
		    vfip->VFI,
		    vfip->flag,
		    vfip->vpi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_ONLINE_CMPL,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_evt_action:%d flag=%x vpi_online=%d. <",
		    vfip->VFI,
		    vfip->flag,
		    vfip->vpi_online);

		return (1);
	}

	return (rval);

} /* emlxs_vfi_vpi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_offline_handler(emlxs_port_t *port, VFIobj_t *vfip, void *arg1)
{
	uint32_t rval = 0;

	if (!(vfip->flag & EMLXS_VFI_OFFLINE_REQ)) {
		return (0);
	}

	if (vfip->vpi_online) {
		if (vfip->flag & EMLXS_VFI_PAUSE_REQ) {
			rval = emlxs_vfi_state(port, vfip, VFI_STATE_PAUSED,
			    FCF_REASON_REQUESTED, 0, arg1);
		} else {
			rval = emlxs_vfi_state(port, vfip,
			    VFI_STATE_VPI_OFFLINE, FCF_REASON_REQUESTED,
			    0, arg1);
		}

	} else if (vfip->flag & EMLXS_VFI_REG) {
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else if (vfip->flag & EMLXS_VFI_INIT) {
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else {
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	return (rval);

} /* emlxs_vfi_offline_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_offline_evt_action(emlxs_port_t *port, VFIobj_t *vfip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;
	VPIobj_t *vpip;

	if (evt != FCF_EVENT_VPI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_vpi_offline_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	/* Disconnect VPI object from VFI */
	vpip = (VPIobj_t *)arg1;
	vpip->vfip = NULL;

	switch (vfip->state) {
	case VFI_STATE_ONLINE:
	case VFI_STATE_VPI_ONLINE:
		if (vfip->vpi_online == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vfi_vpi_offline_evt_action:%d flag=%x "
			    "vpi_online=%d. Offlining.",
			    vfip->VFI,
			    vfip->flag, vfip->vpi_online);

			vfip->flag &= ~EMLXS_VFI_REQ_MASK;
			vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
			rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vfi_vpi_offline_evt_action:%d flag=%x "
			    "vpi_online=%d. <",
			    vfip->VFI,
			    vfip->flag, vfip->vpi_online);
		}
		break;

	case VFI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_evt_action:%d flag=%x vpi_online=%d. <",
		    vfip->VFI,
		    vfip->flag, vfip->vpi_online);
		break;

	case VFI_STATE_VPI_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_evt_action:%d flag=%x. VPI offline cmpl.",
		    vfip->VFI,
		    vfip->flag);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_OFFLINE_CMPL,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case VFI_STATE_VPI_OFFLINE_CMPL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_evt_action:%d flag=%x. VPI offline cmpl.",
		    vfip->VFI,
		    vfip->flag);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_OFFLINE_CMPL,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		if (vfip->vpi_online == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vfi_vpi_offline_evt_action:%d flag=%x "
			    "vpi_online=%d. Requesting offline. <",
			    vfip->VFI,
			    vfip->flag, vfip->vpi_online);

			vfip->flag &= ~EMLXS_VFI_REQ_MASK;
			vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vfi_vpi_offline_evt_action:%d flag=%x "
			    "vpi_online=%d. <",
			    vfip->VFI,
			    vfip->flag, vfip->vpi_online);
		}
		return (1);
	}

	return (rval);

} /* emlxs_vfi_vpi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_online_evt_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *vport;
	VPIobj_t *vpip;
	uint32_t rval = 0;
	uint32_t i;

	if (evt != FCF_EVENT_VFI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_online_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	if (vfip->flag & EMLXS_VFI_ONLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_evt_action:%d flag=%x. "
		    "Online already requested. <",
		    vfip->VFI,
		    vfip->flag);
		return (0);
	}

	vfip->flag &= ~EMLXS_VFI_REQ_MASK;

	switch (vfip->state) {
	case VFI_STATE_OFFLINE:
		vfip->flag |= EMLXS_VFI_ONLINE_REQ;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_evt_action:%d flag=%x. Initiating online.",
		    vfip->VFI,
		    vfip->flag);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_INIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case VFI_STATE_VPI_OFFLINE:
	case VFI_STATE_PAUSED:
		vfip->flag |= EMLXS_VFI_ONLINE_REQ;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_evt_action:%d flag=%x. Initiating online.",
		    vfip->VFI,
		    vfip->flag);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case VFI_STATE_ONLINE:
		/* Online all VPI's belonging to this vfi */
		for (i = 0; i <= hba->vpi_max; i++) {
			vport = &VPORT(i);
			vpip = vport->vpip;

			if (!(vport->flag & EMLXS_PORT_BOUND) ||
			    (vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
				continue;
			}

			if (vpip->vfip != vfip) {
				continue;
			}

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vfi_online_evt_action:%d. Onlining VPI:%d >",
			    vfip->VFI,
			    vpip->VPI);

			(void) emlxs_vpi_event(vport, FCF_EVENT_VPI_ONLINE,
			    vpip);
		}
		break;

	default:
		vfip->flag |= EMLXS_VFI_ONLINE_REQ;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_evt_action:%d flag=%x. <",
		    vfip->VFI,
		    vfip->flag);
		return (1);
	}

	return (rval);

} /* emlxs_vfi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_offline_evt_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VFI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_offline_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	if ((vfip->flag & EMLXS_VFI_OFFLINE_REQ) &&
	    !(vfip->flag & EMLXS_VFI_PAUSE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_evt_action:%d flag=%x. "
		    "Offline already requested. <",
		    vfip->VFI,
		    vfip->flag);
		return (0);
	}

	switch (vfip->state) {
	case VFI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_evt_action:%d flag=%x. "
		    "Already offline. <",
		    vfip->VFI,
		    vfip->flag);
		break;

	/* Wait states */
	case VFI_STATE_VPI_ONLINE:
	case VFI_STATE_VPI_OFFLINE:
	case VFI_STATE_VPI_OFFLINE_CMPL:
	case VFI_STATE_INIT:
	case VFI_STATE_REG:
	case VFI_STATE_ONLINE:
	case VFI_STATE_PAUSED:
		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_evt_action:%d flag=%x.  Handling offline.",
		    vfip->VFI,
		    vfip->flag);

		/* Handle offline now */
		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		break;

	default:
		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_evt_action:%d flag=%x. <",
		    vfip->VFI,
		    vfip->flag);
		break;
	}

	return (rval);

} /* emlxs_vfi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_pause_evt_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VFI_PAUSE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_pause_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	if (vfip->flag & EMLXS_VFI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. "
		    "Pause already requested. <",
		    vfip->VFI,
		    vfip->flag);
		return (0);
	}

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. "
		    "Offline already requested. <",
		    vfip->VFI,
		    vfip->flag);
		return (0);
	}

	switch (vfip->state) {
	case VFI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. "
		    "Already offline. <",
		    vfip->VFI,
		    vfip->flag);
		break;

	case VFI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. "
		    "Already paused. <",
		    vfip->VFI,
		    vfip->flag);
		break;

	/* Wait states */
	case VFI_STATE_VPI_ONLINE:
	case VFI_STATE_VPI_OFFLINE_CMPL:
	case VFI_STATE_INIT:
	case VFI_STATE_REG:
	case VFI_STATE_ONLINE:
		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= (EMLXS_VFI_OFFLINE_REQ | EMLXS_VFI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. Handling offline.",
		    vfip->VFI,
		    vfip->flag);

		/* Handle offline now */
		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		break;

	default:
		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= (EMLXS_VFI_OFFLINE_REQ | EMLXS_VFI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_pause_evt_action:%d flag=%x. <",
		    vfip->VFI,
		    vfip->flag);
		break;
	}

	return (rval);

} /* emlxs_vfi_pause_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_offline_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!vfip->fcfp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_action:%d %s:%s arg=%p flag=%x. "
		    "Null fcfp found. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->flag);
		return (1);
	}

	vfip->flag &= ~(EMLXS_VFI_OFFLINE_REQ | EMLXS_VFI_PAUSE_REQ);

	if (vfip->prev_state == VFI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_action:%d vfi_online=%d. <",
		    vfip->VFI,
		    vfip->fcfp->vfi_online);

		return (0);
	}

	if (vfip->vpi_online) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_offline_action:%d vpi_online=%d. VPI's still online.",
		    vfip->VFI,
		    vfip->vpi_online);
	}

	if (vfip->flag & EMLXS_VFI_FCFI) {
		vfip->flag &= ~EMLXS_VFI_FCFI;

		if (vfip->fcfp->vfi_online) {
			vfip->fcfp->vfi_online--;
		}
	}

	/* Check if online was requested */
	if (vfip->flag & EMLXS_VFI_ONLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_offline_action:%d vfi_online=%d. Online requested.",
		    vfip->VFI,
		    vfip->fcfp->vfi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_INIT,
		    FCF_REASON_REQUESTED, 0, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_offline_action:%d vfi_online=%d. "
	    "VFI offline. Notifying FCFI:%d >",
	    vfip->VFI,
	    vfip->fcfp->vfi_online,
	    vfip->fcfp->fcf_index);

	/* Notify FCFI */
	rval = emlxs_fcfi_event(port, FCF_EVENT_VFI_OFFLINE, vfip);

	return (rval);

} /* emlxs_vfi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_init_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	VFIobj_t *vfip;
	MAILBOX4 *mb4;

	vfip = (VFIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vfip->state != VFI_STATE_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_mbcmpl:%d %s.",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_mbcmpl:%d failed. %s. >",
		    vfip->VFI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_vfi_state(port, vfip, VFI_STATE_INIT_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_init_mbcmpl:%d. Init complete. >",
	    vfip->VFI,
	    mb4->mbxStatus);

	vfip->flag |= EMLXS_VFI_INIT;
	(void) emlxs_vfi_state(port, vfip, VFI_STATE_INIT_CMPL, 0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vfi_init_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_init_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(vfip->flag & EMLXS_VFI_FCFI)) {
		vfip->flag |= EMLXS_VFI_FCFI;
		vfip->fcfp->vfi_online++;
	}

	if (vfip->prev_state != VFI_STATE_INIT_FAILED) {
		vfip->attempts = 0;
	}

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d attempts=%d. Offline requested.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	if (vfip->flag & EMLXS_VFI_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d flag=%x. "
		    "Already init'd. Skipping INIT_VFI.",
		    vfip->VFI);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (((hba->sli_intf & SLI_INTF_IF_TYPE_MASK) ==
	    SLI_INTF_IF_TYPE_0) && (vfip->fcfp->vfi_online == 1)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d. First VFI. Skipping INIT_VFI.",
		    vfip->VFI);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_init_action:%d vfi_online=%d attempts=%d. Sending INIT_VFI. <",
	    vfip->VFI,
	    vfip->fcfp->vfi_online,
	    vfip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vfi_state(port, vfip, FCFI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_vfi_init_mbcmpl;
	mbq->context = (void *)vfip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_INIT_VFI;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varInitVFI4.fcfi = vfip->fcfp->FCFI;
	mb4->un.varInitVFI4.vfi = vfip->VFI;

	/* ??? This function is untested and incomplete */

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_INIT_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vfi_init_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_init_failed_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vfip->attempts++;

	if (vfip->state != VFI_STATE_INIT_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_init_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->attempts);
		return (1);
	}

	if ((vfip->reason == FCF_REASON_SEND_FAILED) ||
	    (vfip->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d attempt=%d reason=%x. Init cmpl.",
		    vfip->VFI,
		    vfip->attempts,
		    vfip->reason);

		vfip->flag &= ~(EMLXS_VFI_REG | EMLXS_VFI_INIT);

		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_INIT_CMPL,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_action:%d attempt=%d. Initializing.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_INIT,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vfi_init_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_init_cmpl_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_INIT_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_init_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_init_cmpl_action:%d attempts=%d. Init cmpl.",
	    vfip->VFI,
	    vfip->attempts);

	rval = emlxs_vfi_state(port, vfip, VFI_STATE_VPI_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vfi_init_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_online_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;
	uint32_t i;
	emlxs_port_t *vport;
	VPIobj_t *vpip;

	if (vfip->state != VFI_STATE_VPI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_action:%d. Offline requested.",
		    vfip->VFI);

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	if (vfip->logi_count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_vpi_online_action:%d vpi_online=%d logi_count=%d. "
		    "VPI already logged in.",
		    vfip->VFI,
		    vfip->vpi_online,
		    vfip->logi_count);
	}

	if (vfip->vpi_online) {
		/* Waking up after being paused */

		/* Find first VPI of this VFI */
		for (i = 0; i <= hba->vpi_max; i++) {
			vport = &VPORT(i);
			vpip = vport->vpip;

			if (!(vport->flag & EMLXS_PORT_BOUND) ||
			    (vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
				continue;
			}

			if (vpip->vfip == vfip) {
				break;
			}
		}

	} else {

		/* Find first available VPI */
		for (i = 0; i <= hba->vpi_max; i++) {
			vport = &VPORT(i);
			vpip = vport->vpip;

			if (!(vport->flag & EMLXS_PORT_BOUND) ||
			    (vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
				continue;
			}

			if (vpip->vfip == NULL) {
				vpip->vfip = vfip;
				break;
			}
		}
	}

	if (i > hba->vpi_max) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_action:%d vpi_online=%d logi_count=%d. "
		    "No VPI found. Offlining.",
		    vfip->VFI,
		    vfip->vpi_online,
		    vfip->logi_count);

		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_vpi_online_action:%d vpi_online=%d logi_count=%d. "
	    "Onlining VPI:%d >",
	    vfip->VFI,
	    vfip->vpi_online,
	    vfip->logi_count,
	    vpip->VPI);

	rval = emlxs_vpi_event(port, FCF_EVENT_VPI_ONLINE, vpip);

	/* Wait for FCF_EVENT_VPI_ONLINE in return */

	return (rval);

} /* emlxs_vfi_vpi_online_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_online_cmpl_action(emlxs_port_t *port, VFIobj_t *vfip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;
	VPIobj_t *vpip = (VPIobj_t *)arg1;

	if (vfip->state != VFI_STATE_VPI_ONLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip == vfip->flogi_vpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_cmpl_action:%d flag=%x vpi_online=%d "
		    "logi_count=%d. flogi_vpi. Registering.",
		    vfip->VFI,
		    vfip->flag,
		    vfip->vpi_online,
		    vfip->logi_count);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG,
		    FCF_REASON_EVENT, evt, arg1);
	} else {
		/* Waking up after pause */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_online_cmpl_action:%d flag=%x vpi_online=%d "
		    "logi_count=%d. Going online.",
		    vfip->VFI,
		    vfip->flag,
		    vfip->vpi_online,
		    vfip->logi_count);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
	}

	return (rval);

} /* emlxs_vfi_vpi_online_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_offline_cmpl_action(emlxs_port_t *port, VFIobj_t *vfip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_VPI_OFFLINE_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((vfip->vpi_online == 0) &&
	    (vfip->flag & EMLXS_VFI_OFFLINE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_cmpl_action:%d vpi_online=%d. "
		    "Unregistering.",
		    vfip->VFI,
		    vfip->vpi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_cmpl_action:%d vpi_online=%d. <",
		    vfip->VFI,
		    vfip->vpi_online);
	}

	return (rval);

} /* emlxs_vfi_vpi_offline_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_vpi_offline_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *vport;
	uint32_t rval = 0;
	int32_t i;
	VPIobj_t *vpip;

	if (vfip->state != VFI_STATE_VPI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vfip->flag & EMLXS_VFI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_action:%d vpi_online=%d. Pausing.",
		    vfip->VFI,
		    vfip->vpi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_PAUSED,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (vfip->vpi_online == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_action:%d vpi_online=%d. "
		    "VPI already offline. Skipping VPI offline.",
		    vfip->VFI,
		    vfip->vpi_online);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	/* Offline all VPI's of this VFI */
	for (i = hba->vpi_max; i >= 0; i--) {
		vport = &VPORT(i);
		vpip = vport->vpip;

		if ((vpip->state == VPI_STATE_OFFLINE) ||
		    (vpip->vfip != vfip)) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_vpi_offline_action:%d. Offlining VPI:%d. >",
		    vfip->VFI,
		    vpip->VPI);

		(void) emlxs_vpi_event(vport, FCF_EVENT_VPI_OFFLINE, vpip);
	}

	/* Wait for FCF_EVENT_VPI_OFFLINE in return */

	return (0);

} /* emlxs_vfi_vpi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_paused_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *vport;
	int32_t i;
	VPIobj_t *vpip;

	if (vfip->state != VFI_STATE_PAUSED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_paused_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	vfip->flag &= ~(EMLXS_VFI_OFFLINE_REQ | EMLXS_VFI_PAUSE_REQ);

	/* Pause all VPI's of this VFI */
	for (i = hba->vpi_max; i >= 0; i--) {
		vport = &VPORT(i);
		vpip = vport->vpip;

		if ((vpip->state == VPI_STATE_PAUSED) ||
		    (vpip->vfip != vfip)) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_paused_action:%d vpi_online=%d. Pausing VPI:%d. >",
		    vfip->VFI,
		    vfip->vpi_online,
		    vpip->VPI);

		(void) emlxs_vpi_event(vport, FCF_EVENT_VPI_PAUSE, vpip);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_paused_action:%d vpi_online=%d. VFI paused. <",
	    vfip->VFI,
	    vfip->vpi_online);

	return (0);

} /* emlxs_vfi_paused_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_unreg_failed_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vfip->attempts++;

	if (vfip->state != VFI_STATE_UNREG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_unreg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->attempts);
		return (1);
	}

	if (vfip->attempts >= 3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_unreg_failed_action:%d attempt=%d. Unreg cmpl.",
		    vfip->VFI,
		    vfip->attempts);

		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG_CMPL,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_unreg_failed_action:%d attempt=%d. Unregistering.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vfi_unreg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_unreg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	VFIobj_t *vfip;

	vfip = (VFIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vfip->state != VFI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_unreg_mbcmpl:%d state=%s.",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_unreg_mbcmpl:%d failed. %s. >",
		    vfip->VFI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_vfi_state(port, vfip, VFI_STATE_UNREG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, (void *)mbq->sbp);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_unreg_mbcmpl:%d. Unreg complete. >",
	    vfip->VFI);

	vfip->flag &= ~(EMLXS_VFI_REG | EMLXS_VFI_INIT);
	(void) emlxs_vfi_state(port, vfip, VFI_STATE_UNREG_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vfi_unreg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_unreg_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_unreg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(vfip->flag & EMLXS_VFI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_unreg_action:%d. Not registered. Skipping UNREG_VFI.",
		    vfip->VFI);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (vfip->prev_state != VFI_STATE_UNREG_FAILED) {
		vfip->attempts = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_unreg_action:%d attempts=%d. Sending UNREG_VFI. <",
	    vfip->VFI,
	    vfip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_vfi_unreg_mbcmpl;
	mbq->context = (void *)vfip;
	mbq->port = (void *)port;

	mb4->un.varUnRegVFI4.vfi = vfip->VFI;
	mb4->mbxCommand = MBX_UNREG_VFI;
	mb4->mbxOwner = OWN_HOST;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_UNREG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vfi_unreg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_unreg_cmpl_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_UNREG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_unreg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_unreg_cmpl_action:%d attempts=%d. Going offline.",
	    vfip->VFI,
	    vfip->attempts);

	rval = emlxs_vfi_state(port, vfip, VFI_STATE_OFFLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vfi_unreg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_reg_failed_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vfip->attempts++;

	if (vfip->state != VFI_STATE_REG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_reg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vfip->attempts);
		return (1);
	}

	if ((vfip->reason == FCF_REASON_SEND_FAILED) ||
	    (vfip->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_failed_action:%d attempt=%d reason=%x. Reg cmpl.",
		    vfip->VFI,
		    vfip->attempts,
		    vfip->reason);

		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG_CMPL,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_failed_action:%d attempt=%d. Registering.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG,
		    FCF_REASON_OP_FAILED, vfip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vfi_reg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_reg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	VFIobj_t *vfip;
	MATCHMAP *mp;

	vfip = (VFIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vfip->state != VFI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_mbcmpl:%d state=%s.",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_mbcmpl:%d failed. %s. >",
		    vfip->VFI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_vfi_state(port, vfip, VFI_STATE_REG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, (void *)mbq->sbp);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	/* Archive a copy of the sparams in case we need them later */
	mp = (MATCHMAP *)mbq->bp;
	bcopy((uint32_t *)mp->virt, (uint32_t *)&vfip->sparam,
	    sizeof (SERV_PARM));

	if (vfip->flogi_vpip) {
		if (mb4->un.varRegVFI4.vp == 1) {
			vfip->flogi_vpip->flag |= EMLXS_VPI_REG;
		}
		vfip->flogi_vpip = NULL;
	}

	vfip->flag |= EMLXS_VFI_REG;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_reg_mbcmpl:%d. Reg complete. >",
	    vfip->VFI);

	(void) emlxs_vfi_state(port, vfip, VFI_STATE_REG_CMPL, 0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vfi_reg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_reg_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	MATCHMAP *mp;
	uint32_t rval = 0;
	uint32_t edtov;
	uint32_t ratov;
	SERV_PARM *flogi_sparam;
	uint32_t *wwpn;

	if (vfip->state != VFI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_reg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vfip->prev_state != VFI_STATE_REG_FAILED) {
		vfip->attempts = 0;
	}

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_action:%d %attempts=%d. Offline requested.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	if (!vfip->flogi_vpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_action:%d %attempts=%d. No flogi_vpi found.",
		    vfip->VFI,
		    vfip->attempts);

		vfip->flag &= ~EMLXS_VFI_REQ_MASK;
		vfip->flag |= EMLXS_VFI_OFFLINE_REQ;

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	if ((hba->model_info.chip & EMLXS_BE_CHIPS) &&
	    (vfip->flag & EMLXS_VFI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_action:%d flag=%x. "
		    "Already registered. Skipping REG_VFI update.",
		    vfip->VFI);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	/* Get the flogi_vpip's fabric_rpip's service parameters */
	flogi_sparam = &vfip->flogi_vpip->fabric_rpip->sparam;

	if (flogi_sparam->cmn.edtovResolution) {
		edtov = (LE_SWAP32(flogi_sparam->cmn.e_d_tov) + 999999) /
		    1000000;
	} else {
		edtov = LE_SWAP32(flogi_sparam->cmn.e_d_tov);
	}

	ratov = (LE_SWAP32(flogi_sparam->cmn.w2.r_a_tov) + 999) / 1000;

	if (vfip->flag & EMLXS_VFI_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_action:%d attempts=%d edtov=%d ratov=%d. "
		    "Updating REG_VFI. <",
		    vfip->VFI,
		    vfip->attempts,
		    edtov, ratov);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_action:%d attempts=%d edtov=%d ratov=%d. "
		    "Sending REG_VFI. <",
		    vfip->VFI,
		    vfip->attempts,
		    edtov, ratov);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG_FAILED,
		    FCF_REASON_NO_BUFFER, 0, arg1);

		return (1);
	}

	mbq->bp = (void *)mp;
	mbq->nonembed = NULL;

	mbq->mbox_cmpl = emlxs_vfi_reg_mbcmpl;
	mbq->context = (void *)vfip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_REG_VFI;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varRegVFI4.vfi = vfip->VFI;
	mb4->un.varRegVFI4.upd = (vfip->flag & EMLXS_VFI_REG)? 1:0;

	/* If the flogi_vpip was not previously registered, */
	/* perform the REG_VPI now */
	if (!(vfip->flogi_vpip->flag & EMLXS_VPI_REG)) {
		mb4->un.varRegVFI4.vp = 1;
		mb4->un.varRegVFI4.vpi = vfip->flogi_vpip->VPI;
	}

	mb4->un.varRegVFI4.fcfi = vfip->fcfp->FCFI;
	wwpn = (uint32_t *)&port->wwpn;
	mb4->un.varRegVFI4.portname[0] = BE_SWAP32(*wwpn);
	wwpn++;
	mb4->un.varRegVFI4.portname[1] = BE_SWAP32(*wwpn);
	mb4->un.varRegVFI4.sid = port->did;
	mb4->un.varRegVFI4.edtov = edtov;
	mb4->un.varRegVFI4.ratov = ratov;
	mb4->un.varRegVFI4.bde.tus.f.bdeSize = sizeof (SERV_PARM);
	mb4->un.varRegVFI4.bde.addrHigh = PADDR_HI(mp->phys);
	mb4->un.varRegVFI4.bde.addrLow = PADDR_LO(mp->phys);
	bcopy((uint32_t *)flogi_sparam, (uint32_t *)mp->virt,
	    sizeof (SERV_PARM));

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vfi_state(port, vfip, VFI_STATE_REG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vfi_reg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_reg_cmpl_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vfip->state != VFI_STATE_REG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vfi_reg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_reg_cmpl_action:%d attempts=%d. Offline requested.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_reg_cmpl_action:%d attempts=%d. Going online.",
	    vfip->VFI,
	    vfip->attempts);

	rval = emlxs_vfi_state(port, vfip, VFI_STATE_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vfi_reg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vfi_online_action(emlxs_port_t *port, VFIobj_t *vfip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t i;
	uint32_t rval = 0;
	VPIobj_t *vpip = port->vpip;
	emlxs_port_t *vport;

	if (vfip->state != VFI_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vfip->VFI,
		    emlxs_vfi_state_xlate(vfip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	vfip->flag &= ~EMLXS_VFI_ONLINE_REQ;

	if (vfip->flag & EMLXS_VFI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_action:%d attempts=%d. Offline requested.",
		    vfip->VFI,
		    vfip->attempts);

		rval = emlxs_vfi_offline_handler(port, vfip, arg1);
		return (rval);
	}

	/* Take the port's Fabric RPI online now */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_online_action:%d. Onlining Fabric RPI. >",
	    vfip->VFI);

	/* This will complete the FLOGI/FDISC back to Leadville */
	(void) emlxs_rpi_event(port, FCF_EVENT_RPI_ONLINE,
	    vpip->fabric_rpip);

	/* FLOGI/FDISC has been completed back to Leadville */
	/* It is now safe to accept unsolicited requests */
	vpip->flag |= EMLXS_VPI_PORT_ENABLED;

	/* Online remaining VPI's */
	for (i = 0; i <= hba->vpi_max; i++) {
		vport = &VPORT(i);
		vpip = vport->vpip;

		if (!(vport->flag & EMLXS_PORT_BOUND) ||
		    (vpip->flag & EMLXS_VPI_PORT_UNBIND)) {
			continue;
		}

		if ((vpip->state == VPI_STATE_ONLINE) ||
		    (vpip->flag & EMLXS_VPI_ONLINE_REQ)) {
			continue;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vfi_online_action:%d vpi_online=%d logi_count=%d. "
		    "Onlining VPI:%d >",
		    vfip->VFI,
		    vfip->vpi_online,
		    vfip->logi_count,
		    vpip->VPI);

		vpip->vfip = vfip;
		(void) emlxs_vpi_event(vport, FCF_EVENT_VPI_ONLINE, vpip);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vfi_online_action:%d vpi_online=%d logi_count=%d. "
	    "VFI online. Notifying FCFI:%d. >",
	    vfip->VFI,
	    vfip->vpi_online,
	    vfip->logi_count,
	    vfip->fcfp->fcf_index);

	/* Notify FCFI */
	rval = emlxs_fcfi_event(port, FCF_EVENT_VFI_ONLINE, vfip);

	return (rval);

} /* emlxs_vfi_online_action() */


/* ************************************************************************** */
/* VPI */
/* ************************************************************************** */

static char *
emlxs_vpi_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_vpi_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_vpi_state_table[i].code) {
			return (emlxs_vpi_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_vpi_state_xlate() */


static uint32_t
emlxs_vpi_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, VPIobj_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_VPI_ONLINE:
		index = 1;
		break;
	case FCF_EVENT_VPI_OFFLINE:
		index = 2;
		break;
	case FCF_EVENT_VPI_PAUSE:
		index = 3;
		break;
	case FCF_EVENT_RPI_ONLINE:
		index = 4;
		break;
	case FCF_EVENT_RPI_OFFLINE:
		index = 5;
		break;
	case FCF_EVENT_RPI_PAUSE:
		index = 6;
		break;
	default:
		return (1);
	}

	events = VPI_ACTION_EVENTS;
	state  = vpip->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, VPIobj_t *, uint32_t, void *))
	    emlxs_vpi_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "vpi_action:%d %s:%s arg=%p. No action. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, vpip, evt, arg1);

	return (rval);

} /* emlxs_vpi_action() */


static uint32_t
emlxs_vpi_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	VPIobj_t *vpip = NULL;
	RPIobj_t *rpip;
	uint32_t rval = 0;

	/* Filter events and acquire fcfi context */
	switch (evt) {
	case FCF_EVENT_RPI_ONLINE:
	case FCF_EVENT_RPI_OFFLINE:
	case FCF_EVENT_RPI_PAUSE:
		rpip = (RPIobj_t *)arg1;

		if (!rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "vpi_event: %s arg=%p. Null RPI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}

		vpip = rpip->vpip;
		break;

	case FCF_EVENT_VPI_ONLINE:
	case FCF_EVENT_VPI_PAUSE:
	case FCF_EVENT_VPI_OFFLINE:
		vpip = (VPIobj_t *)arg1;

		if (!vpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "vpi_event: %s arg=%p. Null VPI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}

		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "vpi_event:%d %s:%s arg=%p",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_vpi_action(port, vpip, evt, arg1);

	return (rval);

} /* emlxs_vpi_event() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_state(emlxs_port_t *port, VPIobj_t *vpip, uint16_t state,
    uint16_t reason, uint32_t explain, void *arg1)
{
	uint32_t rval = 0;

	if (state >= VPI_ACTION_STATES) {
		return (1);
	}

	if ((vpip->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_state:%d %s:%s:0x%x arg=%p. "
		    "State not changed. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vpi_state:%d %s-->%s arg=%p",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_vpi_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vpi_state:%d %s-->%s:%s:%s arg=%p",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_vpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vpi_state:%d %s-->%s:%s:0x%x arg=%p",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_vpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "vpi_state:%d %s-->%s:%s arg=%p",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_vpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	vpip->prev_state = vpip->state;
	vpip->prev_reason = vpip->reason;
	vpip->state = state;
	vpip->reason = reason;

	rval = emlxs_vpi_action(port, vpip, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_vpi_state() */


extern uint32_t
emlxs_vpi_port_bind_notify(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t 	*vpip = port->vpip;
	FCFTable_t	*fcftab = &hba->sli.sli4.fcftab;
	uint32_t rval = 0;
	VFIobj_t *vfip;
	VFIobj_t *vfip1;
	uint32_t i = 0;
	FCFIobj_t *fcfp;
	FCFIobj_t *fcfp1;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (hba->state < FC_LINK_UP) {
		if (port->vpi == 0) {
			(void) emlxs_reset_link(hba, 1, 0);

			/* Wait for VPI to go online */
			while ((vpip->state != VPI_STATE_PORT_ONLINE) &&
			    (hba->state != FC_ERROR)) {
				delay(drv_usectohz(500000));
				if (i++ > 30) {
					break;
				}
			}
		}
		return (0);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->vfip) {
		vfip = vpip->vfip;
		fcfp = vfip->fcfp;
		goto done;
	}

	/* We need to select a VFI for this VPI */

	/* First find a selected Fabric */
	fcfp = NULL;
	for (i = 0; i < fcftab->fcfi_count; i++) {
		fcfp1 = fcftab->fcfi[i];

		if (fcfp1->flag & EMLXS_FCFI_SELECTED) {
			fcfp = fcfp1;
			break;
		}
	}

	if (!fcfp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_bind_notify:%d %s. "
		    "No FCF available yet.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	/* Find first available VFI for this FCFI */
	vfip = NULL;
	vfip1 = hba->sli.sli4.VFI_table;
	for (i = 0; i < hba->sli.sli4.VFICount; i++, vfip1++) {
		if (vfip1->fcfp == fcfp) {
			vfip = vfip1;
			break;
		}
	}

	if (!vfip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_bind_notify:%d %s fcfi:%d. "
		    "No VFI available yet.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    fcfp->fcf_index);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	vpip->vfip = vfip;
done:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_port_bind_notify:%d %s fcfi:%d vfi:%d. Onlining VPI:%d >",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state),
	    fcfp->fcf_index,
	    vfip->VFI,
	    vpip->VPI);

	rval = emlxs_vpi_event(port, FCF_EVENT_VPI_ONLINE, vpip);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_vpi_port_bind_notify() */


extern uint32_t
emlxs_vpi_port_unbind_notify(emlxs_port_t *port, uint32_t wait)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t 	*vpip = port->vpip;
	uint32_t rval = 0;
	VFIobj_t *vfip;
	uint32_t i;
	FCFIobj_t *fcfp;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!(hba->sli.sli4.flag & EMLXS_SLI4_FCF_INIT)) {
		return (0);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state == VPI_STATE_OFFLINE) {
		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	/*
	 * Set flag to indicate that emlxs_vpi_port_unbind_notify
	 * has been called
	 */
	vpip->flag |= EMLXS_VPI_PORT_UNBIND;

	vfip = vpip->vfip;
	fcfp = vfip->fcfp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_port_unbind_notify:%d %s fcfi:%d vfi:%d. "
	    "Offlining VPI:%d,%d >",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state),
	    fcfp->fcf_index,
	    vfip->VFI,
	    vpip->index, vpip->VPI);

	rval = emlxs_vpi_event(port, FCF_EVENT_VPI_OFFLINE, vpip);

	if (wait && (rval == 0)) {
		/* Wait for VPI to go offline */
		i = 0;
		while (i++ < 120) {
			if (vpip->state == VPI_STATE_OFFLINE) {
				break;
			}

			mutex_exit(&EMLXS_FCF_LOCK);
			BUSYWAIT_MS(1000);
			mutex_enter(&EMLXS_FCF_LOCK);
		}

		if (i >= 120) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
			    "vpi_port_unbind_notify:%d %s fcfi:%d vfi:%d "
			    "rpi_online=%d,%d. Offline timeout.",
			    vpip->VPI,
			    emlxs_vpi_state_xlate(vpip->state),
			    fcfp->fcf_index,
			    vfip->VFI,
			    vpip->rpi_online, vpip->rpi_paused);
		}
	}

	vpip->flag &= ~EMLXS_VPI_PORT_UNBIND;

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_vpi_port_unbind_notify() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_rpi_offline_evt_action(emlxs_port_t *port, VPIobj_t *vpip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;
	RPIobj_t *rpip = (RPIobj_t *)arg1;

	if (evt != FCF_EVENT_RPI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_rpi_offline_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	switch (vpip->state) {
	case VPI_STATE_LOGO:
		/* rpi_online will be checked when LOGO is complete */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_offline_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. Waiting for LOGO. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 0;
		break;

	case VPI_STATE_PORT_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_offline_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d.",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	case VPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_offline_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. VPI paused. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 0;
		break;

	case VPI_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_offline_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 0;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_offline_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 1;
		break;
	}

	return (rval);

} /* emlxs_vpi_rpi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_rpi_pause_evt_action(emlxs_port_t *port, VPIobj_t *vpip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;
	RPIobj_t *rpip = (RPIobj_t *)arg1;

	if (evt != FCF_EVENT_RPI_PAUSE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_rpi_pause_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	switch (vpip->state) {
	case VPI_STATE_LOGO:
		/* rpi_online will be checked when LOGO is complete */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_pause_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. Waiting for LOGO. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 0;
		break;

	case VPI_STATE_PORT_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_pause_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d.",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_REENTER, 0, 0);
		break;

	case VPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_pause_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. VPI already paused. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 0;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_rpi_pause_evt_action:%d rpi_online=%d,%d did=%x "
		    "rpi=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->did, rpip->RPI);

		rval = 1;
		break;
	}

	return (rval);

} /* emlxs_vpi_rpi_pause_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_rpi_online_evt_action(emlxs_port_t *port, VPIobj_t *vpip,
    uint32_t evt, void *arg1)
{
	RPIobj_t *rpip = (RPIobj_t *)arg1;

	if (evt != FCF_EVENT_RPI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_rpi_online_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_rpi_online_evt_action:%d rpi_online=%d,%d did=%x rpi=%d. <",
	    vpip->VPI,
	    vpip->rpi_online, vpip->rpi_paused,
	    rpip->did, rpip->RPI);

	return (0);

} /* emlxs_vpi_rpi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_online_evt_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VPI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_online_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_ONLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_evt_action:%d flag=%x. "
		    "Online already requested. <",
		    vpip->VPI,
		    vpip->flag);
		return (1);
	}

	vpip->flag &= ~EMLXS_VPI_REQ_MASK;
	vpip->flag |= EMLXS_VPI_ONLINE_REQ;

	switch (vpip->state) {
	case VPI_STATE_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_evt_action:%d flag=%x. Initiating online.",
		    vpip->VPI,
		    vpip->flag);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_INIT,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case VPI_STATE_PORT_OFFLINE:
	case VPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_evt_action:%d flag=%x. Initiating online.",
		    vpip->VPI,
		    vpip->flag);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_evt_action:%d flag=%x. <",
		    vpip->VPI,
		    vpip->flag);
		return (1);
	}

	return (rval);

} /* emlxs_vpi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_offline_handler(emlxs_port_t *port, VPIobj_t *vpip, void *arg1)
{
	uint32_t rval = 0;

	if (!(vpip->flag & EMLXS_VPI_OFFLINE_REQ)) {
		return (0);
	}

	if (vpip->flag & EMLXS_VPI_PORT_ONLINE) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else if (vpip->flag & EMLXS_VPI_LOGI) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else if (vpip->flag & EMLXS_VPI_REG) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else if (vpip->flag & EMLXS_VPI_INIT) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG,
		    FCF_REASON_REQUESTED, 0, arg1);

	} else {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_OFFLINE,
		    FCF_REASON_REQUESTED, 0, arg1);
	}

	return (rval);

} /* emlxs_vpi_offline_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_offline_evt_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	uint32_t pause_req;

	if (evt != FCF_EVENT_VPI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_offline_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	if ((vpip->flag & EMLXS_VPI_OFFLINE_REQ) &&
	    !(vpip->flag & EMLXS_VPI_PAUSE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_evt_action:%d flag=%x. "
		    "Offline already requested. <",
		    vpip->VPI,
		    vpip->flag);
		return (1);
	}

	pause_req = vpip->flag & EMLXS_VPI_PAUSE_REQ;

	vpip->flag &= ~EMLXS_VPI_REQ_MASK;
	vpip->flag |= EMLXS_VPI_OFFLINE_REQ;

	switch (vpip->state) {
	case VPI_STATE_PORT_OFFLINE:
		if (pause_req || vpip->rpi_paused) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_offline_evt_action:%d flag=%x. Clear nodes.",
			    vpip->VPI,
			    vpip->flag);

			vpip->flag |= EMLXS_VPI_PORT_ONLINE;

			rval = emlxs_vpi_state(port, vpip,
			    VPI_STATE_PORT_OFFLINE, FCF_REASON_REENTER, evt,
			    arg1);

			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_evt_action:%d flag=%x. Handling offline.",
		    vpip->VPI,
		    vpip->flag);

		/* Handle offline now */
		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		break;

	case VPI_STATE_PAUSED:
		if (vpip->rpi_paused) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_offline_evt_action:%d flag=%x. Clear nodes.",
			    vpip->VPI,
			    vpip->flag);

			vpip->flag |= EMLXS_VPI_PORT_ONLINE;

			rval = emlxs_vpi_state(port, vpip,
			    VPI_STATE_PORT_OFFLINE, FCF_REASON_EVENT, evt,
			    arg1);

			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_evt_action:%d flag=%x. Handling offline.",
		    vpip->VPI,
		    vpip->flag);

		/* Handle offline now */
		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		break;

	/* wait states */
	case VPI_STATE_UNREG:
	case VPI_STATE_PORT_ONLINE:
	case VPI_STATE_LOGI:
	case VPI_STATE_INIT:
	case VPI_STATE_REG:
	case VPI_STATE_ONLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_evt_action:%d flag=%x. Handling offline.",
		    vpip->VPI,
		    vpip->flag);

		/* Handle offline now */
		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		break;

	/* Transitional states */
	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_evt_action:%d flag=%x. <",
		    vpip->VPI,
		    vpip->flag);
		break;
	}

	return (rval);

} /* emlxs_vpi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_pause_evt_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;

	if (evt != FCF_EVENT_VPI_PAUSE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_pause_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. "
		    "Pause already requested. <",
		    vpip->VPI,
		    vpip->flag);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. "
		    "Offline already requested. <",
		    vpip->VPI,
		    vpip->flag);
		return (1);
	}

	if (SLI4_FC_MODE || !(hba->sli.sli4.flag & EMLXS_SLI4_DOWN_LINK)) {
		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);
	}

	switch (vpip->state) {
	case VPI_STATE_PORT_OFFLINE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. "
		    "Already offline. <",
		    vpip->VPI,
		    vpip->flag);
		break;

	case VPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. "
		    "Already paused. <",
		    vpip->VPI,
		    vpip->flag);
		break;

	/* Wait states */
	case VPI_STATE_UNREG:
	case VPI_STATE_PORT_ONLINE:
	case VPI_STATE_LOGI:
	case VPI_STATE_INIT:
	case VPI_STATE_REG:
	case VPI_STATE_ONLINE:
		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= (EMLXS_VPI_OFFLINE_REQ | EMLXS_VPI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. Handling offline.",
		    vpip->VPI,
		    vpip->flag);

		/* Handle offline now */
		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		break;

	/* Transitional states */
	default:
		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= (EMLXS_VPI_OFFLINE_REQ | EMLXS_VPI_PAUSE_REQ);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_pause_evt_action:%d flag=%x. <",
		    vpip->VPI,
		    vpip->flag);
		break;
	}

	return (rval);

} /* emlxs_vpi_pause_evt_action() */


/* ARGSUSED */
static void
emlxs_deferred_cmpl_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	emlxs_deferred_cmpl_t *cmpl = (emlxs_deferred_cmpl_t *)arg1;
	uint32_t status = (uint32_t)((unsigned long)arg2);
	emlxs_port_t *port;
	uint32_t mbxStatus;
	emlxs_buf_t *sbp;
	fc_unsol_buf_t *ubp;
	IOCBQ *iocbq;

	mbxStatus = (status)? MBX_FAILURE:MBX_SUCCESS;

	port = cmpl->port;
	sbp = (emlxs_buf_t *)cmpl->arg1;
	ubp = (fc_unsol_buf_t *)cmpl->arg2;
	iocbq = (IOCBQ *)cmpl->arg3;

	kmem_free(cmpl, sizeof (emlxs_deferred_cmpl_t));

	emlxs_mb_deferred_cmpl(port, mbxStatus, sbp, ubp, iocbq);

	return;

} /* emlxs_deferred_cmpl_thread() */




/* ARGSUSED */
static void
emlxs_port_offline_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	emlxs_port_t *port = (emlxs_port_t *)arg1;
	uint32_t scope = (uint32_t)((unsigned long)arg2);

	(void) emlxs_port_offline(port, scope);
	return;

} /* emlxs_port_offline_thread() */


/* ARGSUSED */
static void
emlxs_port_online_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	emlxs_port_t *port = (emlxs_port_t *)arg1;

	(void) emlxs_port_online(port);
	return;

} /* emlxs_port_online_thread() */


/*ARGSUSED*/
static void
emlxs_vpi_logo_handler(emlxs_port_t *port, VPIobj_t *vpip)
{
	vpip->flag &= ~EMLXS_VPI_LOGI;
	if (vpip->flag & EMLXS_VPI_VFI_LOGI) {
		vpip->flag &= ~EMLXS_VPI_VFI_LOGI;

		if (vpip->vfip->logi_count) {
			vpip->vfip->logi_count--;
		}
		if (vpip == vpip->vfip->flogi_vpip) {
			vpip->vfip->flogi_vpip = NULL;
		}
	}

} /* emlxs_vpi_logo_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_port_offline_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;
	uint32_t scope;

	if (vpip->state != VPI_STATE_PORT_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_PORT_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_offline_action:%d flag=%x. Offlining port...",
		    vpip->VPI,
		    vpip->flag);

		vpip->flag &= ~(EMLXS_VPI_PORT_ONLINE|EMLXS_VPI_PORT_ENABLED);

		if (vpip->flag & EMLXS_VPI_PAUSE_REQ) {
			scope = 0xFFFFFFFF; /* Clear all non-FCP2 nodes */
					    /* Pause FCP2 nodes */
		} else {
			scope = 0xFDFFFFFF; /* Clear all nodes */
		}

		emlxs_thread_spawn(hba, emlxs_port_offline_thread,
		    (void *)vpip->port, (void *)((unsigned long)scope));

		if (vpip->flag & EMLXS_VPI_LOGI) {
			rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO,
			    FCF_REASON_EVENT, evt, arg1);

			return (rval);
		}
	}

	if (vpip->flag & EMLXS_VPI_PAUSE_REQ) {
		if (vpip->rpi_online > vpip->rpi_paused) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_port_offline_action:%d rpi_online=%d,%d. "
			    "Pausing. Waiting for RPI's. <",
			    vpip->VPI,
			    vpip->rpi_online, vpip->rpi_paused);
			return (0);
		}

		/* Take the Fabric RPI offline now */
		if (vpip->fabric_rpip->state != RPI_STATE_FREE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_port_offline_action:%d. "
			    "Offlining Fabric RPI. >",
			    vpip->VPI);

			(void) emlxs_rpi_event(port, FCF_EVENT_RPI_OFFLINE,
			    vpip->fabric_rpip);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_offline_action:%d rpi_online=%d,%d. Pausing.",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PAUSED,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (vpip->rpi_online > 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_offline_action:%d rpi_online=%d,%d. Offlining. "
		    "Waiting for RPI's. <",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused);

		return (0);
	}

	/* Take the Fabric RPI offline now */
	if (vpip->fabric_rpip->state != RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_offline_action:%d. Offlining Fabric RPI. >",
		    vpip->VPI);

		(void) emlxs_rpi_event(port, FCF_EVENT_RPI_OFFLINE,
		    vpip->fabric_rpip);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_port_offline_action:%d rpi_online=%d,%d. Offlining. "
	    "Unreg VPI.",
	    vpip->VPI,
	    vpip->rpi_online, vpip->rpi_paused);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_port_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_paused_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	if (vpip->state != VPI_STATE_PAUSED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_paused_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	vpip->flag &= ~(EMLXS_VPI_OFFLINE_REQ | EMLXS_VPI_PAUSE_REQ);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_paused_action:%d rpi_online=%d,%d. VPI paused. <",
	    vpip->VPI,
	    vpip->rpi_online, vpip->rpi_paused);

	return (0);

} /* emlxs_vpi_paused_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_offline_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!vpip->vfip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_action:%d %s:%s arg=%p flag=%x. "
		    "Null vfip found. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->flag);
		return (1);
	}

	/* Take the Fabric RPI offline, if still active */
	if (vpip->fabric_rpip->state != RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_action:%d. Offlining Fabric RPI. >",
		    vpip->VPI);

		(void) emlxs_rpi_event(port, FCF_EVENT_RPI_OFFLINE,
		    vpip->fabric_rpip);
	}

	vpip->flag &= ~(EMLXS_VPI_OFFLINE_REQ | EMLXS_VPI_PAUSE_REQ);

	if (vpip->flag & EMLXS_VPI_VFI) {
		vpip->flag &= ~EMLXS_VPI_VFI;

		if (vpip->vfip->vpi_online) {
			vpip->vfip->vpi_online--;
		}
	}

	/* Check if online was requested */
	if (vpip->flag & EMLXS_VPI_ONLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_offline_action:%d vpi_online=%d. Online requested.",
		    vpip->VPI,
		    vpip->vfip->vpi_online);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_INIT,
		    FCF_REASON_REQUESTED, 0, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_offline_action:%d vpi_online=%d. "
	    "VPI offline. Notifying VFI:%d. >",
	    vpip->VPI,
	    vpip->vfip->vpi_online,
	    vpip->vfip->VFI);

	/* Notify VFI */
	rval = emlxs_vfi_event(port, FCF_EVENT_VPI_OFFLINE, vpip);

	return (rval);

} /* emlxs_vpi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_init_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	VPIobj_t *vpip;
	MAILBOX4 *mb4;

	vpip = (VPIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state != VPI_STATE_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_mbcmpl:%d %s.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_mbcmpl:%d failed. %s. >",
		    vpip->VPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_vpi_state(port, vpip, VPI_STATE_INIT_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_init_mbcmpl:%d. Init complete. >",
	    vpip->VPI,
	    mb4->mbxStatus);

	vpip->flag |= EMLXS_VPI_INIT;
	(void) emlxs_vpi_state(port, vpip, VPI_STATE_INIT_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vpi_init_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_init_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX4 *mb4;
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->prev_state != VPI_STATE_INIT_FAILED) {
		vpip->attempts = 0;
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d attempts=%d. Offline requested.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		return (rval);
	}

	if (!(vpip->flag & EMLXS_VPI_VFI)) {
		vpip->flag |= EMLXS_VPI_VFI;
		vpip->vfip->vpi_online++;
	}

	if (((hba->sli_intf & SLI_INTF_IF_TYPE_MASK) ==
	    SLI_INTF_IF_TYPE_0) && (vpip->vfip->vpi_online == 1)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d. First VPI. Skipping INIT_VPI.",
		    vpip->VPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (vpip->flag & EMLXS_VPI_INIT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d flag=%x. "
		    "Already init'd. Skipping INIT_VPI.",
		    vpip->VPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_init_action:%d vpi_online=%d attempts=%d. Sending INIT_VPI. <",
	    vpip->VPI,
	    vpip->vfip->vpi_online,
	    vpip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vpi_state(port, vpip, FCFI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);
		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_vpi_init_mbcmpl;
	mbq->context = (void *)vpip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_INIT_VPI;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varInitVPI4.vfi = vpip->vfip->VFI;
	mb4->un.varInitVPI4.vpi = vpip->VPI;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_INIT_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vpi_init_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_init_failed_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vpip->attempts++;

	if (vpip->state != VPI_STATE_INIT_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_init_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->attempts);
		return (1);
	}

	if ((vpip->reason == FCF_REASON_SEND_FAILED) ||
	    (vpip->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d attempt=%d reason=%x. Init cmpl.",
		    vpip->VPI,
		    vpip->attempts,
		    vpip->reason);

		vpip->flag &= ~(EMLXS_VPI_REG | EMLXS_VPI_INIT);

		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_INIT_CMPL,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_action:%d attempt=%d. Initializing.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_INIT,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vpi_init_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_init_cmpl_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_INIT_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_init_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_init_cmpl_action:%d attempts=%d. Onlining port.",
	    vpip->VPI,
	    vpip->attempts);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);
	return (rval);

} /* emlxs_vpi_init_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_port_online_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_PORT_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_PORT_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_online_action:%d. Port already online.",
		    vpip->VPI);
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_online_action:%d. Offline requested.",
		    vpip->VPI);

		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		return (rval);
	}

	/* Initialize the Fabric RPI */
	if (vpip->fabric_rpip->state == RPI_STATE_FREE) {
		emlxs_rpi_alloc_fabric_rpi(vpip->port);
	}

	/* Notify ULP */
	vpip->flag |= EMLXS_VPI_PORT_ONLINE;

	if (hba->flag & FC_LOOPBACK_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_port_online_action:%d. Loopback mode. "
		    "Registering VPI.",
		    vpip->VPI);

		if (hba->topology != TOPOLOGY_LOOP) {
			port->did = 1;
		}

		vpip->vfip->flogi_vpip = vpip;

		bcopy((void *)&vpip->port->sparam,
		    (void *)&vpip->fabric_rpip->sparam,
		    sizeof (SERV_PARM));

		/* Update the VPI Fabric RPI */
		vpip->fabric_rpip->sparam.cmn.w2.r_a_tov =
		    LE_SWAP32((FF_DEF_RATOV * 1000));

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if ((hba->topology == TOPOLOGY_LOOP) && ! (port->did)) {
		port->did = port->granted_alpa;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_port_online_action:%d vpi_online=%d. Onlining port... <",
	    vpip->VPI,
	    vpip->vfip->vpi_online);

	if (SLI4_FC_MODE && (port->vpi == 0)) {
		mutex_enter(&EMLXS_PORT_LOCK);
		hba->linkup_timer = hba->timer_tics +
		    cfg[CFG_LINKUP_TIMEOUT].current;
		mutex_exit(&EMLXS_PORT_LOCK);
	} else {
		emlxs_thread_spawn(hba, emlxs_port_online_thread,
		    (void *)vpip->port, 0);
	}

	/* Wait for emlxs_vpi_logi_notify() */

	return (0);

} /* emlxs_vpi_port_online_action() */


extern uint32_t
emlxs_vpi_logi_notify(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	VPIobj_t *vpip = port->vpip;
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state == VPI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_notify:%d %s.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);

		return (1);
	}

	if (vpip->state != VPI_STATE_PORT_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logi_notify:%d %s. "
		    "Invalid state.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);

		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logi_notify:%d %s. "
	    "Logging in. >",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state));

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGI,
	    0, 0, sbp);

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_notify:%d %s rval=%d.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    rval);
	}

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_vpi_logi_notify() */


static uint32_t
emlxs_vpi_logi_cmpl_notify(emlxs_port_t *port, RPIobj_t *rpip)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t *vpip = port->vpip;
	uint32_t rval = 0;

	/* EMLXS_FCF_LOCK must be held when calling this routine */

	if (vpip->state != VPI_STATE_LOGI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logi_cmpl_notify:%d %s. "
		    "Invalid state.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));
		return (1);
	}

	if (rpip->RPI == FABRIC_RPI) {
		if (hba->flag & FC_PT_TO_PT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_logi_cmpl_notify:%d %s. P2P mode. "
			    "Completing FLOGI.",
			    vpip->VPI,
			    emlxs_vpi_state_xlate(vpip->state));

			/* Complete the FLOGI/FDISC now */
			if (rpip->cmpl) {
				emlxs_rpi_deferred_cmpl(port, rpip, 0);
			}

			/* Wait for P2P PLOGI completion to continue */
			return (0);
		}

		if (!rpip->cmpl || !rpip->cmpl->arg1) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
			    "vpi_logi_cmpl_notify:%d. Null sbp.",
			    vpip->VPI);
			return (1);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_cmpl_notify:%d %s. Fabric mode. "
		    "Completing login. >",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGI_CMPL,
		    0, 0, 0);

		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_logi_cmpl_notify:%d %s rval=%d.",
			    vpip->VPI,
			    emlxs_vpi_state_xlate(vpip->state),
			    rval);
		}

		return (rval);
	}

	if (hba->flag & FC_PT_TO_PT) {
		if (port->did == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_logi_cmpl_notify:%d %s did=0. P2P mode. "
			    "Wait for PLOGI compl.",
			    vpip->VPI,
			    emlxs_vpi_state_xlate(vpip->state));

			if (rpip->cmpl) {
				emlxs_rpi_deferred_cmpl(port, rpip, 0);
			}

			/* Wait for P2P PLOGI completion to continue */
			return (0);
		}

		vpip->p2p_rpip = rpip;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_cmpl_notify:%d %s. P2P mode. "
		    "Completing login. >",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGI_CMPL,
		    0, 0, 0);

		if (rval) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_logi_cmpl_notify:%d %s rval=%d.",
			    vpip->VPI,
			    emlxs_vpi_state_xlate(vpip->state),
			    rval);
		}

		return (rval);
	}

	return (1);

} /* emlxs_vpi_logi_cmpl_notify() */


extern uint32_t
emlxs_vpi_logi_failed_notify(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t *vpip = port->vpip;
	RPIobj_t *rpip = vpip->fabric_rpip;
	uint32_t rval = 0;
	emlxs_deferred_cmpl_t *cmpl;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state != VPI_STATE_LOGI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_failed_notify:%d %s. "
		    "Invalid state.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);

		mutex_exit(&EMLXS_FCF_LOCK);

		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logi_failed_notify:%d %s. "
	    "Failing login. >",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state));

	/* For safety */
	if (rpip->cmpl) {
		emlxs_rpi_deferred_cmpl(port, rpip, 1);
	}

	if (sbp) {
		cmpl = (emlxs_deferred_cmpl_t *)kmem_zalloc(
		    sizeof (emlxs_deferred_cmpl_t), KM_SLEEP);

		cmpl->port = port;
		cmpl->arg1 = (void *)sbp;
		cmpl->arg2 = 0;
		cmpl->arg3 = 0;

		rpip->cmpl = cmpl;
	}

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGI_FAILED,
	    FCF_REASON_OP_FAILED, 1, 0);

	if (rval && rpip->cmpl) {
		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;
	}

	mutex_exit(&EMLXS_FCF_LOCK);
	return (rval);

} /* emlxs_vpi_logi_failed_notify() */


extern uint32_t
emlxs_vpi_logo_cmpl_notify(emlxs_port_t *port)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t *vpip = port->vpip;
	uint32_t rval = 0;
	VFIobj_t *vfip;
	FCFIobj_t *fcfp;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	/* Fabric logo is complete */
	emlxs_vpi_logo_handler(port, vpip);

	if ((vpip->state == VPI_STATE_OFFLINE) ||
	    (vpip->flag & EMLXS_VPI_OFFLINE_REQ)) {
		/* Already offline. Do nothing */
		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	vfip = vpip->vfip;
	fcfp = vfip->fcfp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logo_cmpl_notify:%d %s fcfi:%d vfi:%d. "
	    "Offlining VPI:%d,%d >",
	    vpip->VPI,
	    emlxs_vpi_state_xlate(vpip->state),
	    fcfp->fcf_index,
	    vfip->VFI,
	    vpip->index, vpip->VPI);

	rval = emlxs_vpi_event(port, FCF_EVENT_VPI_OFFLINE, vpip);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_vpi_logo_cmpl_notify() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logi_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp = (emlxs_buf_t *)arg1;
	fc_packet_t *pkt = PRIV2PKT(sbp);
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_LOGI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_action:%d. Offline requested.",
		    vpip->VPI);

		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		return (rval);
	}

	if (vpip->flag & EMLXS_VPI_LOGI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logi_action:%d flag=%x. LOGI already set.",
		    vpip->VPI, vpip->flag);

		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);
	}

	/* Check if FC_PT_TO_PT is set */
	if (hba->flag & FC_PT_TO_PT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_action:%d logi_count=%d. FLOGI set. P2P. <",
		    vpip->VPI,
		    vpip->vfip->logi_count);

		*((uint32_t *)pkt->pkt_cmd) = (uint32_t)ELS_CMD_FLOGI;

		vpip->vfip->flogi_vpip = vpip;

		if (vpip->vfip->logi_count == 0) {
			vpip->vfip->logi_count++;
			vpip->flag |= EMLXS_VPI_VFI_LOGI;
		}

		return (0);
	}

	/* Set login command based on vfi logi_count */
	if (vpip->vfip->logi_count == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_action:%d logi_count=%d. FLOGI set. <",
		    vpip->VPI,
		    vpip->vfip->logi_count);

		*((uint32_t *)pkt->pkt_cmd) = (uint32_t)ELS_CMD_FLOGI;

		vpip->vfip->flogi_vpip = vpip;
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_action:%d logi_count=%d. FDISC set. <",
		    vpip->VPI,
		    vpip->vfip->logi_count);

		*((uint32_t *)pkt->pkt_cmd) = (uint32_t)ELS_CMD_FDISC;
	}

	vpip->vfip->logi_count++;
	vpip->flag |= EMLXS_VPI_VFI_LOGI;

	return (0);

} /* emlxs_vpi_logi_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logi_failed_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_LOGI_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_failed_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	/* Fabric logo is implied */
	emlxs_vpi_logo_handler(port, vpip);

	if (hba->topology == TOPOLOGY_LOOP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_failed_action:%d. Private loop. "
		    "Registering VPI.",
		    vpip->VPI);

		/* Update the VPI flogi_vpip pointer for loop */
		/* because the vpi_logo_handler cleared it */
		vpip->vfip->flogi_vpip = vpip;

		bcopy((void *)&vpip->port->sparam,
		    (void *)&vpip->fabric_rpip->sparam,
		    sizeof (SERV_PARM));

		/* Update the VPI Fabric RPI */
		vpip->fabric_rpip->sparam.cmn.w2.r_a_tov =
		    LE_SWAP32((FF_DEF_RATOV * 1000));

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logi_failed_action:%d. Requesting offline.",
	    vpip->VPI);

	vpip->flag &= ~EMLXS_VPI_REQ_MASK;
	vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
	rval = emlxs_vpi_offline_handler(port, vpip, arg1);

	return (rval);

} /* emlxs_vpi_logi_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logi_cmpl_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;
	char buffer1[64];
	char buffer2[64];
	uint32_t new_config = 0;

	if (vpip->state != VPI_STATE_LOGI_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	vpip->flag |= EMLXS_VPI_LOGI;

	/* Check for new fabric */
	if (port->prev_did) {
		if (SLI4_FCOE_MODE) {
			/* Check for FCF change */
			if (((port->prev_did != port->did) ||
			    bcmp(&port->prev_fabric_sparam.portName,
			    &port->fabric_sparam.portName, 8)) &&
			    emlxs_nport_count(port)) {
				new_config = 1;
			}
		} else {
			uint32_t old_topo;
			uint32_t new_topo;

			/* Check for topology change (0=loop 1=fabric) */
			old_topo = ((port->prev_did && 0xFFFF00) == 0)? 0:1;
			new_topo = ((port->did && 0xFFFF00) == 0)? 0:1;

			if (old_topo != new_topo) {
				new_config = 1;

			/* Check for any switch change */
			} else if ((port->prev_did != port->did) ||
			    bcmp(&port->prev_fabric_sparam.portName,
			    &port->fabric_sparam.portName, 8)) {
				new_config = 1;
			}
		}
	}

	if (new_config) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_cmpl_action:%d. "
		    "New config. Offlining port.",
		    vpip->VPI);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logi_cmpl_action: prev_wwpn=%s wwpn=%s prev_did=%x "
		    "did=%x.",
		    emlxs_wwn_xlate(buffer1, sizeof (buffer1),
		    (uint8_t *)&port->prev_fabric_sparam.portName),
		    emlxs_wwn_xlate(buffer2, sizeof (buffer2),
		    (uint8_t *)&port->fabric_sparam.portName),
		    port->prev_did, port->did);

		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		rval = emlxs_vpi_offline_handler(port, vpip, arg1);

		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logi_cmpl_action:%d. Registering.",
	    vpip->VPI);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_logi_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logo_failed_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;

	vpip->attempts++;

	if (vpip->state != VPI_STATE_LOGO_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logo_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->attempts);
		return (1);
	}

	if (hba->state <= FC_LINK_DOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_failed_action:%d attempt=%d. Logo cmpl.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO_CMPL,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	} else if (vpip->attempts >= 3) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_failed_action:%d attempt=%d. Logo cmpl.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO_CMPL,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_failed_action:%d attempt=%d. Logging out.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vpi_logo_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logo_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_t *vport = vpip->port;
	uint32_t rval = 0;
	uint32_t did;
	uint32_t sid;
	fc_packet_t *pkt;
	ELS_PKT *els;

	if (vpip->state != VPI_STATE_LOGO) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logo_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(vpip->flag & EMLXS_VPI_LOGI)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_action:%d. No login. Skipping LOGO.",
		    vpip->VPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (!(hba->flag & FC_ONLINE_MODE) &&
	    !(hba->flag & FC_OFFLINING_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_action:%d. HBA offline. Skipping LOGO.",
		    vpip->VPI);

		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (SLI4_FC_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_logo_action:%d. FC mode. Skipping LOGO.",
		    vpip->VPI);

		/* Fabric logo is implied */
		emlxs_vpi_logo_handler(port, vpip);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (vpip->prev_state != VPI_STATE_LOGO_FAILED) {
		vpip->attempts = 0;
	}

	did = FABRIC_DID;
	sid = (vport->did)? vport->did:vport->prev_did;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logo_action:%d attempts=%d sid=%x did=%x. Sending LOGO. <",
	    vpip->VPI,
	    vpip->attempts,
	    sid, did);

	pkt = emlxs_pkt_alloc(vport,
	    (sizeof (uint32_t) + sizeof (LOGO)),
	    (sizeof (uint32_t) + sizeof (LOGO)), 0, KM_NOSLEEP);

	if (!pkt) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO_FAILED,
		    FCF_REASON_NO_PKT, 0, arg1);

		return (rval);
	}

	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = (2 * hba->fc_ratov);

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(did);
	pkt->pkt_cmd_fhdr.r_ctl =
	    R_CTL_EXTENDED_SVC | R_CTL_SOLICITED_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(sid);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;

	/* Build the command */
	els = (ELS_PKT *)pkt->pkt_cmd;
	els->elsCode = 0x05;
	els->un.logo.un.nPortId32 = pkt->pkt_cmd_fhdr.s_id;
	bcopy((uint8_t *)&vport->wwpn,
	    (uint8_t *)&els->un.logo.portName, 8);

	/* Send the pkt now */
	rval = emlxs_pkt_send(pkt, 0);
	if (rval != FC_SUCCESS) {
		/* Free the pkt */
		emlxs_pkt_free(pkt);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	/* For now we will send and forget */
	rval = emlxs_vpi_state(port, vpip, VPI_STATE_LOGO_CMPL,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_logo_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_logo_cmpl_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_LOGO_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_logo_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	/* Fabric logo is complete */
	emlxs_vpi_logo_handler(port, vpip);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_logo_cmpl_action:%d attempts=%d. Offline RPI's.",
	    vpip->VPI,
	    vpip->attempts);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_logo_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_unreg_failed_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vpip->attempts++;

	if (vpip->state != VPI_STATE_UNREG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_unreg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->attempts);
		return (1);
	}

	if ((vpip->reason == FCF_REASON_SEND_FAILED) ||
	    (vpip->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_failed_action:%d attempt=%d. Unreg cmpl.",
		    vpip->VPI,
		    vpip->attempts);

		vpip->flag &= ~(EMLXS_VPI_REG | EMLXS_VPI_INIT);

		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG_CMPL,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_failed_action:%d attempt=%d. Unregistering.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vpi_unreg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_unreg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	VPIobj_t *vpip;

	vpip = (VPIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state != VPI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_mbcmpl:%d state=%s.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_mbcmpl:%d failed. %s. >",
		    vpip->VPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_vpi_state(port, vpip, VPI_STATE_UNREG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, (void *)mbq->sbp);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_unreg_mbcmpl:%d. Unreg complete. >",
	    vpip->VPI);

	vpip->flag &= ~(EMLXS_VPI_REG | EMLXS_VPI_INIT);
	(void) emlxs_vpi_state(port, vpip, VPI_STATE_UNREG_CMPL, 0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vpi_unreg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_unreg_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_unreg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if ((vpip->rpi_online > vpip->rpi_paused) ||
	    (vpip->fabric_rpip->state != RPI_STATE_FREE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_action:%d rpi_online=%d,%d fstate=%x. "
		    "Waiting for RPI's.", vpip->VPI, vpip->rpi_online,
		    vpip->rpi_paused, vpip->fabric_rpip->state);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PORT_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (!(vpip->flag & EMLXS_VPI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_action:%d. Not registered. Skipping UNREG_VPI.",
		    vpip->VPI);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (vpip->flag & EMLXS_VPI_PAUSE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_unreg_action:%d rpi_online=%d,%d. Pausing.",
		    vpip->VPI,
		    vpip->rpi_online, vpip->rpi_paused);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_PAUSED,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (vpip->prev_state != VPI_STATE_UNREG_FAILED) {
		vpip->attempts = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_unreg_action:%d attempts=%d. Sending UNREG_VPI. <",
	    vpip->VPI,
	    vpip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_vpi_unreg_mbcmpl;
	mbq->context = (void *)vpip;
	mbq->port = (void *)vpip->port;

	mb4->un.varUnRegVPI4.ii = 0; /* index is a VPI */
	mb4->un.varUnRegVPI4.index = vpip->VPI;
	mb4->mbxCommand = MBX_UNREG_VPI;
	mb4->mbxOwner = OWN_HOST;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_UNREG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vpi_unreg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_unreg_cmpl_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_UNREG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_unreg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_unreg_cmpl_action:%d attempts=%d. Going offline.",
	    vpip->VPI,
	    vpip->attempts);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_OFFLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_unreg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_reg_failed_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	vpip->attempts++;

	if (vpip->state != VPI_STATE_REG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_reg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    vpip->attempts);
		return (1);
	}

	if ((vpip->reason == FCF_REASON_SEND_FAILED) ||
	    (vpip->attempts >= 3)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_failed_action:%d attempt=%d reason=%x. Reg cmpl.",
		    vpip->VPI,
		    vpip->attempts,
		    vpip->reason);

		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG_CMPL,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_failed_action:%d attempt=%d. Registering.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG,
		    FCF_REASON_OP_FAILED, vpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_vpi_reg_failed_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_reg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	VPIobj_t *vpip;

	vpip = (VPIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	mutex_enter(&EMLXS_FCF_LOCK);

	if (vpip->state != VPI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_mbcmpl:%d state=%s.",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_mbcmpl:%d failed. %s. >",
		    vpip->VPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		if (mb4->mbxStatus == MBXERR_DID_INCONSISTENT) {
			vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		}

		(void) emlxs_vpi_state(port, vpip, VPI_STATE_REG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_reg_mbcmpl:%d. Reg complete. >",
	    vpip->VPI);

	vpip->flag |= EMLXS_VPI_REG;
	(void) emlxs_vpi_state(port, vpip, VPI_STATE_REG_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_vpi_reg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_reg_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t *wwpn;
	MAILBOX *mb;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_reg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->prev_state != VPI_STATE_REG_FAILED) {
		vpip->attempts = 0;
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_action:%d attempts=%d. Offline requested.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_offline_handler(port, vpip, 0);
		return (rval);
	}

	if (!(vpip->vfip->flag & EMLXS_VFI_REG)) {
		/* We can't register the VPI until our VFI is registered */

		/* If this is the flogi_vpip, then we can skip the REG_VPI. */
		/* REG_VPI will be performed later during REG_VFI */
		if (vpip == vpip->vfip->flogi_vpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "vpi_reg_action:%d. flogi_vpi. Skipping REG_VPI.",
			    vpip->VPI);

			rval = emlxs_vpi_state(port, vpip, VPI_STATE_ONLINE,
			    FCF_REASON_EVENT, evt, arg1);

			return (rval);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_action:%d attempts=%d. VFI not registered. "
		    "Offlining.",
		    vpip->VPI,
		    vpip->attempts);

		vpip->flag &= ~EMLXS_VPI_REQ_MASK;
		vpip->flag |= EMLXS_VPI_OFFLINE_REQ;
		rval = emlxs_vpi_offline_handler(port, vpip, 0);
		return (rval);
	}

	if (vpip->flag & EMLXS_VPI_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_action:%d attempts=%d. Updating REG_VPI. <",
		    vpip->VPI,
		    vpip->attempts);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_action:%d attempts=%d. Sending REG_VPI. <",
		    vpip->VPI,
		    vpip->attempts);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb = (MAILBOX*)mbq;
	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_vpi_reg_mbcmpl;
	mbq->context = (void *)vpip;
	mbq->port = (void *)vpip->port;

	mb->un.varRegVpi.vfi = vpip->vfip->VFI;
	mb->un.varRegVpi.upd = (vpip->flag & EMLXS_VPI_REG)? 1:0;

	wwpn = (uint32_t *)&port->wwpn;
	mb->un.varRegVpi.portname[0] = BE_SWAP32(*wwpn);
	wwpn++;
	mb->un.varRegVpi.portname[1] = BE_SWAP32(*wwpn);

	mb->un.varRegVpi.vpi = vpip->VPI;
	mb->un.varRegVpi.sid = vpip->port->did;
	mb->mbxCommand = MBX_REG_VPI;
	mb->mbxOwner = OWN_HOST;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_vpi_state(port, vpip, VPI_STATE_REG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	return (0);

} /* emlxs_vpi_reg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_reg_cmpl_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_REG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "vpi_reg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_reg_cmpl_action:%d attempts=%d. Offline requested.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_reg_cmpl_action:%d attempts=%d. Going online.",
	    vpip->VPI,
	    vpip->attempts);

	rval = emlxs_vpi_state(port, vpip, VPI_STATE_ONLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_vpi_reg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_vpi_online_action(emlxs_port_t *port, VPIobj_t *vpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (vpip->state != VPI_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    vpip->VPI,
		    emlxs_vpi_state_xlate(vpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	vpip->flag &= ~EMLXS_VPI_ONLINE_REQ;

	if (vpip->flag & EMLXS_VPI_OFFLINE_REQ) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "vpi_online_action:%d attempts=%d. Offline requested.",
		    vpip->VPI,
		    vpip->attempts);

		rval = emlxs_vpi_offline_handler(port, vpip, arg1);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "vpi_online_action:%d. VPI online. Notifying VFI:%d >",
	    vpip->VPI,
	    vpip->vfip->VFI);

	/* Notify VFI */
	rval = emlxs_vfi_event(port, FCF_EVENT_VPI_ONLINE, vpip);

	return (rval);

} /* emlxs_vpi_online_action() */


/* ************************************************************************** */
/* RPI */
/* ************************************************************************** */

static char *
emlxs_rpi_state_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_rpi_state_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_rpi_state_table[i].code) {
			return (emlxs_rpi_state_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_rpi_state_xlate() */


static uint32_t
emlxs_rpi_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	uint32_t(*func) (emlxs_port_t *, RPIobj_t *, uint32_t, void *);
	uint32_t index;
	uint32_t events;
	uint16_t state;

	/* Convert event to action table index */
	switch (evt) {
	case FCF_EVENT_STATE_ENTER:
		index = 0;
		break;
	case FCF_EVENT_RPI_ONLINE:
		index = 1;
		break;
	case FCF_EVENT_RPI_OFFLINE:
		index = 2;
		break;
	case FCF_EVENT_RPI_PAUSE:
		index = 3;
		break;
	case FCF_EVENT_RPI_RESUME:
		index = 4;
		break;
	default:
		return (1);
	}

	events = RPI_ACTION_EVENTS;
	state  = rpip->state;

	index += (state * events);
	func   = (uint32_t(*) (emlxs_port_t *, RPIobj_t *, uint32_t, void *))
	    emlxs_rpi_action_table[index];

	if (!func) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
		    "rpi_action:%d %s:%s arg=%p. No action. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);

		return (1);
	}

	rval = (func)(port, rpip, evt, arg1);

	return (rval);

} /* emlxs_rpi_action() */


static uint32_t
emlxs_rpi_event(emlxs_port_t *port, uint32_t evt,
    void *arg1)
{
	RPIobj_t *rpip = NULL;
	uint32_t rval = 0;

	/* Filter events and acquire fcfi context */
	switch (evt) {
	case FCF_EVENT_RPI_ONLINE:
	case FCF_EVENT_RPI_OFFLINE:
	case FCF_EVENT_RPI_PAUSE:
	case FCF_EVENT_RPI_RESUME:
		rpip = (RPIobj_t *)arg1;

		if (!rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
			    "rpi_event: %s arg=%p. Null RPI found. <",
			    emlxs_fcf_event_xlate(evt), arg1);

			return (1);
		}

		break;

	default:
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_event_msg,
	    "rpi_event:%d %s:%s arg=%p",
	    rpip->RPI,
	    emlxs_rpi_state_xlate(rpip->state),
	    emlxs_fcf_event_xlate(evt), arg1);

	rval = emlxs_rpi_action(port, rpip, evt, arg1);

	return (rval);

} /* emlxs_rpi_event() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_state(emlxs_port_t *port, RPIobj_t *rpip, uint16_t state,
    uint16_t reason, uint32_t explain, void *arg1)
{
	uint32_t rval = 0;

	if (state >= RPI_ACTION_STATES) {
		return (1);
	}

	if ((rpip->state == state) &&
	    (reason != FCF_REASON_REENTER)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_state:%d %s:%s:0x%x arg=%p. State not changed. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
		return (1);
	}

	if (!reason) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "rpi_state:%d %s-->%s arg=%p",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_rpi_state_xlate(state), arg1);
	} else if (reason == FCF_REASON_EVENT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "rpi_state:%d %s-->%s:%s:%s arg=%p",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_rpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    emlxs_fcf_event_xlate(explain), arg1);
	} else if (explain) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "rpi_state:%d %s-->%s:%s:0x%x arg=%p",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_rpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason),
		    explain, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_state_msg,
		    "rpi_state:%d %s-->%s:%s arg=%p",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_rpi_state_xlate(state),
		    emlxs_fcf_reason_xlate(reason), arg1);
	}

	rpip->prev_state = rpip->state;
	rpip->prev_reason = rpip->reason;
	rpip->state = state;
	rpip->reason = reason;

	rval = emlxs_rpi_action(port, rpip, FCF_EVENT_STATE_ENTER, arg1);

	return (rval);

} /* emlxs_rpi_state() */


static void
emlxs_rpi_deferred_cmpl(emlxs_port_t *port, RPIobj_t *rpip, uint32_t status)
{
	emlxs_hba_t *hba = HBA;
	emlxs_deferred_cmpl_t *cmpl;

	if (!rpip->cmpl) {
		return;
	}

	cmpl = rpip->cmpl;
	rpip->cmpl = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_deferred_cmpl:%d. status=%x ...",
	    port->vpip->VPI,
	    status);

	emlxs_thread_spawn(hba, emlxs_deferred_cmpl_thread, (void *)cmpl,
	    (void*)(uintptr_t)status);

	return;

} /* emlxs_rpi_deferred_cmpl() */


static void
emlxs_rpi_idle_timer(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	RPIobj_t *rpip;
	uint32_t i;

	/* This timer monitors for idle timeout of an RPI in a */
	/* RESERVED state. */
	/* This means that the RPI was reserved, but never registered. */
	/* If the RPI sits for too long (~2 secs) in this state we free it */
	rpip = hba->sli.sli4.RPIp;
	for (i = 0; i < hba->sli.sli4.RPICount; i++, rpip++) {
		if (rpip->state != RPI_STATE_RESERVED) {
			continue;
		}

		/* If RPI is active, then clear timer. */
		if (rpip->xri_count) {
			rpip->idle_timer = 0;
			continue;
		}

		/* If an F-port RPI is found idle, then free it. */
		/* Since an F-port RPI is never registered after the login */
		/* completes, it is safe to free it immediately. */
		if ((rpip->did == FABRIC_DID) ||
		    (rpip->did == SCR_DID)) {
			goto free_it;
		}

		/* Start idle timer if not already active */
		if (!rpip->idle_timer) {
			rpip->idle_timer = hba->timer_tics +
			    cfg[CFG_FCF_RPI_IDLE_TIMEOUT].current;
		}

		/* Check for idle timeout */
		if (hba->timer_tics < rpip->idle_timer) {
			continue;
		}
		rpip->idle_timer = 0;

free_it:
		(void) emlxs_rpi_state(rpip->vpip->port, rpip, RPI_STATE_FREE,
		    FCF_REASON_UNUSED, 0, 0);
	}

	return;

}  /* emlxs_rpi_idle_timer() */


static RPIobj_t *
emlxs_rpi_alloc(emlxs_port_t *port, uint32_t did)
{
	emlxs_hba_t *hba = HBA;
	uint16_t	i;
	RPIobj_t	*rpip;

	rpip = hba->sli.sli4.RPIp;
	for (i = 0; i < hba->sli.sli4.RPICount; i++, rpip++) {
		/* To be consistent with SLI3, the RPI assignment */
		/* starts with 1. ONLY one SLI4 HBA in the entire */
		/* system will be sacrificed by one RPI and that  */
		/* is the one having RPI base equal 0. */
		if ((rpip->state == RPI_STATE_FREE) && (rpip->RPI != 0)) {

			bzero(rpip, sizeof (RPIobj_t));
			rpip->index = i;
			rpip->RPI = emlxs_sli4_index_to_rpi(hba, i);
			rpip->vpip = port->vpip;
			rpip->did = did;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_alloc:%d. RPI allocated. >",
			    rpip->RPI);

			(void) emlxs_rpi_state(port, rpip, RPI_STATE_RESERVED,
			    0, 0, 0);

			return (rpip);
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_alloc: Out of RPI objects.");

	return (NULL);

} /* emlxs_rpi_alloc() */


/* Special routine for VPI object */
static void
emlxs_rpi_alloc_fabric_rpi(emlxs_port_t *port)
{
	RPIobj_t	*fabric_rpip;

	fabric_rpip = port->vpip->fabric_rpip;

	if (fabric_rpip->state != RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_alloc_fabric_rpi: Fabric RPI active:%s.",
		    emlxs_rpi_state_xlate(fabric_rpip->state));
		return;
	}

	bzero(fabric_rpip, sizeof (RPIobj_t));
	fabric_rpip->index = 0xffff;
	fabric_rpip->RPI = FABRIC_RPI;
	fabric_rpip->did = FABRIC_DID;
	fabric_rpip->vpip = port->vpip;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_alloc_fabric_rpi: Allocating Fabric RPI. >");

	(void) emlxs_rpi_state(port, fabric_rpip, RPI_STATE_RESERVED,
	    0, 0, 0);

	return;

} /* emlxs_rpi_alloc_fabric_rpi() */


static uint32_t
emlxs_rpi_free(emlxs_port_t *port, RPIobj_t *rpip)
{
	uint32_t rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_free:%d did=%x. Freeing RPI. >",
	    rpip->RPI, rpip->did);

	rval = emlxs_rpi_state(port, rpip, RPI_STATE_FREE, 0, 0, 0);

	return (rval);

} /* emlxs_rpi_free() */


extern RPIobj_t *
emlxs_rpi_find(emlxs_port_t *port, uint16_t rpi)
{
	emlxs_hba_t *hba = HBA;
	RPIobj_t *rpip;
	uint32_t index;

	/* Special handling for Fabric RPI */
	if (rpi == FABRIC_RPI) {
		return (port->vpip->fabric_rpip);
	}

	index = emlxs_sli4_rpi_to_index(hba, rpi);

	if (index >= hba->sli.sli4.RPICount) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_find:%d. RPI Invalid.",
		    rpi);

		return (NULL);
	}

	rpip = &hba->sli.sli4.RPIp[index];

	if (rpip->state == RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_find:%d  RPI not active",
		    rpi);

		return (NULL);
	}

	return (rpip);

} /* emlxs_rpi_find() */


static RPIobj_t *
emlxs_rpi_find_did(emlxs_port_t *port, uint32_t did)
{
	emlxs_hba_t *hba = HBA;
	RPIobj_t	*rpip;
	RPIobj_t	*rpip1;
	uint32_t	i;

	rpip1 = NULL;
	rpip = hba->sli.sli4.RPIp;
	for (i = 0; i < hba->sli.sli4.RPICount; i++, rpip++) {
		if (rpip->state == RPI_STATE_FREE) {
			continue;
		}

		if ((rpip->did == did) && (rpip->vpip == port->vpip)) {
			rpip1 = rpip;
			break;
		}
	}

	return (rpip1);

} /* emlxs_rpi_find_did() */


extern RPIobj_t *
emlxs_rpi_reserve_notify(emlxs_port_t *port, uint32_t did, XRIobj_t *xrip)
{
	emlxs_hba_t 	*hba = HBA;
	RPIobj_t	*rpip;

	/* xrip will be NULL for unsolicited BLS requests */

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (NULL);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	rpip = emlxs_rpi_find_did(port, did);

	if (!rpip) {
		rpip = emlxs_rpi_alloc(port, did);
	}

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reserve_notify: Unable to reserve an rpi. "
		    "did=%x xri=%d.",
		    did, ((xrip)?xrip->XRI:0));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (NULL);
	}

	/* Bind the XRI */
	if (xrip) {
		mutex_enter(&EMLXS_FCTAB_LOCK);
		xrip->reserved_rpip = rpip;
		rpip->xri_count++;
		mutex_exit(&EMLXS_FCTAB_LOCK);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_reserve_notify:%d  did=%x xri=%d.",
	    rpip->RPI, rpip->did, ((xrip)?xrip->XRI:0));

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rpip);

} /* emlxs_rpi_reserve_notify() */


extern RPIobj_t *
emlxs_rpi_alloc_notify(emlxs_port_t *port, uint32_t did)
{
	emlxs_hba_t *hba = HBA;
	RPIobj_t	*rpip;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (NULL);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	rpip = emlxs_rpi_alloc(port, did);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rpip);

} /* emlxs_rpi_alloc_notify() */


extern uint32_t
emlxs_rpi_free_notify(emlxs_port_t *port, RPIobj_t *rpip)
{
	emlxs_hba_t	*hba = HBA;
	uint32_t	rval = 0;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!rpip) {
		return (1);
	}

	/* Fabric RPI will be handled automatically */
	if (rpip->RPI == FABRIC_RPI) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	rval =  emlxs_rpi_free(port, rpip);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (rval);

} /* emlxs_rpi_free_notify() */


extern uint32_t
emlxs_rpi_pause_notify(emlxs_port_t *port, RPIobj_t *rpip)
{
	emlxs_hba_t *hba = HBA;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_pause_notify: No RPI provided.");
		return (1);
	}

	/* Fabric RPI will be handled automatically */
	if (rpip->RPI == FABRIC_RPI) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_pause_notify:%d %s. Pausing RPI. >",
	    rpip->RPI,
	    emlxs_rpi_state_xlate(rpip->state));

	(void) emlxs_rpi_event(port, FCF_EVENT_RPI_PAUSE, rpip);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (0);

} /* emlxs_rpi_pause_notify() */


extern uint32_t
emlxs_rpi_online_notify(emlxs_port_t *port, RPIobj_t *rpip, uint32_t did,
    SERV_PARM *sparam, void *arg1, void *arg2, void *arg3)
{
	emlxs_hba_t *hba = HBA;
	emlxs_deferred_cmpl_t *cmpl;
	uint32_t allocated = 0;
	uint32_t rval = 0;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if ((did == port->did) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		/* We never register our local port */
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (!rpip && (did == FABRIC_DID)) {
		/* We never online the Fabric DID other */
		/* than the fabric_rpip */
		rpip = port->vpip->fabric_rpip;
	}

	if (!rpip) {
		rpip = emlxs_rpi_find_did(port, did);
	}

	if (!rpip) {
		rpip = emlxs_rpi_alloc(port, did);
		allocated = 1;
	}

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_notify: Unable to allocate an rpi. did=%x",
		    did);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (1);
	}

	/* Initialize RPI node info */
	bcopy((void *)sparam, (void *)&rpip->sparam, sizeof (SERV_PARM));

	if (arg1 || arg2 || arg3) {
		cmpl = (emlxs_deferred_cmpl_t *)kmem_zalloc(
		    sizeof (emlxs_deferred_cmpl_t), KM_SLEEP);

		cmpl->port = port;
		cmpl->arg1 = arg1;
		cmpl->arg2 = arg2;
		cmpl->arg3 = arg3;

		/* For safety */
		if (rpip->cmpl) {
			emlxs_rpi_deferred_cmpl(port, rpip, 1);
		}

		rpip->cmpl = cmpl;
	}

	if ((rpip->RPI == FABRIC_RPI) ||
	    (hba->flag & FC_PT_TO_PT)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_notify:%d %s. %s. Login cmpl.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    ((allocated)? "Allocated":"Updated"));

		rval = emlxs_vpi_logi_cmpl_notify(port, rpip);

		if (rval && rpip->cmpl) {
			kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
			rpip->cmpl = 0;
		}

		mutex_exit(&EMLXS_FCF_LOCK);
		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_online_notify:%d %s. %s. Onlining RPI. >",
	    rpip->RPI,
	    emlxs_rpi_state_xlate(rpip->state),
	    ((allocated)? "Allocated":"Updated"));

	(void) emlxs_rpi_event(port, FCF_EVENT_RPI_ONLINE, rpip);

	if (rpip->cmpl) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_online_notify:%d %s. Deferred args not completed.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;

		mutex_exit(&EMLXS_FCF_LOCK);
		return (1);
	}

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_rpi_online_notify() */


extern uint32_t
emlxs_rpi_offline_notify(emlxs_port_t *port, RPIobj_t *rpip,
    void *arg1, void *arg2, void *arg3)
{
	emlxs_hba_t *hba = HBA;
	emlxs_deferred_cmpl_t *cmpl;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_offline_notify: No RPI provided.");
		return (1);
	}

	/* Fabric RPI will be handled automatically */
	if (rpip->RPI == FABRIC_RPI) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (arg1 || arg2 || arg3) {
		cmpl = (emlxs_deferred_cmpl_t *)kmem_zalloc(
		    sizeof (emlxs_deferred_cmpl_t), KM_SLEEP);

		cmpl->port = port;
		cmpl->arg1 = arg1;
		cmpl->arg2 = arg2;
		cmpl->arg3 = arg3;

		rpip->cmpl = cmpl;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_offline_notify:%d %s. Offlining RPI. >",
	    rpip->RPI,
	    emlxs_rpi_state_xlate(rpip->state));

	(void) emlxs_rpi_event(port, FCF_EVENT_RPI_OFFLINE, rpip);

	if (rpip->cmpl) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_offline_notify:%d %s. Deferred args not completed.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;

		mutex_exit(&EMLXS_FCF_LOCK);
		return (1);
	}

	mutex_exit(&EMLXS_FCF_LOCK);

	return (0);

} /* emlxs_rpi_offline_notify() */


extern uint32_t
emlxs_rpi_resume_notify(emlxs_port_t *port, RPIobj_t *rpip, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_deferred_cmpl_t *cmpl;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_notify: No RPI provided.");
		return (1);
	}

	/* Fabric RPI will be handled automatically */
	if (rpip->RPI == FABRIC_RPI) {
		return (1);
	}

	mutex_enter(&EMLXS_FCF_LOCK);

	if (rpip->state != RPI_STATE_PAUSED) {
		mutex_exit(&EMLXS_FCF_LOCK);
		return (1);
	}

	if (sbp) {
		cmpl = (emlxs_deferred_cmpl_t *)kmem_zalloc(
		    sizeof (emlxs_deferred_cmpl_t), KM_SLEEP);

		cmpl->port = port;
		cmpl->arg1 = (void *)sbp;
		cmpl->arg2 = 0;
		cmpl->arg3 = 0;

		rpip->cmpl = cmpl;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_resume_notify:%d %s. Resuming RPI. >",
	    rpip->RPI,
	    emlxs_rpi_state_xlate(rpip->state));

	(void) emlxs_rpi_event(port, FCF_EVENT_RPI_RESUME, rpip);

	if (rpip->cmpl) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_notify:%d %s. Deferred args not completed.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;

		mutex_exit(&EMLXS_FCF_LOCK);
		return (1);
	}

	mutex_exit(&EMLXS_FCF_LOCK);

	return (0);

} /* emlxs_rpi_resume_notify() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_free_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	XRIobj_t	*xrip;
	XRIobj_t	*next_xrip;

	if (rpip->state != RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_free_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->cmpl) {
		emlxs_rpi_deferred_cmpl(port, rpip, 1);
	}

	if (rpip->vpip->p2p_rpip == rpip) {
		rpip->vpip->p2p_rpip = NULL;
	}

	/* Break node/RPI binding */
	rw_enter(&port->node_rwlock, RW_WRITER);
	if (rpip->node) {
		rpip->node->rpip = NULL;
		rpip->node = NULL;
	}
	rw_exit(&port->node_rwlock);

	/* Remove all XRIs under this RPI */
	mutex_enter(&EMLXS_FCTAB_LOCK);
	xrip = (XRIobj_t *)hba->sli.sli4.XRIinuse_f;
	while (xrip != (XRIobj_t *)&hba->sli.sli4.XRIinuse_f) {
		next_xrip = xrip->_f;
		if (xrip->rpip == rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_free_action:%d xri_count=%d. "
			    "Removing XRI:%d iotag:%d.",
			    rpip->RPI,
			    rpip->xri_count,
			    xrip->XRI, xrip->iotag);

			rpip->xri_count--;
			xrip->rpip = NULL;
		}

		if (xrip->reserved_rpip == rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_free_action:%d xri_count=%d. "
			    "Removing XRI:%d iotag:%d.",
			    rpip->RPI,
			    rpip->xri_count,
			    xrip->XRI, xrip->iotag);

			rpip->xri_count--;
			xrip->reserved_rpip = NULL;
		}

		xrip = next_xrip;
	}
	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (rpip->xri_count) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_free_action:%d. xri_count=%d",
		    rpip->RPI,
		    rpip->xri_count);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_free_action:%d flag=%x. RPI freed. <",
	    rpip->RPI,
	    rpip->flag);

	rpip->flag = 0;

	return (0);

} /* emlxs_rpi_free_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_online_evt_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 1;

	if (evt != FCF_EVENT_RPI_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_online_evt_action:%d %s:%s arg=%p. "
		    "Invalid event type. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	switch (rpip->state) {
	case RPI_STATE_REG:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_evt_action:%d flag=%x. Registering.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG,
		    FCF_REASON_REENTER, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_evt_action:%d flag=%x. Registering.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG,
		    FCF_REASON_EVENT, evt, arg1);
		break;
	}

	return (rval);

} /* emlxs_rpi_online_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_offline_evt_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 1;

	if (evt != FCF_EVENT_RPI_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_offline_evt_action:%d %s:%s arg=%p. "
		    "Invalid event type. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	switch (rpip->state) {
	case RPI_STATE_RESERVED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_evt_action:%d flag=%x. Freeing RPI.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_FREE,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case RPI_STATE_UNREG:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_evt_action:%d flag=%x. "
		    "Already unregistering. <",
		    rpip->RPI,
		    rpip->flag);

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_evt_action:%d flag=%x. Unregistering.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	}

	return (rval);

} /* emlxs_rpi_offline_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_pause_evt_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	VPIobj_t *vpip;
	uint32_t rval = 1;

	vpip = rpip->vpip;

	if (evt != FCF_EVENT_RPI_PAUSE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_pause_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    rpip->flag);
		return (1);
	}

	switch (rpip->state) {
	case RPI_STATE_RESERVED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_pause_evt_action:%d flag=%x. Freeing RPI.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_FREE,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	case RPI_STATE_UNREG:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_pause_evt_action:%d flag=%x. Not online. <",
		    rpip->RPI,
		    rpip->flag);

		break;

	case RPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_pause_evt_action:%d flag=%x. Already paused. <",
		    rpip->RPI,
		    rpip->flag);

		break;

	case RPI_STATE_REG:
	case RPI_STATE_ONLINE:
	case RPI_STATE_RESUME:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_pause_evt_action:%d flag=%x. Pausing.",
		    rpip->RPI,
		    rpip->flag);

		/* Don't pause an RPI, if the VPI is not pausing too */
		if (!(vpip->flag & EMLXS_VPI_PAUSE_REQ)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_pause_evt_action:%d rpi_online=%d,%d "
			    "xri_count=%d. VPI:%d pause not requested.  "
			    "Unregistering.", rpip->RPI,
			    vpip->rpi_online, vpip->rpi_paused,
			    rpip->xri_count, vpip->VPI);

			rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
			    FCF_REASON_EVENT, evt, arg1);
			break;
		}

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_PAUSED,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_pause_evt_action:%d flag=%x. <",
		    rpip->RPI,
		    rpip->flag);
		break;
	}

	return (rval);

} /* emlxs_rpi_pause_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_resume_evt_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 1;

	if (evt != FCF_EVENT_RPI_RESUME) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_evt_action:%d %s:%s arg=%p flag=%x. "
		    "Invalid event type. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    rpip->flag);
		return (1);
	}

	switch (rpip->state) {
	case RPI_STATE_PAUSED:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_evt_action:%d flag=%x. Resuming.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_RESUME,
		    FCF_REASON_EVENT, evt, arg1);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_evt_action:%d flag=%x. Not paused. <",
		    rpip->RPI,
		    rpip->flag);
		break;
	}

	return (rval);

} /* emlxs_rpi_resume_evt_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_reserved_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	VPIobj_t *vpip;

	vpip = rpip->vpip;

	if (rpip->state != RPI_STATE_RESERVED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reserved_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->prev_state != RPI_STATE_FREE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reserved_action:%d %s:%s arg=%p. "
		    "Invalid previous state. %s  <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    emlxs_rpi_state_xlate(rpip->prev_state));

		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_reserved_action:%d rpi_online=%d,%d. <",
	    rpip->RPI,
	    vpip->rpi_online, vpip->rpi_paused);

	return (0);

} /* emlxs_rpi_reserved_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_offline_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;
	VPIobj_t *vpip;

	vpip = rpip->vpip;

	if (rpip->state != RPI_STATE_OFFLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->flag & EMLXS_RPI_PAUSED) {
		rpip->flag &= ~EMLXS_RPI_PAUSED;

		if (vpip->rpi_paused) {
			vpip->rpi_paused--;
		}
	}

	if (rpip->flag & EMLXS_RPI_VPI) {
		rpip->flag &= ~EMLXS_RPI_VPI;

		if (vpip->rpi_online) {
			vpip->rpi_online--;
		}

		/* Added protection */
		if (vpip->rpi_online < vpip->rpi_paused) {
			vpip->rpi_paused = vpip->rpi_online;
		}
	}

	if (rpip->RPI == FABRIC_RPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_action:%d rpi_online=%d,%d xri_count=%d. "
		    "Fabric RPI offline. Freeing.",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count);

		/* Free RPI */
		rval = emlxs_rpi_state(port, rpip, RPI_STATE_FREE, 0, 0, 0);

		return (rval);
	}

	if ((vpip->rpi_online == 0) ||
	    (vpip->rpi_online == vpip->rpi_paused)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_action:%d rpi_online=%d,%d xri_count=%d. "
		    "RPI offline. "
		    "Notifying VPI:%d >",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count,
		    vpip->VPI);

		/* Notify VPI */
		(void) emlxs_vpi_event(port, FCF_EVENT_RPI_OFFLINE, rpip);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_offline_action:%d rpi_online=%d,%d xri_count=%d. "
		    "RPI offline. Freeing.",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count);
	}

	/* Free RPI */
	rval = emlxs_rpi_state(port, rpip, RPI_STATE_FREE, 0, 0, 0);

	return (rval);

} /* emlxs_rpi_offline_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_paused_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	VPIobj_t *vpip;
	uint32_t rval = 0;

	vpip = rpip->vpip;

	if (rpip->state != RPI_STATE_PAUSED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_paused_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(vpip->flag & EMLXS_VPI_PAUSE_REQ)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_paused_action:%d rpi_online=%d,%d xri_count=%d. "
		    "VPI:%d pause not requested.  Unregistering.",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count,
		    vpip->VPI);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
		    FCF_REASON_EVENT, evt, arg1);
		return (rval);
	}

	if (!(rpip->flag & EMLXS_RPI_PAUSED)) {
		rpip->flag |= EMLXS_RPI_PAUSED;
		vpip->rpi_paused++;
	}

	/* Check if all RPI's have been paused for a VPI */
	if (vpip->rpi_online == vpip->rpi_paused) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_paused_action:%d rpi_online=%d,%d xri_count=%d. "
		    "RPI paused. "
		    "Notifying VPI:%d >",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count,
		    vpip->VPI);

		/* Notify VPI */
		(void) emlxs_vpi_event(port, FCF_EVENT_RPI_PAUSE, rpip);

	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_paused_action:%d rpi_online=%d,%d xri_count=%d. "
		    "RPI paused. <",
		    rpip->RPI,
		    vpip->rpi_online, vpip->rpi_paused,
		    rpip->xri_count);
	}

	return (0);

} /* emlxs_rpi_paused_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_unreg_failed_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	rpip->attempts++;

	if (rpip->state != RPI_STATE_UNREG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_unreg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    rpip->attempts);
		return (1);
	}

	if ((rpip->reason == FCF_REASON_SEND_FAILED) ||
	    !(rpip->flag & EMLXS_RPI_REG)) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_failed_action:%d reason=%x flag=%x. "
		    "Going offline.",
		    rpip->RPI,
		    rpip->reason,
		    rpip->flag);

		rpip->flag &= ~EMLXS_RPI_REG;

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_failed_action:%d flag=%x. Going online.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_rpi_unreg_failed_action() */


static void
emlxs_rpi_unreg_handler(emlxs_port_t *port, RPIobj_t *rpip)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t *vpip = rpip->vpip;
	emlxs_node_t *node = rpip->node;
	XRIobj_t *xrip;
	XRIobj_t *next_xrip;

	/* Special handling for Fabric RPI */
	if (rpip->RPI == FABRIC_RPI) {
		if (node) {
			(void) emlxs_tx_node_flush(port, node, 0, 0, 0);
			(void) emlxs_chipq_node_flush(port, 0, node, 0);
		}

		/* Clear all reserved XRIs under this RPI */
		mutex_enter(&EMLXS_FCTAB_LOCK);
		xrip = (XRIobj_t *)hba->sli.sli4.XRIinuse_f;
		while (xrip != (XRIobj_t *)&hba->sli.sli4.XRIinuse_f) {
			next_xrip = xrip->_f;
			/* We don't need to worry about xrip->reserved_rpip */
			/* here because the Fabric RPI can never be reserved */
			/* by an xri. */
			if ((xrip->rpip == rpip) &&
			    (xrip->flag & EMLXS_XRI_RESERVED)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
				    "rpi_unreg_action:%d xri_count=%d. "
				    "Unreserving XRI:%d iotag:%d.",
				    rpip->RPI,
				    rpip->xri_count,
				    xrip->XRI, xrip->iotag);

				(void) emlxs_sli4_unreserve_xri(port,
				    xrip->XRI, 0);
			}
			xrip = next_xrip;
		}
		mutex_exit(&EMLXS_FCTAB_LOCK);
	}

	rpip->flag &= ~EMLXS_RPI_REG;

	if (rpip->flag & EMLXS_RPI_PAUSED) {
		rpip->flag &= ~EMLXS_RPI_PAUSED;

		if (vpip->rpi_paused) {
			vpip->rpi_paused--;
		}
	}

	if (rpip->flag & EMLXS_RPI_VPI) {
		rpip->flag &= ~EMLXS_RPI_VPI;

		if (vpip->rpi_online) {
			vpip->rpi_online--;
		}

		/* Added protection */
		if (vpip->rpi_online < vpip->rpi_paused) {
			vpip->rpi_paused = vpip->rpi_online;
		}
	}

	rw_enter(&port->node_rwlock, RW_WRITER);
	if (node) {
		rpip->node = NULL;
		node->rpip = NULL;
	}
	rw_exit(&port->node_rwlock);

	if (node) {
		emlxs_node_rm(port, node);
	}

	return;

} /* emlxs_rpi_unreg_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_unreg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	RPIobj_t *rpip;

	mutex_enter(&EMLXS_FCF_LOCK);

	rpip = (RPIobj_t *)mbq->context;

	mb4 = (MAILBOX4 *)mbq;

	if (rpip->state != RPI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_mbcmpl:%d state=%s. "
		    "No longer in RPI_STATE_UNREG.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_mbcmpl:%d failed. %s. >",
		    rpip->RPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_rpi_state(port, rpip, RPI_STATE_UNREG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	emlxs_rpi_unreg_handler(port, rpip);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_unreg_mbcmpl:%d Unregistered. Unreg complete. >",
	    rpip->RPI);

	(void) emlxs_rpi_state(port, rpip, RPI_STATE_UNREG_CMPL,
	    0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);
	return (0);

} /* emlxs_rpi_unreg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_unreg_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;
	VPIobj_t *vpip = rpip->vpip;

	if (rpip->state != RPI_STATE_UNREG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_unreg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(rpip->flag & EMLXS_RPI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_action:%d. Not registered. Going offline.",
		    rpip->RPI);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (rpip->prev_state != RPI_STATE_UNREG_FAILED) {
		rpip->attempts = 0;
	}

	if (rpip->RPI == FABRIC_RPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_unreg_action:%d did=%x vpi=%d. Fabric RPI. "
		    "Going offline.",
		    rpip->RPI,
		    rpip->did,
		    rpip->vpip->VPI);

		/* Don't send UNREG_RPI, but process it as if we did */
		emlxs_rpi_unreg_handler(port, rpip);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_unreg_action:%d attempts=%d. Sending UNREG_RPI. <",
	    rpip->RPI,
	    rpip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_rpi_unreg_mbcmpl;
	mbq->context = (void *)rpip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_UNREG_RPI;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varUnregLogin.rpi = rpip->RPI;
	mb4->un.varUnregLogin.vpi = vpip->VPI;

	if (rpip->cmpl) {
		mbq->sbp = rpip->cmpl->arg1;
		mbq->ubp = rpip->cmpl->arg2;
		mbq->iocbq = rpip->cmpl->arg3;
	}

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	if (rpip->cmpl) {
		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;
	}

	return (0);

} /* emlxs_rpi_unreg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_unreg_cmpl_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (rpip->state != RPI_STATE_UNREG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_unreg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_unreg_cmpl_action:%d flag=%x. Going offline.",
	    rpip->RPI,
	    rpip->flag);

	rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
	    FCF_REASON_EVENT, evt, arg1);

	return (rval);

} /* emlxs_rpi_unreg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_reg_failed_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	rpip->attempts++;

	if (rpip->state != RPI_STATE_REG_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_reg_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    rpip->attempts);
		return (1);
	}

	if ((rpip->reason == FCF_REASON_SEND_FAILED) ||
	    !(rpip->flag & EMLXS_RPI_REG)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_failed_action:%d reason=%x flag=%x. "
		    "Going offline.",
		    rpip->RPI,
		    rpip->reason,
		    rpip->flag);

		rpip->flag &= ~EMLXS_RPI_REG;

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_failed_action:%d flag=%x. Unregistering",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_rpi_reg_failed_action() */


static uint32_t
emlxs_rpi_reg_handler(emlxs_port_t *port, RPIobj_t *rpip)
{
	emlxs_hba_t *hba = HBA;
	VPIobj_t *vpip;
	emlxs_node_t *node;

	vpip = rpip->vpip;

	rpip->flag |= EMLXS_RPI_REG;

	if (rpip->flag & EMLXS_RPI_PAUSED) {
		rpip->flag &= ~EMLXS_RPI_PAUSED;

		if (vpip->rpi_paused) {
			vpip->rpi_paused--;
		}
	}

	if (!(rpip->flag & EMLXS_RPI_VPI) && (rpip->RPI != FABRIC_RPI)) {
		rpip->flag |= EMLXS_RPI_VPI;
		vpip->rpi_online++;
	}

	/* If private loop and this is fabric RPI, then exit now */
	if (!(hba->flag & FC_FABRIC_ATTACHED) && (rpip->RPI == FABRIC_RPI)) {
		return (0);
	}

	/* Create or update the node */
	node = emlxs_node_create(port, rpip->did, rpip->RPI, &rpip->sparam);

	if (!node) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_handler:%d. Node create failed. Reg failed.",
		    rpip->RPI);

		return (FCF_REASON_NO_NODE);
	}

	return (0);

} /* emlxs_rpi_reg_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_reg_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	RPIobj_t *rpip;
	emlxs_node_t *node;
	uint32_t rval = 0;

	mutex_enter(&EMLXS_FCF_LOCK);

	rpip = (RPIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	if (rpip->state != RPI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_mbcmpl:%d state=%s. No longer in RPI_STATE_REG.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_mbcmpl:%d failed. %s. >",
		    rpip->RPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	rval = emlxs_rpi_reg_handler(port, rpip);

	if (rval) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_mbcmpl:%d. Reg failed. >",
		    rpip->RPI);

		mb4->mbxStatus = MBX_FAILURE;

		(void) emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
		    rval, 0, 0);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	node = rpip->node;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_reg_mbcmpl:%d Registered. Reg complete. >",
	    rpip->RPI);

	(void) emlxs_rpi_state(port, rpip, RPI_STATE_REG_CMPL, 0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);

	/* Needed for FCT trigger in emlxs_mb_deferred_cmpl */
	if (mbq->sbp) {
		((emlxs_buf_t *)mbq->sbp)->node = node;
	}

#ifdef DHCHAP_SUPPORT
	if (mbq->sbp || mbq->ubp) {
		if (emlxs_dhc_auth_start(port, node, (uint8_t *)mbq->sbp,
		    (uint8_t *)mbq->ubp) == 0) {
			/* Auth started - auth completion will */
			/* handle sbp and ubp now */
			mbq->sbp = NULL;
			mbq->ubp = NULL;
		}
	}
#endif	/* DHCHAP_SUPPORT */

	return (0);

} /* emlxs_rpi_reg_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_reg_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	MATCHMAP *mp;
	uint32_t rval = 0;

	if (rpip->state != RPI_STATE_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_reg_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->RPI == FABRIC_RPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_action:%d did=%x vpi=%d. Fabric RPI. "
		    "Going online.",
		    rpip->RPI,
		    rpip->did,
		    rpip->vpip->VPI);

		/* Don't send REG_RPI, but process it as if we did */
		rval = emlxs_rpi_reg_handler(port, rpip);

		if (rval) {
			rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
			    rval, 0, 0);

			return (rval);
		}

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (rpip->prev_state != RPI_STATE_REG_FAILED) {
		rpip->attempts = 0;
	}

	if (rpip->flag & EMLXS_RPI_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_action:%d attempts=%d. "
		    "Updating REG_RPI. <",
		    rpip->RPI,
		    rpip->attempts);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_action:%d attempts=%d. "
		    "Sending REG_RPI. <",
		    rpip->RPI,
		    rpip->attempts);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}

	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
		    FCF_REASON_NO_BUFFER, 0, arg1);

		return (rval);
	}

	mbq->bp = (void *)mp;
	mbq->nonembed = NULL;

	mbq->mbox_cmpl = emlxs_rpi_reg_mbcmpl;
	mbq->context = (void *)rpip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_REG_RPI;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varRegLogin.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb4->un.varRegLogin.un.sp64.addrHigh = PADDR_HI(mp->phys);
	mb4->un.varRegLogin.un.sp64.addrLow = PADDR_LO(mp->phys);
	mb4->un.varRegLogin.did = rpip->did;
	mb4->un.varWords[30] = 0;	/* flags */

	mb4->un.varRegLogin.vpi = rpip->vpip->VPI;
	mb4->un.varRegLogin.rpi = rpip->RPI;
	mb4->un.varRegLogin.update = (rpip->flag & EMLXS_RPI_REG)? 1:0;

	bcopy((void *)&rpip->sparam, (void *)mp->virt, sizeof (SERV_PARM));

	if (rpip->cmpl) {
		mbq->sbp = rpip->cmpl->arg1;
		mbq->ubp = rpip->cmpl->arg2;
		mbq->iocbq = rpip->cmpl->arg3;
	}

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_REG_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	if (rpip->cmpl) {
		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;
	}

	return (0);

} /* emlxs_rpi_reg_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_reg_cmpl_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (rpip->state != RPI_STATE_REG_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_reg_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->flag & EMLXS_RPI_REG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_cmpl_action:%d flag=%x. Going online.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_reg_cmpl_action:%d flag=%x. Going offline.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_rpi_reg_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_resume_failed_action(emlxs_port_t *port, RPIobj_t *rpip,
    uint32_t evt, void *arg1)
{
	uint32_t rval = 0;

	rpip->attempts++;

	if (rpip->state != RPI_STATE_RESUME_FAILED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_failed_action:%d %s:%s arg=%p attempt=%d. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1,
		    rpip->attempts);
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_resume_failed_action:%d attempt=%d. Unregistering.",
	    rpip->RPI,
	    rpip->attempts);

	rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
	    FCF_REASON_OP_FAILED, rpip->attempts, arg1);

	return (rval);

} /* emlxs_rpi_resume_failed_action() */


/*ARGSUSED*/
static void
emlxs_rpi_resume_handler(emlxs_port_t *port, RPIobj_t *rpip)
{
	if (rpip->flag & EMLXS_RPI_PAUSED) {
		rpip->flag &= ~EMLXS_RPI_PAUSED;

		if (rpip->vpip->rpi_paused) {
			rpip->vpip->rpi_paused--;
		}
	}

	return;

} /* emlxs_rpi_resume_handler() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_resume_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX4 *mb4;
	RPIobj_t *rpip;

	mutex_enter(&EMLXS_FCF_LOCK);

	rpip = (RPIobj_t *)mbq->context;
	mb4 = (MAILBOX4 *)mbq;

	if (rpip->state != RPI_STATE_RESUME) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_mbcmpl:%d state=%s. "
		    "No longer in RPI_STATE_RESUME.",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state));

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	if (mb4->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_mbcmpl:%d failed. %s. >",
		    rpip->RPI,
		    emlxs_mb_xlate_status(mb4->mbxStatus));

		(void) emlxs_rpi_state(port, rpip, RPI_STATE_RESUME_FAILED,
		    FCF_REASON_MBOX_FAILED, mb4->mbxStatus, (void *)mbq->sbp);

		mutex_exit(&EMLXS_FCF_LOCK);
		return (0);
	}

	emlxs_rpi_resume_handler(port, rpip);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_resume_mbcmpl:%d Resumed. Resume complete. >",
	    rpip->RPI);

	(void) emlxs_rpi_state(port, rpip, RPI_STATE_RESUME_CMPL, 0, 0, 0);

	mutex_exit(&EMLXS_FCF_LOCK);

	return (0);

} /* emlxs_rpi_resume_mbcmpl() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_resume_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	MAILBOX4 *mb4;
	MAILBOXQ *mbq;
	uint32_t rval = 0;

	if (rpip->state != RPI_STATE_RESUME) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (!(rpip->flag & EMLXS_RPI_PAUSED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_action:%d flag=%x. Not Paused. Going online.",
		    rpip->RPI, rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (rpip->RPI == FABRIC_RPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_action:%d. Fabric RPI. "
		    "Going online.",
		    rpip->RPI);

		/* Don't send RESUME_RPI, but process it as if we did */
		emlxs_rpi_resume_handler(port, rpip);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_EVENT, evt, arg1);

		return (rval);
	}

	if (rpip->prev_state != RPI_STATE_RESUME_FAILED) {
		rpip->attempts = 0;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_resume_action:%d attempts=%d. Sending RESUME_RPI. <",
	    rpip->RPI,
	    rpip->attempts);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_RESUME_FAILED,
		    FCF_REASON_NO_MBOX, 0, arg1);

		return (rval);
	}
	mb4 = (MAILBOX4*)mbq;
	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mbq->nonembed = NULL;
	mbq->mbox_cmpl = emlxs_rpi_resume_mbcmpl;
	mbq->context = (void *)rpip;
	mbq->port = (void *)port;

	mb4->mbxCommand = MBX_RESUME_RPI;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varResumeRPI.EventTag = hba->link_event_tag;
	mb4->un.varResumeRPI.RPI = rpip->RPI;

	if (rpip->cmpl) {
		mbq->sbp = rpip->cmpl->arg1;
		mbq->ubp = rpip->cmpl->arg2;
		mbq->iocbq = rpip->cmpl->arg3;
	}

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_RESUME_FAILED,
		    FCF_REASON_SEND_FAILED, rval, arg1);

		return (rval);
	}

	if (rpip->cmpl) {
		kmem_free(rpip->cmpl, sizeof (emlxs_deferred_cmpl_t));
		rpip->cmpl = 0;
	}

	return (0);

} /* emlxs_rpi_resume_action() */


static uint32_t
emlxs_rpi_resume_cmpl_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	uint32_t rval = 0;

	if (rpip->state != RPI_STATE_RESUME_CMPL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_error_msg,
		    "rpi_resume_cmpl_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->flag & EMLXS_RPI_PAUSED) {
		if (rpip->flag & EMLXS_RPI_REG) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_reg_cmpl_action:%d flag=%x. Unregistering.",
			    rpip->RPI,
			    rpip->flag);

			rval = emlxs_rpi_state(port, rpip, RPI_STATE_UNREG,
			    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
			    "rpi_reg_cmpl_action:%d flag=%x. Going offline.",
			    rpip->RPI,
			    rpip->flag);

			rval = emlxs_rpi_state(port, rpip, RPI_STATE_OFFLINE,
			    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
		}
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_resume_cmpl_action:%d flag=%x. Going online.",
		    rpip->RPI,
		    rpip->flag);

		rval = emlxs_rpi_state(port, rpip, RPI_STATE_ONLINE,
		    FCF_REASON_OP_FAILED, rpip->attempts, arg1);
	}

	return (rval);

} /* emlxs_rpi_resume_cmpl_action() */


/*ARGSUSED*/
static uint32_t
emlxs_rpi_online_action(emlxs_port_t *port, RPIobj_t *rpip, uint32_t evt,
    void *arg1)
{
	emlxs_hba_t *hba = HBA;
	uint32_t rval = 0;
	RPIobj_t *p2p_rpip;

	if (rpip->state != RPI_STATE_ONLINE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_action:%d %s:%s arg=%p. "
		    "Invalid state. <",
		    rpip->RPI,
		    emlxs_rpi_state_xlate(rpip->state),
		    emlxs_fcf_event_xlate(evt), arg1);
		return (1);
	}

	if (rpip->RPI == FABRIC_RPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
		    "rpi_online_action:%d did=%x. Fabric RPI online. <",
		    rpip->RPI,
		    rpip->did,
		    rpip->vpip->VPI);

		/* Now register the p2p_rpip */
		p2p_rpip = rpip->vpip->p2p_rpip;
		if (p2p_rpip) {
			rpip->vpip->p2p_rpip = NULL;

			rval = emlxs_rpi_state(port, p2p_rpip, RPI_STATE_REG,
			    FCF_REASON_EVENT, evt, arg1);
		}

		EMLXS_STATE_CHANGE(hba, FC_READY);

		if (rpip->cmpl) {
			emlxs_rpi_deferred_cmpl(port, rpip, 0);
		}

		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcf_detail_msg,
	    "rpi_online_action:%d did=%x. RPI online. Notifying VPI:%d. >",
	    rpip->RPI,
	    rpip->did,
	    rpip->vpip->VPI);

	/* Notify VPI */
	rval = emlxs_vpi_event(port, FCF_EVENT_RPI_ONLINE, rpip);

	return (rval);

} /* emlxs_rpi_online_action() */
