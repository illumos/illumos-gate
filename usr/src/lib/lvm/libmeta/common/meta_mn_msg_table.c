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

#include <meta.h>

extern void mdmn_do_cmd(HANDLER_PARMS);
extern void mdmn_do_clu(HANDLER_PARMS);
extern void mdmn_do_req_owner(HANDLER_PARMS);
extern void mdmn_do_susp_write(HANDLER_PARMS);
extern void mdmn_do_state_upd_reswr(HANDLER_PARMS);
extern void mdmn_do_allocate_hotspare(HANDLER_PARMS);
extern void mdmn_do_poke_hotspares(HANDLER_PARMS);
extern void mdmn_do_resync(HANDLER_PARMS);
extern void mdmn_do_setsync(HANDLER_PARMS);
extern void mdmn_do_choose_owner(HANDLER_PARMS);
extern void mdmn_do_change_owner(HANDLER_PARMS);
extern void mdmn_do_set_cap(HANDLER_PARMS);
extern void mdmn_do_dummy(HANDLER_PARMS);
extern void mdmn_do_mddb_parse(HANDLER_PARMS);
extern void mdmn_do_mddb_block(HANDLER_PARMS);
extern void mdmn_do_sm_mddb_attach(HANDLER_PARMS);
extern void mdmn_do_sm_mddb_detach(HANDLER_PARMS);
extern void mdmn_do_meta_db_newside(HANDLER_PARMS);
extern void mdmn_do_meta_db_delside(HANDLER_PARMS);
extern void mdmn_do_meta_md_addside(HANDLER_PARMS);
extern void mdmn_do_meta_md_delside(HANDLER_PARMS);
extern void mdmn_do_mddb_optrecerr(HANDLER_PARMS);
extern void mdmn_do_iocset(HANDLER_PARMS);
extern void mdmn_do_sp_setstat(HANDLER_PARMS);
extern void mdmn_do_addkeyname(HANDLER_PARMS);
extern void mdmn_do_delkeyname(HANDLER_PARMS);
extern void mdmn_do_get_tstate(HANDLER_PARMS);
extern void mdmn_do_get_mirstate(HANDLER_PARMS);
extern void mdmn_do_addmdname(HANDLER_PARMS);
extern void mdmn_do_mark_dirty(HANDLER_PARMS);
extern void mdmn_do_mark_clean(HANDLER_PARMS);

extern int mdmn_smgen_test6(SMGEN_PARMS);
extern int mdmn_smgen_state_upd(SMGEN_PARMS);
extern int mdmn_smgen_mddb_attach(SMGEN_PARMS);
extern int mdmn_smgen_mddb_detach(SMGEN_PARMS);

md_mn_msg_tbl_entry_t  msg_table[MD_MN_NMESSAGES] = {

/*
 * In order to have fast direct access to the table, we use the message type as
 * an index into it.
 * Thus the order of the elements in this table MUST match the order of the
 * message types specified in mdmn_commd.x!
 * See the definition of md_mn_msg_t.
 *
 * Be careful and do not disturb the order of the messages!
 */
	{
	/* MD_MN_MSG_NULL */
		MD_MSG_CLASS0,	/* message class */
		NULL, 		/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		0, 0, 		/* class busy retry / time delta */
		0, 0		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST1 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_dummy, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		200, 4,		/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST2 */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_dummy, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		200, 4,		/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST3 */
		MD_MSG_CLASS3,	/* message class */
		mdmn_do_dummy, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		200, 4,		/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST4 */
		MD_MSG_CLASS4,	/* message class */
		mdmn_do_dummy, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		200, 4,		/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST5 */
		MD_MSG_CLASS5,	/* message class */
		mdmn_do_dummy, 	/* message handler */
		NULL, 		/* submessage generator */
		4,		/* timeout in seconds */
		200, 4, 	/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_TEST6 */
		MD_MSG_CLASS1,	/* message class */
		NULL,		/* message handler */
		mdmn_smgen_test6, /* submessage generator */
		1,		/* timeout in seconds */
		200, 4, 	/* class busy retry / time delta */
		10, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_CMD
	 * Send a command string to all nodes
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_cmd, 	/* message handler */
		NULL, 		/* submessage generator */
		90,		/* times out in 90 secs */
		40, 20,		/* class busy retry / time delta */
		10, 1000	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_CMD_RETRY
	 * Send a command string to all nodes and retry on busy
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_cmd, 	/* message handler */
		NULL, 		/* submessage generator */
		90,		/* times out in 90 secs */
		100000, 20, 	/* class busy retry / time delta */
		10, 1000	/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_CLU_CHECK */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_clu, 	/* message handler */
		NULL, 		/* submessage generator */
		5,		/* timeout in seconds */
		10000, 2, 	/* class busy retry / time delta */
		0, 0		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_CLU_LOCK */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_clu, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		10000, 2, 	/* class busy retry / time delta */
		0, 0		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_CLU_UNLOCK */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_clu, 	/* message handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		10000, 2,	/* class busy retry / time delta */
		0, 0		/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_REQUIRE_OWNER */
		MD_MSG_CLASS5,	/* message class */
		mdmn_do_req_owner, /* message handler */
		NULL, 		/* submessage generator */
		12,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_CHOOSE_OWNER
	 * Using the current resync count for the set, choose a resync
	 * owner and send a CHANGE_OWNER message to request that node
	 * to make itself the owner
	 */
		MD_MSG_CLASS3,	/* message class */
		mdmn_do_choose_owner, /* message handler */
		NULL, 		/* submessage generator */
		12,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_CHANGE_OWNER
	 * Request a change of ownership to the specified node
	 */
		MD_MSG_CLASS4,	/* message class */
		mdmn_do_change_owner, /* message handler */
		NULL, 		/* submessage generator */
		12,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SUSPEND_WRITES
	 * Suspend all writes to the specified mirror
	 */
		MD_MSG_CLASS6,	/* message class */
		mdmn_do_susp_write, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		200, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_STATE_UPDATE_RESWR
	 * Update the state of a mirror component
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_state_upd_reswr, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_STATE_UPDATE
	 * Suspend writes to a mirror and then update the state of a
	 * mirror component
	 */
		MD_MSG_CLASS1,	/* message class */
		NULL,		 /* message handler */
		mdmn_smgen_state_upd,	/* submessage generator */
		16,		/* SUSPEND_WRITES + STATE_UPDATE_RESWR */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_ALLOCATE_HOTSPARE
	 * Allocate a hotspare for a mirror component
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_allocate_hotspare, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RESYNC_STARTING
	 * Start a resync thread for the specified mirror
	 */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_resync, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RESYNC_NEXT
	 * Send the next region to be resyned to all nodes. For ABR
	 * mirrors, the nodes must suspend all writes to this region until
	 * the next message of this type or a RESYNC_FINISH
	 */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_resync, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RESYNC_FINISH
	 * All resyncs for a mirror are complete, terminate resync thread
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_resync, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RESYNC_PHASE_DONE
	 * A resync phase, optimized, submirror or component is complete
	 */
		MD_MSG_CLASS2,	/* message class */
		mdmn_do_resync, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SET_CAP
	 * Set the specified metadevice capability on all nodes
	 * This is used to propagate the ABR capability
	 */
		MD_MSG_CLASS1,	/* message class */
		mdmn_do_set_cap, /* message handler */
		NULL,		/* submessage generator */
		8,		/* timeout in seconds */
		100000, 10,	/* class busy retry/ time delta */
		200, 100	/* comm fail retry / time delta */
	},

	{
	/* MD_MN_MSG_VERBOSITY */
		MD_MSG_CLASS0,	/* special message class */
		mdmn_do_dummy,	/* dummy handler */
		NULL, 		/* submessage generator */
		1,		/* timeout in seconds */
		0, 0,		/* No retries for class busy */
		0, 0		/* No retries for comm fail */
	},

	{
	/*
	 * MD_MN_MSG_MDDB_PARSE
	 * Message cannot fail unless node failure causes node panic
	 */
		MD_MSG_CLASS7,		/* message class */
		mdmn_do_mddb_parse,	/* reparse mddb */
		NULL, 			/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_MDDB_BLOCK
	 * Message cannot fail unless node failure causes node panic
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_mddb_block,	/* block/unblock reparse */
		NULL, 			/* submessage generator */
		5,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_DB_ATTACH
	 */
		MD_MSG_CLASS3,		/* message class */
		NULL,			/* message handler */
		mdmn_smgen_mddb_attach,	/* submessage generator */
		30,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SM_MDDB_ATTACH
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_sm_mddb_attach,	/* message handler */
		NULL,			/* submessage generator */
		20,			/* timeout in seconds */
					/* creates mddbs */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_DB_DETACH
	 */
		MD_MSG_CLASS3,		/* message class */
		NULL,			/* detach mddb */
		mdmn_smgen_mddb_detach,	/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},
	{

	/*
	 * MD_MN_MSG_SM_MDDB_DETACH
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_sm_mddb_detach,	/* detach mddb */
		NULL,			/* submessage generator */
		5,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_DB_NEWSIDE
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_meta_db_newside, /* add new mddb side info */
		NULL, 			/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_DB_DELSIDE
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_meta_db_delside, /* delete mddb side info */
		NULL, 			/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_MD_ADDSIDE
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_meta_md_addside, /* add new md side info */
		NULL, 			/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_META_MD_DELSIDE
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_meta_md_delside, /* delete md side info */
		NULL, 			/* submessage generator */
		10,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_MDDB_OPTRECERR
	 * Message cannot fail unless node failure causes node panic
	 */
		MD_MSG_CLASS3,		/* message class */
		mdmn_do_mddb_optrecerr,	/* fix opt rec mddb */
		NULL, 			/* submessage generator */
		3,			/* timeout in seconds */
		UINT_MAX, 2,		/* class busy retry / time delta */
		10, 100			/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_ABORT
	 */
		MD_MSG_CLASS0,		/* special message class */
		mdmn_do_dummy,		/* dummy handler */
		NULL, 			/* submessage generator */
		1,			/* timeout in seconds */
		0, 0,			/* No retries for class busy */
		0, 0			/* No retries for comm fail */
	},

	{
	/*
	 * MD_MN_MSG_STATE_UPDATE_RESWR2
	 * Update the state of a mirror component, called if during the updates
	 * of the watermarks for a softpartition, an IO error on a submirror
	 * occurs.  Need to have a class different from CLASS1, otherwise we
	 * deadlock with the command that is currently being processed
	 * (metainit/metaclear/metattach/metarecover)
	 *
	 * And we may actually use a class different than CLASS1 because this
	 * can only happen when a metainit or similar is called, and in that
	 * case all potential metadb or metaset commands are blocked anyway.
	 * Besides the different class it does exactly what
	 * MD_MN_MSG_STATE_UPDATE_RESWR would do
	 */
		MD_MSG_CLASS3,	/* message class */
		mdmn_do_state_upd_reswr, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_STATE_UPDATE2
	 * Like MD_MN_MSG_STATE_UPDATE only using a different class.
	 * See comment for MD_MN_MSG_STATE_UPDATE_RESWR2
	 */
		MD_MSG_CLASS3,	/* message class */
		NULL,		 /* message handler */
		mdmn_smgen_state_upd,	/* submessage generator */
		16,		/* SUSPEND_WRITES + STATE_UPDATE_RESWR */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_ALLOCATE_HOTSPARE2
	 * Like MD_MN_MSG_ALLOCATE_HOTSPARE only using a different class.
	 * See comment for MD_MN_MSG_STATE_UPDATE_RESWR2
	 */
		MD_MSG_CLASS3,	/* message class */
		mdmn_do_allocate_hotspare, /* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_IOCSET
	 * Send IOCSET ioctl to create a soft part
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_iocset,		/* create softpart */
		NULL, 			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2, 		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SP_SETSTAT
	 * Update the status of a softpart
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_sp_setstat,	/* create softpart */
		NULL, 			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2, 		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_ADDKEYNAME
	 * Add a key to the namespace
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_addkeyname,	/* add key */
		NULL, 			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2, 		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SP_DELKEYNAME
	 * Remove a key from the namespace
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_delkeyname,	/* delete key */
		NULL, 			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2, 		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_GET_TSTATE
	 * Get ui_tstate for a metadevice from the master. Used to get ABR
	 * state from the master node.
	 */
		MD_MSG_CLASS2,		/* message class */
		mdmn_do_get_tstate,	/* get tstate */
		NULL,			/* submessage generator */
		5,			/* times out in 5 secs */
		UINT_MAX, 10, 		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_GET_MIRROR_STATE
	 * Get submirror state for specified submirror from master node.
	 * Used to synchronise initial resync state across a cluster.
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_get_mirstate,	/* get smstate */
		NULL,			/* submessage generator */
		5,			/* times out in 5 secs */
		UINT_MAX, 10,		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SP_SETSTAT2
	 * Update the status of a softpart. Used for propagating an error from
	 * the soft-part sp_error() routine
	 */
		MD_MSG_CLASS4,		/* message class */
		mdmn_do_sp_setstat,	/* update softpart state */
		NULL,			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2, 		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_SETSYNC
	 * Start a resync thread for the specified mirror
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_setsync,	/* message handler */
		NULL, 			/* submessage generator */
		90,			/* timeout in seconds */
		10000, 2,		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_POKE_HOTSPARES
	 * Call poke_hotspares()
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_poke_hotspares,	/* message handler */
		NULL, 		/* submessage generator */
		8,		/* timeout in seconds */
		UINT_MAX, 10,	/* class busy retry / time delta */
		UINT_MAX, 100	/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_ADDMDNAME
	 * Add metadevice name into replica
	 */
		MD_MSG_CLASS1,		/* message class */
		mdmn_do_addmdname,	/* add metadevice name */
		NULL,			/* submessage generator */
		90,			/* times out in 90 secs */
		10000, 2,		/* class busy retry / time delta */
		10, 1000		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RR_DIRTY
	 * Mark given range of un_dirty_bm as dirty
	 */
		MD_MSG_CLASS2,		/* message class */
		mdmn_do_mark_dirty,	/* message handler */
		NULL,			/* submessage generator */
		8,			/* timeout in seconds */
		UINT_MAX, 10,		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},

	{
	/*
	 * MD_MN_MSG_RR_CLEAN
	 * Mark given range of un_dirty_bm as clean
	 */
		MD_MSG_CLASS2,		/* message class */
		mdmn_do_mark_clean,	/* message handler */
		NULL,			/* submessage generator */
		8,			/* timeout in seconds */
		UINT_MAX, 10,		/* class busy retry / time delta */
		UINT_MAX, 100		/* comm fail retry / time delta */
	},
};
