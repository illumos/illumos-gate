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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread.h>
#include "meta.h"
#include "mdmn_subr.h"

extern int mdmn_init_set(set_t setno, int todo);

uint_t mdmn_busy[MD_MAXSETS][MD_MN_NCLASSES];
mutex_t	mdmn_busy_mutex[MD_MAXSETS];
cond_t	mdmn_busy_cv[MD_MAXSETS];


/* the wakeup table for the initiator's side */
mdmn_wti_t mdmn_initiator_table[MD_MAXSETS][MD_MN_NCLASSES];

/* the wakeup table for the master */
mdmn_wtm_t mdmn_master_table[MD_MAXSETS][MD_MN_NCLASSES];

/* List of licensed ip addresses */
licensed_ip_t   licensed_nodes[NNODES];

/* speed up the search for licensed ip addresses */
md_mn_nodeid_t maxlicnodes = 0; /* 0 is not a valid node ID */

/*
 * Check if a given set/class combination is currently in use
 * If in use, returns TRUE
 * Otherwise returns FALSE
 *
 * Must be called with mdmn_busy_mutex held
 */
bool_t
mdmn_is_class_busy(set_t setno, md_mn_msgclass_t class)
{
	if (mdmn_busy[setno][class] & MDMN_BUSY) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 * Mark a given set/class combination as currently in use
 * If the class was already in use, returns FALSE
 * Otherwise returns TRUE
 *
 * So mdmn_mark_class_busy can be used like
 * if (mdmn_mark_class_busy(setno, class) == FALSE)
 * 	failure;
 * else
 *	success;
 *
 * Must be called with mdmn_busy_mutex held
 */
bool_t
mdmn_mark_class_busy(set_t setno, md_mn_msgclass_t class)
{
	if (mdmn_busy[setno][class] & MDMN_BUSY) {
		return (FALSE);
	} else {
		mdmn_busy[setno][class] |= MDMN_BUSY;
		commd_debug(MD_MMV_MISC, "busy: set=%d, class=%d\n",
		    setno, class);
		return (TRUE);
	}
}

/*
 * Mark a given set/class combination as currently available
 * Always succeeds, thus void.
 *
 * If this class is marked MDMN_SUSPEND_ALL, we are in the middle of
 * draining all classes of this set.
 * We have to mark class+1 as MDMN_SUSPEND_ALL too.
 * If class+2 wasn't busy, we proceed with class+2, and so on
 * If any class is busy, we return.
 * Then the drain process will be continued by the mdmn_mark_class_unbusy() of
 * that busy class
 */
void
mdmn_mark_class_unbusy(set_t setno, md_mn_msgclass_t class)
{
	commd_debug(MD_MMV_MISC, "unbusy: set=%d, class=%d\n", setno, class);
	mdmn_busy[setno][class] &= ~MDMN_BUSY;
	/* something changed, inform threads waiting for that */
	cond_signal(&mdmn_busy_cv[setno]);

	if ((mdmn_busy[setno][class] & MDMN_SUSPEND_ALL) == 0) {
		return;
	}

	while (++class < MD_MN_NCLASSES) {
		commd_debug(MD_MMV_MISC,
		    "unbusy: suspending set=%d, class=%d\n", setno, class);
		if (mdmn_mark_class_suspended(setno, class, MDMN_SUSPEND_ALL)
		    == MDMNE_SET_NOT_DRAINED) {
			break;
		}
	}

}


/*
 * Check if a given set/class combination is locked.
 */
bool_t
mdmn_is_class_locked(set_t setno, md_mn_msgclass_t class)
{
	if (mdmn_busy[setno][class] & MDMN_LOCKED) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 * Mark a given set/class combination as locked.
 * No checking is done here, so routine can be void.
 * Locking a locked set/class is ok.
 *
 * Must be called with mdmn_busy_mutex held
 */
void
mdmn_mark_class_locked(set_t setno, md_mn_msgclass_t class)
{
	mdmn_busy[setno][class] |= MDMN_LOCKED;
}

/*
 * Mark a given set/class combination as unlocked.
 * No checking is done here, so routine can be void.
 * Unlocking a unlocked set/class is ok.
 *
 * Must be called with mdmn_busy_mutex held
 */
void
mdmn_mark_class_unlocked(set_t setno, md_mn_msgclass_t class)
{
	mdmn_busy[setno][class] &= ~MDMN_LOCKED;
}

/*
 * Suspend a set/class combination
 *
 * If called during draining all classes of a set susptype is MDMN_SUSPEND_ALL.
 * If only one class is about to be drained susptype is MDMN_SUSPEND_1.
 *
 * Returns:
 *	MDMNE_ACK if there are no outstanding messages
 *	MDMNE_SET_NOT_DRAINED otherwise
 *
 * Must be called with mdmn_busy_mutex held for this set.
 */
int
mdmn_mark_class_suspended(set_t setno, md_mn_msgclass_t class, uint_t susptype)
{
	/*
	 * We use the mdmn_busy array to mark this set is suspended.
	 */
	mdmn_busy[setno][class] |= susptype;

	/*
	 * If there are outstanding messages for this set/class we
	 * return MDMNE_SET_NOT_DRAINED, otherwise we return MDMNE_ACK
	 */
	if (mdmn_is_class_busy(setno, class) == TRUE) {
		return (MDMNE_SET_NOT_DRAINED);
	}
	return (MDMNE_ACK);
}

/*
 * Resume operation for a set/class combination after it was
 * previously suspended
 *
 * If called from mdmn_comm_resume_svc_1 to resume _one_ specific class
 * then susptype will be MDMN_SUSPEND_1
 * Otherwise to resume all classes of one set,
 * then susptype equals (MDMN_SUSPEND_ALL | MDMN_SUSPEND_1)
 *
 * Always succeeds, thus void.
 *
 * Must be called with mdmn_busy_mutex held for this set.
 */
void
mdmn_mark_class_resumed(set_t setno, md_mn_msgclass_t class, uint_t susptype)
{
	/* simply the reverse operation to mdmn_mark_set_drained() */
	mdmn_busy[setno][class] &= ~susptype;
}

/*
 * Check if a drain command was issued for this set/class combination.
 *
 * Must be called with mdmn_busy_mutex held for this set.
 */
bool_t
mdmn_is_class_suspended(set_t setno, md_mn_msgclass_t class)
{
	if (mdmn_busy[setno][class] & (MDMN_SUSPEND_ALL | MDMN_SUSPEND_1)) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 * Put a result into the wakeup table for the master
 * It's ensured that the msg id from the master_table entry and from
 * result are matching
 */
void
mdmn_set_master_table_res(set_t setno, md_mn_msgclass_t class,
				md_mn_result_t  *res)
{
	mdmn_master_table[setno][class].wtm_result = res;
}
void
mdmn_set_master_table_id(set_t setno, md_mn_msgclass_t class, md_mn_msgid_t *id)
{
	MSGID_COPY(id, &(mdmn_master_table[setno][class].wtm_id));
}

void
mdmn_set_master_table_addr(set_t setno, md_mn_msgclass_t class,
    md_mn_nodeid_t nid)
{
	mdmn_master_table[setno][class].wtm_addr = nid;
}


md_mn_result_t *
mdmn_get_master_table_res(set_t setno, md_mn_msgclass_t class)
{
	return (mdmn_master_table[setno][class].wtm_result);
}

void
mdmn_get_master_table_id(set_t setno, md_mn_msgclass_t class, md_mn_msgid_t *id)
{
	MSGID_COPY(&(mdmn_master_table[setno][class].wtm_id), id);
}

cond_t *
mdmn_get_master_table_cv(set_t setno, md_mn_msgclass_t class)
{
	return (&(mdmn_master_table[setno][class].wtm_cv));
}

mutex_t *
mdmn_get_master_table_mx(set_t setno, md_mn_msgclass_t class)
{
	return (&(mdmn_master_table[setno][class].wtm_mx));
}

md_mn_nodeid_t
mdmn_get_master_table_addr(set_t setno, md_mn_msgclass_t class)
{
	return (mdmn_master_table[setno][class].wtm_addr);
}



/* here come the functions dealing with the wakeup table for the initiators */


void
mdmn_register_initiator_table(set_t setno, md_mn_msgclass_t class,
    md_mn_msg_t *msg, SVCXPRT *transp)
{
	uint_t nnodes	= set_descriptor[setno]->sd_mn_numnodes;
	time_t timeout	= mdmn_get_timeout(msg->msg_type);


	MSGID_COPY(&(msg->msg_msgid),
	    &(mdmn_initiator_table[setno][class].wti_id));
	mdmn_initiator_table[setno][class].wti_transp = transp;
	mdmn_initiator_table[setno][class].wti_args = (char *)msg;

	/*
	 * as the point in time where we want to be guaranteed to be woken up
	 * again, we chose the
	 * current time + nnodes times the timeout value for the message type
	 */
	mdmn_initiator_table[setno][class].wti_time =
	    time((time_t *)NULL) + (nnodes * timeout);
}

/*
 * If the set/class combination is currently busy, return MDMNE_CLASS_BUSY
 * Otherwise return MDMNE_ACK
 */
int
mdmn_check_initiator_table(set_t setno, md_mn_msgclass_t class)
{
	if ((mdmn_initiator_table[setno][class].wti_id.mid_nid == ~0u) &&
	    (mdmn_initiator_table[setno][class].wti_transp == (SVCXPRT *)NULL))
		return (MDMNE_ACK);
	return (MDMNE_CLASS_BUSY);
}

/*
 * Remove an entry from the initiator table entirely,
 * This must be done with mutex held.
 */
void
mdmn_unregister_initiator_table(set_t setno, md_mn_msgclass_t class)
{
	mdmn_initiator_table[setno][class].wti_id.mid_nid = ~0u;
	mdmn_initiator_table[setno][class].wti_id.mid_time = 0LL;
	mdmn_initiator_table[setno][class].wti_transp = (SVCXPRT *)NULL;
	mdmn_initiator_table[setno][class].wti_args = (char *)0;
	mdmn_initiator_table[setno][class].wti_time = (time_t)0;
}

void
mdmn_get_initiator_table_id(set_t setno, md_mn_msgclass_t class,
				md_mn_msgid_t *mid)
{
	MSGID_COPY(&(mdmn_initiator_table[setno][class].wti_id), mid);
}

SVCXPRT *
mdmn_get_initiator_table_transp(set_t setno, md_mn_msgclass_t class)
{
	return (mdmn_initiator_table[setno][class].wti_transp);
}

char *
mdmn_get_initiator_table_args(set_t setno, md_mn_msgclass_t class)
{
	return (mdmn_initiator_table[setno][class].wti_args);
}

mutex_t *
mdmn_get_initiator_table_mx(set_t setno, md_mn_msgclass_t class)
{
	return (&(mdmn_initiator_table[setno][class].wti_mx));
}

time_t
mdmn_get_initiator_table_time(set_t setno, md_mn_msgclass_t class)
{
	return (mdmn_initiator_table[setno][class].wti_time);
}

extern uint_t	md_commd_global_verb;	/* global bitmask for debug classes */
extern FILE	*commdout;		/* debug output file for the commd */
extern hrtime_t __savetime;


/*
 * Print debug messages to the terminal or to syslog
 * commd_debug(MD_MMV_SYSLOG,....) is always printed (and always via syslog),
 * even if md_commd_global_verb is zero.
 *
 * Otherwise the correct bit must be set in the bitmask md_commd_global_verb
 */
void
commd_debug(uint_t debug_class, const char *message, ...)
{
	va_list ap;

	/* Is this a message for syslog? */
	if (debug_class == MD_MMV_SYSLOG) {

		va_start(ap, message);
		(void) vsyslog(LOG_WARNING, message, ap);
		va_end(ap);
	} else {
		/* Is this debug_class set in the global verbosity state?  */
		if ((md_commd_global_verb & debug_class) == 0) {
			return;
		}
		/* Is our output file already functioning? */
		if (commdout == NULL) {
			return;
		}
		/* Are timestamps activated ? */
		if (md_commd_global_verb & MD_MMV_TIMESTAMP) {
			/* print time since last TRESET in usecs */
			fprintf(commdout, "[%s]",
			    meta_print_hrtime(gethrtime() - __savetime));
		}
		/* Now print the real message */
		va_start(ap, message);
		(void) vfprintf(commdout, message, ap);
		va_end(ap);
	}
}


void
dump_hex(uint_t debug_class, unsigned int *x, int cnt)
{
	cnt /= sizeof (unsigned int);
	while (cnt--) {
		commd_debug(debug_class, "0x%8x ", *x++);
		if (cnt % 4)
			continue;
		commd_debug(debug_class, "\n");
	}
	commd_debug(debug_class, "\n");
}

/* debug output: dump a message */
void
dump_msg(uint_t dbc, char *prefix, md_mn_msg_t *msg)
{
	commd_debug(dbc, "%s &msg	= 0x%x\n", prefix, (int)msg);
	commd_debug(dbc, "%s ID	= (%d, 0x%llx-%d)\n", prefix,
	    MSGID_ELEMS(msg->msg_msgid));
	commd_debug(dbc, "%s sender	= %d\n", prefix, msg->msg_sender);
	commd_debug(dbc, "%s flags	= 0x%x\n", prefix, msg->msg_flags);
	commd_debug(dbc, "%s setno	= %d\n", prefix, msg->msg_setno);
	commd_debug(dbc, "%s recipient  = %d\n", prefix, msg->msg_recipient);
	commd_debug(dbc, "%s type	= %d\n", prefix, msg->msg_type);
	commd_debug(dbc, "%s size	= %d\n", prefix, msg->msg_event_size);
	if (msg->msg_event_size) {
		commd_debug(dbc, "%s data	=\n", prefix);
		dump_hex(dbc, (unsigned int *)(void *)msg->msg_event_data,
		    msg->msg_event_size);
	}
}

/* debug output: dump a result structure */
void
dump_result(uint_t dbc, char *prefix, md_mn_result_t *res)
{
	commd_debug(dbc, "%s &res	= 0x%x\n", prefix, (int)res);
	commd_debug(dbc, "%s ID	= (%d, 0x%llx-%d)\n", prefix,
	    MSGID_ELEMS(res->mmr_msgid));
	commd_debug(dbc, "%s setno	= %d\n", prefix, res->mmr_setno);
	commd_debug(dbc, "%s type	= %d\n", prefix, res->mmr_msgtype);
	commd_debug(dbc, "%s flags	= 0x%x\n", prefix, res->mmr_flags);
	commd_debug(dbc, "%s comm_state= %d\n", prefix, res->mmr_comm_state);
	commd_debug(dbc, "%s exitval	= %d\n", prefix, res->mmr_exitval);
	commd_debug(dbc, "%s out_size	= %d\n", prefix, res->mmr_out_size);
	if (res->mmr_out_size)
		commd_debug(dbc, "%s out	= %s\n", prefix, res->mmr_out);
	commd_debug(dbc, "%s err_size	= %d\n", prefix, res->mmr_err_size);
	if (res->mmr_err_size)
		commd_debug(dbc, "%s err	= %s\n", prefix, res->mmr_err);
}


/*
 * Here we find out, where to store or find the results for a given msg.
 *
 * Per set we have a pointer to a three dimensional array:
 * mct[set] -> mct_mce[NNODES][MD_MN_NCLASSES][MAX_SUBMESSAGES]
 * So, for every possible node and for every possible class we can store
 * MAX_SUBMESSAGES results.
 * the way to find the correct index is
 *	submessage +
 *	class * MAX_SUBMESSAGES +
 *	nodeid * MAX_SUBMESSAGES * MD_MN_NCLASSES.
 *
 * To find the correct address the index has to be multiplied
 * by the size of one entry.
 */
static md_mn_mce_t *
mdmn_get_mce_by_msg(md_mn_msg_t *msg)
{
	set_t	setno = msg->msg_setno;
	int	nodeid = msg->msg_msgid.mid_nid;
	int	submsg = msg->msg_msgid.mid_smid;
	int	mct_index;
	off_t	mct_offset;
	md_mn_msgclass_t class;

	if (mct[setno] != NULL) {
		if (mdmn_init_set(setno, MDMN_SET_MCT) != 0) {
			return ((md_mn_mce_t *)MDMN_MCT_ERROR);
		}
	}

	if (submsg == 0) {
		class = mdmn_get_message_class(msg->msg_type);
	} else {
		class = msg->msg_msgid.mid_oclass;
	}

	mct_index = submsg + class * MAX_SUBMESSAGES +
	    nodeid * MAX_SUBMESSAGES * MD_MN_NCLASSES;

	mct_offset = mct_index * sizeof (md_mn_mce_t);

	/* LINTED Pointer alignment */
	return ((md_mn_mce_t *)((caddr_t)(mct[setno]) + mct_offset));

	/*
	 * the lint clean version would be:
	 * return (&(mct[setno]->mct_mce[0][0][0]) + mct_index);
	 * :-)
	 */
}

/*
 * mdmn_mark_completion(msg, result, flag)
 * Stores the result of this message into the mmaped memory MCT[setno]
 * In case the same message comes along a second time we will know that
 * this message has already been processed and we can deliver the
 * results immediately.
 *
 * Before a message handler is called, the message in the MCT is flagged
 * as currently being processed (flag == MDMN_MCT_IN_PROGRESS).
 * This we need so we don't start a second handler for the same message.
 *
 * After a message handler is completed, this routine is called with
 * flag == MDMN_MCT_DONE and the appropriate result that we store in the MCT.
 * As MCT[setno] is memory mapped to disks, this information is persistent
 * even across a crash of the commd.
 * It doesn't have to be persistent across a reboot, though.
 *
 * Returns MDMN_MCT_DONE in case of success
 * Returns MDMN_MCT_ERROR in case of error creating the mct
 */
int
mdmn_mark_completion(md_mn_msg_t *msg, md_mn_result_t *result, uint_t flag)
{
	md_mn_mce_t	*mce;
	uint_t		offset_in_page;

	mce = mdmn_get_mce_by_msg(msg);
	if (mce == (md_mn_mce_t *)-1) {
		return (MDMN_MCT_ERROR);
	}
	offset_in_page = (uint_t)(caddr_t)mce % sysconf(_SC_PAGESIZE);

	memset(mce, 0, sizeof (md_mn_mce_t));

	MSGID_COPY(&msg->msg_msgid, &mce->mce_result.mmr_msgid);
	if (flag == MDMN_MCT_IN_PROGRESS) {
		mce->mce_flags = MDMN_MCT_IN_PROGRESS;
		goto mmc_out;
	}

	/*
	 * In case the message flags indicate that the result should not be
	 * stored in the MCT, we return a MDMN_MCT_NOT_DONE,
	 * so the message will be processed at any rate,
	 * even if we process this message twice.
	 * this makes sense if the result of the message is a dynamic status
	 * and might have changed meanwhile.
	 */
	if (msg->msg_flags & MD_MSGF_NO_MCT) {
		return (MDMN_MCT_DONE);
	}

	/* This msg is no longer in progress */
	mce->mce_flags = MDMN_MCT_DONE;

	mce->mce_result.mmr_msgtype	    = result->mmr_msgtype;
	mce->mce_result.mmr_setno	    = result->mmr_setno;
	mce->mce_result.mmr_flags	    = result->mmr_flags;
	mce->mce_result.mmr_sender	    = result->mmr_sender;
	mce->mce_result.mmr_failing_node    = result->mmr_failing_node;
	mce->mce_result.mmr_comm_state	    = result->mmr_comm_state;
	mce->mce_result.mmr_exitval	    = result->mmr_exitval;

	/* if mmr_exitval is zero, we store stdout, otherwise stderr */
	if (result->mmr_exitval == 0) {
		if (result->mmr_out_size > 0) {
			memcpy(mce->mce_data, result->mmr_out,
			    result->mmr_out_size);
			mce->mce_result.mmr_out_size = result->mmr_out_size;
		}
	} else {
		if (result->mmr_err_size > 0) {
			mce->mce_result.mmr_err_size = result->mmr_err_size;
			memcpy(mce->mce_data, result->mmr_err,
			    result->mmr_err_size);
		}
	}

	dump_result(MD_MMV_PROC_S, "mdmn_mark_completion1", result);

mmc_out:
	/* now flush this entry to disk */
	msync((caddr_t)mce - offset_in_page,
	    sizeof (md_mn_mce_t) + offset_in_page, MS_SYNC);
	return (MDMN_MCT_DONE);
}

/*
 * mdmn_check_completion(msg, resultp)
 * checks if msg has already been processed on this node, and if so copies
 * the stored result to resultp.
 *
 * returns MDMN_MCT_DONE and the result filled out acurately in case the
 *		msg has already been processed before
 * returns MDMN_MCT_NOT_DONE if the message has not been processed before
 * returns MDMN_MCT_IN_PROGRESS if the message is currently being processed
 *	This can only occur on a slave node.
 * return MDMN_MCT_ERROR in case of error creating the mct
 */
int
mdmn_check_completion(md_mn_msg_t *msg, md_mn_result_t *result)
{
	md_mn_mce_t	*mce;
	size_t		outsize;
	size_t		errsize;

	mce = mdmn_get_mce_by_msg(msg);
	if (mce == (md_mn_mce_t *)MDMN_MCT_ERROR) {
		return (MDMN_MCT_ERROR); /* what to do in that case ? */
	}
	if (MSGID_CMP(&(msg->msg_msgid), &(mce->mce_result.mmr_msgid))) {
		/* is the message completed, or in progress? */
		if (mce->mce_flags & MDMN_MCT_IN_PROGRESS) {
			return (MDMN_MCT_IN_PROGRESS);
		}
		/*
		 * See comment on MD_MSGF_NO_MCT above, if this flag is set
		 * for a message no result was stored and so the message has
		 * to be processed no matter if this is the 2nd time then.
		 */
		if (msg->msg_flags & MD_MSGF_NO_MCT) {
			return (MDMN_MCT_NOT_DONE);
		}

		/* Paranoia check: mce_flags must be MDMN_MCT_DONE here */
		if ((mce->mce_flags & MDMN_MCT_DONE) == 0) {
			commd_debug(MD_MMV_ALL,
			    "mdmn_check_completion: msg not done and not in "
			    "progress! ID = (%d, 0x%llx-%d)\n",
			    MSGID_ELEMS(msg->msg_msgid));
			return (MDMN_MCT_NOT_DONE);
		}
		/*
		 * Already processed.
		 * Copy saved results data;
		 * return only a pointer to any output.
		 */
		MSGID_COPY(&(mce->mce_result.mmr_msgid), &result->mmr_msgid);
		result->mmr_msgtype	    = mce->mce_result.mmr_msgtype;
		result->mmr_setno	    = mce->mce_result.mmr_setno;
		result->mmr_flags	    = mce->mce_result.mmr_flags;
		result->mmr_sender	    = mce->mce_result.mmr_sender;
		result->mmr_failing_node    = mce->mce_result.mmr_failing_node;
		result->mmr_comm_state	    = mce->mce_result.mmr_comm_state;
		result->mmr_exitval	    = mce->mce_result.mmr_exitval;
		result->mmr_err		    = NULL;
		result->mmr_out		    = NULL;
		outsize = result->mmr_out_size = mce->mce_result.mmr_out_size;
		errsize = result->mmr_err_size = mce->mce_result.mmr_err_size;
		/*
		 * if the exit val is zero only stdout was stored (if any)
		 * otherwise only stderr was stored (if any)
		 */
		if (result->mmr_exitval == 0) {
			if (outsize != 0) {
				result->mmr_out = Zalloc(outsize);
				memcpy(result->mmr_out, mce->mce_data, outsize);
			}
		} else {
			if (errsize != 0) {
				result->mmr_err = Zalloc(errsize);
				memcpy(result->mmr_err, mce->mce_data, errsize);
			}
		}
		commd_debug(MD_MMV_MISC,
		    "mdmn_check_completion: msg already processed \n");
		dump_result(MD_MMV_MISC, "mdmn_check_completion", result);
		return (MDMN_MCT_DONE);
	}
	commd_debug(MD_MMV_MISC,
	    "mdmn_check_completion: msg not yet processed\n");
	return (MDMN_MCT_NOT_DONE);
}



/*
 * check_license(rqstp, chknid)
 *
 * Is this RPC request sent from a licensed host?
 *
 * If chknid is non-zero, the caller of check_license() knows the ID of
 * the sender. Then we check just the one entry of licensed_nodes[]
 *
 * If chknid is zero, the sender is not known. In that case the sender must be
 * the local node.
 *
 * If the host is licensed, return TRUE, else return FALSE
 */
bool_t
check_license(struct svc_req *rqstp, md_mn_nodeid_t chknid)
{
	char		buf[INET6_ADDRSTRLEN];
	void		*caller = NULL;
	in_addr_t	caller_ipv4;
	in6_addr_t	caller_ipv6;
	struct sockaddr	*ca;


	ca = (struct sockaddr *)(void *)svc_getrpccaller(rqstp->rq_xprt)->buf;

	if (ca->sa_family == AF_INET) {
		caller_ipv4 =
		    ((struct sockaddr_in *)(void *)ca)->sin_addr.s_addr;
		caller = (void *)&caller_ipv4;

		if (chknid == 0) {
			/* check against local node */
			if (caller_ipv4 == htonl(INADDR_LOOPBACK)) {
				return (TRUE);

			}
		} else {
			/* check against one specific node */
			if ((caller_ipv4 == licensed_nodes[chknid].lip_ipv4) &&
			    (licensed_nodes[chknid].lip_family == AF_INET)) {
				return (TRUE);
			} else {
				commd_debug(MD_MMV_MISC,
				    "Bad attempt from %x ln[%d]=%x\n",
				    caller_ipv4, chknid,
				    licensed_nodes[chknid].lip_ipv4);
			}
		}
	} else if (ca->sa_family == AF_INET6) {
		caller_ipv6 = ((struct sockaddr_in6 *)(void *)ca)->sin6_addr;
		caller = (void *)&caller_ipv6;

		if (chknid == 0) {
			/* check against local node */
			if (IN6_IS_ADDR_LOOPBACK(&caller_ipv6)) {
				return (TRUE);

			}
		} else {
			/* check against one specific node */
			if (IN6_ARE_ADDR_EQUAL(&caller_ipv6,
			    &(licensed_nodes[chknid].lip_ipv6)) &&
			    (licensed_nodes[chknid].lip_family == AF_INET6)) {
				return (TRUE);
			}
		}
	}
	/* if  we are here, we were contacted by an unlicensed node */
	commd_debug(MD_MMV_SYSLOG,
	    "Bad attempt to contact rpc.mdcommd from %s\n",
	    caller ?
	    inet_ntop(ca->sa_family, caller, buf, INET6_ADDRSTRLEN) :
	    "unknown");

	return (FALSE);
}

/*
 * Add a node to the list of licensed nodes.
 *
 * Only IPv4 is currently supported.
 * for IPv6, we need to change md_mnnode_desc.
 */
void
add_license(md_mnnode_desc *node)
{
	md_mn_nodeid_t nid = node->nd_nodeid;
	char		buf[INET6_ADDRSTRLEN];

	/*
	 * If this node is not yet licensed, do it now.
	 * For now only IPv4 addresses are supported.
	 */
	commd_debug(MD_MMV_MISC, "add_lic(%s): ln[%d]=%s, lnc[%d]=%d\n",
	    node->nd_priv_ic, nid,
	    inet_ntop(AF_INET, (void *)&licensed_nodes[nid].lip_ipv4,
	    buf, INET6_ADDRSTRLEN), nid, licensed_nodes[nid].lip_cnt);

	if (licensed_nodes[nid].lip_ipv4 == (in_addr_t)0) {
		licensed_nodes[nid].lip_family = AF_INET; /* IPv4 */
		licensed_nodes[nid].lip_ipv4 = inet_addr(node->nd_priv_ic);
		/* keep track of the last entry for faster search */
		if (nid > maxlicnodes)
			maxlicnodes = nid;

	}
	/* in any case bump up the reference count */
	licensed_nodes[nid].lip_cnt++;
}

/*
 * lower the reference count for one node.
 * If that drops to zero, remove the node from the list of licensed nodes
 *
 * Only IPv4 is currently supported.
 * for IPv6, we need to change md_mnnode_desc.
 */
void
rem_license(md_mnnode_desc *node)
{
	md_mn_nodeid_t nid = node->nd_nodeid;
	char		buf[INET6_ADDRSTRLEN];

	commd_debug(MD_MMV_MISC, "rem_lic(%s): ln[%d]=%s, lnc[%d]=%d\n",
	    node->nd_priv_ic, nid,
	    inet_ntop(AF_INET, (void *)&licensed_nodes[nid].lip_ipv4, buf,
	    INET6_ADDRSTRLEN), nid, licensed_nodes[nid].lip_cnt);

	assert(licensed_nodes[nid].lip_cnt > 0);

	/*
	 * If this was the last reference to that node, it's license expires
	 * For now only IPv4 addresses are supported.
	 */
	if (--licensed_nodes[nid].lip_cnt == 0) {
		licensed_nodes[nid].lip_ipv4 = (in_addr_t)0;
	}
}
