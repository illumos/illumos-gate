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
 *	Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#include <sys/cred.h>
#include <sys/kstat.h>
#include <sys/list.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>

#include <nfs/nfs4_clnt.h>
#include <nfs/rnode4.h>

/*
 * Recovery kstats
 */
typedef struct rkstat {
	kstat_named_t	badhandle;
	kstat_named_t	badowner;
	kstat_named_t	clientid;
	kstat_named_t	dead_file;
	kstat_named_t	delay;
	kstat_named_t	fail_relock;
	kstat_named_t	file_diff;
	kstat_named_t	no_grace;
	kstat_named_t	not_responding;
	kstat_named_t	opens_changed;
	kstat_named_t	siglost;
	kstat_named_t	unexp_action;
	kstat_named_t	unexp_errno;
	kstat_named_t	unexp_status;
	kstat_named_t	wrongsec;
	kstat_named_t	lost_state_bad_op;
} rkstat_t;

static rkstat_t rkstat_template = {
	{ "badhandle",		KSTAT_DATA_ULONG },
	{ "badowner",		KSTAT_DATA_ULONG },
	{ "clientid",		KSTAT_DATA_ULONG },
	{ "dead_file",		KSTAT_DATA_ULONG },
	{ "delay",		KSTAT_DATA_ULONG },
	{ "fail_relock",	KSTAT_DATA_ULONG },
	{ "file_diff",		KSTAT_DATA_ULONG },
	{ "no_grace",		KSTAT_DATA_ULONG },
	{ "not_responding",	KSTAT_DATA_ULONG },
	{ "opens_changed",	KSTAT_DATA_ULONG },
	{ "siglost",		KSTAT_DATA_ULONG },
	{ "unexp_action",	KSTAT_DATA_ULONG },
	{ "unexp_errno",	KSTAT_DATA_ULONG },
	{ "unexp_status",	KSTAT_DATA_ULONG },
	{ "wrongsec",		KSTAT_DATA_ULONG },
	{ "bad_op",		KSTAT_DATA_ULONG },
};

/* maximum number of messages allowed on the mi's mi_msg_list */
int nfs4_msg_max = NFS4_MSG_MAX;
#define	DEFAULT_LEASE	180

/*
 * Sets the appropiate fields of "ep", given "id" and various parameters.
 * Assumes that ep's fields have been initialized to zero/null, except for
 * re_type and mount point info, which are already set.
 */
static void
set_event(nfs4_event_type_t id, nfs4_revent_t *ep, mntinfo4_t *mi,
    rnode4_t *rp1, rnode4_t *rp2, uint_t count, pid_t pid, nfsstat4 nfs4_error,
    char *server1, char *why, nfs4_tag_type_t tag1, nfs4_tag_type_t tag2,
    seqid4 seqid1, seqid4 seqid2)
{
	int len;

	switch (id) {
	case RE_BAD_SEQID:
		ep->re_mi = mi;

		/* bad seqid'd file <path/component name> */
		if (rp1 && rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;

		/* for LOCK/LOCKU */
		ep->re_pid = pid;

		ep->re_stat4 = nfs4_error;
		ep->re_tag1 = tag1;
		ep->re_tag2 = tag2;
		ep->re_seqid1 = seqid1;
		ep->re_seqid2 = seqid2;
		break;
	case RE_BADHANDLE:
		ASSERT(rp1 != NULL);

		/* dead file <path/component name> */
		if (rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;
		break;
	case RE_CLIENTID:
		ep->re_mi = mi;

		/* the error we failed with */
		ep->re_uint = count;
		ep->re_stat4 = nfs4_error;
		break;
	case RE_DEAD_FILE:
		ASSERT(rp1 != NULL);

		/* dead file <path/component name> */
		if (rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;

		/* why the file got killed */
		if (why) {
			len = strlen(why);
			ep->re_char2 = kmem_alloc(len + 1, KM_SLEEP);
			bcopy(why, ep->re_char2, len);
			ep->re_char2[len] = '\0';
		} else
			ep->re_char2 = NULL;

		ep->re_stat4 = nfs4_error;
		break;
	case RE_END:
		/* first rnode */
		if (rp1 && rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;

		/* second rnode */
		if (rp2 && rp2->r_svnode.sv_name)
			ep->re_char2 = fn_path(rp2->r_svnode.sv_name);
		else
			ep->re_char2 = NULL;
		ep->re_rp2 = rp2;

		ep->re_mi = mi;
		break;
	case RE_FAIL_RELOCK:
		ASSERT(rp1 != NULL);

		/* error on fail relock */
		ep->re_uint = count;

		/* process that failed */
		ep->re_pid = pid;

		/* nfs4 error */
		ep->re_stat4 = nfs4_error;

		/* file <path/component name> */
		if (rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;
		break;
	case RE_FAIL_REMAP_LEN:
		/* length of returned filehandle */
		ep->re_uint = count;
		break;
	case RE_FAIL_REMAP_OP:
		break;
	case RE_FAILOVER:
		/* server we're failing over to (if not picking original) */
		if (server1 != NULL) {
			len = strlen(server1);
			ep->re_char1 = kmem_alloc(len + 1, KM_SLEEP);
			bcopy(server1, ep->re_char1, len);
			ep->re_char1[len] = '\0';
		} else {
			ep->re_char1 = NULL;
		}
		break;
	case RE_FILE_DIFF:
		ASSERT(rp1 != NULL);

		/* dead file <path/component name> */
		if (rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;
		break;
	case RE_LOST_STATE:
		ep->re_uint = count;		/* op number */
		if (rp1 && rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;
		if (rp2 && rp2->r_svnode.sv_name)
			ep->re_char2 = fn_path(rp2->r_svnode.sv_name);
		else
			ep->re_char2 = NULL;
		ep->re_rp2 = rp2;
		break;
	case RE_OPENS_CHANGED:
		ep->re_mi = mi;

		/* original number of open files */
		ep->re_uint = count;
		/* new number of open files */
		ep->re_pid = pid;
		break;
	case RE_SIGLOST:
	case RE_SIGLOST_NO_DUMP:
		ASSERT(rp1 != NULL);

		/* file <path/component name> */
		if (rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;
		ep->re_pid = pid;
		ep->re_uint = count;
		ep->re_stat4 = nfs4_error;
		break;
	case RE_START:
		/* file <path/component name> */
		if (rp1 && rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;

		/* file <path/component name> */
		if (rp2 && rp2->r_svnode.sv_name)
			ep->re_char2 = fn_path(rp2->r_svnode.sv_name);
		else
			ep->re_char2 = NULL;
		ep->re_rp2 = rp2;

		ep->re_mi = mi;
		ep->re_uint = count;
		break;
	case RE_UNEXPECTED_ACTION:
	case RE_UNEXPECTED_ERRNO:
		/* the error that is unexpected */
		ep->re_uint = count;
		break;
	case RE_UNEXPECTED_STATUS:
		/* nfsstat4 error */
		ep->re_stat4 = nfs4_error;
		break;
	case RE_WRONGSEC:
		/* the error we failed with */
		ep->re_uint = count;

		/* file <path/component name> */
		if (rp1 && rp1->r_svnode.sv_name)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			ep->re_char1 = NULL;
		ep->re_rp1 = rp1;

		/* file <path/component name> */
		if (rp2 && rp2->r_svnode.sv_name)
			ep->re_char2 = fn_path(rp2->r_svnode.sv_name);
		else
			ep->re_char2 = NULL;
		ep->re_rp2 = rp2;
		break;
	case RE_LOST_STATE_BAD_OP:
		ep->re_uint = count;	/* the unexpected op */
		ep->re_pid = pid;
		ep->re_rp1 = rp1;
		if (rp1 != NULL && rp1->r_svnode.sv_name != NULL)
			ep->re_char1 = fn_path(rp1->r_svnode.sv_name);
		ep->re_rp2 = rp2;
		if (rp2 != NULL && rp2->r_svnode.sv_name != NULL)
			ep->re_char2 = fn_path(rp2->r_svnode.sv_name);
		break;
	case RE_REFERRAL:
		/* server we're being referred to */
		if (server1 != NULL) {
			len = strlen(server1);
			ep->re_char1 = kmem_alloc(len + 1, KM_SLEEP);
			bcopy(server1, ep->re_char1, len);
			ep->re_char1[len] = '\0';
		} else {
			ep->re_char1 = NULL;
		}
		break;
	default:
		break;
	}
}

/*
 * Sets the appropiate fields of the 'fact' for this 'id'.
 */
static void
set_fact(nfs4_fact_type_t id, nfs4_rfact_t *fp, nfsstat4 stat4,
    nfs4_recov_t raction, nfs_opnum4 op, bool_t reboot, int error,
    vnode_t *vp)
{
	rnode4_t *rp1;

	switch (id) {
	case RF_BADOWNER:
		fp->rf_op = op;
		fp->rf_reboot = reboot;
		fp->rf_stat4 = stat4;
		break;
	case RF_RENEW_EXPIRED:
		break;
	case RF_ERR:
		fp->rf_op = op;
		fp->rf_reboot = reboot;
		fp->rf_stat4 = stat4;
		fp->rf_action = raction;
		fp->rf_error = error;
		break;
	case RF_SRV_OK:
		break;
	case RF_SRV_NOT_RESPOND:
		break;
	case RF_SRVS_OK:
		break;
	case RF_SRVS_NOT_RESPOND:
		gethrestime(&fp->rf_time);
		break;
	case RF_DELMAP_CB_ERR:
		fp->rf_op = op;
		fp->rf_stat4 = stat4;

		rp1 = VTOR4(vp);
		fp->rf_rp1 = rp1;
		if (rp1 && rp1->r_svnode.sv_name)
			fp->rf_char1 = fn_path(rp1->r_svnode.sv_name);
		else
			fp->rf_char1 = NULL;
		break;
	case RF_SENDQ_FULL:
		break;
	default:
		zcmn_err(getzoneid(), CE_NOTE, "illegal fact %d", id);
		break;
	}
}

/*
 * Returns 1 if the event/fact is of a successful communication
 * from the server; 0 otherwise.
 */
static int
successful_comm(nfs4_debug_msg_t *msgp)
{
	if (msgp->msg_type == RM_EVENT) {
		switch (msgp->rmsg_u.msg_event.re_type) {
		case RE_BAD_SEQID:
		case RE_BADHANDLE:
		case RE_FAIL_REMAP_LEN:
		case RE_FAIL_REMAP_OP:
		case RE_FILE_DIFF:
		case RE_START:
		case RE_UNEXPECTED_ACTION:
		case RE_UNEXPECTED_ERRNO:
		case RE_UNEXPECTED_STATUS:
		case RE_WRONGSEC:
			return (1);
		case RE_CLIENTID:
		case RE_DEAD_FILE:
		case RE_END:
		case RE_FAIL_RELOCK:
		case RE_FAILOVER:
		case RE_LOST_STATE:
		case RE_OPENS_CHANGED:
		case RE_SIGLOST:
		case RE_SIGLOST_NO_DUMP:
		case RE_LOST_STATE_BAD_OP:
		case RE_REFERRAL:
			/* placeholder */
			return (0);
		default:
			return (0);
		}
	} else {
		switch (msgp->rmsg_u.msg_fact.rf_type) {
		case RF_BADOWNER:
		case RF_ERR:
		case RF_RENEW_EXPIRED:
		case RF_SRV_OK:
		case RF_SRVS_OK:
		case RF_DELMAP_CB_ERR:
			return (1);
		case RF_SRV_NOT_RESPOND:
		case RF_SRVS_NOT_RESPOND:
		case RF_SENDQ_FULL:
			return (0);
		default:
			return (0);
		}
	}
}

/*
 * Iterate backwards through the mi's mi_msg_list to find the earliest
 * message that we should find relevant facts to investigate.
 */
static nfs4_debug_msg_t *
find_beginning(nfs4_debug_msg_t *first_msg, mntinfo4_t *mi)
{
	nfs4_debug_msg_t	*oldest_msg, *cur_msg;
	time_t			lease;

	ASSERT(mutex_owned(&mi->mi_msg_list_lock));
	if (mi->mi_lease_period > 0)
		lease = 2 * mi->mi_lease_period;
	else
		lease = DEFAULT_LEASE;

	oldest_msg = first_msg;
	cur_msg = list_prev(&mi->mi_msg_list, first_msg);
	while (cur_msg &&
	    first_msg->msg_time.tv_sec - cur_msg->msg_time.tv_sec < lease) {
		oldest_msg = cur_msg;
		if ((cur_msg->msg_type == RM_FACT) &&
		    (cur_msg->rmsg_u.msg_fact.rf_type == RF_SRV_OK)) {
			/* find where we lost contact with the server */
			while (cur_msg) {
				if ((cur_msg->msg_type == RM_FACT) &&
				    (cur_msg->rmsg_u.msg_fact.rf_type ==
				    RF_SRV_NOT_RESPOND))
					break;
				oldest_msg = cur_msg;
				cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
			}
			/*
			 * Find the first successful message before
			 * we lost contact with the server.
			 */
			if (cur_msg) {
				cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
				while (cur_msg && !successful_comm(cur_msg)) {
					oldest_msg = cur_msg;
					cur_msg = list_prev(&mi->mi_msg_list,
					    cur_msg);
				}
			}
			/*
			 * If we're not at the dummy head pointer,
			 * set the oldest and current message.
			 */
			if (cur_msg) {
				first_msg = cur_msg;
				oldest_msg = cur_msg;
				cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
			}
		} else
			cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
	}

	return (oldest_msg);
}

/*
 * Returns 1 if facts have been found; 0 otherwise.
 */
static int
get_facts(nfs4_debug_msg_t *msgp, nfs4_rfact_t *ret_fp, char **mnt_pt,
mntinfo4_t *mi)
{
	nfs4_debug_msg_t	*cur_msg, *oldest_msg;
	nfs4_rfact_t		*cur_fp;
	int			found_a_fact = 0;
	int			len;

	cur_msg = msgp;

	/* find the oldest msg to search backwards to */
	oldest_msg = find_beginning(cur_msg, mi);
	ASSERT(oldest_msg != NULL);

	/*
	 * Create a fact sheet by searching from our current message
	 * backwards to the 'oldest_msg', recording facts along the way
	 * until we found facts that have been inspected by another time.
	 */
	while (cur_msg && cur_msg != list_prev(&mi->mi_msg_list, oldest_msg)) {
		if (cur_msg->msg_type != RM_FACT) {
			cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
			continue;
		}

		cur_fp = &cur_msg->rmsg_u.msg_fact;
		/*
		 * If this fact has already been looked at, then so
		 * have all preceding facts.  Return Now.
		 */
		if (cur_fp->rf_status == RFS_INSPECT)
			return (found_a_fact);

		cur_fp->rf_status = RFS_INSPECT;
		found_a_fact = 1;
		switch (cur_fp->rf_type) {
		case RF_BADOWNER:
			break;
		case RF_ERR:
			/*
			 * Don't want to overwrite a fact that was
			 * previously found during our current search.
			 */
			if (!ret_fp->rf_reboot)
				ret_fp->rf_reboot = cur_fp->rf_reboot;
			if (!ret_fp->rf_stat4)
				ret_fp->rf_stat4 = cur_fp->rf_stat4;
			if (!ret_fp->rf_action)
				ret_fp->rf_action = cur_fp->rf_action;
			break;
		case RF_RENEW_EXPIRED:
			if (cur_msg->msg_mntpt && !(*mnt_pt)) {
				len = strlen(cur_msg->msg_mntpt) + 1;
				*mnt_pt = kmem_alloc(len, KM_SLEEP);
				bcopy(cur_msg->msg_mntpt, *mnt_pt, len);
			}
			break;
		case RF_SRV_OK:
			break;
		case RF_SRV_NOT_RESPOND:
			/*
			 * Okay to overwrite this fact as
			 * we want the earliest time.
			 */
			ret_fp->rf_time = cur_fp->rf_time;
			break;
		case RF_SRVS_OK:
			break;
		case RF_SRVS_NOT_RESPOND:
			break;
		case RF_DELMAP_CB_ERR:
			break;
		case RF_SENDQ_FULL:
			break;
		default:
			zcmn_err(getzoneid(), CE_NOTE,
			    "get facts: illegal fact %d", cur_fp->rf_type);
			break;
		}
		cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
	}

	return (found_a_fact);
}

/*
 * Returns 1 if this fact is identical to the last fact recorded
 * (only checks for a match within the last 2 lease periods).
 */
static int
facts_same(nfs4_debug_msg_t *cur_msg, nfs4_debug_msg_t *new_msg,
    mntinfo4_t *mi)
{
	nfs4_rfact_t	*fp1, *fp2;
	int		lease, len;

	ASSERT(mutex_owned(&mi->mi_msg_list_lock));
	if (mi->mi_lease_period > 0)
		lease = 2 * mi->mi_lease_period;
	else
		lease = DEFAULT_LEASE;

	fp2 = &new_msg->rmsg_u.msg_fact;

	while (cur_msg &&
	    new_msg->msg_time.tv_sec - cur_msg->msg_time.tv_sec < lease) {
		if (cur_msg->msg_type != RM_FACT) {
			cur_msg = list_prev(&mi->mi_msg_list, cur_msg);
			continue;
		}
		fp1 = &cur_msg->rmsg_u.msg_fact;
		if (fp1->rf_type != fp2->rf_type)
			return (0);

		/* now actually compare the facts */
		if (fp1->rf_action != fp2->rf_action)
			return (0);
		if (fp1->rf_stat4 != fp2->rf_stat4)
			return (0);
		if (fp1->rf_reboot != fp2->rf_reboot)
			return (0);
		if (fp1->rf_op != fp2->rf_op)
			return (0);
		if (fp1->rf_time.tv_sec != fp2->rf_time.tv_sec)
			return (0);
		if (fp1->rf_error != fp2->rf_error)
			return (0);
		if (fp1->rf_rp1 != fp2->rf_rp1)
			return (0);
		if (cur_msg->msg_srv != NULL) {
			if (new_msg->msg_srv == NULL)
				return (0);
			len = strlen(cur_msg->msg_srv);
			if (strncmp(cur_msg->msg_srv, new_msg->msg_srv,
			    len) != 0)
				return (0);
		} else if (new_msg->msg_srv != NULL) {
			return (0);
		}
		if (cur_msg->msg_mntpt != NULL) {
			if (new_msg->msg_mntpt == NULL)
				return (0);
			len = strlen(cur_msg->msg_mntpt);
			if (strncmp(cur_msg->msg_mntpt, new_msg->msg_mntpt,
			    len) != 0)
				return (0);
		} else if (new_msg->msg_mntpt != NULL) {
			return (0);
		}
		if (fp1->rf_char1 != NULL) {
			if (fp2->rf_char1 == NULL)
				return (0);
			len = strlen(fp1->rf_char1);
			if (strncmp(fp1->rf_char1, fp2->rf_char1, len) != 0)
				return (0);
		} else if (fp2->rf_char1 != NULL) {
			return (0);
		}
		return (1);
	}

	return (0);
}

/*
 * Returns 1 if these two messages are identical; 0 otherwise.
 */
static int
events_same(nfs4_debug_msg_t *cur_msg, nfs4_debug_msg_t *new_msg,
    mntinfo4_t *mi)
{
	nfs4_revent_t	*ep1, *ep2;
	int		len;

	/* find the last event, bypassing all facts */
	while (cur_msg && cur_msg->msg_type != RM_EVENT)
		cur_msg = list_prev(&mi->mi_msg_list, cur_msg);

	if (!cur_msg)
		return (0);

	if (cur_msg->msg_type != RM_EVENT)
		return (0);

	ep1 = &cur_msg->rmsg_u.msg_event;
	ep2 = &new_msg->rmsg_u.msg_event;
	if (ep1->re_type != ep2->re_type)
		return (0);

	/*
	 * Since we zalloc the buffer, then the two nfs4_debug_msg's
	 * must match up even if all the fields weren't filled in
	 * the first place.
	 */
	if (ep1->re_mi != ep2->re_mi)
		return (0);
	if (ep1->re_uint != ep2->re_uint)
		return (0);
	if (ep1->re_stat4 != ep2->re_stat4)
		return (0);
	if (ep1->re_pid != ep2->re_pid)
		return (0);
	if (ep1->re_rp1 != ep2->re_rp1)
		return (0);
	if (ep1->re_rp2 != ep2->re_rp2)
		return (0);
	if (ep1->re_tag1 != ep2->re_tag1)
		return (0);
	if (ep1->re_tag2 != ep2->re_tag2)
		return (0);
	if (ep1->re_seqid1 != ep2->re_seqid1)
		return (0);
	if (ep1->re_seqid2 != ep2->re_seqid2)
		return (0);

	if (cur_msg->msg_srv != NULL) {
		if (new_msg->msg_srv == NULL)
			return (0);
		len = strlen(cur_msg->msg_srv);
		if (strncmp(cur_msg->msg_srv, new_msg->msg_srv, len) != 0)
			return (0);
	} else if (new_msg->msg_srv != NULL) {
		return (0);
	}

	if (ep1->re_char1 != NULL) {
		if (ep2->re_char1 == NULL)
			return (0);
		len = strlen(ep1->re_char1);
		if (strncmp(ep1->re_char1, ep2->re_char1, len) != 0)
			return (0);
	} else if (ep2->re_char1 != NULL) {
		return (0);
	}

	if (ep1->re_char2 != NULL) {
		if (ep2->re_char2 == NULL)
			return (0);
		len = strlen(ep1->re_char2);
		if (strncmp(ep1->re_char2, ep2->re_char2, len) != 0)
			return (0);
	} else if (ep2->re_char2 != NULL) {
		return (0);
	}

	if (cur_msg->msg_mntpt != NULL) {
		if (new_msg->msg_mntpt == NULL)
			return (0);
		len = strlen(cur_msg->msg_mntpt);
		if (strncmp(cur_msg->msg_mntpt, cur_msg->msg_mntpt, len) != 0)
			return (0);
	} else if (new_msg->msg_mntpt != NULL) {
		return (0);
	}

	return (1);
}

/*
 * Free up a recovery event.
 */
static void
free_event(nfs4_revent_t *ep)
{
	int	len;

	if (ep->re_char1) {
		len = strlen(ep->re_char1) + 1;
		kmem_free(ep->re_char1, len);
	}
	if (ep->re_char2) {
		len = strlen(ep->re_char2) + 1;
		kmem_free(ep->re_char2, len);
	}
}

/*
 * Free up a recovery fact.
 */
static void
free_fact(nfs4_rfact_t *fp)
{
	int	len;

	if (fp->rf_char1) {
		len = strlen(fp->rf_char1) + 1;
		kmem_free(fp->rf_char1, len);
	}
}

/*
 * Free up the message.
 */
void
nfs4_free_msg(nfs4_debug_msg_t *msg)
{
	int len;

	if (msg->msg_type == RM_EVENT)
		free_event(&msg->rmsg_u.msg_event);
	else
		free_fact(&msg->rmsg_u.msg_fact);

	if (msg->msg_srv) {
		len = strlen(msg->msg_srv) + 1;
		kmem_free(msg->msg_srv, len);
	}

	if (msg->msg_mntpt) {
		len = strlen(msg->msg_mntpt) + 1;
		kmem_free(msg->msg_mntpt, len);
	}

	/* free up the data structure itself */
	kmem_free(msg, sizeof (*msg));
}

/*
 * Prints out the interesting facts for recovery events:
 * -DEAD_FILE
 * -SIGLOST(_NO_DUMP)
 */
static void
print_facts(nfs4_debug_msg_t *msg, mntinfo4_t *mi)
{
	nfs4_rfact_t *fp;
	char *mount_pt;
	int len;

	if (msg->rmsg_u.msg_event.re_type != RE_DEAD_FILE &&
	    msg->rmsg_u.msg_event.re_type != RE_SIGLOST &&
	    msg->rmsg_u.msg_event.re_type != RE_SIGLOST_NO_DUMP)
		return;

	fp = kmem_zalloc(sizeof (*fp), KM_SLEEP);
	mount_pt = NULL;

	if (get_facts(msg, fp, &mount_pt, mi)) {
		char	time[256];


		if (fp->rf_time.tv_sec)
			(void) snprintf(time, 256, "%ld",
			    (gethrestime_sec() - fp->rf_time.tv_sec)/60);
		zcmn_err(mi->mi_zone->zone_id, CE_NOTE,
		    "!NFS4 FACT SHEET: %s%s %s%s %s %s%s%s %s%s",
		    fp->rf_action ? "\n Action: " : "",
		    fp->rf_action ? nfs4_recov_action_to_str(fp->rf_action) :
		    "",
		    fp->rf_stat4 ? "\n NFS4 error: " : "",
		    fp->rf_stat4 ? nfs4_stat_to_str(fp->rf_stat4) : "",
		    fp->rf_reboot ? "\n Suspected server reboot. " : "",
		    fp->rf_time.tv_sec ? "\n Server was down for " : "",
		    fp->rf_time.tv_sec ? time : "",
		    fp->rf_time.tv_sec ? " minutes." : "",
		    mount_pt ? " \n Client's lease expired on mount " : "",
		    mount_pt ? mount_pt : "");
	}

	if (mount_pt) {
		len = strlen(mount_pt) + 1;
		kmem_free(mount_pt, len);
	}

	/* free the fact struct itself */
	if (fp)
		kmem_free(fp, sizeof (*fp));
}

/*
 * Print an event message to /var/adm/messages
 * The last argument to this fuction dictates the repeat status
 * of the event. If set to 1, it means that we are dumping this
 * event and it will _never_ be printed after this time. Else if
 * set to 0 it will be printed again.
 */
static void
queue_print_event(nfs4_debug_msg_t *msg, mntinfo4_t *mi, int dump)
{
	nfs4_revent_t		*ep;
	zoneid_t		zoneid;

	ep = &msg->rmsg_u.msg_event;
	zoneid = mi->mi_zone->zone_id;

	switch (ep->re_type) {
	case RE_BAD_SEQID:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "Operation %s for file %s (rnode_pt 0x%p), pid %d using "
		    "seqid %d got %s.  Last good seqid was %d for "
		    "operation %s.",
		    msg->msg_srv, msg->msg_mntpt,
		    nfs4_ctags[ep->re_tag1].ct_str, ep->re_char1,
		    (void *)ep->re_rp1, ep->re_pid, ep->re_seqid1,
		    nfs4_stat_to_str(ep->re_stat4), ep->re_seqid2,
		    nfs4_ctags[ep->re_tag2].ct_str);
		break;
	case RE_BADHANDLE:
		ASSERT(ep->re_rp1 != NULL);
		if (ep->re_char1 != NULL) {
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "server %s said filehandle was "
			    "invalid for file: %s (rnode_pt 0x%p) on mount %s",
			    msg->msg_srv, msg->msg_mntpt, msg->msg_srv,
			    ep->re_char1, (void *)ep->re_rp1, msg->msg_mntpt);
		} else {
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "server %s said filehandle was "
			    "invalid for file: (rnode_pt 0x%p) on mount %s"
			    " for fh:", msg->msg_srv, msg->msg_mntpt,
			    msg->msg_srv, (void *)ep->re_rp1, msg->msg_mntpt);
			sfh4_printfhandle(ep->re_rp1->r_fh);
		}
		break;
	case RE_CLIENTID:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "Can't recover clientid on mount point %s "
		    "(mi 0x%p) due to error %d (%s), for server %s.  Marking "
		    "file system as unusable.",
		    msg->msg_srv, msg->msg_mntpt, msg->msg_mntpt,
		    (void *)ep->re_mi, ep->re_uint,
		    nfs4_stat_to_str(ep->re_stat4),
		    msg->msg_srv);
		break;
	case RE_DEAD_FILE:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "File %s (rnode_pt: %p) was closed due to NFS "
		    "recovery error on server %s(%s %s)", msg->msg_srv,
		    msg->msg_mntpt, ep->re_char1, (void *)ep->re_rp1,
		    msg->msg_srv, ep->re_char2 ? ep->re_char2 : "",
		    ep->re_stat4 ? nfs4_stat_to_str(ep->re_stat4) : "");
		break;
	case RE_END:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS Recovery done for mount %s (mi 0x%p) "
		    "on server %s, rnode_pt1 %s (0x%p), "
		    "rnode_pt2 %s (0x%p)", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_mntpt, (void *)ep->re_mi, msg->msg_srv,
		    ep->re_char1, (void *)ep->re_rp1, ep->re_char2,
		    (void *)ep->re_rp2);
		break;
	case RE_FAIL_RELOCK:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "Couldn't reclaim lock for pid %d for "
		    "file %s (rnode_pt 0x%p) on (server %s): error %d",
		    msg->msg_srv, msg->msg_mntpt, ep->re_pid, ep->re_char1,
		    (void *)ep->re_rp1, msg->msg_srv,
		    ep->re_uint ? ep->re_uint : ep->re_stat4);
		break;
	case RE_FAIL_REMAP_LEN:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "remap_lookup: server %s returned bad "
		    "fhandle length (%d)", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_srv, ep->re_uint);
		break;
	case RE_FAIL_REMAP_OP:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "remap_lookup: didn't get expected OP_GETFH"
		    " for server %s", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_srv);
		break;
	case RE_FAILOVER:
		if (ep->re_char1)
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "failing over from %s to %s", msg->msg_srv,
			    msg->msg_mntpt, msg->msg_srv, ep->re_char1);
		else
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "NFS4: failing over: selecting "
			    "original server %s", msg->msg_srv, msg->msg_mntpt,
			    msg->msg_srv);
		break;
	case RE_FILE_DIFF:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "File %s (rnode_pt: %p) on server %s was closed "
		    "and failed attempted failover since its is different than "
		    "the original file", msg->msg_srv, msg->msg_mntpt,
		    ep->re_char1, (void *)ep->re_rp1, msg->msg_srv);
		break;
	case RE_LOST_STATE:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "Lost %s request for fs %s, file %s (rnode_pt: 0x%p), "
		    "dir %s (0x%p) for server %s", msg->msg_srv, msg->msg_mntpt,
		    nfs4_op_to_str(ep->re_uint), msg->msg_mntpt,
		    ep->re_char1, (void *)ep->re_rp1, ep->re_char2,
		    (void *)ep->re_rp2, msg->msg_srv);
		break;
	case RE_OPENS_CHANGED:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "The number of open files to reopen changed "
		    "for mount %s mi 0x%p (old %d, new %d) on server %s",
		    msg->msg_srv, msg->msg_mntpt, msg->msg_mntpt,
		    (void *)ep->re_mi, ep->re_uint, ep->re_pid, msg->msg_srv);
		break;
	case RE_SIGLOST:
	case RE_SIGLOST_NO_DUMP:
		if (ep->re_uint)
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "Process %d lost its locks on "
			    "file %s (rnode_pt: %p) due to NFS recovery error "
			    "(%d) on server %s.", msg->msg_srv, msg->msg_mntpt,
			    ep->re_pid, ep->re_char1, (void *)ep->re_rp1,
			    ep->re_uint, msg->msg_srv);
		else
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "Process %d lost its locks on "
			    "file %s (rnode_pt: %p) due to NFS recovery error "
			    "(%s) on server %s.", msg->msg_srv, msg->msg_mntpt,
			    ep->re_pid, ep->re_char1, (void *)ep->re_rp1,
			    nfs4_stat_to_str(ep->re_stat4), msg->msg_srv);
		break;
	case RE_START:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS Starting recovery for mount %s "
		    "(mi 0x%p mi_recovflags [0x%x]) on server %s, "
		    "rnode_pt1 %s (0x%p), rnode_pt2 %s (0x%p)", msg->msg_srv,
		    msg->msg_mntpt, msg->msg_mntpt, (void *)ep->re_mi,
		    ep->re_uint, msg->msg_srv, ep->re_char1, (void *)ep->re_rp1,
		    ep->re_char2, (void *)ep->re_rp2);
		break;
	case RE_UNEXPECTED_ACTION:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS recovery: unexpected action (%s) on server %s",
		    msg->msg_srv, msg->msg_mntpt,
		    nfs4_recov_action_to_str(ep->re_uint), msg->msg_srv);
		break;
	case RE_UNEXPECTED_ERRNO:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS recovery: unexpected errno (%d) on server %s",
		    msg->msg_srv, msg->msg_mntpt, ep->re_uint, msg->msg_srv);
		break;
	case RE_UNEXPECTED_STATUS:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS recovery: unexpected NFS status code (%s) "
		    "on server %s", msg->msg_srv, msg->msg_mntpt,
		    nfs4_stat_to_str(ep->re_stat4),
		    msg->msg_srv);
		break;
	case RE_WRONGSEC:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS can't recover from NFS4ERR_WRONGSEC."
		    "  error %d for server %s: rnode_pt1 %s (0x%p)"
		    " rnode_pt2 %s (0x%p)", msg->msg_srv, msg->msg_mntpt,
		    ep->re_uint, msg->msg_srv, ep->re_char1, (void *)ep->re_rp1,
		    ep->re_char2, (void *)ep->re_rp2);
		break;
	case RE_LOST_STATE_BAD_OP:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS lost state with unrecognized op (%d)."
		    "  fs %s, server %s, pid %d, file %s (rnode_pt: 0x%p), "
		    "dir %s (0x%p)", msg->msg_srv, msg->msg_mntpt,
		    ep->re_uint, msg->msg_mntpt, msg->msg_srv, ep->re_pid,
		    ep->re_char1, (void *)ep->re_rp1, ep->re_char2,
		    (void *)ep->re_rp2);
		break;
	case RE_REFERRAL:
		if (ep->re_char1)
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "being referred from %s to %s", msg->msg_srv,
			    msg->msg_mntpt, msg->msg_srv, ep->re_char1);
		else
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]"
			    "NFS4: being referred from %s to unknown server",
			    msg->msg_srv, msg->msg_mntpt, msg->msg_srv);
		break;
	default:
		zcmn_err(zoneid, CE_WARN,
		    "!queue_print_event: illegal event %d", ep->re_type);
		break;
	}

	print_facts(msg, mi);

	/*
	 * If set this event will not be printed again and is considered
	 * dumped.
	 */
	if (dump)
		msg->msg_status = NFS4_MS_NO_DUMP;
}

/*
 * Print a fact message to /var/adm/messages
 */
static void
queue_print_fact(nfs4_debug_msg_t *msg, int dump)
{
	nfs4_rfact_t	*fp;
	zoneid_t	zoneid;

	fp = &msg->rmsg_u.msg_fact;
	zoneid = getzoneid();

	switch (fp->rf_type) {
	case RF_BADOWNER:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFSMAPID_DOMAIN does not match the server: %s domain\n"
		    "Please check configuration", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_srv);
		break;
	case RF_ERR:
		if (fp->rf_error)
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]NFS op %s got "
			    "error %d causing recovery action %s.%s",
			    msg->msg_srv, msg->msg_mntpt,
			    nfs4_op_to_str(fp->rf_op), fp->rf_error,
			    nfs4_recov_action_to_str(fp->rf_action),
			    fp->rf_reboot ?
			    "  Client also suspects that the server rebooted,"
			    " or experienced a network partition." : "");
		else
			zcmn_err(zoneid, CE_NOTE,
			    "![NFS4][Server: %s][Mntpt: %s]NFS op %s got "
			    "error %s causing recovery action %s.%s",
			    msg->msg_srv, msg->msg_mntpt,
			    nfs4_op_to_str(fp->rf_op),
			    nfs4_stat_to_str(fp->rf_stat4),
			    nfs4_recov_action_to_str(fp->rf_action),
			    fp->rf_reboot ?
			    "  Client also suspects that the server rebooted,"
			    " or experienced a network partition." : "");
		break;
	case RF_RENEW_EXPIRED:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS4 renew thread detected client's "
		    "lease has expired. Current open files/locks/IO may fail",
		    msg->msg_srv, msg->msg_mntpt);
		break;
	case RF_SRV_NOT_RESPOND:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS server %s not responding; still trying\n",
		    msg->msg_srv, msg->msg_mntpt, msg->msg_srv);
		break;
	case RF_SRV_OK:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS server %s ok", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_srv);
		break;
	case RF_SRVS_NOT_RESPOND:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS servers %s not responding; still trying", msg->msg_srv,
		    msg->msg_mntpt, msg->msg_srv);
		break;
	case RF_SRVS_OK:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS servers %s ok", msg->msg_srv, msg->msg_mntpt,
		    msg->msg_srv);
		break;
	case RF_DELMAP_CB_ERR:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "NFS op %s got error %s when executing delmap on file %s "
		    "(rnode_pt 0x%p).",
		    msg->msg_srv, msg->msg_mntpt, nfs4_op_to_str(fp->rf_op),
		    nfs4_stat_to_str(fp->rf_stat4), fp->rf_char1,
		    (void *)fp->rf_rp1);
		break;
	case RF_SENDQ_FULL:
		zcmn_err(zoneid, CE_NOTE, "![NFS4][Server: %s][Mntpt: %s]"
		    "send queue to NFS server %s is full; still trying\n",
		    msg->msg_srv, msg->msg_mntpt, msg->msg_srv);
		break;

	default:
		zcmn_err(zoneid, CE_WARN, "!queue_print_fact: illegal fact %d",
		    fp->rf_type);
	}

	/*
	 * If set this fact will not be printed again and is considered
	 * dumped.
	 */
	if (dump)
		msg->msg_status = NFS4_MS_NO_DUMP;
}

/*
 * Returns 1 if the entire queue should be dumped, 0 otherwise.
 */
static int
id_to_dump_queue(nfs4_event_type_t id)
{
	switch (id) {
	case RE_DEAD_FILE:
	case RE_SIGLOST:
	case RE_WRONGSEC:
	case RE_CLIENTID:
		return (1);
	default:
		return (0);
	}
}

/*
 * Returns 1 if the event (but not the entire queue) should be printed;
 * 0 otherwise.
 */
static int
id_to_dump_solo_event(nfs4_event_type_t id)
{
	switch (id) {
	case RE_BAD_SEQID:
	case RE_BADHANDLE:
	case RE_FAIL_REMAP_LEN:
	case RE_FAIL_REMAP_OP:
	case RE_FAILOVER:
	case RE_OPENS_CHANGED:
	case RE_SIGLOST_NO_DUMP:
	case RE_UNEXPECTED_ACTION:
	case RE_UNEXPECTED_ERRNO:
	case RE_UNEXPECTED_STATUS:
	case RE_LOST_STATE_BAD_OP:
	case RE_REFERRAL:
		return (1);
	default:
		return (0);
	}
}

/*
 * Returns 1 if the fact (but not the entire queue) should be printed;
 * 0 otherwise.
 */
static int
id_to_dump_solo_fact(nfs4_fact_type_t id)
{
	switch (id) {
	case RF_SRV_NOT_RESPOND:
	case RF_SRV_OK:
	case RF_SRVS_NOT_RESPOND:
	case RF_SRVS_OK:
	case RF_SENDQ_FULL:
		return (1);
	default:
		return (0);
	}
}

/*
 * Update a kernel stat
 */
static void
update_recov_kstats(nfs4_debug_msg_t *msg, mntinfo4_t *mi)
{
	rkstat_t	*rsp;

	if (!mi->mi_recov_ksp)
		return;

	rsp = (rkstat_t *)mi->mi_recov_ksp->ks_data;

	if (msg->msg_type == RM_EVENT) {
		switch (msg->rmsg_u.msg_event.re_type) {
		case RE_BADHANDLE:
			rsp->badhandle.value.ul++;
			break;
		case RE_CLIENTID:
			rsp->clientid.value.ul++;
			break;
		case RE_DEAD_FILE:
			rsp->dead_file.value.ul++;
			break;
		case RE_FAIL_RELOCK:
			rsp->fail_relock.value.ul++;
			break;
		case RE_FILE_DIFF:
			rsp->file_diff.value.ul++;
			break;
		case RE_OPENS_CHANGED:
			rsp->opens_changed.value.ul++;
			break;
		case RE_SIGLOST:
		case RE_SIGLOST_NO_DUMP:
			rsp->siglost.value.ul++;
			break;
		case RE_UNEXPECTED_ACTION:
			rsp->unexp_action.value.ul++;
			break;
		case RE_UNEXPECTED_ERRNO:
			rsp->unexp_errno.value.ul++;
			break;
		case RE_UNEXPECTED_STATUS:
			rsp->unexp_status.value.ul++;
			break;
		case RE_WRONGSEC:
			rsp->wrongsec.value.ul++;
			break;
		case RE_LOST_STATE_BAD_OP:
			rsp->lost_state_bad_op.value.ul++;
			break;
		default:
			break;
		}
	} else if (msg->msg_type == RM_FACT) {
		switch (msg->rmsg_u.msg_fact.rf_type) {
		case RF_BADOWNER:
			rsp->badowner.value.ul++;
			break;
		case RF_SRV_NOT_RESPOND:
			rsp->not_responding.value.ul++;
			break;
		default:
			break;
		}
	}
}

/*
 * Dump the mi's mi_msg_list of recovery messages.
 */
static void
dump_queue(mntinfo4_t *mi, nfs4_debug_msg_t *msg)
{
	nfs4_debug_msg_t *tmp_msg;

	ASSERT(mutex_owned(&mi->mi_msg_list_lock));

	/* update kstats */
	update_recov_kstats(msg, mi);

	/*
	 * If we aren't supposed to dump the queue then see if we
	 * should just print this single message, then return.
	 */
	if (!id_to_dump_queue(msg->rmsg_u.msg_event.re_type)) {
		if (id_to_dump_solo_event(msg->rmsg_u.msg_event.re_type))
			queue_print_event(msg, mi, 0);
		return;
	}

	/*
	 * Write all events/facts in the queue that haven't been
	 * previously written to disk.
	 */
	tmp_msg = list_head(&mi->mi_msg_list);
	while (tmp_msg) {
		if (tmp_msg->msg_status == NFS4_MS_DUMP) {
			if (tmp_msg->msg_type == RM_EVENT)
				queue_print_event(tmp_msg, mi, 1);
			else if (tmp_msg->msg_type == RM_FACT)
				queue_print_fact(tmp_msg, 1);
		}
		tmp_msg = list_next(&mi->mi_msg_list, tmp_msg);
	}
}

/*
 * Places the event into mi's debug recovery message queue.  Some of the
 * fields can be overloaded to be a generic value, depending on the event
 * type.  These include "count", "why".
 */
void
nfs4_queue_event(nfs4_event_type_t id, mntinfo4_t *mi, char *server1,
    uint_t count, vnode_t *vp1, vnode_t *vp2, nfsstat4 nfs4_error,
    char *why, pid_t pid, nfs4_tag_type_t tag1, nfs4_tag_type_t tag2,
    seqid4 seqid1, seqid4 seqid2)
{
	nfs4_debug_msg_t	*msg;
	nfs4_revent_t		*ep;
	char			*cur_srv;
	rnode4_t		*rp1 = NULL, *rp2 = NULL;
	refstr_t		*mntpt;

	ASSERT(mi != NULL);
	if (vp1)
		rp1 = VTOR4(vp1);
	if (vp2)
		rp2 = VTOR4(vp2);

	/*
	 * Initialize the message with the relevant server/mount_pt/time
	 * information. Also place the relevent event related info.
	 */
	msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
	msg->msg_type = RM_EVENT;
	msg->msg_status = NFS4_MS_DUMP;
	ep = &msg->rmsg_u.msg_event;
	ep->re_type = id;
	gethrestime(&msg->msg_time);

	cur_srv = mi->mi_curr_serv->sv_hostname;
	msg->msg_srv = strdup(cur_srv);
	mntpt = vfs_getmntpoint(mi->mi_vfsp);
	msg->msg_mntpt = strdup(refstr_value(mntpt));
	refstr_rele(mntpt);

	set_event(id, ep, mi, rp1, rp2, count, pid, nfs4_error, server1,
	    why, tag1, tag2, seqid1, seqid2);

	mutex_enter(&mi->mi_msg_list_lock);

	/* if this event is the same as the last event, drop it */
	if (events_same(list_tail(&mi->mi_msg_list), msg, mi)) {
		mutex_exit(&mi->mi_msg_list_lock);
		nfs4_free_msg(msg);
		return;
	}

	/* queue the message at the end of the list */
	list_insert_tail(&mi->mi_msg_list, msg);

	dump_queue(mi, msg);

	if (mi->mi_msg_count == nfs4_msg_max) {
		nfs4_debug_msg_t *rm_msg;

		/* remove the queue'd message at the front of the list */
		rm_msg = list_head(&mi->mi_msg_list);
		list_remove(&mi->mi_msg_list, rm_msg);
		mutex_exit(&mi->mi_msg_list_lock);
		nfs4_free_msg(rm_msg);
	} else {
		mi->mi_msg_count++;
		mutex_exit(&mi->mi_msg_list_lock);
	}
}

/*
 * Places the fact into mi's debug recovery messages queue.
 */
void
nfs4_queue_fact(nfs4_fact_type_t fid, mntinfo4_t *mi, nfsstat4 stat4,
    nfs4_recov_t raction, nfs_opnum4 op, bool_t reboot, char *srvname,
    int error, vnode_t *vp)
{
	nfs4_debug_msg_t	*msg;
	nfs4_rfact_t		*fp;
	char			*cur_srv;
	refstr_t		*mntpt;

	/*
	 * Initialize the message with the relevant server/mount_pt/time
	 * information. Also place the relevant fact related info.
	 */
	msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
	msg->msg_type = RM_FACT;
	msg->msg_status = NFS4_MS_DUMP;
	gethrestime(&msg->msg_time);

	if (srvname)
		cur_srv = srvname;
	else
		cur_srv = mi->mi_curr_serv->sv_hostname;

	msg->msg_srv = strdup(cur_srv);
	mntpt = vfs_getmntpoint(mi->mi_vfsp);
	msg->msg_mntpt = strdup(refstr_value(mntpt));
	refstr_rele(mntpt);

	fp = &msg->rmsg_u.msg_fact;
	fp->rf_type = fid;
	fp->rf_status = RFS_NO_INSPECT;
	set_fact(fid, fp, stat4, raction, op, reboot, error, vp);

	update_recov_kstats(msg, mi);

	mutex_enter(&mi->mi_msg_list_lock);

	/* if this fact is the same as the last fact, drop it */
	if (facts_same(list_tail(&mi->mi_msg_list), msg, mi)) {
		mutex_exit(&mi->mi_msg_list_lock);
		nfs4_free_msg(msg);
		return;
	}

	/* queue the message at the end of the list */
	list_insert_tail(&mi->mi_msg_list, msg);

	if (id_to_dump_solo_fact(msg->rmsg_u.msg_fact.rf_type))
		queue_print_fact(msg, 0);

	if (mi->mi_msg_count == nfs4_msg_max) {
		nfs4_debug_msg_t *rm_msg;

		/* remove the queue'd message at the front of the list */
		rm_msg = list_head(&mi->mi_msg_list);
		list_remove(&mi->mi_msg_list, rm_msg);
		mutex_exit(&mi->mi_msg_list_lock);
		nfs4_free_msg(rm_msg);
	} else {
		mi->mi_msg_count++;
		mutex_exit(&mi->mi_msg_list_lock);
	}
}

/*
 * Initialize the 'mi_recov_kstat' kstat.
 */
void
nfs4_mnt_recov_kstat_init(vfs_t *vfsp)
{
	mntinfo4_t *mi = VFTOMI4(vfsp);
	kstat_t		*ksp;
	zoneid_t	zoneid = mi->mi_zone->zone_id;

	/*
	 * Create the version specific kstats.
	 *
	 * PSARC 2001/697 Contract Private Interface
	 * All nfs kstats are under SunMC contract
	 * Please refer to the PSARC listed above and contact
	 * SunMC before making any changes!
	 *
	 * Changes must be reviewed by Solaris File Sharing
	 * Changes must be communicated to contract-2001-697@sun.com
	 *
	 */

	if ((ksp = kstat_create_zone("nfs", getminor(vfsp->vfs_dev),
	    "mi_recov_kstat", "misc", KSTAT_TYPE_NAMED,
	    sizeof (rkstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE, zoneid)) == NULL) {
		mi->mi_recov_ksp = NULL;
		zcmn_err(GLOBAL_ZONEID, CE_NOTE,
		    "!mi_recov_kstat for mi %p failed\n",
		    (void *)mi);
		return;
	}
	if (zoneid != GLOBAL_ZONEID)
		kstat_zone_add(ksp, GLOBAL_ZONEID);
	mi->mi_recov_ksp = ksp;
	bcopy(&rkstat_template, ksp->ks_data, sizeof (rkstat_t));
	kstat_install(ksp);
}

/*
 * Increment the "delay" kstat.
 */
void
nfs4_mi_kstat_inc_delay(mntinfo4_t *mi)
{
	rkstat_t    *rsp;

	if (!mi->mi_recov_ksp)
		return;

	rsp = (rkstat_t *)mi->mi_recov_ksp->ks_data;
	rsp->delay.value.ul++;
}

/*
 * Increment the "no_grace" kstat.
 */
void
nfs4_mi_kstat_inc_no_grace(mntinfo4_t *mi)
{
	rkstat_t	*rsp;

	if (!mi->mi_recov_ksp)
		return;

	rsp = (rkstat_t *)mi->mi_recov_ksp->ks_data;
	rsp->no_grace.value.ul++;
}
