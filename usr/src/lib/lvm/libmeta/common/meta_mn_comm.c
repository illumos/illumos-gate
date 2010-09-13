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

#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <sys/time.h>
#include <strings.h>
#include <meta.h>
#include <syslog.h>

extern md_mn_msg_tbl_entry_t  msg_table[];

/*
 * When contacting the local rpc.mdcommd we always want to do that using
 * the IPv4 version of localhost.
 */
#define	LOCALHOST_IPv4	"127.0.0.1"

md_mn_msgclass_t
mdmn_get_message_class(md_mn_msgtype_t msgtype)
{
	return (msg_table[msgtype].mte_class);
}

void (*
mdmn_get_handler(md_mn_msgtype_t msgtype))
	(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *res)
{
	return (msg_table[msgtype].mte_handler);
}

int (*
mdmn_get_submessage_generator(md_mn_msgtype_t msgtype))
	(md_mn_msg_t *msg, md_mn_msg_t **msglist)
{
	return (msg_table[msgtype].mte_smgen);
}

time_t
mdmn_get_timeout(md_mn_msgtype_t msgtype)
{
	return (msg_table[msgtype].mte_timeout);
}


void
ldump_msg(char *prefix, md_mn_msg_t *msg)
{
	(void) fprintf(stderr, "%s &msg       = 0x%x\n", prefix, (uint_t)msg);
	(void) fprintf(stderr, "%s ID         = (%d, 0x%llx-%d)\n", prefix,
	    MSGID_ELEMS(msg->msg_msgid));
	(void) fprintf(stderr, "%s sender     = %d\n", prefix, msg->msg_sender);
	(void) fprintf(stderr, "%s flags      = 0x%x\n",
	    prefix, msg->msg_flags);
	(void) fprintf(stderr, "%s setno      = %d\n", prefix, msg->msg_setno);
	(void) fprintf(stderr, "%s recipient  = %d\n",
	    prefix, msg->msg_recipient);
	(void) fprintf(stderr, "%s type       = %d\n", prefix, msg->msg_type);
	(void) fprintf(stderr, "%s size       = %d\n",
	    prefix, msg->msg_event_size);
}

#define	COMMD_PROGNAME	"rpc.mdcommd"

extern uint_t meta_rpc_err_mask(void);

/*
 * If a clnt_call gets an RPC error, force the message out here with details.
 * This would be nice to send to commd_debug(), but we can't call rpc.mdcommd
 * code from libmeta.
 */
static void
mdmn_handle_RPC_error(CLIENT *clnt, char *ident, md_mn_nodeid_t nid)
{
	/*
	 * This is sized for a max message which would look like this:
	 * "mdmn_wakeup_initiator: rpc.mdcommd node 4294967295"
	 */
	char errstr[51];
	struct rpc_err e;

	CLNT_GETERR((CLIENT *) clnt, &e);
	if (meta_rpc_err_mask() & (1 << e.re_status)) {
		if (nid == 0) {
			(void) snprintf(errstr, sizeof (errstr),
			    "%s: %s node (local)", ident, COMMD_PROGNAME);
		} else {
			(void) snprintf(errstr, sizeof (errstr),
			    "%s: %s node %d", ident, COMMD_PROGNAME, nid);
		}
		syslog(LOG_WARNING, "mdmn_handle_RPC_error: %s",
		    clnt_sperror(clnt, errstr));
	}
}

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

md_mn_result_t *
mdmn_send_2(argp, clnt, nid)
	md_mn_msg_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	md_mn_result_t *clnt_res = Zalloc(sizeof (md_mn_result_t));

	res = clnt_call(clnt, mdmn_send,
		(xdrproc_t)xdr_md_mn_msg_t, (caddr_t)argp,
		(xdrproc_t)xdr_md_mn_result_t, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_send", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_work_2(argp, clnt, nid)
	md_mn_msg_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_work,
		(xdrproc_t)xdr_md_mn_msg_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_work", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_wakeup_initiator_2(argp, clnt, nid)
	md_mn_result_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_wakeup_initiator,
		(xdrproc_t)xdr_md_mn_result_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_wakeup_initiator", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_wakeup_master_2(argp, clnt, nid)
	md_mn_result_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_wakeup_master,
		(xdrproc_t)xdr_md_mn_result_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_wakeup_master", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_lock_2(argp, clnt, nid)
	md_mn_set_and_class_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_lock,
		(xdrproc_t)xdr_md_mn_set_and_class_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_lock", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_unlock_2(argp, clnt, nid)
	md_mn_set_and_class_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_unlock,
		(xdrproc_t)xdr_md_mn_set_and_class_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_unlock", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_suspend_2(argp, clnt, nid)
	md_mn_set_and_class_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_suspend,
		(xdrproc_t)xdr_md_mn_set_and_class_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_suspend", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_resume_2(argp, clnt, nid)
	md_mn_set_and_class_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_resume,
		(xdrproc_t)xdr_md_mn_set_and_class_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_resume", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_reinit_set_2(argp, clnt, nid)
	set_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_reinit_set,
		(xdrproc_t)xdr_set_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_reinit_set", nid);
	Free(clnt_res);
	return (NULL);
}

int *
mdmn_comm_msglock_2(argp, clnt, nid)
	md_mn_type_and_lock_t *argp;
	CLIENT *clnt;
	md_mn_nodeid_t nid;
{
	enum clnt_stat	res;
	int *clnt_res = Zalloc(sizeof (int));

	res = clnt_call(clnt, mdmn_comm_msglock,
		(xdrproc_t)xdr_md_mn_type_and_lock_t, (caddr_t)argp,
		(xdrproc_t)xdr_int, (caddr_t)clnt_res, TIMEOUT);

	if (res == RPC_SUCCESS) {
		return (clnt_res);
	}
	mdmn_handle_RPC_error(clnt, "mdmn_comm_msglock", nid);
	Free(clnt_res);
	return (NULL);
}


#define	USECS_PER_TICK	10000


/*
 * Let the kernel create a clusterwide unique message ID
 *
 * returns 0 on success
 *	   1 on failure
 */

int
mdmn_create_msgid(md_mn_msgid_t *msgid)
{
	md_error_t	mde = mdnullerror;

	if (msgid == NULL) {
		return (1); /* failure */
	}

	if (metaioctl(MD_IOCGUNIQMSGID, msgid, &mde, NULL) != 0) {
		msgid->mid_nid = ~0u;
		msgid->mid_time = 0LL;
		return (1); /* failure */
	}

	/*
	 * mid_smid and mid_oclass are only used for submessages.
	 * mdmn_create_msgid is never called for submessages, as they inherit
	 * the message ID from their parent.
	 * Thus we can safely null out the following fields.
	 */
	msgid->mid_smid = 0;
	msgid->mid_oclass = 0;

	/* if the node_id is not set yet, somethings seems to be wrong */
	if (msgid->mid_nid == ~0u) {
		return (1); /* failure */
	}

	return (0); /* success */
}

md_mn_result_t *
copy_result(md_mn_result_t *res)
{
	md_mn_result_t *nres;
	nres = Zalloc(sizeof (md_mn_result_t));
	/* It's MSGID_COPY(from, to); */
	MSGID_COPY(&(res->mmr_msgid), &(nres->mmr_msgid));
	nres->mmr_msgtype	= res->mmr_msgtype;
	nres->mmr_setno		= res->mmr_setno;
	nres->mmr_flags		= res->mmr_flags;
	nres->mmr_sender	= res->mmr_sender;
	nres->mmr_failing_node	= res->mmr_failing_node;
	nres->mmr_comm_state	= res->mmr_comm_state;
	nres->mmr_exitval	= res->mmr_exitval;
	nres->mmr_out_size	= res->mmr_out_size;
	nres->mmr_err_size	= res->mmr_err_size;
	if (res->mmr_out_size > 0) {
		nres->mmr_out = Zalloc(res->mmr_out_size);
		bcopy(res->mmr_out, nres->mmr_out, res->mmr_out_size);
	}
	if (res->mmr_err_size > 0) {
		nres->mmr_err = Zalloc(res->mmr_err_size);
		bcopy(res->mmr_err, nres->mmr_err, res->mmr_err_size);
	}
	if (res->mmr_ep.host != '\0') {
		nres->mmr_ep.host = strdup(res->mmr_ep.host);
	}
	if (res->mmr_ep.extra != '\0') {
		nres->mmr_ep.extra = strdup(res->mmr_ep.extra);
	}
	if (res->mmr_ep.name != '\0') {
		nres->mmr_ep.name = strdup(res->mmr_ep.name);
	}
	return (nres);
}

void
free_result(md_mn_result_t *res)
{
	if (res->mmr_out_size > 0) {
		Free(res->mmr_out);
	}
	if (res->mmr_err_size > 0) {
		Free(res->mmr_err);
	}
	if (res->mmr_ep.host != '\0') {
		Free(res->mmr_ep.host);
	}
	if (res->mmr_ep.extra != '\0') {
		Free(res->mmr_ep.extra);
	}
	if (res->mmr_ep.name != '\0') {
		Free(res->mmr_ep.name);
	}
	Free(res);
}


/* allocate a new message and copy a given message into it */
md_mn_msg_t *
copy_msg(md_mn_msg_t *msg, md_mn_msg_t *dest)
{
	md_mn_msg_t *nmsg;

	nmsg = dest;

	if (nmsg == NULL) {
		nmsg = Zalloc(sizeof (md_mn_msg_t));
	}
	if (nmsg->msg_event_data == NULL) {
		nmsg->msg_event_data = Zalloc(msg->msg_event_size);
	}
	/* It's MSGID_COPY(from, to); */
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));
	nmsg->msg_sender	= msg->msg_sender;
	nmsg->msg_flags		= msg->msg_flags;
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= msg->msg_type;
	nmsg->msg_recipient	= msg->msg_recipient;
	nmsg->msg_event_size	= msg->msg_event_size;
	if (msg->msg_event_size > 0) {
		bcopy(msg->msg_event_data, nmsg->msg_event_data,
		    msg->msg_event_size);
	}
	return (nmsg);
}

void
copy_msg_2(md_mn_msg_t *msg, md_mn_msg_od_t *msgod, int direction)
{
	assert((direction == MD_MN_COPY_TO_ONDISK) ||
	    (direction == MD_MN_COPY_TO_INCORE));

	if (direction == MD_MN_COPY_TO_ONDISK) {
		MSGID_COPY(&(msg->msg_msgid), &(msgod->msg_msgid));
		msgod->msg_sender	= msg->msg_sender;
		msgod->msg_flags	= msg->msg_flags;
		msgod->msg_setno	= msg->msg_setno;
		msgod->msg_type		= msg->msg_type;
		msgod->msg_recipient	= msg->msg_recipient;
		msgod->msg_od_event_size = msg->msg_event_size;
		/* paranoid checks */
		if (msg->msg_event_size != 0 && msg->msg_event_data != NULL)
			bcopy(msg->msg_event_data,
			    &msgod->msg_od_event_data[0], msg->msg_event_size);
	} else {
		MSGID_COPY(&(msgod->msg_msgid), &(msg->msg_msgid));
		msg->msg_sender	= msgod->msg_sender;
		msg->msg_flags		= msgod->msg_flags;
		msg->msg_setno		= msgod->msg_setno;
		msg->msg_type		= msgod->msg_type;
		msg->msg_recipient	= msgod->msg_recipient;
		msg->msg_event_size	= msgod->msg_od_event_size;
		if (msg->msg_event_data == NULL)
			msg->msg_event_data = Zalloc(msg->msg_event_size);

		bcopy(&msgod->msg_od_event_data[0],
		    msg->msg_event_data, msgod->msg_od_event_size);
	}
}

/* Free a message */
void
free_msg(md_mn_msg_t *msg)
{
	if (msg->msg_event_size > 0) {
		Free(msg->msg_event_data);
	}
	Free(msg);
}


/* The following declarations are only for the next two routines */

md_mn_client_list_t *mdmn_clients;

mutex_t	mcl_mutex;
#define	MNGLC_INIT_ONLY	0x0001
#define	MNGLC_FOR_REAL	0x0002
/*
 * mdmn_get_local_clnt(flag)
 * If there is a client in the free pool, get one,
 * If no client is available, create one.
 * Every multithreaded application that uses mdmn_send_message must call it
 * single threaded first with special flags so we do the initialization
 * stuff in a safe environment.
 *
 * Input: MNGLC_INIT_ONLY: just initializes the mutex
 *        MNGLC_FOR_REAL : do real work
 * Output:
 *	An rpc client for sending rpc requests to the local commd
 *	NULL in case of an error
 *
 */
static CLIENT *
mdmn_get_local_clnt(uint_t flag)
{
	CLIENT *local_daemon;
	static int inited = 0;
	md_mn_client_list_t *tmp;

	if (inited == 0) {
		(void) mutex_init(&mcl_mutex, USYNC_THREAD, NULL);
		inited = 1;
	}

	if (flag == MNGLC_INIT_ONLY)
		return ((CLIENT *)NULL);

	(void) mutex_lock(&mcl_mutex);
	if (mdmn_clients == (md_mn_client_list_t *)NULL) {
		/* if there is no entry, create a client and return a it */
		local_daemon = meta_client_create(LOCALHOST_IPv4, MDMN_COMMD,
		    TWO, "tcp");
	} else {
		/*
		 * If there is an entry from a previous put operation,
		 * remove it from the head of the list and free the list stuff
		 * around it. Then return the client
		 */
		local_daemon = mdmn_clients->mcl_clnt;
		tmp = mdmn_clients;
		mdmn_clients = mdmn_clients->mcl_next;
		Free(tmp);
	}
	(void) mutex_unlock(&mcl_mutex);


	if (local_daemon == (CLIENT *)NULL) {
		clnt_pcreateerror("local_daemon");
	}

	return (local_daemon);
}

/*
 * mdmn_put_local_clnt()
 * returns a no longer used client to the pool
 *
 * Input: an RPC client
 * Output: void
 */
static void
mdmn_put_local_clnt(CLIENT *local_daemon)
{
	md_mn_client_list_t *tmp;

	(void) mutex_lock(&mcl_mutex);

	tmp =  mdmn_clients;
	mdmn_clients = (md_mn_client_list_t *)
	    malloc(sizeof (md_mn_client_list_t));
	mdmn_clients->mcl_clnt = local_daemon;
	mdmn_clients->mcl_next = tmp;

	(void) mutex_unlock(&mcl_mutex);
}

/*
 * This is the regular interface for sending a message.
 * This function only passes through all arguments to
 * mdmn_send_message_with_msgid() and adds a NULL for the message ID.
 *
 * Normally, you don't have already a message ID for the message you want
 * to send.  Only in case of replaying a previously logged message,
 * a msgid is already attached to it.
 * In that case mdmn_send_message_with_msgid() has to be called directly.
 *
 * The recipient argument is almost always unused, and is therefore typically
 * set to zero, as zero is an invalid cluster nodeid.  The exceptions are the
 * marking and clearing of the DRL from a node that is not currently the
 * owner.  In these cases, the recipient argument will be the nodeid of the
 * mirror owner, and MD_MSGF_DIRECTED will be set in the flags.  Non-owner
 * nodes will not receive these messages.
 *
 * Return values / CAVEAT EMPTOR: see mdmn_send_message_with_msgid()
 */

int
mdmn_send_message(
		set_t setno,
		md_mn_msgtype_t type,
		uint_t flags,
		md_mn_nodeid_t recipient,
		char *data,
		int size,
		md_mn_result_t **result,
		md_error_t *ep)
{
	return (mdmn_send_message_with_msgid(setno, type, flags,
	    recipient, data, size, result, MD_NULL_MSGID, ep));
}
/*
 * mdmn_send_message_with_msgid()
 * Create a message from the given pieces of data and hand it over
 * to the local commd.
 * This may fail for various reasons (rpc error / class busy / class locked ...)
 * Some error types are immediately deadly, others will cause retries
 * until the request is fulfilled or until the retries are ecxceeded.
 *
 * In case an error is returned it is up to the user to decide what to do.
 *
 * Returns:
 *	0 on success
 *	1 if retries1 exceeded
 *	2 if retries2 exceeded
 *	-1 if connecting to the local daemon failed
 *	-2 if the RPC call to the local daemon failed
 *	-3 if this node hasn't yet joined the set
 *	-4 if any other problem occured
 *
 * CAVEAT EMPTOR:
 *	The caller is responsible for calling free_result() when finished with
 *	the results!
 */
int
mdmn_send_message_with_msgid(
		set_t setno,
		md_mn_msgtype_t type,
		uint_t flags,
		md_mn_nodeid_t recipient,
		char *data,
		int size,
		md_mn_result_t **result,
		md_mn_msgid_t *msgid,
		md_error_t *ep)
{
	uint_t retry1, ticks1, retry2, ticks2;
	int retval;

	CLIENT *local_daemon;
	struct timeval timeout;

	md_mn_msg_t msg;
	md_mn_result_t *resp;

	/*
	 * Special case for multithreaded applications:
	 * When starting up, the application should call mdmn_send_message
	 * single threaded with all parameters set to NULL.
	 * When we detect this we know, we safely can do initialization
	 * stuff here.
	 * We only check for set and type being zero
	 */
	if ((setno == 0) && (type == 0)) {
		/* do all needed initializations here */
		(void) mdmn_get_local_clnt(MNGLC_INIT_ONLY);
		return (0); /* success */
	}


	/* did the caller specify space to store the result pointer? */
	if (result == (md_mn_result_t **)NULL) {
		syslog(LOG_INFO, dgettext(TEXT_DOMAIN,
		    "FATAL, can not allocate result structure\n"));
		return (-4);
	}
	*result = NULL;

	/* Replay messages already have their msgID */
	if ((flags & MD_MSGF_REPLAY_MSG) == 0) {
		if (mdmn_create_msgid(&msg.msg_msgid) != 0) {
			syslog(LOG_INFO, dgettext(TEXT_DOMAIN,
			    "FATAL, can not create message ID\n"));
			return (-4);
		}
	} else {
		/* in this case a message ID must be specified */
		assert(msgid != MD_NULL_MSGID);
		MSGID_COPY(msgid, &msg.msg_msgid);
	}


	/*
	 * When setting the flags, additionally apply the
	 * default flags for this message type.
	 */
	msg.msg_flags		= flags;
	msg.msg_setno		= setno;
	msg.msg_recipient	= recipient;
	msg.msg_type		= type;
	msg.msg_event_size	= size;
	msg.msg_event_data	= data;

	/*
	 * For the timeout pick the specific timeout for the message times the
	 * the maximum number of nodes.
	 * This is a better estimate than 1 hour or 3 days or never.
	 */
	timeout.tv_sec = mdmn_get_timeout(type) * NNODES;
	timeout.tv_usec = 0;

	if (flags & MD_MSGF_VERBOSE) {
		syslog(LOG_INFO, "send_message: ID=(%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(msg.msg_msgid));
	}

	/* get an RPC client to the local commd */
	local_daemon = mdmn_get_local_clnt(MNGLC_FOR_REAL);
	if (local_daemon == (CLIENT *)NULL) {
		return (-1);
	}
	clnt_control(local_daemon, CLSET_TIMEOUT, (char *)&timeout);

	retry1 = msg_table[type].mte_retry1;
	ticks1 = msg_table[type].mte_ticks1;
	retry2 = msg_table[type].mte_retry2;
	ticks2 = msg_table[type].mte_ticks2;

	/*
	 * run that loop until:
	 * - commstate is Ok
	 * - deadly commstate occured
	 * - retries1 or retries2 exceeded
	 */
	for (; ; ) {
		*result = mdmn_send_2(&msg, local_daemon, 0);
		resp = *result;
		if (resp != (md_mn_result_t *)NULL) {
			/* Bingo! */
			if (resp->mmr_comm_state == MDMNE_ACK) {
				retval = 0;
				goto out;
			}
			/* Hmm... what if there's no handler? */
			if (resp->mmr_comm_state == MDMNE_NO_HANDLER) {
				retval = 0;
				goto out;

			}
			/*
			 * This node didn't yet join the disk set. It is not
			 * supposed to send any messages then.
			 * This is deadly (no retries)
			 */
			if (resp->mmr_comm_state == MDMNE_NOT_JOINED) {
				retval = -3;
				goto out;

			}
			/* these two are deadly too (no retries) */
			if ((resp->mmr_comm_state == MDMNE_NO_WAKEUP_ENTRY) ||
			    (resp->mmr_comm_state == MDMNE_LOG_FAIL)) {
				retval = -4;
				goto out;

			}
			/* Class busy? Use retry1 */
			if (resp->mmr_comm_state == MDMNE_CLASS_BUSY) {
				if (retry1-- == 0) {
					retval = 1; /* retry1 exceeded */
					goto out;
				}
				(void) usleep(ticks1 * USECS_PER_TICK);
				free_result(resp);

				if (flags & MD_MSGF_VERBOSE)
					(void) printf("#Resend1 ID=(%d, "
					    "0x%llx-%d)\n",
					    MSGID_ELEMS(msg.msg_msgid));
				continue;
			}
			if ((resp->mmr_comm_state == MDMNE_CLASS_LOCKED) ||
			    (resp->mmr_comm_state == MDMNE_ABORT)) {
				/*
				 * Be patient, wait for 1 secs and try again.
				 * It's not likely that the ABORT condition ever
				 * goes away, but it won't hurt to retry
				 */
				free_result(resp);
				(void) sleep(1);
				continue;
			}
			if (resp->mmr_comm_state == MDMNE_SUSPENDED) {
				if (flags & MD_MSGF_FAIL_ON_SUSPEND) {
					/* caller wants us to fail here */
					(void) mddserror(ep,
					    MDE_DS_NOTNOW_RECONFIG, setno,
					    mynode(), mynode(), NULL);
					retval = -4;
					goto out;
				} else {
					/* wait for 1 secs and try again. */
					free_result(resp);
					(void) sleep(1);
					continue;
				}
			}
		} else {
			/*
			 * If we get a NULL back from the rpc call, try to
			 * reinitialize the client.
			 * Depending on retries2 we try again, or not.
			 */
			syslog(LOG_INFO,
			    "send_message: ID=(%d, 0x%llx-%d) resp = NULL\n",
			    MSGID_ELEMS(msg.msg_msgid));

			clnt_destroy(local_daemon);
			local_daemon = mdmn_get_local_clnt(MNGLC_FOR_REAL);

			if (local_daemon == (CLIENT *)NULL) {
				return (-1);
			}
			clnt_control(local_daemon, CLSET_TIMEOUT,
			    (char *)&timeout);
		}

		/*
		 * If we are here, either resp is zero or resp is non-zero
		 * but some commstate not mentioned above occured.
		 * In either case we use retry2
		 */
		if (retry2-- == 0) {
			syslog(LOG_INFO, dgettext(TEXT_DOMAIN,
			    "send_message: (%d, 0x%llx-%d) retry2 exceeded\n"),
			    MSGID_ELEMS(msg.msg_msgid));

			retval = 2; /* retry2 exceeded */
			goto out;
		}
		if (flags & MD_MSGF_VERBOSE) {
			syslog(LOG_DEBUG, dgettext(TEXT_DOMAIN,
			    "send_message: (%d, 0x%llx-%d) resend on retry2\n"),
			    MSGID_ELEMS(msg.msg_msgid));
		}

		(void) usleep(ticks2 * USECS_PER_TICK);

		if (resp != (md_mn_result_t *)NULL) {
			free_result(resp);
		}
	}
out:
	mdmn_put_local_clnt(local_daemon);
	return (retval);
}

/*
 * suspend the commd for a given set/class combination.
 *
 * Parameter:
 *	set number or 0 (meaning all sets)
 *	class number or 0 (meaning all classes)
 *
 * Returns:
 *	0 on success (set is suspended and all messages drained)
 *	MDE_DS_COMMDCTL_SUSPEND_NYD if set is not yet drained
 *	MDE_DS_COMMDCTL_SUSPEND_FAIL if any failure occurred
 */
int
mdmn_suspend(set_t setno, md_mn_msgclass_t class, long timeout)
{
	int			*resp;
	CLIENT			*local_daemon;
	md_mn_set_and_class_t	msc;
	md_error_t		xep = mdnullerror;

	if ((setno >= MD_MAXSETS) || (class >= MD_MN_NCLASSES)) {
		return (MDE_DS_COMMDCTL_SUSPEND_FAIL);
	}
	local_daemon = meta_client_create(LOCALHOST_IPv4, MDMN_COMMD, TWO,
	    "tcp");
	if (local_daemon == (CLIENT *)NULL) {
		clnt_pcreateerror("local_daemon");
		return (MDE_DS_COMMDCTL_SUSPEND_FAIL);
	}

	if (timeout != 0) {
		if (cl_sto(local_daemon, LOCALHOST_IPv4, timeout, &xep) != 0) {
			clnt_destroy(local_daemon);
			return (1);
		}
	}

	msc.msc_set = setno;
	msc.msc_class = class;
	msc.msc_flags = 0;

	resp = mdmn_comm_suspend_2(&msc, local_daemon, 0);
	clnt_destroy(local_daemon);

	if (resp == NULL) {
		return (MDE_DS_COMMDCTL_SUSPEND_FAIL);
	}

	if (*resp == MDMNE_ACK) {
		/* set successfully drained, no outstanding messages */
		return (0);
	}
	if (*resp != MDMNE_SET_NOT_DRAINED) {
		/* some error occurred */
		return (MDE_DS_COMMDCTL_SUSPEND_FAIL);
	}

	/* still outstanding messages, return not yet drained failure */
	return (MDE_DS_COMMDCTL_SUSPEND_NYD);
}

/*
 * resume the commd for a given set/class combination.
 *
 * Parameter:
 *	set number or 0 (meaning all sets)
 *	class number or 0 (meaning all classes)
 *
 * Returns:
 *	0 on success
 *	MDE_DS_COMMDCTL_RESUME_FAIL on failure
 */
int
mdmn_resume(set_t setno, md_mn_msgclass_t class, uint_t flags, long timeout)
{
	md_mn_set_and_class_t	msc;
	int			ret = MDE_DS_COMMDCTL_RESUME_FAIL;
	int			*resp;
	CLIENT			*local_daemon;
	md_error_t		xep = mdnullerror;

	if ((setno >= MD_MAXSETS) || (class >= MD_MN_NCLASSES)) {
		return (MDE_DS_COMMDCTL_RESUME_FAIL);
	}
	local_daemon = meta_client_create(LOCALHOST_IPv4, MDMN_COMMD, TWO,
	    "tcp");
	if (local_daemon == (CLIENT *)NULL) {
		clnt_pcreateerror("local_daemon");
		return (MDE_DS_COMMDCTL_RESUME_FAIL);
	}

	if (timeout != 0) {
		if (cl_sto(local_daemon, LOCALHOST_IPv4, timeout, &xep) != 0) {
			clnt_destroy(local_daemon);
			return (1);
		}
	}

	msc.msc_set = setno;
	msc.msc_class = class;
	msc.msc_flags = flags;

	resp = mdmn_comm_resume_2(&msc, local_daemon, 0);

	if (resp != NULL) {
		if (*resp == MDMNE_ACK) {
			ret = 0;
		}
		Free(resp);
	}

	clnt_destroy(local_daemon);
	return (ret);
}

/*
 * abort all communication
 *
 * returns void, because: if *this* get's an error what do you want to do?
 */
void
mdmn_abort(void)
{
	char *dummy = "abort";
	md_mn_result_t	*resultp = NULL;
	md_error_t	mdne = mdnullerror;

	(void) mdmn_send_message(0, /* No set is needed for this message */
	    MD_MN_MSG_ABORT, MD_MSGF_LOCAL_ONLY, 0,
	    dummy, sizeof (dummy), &resultp, &mdne);

	if (resultp != NULL) {
		Free(resultp);
	}
}

/*
 * trigger the reinitialization for a given set.
 *
 * Parameter: set number
 *
 * Returns:
 *	0 on success
 *	1 on failure
 */
int
mdmn_reinit_set(set_t setno, long timeout)
{
	int		ret = 1;
	int		*resp;
	CLIENT 		*local_daemon;
	md_error_t	xep = mdnullerror;

	if ((setno == 0) || (setno >= MD_MAXSETS)) {
		return (1);
	}
	local_daemon = meta_client_create(LOCALHOST_IPv4, MDMN_COMMD, TWO,
	    "tcp");
	if (local_daemon == (CLIENT *)NULL) {
		clnt_pcreateerror("local_daemon");
		return (1);
	}

	if (timeout != 0) {
		if (cl_sto(local_daemon, LOCALHOST_IPv4, timeout, &xep) != 0) {
			clnt_destroy(local_daemon);
			return (1);
		}
	}

	resp = mdmn_comm_reinit_set_2(&setno, local_daemon, 0);

	if (resp != NULL) {
		if (*resp == MDMNE_ACK) {
			ret = 0;
		}
		Free(resp);
	}

	clnt_destroy(local_daemon);
	return (ret);
}


/*
 * Lock a single message type from being processed on this node
 *
 * Parameter: md_mn_msgtype_t msgtype, uint_t locktype
 *
 * Returns:
 *	0 on success
 *	1 on failure
 */
int
mdmn_msgtype_lock(md_mn_msgtype_t msgtype, uint_t locktype)
{
	int			ret = 1;
	int			*resp;
	CLIENT			*local_daemon;
	md_mn_type_and_lock_t	mmtl;


	if ((msgtype == 0) || (msgtype >= MD_MN_NMESSAGES)) {
		return (1);
	}
	local_daemon = meta_client_create(LOCALHOST_IPv4, MDMN_COMMD, TWO,
	    "tcp");
	if (local_daemon == (CLIENT *)NULL) {
		clnt_pcreateerror("local_daemon");
		return (1);
	}
	mmtl.mmtl_type = msgtype;
	mmtl.mmtl_lock = locktype;

	resp = mdmn_comm_msglock_2(&mmtl, local_daemon, 0);

	if (resp != NULL) {
		if (*resp == MDMNE_ACK) {
			ret = 0;
		}
		Free(resp);
	}

	clnt_destroy(local_daemon);
	return (ret);
}
