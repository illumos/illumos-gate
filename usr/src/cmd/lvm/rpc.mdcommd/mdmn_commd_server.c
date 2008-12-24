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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uadmin.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdio.h>
#include <thread.h>
#include <meta.h>
#include <sdssc.h>
#include <mdmn_changelog.h>
#include "mdmn_subr.h"

/*
 * This is the communication daemon for SVM Multi Node Disksets.
 * It runs on every node and provides the following rpc services:
 *  - mdmn_send_svc_2
 *  - mdmn_work_svc_2
 *  - mdmn_wakeup_initiator_svc_2
 *  - mdmn_wakeup_master_svc_2
 *  - mdmn_comm_lock_svc_2
 *  - mdmn_comm_unlock_svc_2
 *  - mdmn_comm_suspend_svc_2
 *  - mdmn_comm_resume_svc_2
 *  - mdmn_comm_reinit_set_svc_2
 * where send, lock, unlock and reinit are meant for external use,
 * work and the two wakeups are for internal use only.
 *
 * NOTE:
 * On every node only one of those xxx_2 functions can be active at the
 * same time because the daemon is single threaded.
 *
 * (not quite true, as mdmn_send_svc_2 and mdmn_work_svc_2 do thr_create()s
 * as part of their handlers, so those aspects are multi-threaded)
 *
 * In case an event occurs that has to be propagated to all the nodes...
 *
 * One node (the initiator)
 *	calls the libmeta function mdmn_send_message()
 *	This function calls the local daemon thru mdmn_send_svc_2.
 *
 * On the initiator:
 *	mdmn_send_svc_2()
 *	    - starts a thread -> mdmn_send_to_work() and returns.
 *	mdmn_send_to_work()
 *	    - sends this message over to the master of the diskset.
 *	      This is done by calling mdmn_work_svc_2 on the master.
 *	    - registers to the initiator_table
 *	    - exits without doing a svc_sendreply() for the call to
 *	      mdmn_send_svc_2. This means that call is blocked until somebody
 *	      (see end of this comment) does a svc_sendreply().
 *	      This means mdmn_send_message() does not yet return.
 *	    - A timeout surveillance is started at this point.
 *	      This means in case the master doesn't reply at all in an
 *	      aproppriate time, an error condition is returned
 *	      to the caller.
 *
 * On the master:
 *	mdmn_work_svc_2()
 *	    - starts a thread -> mdmn_master_process_msg() and returns
 *	mdmn_master_process_msg()
 *	    - logs the message to the change log
 *	    - executes the message locally
 *	    - flags the message in the change log
 *	    - sends the message to mdmn_work_svc_2() on all the
 *	      other nodes (slaves)
 *	      after each call to mdmn_work_svc_2 the thread goes to sleep and
 *	      will be woken up by mdmn_wakeup_master_svc_2() as soon as the
 *	      slave node is done with this message.
 *	    - In case the slave doesn't respond in a apropriate time, an error
 *	      is assumed to ensure the master doesn't wait forever.
 *
 * On a slave:
 *	mdmn_work_svc_2()
 *	    - starts a thread -> mdmn_slave_process_msg() and returns
 *	mdmn_slave_process_msg()
 *	    - processes this message locally by calling the appropriate message
 *	      handler, that creates some result.
 *	    - sends that result thru a call to mdmn_wakeup_master_svc_2() to
 *	      the master.
 *
 * Back on the master:
 *	mdmn_wakeup_master_svc_2()
 *	    - stores the result into the master_table.
 *	    - signals the mdmn_master_process_msg-thread.
 *	    - returns
 *	mdmn_master_process_msg()
 *	    - after getting the results from all nodes
 *	    - sends them back to the initiating node thru a call to
 *	      mdmn_wakeup_initiator_svc_2.
 *
 * Back on the initiator:
 *	mdmn_wakeup_initiator_svc_2()
 *	    - calls svc_sendreply() which makes the call to mdmn_send_svc_2()
 *	      return.
 *	      which allows the initial mdmn_send_message() call to return.
 */

FILE *commdout;		/* debug output for the commd */
char *commdoutfile;	/* file name for the above output */
/* want at least 10 MB free space when logging into a file */
#define	MIN_FS_SPACE	(10LL * 1024 * 1024)

/*
 * Number of outstanding messages that were initiated by this node.
 * If zero, check_timeouts goes to sleep
 */
uint_t	messages_on_their_way;
mutex_t	check_timeout_mutex;	/* need mutex to protect above */
cond_t	check_timeout_cv;	/* trigger for check_timeouts */

/* for printing out time stamps */
hrtime_t __savetime;

/* RPC clients for every set and every node and their protecting locks */
CLIENT	*client[MD_MAXSETS][NNODES];
rwlock_t client_rwlock[MD_MAXSETS];

/* the descriptors of all possible sets and their protectors */
struct md_set_desc *set_descriptor[MD_MAXSETS];
rwlock_t set_desc_rwlock[MD_MAXSETS];

/* the daemon to daemon communication has to timeout quickly */
static struct timeval FOUR_SECS = { 4, 0 };

/* These indicate if a set has already been setup */
int md_mn_set_inited[MD_MAXSETS];

/* For every set we have a message completion table and protecting mutexes */
md_mn_mct_t *mct[MD_MAXSETS];
mutex_t	mct_mutex[MD_MAXSETS][MD_MN_NCLASSES];

/* Stuff to describe the global status of the commd on one node */
#define	MD_CGS_INITED		0x0001
#define	MD_CGS_ABORTED		0x0002	/* return everything with MDMNE_ABORT */
uint_t md_commd_global_state = 0;	/* No state when starting up */

/*
 * Global verbosity level for the daemon
 */
uint_t md_commd_global_verb;

/*
 * libmeta doesn't like multiple threads in metaget_setdesc().
 * So we must protect access to it with a global lock
 */
mutex_t get_setdesc_mutex;

/*
 * Need a way to block single message types,
 * hence an array with a status for every message type
 */
uint_t msgtype_lock_state[MD_MN_NMESSAGES];

/* for reading in the config file */
#define	MAX_LINE_SIZE 1024

extern char *commd_get_outfile(void);
extern uint_t commd_get_verbosity(void);

/*
 * mdmn_clnt_create is a helper function for meta_client_create_retry.  It
 * merely needs to call clnt_create_timed, and meta_client_create_retry
 * will take care of the rest.
 */
/* ARGSUSED */
static CLIENT *
mdmn_clnt_create(char *ignore, void *data, struct timeval *time_out)
{
	md_mnnode_desc	*node = (md_mnnode_desc *)data;

	return (clnt_create_timed(node->nd_priv_ic, MDMN_COMMD, TWO, "tcp",
	    time_out));
}

#define	FLUSH_DEBUGFILE() \
	if (commdout != (FILE *)NULL) { \
		fflush(commdout); \
		fsync(fileno(commdout)); \
	}

static void
panic_system(int nid, md_mn_msgtype_t type, int master_err, int master_exitval,
    md_mn_result_t *slave_result)
{
	md_mn_commd_err_t	commd_err;
	md_error_t		mne = mdnullerror;
	char			*msg_buf;

	msg_buf = (char *)calloc(MAXPATHLEN + 1, sizeof (char));

	FLUSH_DEBUGFILE();

	if (master_err != MDMNE_ACK) {
		snprintf(msg_buf, MAXPATHLEN, "rpc.mdcommd: RPC fail on master "
		    "when processing message type %d\n", type);
	} else if (slave_result == NULL) {
		snprintf(msg_buf, MAXPATHLEN, "rpc.mdcommd: RPC fail on node "
		    "%d when processing message type %d\n", nid, type);
	} else {
		snprintf(msg_buf, MAXPATHLEN, "rpc.mdcommd: Inconsistent "
		    "return value from node %d when processing message "
		    "type %d. Master exitval = %d, Slave exitval = %d\n",
		    nid, type, master_exitval, slave_result->mmr_exitval);
	}
	commd_err.size = strlen(msg_buf);
	commd_err.md_message = (uint64_t)(uintptr_t)&msg_buf[0];

	metaioctl(MD_MN_COMMD_ERR, &commd_err, &mne, "rpc.mdcommd");
	(void) uadmin(A_DUMP, AD_BOOT, NULL);
}

static void
flush_fcout()
{
	struct statvfs64 vfsbuf;
	long long avail_bytes;
	int warned = 0;

	for (; ; ) {
		sleep(10);
		/* No output file, nothing to do */
		if (commdout == (FILE *)NULL)
			continue;

		/*
		 * stat the appropriate filesystem to check for available space.
		 */
		if (statvfs64(commdoutfile, &vfsbuf)) {
			continue;
		}

		avail_bytes = vfsbuf.f_frsize * vfsbuf.f_bavail;
		/*
		 * If we don't have enough space, we print out a warning.
		 * And we drop the verbosity level to NULL
		 * In case the condtion doesn't go away, we don't repeat
		 * the warning.
		 */
		if (avail_bytes < MIN_FS_SPACE) {
			if (warned) {
				continue;
			}
			commd_debug(MD_MMV_SYSLOG,
			    "NOT enough space available for logging\n");
			commd_debug(MD_MMV_SYSLOG,
			    "Have %lld bytes, need %lld bytes\n",
			    avail_bytes, MIN_FS_SPACE);
			warned = 1;
			md_commd_global_verb = MD_MMV_NULL;
		} else {
			warned = 0;
		}

		fflush(commdout);
	}
}

/* safer version of clnt_destroy. If clnt is NULL don't do anything */
#define	mdmn_clnt_destroy(clnt) {	\
	if (clnt)			\
		clnt_destroy(clnt);	\
}

/*
 * Own version of svc_sendreply that checks the integrity of the transport
 * handle and so prevents us from core dumps in the real svc_sendreply()
 */
void
mdmn_svc_sendreply(SVCXPRT *transp, xdrproc_t xdr, caddr_t data)
{
	if (SVC_STAT(transp) == XPRT_DIED) {
		commd_debug(MD_MMV_MISC,
		    "mdmn_svc_sendreply: XPRT_DIED\n");
		return;
	}
	(void) svc_sendreply(transp, xdr, data);
}

/*
 * timeout_initiator(set, class)
 *
 * Alas, I sent a message and didn't get a response back in aproppriate time.
 *
 * timeout_initiator() takes care for doing the needed svc_sendreply() to the
 * calling mdmn_send_message, so that guy doesn't wait forever
 * What is done here is pretty much the same as what is done in
 * wakeup initiator. The difference is that we cannot provide for any results,
 * of course and we set the comm_state to MDMNE_TIMEOUT.
 *
 * By doing so, mdmn_send_message can decide if a retry would make sense or not.
 * It's not our's to decide that here.
 */
void
timeout_initiator(set_t setno, md_mn_msgclass_t class)
{
	SVCXPRT		*transp;
	md_mn_msgid_t	mid;
	md_mn_result_t *resultp;

	resultp = Zalloc(sizeof (md_mn_result_t));
	resultp->mmr_comm_state	= MDMNE_TIMEOUT;

	commd_debug(MD_MMV_MISC,
	    "timeout_initiator set = %d, class = %d\n", setno, class);

	transp = mdmn_get_initiator_table_transp(setno, class);
	mdmn_get_initiator_table_id(setno, class, &mid);

	commd_debug(MD_MMV_MISC, "timeout_ini: (%d, 0x%llx-%d)\n",
	    MSGID_ELEMS(mid));
	/*
	 * Give the result the corresponding msgid from the failed message.
	 */
	MSGID_COPY(&mid, &(resultp->mmr_msgid));

	/* return to mdmn_send_message() and let it deal with the situation */
	mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);

	free(resultp);
	commd_debug(MD_MMV_MISC, "timeout_ini: sendreplied\n");
	svc_done(transp);
	mdmn_unregister_initiator_table(setno, class);
}


/*
 * check_timeouts - thread
 *
 * This implements a timeout surveillance for messages sent from the
 * initiator to the master.
 *
 * If a message is started, this thread is triggered thru
 * cond_signal(&check_timeout_cv) and we keep track of the numbers of
 * messages that are outstanding (messages_on_their_way).
 *
 * As long as there are messages on their way, this thread never goes to sleep.
 * It'll keep checking all class/set combinations for outstanding messages.
 * If one is found, it's checked if this message is overdue. In that case,
 * timeout_initiator() is called to wakeup the calling mdmn_send_message and
 * to clean up the mess.
 *
 * If the result from the master arrives later, this message is considered
 * to be unsolicited. And will be ignored.
 */

void
check_timeouts()
{
	set_t			setno;
	time_t			now, then;
	mutex_t			*mx;
	md_mn_msgclass_t	class;

	for (; ; ) {
		now = time((time_t *)NULL);
		for (setno = 1; setno < MD_MAXSETS; setno++) {
			if (md_mn_set_inited[setno] != MDMN_SET_READY) {
				continue;
			}
			for (class = MD_MSG_CLASS1; class < MD_MN_NCLASSES;
			    class++) {
				mx = mdmn_get_initiator_table_mx(setno, class);
				mutex_lock(mx);

				/* then is the registered time */
				then =
				    mdmn_get_initiator_table_time(setno, class);
				if ((then != 0) && (now > then)) {
					timeout_initiator(setno, class);
				}
				mutex_unlock(mx);
			}
		}
		/* it's ok to check only once per second */
		sleep(1);

		/* is there work to do? */
		mutex_lock(&check_timeout_mutex);
		if (messages_on_their_way == 0) {
			cond_wait(&check_timeout_cv, &check_timeout_mutex);
		}
		mutex_unlock(&check_timeout_mutex);
	}
}

void
setup_debug(void)
{
	char	*tmp_dir;

	/* Read in the debug-controlling tokens from runtime.cf */
	md_commd_global_verb = commd_get_verbosity();
	/*
	 * If the user didn't specify a verbosity level in runtime.cf
	 * we can safely return here. As we don't intend to printout
	 * debug messages, we don't need to check for the output file.
	 */
	if (md_commd_global_verb == 0) {
		return;
	}

	/* if commdout is non-NULL it is an open FILE, we'd better close it */
	if (commdout != (FILE *)NULL) {
		fclose(commdout);
	}

	commdoutfile = commd_get_outfile();

	/* setup the debug output */
	if (commdoutfile == (char *)NULL) {
		/* if no valid file was specified, use the default */
		commdoutfile = "/var/run/commd.out";
		commdout = fopen(commdoutfile, "a");
	} else {
		/* check if the directory exists and is writable */
		tmp_dir = strdup(commdoutfile);
		if ((access(dirname(tmp_dir), X_OK|W_OK)) ||
		    ((commdout = fopen(commdoutfile, "a")) == (FILE *)NULL)) {
			syslog(LOG_ERR,
			    "Can't write to specified output file %s,\n"
			    "using /var/run/commd.out instead\n", commdoutfile);
			free(commdoutfile);
			commdoutfile = "/var/run/commd.out";
			commdout = fopen(commdoutfile, "a");
		}
		free(tmp_dir);
	}

	if (commdout == (FILE *)NULL) {
		syslog(LOG_ERR, "Can't write to debug output file %s\n",
		    commdoutfile);
	}
}

/*
 * mdmn_is_node_dead checks to see if a node is dead using
 * the SunCluster infrastructure which is a stable interface.
 * If unable to contact SunCuster the node is assumed to be alive.
 * Return values:
 *	1 - node is dead
 *	0 - node is alive
 */
int
mdmn_is_node_dead(md_mnnode_desc *node)
{
	char	*fmt = "/usr/cluster/bin/scha_cluster_get -O NODESTATE_NODE ";
	char	*cmd;
	size_t	size;
	char	buf[10];
	FILE	*ptr;
	int	retval = 0;

	/* I know that I'm alive */
	if (strcmp(node->nd_nodename, mynode()) == 0)
		return (retval);

	size = strlen(fmt) + strlen(node->nd_nodename) + 1;
	cmd = Zalloc(size);
	(void) strlcat(cmd, fmt, size);
	(void) strlcat(cmd, node->nd_nodename, size);

	if ((ptr = popen(cmd, "r")) != NULL) {
		if (fgets(buf, sizeof (buf), ptr) != NULL) {
			/* If scha_cluster_get returned DOWN - return dead */
			if (strncmp(buf, "DOWN", 4) == 0)
				retval = 1;
		}
		(void) pclose(ptr);
	}
	Free(cmd);
	return (retval);
}

/*
 * global_init()
 *
 * Perform some global initializations.
 *
 * the following routines have to call this before operation can start:
 *  - mdmn_send_svc_2
 *  - mdmn_work_svc_2
 *  - mdmn_comm_lock_svc_2
 *  - mdmn_comm_unlock_svc_2
 *  - mdmn_comm_suspend_svc_2
 *  - mdmn_comm_resume_svc_2
 *  - mdmn_comm_reinit_set_svc_2
 *
 * This is a single threaded daemon, so it can only be in one of the above
 * routines at the same time.
 * This means, global_init() cannot be called more than once at the same time.
 * Hence, no lock is needed.
 */
void
global_init(void)
{
	set_t			set;
	md_mn_msgclass_t	class;
	struct sigaction	sighandler;
	time_t			clock_val;
	struct rlimit		commd_limit;



	/* Do these global initializations only once */
	if (md_commd_global_state & MD_CGS_INITED) {
		return;
	}
	(void) sdssc_bind_library();

	/* setup the debug options from the config file */
	setup_debug();

	/* make sure that we don't run out of file descriptors */
	commd_limit.rlim_cur = commd_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &commd_limit) != 0) {
		syslog(LOG_WARNING, gettext("setrlimit failed."
		    "Could not increase the max file descriptors"));
	}

	/* Make setup_debug() be the action in case of SIGHUP */
	sighandler.sa_flags = 0;
	sigfillset(&sighandler.sa_mask);
	sighandler.sa_handler = (void (*)(int)) setup_debug;
	sigaction(SIGHUP, &sighandler, NULL);

	__savetime = gethrtime();
	(void) time(&clock_val);
	commd_debug(MD_MMV_MISC, "global init called %s\n", ctime(&clock_val));

	/* start a thread that flushes out the debug on a regular basis */
	thr_create(NULL, 0, (void *(*)(void *))flush_fcout,
	    (void *) NULL, THR_DETACHED, NULL);

	/* global rwlock's / mutex's / cond_t's go here */
	mutex_init(&check_timeout_mutex, USYNC_THREAD, NULL);
	cond_init(&check_timeout_cv, USYNC_THREAD, NULL);
	mutex_init(&get_setdesc_mutex, USYNC_THREAD, NULL);

	/* Make sure the initiator table is initialized correctly */
	for (set = 0; set < MD_MAXSETS; set++) {
		for (class = 0; class < MD_MN_NCLASSES; class++) {
			mdmn_unregister_initiator_table(set, class);
		}
	}


	/* setup the check for timeouts */
	thr_create(NULL, 0, (void *(*)(void *))check_timeouts,
	    (void *) NULL, THR_DETACHED, NULL);

	md_commd_global_state |= MD_CGS_INITED;
}


/*
 * mdmn_init_client(setno, nodeid)
 * called if client[setno][nodeid] is NULL
 *
 * NOTE: Must be called with set_desc_rwlock held as a reader
 * NOTE: Must be called with client_rwlock held as a writer
 *
 * If the rpc client for this node has not been setup for any set, we do it now.
 *
 * Returns	0 on success (node found in set, rpc client setup)
 *		-1 if metaget_setdesc failed,
 *		-2 if node not part of set
 *		-3 if clnt_create fails
 */
static int
mdmn_init_client(set_t setno, md_mn_nodeid_t nid)
{
	md_error_t	ep = mdnullerror;
	md_mnnode_desc	*node;
	md_set_desc	*sd;	/* just an abbr for set_descriptor[setno] */

	sd = set_descriptor[setno];

	/*
	 * Is the appropriate set_descriptor already initialized ?
	 * Can't think of a scenario where this is not the case, but we'd better
	 * check for it anyway.
	 */
	if (sd == NULL) {
		mdsetname_t	*sp;

		rw_unlock(&set_desc_rwlock[setno]); /* readlock -> writelock */
		rw_wrlock(&set_desc_rwlock[setno]);
		sp = metasetnosetname(setno, &ep);
		/* Only one thread is supposed to be in metaget_setdesc() */
		mutex_lock(&get_setdesc_mutex);
		sd = metaget_setdesc(sp, &ep);
		mutex_unlock(&get_setdesc_mutex);
		if (sd == NULL) {
			rw_unlock(&set_desc_rwlock[setno]); /* back to ... */
			rw_rdlock(&set_desc_rwlock[setno]); /* ... readlock */
			return (-1);
		}
		set_descriptor[setno] = sd;
		rw_unlock(&set_desc_rwlock[setno]); /* back to readlock */
		rw_rdlock(&set_desc_rwlock[setno]);
	}

	/* first we have to find the node name for this node id */
	for (node = sd->sd_nodelist; node; node = node->nd_next) {
		if (node->nd_nodeid == nid)
			break; /* we found our node in this set */
	}


	if (node == (md_mnnode_desc *)NULL) {
		commd_debug(MD_MMV_SYSLOG,
		    "FATAL: node %d not found in set %d\n", nid, setno);
		rw_unlock(&set_desc_rwlock[setno]);
		return (-2);
	}

	commd_debug(MD_MMV_INIT, "init: %s has the flags: 0x%x\n",
	    node->nd_nodename ? node->nd_nodename : "NULL", node->nd_flags);

	/* Did this node join the diskset?  */
	if ((node->nd_flags & MD_MN_NODE_OWN) == 0) {
		commd_debug(MD_MMV_INIT, "init: %s didn't join set %d\n",
		    node->nd_nodename ? node->nd_nodename : "NULL", setno);
		rw_unlock(&set_desc_rwlock[setno]);
		return (-2);
	}

	/* if clnt_create has not been done for that node, do it now */
	if (client[setno][nid] == (CLIENT *) NULL) {
		time_t	tout = 0;

		/*
		 * While trying to create a connection to a node,
		 * periodically check to see if the node has been marked
		 * dead by the SunCluster infrastructure.
		 * This periodic check is needed since a non-responsive
		 * rpc.mdcommd (while it is attempting to create a connection
		 * to a dead node) can lead to large delays and/or failures
		 * in the reconfig steps.
		 */
		while ((client[setno][nid] == (CLIENT *) NULL) &&
		    (tout < MD_CLNT_CREATE_TOUT)) {
			client[setno][nid] = meta_client_create_retry(
			    node->nd_nodename, mdmn_clnt_create,
			    (void *) node, MD_CLNT_CREATE_SUBTIMEOUT, &ep);
			/* Is the node dead? */
			if (mdmn_is_node_dead(node) == 1) {
				commd_debug(MD_MMV_SYSLOG,
				    "rpc.mdcommd: no client for dead node %s\n",
				    node->nd_nodename);
				break;
			} else
				tout += MD_CLNT_CREATE_SUBTIMEOUT;
		}

		if (client[setno][nid] == (CLIENT *) NULL) {
			clnt_pcreateerror(node->nd_nodename);
			rw_unlock(&set_desc_rwlock[setno]);
			return (-3);
		}
		/* this node has the license to send */
		commd_debug(MD_MMV_MISC, "init_client: calling add_lic\n");
		add_license(node);

		/* set the timeout value */
		clnt_control(client[setno][nid], CLSET_TIMEOUT,
		    (char *)&FOUR_SECS);

	}
	rw_unlock(&set_desc_rwlock[setno]);
	return (0);
}

/*
 * check_client(setno, nodeid)
 *
 * must be called with reader lock held for set_desc_rwlock[setno]
 * and must be called with reader lock held for client_rwlock[setno]
 * Checks if the client for this set/node combination is already setup
 * if not it upgrades the lock to a writer lock
 * and tries to initialize the client.
 * Finally it's checked if the client nulled out again due to some race
 *
 * returns 0 if there is a usable client
 * returns MDMNE_RPC_FAIL otherwise
 */
static int
check_client(set_t setno, md_mn_nodeid_t nodeid)
{
	int ret = 0;

	while ((client[setno][nodeid] == (CLIENT *)NULL) && (ret == 0)) {
		rw_unlock(&client_rwlock[setno]); /* upgrade reader ... */
		rw_wrlock(&client_rwlock[setno]); /* ... to writer lock. */
		if (mdmn_init_client(setno, nodeid) != 0) {
			ret = MDMNE_RPC_FAIL;
		}
		rw_unlock(&client_rwlock[setno]); /* downgrade writer ... */
		rw_rdlock(&client_rwlock[setno]); /* ... back to reader lock. */
	}
	return (ret);
}

/*
 * mdmn_init_set(setno, todo)
 * setno is the number of the set to be initialized.
 * todo is one of the MDMN_SET_* thingies or MDMN_SET_READY
 * If called with MDMN_SET_READY everything is initialized.
 *
 * If the set mutexes are already initialized, the caller has to hold
 * both set_desc_rwlock[setno] and client_rwlock[setno] as a writer, before
 * calling mdmn_init_set()
 */
int
mdmn_init_set(set_t setno, int todo)
{
	int class;
	md_mnnode_desc	*node;
	md_set_desc	*sd; /* just an abbr for set_descriptor[setno] */
	mdsetname_t	*sp;
	md_error_t	ep = mdnullerror;
	md_mn_nodeid_t	nid;

	/*
	 * Check if we are told to setup the mutexes and
	 * if these are not yet setup
	 */
	if ((todo & MDMN_SET_MUTEXES) &&
	    ((md_mn_set_inited[setno] & MDMN_SET_MUTEXES) == 0)) {
		mutex_init(&mdmn_busy_mutex[setno], USYNC_THREAD, NULL);
		cond_init(&mdmn_busy_cv[setno], USYNC_THREAD, NULL);
		rwlock_init(&client_rwlock[setno], USYNC_THREAD, NULL);
		rwlock_init(&set_desc_rwlock[setno], USYNC_THREAD, NULL);

		for (class = MD_MSG_CLASS1; class < MD_MN_NCLASSES; class++) {
			mutex_init(mdmn_get_master_table_mx(setno, class),
			    USYNC_THREAD, NULL);
			cond_init(mdmn_get_master_table_cv(setno, class),
			    USYNC_THREAD, NULL);
			mutex_init(mdmn_get_initiator_table_mx(setno, class),
			    USYNC_THREAD, NULL);
		}
		md_mn_set_inited[setno] |= MDMN_SET_MUTEXES;
	}
	if ((todo & MDMN_SET_MCT) &&
	    ((md_mn_set_inited[setno] & MDMN_SET_MCT) == 0)) {
		int	fd;
		size_t	filesize;
		caddr_t	addr;
		char table_name[32];

		filesize = (sizeof (md_mn_mct_t));
		(void) snprintf(table_name, sizeof (table_name), "%s%d",
		    MD_MN_MSG_COMP_TABLE, setno);
		/*
		 * If the mct file exists we map it into memory.
		 * Otherwise we create an empty file of appropriate
		 * size and map that into memory.
		 * The mapped areas are stored in mct[setno].
		 */
		fd = open(table_name, O_RDWR|O_CREAT|O_DSYNC, 0600);
		if (fd < 0) {
			commd_debug(MD_MMV_MISC,
			    "init_set: Can't open MCT\n");
			return (-1);
		}
		/*
		 * To ensure that the file has the appropriate size,
		 * we write a byte at the end of the file.
		 */
		lseek(fd, filesize + 1, SEEK_SET);
		write(fd, "\0", 1);

		/* at this point we have a file in place that we can mmap */
		addr = mmap(0, filesize, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, (off_t)0);
		if (addr == MAP_FAILED) {
			commd_debug(MD_MMV_INIT,
			    "init_set: mmap mct error %d\n",
			    errno);
			return (-1);
		}
		/* LINTED pointer alignment */
		mct[setno] = (md_mn_mct_t *)addr;

		/* finally we initialize the mutexes that protect the mct */
		for (class = MD_MSG_CLASS1; class < MD_MN_NCLASSES; class++) {
			mutex_init(&(mct_mutex[setno][class]),
			    USYNC_THREAD, NULL);
		}

		md_mn_set_inited[setno] |= MDMN_SET_MCT;
	}
	/*
	 * Check if we are told to setup the nodes and
	 * if these are not yet setup
	 * (Attention: negative logic here compared to above!)
	 */
	if (((todo & MDMN_SET_NODES) == 0) ||
	    (md_mn_set_inited[setno] & MDMN_SET_NODES)) {
		return (0); /* success */
	}

	if ((sp = metasetnosetname(setno, &ep)) == NULL) {
		commd_debug(MD_MMV_SYSLOG,
		    "metasetnosetname(%d) returned NULL\n", setno);
		return (MDMNE_NOT_JOINED);
	}

	/* flush local copy of rpc.metad data */
	metaflushsetname(sp);

	mutex_lock(&get_setdesc_mutex);
	sd = metaget_setdesc(sp, &ep);
	mutex_unlock(&get_setdesc_mutex);

	if (sd == NULL) {
		commd_debug(MD_MMV_SYSLOG,
		    "metaget_setdesc(%d) returned NULL\n", setno);
		return (MDMNE_NOT_JOINED);
	}

	/*
	 * if this set is not a multinode set or
	 * this node didn't join yet the diskset, better don't do anything
	 */
	if ((MD_MNSET_DESC(sd) == 0) ||
	    (sd->sd_mn_mynode->nd_flags & MD_MN_NODE_OWN) == 0) {
		commd_debug(MD_MMV_INIT, "didn't yet join set %d\n", setno);
		return (MDMNE_NOT_JOINED);
	}

	for (node = sd->sd_nodelist; node != NULL; node = node->nd_next) {
		time_t	tout = 0;
		nid = node->nd_nodeid;

		commd_debug(MD_MMV_INIT,
		    "setting up: node=%s, priv_ic=%s, flags=0x%x\n",
		    node->nd_nodename ? node->nd_nodename : "NULL",
		    node->nd_priv_ic ? node->nd_priv_ic : "NULL",
		    node->nd_flags);

		if ((node->nd_flags & MD_MN_NODE_OWN) == 0) {
			commd_debug(MD_MMV_INIT,
			    "init: %s didn't join set %d\n",
			    node->nd_nodename ? node->nd_nodename : "NULL",
			    setno);
			continue;
		}

		if (client[setno][nid] != (CLIENT *) NULL) {
			/* already inited */
			commd_debug(MD_MMV_INIT, "init: already: node=%s\n",
			    node->nd_nodename ? node->nd_nodename : "NULL");
			continue;
		}

		/*
		 * While trying to create a connection to a node,
		 * periodically check to see if the node has been marked
		 * dead by the SunCluster infrastructure.
		 * This periodic check is needed since a non-responsive
		 * rpc.mdcommd (while it is attempting to create a connection
		 * to a dead node) can lead to large delays and/or failures
		 * in the reconfig steps.
		 */
		while ((client[setno][nid] == (CLIENT *) NULL) &&
		    (tout < MD_CLNT_CREATE_TOUT)) {
			client[setno][nid] = meta_client_create_retry(
			    node->nd_nodename, mdmn_clnt_create,
			    (void *) node, MD_CLNT_CREATE_SUBTIMEOUT, &ep);
			/* Is the node dead? */
			if (mdmn_is_node_dead(node) == 1) {
				commd_debug(MD_MMV_SYSLOG,
				    "rpc.mdcommd: no client for dead node %s\n",
				    node->nd_nodename);
				break;
			} else
				tout += MD_CLNT_CREATE_SUBTIMEOUT;
		}

		if (client[setno][nid] == (CLIENT *) NULL) {
			clnt_pcreateerror(node->nd_nodename);
			/*
			 * If we cannot connect to a single node
			 * (maybe because it is down) we mark this node as not
			 * owned and continue with the next node in the list.
			 * This is better than failing the entire starting up
			 * of the commd system.
			 */
			node->nd_flags &= ~MD_MN_NODE_OWN;
			commd_debug(MD_MMV_SYSLOG,
			    "WARNING couldn't create client for %s\n"
			    "Reconfig cycle required\n",
			    node->nd_nodename);
			commd_debug(MD_MMV_INIT,
			    "WARNING couldn't create client for %s\n"
			    "Reconfig cycle required\n",
			    node->nd_nodename);
			continue;
		}
		/* this node has the license to send */
		commd_debug(MD_MMV_MISC, "init_set: calling add_lic\n");
		add_license(node);

		/* set the timeout value */
		clnt_control(client[setno][nid], CLSET_TIMEOUT,
		    (char *)&FOUR_SECS);

		commd_debug(MD_MMV_INIT, "init: done: node=%s\n",
		    node->nd_nodename ? node->nd_nodename : "NULL");
	}

	set_descriptor[setno] = sd;
	md_mn_set_inited[setno] |= MDMN_SET_NODES;
	return (0); /* success */
}

void *
mdmn_send_to_work(void *arg)
{
	int			*rpc_err = NULL;
	int			success;
	int			try_master;
	set_t			setno;
	mutex_t			*mx;	/* protection for initiator_table */
	SVCXPRT			*transp;
	md_mn_msg_t		*msg;
	md_mn_nodeid_t		set_master;
	md_mn_msgclass_t	class;
	md_mn_msg_and_transp_t	*matp = (md_mn_msg_and_transp_t *)arg;

	msg			= matp->mat_msg;
	transp			= matp->mat_transp;

	class = mdmn_get_message_class(msg->msg_type);
	setno = msg->msg_setno;

	/* set the sender, so the master knows who to send the results */
	rw_rdlock(&set_desc_rwlock[setno]);
	msg->msg_sender = set_descriptor[setno]->sd_mn_mynode->nd_nodeid;
	set_master	= set_descriptor[setno]->sd_mn_master_nodeid;

	mx = mdmn_get_initiator_table_mx(setno, class);
	mutex_lock(mx);

	/*
	 * Here we check, if the initiator table slot for this set/class
	 * combination is free to use.
	 * If this is not the case, we return CLASS_BUSY forcing the
	 * initiating send_message call to retry
	 */
	success = mdmn_check_initiator_table(setno, class);
	if (success == MDMNE_CLASS_BUSY) {
		md_mn_msgid_t		active_mid;

		mdmn_get_initiator_table_id(setno, class, &active_mid);

		commd_debug(MD_MMV_SEND,
		    "send_to_work: received but locally busy "
		    "(%d, 0x%llx-%d), set=%d, class=%d, type=%d, "
		    "active msg=(%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(msg->msg_msgid), setno, class,
		    msg->msg_type, MSGID_ELEMS(active_mid));
	} else {
		commd_debug(MD_MMV_SEND,
		    "send_to_work: received (%d, 0x%llx-%d), "
		    "set=%d, class=%d, type=%d\n",
		    MSGID_ELEMS(msg->msg_msgid), setno, class, msg->msg_type);
	}

	try_master = 2; /* return failure after two retries */
	while ((success == MDMNE_ACK) && (try_master--)) {
		rw_rdlock(&client_rwlock[setno]);
		/* is the rpc client to the master still around ? */
		if (check_client(setno, set_master)) {
			success = MDMNE_RPC_FAIL;
			FLUSH_DEBUGFILE();
			rw_unlock(&client_rwlock[setno]);
			break; /* out of try_master-loop */
		}

		/*
		 * Send the request to the work function on the master
		 * this call will return immediately
		 */
		rpc_err = mdmn_work_2(msg, client[setno][set_master],
		    set_master);

		/* Everything's Ok? */
		if (rpc_err == NULL) {
			success = MDMNE_RPC_FAIL;
			/*
			 * Probably something happened to the daemon on the
			 * master. Kill the client, and try again...
			 */
			rw_unlock(&client_rwlock[setno]);
			rw_wrlock(&client_rwlock[setno]);
			mdmn_clnt_destroy(client[setno][set_master]);
			if (client[setno][set_master] != (CLIENT *)NULL) {
				client[setno][set_master] = (CLIENT *)NULL;
			}
			rw_unlock(&client_rwlock[setno]);
			continue;

		} else  if (*rpc_err != MDMNE_ACK) {
			/* something went wrong, break out */
			success = *rpc_err;
			free(rpc_err);
			rw_unlock(&client_rwlock[setno]);
			break; /* out of try_master-loop */
		}

		rw_unlock(&client_rwlock[setno]);
		free(rpc_err);

		/*
		 * If we are here, we sucessfully delivered the message.
		 * We register the initiator_table, so that
		 * wakeup_initiator_2 can do the sendreply with the
		 * results for us.
		 */
		success = MDMNE_ACK;
		mdmn_register_initiator_table(setno, class, msg, transp);

		/* tell check_timeouts, there's work to do */
		mutex_lock(&check_timeout_mutex);
		messages_on_their_way++;
		cond_signal(&check_timeout_cv);
		mutex_unlock(&check_timeout_mutex);
		break; /* out of try_master-loop */
	}

	rw_unlock(&set_desc_rwlock[setno]);

	if (success == MDMNE_ACK) {
		commd_debug(MD_MMV_SEND,
		    "send_to_work: registered (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(msg->msg_msgid));
	} else {
		/* In case of failure do the sendreply now */
		md_mn_result_t *resultp;
		resultp = Zalloc(sizeof (md_mn_result_t));
		resultp->mmr_comm_state = success;
		/*
		 * copy the MSGID so that we know _which_ message
		 * failed (if the transp has got mangled)
		 */
		MSGID_COPY(&(msg->msg_msgid), &(resultp->mmr_msgid));
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);
		commd_debug(MD_MMV_SEND,
		    "send_to_work: not registered (%d, 0x%llx-%d) cs=%d\n",
		    MSGID_ELEMS(msg->msg_msgid), success);
		free_result(resultp);
		/*
		 * We don't have a timeout registered to wake us up, so we're
		 * now done with this handle. Release it back to the pool.
		 */
		svc_done(transp);

	}

	free_msg(msg);
	/* the alloc was done in mdmn_send_svc_2 */
	Free(matp);
	mutex_unlock(mx);
	return (NULL);

}

/*
 * do_message_locally(msg, result)
 * Process a message locally on the master
 * Lookup the MCT if the message has already been processed.
 * If not, call the handler and store the result
 * If yes, retrieve the result from the MCT.
 * Return:
 *	MDMNE_ACK in case of success
 *	MDMNE_LOG_FAIL if the MCT could not be checked
 */
static int
do_message_locally(md_mn_msg_t *msg, md_mn_result_t *result)
{
	int			completed;
	set_t			setno;
	md_mn_msgtype_t		msgtype = msg->msg_type;
	md_mn_msgclass_t	class;

	void (*handler)(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *res);

	handler = mdmn_get_handler(msgtype);
	if (handler == NULL) {
		result->mmr_exitval = 0;
		/* let the sender decide if this is an error or not */
		result->mmr_comm_state = MDMNE_NO_HANDLER;
		return (MDMNE_NO_HANDLER);
	}

	class = mdmn_get_message_class(msg->msg_type);
	setno = msg->msg_setno;

	result->mmr_msgtype	= msgtype;
	result->mmr_flags	= msg->msg_flags;
	MSGID_COPY(&(msg->msg_msgid), &(result->mmr_msgid));

	mutex_lock(&mct_mutex[setno][class]);
	completed = mdmn_check_completion(msg, result);
	if (completed == MDMN_MCT_NOT_DONE) {
		/* message not yet processed locally */
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "calling handler for (%d,0x%llx-%d) type %d\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);

		/*
		 * Mark the message as being currently processed,
		 * so we won't start a second handler for it
		 */
		(void) mdmn_mark_completion(msg, NULL, MDMN_MCT_IN_PROGRESS);
		mutex_unlock(&mct_mutex[setno][class]);

		/* here we actually process the message on the master */
		(*handler)(msg, MD_MSGF_ON_MASTER, result);

		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "finished handler for (%d,0x%llx-%d) type %d\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);

		/* Mark the message as fully processed, store the result */
		mutex_lock(&mct_mutex[setno][class]);
		(void) mdmn_mark_completion(msg, result, MDMN_MCT_DONE);
	} else if (completed == MDMN_MCT_DONE) {
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "result for (%d, 0x%llx-%d) from MCT\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);
	} else if (completed == MDMN_MCT_IN_PROGRESS) {
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "(%d, 0x%llx-%d) is currently being processed\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);
	} else {
		/* MCT error occurred (should never happen) */
		mutex_unlock(&mct_mutex[setno][class]);
		result->mmr_comm_state = MDMNE_LOG_FAIL;
		commd_debug(MD_MMV_SYSLOG, "WARNING "
		    "mdmn_check_completion returned %d "
		    "for (%d,0x%llx-%d)\n", completed,
		    MSGID_ELEMS(msg->msg_msgid));
		return (MDMNE_LOG_FAIL);
	}
	mutex_unlock(&mct_mutex[setno][class]);
	return (MDMNE_ACK);

}

/*
 * do_send_message(msg, node)
 *
 * Send a message to a given node and wait for a acknowledgment, that the
 * message has arrived on the remote node.
 * Make sure that the client for the set is setup correctly.
 * If no ACK arrives, destroy and recreate the RPC client and retry the
 * message one time
 * After actually sending wait no longer than the appropriate number of
 * before timing out the message.
 *
 * Note must be called with set_desc_wrlock held in reader mode
 */
static int
do_send_message(md_mn_msg_t *msg, md_mnnode_desc *node)
{
	int			err;
	int			rpc_retries;
	int			timeout_retries = 0;
	int			*ret = NULL;
	set_t			setno;
	cond_t			*cv;	/* see mdmn_wakeup_master_svc_2 */
	mutex_t			*mx;	/* protection for class_busy */
	timestruc_t		timeout; /* surveillance for remote daemon */
	md_mn_nodeid_t		nid;
	md_mn_msgtype_t		msgtype;
	md_mn_msgclass_t	class;

	nid	= node->nd_nodeid;
	msgtype = msg->msg_type;
	setno	= msg->msg_setno;
	class	= mdmn_get_message_class(msgtype);
	mx	= mdmn_get_master_table_mx(setno, class);
	cv	= mdmn_get_master_table_cv(setno, class);

retry_rpc:

	/* We try two times to send the message */
	rpc_retries = 2;

	/*
	 * if sending the message doesn't succeed the first time due to a
	 * RPC problem, we retry one time
	 */
	while ((rpc_retries != 0) && (ret == NULL)) {
		/*  in abort state, we error out immediately */
		if (md_commd_global_state & MD_CGS_ABORTED) {
			return (MDMNE_ABORT);
		}

		rw_rdlock(&client_rwlock[setno]);
		/* unable to create client? Ignore it */
		if (check_client(setno, nid)) {
			/*
			 * In case we cannot establish an RPC client, we
			 * take this node out of our considerations.
			 * This will be reset by a reconfig
			 * cycle that should come pretty soon.
			 * MNISSUE: Should a reconfig cycle
			 * be forced on SunCluster?
			 */
			node->nd_flags &= ~MD_MN_NODE_OWN;
			commd_debug(MD_MMV_SYSLOG,
			    "WARNING couldn't create client for %s\n"
			    "Reconfig cycle required\n",
			    node->nd_nodename);
			commd_debug(MD_MMV_PROC_M, "proc_mas: (%d,0x%llx-%d) "
			    "WARNING couldn't create client for %s\n",
			    MSGID_ELEMS(msg->msg_msgid), node->nd_nodename);
			rw_unlock(&client_rwlock[setno]);
			return (MDMNE_IGNORE_NODE);
		}
		/* let's be paranoid and check again before sending */
		if (client[setno][nid] == NULL) {
			/*
			 * if this is true, strange enough, we catch our breath,
			 * and then continue, so that the client is set up
			 * once again.
			 */
			commd_debug(MD_MMV_PROC_M, "client is NULL\n");
			rw_unlock(&client_rwlock[setno]);
			sleep(1);
			continue;
		}

		/* send it over, it will return immediately */
		ret = mdmn_work_2(msg, client[setno][nid], nid);

		rw_unlock(&client_rwlock[setno]);

		if (ret != NULL) {
			commd_debug(MD_MMV_PROC_M,
			    "proc_mas: sending (%d,0x%llx-%d) to %d returned "
			    " 0x%x\n",
			    MSGID_ELEMS(msg->msg_msgid), nid, *ret);
		} else {
			commd_debug(MD_MMV_PROC_M,
			    "proc_mas: sending (%d,0x%llx-%d) to %d returned "
			    " NULL \n",
			    MSGID_ELEMS(msg->msg_msgid), nid);
		}

		if ((ret == NULL) || (*ret == MDMNE_CANNOT_CONNECT) ||
		    (*ret == MDMNE_THR_CREATE_FAIL)) {
			/*
			 * Something happened to the daemon on the other side.
			 * Kill the client, and try again.
			 * check_client() will create a new client
			 */
			rw_wrlock(&client_rwlock[setno]);
			mdmn_clnt_destroy(client[setno][nid]);
			if (client[setno][nid] != (CLIENT *)NULL) {
				client[setno][nid] = (CLIENT *)NULL;
			}
			rw_unlock(&client_rwlock[setno]);

			/* ... but don't try infinitely */
			--rpc_retries;
			continue;
		}
		/*
		 * If the class is locked on the other node, keep trying.
		 * This situation will go away automatically,
		 * if we wait long enough
		 */
		if (*ret == MDMNE_CLASS_LOCKED) {
			sleep(1);
			free(ret);
			ret = NULL;
			continue;
		}
	}
	if (ret == NULL) {
		return (MDMNE_RPC_FAIL);
	}


	/* if the slave is in abort state, we just ignore it. */
	if (*ret == MDMNE_ABORT) {
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: work(%d,0x%llx-%d) returned "
		    "MDMNE_ABORT\n",
		    MSGID_ELEMS(msg->msg_msgid));
		free(ret);
		return (MDMNE_IGNORE_NODE);
	}

	/* Did the remote processing succeed? */
	if (*ret != MDMNE_ACK) {
		/*
		 * Some commd failure in the middle of sending the msg
		 * to the nodes. We don't continue here.
		 */
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: work(%d,0x%llx-%d) returns %d\n",
		    MSGID_ELEMS(msg->msg_msgid), *ret);
		free(ret);
		return (MDMNE_RPC_FAIL);
	}
	free(ret);
	ret = NULL;

	/*
	 * When we are here, we have sent the message to the other node and
	 * we know that node has accepted it.
	 * We go to sleep and have trust to be woken up by wakeup.
	 * If we wakeup due to a timeout, or a signal, no result has been
	 * placed in the appropriate slot.
	 * If we timeout, it is likely that this is because the node has
	 * gone away, so we will destroy the client and try it again in the
	 * expectation that the rpc will fail and we will return
	 * MDMNE_IGNORE_NODE. If that is not the case, the message must still
	 * be being processed on the slave. In this case just timeout for 4
	 * more seconds and then return RPC_FAIL if the message is not complete.
	 */
	timeout.tv_nsec = 0;
	timeout.tv_sec = (timeout_retries == 0) ? mdmn_get_timeout(msgtype) :
	    FOUR_SECS.tv_sec;
	err = cond_reltimedwait(cv, mx, &timeout);

	if (err == 0) {
		/* everything's fine, return success */
		return (MDMNE_ACK);
	}

	if (err == ETIME) {
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "timeout occured, set=%d, class=%d, "
		    "msgid=(%d, 0x%llx-%d), timeout_retries=%d\n",
		    setno, class, MSGID_ELEMS(msg->msg_msgid), timeout_retries);
		if (timeout_retries == 0) {
			timeout_retries++;
			/*
			 * Destroy the client and try the rpc call again
			 */
			rw_wrlock(&client_rwlock[setno]);
			mdmn_clnt_destroy(client[setno][nid]);
			client[setno][nid] = (CLIENT *)NULL;
			rw_unlock(&client_rwlock[setno]);
			goto retry_rpc;
		}
	} else if (err == EINTR) {
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "commd signalled, set=%d, class=%d, "
		    "msgid=(%d, 0x%llx-%d)\n",
		    setno, class, MSGID_ELEMS(msg->msg_msgid));
	} else {
		commd_debug(MD_MMV_PROC_M, "proc_mas: "
		    "cond_reltimedwait err=%d, set=%d, "
		    "class=%d, msgid=(%d, 0x%llx-%d)\n",
		    err, setno, class,
		    MSGID_ELEMS(msg->msg_msgid));
	}

	/* some failure happened */
	return (MDMNE_RPC_FAIL);
}

/*
 * before we return we have to
 * free_msg(msg); because we are working on a copied message
 */
void
mdmn_master_process_msg(md_mn_msg_t *msg)
{
	int		*ret;
	int		err;
	int		nmsgs;		/* total number of msgs */
	int		curmsg;		/* index of current msg */
	set_t		setno;
	uint_t		inherit_flags = 0;
	uint_t		secdiff, usecdiff; /* runtime of this message */
	md_error_t	mde = mdnullerror;
	md_mn_msg_t	*msglist[MAX_SUBMESSAGES]; /* all msgs to process */
	md_mn_msg_t	*cmsg;		/* current msg */
	md_mn_msgid_t	dummyid;
	md_mn_result_t	*result;
	md_mn_result_t	*slave_result;
	md_mn_nodeid_t	sender;
	md_mn_nodeid_t	set_master;
	md_mnnode_desc	*node;
	md_mn_msgtype_t	orig_type;	/* type of the original message */
	md_mn_msgtype_t	msgtype;	/* type of the current message */
	md_mn_msgclass_t orig_class;	/* class of the original message */
	md_mn_msgclass_t class;		/* class of the current message */

	int (*smgen)(md_mn_msg_t *msg, md_mn_msg_t **msglist);

	orig_type = msgtype = msg->msg_type;
	sender	= msg->msg_sender;
	setno	= msg->msg_setno;

	result = Zalloc(sizeof (md_mn_result_t));
	result->mmr_setno	= setno;
	result->mmr_msgtype	= msgtype;
	MSGID_COPY(&(msg->msg_msgid), &(result->mmr_msgid));

	orig_class = mdmn_get_message_class(msgtype);

	commd_debug(MD_MMV_PROC_M,
	    "proc_mas: received (%d, 0x%llx-%d) set=%d, class=%d, type=%d\n",
	    MSGID_ELEMS(msg->msg_msgid), setno, orig_class, msgtype);

	rw_rdlock(&set_desc_rwlock[setno]);
	set_master = set_descriptor[setno]->sd_mn_master_nodeid;
	result->mmr_sender	= set_master;
	/*
	 * Put message into the change log unless told otherwise
	 * Note that we only log original messages.
	 * If they are generated by some smgen, we don't log them!
	 * Replay messages aren't logged either.
	 * Note, that replay messages are unlogged on completion.
	 */
	if ((msg->msg_flags & (MD_MSGF_NO_LOG | MD_MSGF_REPLAY_MSG)) == 0) {
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: calling log_msg for (%d,0x%llx-%d) type %d\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);
		err = mdmn_log_msg(msg);
		if (err == MDMNE_NULL) {
			/* msg logged successfully */
			commd_debug(MD_MMV_PROC_M, "proc_mas: "
			    "done log_msg for (%d,0x%llx-%d) type %d\n",
			    MSGID_ELEMS(msg->msg_msgid), msgtype);
			goto proceed;
		}
		if (err == MDMNE_ACK) {
			/* Same msg in the slot, proceed */
			commd_debug(MD_MMV_PROC_M, "proc_mas: "
			    "already logged (%d,0x%llx-%d) type %d\n",
			    MSGID_ELEMS(msg->msg_msgid), msgtype);
			goto proceed;
		}
		if (err == MDMNE_LOG_FAIL) {
			/* Oh, bad, the log is non functional. */
			result->mmr_comm_state = MDMNE_LOG_FAIL;
			/*
			 * Note that the mark_busy was already done by
			 * mdmn_work_svc_2()
			 */
			mutex_lock(&mdmn_busy_mutex[setno]);
			mdmn_mark_class_unbusy(setno, orig_class);
			mutex_unlock(&mdmn_busy_mutex[setno]);

		}
		if (err == MDMNE_CLASS_BUSY) {
			/*
			 * The log is occupied with a different message
			 * that needs to be played first.
			 * We reject the current message with MDMNE_CLASS_BUSY
			 * to the initiator and do not unbusy the set/class,
			 * because we will proceed with the logged message,
			 * which has the same set/class combination
			 */
			result->mmr_comm_state = MDMNE_CLASS_BUSY;
		}
		ret = (int *)NULL;
		rw_rdlock(&client_rwlock[setno]);

		if (check_client(setno, sender)) {
			commd_debug(MD_MMV_SYSLOG,
			    "proc_mas: No client for initiator \n");
		} else {
			ret = mdmn_wakeup_initiator_2(result,
			    client[setno][sender], sender);
		}
		rw_unlock(&client_rwlock[setno]);

		if (ret == (int *)NULL) {
			commd_debug(MD_MMV_SYSLOG,
			    "proc_mas: couldn't wakeup_initiator \n");
		} else {
			if (*ret != MDMNE_ACK) {
				commd_debug(MD_MMV_SYSLOG, "proc_mas: "
				    "wakeup_initiator returned %d\n", *ret);
			}
			free(ret);
		}
		free_msg(msg);

		if (err == MDMNE_LOG_FAIL) {
			/* we can't proceed here */
			free_result(result);
			rw_unlock(&set_desc_rwlock[setno]);
			return;
		} else if (err == MDMNE_CLASS_BUSY) {
			mdmn_changelog_record_t *lr;
			lr = mdmn_get_changelogrec(setno, orig_class);
			assert(lr != NULL);

			/* proceed with the logged message */
			msg = copy_msg(&(lr->lr_msg), NULL);

			/*
			 * The logged message has to have the same class but
			 * type and sender can be different
			 */
			orig_type = msgtype = msg->msg_type;
			sender	= msg->msg_sender;

			commd_debug(MD_MMV_PROC_M,
			    "proc_mas: Got new message from change log: "
			    "(%d,0x%llx-%d) type %d\n",
			    MSGID_ELEMS(msg->msg_msgid), msgtype);

			/* continue normal operation with this message */
		}
	}

proceed:
	smgen = mdmn_get_submessage_generator(msgtype);
	if (smgen == NULL) {
		/* no submessages to create, just use the original message */
		msglist[0] = msg;
		nmsgs = 1;
	} else {
		/* some bits are passed on to submessages */
		inherit_flags = msg->msg_flags & MD_MSGF_INHERIT_BITS;

		nmsgs = smgen(msg, msglist);

		/* some settings for the submessages */
		for (curmsg = 0; curmsg < nmsgs; curmsg++) {
			cmsg    = msglist[curmsg];

			/* Apply the inherited flags */
			cmsg->msg_flags |= inherit_flags;

			/*
			 * Make sure the submessage ID is set correctly
			 * Note: first submessage has mid_smid of 1 (not 0)
			 */
			cmsg->msg_msgid.mid_smid = curmsg + 1;

			/* need the original class set in msgID (for MCT) */
			cmsg->msg_msgid.mid_oclass = orig_class;
		}

		commd_debug(MD_MMV_PROC_M,
		    "smgen generated %d submsgs, origclass = %d\n",
		    nmsgs, orig_class);
	}
	/*
	 * This big loop does the following.
	 * For all messages:
	 *	process message on the master first (a message completion
	 *		table MCT ensures a message is not processed twice)
	 *	in case of an error break out of message loop
	 *	for all nodes -- unless MD_MSGF_NO_BCAST is set --
	 *		send message to node until that succeeds
	 *		merge result -- not yet implemented
	 *		respect MD_MSGF_STOP_ON_ERROR
	 */
	for (curmsg = 0; curmsg < nmsgs; curmsg++) {
		int	break_msg_loop = 0;
		mutex_t	*mx;		/* protection for class_busy */
		int	master_err;
		int	master_exitval = -1;

		cmsg	= msglist[curmsg];
		msgtype = cmsg->msg_type;
		class	= mdmn_get_message_class(msgtype);
		node	= NULL;
		mx	= mdmn_get_master_table_mx(setno, class);

		/* If we are in the abort state, we error out immediately */
		if (md_commd_global_state & MD_CGS_ABORTED) {
			break; /* out of the message loop */
		}

		commd_debug(MD_MMV_PROC_M, "class=%d, orig_class=%d\n",
		    class, orig_class);
		/*
		 * If the current class is different from the original class,
		 * we have to lock it down.
		 * The original class is already marked busy.
		 * At this point we cannot refuse the message because the
		 * class is busy right now, so we wait until the class becomes
		 * available again. As soon as something changes for this set
		 * we will be cond_signal'ed (in mdmn_mark_class_unbusy)
		 *
		 * Granularity could be finer (setno/class)
		 */
		if (class != orig_class) {
			mutex_lock(&mdmn_busy_mutex[setno]);
			while (mdmn_mark_class_busy(setno, class) == FALSE) {
				cond_wait(&mdmn_busy_cv[setno],
				    &mdmn_busy_mutex[setno]);
			}
			mutex_unlock(&mdmn_busy_mutex[setno]);
		}

		master_err = do_message_locally(cmsg, result);

		if ((master_err != MDMNE_ACK) ||
		    ((master_err == MDMNE_ACK) && (result->mmr_exitval != 0))) {
			result->mmr_failing_node = set_master;
			if (cmsg->msg_flags & MD_MSGF_STOP_ON_ERROR) {
				/*
				 * if appropriate, unbusy the class and
				 * break out of the message loop
				 */
				if (class != orig_class) {
					mutex_lock(&mdmn_busy_mutex[setno]);
					mdmn_mark_class_unbusy(setno, class);
					mutex_unlock(&mdmn_busy_mutex[setno]);
				}
				break;
			}
		}

		if (master_err == MDMNE_ACK)
			master_exitval = result->mmr_exitval;

		/* No broadcast? => next message */
		if (cmsg->msg_flags & MD_MSGF_NO_BCAST) {
			/* if appropriate, unbusy the class */
			if (class != orig_class) {
				mutex_lock(&mdmn_busy_mutex[setno]);
				mdmn_mark_class_unbusy(setno, class);
				mutex_unlock(&mdmn_busy_mutex[setno]);
			}
			continue;
		}


		/* fake sender, so we get notified when the results are avail */
		cmsg->msg_sender = set_master;
		/*
		 * register to the master_table. It's needed by wakeup_master to
		 * wakeup the sleeping thread.
		 * Access is protected by the class lock: mdmn_mark_class_busy()
		 */
		mdmn_set_master_table_id(setno, class, &(cmsg->msg_msgid));



		rw_rdlock(&set_desc_rwlock[setno]);
		/* Send the message  to all other nodes */
		for (node = set_descriptor[setno]->sd_nodelist; node;
		    node = node->nd_next) {
			md_mn_nodeid_t nid = node->nd_nodeid;

			/* We are master and have already processed the msg */
			if (node == set_descriptor[setno]->sd_mn_masternode) {
				continue;
			}

			/* If this node didn't join the disk set, ignore it */
			if ((node->nd_flags & MD_MN_NODE_OWN) == 0) {
				continue;
			}

			/* If a DIRECTED message, skip non-recipient nodes */
			if ((cmsg->msg_flags & MD_MSGF_DIRECTED) &&
			    nid != cmsg->msg_recipient) {
				continue;
			}

			mutex_lock(mx);
			/*
			 * Register the node that is addressed,
			 * so we can detect unsolicited messages
			 */
			mdmn_set_master_table_addr(setno, class, nid);
			slave_result = (md_mn_result_t *)NULL;

			/*
			 * Now send it. do_send_message() will return if
			 *	a failure occurs or
			 *	the results are available
			 */
			err = do_send_message(cmsg, node);

			/*  in abort state, we error out immediately */
			if (md_commd_global_state & MD_CGS_ABORTED) {
				break;
			}

			if (err == MDMNE_ACK) {
				slave_result =
				    mdmn_get_master_table_res(setno, class);
				commd_debug(MD_MMV_PROC_M,
				    "proc_mas: got result for (%d,0x%llx-%d)\n",
				    MSGID_ELEMS(cmsg->msg_msgid));
			} else if (err == MDMNE_IGNORE_NODE) {
				mutex_unlock(mx);
				continue; /* send to next node */
			}
			mutex_unlock(mx);


			/*
			 * If the result is NULL, or err doesn't show success,
			 * something went wrong with this RPC call.
			 */
			if ((slave_result == NULL) || (err != MDMNE_ACK)) {
				/*
				 * If PANIC_WHEN_INCONSISTENT set,
				 * panic if the master succeeded while
				 * this node failed
				 */
				if ((cmsg->msg_flags &
				    MD_MSGF_PANIC_WHEN_INCONSISTENT) &&
				    (master_err == MDMNE_ACK))
					panic_system(nid, cmsg->msg_type,
					    master_err, master_exitval,
					    slave_result);

				result->mmr_failing_node = nid;
				/* are we supposed to stop in case of error? */
				if (cmsg->msg_flags & MD_MSGF_STOP_ON_ERROR) {
					result->mmr_exitval = MDMNE_RPC_FAIL;
					commd_debug(MD_MMV_SYSLOG, "proc_mas: "
					    "result (%d,0x%llx-%d) is NULL\n",
					    MSGID_ELEMS(cmsg->msg_msgid));
					FLUSH_DEBUGFILE();
					break_msg_loop = 1;
					break; /* out of node loop first */
				} else {
					/* send msg to the next node */
					continue;
				}

			}

			/*
			 * Message processed on remote node.
			 * If PANIC_WHEN_INCONSISTENT set, panic if the
			 * result is different on this node from the result
			 * on the master
			 */
			if ((cmsg->msg_flags &
			    MD_MSGF_PANIC_WHEN_INCONSISTENT) &&
			    ((master_err != MDMNE_ACK) ||
			    (slave_result->mmr_exitval != master_exitval)))
				panic_system(nid, cmsg->msg_type, master_err,
				    master_exitval, slave_result);

			/*
			 * At this point we know we have a message that was
			 * processed on the remote node.
			 * We now check if the exitval is non zero.
			 * In that case we discard the previous result and
			 * rather use the current.
			 * This means: If a message fails on no node,
			 * the result from the master will be returned.
			 * There's currently no such thing as merge of results
			 * If additionally STOP_ON_ERROR is set, we bail out
			 */
			if (slave_result->mmr_exitval != 0) {
				/* throw away the previously allocated result */
				free_result(result);

				/* copy_result() allocates new memory */
				result = copy_result(slave_result);
				free_result(slave_result);

				dump_result(MD_MMV_PROC_M, "proc_mas", result);

				result->mmr_failing_node = nid;
				if (cmsg->msg_flags & MD_MSGF_STOP_ON_ERROR) {
					break_msg_loop = 1;
					break; /* out of node loop */
				}
				continue; /* try next node */

			} else {
				/*
				 * MNIssue: may want to merge the results
				 * from all slaves.  Currently only report
				 * the results from the master.
				 */
				free_result(slave_result);
			}

		} /* End of loop over the nodes */
		rw_unlock(&set_desc_rwlock[setno]);


		/* release the current class again */
		if (class != orig_class) {
			mutex_lock(&mdmn_busy_mutex[setno]);
			mdmn_mark_class_unbusy(setno, class);
			mutex_unlock(&mdmn_busy_mutex[setno]);
		}

		/* are we supposed to quit entirely ? */
		if (break_msg_loop ||
		    (md_commd_global_state & MD_CGS_ABORTED)) {
			break; /* out of msg loop */
		}

	} /* End of loop over the messages */
	/*
	 * If we are here, there's two possibilities:
	 * 	- we processed all messages on all nodes without an error.
	 *	    In this case we return the result from the master.
	 *	    (to be implemented: return the merged result)
	 *	- we encountered an error in which case result has been
	 *	    set accordingly already.
	 */

	if (md_commd_global_state & MD_CGS_ABORTED) {
		result->mmr_comm_state = MDMNE_ABORT;
	}

	/*
	 * This message has been processed completely.
	 * Remove it from the changelog.
	 * Do this for replay messages too.
	 * Note that the message is unlogged before waking up the
	 * initiator.  This is done for two reasons.
	 * 1. Remove a race condition that occurs when back to back
	 *   messages are sent for the same class, the registeration is
	 *   is lost.
	 * 2. If the initiator died but the action was completed on all the
	 *   the nodes, we want that to be marked "done" quickly.
	 */

	if ((msg->msg_flags & MD_MSGF_NO_LOG) == 0) {
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: calling unlog_msg for (%d,0x%llx-%d) type %d\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);
		mdmn_unlog_msg(msg);
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: done unlog_msg for (%d,0x%llx-%d) type %d\n",
		    MSGID_ELEMS(msg->msg_msgid), msgtype);
	}

	/*
	 * In case of submessages, we increased the submessage ID in the
	 * result structure. We restore the message ID to the value that
	 * the initiator is waiting for.
	 */
	result->mmr_msgid.mid_smid	= 0;
	result->mmr_msgtype		= orig_type;
	result->mmr_sender		= set_master;

	/* if we have an inited client, send result */
	ret = (int *)NULL;

	rw_rdlock(&client_rwlock[setno]);
	if (check_client(setno, sender)) {
		commd_debug(MD_MMV_SYSLOG,
		    "proc_mas: unable to create client for initiator\n");
	} else {
		ret = mdmn_wakeup_initiator_2(result, client[setno][sender],
		    sender);
	}
	rw_unlock(&client_rwlock[setno]);

	if (ret == (int *)NULL) {
		commd_debug(MD_MMV_PROC_M,
		    "proc_mas: couldn't wakeup initiator\n");
	} else {
		if (*ret != MDMNE_ACK) {
			commd_debug(MD_MMV_PROC_M,
			    "proc_mas: wakeup_initiator returned %d\n",
			    *ret);
		}
		free(ret);
	}

	rw_unlock(&set_desc_rwlock[setno]);
	/* Free all submessages, if there were any */
	if (nmsgs > 1) {
		for (curmsg = 0; curmsg < nmsgs; curmsg++) {
			free_msg(msglist[curmsg]);
		}
	}
	/* Free the result */
	free_result(result);

	mutex_lock(&mdmn_busy_mutex[setno]);
	mdmn_mark_class_unbusy(setno, orig_class);
	mutex_unlock(&mdmn_busy_mutex[setno]);


	/*
	 * We use this ioctl just to get the time in the same format as used in
	 * the messageID. If it fails, all we get is a bad runtime output.
	 */
	(void) metaioctl(MD_IOCGUNIQMSGID, &dummyid, &mde, NULL);
	secdiff = (dummyid.mid_time - msg->msg_msgid.mid_time) >> 32;
	usecdiff = (dummyid.mid_time - msg->msg_msgid.mid_time) & 0xfffff;

	/* catching possible overflow */
	if (usecdiff >= 1000000) {
		usecdiff -= 1000000;
		secdiff++;
	}


	commd_debug(MD_MMV_PROC_M, "proc_mas: done (%d, 0x%llx-%d) type=%02d "
	    "%5d.%06d secs runtime\n",
	    MSGID_ELEMS(msg->msg_msgid), orig_type, secdiff, usecdiff);

	/* Free the original message */
	free_msg(msg);
}

void
mdmn_slave_process_msg(md_mn_msg_t *msg)
{
	int			*ret = NULL;
	int			completed;
	int			retries;
	int			successfully_returned;
	set_t			setno;
	md_mn_result_t		*result;
	md_mn_nodeid_t		sender;
	md_mn_nodeid_t		whoami;
	md_mn_msgtype_t		msgtype;
	md_mn_msgclass_t	class;

	void (*handler)(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *res);

	setno	= msg->msg_setno;
	sender	= msg->msg_sender; /* this is always the master of the set */
	msgtype	= msg->msg_type;

	rw_rdlock(&set_desc_rwlock[setno]);
	whoami		= set_descriptor[setno]->sd_mn_mynode->nd_nodeid;
	rw_unlock(&set_desc_rwlock[setno]);

	result = Zalloc(sizeof (md_mn_result_t));
	result->mmr_flags	= msg->msg_flags;
	result->mmr_setno	= setno;
	result->mmr_msgtype	= msgtype;
	result->mmr_sender	= whoami;
	result->mmr_comm_state	= MDMNE_ACK; /* Ok state */
	MSGID_COPY(&(msg->msg_msgid), &(result->mmr_msgid));
	class = mdmn_get_message_class(msgtype);

	commd_debug(MD_MMV_PROC_S,
	    "proc_sla: received (%d, 0x%llx-%d) set=%d, class=%d, type=%d\n",
	    MSGID_ELEMS(msg->msg_msgid), setno, class, msgtype);

	handler = mdmn_get_handler(msgtype);

	if (handler == NULL) {
		result->mmr_exitval = 0;
		/* let the sender decide if this is an error or not */
		result->mmr_comm_state = MDMNE_NO_HANDLER;
		commd_debug(MD_MMV_PROC_S,
		    "proc_sla: No handler for (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(msg->msg_msgid));
	} else {

		/* Did we already process this message ? */
		mutex_lock(&mct_mutex[setno][class]);
		completed = mdmn_check_completion(msg, result);

		if (completed == MDMN_MCT_NOT_DONE) {
			/* message not yet processed locally */
			commd_debug(MD_MMV_PROC_S,
			    "proc_sla: calling handler for (%d, 0x%llx-%d)\n",
			    MSGID_ELEMS(msg->msg_msgid));

			/*
			 * Mark the message as being currently processed,
			 * so we won't start a second handler for it
			 */
			(void) mdmn_mark_completion(msg, NULL,
			    MDMN_MCT_IN_PROGRESS);

			mutex_unlock(&mct_mutex[setno][class]);
			(*handler)(msg, MD_MSGF_ON_SLAVE, result);

			commd_debug(MD_MMV_PROC_S,
			    "proc_sla: finished handler for (%d, 0x%llx-%d)\n",
			    MSGID_ELEMS(msg->msg_msgid));

			mutex_lock(&mct_mutex[setno][class]);
			/* Mark the message as fully done, store the result */
			(void) mdmn_mark_completion(msg, result, MDMN_MCT_DONE);

		} else if (completed == MDMN_MCT_DONE) {
			/* message processed previously, got result from MCT */
			commd_debug(MD_MMV_PROC_S,
			    "proc_sla: result for (%d, 0x%llx-%d) from MCT\n",
			    MSGID_ELEMS(msg->msg_msgid));
		} else if (completed == MDMN_MCT_IN_PROGRESS) {
			/*
			 * If the message is curruntly being processed,
			 * we can return here, without sending a result back.
			 * This will be done by the initial message handling
			 * thread
			 */
			mutex_unlock(&mct_mutex[setno][class]);
			commd_debug(MD_MMV_PROC_M, "proc_sla: "
			    "(%d, 0x%llx-%d) is currently being processed\n",
			    MSGID_ELEMS(msg->msg_msgid), msgtype);

			free_msg(msg);
			free_result(result);
			return;
		} else {
			/* MCT error occurred (should never happen) */
			result->mmr_comm_state = MDMNE_LOG_FAIL;
			commd_debug(MD_MMV_PROC_S,
			    "proc_sla: MCT error for (%d, 0x%llx-%d)\n",
			    MSGID_ELEMS(msg->msg_msgid));
		}
		mutex_unlock(&mct_mutex[setno][class]);
	}

	/*
	 * At this point we have a result (even in an error case)
	 * that we return to the master.
	 */
	rw_rdlock(&set_desc_rwlock[setno]);
	retries = 2; /* we will try two times to send the results */
	successfully_returned = 0;

	while (!successfully_returned && (retries != 0)) {
		ret = (int *)NULL;
		rw_rdlock(&client_rwlock[setno]);
		if (check_client(setno, sender)) {
			/*
			 * If we cannot setup the rpc connection to the master,
			 * we can't do anything besides logging this fact.
			 */
			commd_debug(MD_MMV_SYSLOG,
			    "proc_mas: unable to create client for master\n");
			rw_unlock(&client_rwlock[setno]);
			break;
		} else {
			ret = mdmn_wakeup_master_2(result,
			    client[setno][sender], sender);
			/*
			 * if mdmn_wakeup_master_2 returns NULL, it can be that
			 * the master (or the commd on the master) had died.
			 * In that case, we destroy the client to the master
			 * and retry.
			 * If mdmn_wakeup_master_2 doesn't return MDMNE_ACK,
			 * the commd on the master is alive but
			 * something else is wrong,
			 * in that case a retry doesn't make sense => break out
			 */
			if (ret == (int *)NULL) {
				commd_debug(MD_MMV_PROC_S,
				    "proc_sla: wakeup_master returned NULL\n");
				/* release reader lock, grab writer lock */
				rw_unlock(&client_rwlock[setno]);
				rw_wrlock(&client_rwlock[setno]);
				mdmn_clnt_destroy(client[setno][sender]);
				if (client[setno][sender] != (CLIENT *)NULL) {
					client[setno][sender] = (CLIENT *)NULL;
				}
				rw_unlock(&client_rwlock[setno]);
				retries--;
				commd_debug(MD_MMV_PROC_S,
				    "retries = %d\n", retries);
				continue;
			}
			if (*ret != MDMNE_ACK) {
				commd_debug(MD_MMV_PROC_S, "proc_sla: "
				    "wakeup_master returned %d\n", *ret);
				rw_unlock(&client_rwlock[setno]);
				break;
			} else { /* Good case */
				successfully_returned = 1;
				rw_unlock(&client_rwlock[setno]);
			}
		}
	}

	rw_unlock(&set_desc_rwlock[setno]);
	commd_debug(MD_MMV_PROC_S, "proc_sla: done (%d, 0x%llx-%d)\n",
	    MSGID_ELEMS(msg->msg_msgid));

	if (ret != (int *)NULL)
		free(ret);
	free_msg(msg);
	free_result(result);
}


/*
 * mdmn_send_svc_2:
 * ---------------
 * Check that the issuing node is a legitimate one (i.e. is licensed to send
 * messages to us), that the RPC request can be staged.
 *
 * Returns:
 *	0	=> no RPC request is in-flight, no deferred svc_sendreply()
 *	1	=> queued RPC request in-flight. Completion will be made (later)
 *		   by a wakeup_initiator_2() [hopefully]
 */
int
mdmn_send_svc_2(md_mn_msg_t *omsg, struct svc_req *rqstp)
{
	int			err;
	set_t			setno;
	SVCXPRT			*transp = rqstp->rq_xprt;
	md_mn_msg_t		*msg;
	md_mn_result_t		*resultp;
	md_mn_msgclass_t	class;
	md_mn_msg_and_transp_t	*matp;

	msg = copy_msg(omsg, NULL);
	xdr_free(xdr_md_mn_msg_t, (caddr_t)omsg);

	setno = msg->msg_setno;
	class = mdmn_get_message_class(msg->msg_type);

	/* If we are in the abort state, we error out immediately */
	if (md_commd_global_state & MD_CGS_ABORTED) {
		resultp = Zalloc(sizeof (md_mn_result_t));
		resultp->mmr_comm_state = MDMNE_ABORT;
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);
		free_result(resultp);
		svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
		return (0);
	}

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	commd_debug(MD_MMV_SEND,
	    "send: received (%d, 0x%llx-%d), set=%d, class=%d, type=%d\n",
	    MSGID_ELEMS(msg->msg_msgid), setno, class, msg->msg_type);

	/* Check for verbosity related message */
	if (msg->msg_type == MD_MN_MSG_VERBOSITY) {
		md_mn_verbose_t *d;

		d = (md_mn_verbose_t *)((void *)(msg->msg_event_data));
		md_commd_global_verb = d->mmv_what;
		/* everytime the bitmask is set, we reset the timer */
		__savetime = gethrtime();
		/*
		 * If local-only-flag is set, we are done here,
		 * otherwise we pass that message on to the master.
		 */
		if (msg->msg_flags & MD_MSGF_LOCAL_ONLY) {
			resultp = Zalloc(sizeof (md_mn_result_t));
			resultp->mmr_comm_state = MDMNE_ACK;
			mdmn_svc_sendreply(transp, xdr_md_mn_result_t,
			    (char *)resultp);
			free_result(resultp);
			svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
			return (0);
		}
	}

	/*
	 * Are we entering the abort state?
	 * Here we don't even need to check for MD_MSGF_LOCAL_ONLY, because
	 * this message cannot be distributed anyway.
	 * So, it's safe to return immediately.
	 */
	if (msg->msg_type == MD_MN_MSG_ABORT) {
		md_commd_global_state |= MD_CGS_ABORTED;
		resultp = Zalloc(sizeof (md_mn_result_t));
		resultp->mmr_comm_state = MDMNE_ACK;
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);
		free_result(resultp);
		svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
		return (0);
	}


	/*
	 * Is this message type blocked?
	 * If so we return MDMNE_CLASS_LOCKED, immediately
	 */
	if (msgtype_lock_state[msg->msg_type] == MMTL_LOCK) {
		resultp = Zalloc(sizeof (md_mn_result_t));
		resultp->mmr_comm_state = MDMNE_CLASS_LOCKED;
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);
		free_result(resultp);
		svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
		commd_debug(MD_MMV_SEND,
		    "send: type locked (%d, 0x%llx-%d), set=%d, class=%d, "
		    "type=%d\n", MSGID_ELEMS(msg->msg_msgid), setno, class,
		    msg->msg_type);
		return (0);
	}


	if (md_mn_set_inited[setno] != MDMN_SET_READY) {
		/* Can only use the appropriate mutexes if they are inited */
		if (md_mn_set_inited[setno] & MDMN_SET_MUTEXES) {
			rw_wrlock(&set_desc_rwlock[setno]);
			rw_wrlock(&client_rwlock[setno]);
			err = mdmn_init_set(setno, MDMN_SET_READY);
			rw_unlock(&client_rwlock[setno]);
			rw_unlock(&set_desc_rwlock[setno]);
		} else {
			err = mdmn_init_set(setno, MDMN_SET_READY);
		}

		if (err) {
			/* couldn't initialize connections, cannot proceed */
			resultp = Zalloc(sizeof (md_mn_result_t));
			resultp->mmr_comm_state = err;
			mdmn_svc_sendreply(transp, xdr_md_mn_result_t,
			    (char *)resultp);
			svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
			free_result(resultp);
			commd_debug(MD_MMV_SEND,
			    "send: init err = %d\n", err);
			return (0);
		}
	}

	mutex_lock(&mdmn_busy_mutex[setno]);
	if ((mdmn_is_class_suspended(setno, class) == TRUE) &&
	    ((msg->msg_flags & MD_MSGF_OVERRIDE_SUSPEND) == 0)) {
		mutex_unlock(&mdmn_busy_mutex[setno]);
		resultp = Zalloc(sizeof (md_mn_result_t));
		resultp->mmr_comm_state = MDMNE_SUSPENDED;
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)resultp);
		svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
		free_result(resultp);
		commd_debug(MD_MMV_SEND,
		    "send: class suspended (%d, 0x%llx-%d), set=%d, "
		    "class=%d, type=%d\n", MSGID_ELEMS(msg->msg_msgid),
		    setno, class, msg->msg_type);
		return (0);
	}
	mutex_unlock(&mdmn_busy_mutex[setno]);

	/* is this rpc request coming from the local node? */
	if (check_license(rqstp, 0) == FALSE) {
		svc_freeargs(transp, xdr_md_mn_msg_t, (caddr_t)msg);
		commd_debug(MD_MMV_SEND,
		    "send: check licence fail(%d, 0x%llx-%d), set=%d, "
		    "class=%d, type=%d\n", MSGID_ELEMS(msg->msg_msgid),
		    setno, class, msg->msg_type);
		return (0);
	}


	/*
	 * We allocate a structure that can take two pointers in order to pass
	 * both the message and the transp into thread_create.
	 * The free for this alloc is done in mdmn_send_to_work()
	 */
	matp = Malloc(sizeof (md_mn_msg_and_transp_t));
	matp->mat_msg = msg;
	matp->mat_transp = transp;

	/*
	 * create a thread here that calls work on the master.
	 * If we are already on the master, this would block if running
	 * in the same context. (our service is single threaded)(
	 * Make it a detached thread because it will not communicate with
	 * anybody thru thr_* mechanisms
	 */
	thr_create(NULL, 0, mdmn_send_to_work, (void *) matp, THR_DETACHED,
	    NULL);

	commd_debug(MD_MMV_SEND, "send: done (%d, 0x%llx-%d)\n",
	    MSGID_ELEMS(msg->msg_msgid));
	/*
	 * We return here without sending results. This will be done by
	 * mdmn_wakeup_initiator_svc_2() as soon as the results are available.
	 * Until then the calling send_message will be blocked, while we
	 * are able to take calls.
	 */

	return (1);
}

/* ARGSUSED */
int *
mdmn_work_svc_2(md_mn_msg_t *omsg, struct svc_req *rqstp)
{
	int		err;
	set_t		setno;
	thread_t	tid;
	int		*retval;
	md_mn_msg_t	*msg;
	md_mn_msgclass_t class;

	retval = Malloc(sizeof (int));

	/* If we are in the abort state, we error out immediately */
	if (md_commd_global_state & MD_CGS_ABORTED) {
	xdr_free(xdr_md_mn_msg_t, (caddr_t)omsg);
		*retval = MDMNE_ABORT;
		return (retval);
	}

	msg = copy_msg(omsg, NULL);
	xdr_free(xdr_md_mn_msg_t, (caddr_t)omsg);

	/*
	 * Is this message type blocked?
	 * If so we return MDMNE_CLASS_LOCKED, immediately.
	 * This check is performed on master and slave.
	 */
	if (msgtype_lock_state[msg->msg_type] == MMTL_LOCK) {
		*retval = MDMNE_CLASS_LOCKED;
		return (retval);
	}

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	class = mdmn_get_message_class(msg->msg_type);
	setno = msg->msg_setno;

	if (md_mn_set_inited[setno] != MDMN_SET_READY) {
		/* Can only use the appropriate mutexes if they are inited */
		if (md_mn_set_inited[setno] & MDMN_SET_MUTEXES) {
			rw_wrlock(&set_desc_rwlock[setno]);
			rw_wrlock(&client_rwlock[setno]);
			err = mdmn_init_set(setno, MDMN_SET_READY);
			rw_unlock(&client_rwlock[setno]);
			rw_unlock(&set_desc_rwlock[setno]);
		} else {
			err = mdmn_init_set(setno, MDMN_SET_READY);
		}

		if (err) {
			*retval = MDMNE_CANNOT_CONNECT;
			free_msg(msg);
			return (retval);
		}
	}

	/* is this rpc request coming from a licensed node? */
	if (check_license(rqstp, msg->msg_sender) == FALSE) {
		free_msg(msg);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	commd_debug(MD_MMV_WORK,
	    "work: received (%d, 0x%llx-%d), set=%d, class=%d, type=%d, "
	    "flags=0x%x\n",
	    MSGID_ELEMS(msg->msg_msgid), setno, class, msg->msg_type,
	    msg->msg_flags);

	/* Check for various CLASS0 message types */
	if (msg->msg_type == MD_MN_MSG_VERBOSITY) {
		md_mn_verbose_t *d;

		d = (md_mn_verbose_t *)((void *)(msg->msg_event_data));
		/* for now we ignore set / class in md_mn_verbose_t */
		md_commd_global_verb = d->mmv_what;
		/* everytime the bitmask is set, we reset the timer */
		__savetime = gethrtime();
	}

	mutex_lock(&mdmn_busy_mutex[setno]);

	/* check if class is locked via a call to mdmn_comm_lock_svc_2 */
	if (mdmn_is_class_locked(setno, class) == TRUE) {
		mutex_unlock(&mdmn_busy_mutex[setno]);
		*retval = MDMNE_CLASS_LOCKED;
		free_msg(msg);
		return (retval);
	}
	mutex_unlock(&mdmn_busy_mutex[setno]);

	/* Check if the class is busy right now. Do it only on the master */
	rw_rdlock(&set_desc_rwlock[setno]);
	if (set_descriptor[setno]->sd_mn_am_i_master) {
		rw_unlock(&set_desc_rwlock[setno]);
		/*
		 * If the class is currently suspended, don't accept new
		 * messages, unless they are flagged with an override bit.
		 */
		mutex_lock(&mdmn_busy_mutex[setno]);
		if ((mdmn_is_class_suspended(setno, class) == TRUE) &&
		    ((msg->msg_flags & MD_MSGF_OVERRIDE_SUSPEND) == 0)) {
			mutex_unlock(&mdmn_busy_mutex[setno]);
			*retval = MDMNE_SUSPENDED;
			commd_debug(MD_MMV_SEND,
			    "send: set %d is suspended\n", setno);
			free_msg(msg);
			return (retval);
		}
		if (mdmn_mark_class_busy(setno, class) == FALSE) {
			mutex_unlock(&mdmn_busy_mutex[setno]);
			*retval = MDMNE_CLASS_BUSY;
			free_msg(msg);
			return (retval);
		}
		mutex_unlock(&mdmn_busy_mutex[setno]);
		/*
		 * Because the real processing of the message takes time we
		 * create a thread for it. So the master thread can continue
		 * to run and accept further messages.
		 */
		*retval = thr_create(NULL, 0,
		    (void *(*)(void *))mdmn_master_process_msg, (void *)msg,
		    THR_DETACHED|THR_SUSPENDED, &tid);
	} else {
		rw_unlock(&set_desc_rwlock[setno]);
		*retval = thr_create(NULL, 0,
		    (void *(*)(void *)) mdmn_slave_process_msg, (void *)msg,
		    THR_DETACHED|THR_SUSPENDED, &tid);
	}

	if (*retval != 0) {
		*retval = MDMNE_THR_CREATE_FAIL;
		free_msg(msg);
		return (retval);
	}

	/* Now run the new thread */
	thr_continue(tid);

	commd_debug(MD_MMV_WORK,
	    "work: done (%d, 0x%llx-%d), set=%d, class=%d, type=%d\n",
	    MSGID_ELEMS(msg->msg_msgid), setno, class, msg->msg_type);

	*retval = MDMNE_ACK; /* this means success */
	return (retval);
}

/* ARGSUSED */
int *
mdmn_wakeup_initiator_svc_2(md_mn_result_t *res, struct svc_req *rqstp)
{

	int		*retval;
	int		err;
	set_t		setno;
	mutex_t		*mx;   /* protection of initiator_table */
	SVCXPRT		*transp = NULL;
	md_mn_msgid_t	initiator_table_id;
	md_mn_msgclass_t class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	setno	= res->mmr_setno;

	if (md_mn_set_inited[setno] != MDMN_SET_READY) {
		/* set not ready means we just crashed are restarted now */
		/* Can only use the appropriate mutexes if they are inited */
		if (md_mn_set_inited[setno] & MDMN_SET_MUTEXES) {
			rw_wrlock(&set_desc_rwlock[setno]);
			rw_wrlock(&client_rwlock[setno]);
			err = mdmn_init_set(setno, MDMN_SET_READY);
			rw_unlock(&client_rwlock[setno]);
			rw_unlock(&set_desc_rwlock[setno]);
		} else {
			err = mdmn_init_set(setno, MDMN_SET_READY);
		}

		if (err) {
			*retval = MDMNE_CANNOT_CONNECT;
			xdr_free(xdr_md_mn_result_t, (caddr_t)res);
			return (retval);
		}
	}

	/* is this rpc request coming from a licensed node? */
	if (check_license(rqstp, res->mmr_sender) == FALSE) {
		xdr_free(xdr_md_mn_result_t, (caddr_t)res);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}


	class	= mdmn_get_message_class(res->mmr_msgtype);
	mx	= mdmn_get_initiator_table_mx(setno, class);

	commd_debug(MD_MMV_WAKE_I,
	    "wake_ini: received (%d, 0x%llx-%d) set=%d, class=%d, type=%d\n",
	    MSGID_ELEMS(res->mmr_msgid), setno, class, res->mmr_msgtype);

	mutex_lock(mx);

	/*
	 * Search the initiator wakeup table.
	 * If we find an entry here (which should always be true)
	 * we are on the initiating node and we wakeup the original
	 * local rpc call.
	 */
	mdmn_get_initiator_table_id(setno, class, &initiator_table_id);

	if (MSGID_CMP(&(initiator_table_id), &(res->mmr_msgid))) {
		transp = mdmn_get_initiator_table_transp(setno, class);
		mdmn_svc_sendreply(transp, xdr_md_mn_result_t, (char *)res);
		svc_done(transp);
		mdmn_unregister_initiator_table(setno, class);
		*retval = MDMNE_ACK;

		commd_debug(MD_MMV_WAKE_I,
		    "wake_ini: replied (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(res->mmr_msgid));
	} else {
		commd_debug(MD_MMV_WAKE_I,
		    "wakeup initiator: unsolicited message (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(res->mmr_msgid));
		*retval = MDMNE_NO_WAKEUP_ENTRY;
	}
	mutex_unlock(mx);
	/* less work for check_timeouts */
	mutex_lock(&check_timeout_mutex);
	if (messages_on_their_way == 0) {
		commd_debug(MD_MMV_WAKE_I,
		    "Oops, messages_on_their_way < 0 (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(res->mmr_msgid));
	} else {
		messages_on_their_way--;
	}
	mutex_unlock(&check_timeout_mutex);
	xdr_free(xdr_md_mn_result_t, (caddr_t)res);

	return (retval);
}


/*
 * res must be free'd by the thread we wake up
 */
/* ARGSUSED */
int *
mdmn_wakeup_master_svc_2(md_mn_result_t *ores, struct svc_req *rqstp)
{

	int		*retval;
	int		err;
	set_t		setno;
	cond_t		*cv;
	mutex_t		*mx;
	md_mn_msgid_t	master_table_id;
	md_mn_nodeid_t	sender;
	md_mn_result_t	*res;
	md_mn_msgclass_t class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* Need to copy the results here, as they are static for RPC */
	res = copy_result(ores);
	xdr_free(xdr_md_mn_result_t, (caddr_t)ores);

	class = mdmn_get_message_class(res->mmr_msgtype);
	setno = res->mmr_setno;

	if (md_mn_set_inited[setno] != MDMN_SET_READY) {
		/* set not ready means we just crashed are restarted now */
		/* Can only use the appropriate mutexes if they are inited */
		if (md_mn_set_inited[setno] & MDMN_SET_MUTEXES) {
			rw_wrlock(&set_desc_rwlock[setno]);
			rw_wrlock(&client_rwlock[setno]);
			err = mdmn_init_set(setno, MDMN_SET_READY);
			rw_unlock(&client_rwlock[setno]);
			rw_unlock(&set_desc_rwlock[setno]);
		} else {
			err = mdmn_init_set(setno, MDMN_SET_READY);
		}

		if (err) {
			*retval = MDMNE_CANNOT_CONNECT;
			xdr_free(xdr_md_mn_result_t, (caddr_t)res);
			return (retval);
		}
	}

	/* is this rpc request coming from a licensed node? */
	if (check_license(rqstp, res->mmr_sender) == FALSE) {
		*retval = MDMNE_RPC_FAIL;
		xdr_free(xdr_md_mn_result_t, (caddr_t)res);
		return (retval);
	}


	commd_debug(MD_MMV_WAKE_M,
	    "wake_mas: received (%d, 0x%llx-%d) set=%d, class=%d, type=%d "
	    "from %d\n",
	    MSGID_ELEMS(res->mmr_msgid), setno, class, res->mmr_msgtype,
	    res->mmr_sender);
	/*
	 * The mutex and cv are needed for waking up the thread
	 * sleeping in mdmn_master_process_msg()
	 */
	mx = mdmn_get_master_table_mx(setno, class);
	cv = mdmn_get_master_table_cv(setno, class);

	/*
	 * lookup the master wakeup table
	 * If we find our message, we are on the master and
	 * called by a slave that finished processing a message.
	 * We store the results in the appropriate slot and
	 * wakeup the thread (mdmn_master_process_msg()) waiting for them.
	 */
	mutex_lock(mx);
	mdmn_get_master_table_id(setno, class, &master_table_id);
	sender = mdmn_get_master_table_addr(setno, class);

	if (MSGID_CMP(&(master_table_id), &(res->mmr_msgid))) {
		if (sender == res->mmr_sender) {
			mdmn_set_master_table_res(setno, class, res);
			cond_signal(cv);
			*retval = MDMNE_ACK;
		} else {
			/* id is correct but wrong sender (I smell a timeout) */
			commd_debug(MD_MMV_WAKE_M,
			    "wakeup master got unsolicited message: "
			    "(%d, 0x%llx-%d) from %d\n",
			    MSGID_ELEMS(res->mmr_msgid), res->mmr_sender);
			free_result(res);
			*retval = MDMNE_TIMEOUT;
		}
	} else {
		/* id is wrong, smells like a very late timeout */
		commd_debug(MD_MMV_WAKE_M,
		    "wakeup master got unsolicited message: "
		    "(%d, 0x%llx-%d) from %d, expected (%d, 0x%llx-%d)\n",
		    MSGID_ELEMS(res->mmr_msgid), res->mmr_sender,
		    MSGID_ELEMS(master_table_id));
		free_result(res);
		*retval = MDMNE_NO_WAKEUP_ENTRY;
	}

	mutex_unlock(mx);

	return (retval);
}

/*
 * Lock a set/class combination.
 * This is mainly done for debug purpose.
 * This set/class combination immediately is blocked,
 * even in the middle of sending messages to multiple slaves.
 * This remains until the user issues a mdmn_comm_unlock_svc_2 for the same
 * set/class combination.
 *
 * Special messages of class MD_MSG_CLASS0 can never be locked.
 * 	e.g. MD_MN_MSG_VERBOSITY, MD_MN_MSG_ABORT
 *
 * That means, if MD_MSG_CLASS0 is specified, we lock all classes from
 * >= MD_MSG_CLASS1 to < MD_MN_NCLASSES
 *
 * set must be between 1 and MD_MAXSETS
 * class can be:
 *	MD_MSG_CLASS0 which means all other classes in this case
 *	or one specific class (< MD_MN_NCLASSES)
 *
 * Returns:
 *	MDMNE_ACK on sucess (locking a locked class is Ok)
 *	MDMNE_EINVAL if a parameter is out of range
 */

/* ARGSUSED */
int *
mdmn_comm_lock_svc_2(md_mn_set_and_class_t *msc, struct svc_req *rqstp)
{
	int			*retval;
	set_t			setno = msc->msc_set;
	md_mn_msgclass_t	class = msc->msc_class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_md_mn_set_and_class_t, (caddr_t)msc);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	/* Perform some range checking */
	if ((setno == 0) || (setno >= MD_MAXSETS) ||
	    (class < MD_MSG_CLASS0) || (class >= MD_MN_NCLASSES)) {
		*retval = MDMNE_EINVAL;
		return (retval);
	}

	commd_debug(MD_MMV_MISC, "lock: set=%d, class=%d\n", setno, class);
	mutex_lock(&mdmn_busy_mutex[setno]);
	if (class != MD_MSG_CLASS0) {
		mdmn_mark_class_locked(setno, class);
	} else {
		/* MD_MSG_CLASS0 is used as a wild card for all classes */
		for (class = MD_MSG_CLASS1; class < MD_MN_NCLASSES; class++) {
			mdmn_mark_class_locked(setno, class);
		}
	}
	mutex_unlock(&mdmn_busy_mutex[setno]);

	*retval = MDMNE_ACK;
	return (retval);
}

/*
 * Unlock a set/class combination.
 * set must be between 1 and MD_MAXSETS
 * class can be:
 *	MD_MSG_CLASS0 which means all other classes in this case (like above)
 *	or one specific class (< MD_MN_NCLASSES)
 *
 * Returns:
 *	MDMNE_ACK on sucess (unlocking an unlocked class is Ok)
 *	MDMNE_EINVAL if a parameter is out of range
 */
/* ARGSUSED */
int *
mdmn_comm_unlock_svc_2(md_mn_set_and_class_t *msc, struct svc_req *rqstp)
{
	int			*retval;
	set_t			setno  = msc->msc_set;
	md_mn_msgclass_t	class  = msc->msc_class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_md_mn_set_and_class_t, (caddr_t)msc);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	/* Perform some range checking */
	if ((setno == 0) || (setno >= MD_MAXSETS) ||
	    (class < MD_MSG_CLASS0) || (class >= MD_MN_NCLASSES)) {
		*retval = MDMNE_EINVAL;
		return (retval);
	}
	commd_debug(MD_MMV_MISC, "unlock: set=%d, class=%d\n", setno, class);

	mutex_lock(&mdmn_busy_mutex[setno]);
	if (class != MD_MSG_CLASS0) {
		mdmn_mark_class_unlocked(setno, class);
	} else {
		/* MD_MSG_CLASS0 is used as a wild card for all classes */
		for (class = MD_MSG_CLASS1; class < MD_MN_NCLASSES; class++) {
			mdmn_mark_class_unlocked(setno, class);
		}
	}
	mutex_unlock(&mdmn_busy_mutex[setno]);

	*retval = MDMNE_ACK;
	return (retval);
}

/*
 * mdmn_comm_suspend_svc_2(setno, class)
 *
 * Drain all outstanding messages for a given set/class combination
 * and don't allow new messages to be processed.
 *
 * Special messages of class MD_MSG_CLASS0 can never be locked.
 * 	e.g. MD_MN_MSG_VERBOSITY
 *
 * 1 <= setno < MD_MAXSETS	or setno == MD_COMM_ALL_SETS
 * 1 <= class < MD_MN_NCLASSES	or class == MD_COMM_ALL_CLASSES
 *
 * If class _is_not_ MD_COMM_ALL_CLASSES, then we simply mark this
 * one class as being suspended.
 * If messages for this class are currently on their way,
 * MDMNE_SET_NOT_DRAINED is returned. Otherwise MDMNE_ACK is returned.
 *
 * If class _is_ MD_COMM_ALL_CLASSES we drain all classes of this set.
 * Messages must be generated in ascending order.
 * This means, a message cannot create submessages with the same or lower class.
 * Draining messages must go from 1 to NCLASSES in order to ensure we don't
 * generate a hanging situation here.
 * We mark class 1 as being suspended.
 * if the class is not busy, we proceed with class 2
 * and so on
 * if a class *is* busy, we cannot continue here, but return
 * MDMNE_SET_NOT_DRAINED.
 * We expect the caller to hold on for some seconds and try again.
 * When that message, that held the class busy is done in
 * mdmn_master_process_msg(), mdmn_mark_class_unbusy() called.
 * There it is checked if the class is about to drain.
 * In that case it tries to drain all higher classes there.
 *
 * If setno is MD_COMM_ALL_SETS then we perform this on all possible sets.
 * In that case we return MDMNE_SET_NOT_DRAINED if not all sets are
 * completely drained.
 *
 * Returns:
 *	MDMNE_ACK on sucess (set is drained, no outstanding messages)
 *	MDMNE_SET_NOT_DRAINED  if drain process is started, but there are
 *		still outstanding messages for this set(s)
 *	MDMNE_EINVAL if setno is out of range
 *	MDMNE_NOT_JOINED if the set is not yet initialized on this node
 */

/* ARGSUSED */
int *
mdmn_comm_suspend_svc_2(md_mn_set_and_class_t *msc, struct svc_req *rqstp)
{
	int			*retval;
	int			failure = 0;
	set_t			startset, endset;
	set_t			setno  = msc->msc_set;
	md_mn_msgclass_t	oclass = msc->msc_class;
#ifdef NOT_YET_NEEDED
	uint_t			flags  = msc->msc_flags;
#endif /* NOT_YET_NEEDED */
	md_mn_msgclass_t	class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_md_mn_set_and_class_t, (caddr_t)msc);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	commd_debug(MD_MMV_MISC, "suspend: called for set=%d class=%d\n",
	    setno, oclass);

	/* Perform some range checking */
	if (setno >= MD_MAXSETS) {
		*retval = MDMNE_EINVAL;
		commd_debug(MD_MMV_MISC, "suspend: returning MDMNE_EINVAL\n");
		return (retval);
	}

	/*  setno == MD_COMM_ALL_SETS means: we walk thru all possible sets. */
	if (setno == MD_COMM_ALL_SETS) {
		startset = 1;
		endset = MD_MAXSETS - 1;
	} else {
		startset = setno;
		endset = setno;
	}

	for (setno = startset; setno <= endset; setno++) {
		/* Here we need the mutexes for the set to be setup */
		if (md_mn_set_inited[setno] != MDMN_SET_MUTEXES) {
			(void) mdmn_init_set(setno, MDMN_SET_MUTEXES);
		}

		mutex_lock(&mdmn_busy_mutex[setno]);
		/* shall we drain all classes of this set? */
		if (oclass == MD_COMM_ALL_CLASSES) {
			for (class = 1; class < MD_MN_NCLASSES; class ++) {
				commd_debug(MD_MMV_MISC,
				    "suspend: suspending set %d, class %d\n",
				    setno, class);
				*retval = mdmn_mark_class_suspended(setno,
				    class, MDMN_SUSPEND_ALL);
				if (*retval == MDMNE_SET_NOT_DRAINED) {
					failure++;
				}
			}
		} else {
			/* only drain one specific class */
			commd_debug(MD_MMV_MISC,
			    "suspend: suspending set=%d class=%d\n",
			    setno, oclass);
			*retval = mdmn_mark_class_suspended(setno, oclass,
			    MDMN_SUSPEND_1);
			if (*retval == MDMNE_SET_NOT_DRAINED) {
				failure++;
			}
		}
		mutex_unlock(&mdmn_busy_mutex[setno]);
	}
	/* If one or more sets are not entirely drained, failure is non-zero */
	if (failure != 0) {
		*retval = MDMNE_SET_NOT_DRAINED;
		commd_debug(MD_MMV_MISC,
		    "suspend: returning MDMNE_SET_NOT_DRAINED\n");
	} else {
		*retval = MDMNE_ACK;
	}

	return (retval);
}

/*
 * mdmn_comm_resume_svc_2(setno, class)
 *
 * Resume processing messages for a given set.
 * This incorporates the repeal of a previous suspend operation.
 *
 * 1 <= setno < MD_MAXSETS	or setno == MD_COMM_ALL_SETS
 * 1 <= class < MD_MN_NCLASSES	or class == MD_COMM_ALL_CLASSES
 *
 * If class _is_not_ MD_COMM_ALL_CLASSES, then we simply mark this
 * one class as being resumed.
 *
 * If class _is_ MD_COMM_ALL_CLASSES we resume all classes of this set.
 *
 * If setno is MD_COMM_ALL_SETS then we perform this on all possible sets.
 *
 * If both setno is MD_COMM_ALL_SETS and class is MD_COMM_ALL_CLASSES we also
 * reset any ABORT flag from the global state.
 *
 * Returns:
 *	MDMNE_ACK on sucess (resuming an unlocked set is Ok)
 *	MDMNE_EINVAL if setno is out of range
 *	MDMNE_NOT_JOINED if the set is not yet initialized on this node
 */
/* ARGSUSED */
int *
mdmn_comm_resume_svc_2(md_mn_set_and_class_t *msc, struct svc_req *rqstp)
{
	int			*retval;
	set_t			startset, endset;
	set_t			setno  = msc->msc_set;
	md_mn_msgclass_t	oclass = msc->msc_class;
	uint_t			flags  = msc->msc_flags;
	md_mn_msgclass_t	class;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_md_mn_set_and_class_t, (caddr_t)msc);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	commd_debug(MD_MMV_MISC, "resume: called for set=%d class=%d\n",
	    setno, oclass);

	/* Perform some range checking */
	if (setno > MD_MAXSETS) {
		*retval = MDMNE_EINVAL;
		return (retval);
	}

	if (setno == MD_COMM_ALL_SETS) {
		startset = 1;
		endset = MD_MAXSETS - 1;
		if (oclass == MD_COMM_ALL_CLASSES) {
			/* This is the point where we "unabort" the commd */
			commd_debug(MD_MMV_MISC, "resume: resetting ABORT\n");
			md_commd_global_state &= ~MD_CGS_ABORTED;
		}
	} else {
		startset = setno;
		endset = setno;
	}

	for (setno = startset; setno <= endset; setno++) {

		/* Here we need the mutexes for the set to be setup */
		if ((md_mn_set_inited[setno] & MDMN_SET_MUTEXES) == 0) {
			(void) mdmn_init_set(setno, MDMN_SET_MUTEXES);
		}

		mutex_lock(&mdmn_busy_mutex[setno]);

		if (oclass == MD_COMM_ALL_CLASSES) {
			int end_class = 1;
			/*
			 * When SUSPENDing all classes, we go
			 * from 1 to MD_MN_NCLASSES-1
			 * The correct reverse action is RESUMing
			 * from MD_MN_NCLASSES-1 to 1 (or 2)
			 */

			if (flags & MD_MSCF_DONT_RESUME_CLASS1) {
				end_class = 2;
			}

			/*
			 * Then mark all classes of this set as no longer
			 * suspended. This supersedes any previous suspend(1)
			 * calls and resumes the set entirely.
			 */
			for (class = MD_MN_NCLASSES - 1; class >= end_class;
			    class --) {
				commd_debug(MD_MMV_MISC,
				    "resume: resuming set=%d class=%d\n",
				    setno, class);
				mdmn_mark_class_resumed(setno, class,
				    (MDMN_SUSPEND_ALL | MDMN_SUSPEND_1));
			}
		} else {
			/*
			 * In this case only one class is marked as not
			 * suspended. If a suspend(all) is currently active for
			 * this set, this class will still be suspended.
			 * That state will be cleared by a suspend(all)
			 * (see above)
			 */
			commd_debug(MD_MMV_MISC,
			    "resume: resuming set=%d class=%d\n",
			    setno, oclass);
			mdmn_mark_class_resumed(setno, oclass, MDMN_SUSPEND_1);
		}

		mutex_unlock(&mdmn_busy_mutex[setno]);
	}

	*retval = MDMNE_ACK;
	return (retval);
}
/* ARGSUSED */
int *
mdmn_comm_reinit_set_svc_2(set_t *setnop, struct svc_req *rqstp)
{
	int		*retval;
	md_mnnode_desc	*node;
	set_t		 setno = *setnop;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_set_t, (caddr_t)setnop);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	commd_debug(MD_MMV_MISC, "reinit: set=%d\n", setno);

	rw_rdlock(&set_desc_rwlock[setno]);
	/*
	 * We assume, that all messages have been suspended previously.
	 *
	 * As we are modifying lots of clients here we grab the client_rwlock
	 * in writer mode. This ensures, no new messages come in.
	 */
	rw_wrlock(&client_rwlock[setno]);
	/* This set is no longer initialized */

	if ((set_descriptor[setno] != NULL) &&
	    (md_mn_set_inited[setno] & MDMN_SET_NODES)) {
		/* destroy all rpc clients from this set */
		for (node = set_descriptor[setno]->sd_nodelist; node;
		    node = node->nd_next) {
			mdmn_clnt_destroy(client[setno][node->nd_nodeid]);
			if (client[setno][node->nd_nodeid] != (CLIENT *)NULL) {
				client[setno][node->nd_nodeid] = (CLIENT *)NULL;
			}
		}
	md_mn_set_inited[setno] &= ~MDMN_SET_NODES;
	}

	commd_debug(MD_MMV_MISC, "reinit: done init_set(%d)\n", setno);

	rw_unlock(&client_rwlock[setno]);
	rw_unlock(&set_desc_rwlock[setno]);
	*retval = MDMNE_ACK;
	return (retval);
}

/*
 * This is just an interface for testing purpose.
 * Here we can disable single message types.
 * If we block a message type, this is valid for all MN sets.
 * If a message arrives later, and  it's message type is blocked, it will
 * be returned immediately with MDMNE_CLASS_LOCKED, which causes the sender to
 * resend this message over and over again.
 */

/* ARGSUSED */
int *
mdmn_comm_msglock_svc_2(md_mn_type_and_lock_t *mmtl, struct svc_req *rqstp)
{
	int			*retval;
	md_mn_msgtype_t		type = mmtl->mmtl_type;
	uint_t			lock = mmtl->mmtl_lock;

	retval = Malloc(sizeof (int));

	/* check if the global initialization is done */
	if ((md_commd_global_state & MD_CGS_INITED) == 0) {
		global_init();
	}

	/* is this rpc request coming from the local node ? */
	if (check_license(rqstp, 0) == FALSE) {
		xdr_free(xdr_md_mn_type_and_lock_t, (caddr_t)mmtl);
		*retval = MDMNE_RPC_FAIL;
		return (retval);
	}

	/* Perform some range checking */
	if ((type == 0) || (type >= MD_MN_NMESSAGES)) {
		*retval = MDMNE_EINVAL;
		return (retval);
	}

	commd_debug(MD_MMV_MISC, "msglock: type=%d, lock=%d\n", type, lock);
	msgtype_lock_state[type] = lock;

	*retval = MDMNE_ACK;
	return (retval);
}
