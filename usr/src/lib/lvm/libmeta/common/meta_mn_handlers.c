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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <wait.h>
#include <sys/time.h>
#include <syslog.h>

#include <meta.h>
#include <sys/lvm/mdio.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_mirror.h>

#define	MAX_N_ARGS 64
#define	MAX_ARG_LEN 1024
#define	MAX_SLEEPS 99
#define	SLEEP_MOD 5

/* we reserve 1024 bytes for stdout and the same for stderr */
#define	MAX_OUT	1024
#define	MAX_ERR	1024
#define	JUNK 128 /* used to flush stdout and stderr */


/*ARGSUSED*/
void
mdmn_do_cmd(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{

	/*
	 * We are given one string containing all the arguments
	 * For execvp() we have to regenerate the arguments again
	 */
	int	arg;		/* argument that is currently been built */
	int	index;		/* runs through arg above */
	int	i;		/* helper for for loop */
	char	*argv[MAX_N_ARGS]; /* argument array for execvp */
	char	*cp;		/* runs through the given command line string */
	char	*command = NULL; /* the command we call locally */
	int	pout[2];	/* pipe for stdout */
	int	perr[2];	/* pipe for stderr */
	pid_t	pid;		/* process id */

	cp	= msg->msg_event_data;
	arg	= 0;
	index	= 0;

	/* init the args array alloc the first one and null out the rest */
	argv[0] = Malloc(MAX_ARG_LEN);
	for (i = 1; i < MAX_N_ARGS; i++) {
		argv[i] = NULL;
	}

	resp->mmr_comm_state	= MDMNE_ACK; /* Ok state */;

	while (*cp != '\0') {
		if (arg == MAX_N_ARGS) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "PANIC: too many arguments specified\n"));
			resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
			goto out;
		}
		if (index == MAX_ARG_LEN) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "PANIC: argument too long\n"));
			resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
			goto out;
		}

		if ((*cp != ' ') && (*cp != '\t')) {
			/*
			 * No space or tab: copy char into current
			 * argv and advance both pointers
			 */

			argv[arg][index] = *cp;
			cp++;	/* next char in command line	*/
			index++;	/* next char in argument	*/
		} else {
			/*
			 * space or tab: terminate current argv,
			 * advance arg, reset pointer into arg,
			 * advance pointer in command line
			 */
			argv[arg][index] = '\0';
			arg++; /* next argument */
			argv[arg] = Malloc(MAX_ARG_LEN);
			cp++; /* next char in command line */
			index = 0; /* starts at char 0 */
		}
	}
	/* terminate the last real argument */
	argv[arg][index] = '\0';
	/* the last argument is an NULL pointer */
	argv[++arg] = NULL;
	if (pipe(pout) < 0)  {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "PANIC: pipe failed\n"));
		resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
		goto out;
	}
	if (pipe(perr) < 0) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "PANIC: pipe failed\n"));
		(void) close(pout[0]);
		(void) close(pout[1]);
		resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
		goto out;
	}
	command = Strdup(argv[0]);
	(void) strcat(argv[0], ".rpc_call");
	pid = fork1();
	if (pid == (pid_t)-1) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "PANIC: fork failed\n"));
		resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
		(void) close(pout[0]);
		(void) close(pout[1]);
		(void) close(perr[0]);
		(void) close(perr[1]);
		goto out;
	} else  if (pid == (pid_t)0) {
		/* child */
		(void) close(0);
		/* close the reading channels of pout and perr */
		(void) close(pout[0]);
		(void) close(perr[0]);
		/* redirect stdout */
		if (dup2(pout[1], 1) < 0) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "PANIC: dup2 failed\n"));
			resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
			return;
		}

		/* redirect stderr */
		if (dup2(perr[1], 2) < 0) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "PANIC: dup2 failed\n"));
			resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
			return;
		}

		(void) execvp(command, (char *const *)argv);
		perror("execvp");
		_exit(1);
	} else {
		/* parent process */
		int stat_loc;
		char *out, *err; /* for stdout and stderr of child */
		int i; /* index into the aboves */
		char junk[JUNK];
		int out_done = 0;
		int err_done = 0;
		int out_read = 0;
		int err_read = 0;
		int maxfd;
		fd_set	rset;


		/* close the writing channels of pout and perr */
		(void) close(pout[1]);
		(void) close(perr[1]);
		resp->mmr_out = Malloc(MAX_OUT);
		resp->mmr_err = Malloc(MAX_ERR);
		resp->mmr_out_size = MAX_OUT;
		resp->mmr_err_size = MAX_ERR;
		out = resp->mmr_out;
		err = resp->mmr_err;
		FD_ZERO(&rset);
		while ((out_done == 0) || (err_done == 0)) {
			FD_SET(pout[0], &rset);
			FD_SET(perr[0], &rset);
			maxfd = max(pout[0], perr[0]) + 1;
			(void) select(maxfd, &rset, NULL, NULL, NULL);

			/*
			 * Did the child produce some output to stdout?
			 * If so, read it until we either reach the end of the
			 * output or until we read MAX_OUT bytes.
			 * Whatever comes first.
			 * In case we already read MAX_OUT bytes we simply
			 * read away the output into a junk buffer.
			 * Just to make the child happy
			 */
			if (FD_ISSET(pout[0], &rset)) {
				if (MAX_OUT - out_read - 1 > 0) {
					i = read(pout[0], out,
					    MAX_OUT - out_read);
					out_read += i;
					out += i;
				} else {
					/* buffer full, empty stdout */
					i = read(pout[0], junk, JUNK);
				}
				if (i == 0) {
					/* stdout is closed by child */
					out_done++;
				}
			}
			/* same comment as above | sed -e 's/stdout/stderr/' */
			if (FD_ISSET(perr[0], &rset)) {
				if (MAX_ERR - err_read - 1 > 0) {
					i = read(perr[0], err,
					    MAX_ERR - err_read);
					err_read += i;
					err += i;
				} else {
					/* buffer full, empty stderr */
					i = read(perr[0], junk, JUNK);
				}
				if (i == 0) {
					/* stderr is closed by child */
					err_done++;
				}
			}
		}
		resp->mmr_out[out_read] = '\0';
		resp->mmr_err[err_read] = '\0';

		while (waitpid(pid, &stat_loc, 0) < 0) {
			if (errno != EINTR) {
				resp->mmr_comm_state = MDMNE_HANDLER_FAILED;
				break;
			}
		}
		if (errno == 0)
			resp->mmr_exitval = WEXITSTATUS(stat_loc);

		(void) close(pout[0]);
		(void) close(perr[0]);
	}
out:
	for (i = 0; i < MAX_N_ARGS; i++) {
		if (argv[i] != NULL) {
			free(argv[i]);
		}
	}
	if (command != NULL) {
		Free(command);
	}
}

/*
 * This is for checking if a metadevice is opened, and for
 * locking in case it is not and for
 * unlocking a locked device
 */
/*ARGSUSED*/
void
mdmn_do_clu(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	if (msg->msg_type == MD_MN_MSG_CLU_CHECK) {
		md_isopen_t	*d;
		int		ret;

		resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
		resp->mmr_out_size = 0;
		resp->mmr_err_size = 0;
		resp->mmr_out = NULL;
		resp->mmr_err = NULL;
		d = (md_isopen_t *)(void *)msg->msg_event_data;
		ret = metaioctl(MD_IOCISOPEN, d, &(d->mde), NULL);
		/*
		 * In case the ioctl succeeded, return the open state of
		 * the metadevice. Otherwise we return the error the ioctl
		 * produced. As this is not zero, no attempt is made to
		 * remove/rename the metadevice later
		 */

		if (ret == 0) {
			resp->mmr_exitval = d->isopen;
		} else {
			/*
			 * When doing a metaclear, one node after the other
			 * does the two steps:
			 * - check on all nodes if this md is opened.
			 * - remove the md locally.
			 * When the 2nd node asks all nodes if the md is
			 * open it starts with the first node.
			 * As this already removed the md, the check
			 * returns MDE_UNIT_NOT_SETUP.
			 * In order to not keep the 2nd node from proceeding,
			 * we map this to an Ok.
			 */
			if (mdismderror(&(d->mde), MDE_UNIT_NOT_SETUP)) {
				mdclrerror(&(d->mde));
				ret = 0;
			}

			resp->mmr_exitval = ret;
		}
	}
}

/* handler for MD_MN_MSG_REQUIRE_OWNER */
/*ARGSUSED*/
void
mdmn_do_req_owner(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_set_mmown_params_t	setown;
	md_mn_req_owner_t	*d;
	int			ret, n = 0;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_req_owner_t *)(void *)msg->msg_event_data;

	(void) memset(&setown, 0, sizeof (setown));
	MD_SETDRIVERNAME(&setown, MD_MIRROR, MD_MIN2SET(d->mnum))
	setown.d.mnum = d->mnum;
	setown.d.owner = d->owner;

	/* Retry ownership change if we get EAGAIN returned */
	while ((ret = metaioctl(MD_MN_SET_MM_OWNER, &setown, &setown.mde, NULL))
	    != 0) {
		md_sys_error_t	*ip =
		    &setown.mde.info.md_error_info_t_u.sys_error;
		if (ip->errnum != EAGAIN) {
			break;
		}
		if (n++ >= 10) {
			break;
		}
		(void) sleep(1);
	}

	resp->mmr_exitval = ret;
}

/*
 * handler for MD_MN_MSG_CHOOSE_OWNER
 * This is called when a mirror resync has no owner. The master node generates
 * this message which is not broadcast to the other nodes. The message is
 * required as the kernel does not have access to the nodelist for the set.
 */
/*ARGSUSED*/
void
mdmn_do_choose_owner(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_chowner_t	chownermsg;
	md_mn_msg_chooseid_t	*d;
	int			ret = 0;
	int			nodecnt;
	int			nodeno;
	uint_t			nodeid;
	uint_t			myflags;
	set_t			setno;
	mdsetname_t		*sp;
	md_set_desc		*sd;
	md_mnnode_desc		*nd;
	md_error_t		mde = mdnullerror;
	md_mn_result_t		*resp1 = NULL;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_chooseid_t *)(void *)msg->msg_event_data;

	/*
	 * The node to be chosen will be the resync count for the set
	 * modulo the number of live nodes in the set
	 */
	setno = MD_MIN2SET(d->msg_chooseid_mnum);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_CHOOSE_OWNER: Invalid setno %d\n"), setno);
		resp->mmr_exitval = 1;
		return;
	}
	if ((sd = metaget_setdesc(sp, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_CHOOSE_OWNER: Invalid set pointer\n"));
		resp->mmr_exitval = 1;
		return;
	}

	/* Count the number of live nodes */
	nodecnt = 0;
	nd = sd->sd_nodelist;
	while (nd) {
		if (nd->nd_flags & MD_MN_NODE_ALIVE)
			nodecnt++;
		nd = nd->nd_next;
	}
	nodeno = (d->msg_chooseid_rcnt%nodecnt);

	/*
	 * If we've been called with msg_chooseid_set_node set TRUE then we
	 * are simply re-setting the owner id to ensure consistency across
	 * the cluster.
	 * If the flag is reset (B_FALSE) we are requesting a new owner to be
	 * determined.
	 */
	if (d->msg_chooseid_set_node) {
		nodeid = d->msg_chooseid_rcnt;
	} else {
		/* scan the nodelist looking for the required node */
		nodecnt = 0;
		nd = sd->sd_nodelist;
		while (nd) {
			if (nd->nd_flags & MD_MN_NODE_ALIVE) {
				if (nodecnt == nodeno)
					break;
				nodecnt++;
			}
			nd = nd->nd_next;
		}
		nodeid = nd->nd_nodeid;
	}

	/* Send message to all nodes to make ownership change */
	chownermsg.msg_chowner_mnum =  d->msg_chooseid_mnum;
	chownermsg.msg_chowner_nodeid = nodeid;
	myflags = MD_MSGF_NO_LOG;

	/* inherit some flags from the parent message */
	myflags |= msg->msg_flags & MD_MSGF_INHERIT_BITS;

	ret = mdmn_send_message(MD_MIN2SET(d->msg_chooseid_mnum),
	    MD_MN_MSG_CHANGE_OWNER, myflags, (char *)&chownermsg,
	    sizeof (chownermsg), &resp1, &mde);
	if (resp1 != NULL)
		free_result(resp1);
	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_CHANGE_OWNER
 * This is called when we are perfoming a resync and wish to change from
 * no mirror owner to an owner chosen by the master.
 * This mesage is only relevant for the new owner, the message will be
 * ignored by all other nodes
 */
/*ARGSUSED*/
void
mdmn_do_change_owner(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_set_mmown_params_t	setown;
	md_mn_msg_chowner_t	*d;
	int			ret = 0;
	set_t			setno;
	mdsetname_t		*sp;
	md_set_desc		*sd;
	md_error_t		mde = mdnullerror;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_chowner_t *)(void *)msg->msg_event_data;

	setno = MD_MIN2SET(d->msg_chowner_mnum);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_CHANGE_OWNER: Invalid setno %d\n"), setno);
		resp->mmr_exitval = 1;
		return;
	}
	if ((sd = metaget_setdesc(sp, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_CHANGE_OWNER: Invalid set pointer\n"));
		resp->mmr_exitval = 1;
		return;
	}

	if (d->msg_chowner_nodeid == sd->sd_mn_mynode->nd_nodeid) {
		/*
		 * If we are the chosen owner, issue ioctl to make the
		 * ownership change
		 */
		(void) memset(&setown, 0, sizeof (md_set_mmown_params_t));
		setown.d.mnum = d->msg_chowner_mnum;
		setown.d.owner = d->msg_chowner_nodeid;
		setown.d.flags = MD_MN_MM_SPAWN_THREAD;
		MD_SETDRIVERNAME(&setown, MD_MIRROR,
		    MD_MIN2SET(d->msg_chowner_mnum));

		/*
		 * Single shot at changing the the owner, if it fails EAGAIN,
		 * another node must have become the owner while we are in the
		 * process of making this choice.
		 */

		ret = metaioctl(MD_MN_SET_MM_OWNER, &setown,
		    &(setown.mde), NULL);
		if (ret == EAGAIN)
			ret = 0;
	}
	resp->mmr_exitval = ret;
}

/* handler for MD_MN_MSG_SUSPEND_WRITES */
/*ARGSUSED*/
void
mdmn_do_susp_write(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	/* Suspend writes to a region of a mirror */
	md_suspend_wr_params_t	suspwr_ioc;
	md_mn_msg_suspwr_t	*d;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_suspwr_t *)(void *)msg->msg_event_data;

	(void) memset(&suspwr_ioc, 0, sizeof (md_suspend_wr_params_t));
	MD_SETDRIVERNAME(&suspwr_ioc, MD_MIRROR,
	    MD_MIN2SET(d->msg_suspwr_mnum));
	suspwr_ioc.mnum = d->msg_suspwr_mnum;
	ret = metaioctl(MD_MN_SUSPEND_WRITES, &suspwr_ioc,
	    &(suspwr_ioc.mde), NULL);
	resp->mmr_exitval = ret;
}

/*
 * handler for MD_MN_MSG_STATE_UPDATE_RESWR
 * This functions update a submirror component state and then resumes writes
 * to the mirror
 */
/*ARGSUSED*/
void
mdmn_do_state_upd_reswr(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	/* Update the state of the component of a mirror */
	md_set_state_params_t	setstate_ioc;
	md_mn_msg_stch_t	*d;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_stch_t *)(void *)msg->msg_event_data;

	(void) memset(&setstate_ioc, 0, sizeof (md_set_state_params_t));
	MD_SETDRIVERNAME(&setstate_ioc, MD_MIRROR,
	    MD_MIN2SET(d->msg_stch_mnum));
	setstate_ioc.mnum = d->msg_stch_mnum;
	setstate_ioc.sm = d->msg_stch_sm;
	setstate_ioc.comp = d->msg_stch_comp;
	setstate_ioc.state = d->msg_stch_new_state;
	setstate_ioc.hs_id = d->msg_stch_hs_id;
	ret = metaioctl(MD_MN_SET_STATE, &setstate_ioc,
	    &(setstate_ioc.mde), NULL);
	resp->mmr_exitval = ret;
}

/*
 * submessage generator for MD_MN_MSG_STATE_UPDATE and MD_MN_MSG_STATE_UPDATE2
 * This generates 2 messages, the first is SUSPEND_WRITES and
 * depending on the type of the original message the second one is
 * either STATE_UPDATE_RESWR or STATE_UPDATE_RESWR2 which actually does
 * the same, but runs on a higher class.
 */
int
mdmn_smgen_state_upd(md_mn_msg_t *msg, md_mn_msg_t *msglist[])
{
	md_mn_msg_t		*nmsg;
	md_mn_msg_stch_t	*d;
	md_mn_msg_stch_t	*stch_data;
	md_mn_msg_suspwr_t	*suspwr_data;

	d = (md_mn_msg_stch_t *)(void *)msg->msg_event_data;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_SUSPEND_WRITES;
	nmsg->msg_event_size	= sizeof (md_mn_msg_suspwr_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_suspwr_t));
	suspwr_data = (md_mn_msg_suspwr_t *)(void *)nmsg->msg_event_data;
	suspwr_data->msg_suspwr_mnum = d->msg_stch_mnum;
	msglist[0] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	if (msg->msg_type == MD_MN_MSG_STATE_UPDATE2) {
		nmsg->msg_type		= MD_MN_MSG_STATE_UPDATE_RESWR2;
	} else {
		nmsg->msg_type		= MD_MN_MSG_STATE_UPDATE_RESWR;
	}
	nmsg->msg_event_size	= sizeof (md_mn_msg_stch_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_stch_t));
	stch_data = (md_mn_msg_stch_t *)(void *)nmsg->msg_event_data;
	stch_data->msg_stch_mnum = d->msg_stch_mnum;
	stch_data->msg_stch_sm = d->msg_stch_sm;
	stch_data->msg_stch_comp = d->msg_stch_comp;
	stch_data->msg_stch_new_state = d->msg_stch_new_state;
	stch_data->msg_stch_hs_id = d->msg_stch_hs_id;
	msglist[1] = nmsg;
	return (2); /* Return the number of submessages generated */
}

/*
 * handler for MD_MN_MSG_ALLOCATE_HOTSPARE and MD_MN_MSG_ALLOCATE_HOTSPARE2
 * This sends a message to all nodes requesting them to allocate a hotspare
 * for the specified component. The component is specified by the mnum of
 * the mirror, the submirror index and the component index.
 */
/*ARGSUSED*/
void
mdmn_do_allocate_hotspare(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	/* Allocate a hotspare for a mirror component */
	md_alloc_hotsp_params_t allochsp_ioc;
	md_mn_msg_allochsp_t    *d;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_allochsp_t *)((void *)(msg->msg_event_data));

	(void) memset(&allochsp_ioc, 0,
	    sizeof (md_alloc_hotsp_params_t));
	MD_SETDRIVERNAME(&allochsp_ioc, MD_MIRROR,
	    MD_MIN2SET(d->msg_allochsp_mnum));
	allochsp_ioc.mnum = d->msg_allochsp_mnum;
	allochsp_ioc.sm = d->msg_allochsp_sm;
	allochsp_ioc.comp = d->msg_allochsp_comp;
	allochsp_ioc.hs_id = d->msg_allochsp_hs_id;
	ret = metaioctl(MD_MN_ALLOCATE_HOTSPARE, &allochsp_ioc,
	    &(allochsp_ioc.mde), NULL);
	resp->mmr_exitval = ret;
}

/*
 * handler for MD_MN_MSG_RESYNC_STARTING,MD_MN_MSG_RESYNC_FIRST,
 * MD_MN_MSG_RESYNC_NEXT, MD_MN_MSG_RESYNC_FINISH, MD_MN_MSG_RESYNC_PHASE_DONE
 */
/*ARGSUSED*/
void
mdmn_do_resync(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_resync_t		*d;
	md_mn_rs_params_t		respar;
	mddb_setflags_config_t	sf;
	md_error_t				ep = mdnullerror;
	mdsetname_t				*sp;
	int	ret;
	int	smi;
	int start_flag = 1;
	int sleep_count = 0;
	unsigned int sleep_time = 2;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_resync_t *)((void *)(msg->msg_event_data));

	(void) memset(&respar, 0, sizeof (respar));
	MD_SETDRIVERNAME(&respar, MD_MIRROR,
	    MD_MIN2SET(d->msg_resync_mnum))
	respar.msg_type = (int)msg->msg_type;
	respar.mnum = d->msg_resync_mnum;
	respar.rs_type = d->msg_resync_type;
	respar.rs_start = d->msg_resync_start;
	respar.rs_size = d->msg_resync_rsize;
	respar.rs_done = d->msg_resync_done;
	respar.rs_2_do = d->msg_resync_2_do;
	respar.rs_originator = d->msg_originator;
	respar.rs_flags = d->msg_resync_flags;

	for (smi = 0; smi < NMIRROR; smi++) {
		respar.rs_sm_state[smi] = d->msg_sm_state[smi];
		respar.rs_sm_flags[smi] = d->msg_sm_flags[smi];
	}

	/*
	 * Prior to running the resync thread first check that the start_step
	 * flag (MD_SET_MN_START_RC) added by metaclust's MC_START step has been
	 * removed from the set record flags. Ordinarily, this would be removed
	 * at MC_STEP4 in metaclust - need to ensure this has happened on all
	 * nodes.
	 */
	(void) memset(&sf, 0, sizeof (sf));
	sf.sf_setno = MD_MIN2SET(d->msg_resync_mnum);
	sf.sf_flags = MDDB_NM_GET;
	/* Use magic to help protect ioctl against attack. */
	sf.sf_magic = MDDB_SETFLAGS_MAGIC;
	if ((sp = metasetnosetname(sf.sf_setno, &ep)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MDMN_DO_RESYNC: Invalid setno = %d\n"),
		    sf.sf_setno);
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}

	/* start_flag always true initially */
	while (start_flag) {
		if (metaioctl(MD_MN_GET_SETFLAGS, &sf, &sf.sf_mde, NULL) != 0) {
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			    "MDMN_DO_RESYNC: Could not get start_step "
			    "flag for set %s - returning\n"),
			    sp->setname);
			(void) mdstealerror(&(resp->mmr_ep), &sf.sf_mde);
			resp->mmr_exitval = -1;
			return;
		}

		/* metaioctl returns successfully - is start flag cleared? */
		if (sf.sf_setflags & MD_SET_MN_START_RC) {
			start_flag = 1;
			(void) sleep(sleep_time);
			sleep_count++;
			if ((sleep_count == 1) ||
			    (sleep_count % SLEEP_MOD) == 0) {
				syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "MDMN_DO_RESYNC: Waiting for start_step "
				    "flag for set %s to be cleared\n"),
				    sp->setname);
			}
			if (sleep_count == MAX_SLEEPS) {
				syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "MDMN_DO_RESYNC: Could not clear "
				    "start_step flag for set %s "
				    "- returning\n"), sp->setname);
				resp->mmr_exitval = -1;
				return;
			}
		} else {
			start_flag = 0;
		}
	}

	ret = metaioctl(MD_MN_RESYNC, &respar, &respar.mde, NULL);
	if (ret) {
		(void) mdstealerror(&(resp->mmr_ep), &respar.mde);
	}
	resp->mmr_exitval = ret;
}

/*
 * handler for MD_MN_MSG_SETSYNC
 */
/*ARGSUSED*/
void
mdmn_do_setsync(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_setsync_t	*d;
	md_resync_ioctl_t	ri;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_setsync_t *)((void *)(msg->msg_event_data));

	(void) memset(&ri, 0, sizeof (ri));
	MD_SETDRIVERNAME(&ri, MD_MIRROR, MD_MIN2SET(d->setsync_mnum))
	ri.ri_mnum = d->setsync_mnum;
	ri.ri_copysize = d->setsync_copysize;
	ri.ri_flags = d->setsync_flags;

	ret = metaioctl(MD_MN_SETSYNC, &ri, &ri.mde, NULL);

	resp->mmr_exitval = ret;
}

/*
 * handler for MD_MN_MSG_SET_CAP. As this handler can deal with both mirrors
 * and soft partitions, the driver name that is required for the ioctl call
 * is included in the message.
 */
/*ARGSUSED*/
void
mdmn_do_set_cap(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_setcap_t	*d;
	md_mn_setcap_params_t	setcap_ioc;
	minor_t			mnum;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_setcap_t *)((void *)(msg->msg_event_data));
	mnum = d->msg_setcap_mnum;

	(void) memset(&setcap_ioc, 0, sizeof (setcap_ioc));

	MD_SETDRIVERNAME(&setcap_ioc, d->msg_setcap_driver, MD_MIN2SET(mnum));
	setcap_ioc.mnum = mnum;
	setcap_ioc.sc_set = d->msg_setcap_set;

	ret = metaioctl(MD_MN_SET_CAP, &setcap_ioc, &setcap_ioc.mde, NULL);

	resp->mmr_exitval = ret;
}

/*
 * Dummy handler for various CLASS0 messages like
 * MD_MN_MSG_VERBOSITY / MD_MN_MSG_RESUME / MD_MN_MSG_SUSPEND ...
 */
/*ARGSUSED*/
void
mdmn_do_dummy(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_exitval = 0;
	resp->mmr_comm_state = MDMNE_ACK;
}

/*
 * Overall description of mdcommd support that keeps all nodes in-sync
 * with the ondisk diskset mddbs.
 *
 * All configuration changes to the mddb - addition/deletion of metadevices
 * or replicas must use a CLASS1 message to block out these changes.
 * Changes to the state of existing replicas do not need to block CLASS1
 * since there is no conflict when just updating the state of a replica.
 *
 * Error encountered when master writes to mddbs:
 *	As the master updates parts of the mddbs, flags are updated describing
 *	what has been written.  When all locks are dropped (either in
 *	mddb_setexit or mdioctl), a PARSE message will be generated to all
 *	nodes with an index list of known good mddbs and the parse flags.
 *	The master node ignore the parse message since it sent it.
 *	The slave nodes re-read in the changed part of the mddb using the list
 *	of known good replicas that was passed.
 *	PARSE message does not block CLASS1.
 *	The PARSE message must be the highest class message.  Since this
 *	message could be sent on any ioctl, this PARSE message class must
 *	be higher than any other class message that could issue an ioctl.
 *
 *	Master		Slave1		Slave2
 * 	Handles_error
 *	PARSE		PARSE		PARSE
 *
 *
 * Add/Delete mddbs can occur from the following commands:
 *	metadb -s set_name -a/-d
 *	metaset -s set_name -a/-d disk
 *	metaset -s set_name -b
 *
 *	The metadb/metaset command is run on the node executing the command
 *	and sends an ATTACH/DETACH message to the master node blocking CLASS1
 *	messages on all nodes until this message is finished.  The master
 *	node generates 3 submessages of BLOCK, SM_ATTACH/SM_DETACH, UNBLOCK.
 *	The BLOCK message is only run on the master node and will BLOCK
 *	the PARSE messages from being sent to the nodes.
 *	The SM_ATTACH/SM_DETACH message is run on all nodes and actually adds or
 *	removes the replica(s) from the given disk slice.
 *	The UNBLOCK message is only run on the master node and allows the
 *	sending of PARSE messages.
 *
 *	Master		Slave1		Slave2
 *			Add mddb cmd
 *			ATTACH msg to master
 *	BLOCK
 *	ATTACH		ATTACH		ATTACH
 *	UNBLOCK
 *	PARSE		PARSE		PARSE
 *	ATTACH msg finished
 *
 * Add/Delete host side information from the following commands:
 *	metaset -s set_name -a/-d -h
 *
 *	The metaset command is run on the node executing the command and
 *	sends a DB_NEWSIDE/DB_DELSIDE message and a MD_NEWSIDE/MD_DELSIDE
 *	message whenever a host is added to or deleted from the diskset.
 *
 *	The side information contains the major name and minor number
 *	associated with a disk slice from a certain node's perspective
 *	in an (failed) effort to support clustered systems that don't have the
 *	same device name for a physical device. (The original designers of
 *	SVM eventually took the shortcut of assuming that all device names
 *	are the same on all systems, but left the side information in the
 *	mddb and namespace.)  The side information is used for disk slices
 *	that contain mddbs and/or are components for metadevices.
 *
 *	The DB_NEWSIDE/DELSIDE command adds or deletes the side information
 *	for each mddb for the host being added or deleted.
 *	The MD_ADDSIDE/MD_DELSIDE command adds or deletes the side information
 *	for all disk slice components that are in the namespace records for
 *	the host being added or deleted.
 *
 *	The DB_NEWSIDE/DB_DELSIDE message does not change any mddb records
 *	and only needs to be executed on the master node since the slave
 *	nodes will be brought up to date by the PARSE message that is
 *	generated as a result of a change to the mddb.
 *	The MD_ADDSIDE/MD_DELSIDE message does modify the records in the mddb
 *	and needs to be run on all nodes.  The message must block class1
 *	messages so that record changing commands don't interfere.
 *
 *	Master		Slave1		Slave2
 *			Add host
 *			DB_NEWSIDE msg to master
 *	DB_NEWSIDE
 *	PARSE		PARSE		PARSE
 *	DB_NEWSIDE msg finished
 *			MD_NEWSIDE msg to master
 *	MD_NEWSIDE	MD_NEWSIDE	MD_NEWSIDE
 *	MD_NEWSIDE msg finished
 *
 *
 * Optimized resync record failure:
 *	When any node sees a failure to write an optimized resync record
 *	that node notifies the master node of the replica that failed.
 *	The master node handles the error and updates the rest of the
 *	nodes using a PARSE message.  The PARSE message also calls
 *	fixoptrecord on each slave node causing each node to fix up
 * 	the optimized resync records that are owned by that node (the mirror
 *	owner code also sets the optimized resync record owner).  The master
 *	node will fix up all optimized resync records that have no owner or
 *	are owned by the master node.
 *
 *	Master		Slave1		Slave2
 *					Optimized Record Failure
 *					OPTRECERR msg to master
 *	Master handles opt rec failure
 *	PARSE		PARSE		PARSE
 *	OPTRECERR msg finished
 *					Slave rewrites optimized record
 *
 */

/*
 * Handler for MD_MN_MSG_MDDB_PARSE which send parse messages to the
 * slave nodes in order to keep the incore view of the mddbs the
 * same on all nodes.
 *
 * Since master node generated the mddb parse message, do nothing
 * if this is the master node.
 *
 * If this is a slave node, send the parse message down to the kernel
 * where this node will re-read in parts of the mddbs.
 *
 */
void
mdmn_do_mddb_parse(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_mddb_parse_t	*d;
	mddb_parse_parm_t	mpp;
	int			ret = 0;
	int			i;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_mddb_parse_t *)((void *)(msg->msg_event_data));

	if (flags & MD_MSGF_ON_MASTER)
		return;

	(void) memset(&mpp, 0, sizeof (mpp));
	mpp.c_setno = msg->msg_setno;
	mpp.c_parse_flags = d->msg_parse_flags;
	for (i = 0; i < MDDB_NLB; i++) {
		mpp.c_lb_flags[i] = d->msg_lb_flags[i];
	}
	ret = metaioctl(MD_MN_MDDB_PARSE, &mpp, &mpp.c_mde, NULL);
	if (ret)
		(void) mdstealerror(&(resp->mmr_ep), &mpp.c_mde);

	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_MDDB_BLOCK which blocks the generation
 * of parse messages from this node.
 *
 * This is needed when attaching/detaching mddbs on the master and the
 * slave node is unable to handle a parse message until the slave node
 * has done the attach/detach of the mddbs.  So, master node will block
 * the parse messages, execute the attach/detach on all nodes and
 * then unblock the parse messages which causes the parse message to
 * be sent to all nodes.
 */
/*ARGSUSED*/
void
mdmn_do_mddb_block(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_mddb_block_t	*d;
	mddb_block_parm_t	mbp;
	int			ret;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_mddb_block_t *)((void *)(msg->msg_event_data));

	(void) memset(&mbp, 0, sizeof (mbp));
	mbp.c_setno = msg->msg_setno;
	mbp.c_blk_flags = d->msg_block_flags;
	ret = metaioctl(MD_MN_MDDB_BLOCK, &mbp, &mbp.c_mde, NULL);
	if (ret)
		(void) mdstealerror(&(resp->mmr_ep), &mbp.c_mde);

	resp->mmr_exitval = ret;
}

/*
 * Submessage generator for MD_MN_MSG_META_DB_ATTACH which generates
 * a BLOCK message on the master node only, a MD_MN_MSG_SM_MDDB_ATTACH
 * message on all nodes and then an UNBLOCK message on the master only.
 */
int
mdmn_smgen_mddb_attach(md_mn_msg_t *msg, md_mn_msg_t *msglist[])
{
	md_mn_msg_t			*nmsg;
	md_mn_msg_meta_db_attach_t	*d;
	md_mn_msg_meta_db_attach_t	*attach_d;
	md_mn_msg_mddb_block_t		*block_d;

	d = (md_mn_msg_meta_db_attach_t *)(void *)msg->msg_event_data;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= (MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST);
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_MDDB_BLOCK;
	nmsg->msg_event_size	= sizeof (md_mn_msg_mddb_block_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_mddb_block_t));
	block_d = (md_mn_msg_mddb_block_t *)(void *)nmsg->msg_event_data;
	block_d->msg_block_flags = MDDB_BLOCK_PARSE;
	msglist[0] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	/* Don't log submessages and panic on inconsistent results */
	nmsg->msg_flags = MD_MSGF_NO_LOG |
	    MD_MSGF_PANIC_WHEN_INCONSISTENT;
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_SM_MDDB_ATTACH;
	nmsg->msg_event_size	= sizeof (md_mn_msg_meta_db_attach_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_meta_db_attach_t));
	attach_d = (md_mn_msg_meta_db_attach_t *)
	    (void *)nmsg->msg_event_data;
	attach_d->msg_l_dev = d->msg_l_dev;
	attach_d->msg_cnt = d->msg_cnt;
	attach_d->msg_dbsize = d->msg_dbsize;
	(void) strncpy(attach_d->msg_dname, d->msg_dname, 16);
	attach_d->msg_splitname = d->msg_splitname;
	attach_d->msg_options = d->msg_options;
	msglist[1] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= (MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST);
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_MDDB_BLOCK;
	nmsg->msg_event_size	= sizeof (md_mn_msg_mddb_block_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_mddb_block_t));
	block_d = (md_mn_msg_mddb_block_t *)(void *)nmsg->msg_event_data;
	block_d->msg_block_flags = MDDB_UNBLOCK_PARSE;
	msglist[2] = nmsg;

	return (3); /* Return the number of submessages generated */
}

/*
 * Submessage generator for MD_MN_MSG_META_DB_DETACH which generates
 * a BLOCK message on the master node only, a MD_MN_MSG_SM_MDDB_DETACH
 * message on all nodes and then an UNBLOCK message on the master only.
 */
int
mdmn_smgen_mddb_detach(md_mn_msg_t *msg, md_mn_msg_t *msglist[])
{
	md_mn_msg_t			*nmsg;
	md_mn_msg_meta_db_detach_t	*d;
	md_mn_msg_meta_db_detach_t	*detach_d;
	md_mn_msg_mddb_block_t		*block_d;

	d = (md_mn_msg_meta_db_detach_t *)(void *)msg->msg_event_data;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= (MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST);
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_MDDB_BLOCK;
	nmsg->msg_event_size	= sizeof (md_mn_msg_mddb_block_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_mddb_block_t));
	block_d = (md_mn_msg_mddb_block_t *)(void *)nmsg->msg_event_data;
	block_d->msg_block_flags = MDDB_BLOCK_PARSE;
	msglist[0] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	/* Don't log submessages and panic on inconsistent results */
	nmsg->msg_flags = MD_MSGF_NO_LOG |
	    MD_MSGF_PANIC_WHEN_INCONSISTENT;
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_SM_MDDB_DETACH;
	nmsg->msg_event_size	= sizeof (md_mn_msg_meta_db_detach_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_meta_db_detach_t));
	detach_d = (md_mn_msg_meta_db_detach_t *)
	    (void *)nmsg->msg_event_data;
	detach_d->msg_splitname = d->msg_splitname;
	msglist[1] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= (MD_MSGF_NO_LOG | MD_MSGF_NO_BCAST);
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_MDDB_BLOCK;
	nmsg->msg_event_size	= sizeof (md_mn_msg_mddb_block_t);
	nmsg->msg_event_data	= Zalloc(sizeof (md_mn_msg_mddb_block_t));
	block_d = (md_mn_msg_mddb_block_t *)(void *)nmsg->msg_event_data;
	block_d->msg_block_flags = MDDB_UNBLOCK_PARSE;
	msglist[2] = nmsg;

	return (3); /* Return the number of submessages generated */
}

/*
 * Handler for MD_MN_MSG_SM_MDDB_ATTACH which is used to attach mddbs.
 *
 * Used when running:
 *	metadb -s set_name -a
 * 	metaset -s set_name -a/-d disk
 *	metaset -s set_name -b
 */
/*ARGSUSED*/
void
mdmn_do_sm_mddb_attach(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_db_attach_t	*d;
	struct mddb_config		c;
	int				i;
	int				ret = 0;
	md_error_t			ep = mdnullerror;
	char				*name, *add_name;
	mdname_t			*np;
	mdsetname_t			*sp;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_db_attach_t *)((void *)(msg->msg_event_data));

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = msg->msg_setno;
	c.c_locator.l_dev = meta_cmpldev(d->msg_l_dev);
	(void) strncpy(c.c_locator.l_driver, d->msg_dname,
	    sizeof (c.c_locator.l_driver));
	c.c_devname = d->msg_splitname;
	c.c_locator.l_mnum = meta_getminor(d->msg_l_dev);
	c.c_multi_node = 1;
	if ((sp = metasetnosetname(c.c_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}
	(void) strcpy(c.c_setname, sp->setname);
	c.c_sideno = getmyside(sp, &ep);
	if (c.c_sideno == MD_SIDEWILD) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}

	name = splicename(&d->msg_splitname);
	np = metaname(&sp, name, LOGICAL_DEVICE, &ep);
	Free(name);
	if (np == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}
	/*
	 * All nodes in MN diskset must do meta_check_replica
	 * since this causes the shared namespace to be
	 * populated by the md driver names while checking
	 * to see if this device is already in use as a
	 * metadevice.
	 */
	if (meta_check_replica(sp, np, d->msg_options, 0,
	    (d->msg_cnt * d->msg_dbsize), &ep)) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}

	for (i = 0; i < d->msg_cnt; i++) {
		c.c_locator.l_blkno = i * d->msg_dbsize + 16;
		if (setup_med_cfg(sp, &c,
		    (d->msg_options & MDCHK_SET_FORCE), &ep)) {
			ret = -1;
			(void) mdstealerror(&(resp->mmr_ep), &ep);
			break;
		}
		ret = metaioctl(MD_DB_NEWDEV, &c, &c.c_mde, NULL);
		/* If newdev was successful, continue with attach */
		if (ret == 0) {
			if (meta_db_addsidenms(sp, np, c.c_locator.l_blkno,
			    DB_ADDSIDENMS_NO_BCAST, &ep)) {
				ret = -1;
				(void) mdstealerror(&(resp->mmr_ep), &ep);
				break;
			}
		} else {
			(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
			break;
		}
	}
	add_name = splicename(&d->msg_splitname);
	if ((np = metaname(&sp, add_name, LOGICAL_DEVICE, &ep)) != NULL) {
		meta_invalidate_name(np);
	} else {
		ret = -1;
		(void) mdstealerror(&(resp->mmr_ep), &ep);
	}
	Free(add_name);

	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_SM_MDDB_DETACH which is used to detach mddbs.
 *
 * Used when running:
 *	metadb -s set_name -d
 * 	metaset -s set_name -a/-d disk
 *	metaset -s set_name -b
 */
/*ARGSUSED*/
void
mdmn_do_sm_mddb_detach(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_db_detach_t	*d;
	struct mddb_config		c;
	int				i;
	int				ret = 0;
	md_error_t			ep = mdnullerror;
	char				*name, *del_name;
	mdname_t			*np;
	mdsetname_t			*sp;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_db_detach_t *)((void *)(msg->msg_event_data));

	if ((sp = metasetnosetname(msg->msg_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = msg->msg_setno;
	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		resp->mmr_exitval = -1;
		(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
		return;
	}
	i = 0;
	del_name = splicename(&d->msg_splitname);
	while (i < c.c_dbcnt) {
		c.c_id = i;
		if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
			ret = -1;
			(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
			break;
		}
		name = splicename(&c.c_devname);
		if (strcmp(name, del_name) != 0) {
			Free(name);
			i++;
			continue;
		}
		Free(name);
		/* Found a match - delete mddb */
		if (metaioctl(MD_DB_DELDEV, &c, &c.c_mde, NULL) != 0) {
			ret = -1;
			(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
			break;
		}
		/* Not incrementing "i" intentionally (dbcnt is changed) */
	}
	if ((np = metaname(&sp, del_name, LOGICAL_DEVICE, &ep)) != NULL) {
		meta_invalidate_name(np);
	} else {
		ret = -1;
		(void) mdstealerror(&(resp->mmr_ep), &ep);
	}
	Free(del_name);

	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_META_DB_NEWSIDE which is used to update the
 * side information for each diskset mddb when a new host has been
 * added to the diskset.  The side information is the /dev/dsk/ctds name
 * that the new node would use to access each mddb.
 *
 * Since this routine makes no changes to the records in the diskset mddb,
 * this routine only needs to be run on the master node.  The master node's
 * kernel code will detect that portions of the mddb have changed and
 * will send a parse message to all nodes to re-parse parts of the mddb.
 *
 * Used when running:
 * 	metaset -s set_name -a -h new_hostname
 */
/*ARGSUSED*/
void
mdmn_do_meta_db_newside(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_db_newside_t	*d;
	struct mddb_config		c;
	int				ret = 0;
	mdsetname_t			*sp;
	md_error_t			ep = mdnullerror;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_db_newside_t *)((void *)(msg->msg_event_data));

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = msg->msg_setno;
	c.c_locator.l_dev = meta_cmpldev(d->msg_l_dev);
	c.c_locator.l_blkno = d->msg_blkno;
	(void) strncpy(c.c_locator.l_driver, d->msg_dname,
	    sizeof (c.c_locator.l_driver));
	c.c_devname = d->msg_splitname;
	c.c_locator.l_mnum = d->msg_mnum;
	c.c_multi_node = 1;
	if ((sp = metasetnosetname(c.c_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}
	(void) strcpy(c.c_setname, sp->setname);
	c.c_sideno = d->msg_sideno;

	if ((ret = metaioctl(MD_DB_NEWSIDE, &c, &c.c_mde, NULL)) != 0) {
		(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
	}
	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_META_DB_DELSIDE which is used to remove the
 * side information for each diskset mddb when a host has been
 * deleted from the diskset.  The side information is the /dev/dsk/ctds name
 * that the node would use to access each mddb.
 *
 * Since this routine makes no changes to the records in the diskset mddb,
 * this routine only needs to be run on the master node.  The master node's
 * kernel code will detect that portions of the mddb have changed and
 * will send a parse message to all nodes to re-parse parts of the mddb.
 *
 * Used when running:
 * 	metaset -s set_name -d -h hostname
 */
/*ARGSUSED*/
void
mdmn_do_meta_db_delside(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_db_delside_t	*d;
	mddb_config_t			c;
	int				ret = 0;
	mdsetname_t			*sp;
	md_error_t			ep = mdnullerror;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_db_delside_t *)((void *)(msg->msg_event_data));

	(void) memset(&c, 0, sizeof (c));
	c.c_setno = msg->msg_setno;
	c.c_locator.l_dev = meta_cmpldev(d->msg_l_dev);
	c.c_locator.l_blkno = d->msg_blkno;
	c.c_multi_node = 1;
	if ((sp = metasetnosetname(c.c_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}
	(void) strcpy(c.c_setname, sp->setname);
	c.c_sideno = d->msg_sideno;

	if ((ret = metaioctl(MD_DB_DELSIDE, &c, &c.c_mde, NULL)) != 0) {
		(void) mdstealerror(&(resp->mmr_ep), &c.c_mde);
	}
	resp->mmr_exitval = ret;
}

/*
 * Handler for MD_MN_MSG_META_MD_ADDSIDE which is used to add the
 * side information for each diskset metadevice component (if that
 * component is a disk) when a host has been added to the diskset.
 * The side information is the /dev/dsk/ctds name that the node would
 * use to access the metadevice component.
 *
 * This routine makes changes to the mddb records and must be run
 * on all nodes.
 *
 * Used when running:
 * 	metaset -s set_name -a -h new_hostname
 */
/*ARGSUSED*/
void
mdmn_do_meta_md_addside(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_md_addside_t	*d;
	mdnm_params_t			nm;
	mdsetname_t			*sp;
	char				*cname, *dname;
	minor_t				mnum;
	int				done, i;
	md_error_t			ep = mdnullerror;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_md_addside_t *)((void *)(msg->msg_event_data));

	(void) memset(&nm, 0, sizeof (nm));
	if ((sp = metasetnosetname(msg->msg_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}
	/* While loop continues until IOCNXTKEY_NM gives nm.key of KEYWILD */
	/*CONSTCOND*/
	while (1) {
		char	*drvnm = NULL;

		nm.mde = mdnullerror;
		nm.setno = msg->msg_setno;
		nm.side = d->msg_otherside;
		if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0) {
			(void) mdstealerror(&(resp->mmr_ep), &nm.mde);
			resp->mmr_exitval = -1;
			return;
		}

		/* Normal exit path is to eventually get a KEYWILD */
		if (nm.key == MD_KEYWILD) {
			resp->mmr_exitval = 0;
			return;
		}

		/*
		 * Okay we have a valid key
		 * Let's see if it is hsp or not
		 */
		nm.devname = (uintptr_t)meta_getnmentbykey(msg->msg_setno,
		    d->msg_otherside, nm.key, &drvnm, NULL, NULL, &ep);
		if (nm.devname == NULL || drvnm == NULL) {
			if (nm.devname)
				Free((void *)(uintptr_t)nm.devname);
			if (drvnm)
				Free((void *)(uintptr_t)drvnm);
			(void) mdstealerror(&(resp->mmr_ep), &ep);
			resp->mmr_exitval = -1;
			return;
		}

		/*
		 * If it is hsp add here
		 */
		if (strcmp(drvnm, MD_HOTSPARES) == 0) {
			if (add_name(sp, d->msg_sideno, nm.key, MD_HOTSPARES,
			    minor(NODEV), (char *)(uintptr_t)nm.devname,
			    NULL, NULL, &ep) == -1) {
				Free((void *)(uintptr_t)nm.devname);
				Free((void *)(uintptr_t)drvnm);
				(void) mdstealerror(&(resp->mmr_ep), &ep);
				resp->mmr_exitval = -1;
				return;
			} else {
				Free((void *)(uintptr_t)nm.devname);
				Free((void *)(uintptr_t)drvnm);
				continue;
			}
		}

		nm.side = d->msg_sideno;
		if ((done = meta_getside_devinfo(sp,
		    (char *)(uintptr_t)nm.devname,
		    d->msg_sideno, &cname, &dname, &mnum, &ep)) == -1) {
			(void) mdstealerror(&(resp->mmr_ep), &ep);
			Free((void *)(uintptr_t)nm.devname);
			resp->mmr_exitval = -1;
			return;
		}

		Free((void *)(uintptr_t)nm.devname);
		Free((void *)(uintptr_t)drvnm);

		if (done != 1) {
			Free(cname);
			Free(dname);
			resp->mmr_exitval = -1;
			return;
		}

		/*
		 * The device reference count can be greater than 1 if
		 * more than one softpart is configured on top of the
		 * same device.  If this is the case then we want to
		 * increment the count to sync up with the other sides.
		 */
		for (i = 0; i < nm.ref_count; i++) {
			if (add_name(sp, d->msg_sideno, nm.key, dname, mnum,
			    cname, NULL, NULL, &ep) == -1) {
				(void) mdstealerror(&(resp->mmr_ep), &ep);
				Free(cname);
				Free(dname);
				resp->mmr_exitval = -1;
				return;
			}
		}
		Free(cname);
		Free(dname);
	}

	/*NOTREACHED*/
}
/*
 * Handler for MD_MN_MSG_META_MD_DELSIDE which is used to delete the
 * side information for each diskset metadevice component (if that
 * component is a disk) when a host has been removed from the diskset.
 * The side information is the /dev/dsk/ctds name that the node would
 * use to access the metadevice component.
 *
 * This routine makes changes to the mddb records and must be run
 * on all nodes.
 *
 * Used when running:
 * 	metaset -s set_name -d -h hostname
 */
/*ARGSUSED*/
void
mdmn_do_meta_md_delside(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_meta_md_delside_t	*d;
	mdnm_params_t			nm;
	mdsetname_t			*sp;
	md_error_t			ep = mdnullerror;
	int				i;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_meta_md_delside_t *)((void *)(msg->msg_event_data));

	if ((sp = metasetnosetname(msg->msg_setno, &ep)) == NULL) {
		(void) mdstealerror(&(resp->mmr_ep), &ep);
		resp->mmr_exitval = -1;
		return;
	}

	(void) memset(&nm, 0, sizeof (nm));
	nm.key = MD_KEYWILD;
	/*CONSTCOND*/
	while (1) {
		nm.mde = mdnullerror;
		nm.setno = msg->msg_setno;
		nm.side = MD_SIDEWILD;
		if (metaioctl(MD_IOCNXTKEY_NM, &nm, &nm.mde, NULL) != 0) {
			(void) mdstealerror(&(resp->mmr_ep), &nm.mde);
			resp->mmr_exitval = -1;
			return;
		}

		/* Normal exit path is to eventually get a KEYWILD */
		if (nm.key == MD_KEYWILD) {
			resp->mmr_exitval = 0;
			return;
		}

		/*
		 * The device reference count can be greater than 1 if
		 * more than one softpart is configured on top of the
		 * same device.  If this is the case then we want to
		 * decrement the count to zero so the entry can be
		 * actually removed.
		 */
		for (i = 0; i < nm.ref_count; i++) {
			if (del_name(sp, d->msg_sideno, nm.key, &ep) == -1) {
				(void) mdstealerror(&(resp->mmr_ep), &ep);
				resp->mmr_exitval = -1;
				return;
			}
		}
	}

	/*NOTREACHED*/
}

/*
 * Handler for MD_MN_MSG_MDDB_OPTRECERR which is used to notify
 * the master node that a node has seen an error when attempting to
 * write to the optimized resync records that reside on 2 of the diskset
 * mddbs.  Master node will mark the failed replica in error and this
 * will send a parse message to all nodes to re-read parts of the mddb
 * and to fix their optimized resync records based on this information.
 */
/*ARGSUSED*/
void
mdmn_do_mddb_optrecerr(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_mddb_optrecerr_t	*d;
	mddb_optrec_parm_t		mop;
	int				ret;
	int				i;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_mddb_optrecerr_t *)((void *)(msg->msg_event_data));

	(void) memset(&mop, 0, sizeof (mop));
	mop.c_setno = msg->msg_setno;
	for (i = 0; i < 2; i++) {
		mop.c_recerr[i] = d->msg_recerr[i];
	}
	ret = metaioctl(MD_MN_MDDB_OPTRECFIX, &mop, &mop.c_mde, NULL);
	if (ret)
		(void) mdstealerror(&(resp->mmr_ep), &mop.c_mde);

	resp->mmr_exitval = ret;
}

int
mdmn_smgen_test6(md_mn_msg_t *msg, md_mn_msg_t **msglist)
{
	md_mn_msg_t	*nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_TEST2;
	nmsg->msg_event_size	= sizeof ("test2");
	nmsg->msg_event_data	= Strdup("test2");
	msglist[0] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_TEST2;
	nmsg->msg_event_size	= sizeof ("test2");
	nmsg->msg_event_data	= Strdup("test2");
	msglist[1] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_TEST3;
	nmsg->msg_event_size	= sizeof ("test3");
	nmsg->msg_event_data	= Strdup("test3");
	msglist[2] = nmsg;

	nmsg = Zalloc(sizeof (md_mn_msg_t));
	MSGID_COPY(&(msg->msg_msgid), &(nmsg->msg_msgid));

	nmsg->msg_flags		= MD_MSGF_NO_LOG; /* Don't log submessages */
	nmsg->msg_setno		= msg->msg_setno;
	nmsg->msg_type		= MD_MN_MSG_TEST4;
	nmsg->msg_event_size	= sizeof ("test4");
	nmsg->msg_event_data	= Strdup("test4");
	msglist[3] = nmsg;

	return (4); /* Return the number of submessages generated */
}

/*
 * This is to send an MD_IOCSET ioctl to all nodes to create a soft
 * partition.
 */
/*ARGSUSED*/
void
mdmn_do_iocset(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_iocset_t	*d;
	int			ret;
	set_t			setno;
	mdsetname_t		*sp;
	mdname_t		*np;
	md_error_t		mde = mdnullerror;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_iocset_t *)(void *)msg->msg_event_data;

	setno = MD_MIN2SET(d->iocset_params.mnum);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_IOCSET: Invalid setno %d\n"), setno);
		resp->mmr_exitval = 1;
		return;
	}

	/*
	 * Device should be in the namespace already
	 */
	if ((np = metamnumname(&sp, d->iocset_params.mnum, 1, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_IOCSET: Invalid mnum %d\n"),
		    d->iocset_params.mnum);
		resp->mmr_exitval = 1;
		return;
	}

	/*
	 * Create unit structure
	 */
	d->iocset_params.mdp = (uintptr_t)&d->unit; /* set pointer to unit */
	ret = metaioctl(MD_IOCSET, &(d->iocset_params), &mde, np->cname);
	resp->mmr_exitval = ret;
}

/*
 * This is to update the status of a softpart
 */
/*ARGSUSED*/
void
mdmn_do_sp_setstat(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_sp_setstat_t	*d;
	int			ret;
	set_t			setno;
	mdsetname_t		*sp;
	minor_t			mnum;
	md_error_t		mde = mdnullerror;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_sp_setstat_t *)(void *)msg->msg_event_data;

	mnum = d->sp_setstat_mnum;
	setno = MD_MIN2SET(mnum);
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_IOCSET: Invalid setno %d\n"), setno);
		resp->mmr_exitval = 1;
		return;
	}

	ret = meta_sp_setstatus(sp, &mnum, 1, d->sp_setstat_status, &mde);
	resp->mmr_exitval = ret;
}

/*
 * This is to add a key to the namespace
 */
/*ARGSUSED*/
void
mdmn_do_addkeyname(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_addkeyname_t	*d;
	int			ret;
	set_t			setno;
	mdsetname_t		*sp;
	md_error_t		mde = mdnullerror;
	mdname_t		*compnp;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_addkeyname_t *)(void *)msg->msg_event_data;

	setno = d->addkeyname_setno;
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_ADDKEYNAME: Invalid setno %d\n"), setno);
		resp->mmr_exitval = -1;
		return;
	}

	compnp = metaname(&sp, d->addkeyname_name, UNKNOWN, &mde);
	if (compnp != NULL) {
		ret = add_key_name(sp, compnp, NULL, &mde);
		if (ret < 0)
			resp->mmr_exitval = -1;
		else
			resp->mmr_exitval = compnp->key;
	} else {
		resp->mmr_exitval = -1;
	}
}

/*
 * This is to delete a key from the namespace
 */
/*ARGSUSED*/
void
mdmn_do_delkeyname(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_delkeyname_t	*d;
	int			ret;
	set_t			setno;
	mdsetname_t		*sp;
	md_error_t		mde = mdnullerror;
	mdname_t		*compnp;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_delkeyname_t *)(void *)msg->msg_event_data;

	setno = d->delkeyname_setno;
	if ((sp = metasetnosetname(setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_DELKEYNAME: Invalid setno %d\n"), setno);
		resp->mmr_exitval = -1;
		return;
	}

	compnp = metadevname(&sp, d->delkeyname_dev, &mde);
	if (compnp != NULL) {
		/*
		 * Reset the key value for the name. This is required because
		 * any previous call of del_key_name for the same component
		 * will have resulted in the key value being reset to MD_KEYBAD
		 * even though there may still be references to this component.
		 */
		compnp->key = d->delkeyname_key;
		ret = del_key_name(sp, compnp, &mde);
		resp->mmr_exitval = ret;
	} else {
		resp->mmr_exitval = -1;
	}
}

/*
 * This is to get the value of tstate from the master node. We use this
 * to get the ABR state of a metadevice from the master.
 */
/*ARGSUSED*/
void
mdmn_do_get_tstate(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_gettstate_t	*d;
	int			ret;
	uint_t			tstate;
	md_error_t		mde = mdnullerror;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_gettstate_t *)(void *)msg->msg_event_data;

	ret = meta_get_tstate(d->gettstate_dev, &tstate, &mde);
	if (ret != 0) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_GET_TSTATE: Invalid dev %llx\n"), d->gettstate_dev);
		tstate = 0;
	}
	resp->mmr_exitval = tstate;
}

/*
 * This is to get the mirror ABR state and the state of its submirrors from
 * the master node. We need this to ensure consistent output from metastat
 * when a new node joins the cluster during a resync. Without this the
 * submirror status will be incorrect until the whole resync is complete which
 * may take days for very large metadevices.
 */
/*ARGSUSED*/
void
mdmn_do_get_mirstate(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_mir_state_t		*d;
	md_mn_msg_mir_state_res_t	*res;		/* Results */
	set_t				setno;
	mdsetname_t			*sp;		/* Set name */
	mdname_t			*mirnp;		/* Mirror name */
	md_error_t			mde = mdnullerror;
	mm_unit_t			*mm;		/* Mirror */
	int				smi;
	uint_t				tstate;

	resp->mmr_comm_state = MDMNE_ACK;
	resp->mmr_out_size = sizeof (md_mn_msg_mir_state_res_t);
	resp->mmr_err_size = 0;
	resp->mmr_out = Malloc(resp->mmr_out_size);
	resp->mmr_err = NULL;
	d = (md_mn_msg_mir_state_t *)(void *)msg->msg_event_data;
	res = (md_mn_msg_mir_state_res_t *)(void *)resp->mmr_out;

	/* Validate set information from minor number */
	setno = MD_MIN2SET(d->mir_state_mnum);
	sp = metasetnosetname(setno, &mde);
	if (sp == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_GET_MIRROR_STATE: Invalid set %d\n"), setno);
		resp->mmr_exitval = 1;	/* Failure */
		Free(resp->mmr_out);
		resp->mmr_out_size = 0;
		return;
	}

	/* Construct mirror name from minor number */
	mirnp = metamnumname(&sp, d->mir_state_mnum, 0, &mde);
	if (mirnp == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_GET_MIRROR_STATE: Invalid minor %lx\n"),
		    d->mir_state_mnum);
		resp->mmr_exitval = 2;	/* Failure */
		Free(resp->mmr_out);
		resp->mmr_out_size = 0;
		return;
	}

	/* Get common mirror structure */
	mm = (mm_unit_t *)meta_get_mdunit(sp, mirnp, &mde);
	if (mm == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_GET_MIRROR_STATE: Invalid mirror minor %x\n"),
		    d->mir_state_mnum);
		resp->mmr_exitval = 3;	/* Failure */
		Free(resp->mmr_out);
		resp->mmr_out_size = 0;
		return;
	}

	if (meta_get_tstate(d->mir_state_mnum, &tstate, &mde) != 0) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_GET_MIRROR_STATE: Invalid minor %lx\n"),
		    d->mir_state_mnum);
		resp->mmr_exitval = 4;	/* Failure */
		Free(resp->mmr_out);
		resp->mmr_out_size = 0;
		return;
	}
	/*
	 * Fill in the sm_state/sm_flags value in the results structure which
	 * gets passed back to the message originator
	 */
	resp->mmr_exitval = 0;
	for (smi = 0; (smi < NMIRROR); smi++) {
		mm_submirror_t *mmsp = &mm->un_sm[smi];
		res->sm_state[smi] = mmsp->sm_state;
		res->sm_flags[smi] = mmsp->sm_flags;
	}
	/* Returm value of tstate for mirror */
	res->mir_tstate = tstate;
}

/*
 * This is to issue an ioctl to call poke_hotspares
 */
/*ARGSUSED*/
void
mdmn_do_poke_hotspares(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{

	md_mn_poke_hotspares_t	pokehsp;
	md_mn_msg_pokehsp_t	*d;

	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	resp->mmr_comm_state = MDMNE_ACK;
	d = (md_mn_msg_pokehsp_t *)(void *)msg->msg_event_data;

	(void) memset(&pokehsp, 0, sizeof (pokehsp));
	MD_SETDRIVERNAME(&pokehsp, MD_MIRROR, d->pokehsp_setno);

	resp->mmr_exitval = metaioctl(MD_MN_POKE_HOTSPARES, &pokehsp,
	    &pokehsp.mde, NULL);
}

/*
 * Called to create a softpart during a metarecover operation
 */
/*ARGSUSED*/
void
mdmn_do_addmdname(md_mn_msg_t *msg, uint_t flags, md_mn_result_t *resp)
{
	md_mn_msg_addmdname_t	*d;
	md_error_t		mde = mdnullerror;
	mdsetname_t		*sp;
	int			init = 0;
	mdkey_t			key;
	minor_t			mnum;

	resp->mmr_comm_state = MDMNE_ACK; /* Ok state */;
	resp->mmr_out_size = 0;
	resp->mmr_err_size = 0;
	resp->mmr_out = NULL;
	resp->mmr_err = NULL;
	d = (md_mn_msg_addmdname_t *)(void *)msg->msg_event_data;

	if ((sp = metasetnosetname(d->addmdname_setno, &mde)) == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
		    "MD_MN_MSG_ADDMDNAME: Invalid setno %d\n"),
		    d->addmdname_setno);
		resp->mmr_exitval = 1;
		return;
	}

	/*
	 * If device node does not exist then init it
	 */
	if (!is_existing_meta_hsp(sp, d->addmdname_name)) {
		if ((key = meta_init_make_device(&sp, d->addmdname_name,
		    &mde)) <= 0) {
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			    "MD_MN_MSG_ADDMDNAME: Invalid name %s\n"),
			    d->addmdname_name);
			resp->mmr_exitval = 1;
			return;
		}

		init = 1;
	}

	/*
	 * We should have it
	 */
	if (metaname(&sp, d->addmdname_name, META_DEVICE, &mde) == NULL) {

		if (init) {
			if (meta_getnmentbykey(sp->setno, MD_SIDEWILD,
			    key, NULL, &mnum, NULL, &mde) != NULL) {
				(void) metaioctl(
				    MD_IOCREM_DEV, &mnum, &mde, NULL);
			}
		(void) del_self_name(sp, key, &mde);
		}

		resp->mmr_exitval = 1;
		return;
	}

	resp->mmr_exitval = 0;
}
