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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The core of ilbd daemon is a single-threaded event loop using
 * event completion framework; it receives requests from client using
 * the libilb functions, handles timeouts, initiates health checks, and
 * populates the kernel state.
 *
 * The daemon has the following privileges (in addition to the basic ones):
 *
 * 	PRIV_PROC_OWNER, PRIV_NET_ICMPACCESS,
 *	PRIV_SYS_IP_CONFIG, PRIV_PROC_AUDIT
 *
 * The aforementioned  privileges will be specified in the SMF manifest.
 *
 * AF_UNIX socket is used for IPC between libilb and this daemon as
 * both processes will run on the same machine.
 *
 * To do health check, the daemon will create a timer for every health
 * check probe. Each of these timers will be  associated with the
 * event port. When a timer goes off, the daemon will initiate a
 * pipe to a separate process to execute the specific health check
 * probe. This new process will run with the same user-id as that of
 * ilbd daemon and will inherit all the privileges from the ilbd
 * daemon parent process except the following:
 *
 * PRIV_PROC_OWNER, PRIV_PROC_AUDIT
 *
 * All health checks, will be implemented as external methods
 * (binary or script). The following arguments will be passed
 * to external methods:
 *
 *	$1	VIP (literal IPv4 or IPv6 address)
 *	$2	Server IP (literal IPv4 or IPv6 address)
 *	$3	Protocol (UDP, TCP as a string)
 *	$4	The load balance mode, "DSR", "NAT", "HALF_NAT"
 *	$5	Numeric port range
 *	$6	maximum time (in seconds) the method
 * should wait before returning failure. If the method runs for
 * longer, it may be killed, and the test considered failed.
 *
 * Upon success, a health check method should print the RTT to the
 * it finds to its STDOUT for ilbd to consume.  The implicit unit
 * is microseconds but only the number needs to be printed.  If it
 * cannot find the RTT, it should print 0.  If the method decides
 * that the server is dead, it should print -1 to its STDOUT.
 *
 * By default, an user-supplied health check probe process will
 * also run with the same set of privileges as ILB's built-in
 * probes.  If the administrator has an user-supplied health check
 * program that requires a larger privilege set, he/she will have
 * to implement setuid program.
 *
 * Each health check will have a timeout, such that if the health
 * check process is hung, it will be killed after the timeout interval
 * and the daemon will notify the kernel ILB engine of the server's
 * unresponsiveness, so that load distribution can be appropriately
 * adjusted.  If on the other hand the health check is successful
 * the timeout timer is cancelled.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <port.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/note.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <ucred.h>
#include <priv_utils.h>
#include <net/if.h>
#include <libilb.h>
#include <assert.h>
#include <inet/ilb.h>
#include <libintl.h>
#include <fcntl.h>
#include <rpcsvc/daemon_utils.h>
#include "libilb_impl.h"
#include "ilbd.h"

/*
 * NOTE: The following needs to be kept up to date.
 */
#define	ILBD_VERSION	"1.0"
#define	ILBD_COPYRIGHT	\
	"Copyright (c) 2005, 2010, Oracle and/or its affiliates. " \
	"All rights reserved.\n"

/*
 * Global reply buffer to client request.  Note that ilbd is single threaded,
 * so a global buffer is OK.  If ilbd becomes multi-threaded, this needs to
 * be changed.
 */
static uint32_t reply_buf[ILBD_MSG_SIZE / sizeof (uint32_t)];

static void
ilbd_free_cli(ilbd_client_t *cli)
{
	(void) close(cli->cli_sd);
	if (cli->cli_cmd == ILBD_SHOW_NAT)
		ilbd_show_nat_cleanup();
	if (cli->cli_cmd == ILBD_SHOW_PERSIST)
		ilbd_show_sticky_cleanup();
	if (cli->cli_saved_reply != NULL)
		free(cli->cli_saved_reply);
	if (cli->cli_peer_ucredp != NULL)
		ucred_free(cli->cli_peer_ucredp);
	free(cli->cli_pw_buf);
	free(cli);
}

static void
ilbd_reset_kernel_state(void)
{
	ilb_status_t	rc;
	ilb_name_cmd_t	kcmd;

	kcmd.cmd = ILB_DESTROY_RULE;
	kcmd.flags = ILB_RULE_ALLRULES;
	kcmd.name[0] = '\0';

	rc = do_ioctl(&kcmd, 0);
	if (rc != ILB_STATUS_OK)
		logdebug("ilbd_reset_kernel_state: do_ioctl failed: %s",
		    strerror(errno));
}

/* Signal handler to do clean up. */
/* ARGSUSED */
static void
ilbd_cleanup(int sig)
{
	(void) remove(SOCKET_PATH);
	ilbd_reset_kernel_state();
	exit(0);
}

/*
 * Create a socket and return it to caller.  If there is a failure, this
 * function calls exit(2).  Hence it always returns a valid listener socket.
 *
 * Note that this function is called before ilbd becomes a daemon.  So
 * we call perror(3C) to print out error message directly so that SMF can
 * catch them.
 */
static int
ilbd_create_client_socket(void)
{
	int			s;
	mode_t			omask;
	struct sockaddr_un	sa;
	int			sobufsz;

	s = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (s == -1) {
		perror("ilbd_create_client_socket: socket to"
		    " client failed");
		exit(errno);
	}
	if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
		perror("ilbd_create_client_socket: fcntl(FD_CLOEXEC)");
		exit(errno);
	}

	sobufsz = ILBD_MSG_SIZE;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sobufsz,
	    sizeof (sobufsz)) != 0) {
		perror("ilbd_creat_client_socket: setsockopt(SO_SNDBUF) "
		    "failed");
		exit(errno);
	}
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sobufsz,
	    sizeof (sobufsz)) != 0) {
		perror("ilbd_creat_client_socket: setsockopt(SO_RCVBUF) "
		    "failed");
		exit(errno);
	}

	/*
	 * since everybody can talk to us, we need to open up permissions
	 * we check peer privileges on a per-operation basis.
	 * This is no security issue as long as we're single-threaded.
	 */
	omask = umask(0);

	/* just in case we didn't clean up properly after last exit */
	(void) remove(SOCKET_PATH);

	bzero(&sa, sizeof (sa));
	sa.sun_family = AF_UNIX;
	(void) strlcpy(sa.sun_path, SOCKET_PATH, sizeof (sa.sun_path));

	if (bind(s, (struct sockaddr *)&sa, sizeof (sa)) != 0) {
		perror("ilbd_create_client_socket(): bind to client"
		    " socket failed");
		exit(errno);
	}

	/* re-instate old umask */
	(void) umask(omask);

#define	QLEN	16

	if (listen(s, QLEN) != 0) {
		perror("ilbd_create_client_socket: listen to client"
		    " socket failed");
		exit(errno);
	}

	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGSTOP, SIG_IGN);
	(void) signal(SIGTSTP, SIG_IGN);
	(void) signal(SIGTTIN, SIG_IGN);
	(void) signal(SIGTTOU, SIG_IGN);

	(void) signal(SIGINT, ilbd_cleanup);
	(void) signal(SIGTERM, ilbd_cleanup);
	(void) signal(SIGQUIT, ilbd_cleanup);

	return (s);
}

/*
 * Return the minimum size of a given request.  The returned size does not
 * include the variable part of a request.
 */
static size_t
ilbd_cmd_size(const ilb_comm_t *ic)
{
	size_t cmd_sz;

	cmd_sz = sizeof (*ic);
	switch (ic->ic_cmd) {
	case ILBD_RETRIEVE_SG_NAMES:
	case ILBD_RETRIEVE_RULE_NAMES:
	case ILBD_RETRIEVE_HC_NAMES:
	case ILBD_CMD_OK:
		break;
	case ILBD_CMD_ERROR:
		cmd_sz += sizeof (ilb_status_t);
		break;
	case ILBD_RETRIEVE_SG_HOSTS:
	case ILBD_CREATE_SERVERGROUP:
	case ILBD_DESTROY_SERVERGROUP:
	case ILBD_DESTROY_RULE:
	case ILBD_ENABLE_RULE:
	case ILBD_DISABLE_RULE:
	case ILBD_RETRIEVE_RULE:
	case ILBD_DESTROY_HC:
	case ILBD_GET_HC_INFO:
	case ILBD_GET_HC_SRVS:
		cmd_sz += sizeof (ilbd_name_t);
		break;
	case ILBD_ENABLE_SERVER:
	case ILBD_DISABLE_SERVER:
	case ILBD_ADD_SERVER_TO_GROUP:
	case ILBD_REM_SERVER_FROM_GROUP:
		cmd_sz += sizeof (ilb_sg_info_t);
		break;
	case ILBD_SRV_ADDR2ID:
	case ILBD_SRV_ID2ADDR:
		cmd_sz += sizeof (ilb_sg_info_t) + sizeof (ilb_sg_srv_t);
		break;
	case ILBD_CREATE_RULE:
		cmd_sz += sizeof (ilb_rule_info_t);
		break;
	case ILBD_CREATE_HC:
		cmd_sz += sizeof (ilb_hc_info_t);
		break;
	case ILBD_SHOW_NAT:
	case ILBD_SHOW_PERSIST:
		cmd_sz += sizeof (ilb_show_info_t);
		break;
	}

	return (cmd_sz);
}

/*
 * Given a request and its size, check that the size is big enough to
 * contain the variable part of a request.
 */
static ilb_status_t
ilbd_check_req_size(ilb_comm_t *ic, size_t ic_sz)
{
	ilb_status_t rc = ILB_STATUS_OK;
	ilb_sg_info_t *sg_info;
	ilbd_namelist_t *nlist;

	switch (ic->ic_cmd) {
	case ILBD_CREATE_SERVERGROUP:
	case ILBD_ENABLE_SERVER:
	case ILBD_DISABLE_SERVER:
	case ILBD_ADD_SERVER_TO_GROUP:
	case ILBD_REM_SERVER_FROM_GROUP:
		sg_info = (ilb_sg_info_t *)&ic->ic_data;

		if (ic_sz < ilbd_cmd_size(ic) + sg_info->sg_srvcount *
		    sizeof (ilb_sg_srv_t)) {
			rc = ILB_STATUS_EINVAL;
		}
		break;
	case ILBD_ENABLE_RULE:
	case ILBD_DISABLE_RULE:
	case ILBD_DESTROY_RULE:
		nlist = (ilbd_namelist_t *)&ic->ic_data;

		if (ic_sz < ilbd_cmd_size(ic) + nlist->ilbl_count *
		    sizeof (ilbd_name_t)) {
			rc = ILB_STATUS_EINVAL;
		}
		break;
	}
	return (rc);
}

/*
 * this function *relies* on a complete message/data struct
 * being passed in (currently via the SOCK_SEQPACKET socket type).
 *
 * Note that the size of ip is at most ILBD_MSG_SIZE.
 */
static ilb_status_t
consume_common_struct(ilb_comm_t *ic, size_t ic_sz, ilbd_client_t *cli,
    int ev_port)
{
	ilb_status_t	rc;
	struct passwd	*ps;
	size_t		rbufsz;
	ssize_t		ret;
	boolean_t	standard_reply = B_TRUE;
	ilbd_name_t	name;

	/*
	 * cli_ev must be overridden during handling of individual commands,
	 * if there's a special need; otherwise, leave this for
	 * the "default" case
	 */
	cli->cli_ev = ILBD_EVENT_REQ;

	ps = &cli->cli_pw;
	rbufsz = ILBD_MSG_SIZE;

	/* Sanity check on the size of the static part of a request. */
	if (ic_sz < ilbd_cmd_size(ic)) {
		rc = ILB_STATUS_EINVAL;
		goto out;
	}

	switch (ic->ic_cmd) {
	case ILBD_CREATE_SERVERGROUP: {
		ilb_sg_info_t sg_info;

		/*
		 * ilbd_create_sg() only needs the sg_name field.  But it
		 * takes in a ilb_sg_info_t because it is used as a callback
		 * in ilbd_walk_sg_pgs().
		 */
		(void) strlcpy(sg_info.sg_name, (char *)&(ic->ic_data),
		    sizeof (sg_info.sg_name));
		rc = ilbd_create_sg(&sg_info, ev_port, ps,
		    cli->cli_peer_ucredp);
		break;
	}

	case ILBD_DESTROY_SERVERGROUP:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_destroy_sg(name, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_ADD_SERVER_TO_GROUP:
		if ((rc = ilbd_check_req_size(ic, ic_sz)) != ILB_STATUS_OK)
			break;
		rc = ilbd_add_server_to_group((ilb_sg_info_t *)&ic->ic_data,
		    ev_port, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_REM_SERVER_FROM_GROUP:
		if ((rc = ilbd_check_req_size(ic, ic_sz)) != ILB_STATUS_OK)
			break;
		rc = ilbd_rem_server_from_group((ilb_sg_info_t *)&ic->ic_data,
		    ev_port, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_ENABLE_SERVER:
		if ((rc = ilbd_check_req_size(ic, ic_sz)) != ILB_STATUS_OK)
			break;
		rc = ilbd_enable_server((ilb_sg_info_t *)&ic->ic_data, ps,
		    cli->cli_peer_ucredp);
		break;

	case ILBD_DISABLE_SERVER:
		if ((rc = ilbd_check_req_size(ic, ic_sz)) != ILB_STATUS_OK)
			break;
		rc = ilbd_disable_server((ilb_sg_info_t *)&ic->ic_data, ps,
		    cli->cli_peer_ucredp);
		break;

	case ILBD_SRV_ADDR2ID:
		rc = ilbd_address_to_srvID((ilb_sg_info_t *)&ic->ic_data,
		    reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_SRV_ID2ADDR:
		rc = ilbd_srvID_to_address((ilb_sg_info_t *)&ic->ic_data,
		    reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_RETRIEVE_SG_HOSTS:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_retrieve_sg_hosts(name, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_RETRIEVE_SG_NAMES:
	case ILBD_RETRIEVE_RULE_NAMES:
	case ILBD_RETRIEVE_HC_NAMES:
		rc = ilbd_retrieve_names(ic->ic_cmd, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_CREATE_RULE:
		rc = ilbd_create_rule((ilb_rule_info_t *)&ic->ic_data, ev_port,
		    ps, cli->cli_peer_ucredp);
		break;

	case ILBD_DESTROY_RULE:
		/* Copy the name to ensure that name is NULL terminated. */
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_destroy_rule(name, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_ENABLE_RULE:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_enable_rule(name, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_DISABLE_RULE:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_disable_rule(name, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_RETRIEVE_RULE:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_retrieve_rule(name, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_CREATE_HC:
		rc = ilbd_create_hc((ilb_hc_info_t *)&ic->ic_data, ev_port, ps,
		    cli->cli_peer_ucredp);
		break;

	case ILBD_DESTROY_HC:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_destroy_hc(name, ps, cli->cli_peer_ucredp);
		break;

	case ILBD_GET_HC_INFO:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_get_hc_info(name, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_GET_HC_SRVS:
		(void) strlcpy(name, (char *)&(ic->ic_data), sizeof (name));
		rc = ilbd_get_hc_srvs(name, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_SHOW_NAT:
		rc = ilbd_show_nat(cli, ic, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	case ILBD_SHOW_PERSIST:
		rc = ilbd_show_sticky(cli, ic, reply_buf, &rbufsz);
		if (rc == ILB_STATUS_OK)
			standard_reply = B_FALSE;
		break;

	default:
		logdebug("consume_common_struct: unknown command");
		rc = ILB_STATUS_INVAL_CMD;
		break;
	}

out:
	/*
	 * The message exchange is always in pairs, request/response.  If
	 * a transaction requires multiple exchanges, the client will send
	 * in multiple requests to get multiple responses.  The show-nat and
	 * show-persist request are examples of this.  The end of transaction
	 * is marked with ic_flags set to ILB_COMM_END.
	 */

	/* This is the standard reply. */
	if (standard_reply) {
		if (rc == ILB_STATUS_OK)
			ilbd_reply_ok(reply_buf, &rbufsz);
		else
			ilbd_reply_err(reply_buf, &rbufsz, rc);
	}

	if ((ret = send(cli->cli_sd, reply_buf, rbufsz, 0)) != rbufsz) {
		if (ret == -1) {
			if (errno != EWOULDBLOCK) {
				logdebug("consume_common_struct: send: %s",
				    strerror(errno));
				rc = ILB_STATUS_SEND;
				goto err_out;
			}
			/*
			 * The reply is blocked, save the reply.  handle_req()
			 * will associate the event port for the re-send.
			 */
			assert(cli->cli_saved_reply == NULL);
			if ((cli->cli_saved_reply = malloc(rbufsz)) == NULL) {
				/*
				 * Set the error to ILB_STATUS_SEND so that
				 * handle_req() will free the client.
				 */
				logdebug("consume_common_struct: failure to "
				    "allocate memory to save reply");
				rc = ILB_STATUS_SEND;
				goto err_out;
			}
			bcopy(reply_buf, cli->cli_saved_reply, rbufsz);
			cli->cli_saved_size = rbufsz;
			return (ILB_STATUS_EWOULDBLOCK);
		}
	}
err_out:
	return (rc);
}

/*
 * Accept a new client request.  A struct ilbd_client_t is allocated to
 * store the client info.  The accepted socket is port_associate() with
 * the given port.  And the allocated ilbd_client_t struct is passed as
 * the user pointer.
 */
static void
new_req(int ev_port, int listener, void *ev_obj)
{
	struct sockaddr	sa;
	int		sa_len;
	int		new_sd;
	int		sflags;
	ilbd_client_t	*cli = NULL;
	int		res;
	uid_t		uid;

	sa_len = sizeof (sa);
	if ((new_sd = accept(listener, &sa, &sa_len)) == -1) {
		/* don't log if we're out of file descriptors */
		if (errno != EINTR && errno != EMFILE)
			logperror("new_req: accept failed");
		goto done;
	}

	/* Set the new socket to be non-blocking. */
	if ((sflags = fcntl(new_sd, F_GETFL, 0)) == -1) {
		logperror("new_req: fcntl(F_GETFL)");
		goto clean_up;
	}
	if (fcntl(new_sd, F_SETFL, sflags | O_NONBLOCK) == -1) {
		logperror("new_req: fcntl(F_SETFL)");
		goto clean_up;
	}
	if (fcntl(new_sd, F_SETFD, FD_CLOEXEC) == -1) {
		logperror("new_req: fcntl(FD_CLOEXEC)");
		goto clean_up;
	}
	if ((cli = calloc(1, sizeof (ilbd_client_t))) == NULL) {
		logerr("new_req: malloc(ilbd_client_t)");
		goto clean_up;
	}
	res = getpeerucred(new_sd, &cli->cli_peer_ucredp);
	if (res == -1) {
		logperror("new_req: getpeerucred failed");
		goto clean_up;
	}
	if ((uid = ucred_getruid(cli->cli_peer_ucredp)) == (uid_t)-1) {
		logperror("new_req: ucred_getruid failed");
		goto clean_up;
	}
	cli->cli_pw_bufsz = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);
	if ((cli->cli_pw_buf = malloc(cli->cli_pw_bufsz)) == NULL) {
		logerr("new_req: malloc(cli_pw_buf)");
		goto clean_up;
	}
	if (getpwuid_r(uid, &cli->cli_pw, cli->cli_pw_buf,
	    cli->cli_pw_bufsz) == NULL) {
		logperror("new_req: invalid user");
		goto clean_up;
	}
	cli->cli_ev = ILBD_EVENT_REQ;
	cli->cli_sd = new_sd;
	cli->cli_cmd = ILBD_BAD_CMD;
	cli->cli_saved_reply = NULL;
	cli->cli_saved_size = 0;
	if (port_associate(ev_port, PORT_SOURCE_FD, new_sd, POLLRDNORM,
	    cli) == -1) {
		logperror("new_req: port_associate(cli) failed");
clean_up:
		if (cli != NULL) {
			if (cli->cli_peer_ucredp != NULL)
				ucred_free(cli->cli_peer_ucredp);
			free(cli->cli_pw_buf);
			free(cli);
		}
		(void) close(new_sd);
	}

done:
	/* Re-associate the listener with the event port. */
	if (port_associate(ev_port, PORT_SOURCE_FD, listener, POLLRDNORM,
	    ev_obj) == -1) {
		logperror("new_req: port_associate(listener) failed");
		exit(1);
	}
}

static void
handle_req(int ev_port, ilbd_event_t event, ilbd_client_t *cli)
{
	/* All request should be smaller than ILBD_MSG_SIZE */
	union {
		ilb_comm_t	ic;
		uint32_t	buf[ILBD_MSG_SIZE / sizeof (uint32_t)];
	} ic_u;
	int	rc = ILB_STATUS_OK;
	ssize_t	r;

	if (event == ILBD_EVENT_REQ) {
		/*
		 * Something is wrong with the client since there is a
		 * pending reply, the client should not send us another
		 * request.  Kill this client.
		 */
		if (cli->cli_saved_reply != NULL) {
			logerr("handle_req: misbehaving client, more than one "
			    "outstanding request");
			rc = ILB_STATUS_INTERNAL;
			goto err_out;
		}

		/*
		 * Our socket is message based so we should be able
		 * to get the request in one single read.
		 */
		r = recv(cli->cli_sd, (void *)ic_u.buf, sizeof (ic_u.buf), 0);
		if (r < 0) {
			if (errno != EINTR) {
				logperror("handle_req: read failed");
				rc = ILB_STATUS_READ;
				goto err_out;
			}
			/*
			 * If interrupted, just re-associate the cli_sd
			 * with the port.
			 */
			goto done;
		}
		cli->cli_cmd = ic_u.ic.ic_cmd;

		rc = consume_common_struct(&ic_u.ic, r, cli, ev_port);
		if (rc == ILB_STATUS_EWOULDBLOCK)
			goto blocked;
		/* Fatal error communicating with client, free it. */
		if (rc == ILB_STATUS_SEND)
			goto err_out;
	} else {
		assert(event == ILBD_EVENT_REP_OK);
		assert(cli->cli_saved_reply != NULL);

		/*
		 * The reply to client was previously blocked, we will
		 * send again.
		 */
		if (send(cli->cli_sd, cli->cli_saved_reply,
		    cli->cli_saved_size, 0) != cli->cli_saved_size) {
			if (errno != EWOULDBLOCK) {
				logdebug("handle_req: send: %s",
				    strerror(errno));
				rc = ILB_STATUS_SEND;
				goto err_out;
			}
			goto blocked;
		}
		free(cli->cli_saved_reply);
		cli->cli_saved_reply = NULL;
		cli->cli_saved_size = 0;
	}
done:
	/* Re-associate with the event port for more requests. */
	cli->cli_ev = ILBD_EVENT_REQ;
	if (port_associate(ev_port, PORT_SOURCE_FD, cli->cli_sd,
	    POLLRDNORM, cli) == -1) {
		logperror("handle_req: port_associate(POLLRDNORM)");
		rc = ILB_STATUS_INTERNAL;
		goto err_out;
	}
	return;

blocked:
	/* Re-associate with the event port. */
	cli->cli_ev = ILBD_EVENT_REP_OK;
	if (port_associate(ev_port, PORT_SOURCE_FD, cli->cli_sd, POLLWRNORM,
	    cli) == -1) {
		logperror("handle_req: port_associate(POLLWRNORM)");
		rc = ILB_STATUS_INTERNAL;
		goto err_out;
	}
	return;

err_out:
	ilbd_free_cli(cli);
}

static void
i_ilbd_read_config(int ev_port)
{
	logdebug("i_ilbd_read_config: port %d", ev_port);
	(void) ilbd_walk_sg_pgs(ilbd_create_sg, &ev_port, NULL);
	(void) ilbd_walk_hc_pgs(ilbd_create_hc, &ev_port, NULL);
	(void) ilbd_walk_rule_pgs(ilbd_create_rule, &ev_port, NULL);
}

/*
 * main event loop for ilbd
 * asserts that argument 'listener' is a server socket ready to accept() on.
 */
static void
main_loop(int listener)
{
	port_event_t		p_ev;
	int			ev_port, ev_port_obj;
	ilbd_event_obj_t	ev_obj;
	ilbd_timer_event_obj_t	timer_ev_obj;

	ev_port = port_create();
	if (ev_port == -1) {
		logperror("main_loop: port_create failed");
		exit(-1);
	}
	ilbd_hc_timer_init(ev_port, &timer_ev_obj);

	ev_obj.ev = ILBD_EVENT_NEW_REQ;
	if (port_associate(ev_port, PORT_SOURCE_FD, listener, POLLRDNORM,
	    &ev_obj) == -1) {
		logperror("main_loop: port_associate failed");
		exit(1);
	}

	i_ilbd_read_config(ev_port);
	ilbd_hc_timer_update(&timer_ev_obj);

	_NOTE(CONSTCOND)
	while (B_TRUE) {
		int r;
		ilbd_event_t event;
		ilbd_client_t *cli;

		r = port_get(ev_port, &p_ev, NULL);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			logperror("main_loop: port_get failed");
			break;
		}

		ev_port_obj = p_ev.portev_object;
		event = ((ilbd_event_obj_t *)p_ev.portev_user)->ev;

		switch (event) {
		case ILBD_EVENT_TIMER:
			ilbd_hc_timeout();
			break;

		case ILBD_EVENT_PROBE:
			ilbd_hc_probe_return(ev_port, ev_port_obj,
			    p_ev.portev_events,
			    (ilbd_hc_probe_event_t *)p_ev.portev_user);
			break;

		case ILBD_EVENT_NEW_REQ:
			assert(ev_port_obj == listener);
			/*
			 * An error happens in the listener.  Exit
			 * for now....
			 */
			if (p_ev.portev_events & (POLLHUP|POLLERR)) {
				logerr("main_loop: listener error");
				exit(1);
			}
			new_req(ev_port, ev_port_obj, &ev_obj);
			break;

		case ILBD_EVENT_REP_OK:
		case ILBD_EVENT_REQ:
			cli = (ilbd_client_t *)p_ev.portev_user;
			assert(ev_port_obj == cli->cli_sd);

			/*
			 * An error happens in the newly accepted
			 * client request.  Clean up the client.
			 * this also happens when client closes socket,
			 * so not necessarily a reason for alarm
			 */
			if (p_ev.portev_events & (POLLHUP|POLLERR)) {
				ilbd_free_cli(cli);
				break;
			}

			handle_req(ev_port, event, cli);
			break;

		default:
			logerr("main_loop: unknown event %d", event);
			exit(EXIT_FAILURE);
			break;
		}

		ilbd_hc_timer_update(&timer_ev_obj);
	}
}

static void
i_ilbd_setup_lists(void)
{
	i_setup_sg_hlist();
	i_setup_rule_hlist();
	i_ilbd_setup_hc_list();
}

/*
 * Usage message - call only during startup. it will print its
 * message on stderr and exit
 */
static void
Usage(char *name)
{
	(void) fprintf(stderr, gettext("Usage: %s [-d|--debug]\n"), name);
	exit(1);
}

static void
print_version(char *name)
{
	(void) printf("%s %s\n", basename(name), ILBD_VERSION);
	(void) printf(gettext(ILBD_COPYRIGHT));
	exit(0);
}

/*
 * Increase the file descriptor limit for handling a lot of health check
 * processes (each requires a pipe).
 *
 * Note that this function is called before ilbd becomes a daemon.  So
 * we call perror(3C) to print out error message directly so that SMF
 * can catch them.
 */
static void
set_rlim(void)
{
	struct rlimit rlp;

	if (getrlimit(RLIMIT_NOFILE, &rlp) == -1) {
		perror("ilbd: getrlimit");
		exit(errno);
	}
	rlp.rlim_cur = rlp.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlp) == -1) {
		perror("ilbd: setrlimit");
		exit(errno);
	}
}

int
main(int argc, char **argv)
{
	int	s;
	int	c;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	static const char daemon_dir[] = DAEMON_DIR;

	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, ":V?d(debug)")) != -1) {
		switch ((char)c) {
		case '?': Usage(argv[0]);
			/* not reached */
			break;
		case 'V': print_version(argv[0]);
			/* not reached */
			break;
		case 'd': ilbd_enable_debug();
			break;
		default: Usage(argv[0]);
			/* not reached */
			break;
		}
	}

	/*
	 * Whenever the daemon starts, it needs to start with a clean
	 * slate in the kernel. We need sys_ip_config privilege for
	 * this.
	 */
	ilbd_reset_kernel_state();

	/* Increase the limit on the number of file descriptors. */
	set_rlim();

	/*
	 * ilbd daemon starts off as root, just so it can create
	 * /var/run/daemon if one does not exist. After that is done
	 * the daemon switches to "daemon" uid. This is similar to what
	 * rpcbind does.
	 */
	if (mkdir(daemon_dir, DAEMON_DIR_MODE) == 0 || errno == EEXIST) {
		(void) chmod(daemon_dir, DAEMON_DIR_MODE);
		(void) chown(daemon_dir, DAEMON_UID, DAEMON_GID);
	} else {
		perror("main: mkdir failed");
		exit(errno);
	}
	/*
	 * Now lets switch ilbd as uid = daemon, gid = daemon with a
	 * trimmed down privilege set
	 */
	if (__init_daemon_priv(PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS,
	    DAEMON_UID, DAEMON_GID, PRIV_PROC_OWNER, PRIV_PROC_AUDIT,
	    PRIV_NET_ICMPACCESS, PRIV_SYS_IP_CONFIG, NULL) == -1) {
		(void) fprintf(stderr, "Insufficient privileges\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Opens a PF_UNIX socket to the client. No privilege needed
	 * for this.
	 */
	s = ilbd_create_client_socket();

	/*
	 * Daemonify if ilbd is not running with -d option
	 * Need proc_fork privilege for this
	 */
	if (!is_debugging_on()) {
		logdebug("daemonizing...");
		if (daemon(0, 0) != 0) {
			logperror("daemon failed");
			exit(EXIT_FAILURE);
		}
	}
	(void) priv_set(PRIV_OFF, PRIV_INHERITABLE, PRIV_PROC_OWNER,
	    PRIV_PROC_AUDIT, NULL);

	/* if daemonified then set up syslog */
	if (!is_debugging_on())
		openlog("ilbd", LOG_PID, LOG_DAEMON);

	i_ilbd_setup_lists();

	main_loop(s);

	/*
	 * if we come here, then we experienced an error or a shutdown
	 * indicator, so clean up after ourselves.
	 */
	logdebug("main(): terminating");

	(void) remove(SOCKET_PATH);
	ilbd_reset_kernel_state();

	return (0);
}
