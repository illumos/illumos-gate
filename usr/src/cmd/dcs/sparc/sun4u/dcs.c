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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is the main file for the Domain Configuration Server (DCS).
 *
 * The DCS is a server that runs on a domain and communicates with
 * a Domain Configuration Agent (DCA) running on a remote host. The
 * DCA initiates DR requests that the DCS performs by calling the
 * appropriate libcfgadm(3LIB) function.
 *
 * This file contains functions that receive and process the messages
 * received from the DCA. It also handles the initialization of the
 * server and is responsible for starting a concurrent session to
 * handle each DR request.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <signal.h>
#include <netdb.h>
#include <config_admin.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <strings.h>

#include "dcs.h"
#include "remote_cfg.h"
#include "rdr_param_types.h"
#include "rdr_messages.h"
#include "rsrc_info.h"


typedef struct {
	ushort_t	major;
	ushort_t	minor;
} dcs_ver_t;


/* initialization functions */
static int init_server(struct pollfd *pfd, uint8_t ah_auth_alg,
    uint8_t esp_encr_alg, uint8_t esp_auth_alg);
static void init_signals(void);

/* message processing functions */
static int invalid_msg(rdr_msg_hdr_t *hdr);

/* message handling functions */
static int dcs_ses_req(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_ses_estbl(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_ses_end(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_change_state(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_private_func(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_test(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_list_ext(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_help(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_ap_id_cmp(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_abort_cmd(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_rsrc_info(rdr_msg_hdr_t *hdr, cfga_params_t *param);
static int dcs_unknown_op(rdr_msg_hdr_t *hdr, cfga_params_t *param);

/* local callback functions */
static int dcs_confirm_callback(void *appdata_ptr, const char *message);
static int dcs_message_callback(void *appdata_ptr, const char *message);

/* utility functions */
static dcs_ver_t resolve_version(ushort_t req_major, ushort_t req_minor);
static void filter_list_data(int perm, int *nlistp, cfga_list_data_t *linfo);
static rdr_list_t *generate_sort_order(cfga_list_data_t *listp, int nlist);
static int ldata_compare(const void *ap1, const void *ap2);
static int invalid_msg(rdr_msg_hdr_t *hdr);
static char *basename(char *path);
static boolean_t is_socket(int fd);
static uint8_t dcs_get_alg(dcs_alg_t *algs, char *arg, dcs_err_code *error);
static void dcs_log_bad_alg(char optopt, char *optarg);
static boolean_t dcs_global_policy(void);


/*
 * Lookup table for handling different message types. This
 * assumes the ordering of rdr_msg_opcode_t in remote_cfg.h.
 * If this enum changes, the lookup table must be updated.
 *
 * The lookup table handles all _known_ opcodes >= 0. Unsupported
 * opcodes, or opcodes that should not be received by the
 * dispatcher are handled by the dcs_unknown_op() function.
 */
int (*dcs_cmd[])(rdr_msg_hdr_t *, cfga_params_t *) = {
	dcs_unknown_op,		/* 0 is an invalid opcode	*/
	dcs_ses_req,		/* RDR_SES_REQ			*/
	dcs_ses_estbl,		/* RDR_SES_ESTBL		*/
	dcs_ses_end,		/* RDR_SES_END			*/
	dcs_change_state,	/* RDR_CONF_CHANGE_STATE	*/
	dcs_private_func,	/* RDR_CONF_PRIVATE_FUNC	*/
	dcs_test,		/* RDR_CONF_TEST		*/
	dcs_list_ext,		/* RDR_CONF_LIST_EXT		*/
	dcs_help,		/* RDR_CONF_HELP		*/
	dcs_ap_id_cmp,		/* RDR_CONF_AP_ID_CMP		*/
	dcs_abort_cmd,		/* RDR_CONF_ABORT_CMD		*/
	dcs_unknown_op,		/* RDR_CONF_CONFIRM_CALLBACK	*/
	dcs_unknown_op,		/* RDR_CONF_MSG_CALLBACK	*/
	dcs_rsrc_info		/* RDR_RSRC_INFO		*/
};


/*
 * ver_supp[] is an array of the supported versions for the network
 * transport protocol used by the DCA and DCS. Each item in the array
 * is a pair: { major_version, minor_version }.
 *
 * The order of the array is significant. The first element should be
 * the highest supported version and all successive elements should be
 * strictly decreasing.
 */
dcs_ver_t ver_supp[] = {
	{ 1, 1 },
	{ 1, 0 }
};

#define	DCS_CURR_VER		ver_supp[0]


/*
 * Global Data
 */
char	*cmdname = NULL;		 /* the name of the executable	    */
ulong_t	dcs_debug = 0;			 /* control the amount of debugging */
int	standalone = 0;			 /* control standalone mode	    */
boolean_t inetd = B_FALSE;		 /* control daemon mode		    */
ulong_t	max_sessions = DCS_MAX_SESSIONS; /* control maximum active sessions */
int	dcsfd = STDIN_FILENO;		 /* fd for the DCS reserved port    */
int	use_libdscp = 0;		 /* control use of libdscp */
sa_family_t use_family = AF_INET6;	/* control use of AF_INET/AF_INET6 */

/*
 * Array of acceptable -a, -e and -u arguments.
 */
static dcs_alg_t auth_algs_array[] = {
	{ "none",	SADB_AALG_NONE },	/* -a none or -u none */
	{ "md5",	SADB_AALG_MD5HMAC },	/* -a md5  or -u md5 */
	{ "sha1",	SADB_AALG_SHA1HMAC },	/* -a sha1 or -u sha1 */
	{ NULL,		0x0 }
}, esp_algs_array[] = {
	{ "none",	SADB_EALG_NONE },	/* -e none */
	{ "des",	SADB_EALG_DESCBC },	/* -e des  */
	{ "3des",	SADB_EALG_3DESCBC },	/* -e 3des */
	{ NULL,		0x0 }
};


/*
 * main:
 *
 * Initialize the DCS and then enter an infinite loop. This loop waits
 * for connection requests to come and then establishes a connection.
 * It dispatches the connection to be handled in a concurrent session.
 */
int
main(int argc, char **argv)
{
	int		opt;
	struct timeval	tv;
	struct pollfd	dcs_rcv;
	int		newfd;
	uint8_t		ah_auth_alg	= SADB_AALG_NONE;
	uint8_t		esp_encr_alg	= SADB_EALG_NONE;
	uint8_t		esp_auth_alg	= SADB_AALG_NONE;
	dcs_err_code	alg_ec		= DCS_NO_ERR;


	/* initialize globals */
	dcs_debug = DBG_NONE;
	cmdname = basename(argv[0]);

	/* open log file with unique prefix */
	openlog(cmdname, LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	/*
	 * Process command line args
	 */
	opterr = 0;	/* disable getopt error messages */
	while ((opt = getopt(argc, argv, OPT_STR)) != EOF) {

		switch (opt) {

		case 'd': {
			int	usr_debug;
			char	*err_str;

			usr_debug = strtol(optarg, &err_str, 0);

			/*
			 * The err_str parameter will be an
			 * empty string if successful.
			 */
			if (*err_str != '\0') {
				dcs_log_msg(LOG_ERR, DCS_BAD_OPT_ARG, optopt,
				    optarg, "exiting");
				(void) rdr_reject(dcsfd);
				exit(1);
			}

			dcs_debug = usr_debug;
			break;
		}

		case 'S':
			standalone++;
			break;

		case 's': {
			int	usr_ses;
			char	*err_str;

			usr_ses = strtol(optarg, &err_str, 0);

			if (usr_ses >= 1) {
				max_sessions = usr_ses;
			} else {
				char	behavior_str[MAX_MSG_LEN];

				snprintf(behavior_str, MAX_MSG_LEN,
				    "using default value (%d)", max_sessions);

				dcs_log_msg(LOG_NOTICE, DCS_BAD_OPT_ARG, optopt,
				    optarg, behavior_str);
			}

			break;
		}

		case 'a':
		case 'u':
			if (opt == 'a')
				ah_auth_alg = dcs_get_alg(auth_algs_array,
				    optarg, &alg_ec);
			else /* opt == 'u' */
				esp_auth_alg = dcs_get_alg(auth_algs_array,
				    optarg, &alg_ec);

			if (alg_ec == DCS_BAD_OPT_ARG) {
				dcs_log_bad_alg(optopt, optarg);
				(void) rdr_reject(dcsfd);
				exit(1);
			}

			break;

		case 'e':
			esp_encr_alg = dcs_get_alg(esp_algs_array, optarg,
			    &alg_ec);

			if (alg_ec == DCS_BAD_OPT_ARG) {
				dcs_log_bad_alg(optopt, optarg);
				(void) rdr_reject(dcsfd);
				exit(1);
			}

			break;

		case 'l':
			use_libdscp = 1;
			use_family = AF_INET;
			break;

		default:
			if (optopt == 'a' || optopt == 'e' || optopt == 'u')
				dcs_log_bad_alg(optopt, optarg);
			else
				dcs_log_msg(LOG_ERR, DCS_BAD_OPT, optopt);
			(void) rdr_reject(dcsfd);
			exit(1);

			/* NOTREACHED */
			break;
		}
	}

	/*
	 * In the future if inetd supports per-socket IPsec dcs can be run
	 * under inetd.
	 * Daemonize if we were not started by inetd unless running standalone.
	 */
	inetd = is_socket(STDIN_FILENO);
	if (inetd == B_FALSE && standalone == 0) {
		closefrom(0);
		(void) chdir("/");
		(void) umask(0);

		if (fork() != 0)
			exit(0);

		(void) setsid();

		/* open log again after all files were closed */
		openlog(cmdname, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	}

	DCS_DBG(DBG_ALL, "initializing %s...", cmdname);

	init_signals();

	/* must be root */
	if (geteuid() != 0) {
		dcs_log_msg(LOG_ERR, DCS_NO_PRIV);
		(void) rdr_reject(dcsfd);
		exit(1);
	}

	/*
	 * Seed the random number generator for
	 * generating random session identifiers.
	 */
	gettimeofday(&tv, NULL);
	srand48(tv.tv_usec);

	/* initialize our transport endpoint */
	if (init_server(&dcs_rcv, ah_auth_alg, esp_encr_alg, esp_auth_alg) ==
	    -1) {
		dcs_log_msg(LOG_ERR, DCS_INIT_ERR);
		(void) rdr_reject(dcsfd);
		exit(1);
	}


	DCS_DBG(DBG_ALL, "%s initialized, debug level = 0x%X, "
	    "max sessions = %d", cmdname, dcs_debug, max_sessions);

	/*
	 * Main service loop
	 */
	for (;;) {

		/* wait for a connection request */
		if (ses_poll(&dcs_rcv, 1, BLOCKFOREVER) == -1) {
			if (errno != EINTR) {
				dcs_log_msg(LOG_ERR, DCS_INT_ERR, "poll",
				    strerror(errno));
			}
			continue;
		}

		/* attempt to connect */
		newfd = rdr_connect_srv(dcs_rcv.fd);

		if ((newfd == RDR_ERROR) || (newfd == RDR_NET_ERR)) {
			dcs_log_msg(LOG_ERR, DCS_CONNECT_ERR);
			continue;
		}


		/* process the session concurrently */
		if (ses_start(newfd) == -1) {
			dcs_log_msg(LOG_ERR, DCS_SES_HAND_ERR);
			(void) rdr_close(newfd);
			break;
		}
	}

	close(dcs_rcv.fd);
	return (1);
}


/*
 * dcs_get_alg:
 *
 * Returns the ID of the first algorithm found in the 'algs' array
 * with a name matching 'arg'. If there is no matching algorithm,
 * 'error' is set to DCS_BAD_OPT_ARG, otherwise it is set to DCS_NO_ERR.
 * The 'algs' array must be terminated by an entry containing a NULL
 * 'arg_name' field. The 'error' argument must be a valid pointer.
 */
static uint8_t
dcs_get_alg(dcs_alg_t *algs, char *arg, dcs_err_code *error)
{
	dcs_alg_t *alg;

	*error = DCS_NO_ERR;

	for (alg = algs; alg->arg_name != NULL && arg != NULL; alg++) {
		if (strncmp(alg->arg_name, arg, strlen(alg->arg_name) + 1)
		    == 0) {
			return (alg->alg_id);
		}
	}

	*error = DCS_BAD_OPT_ARG;

	return (0);
}


/*
 * dcs_log_bad_alg:
 *
 * Logs an appropriate message when an invalid command line argument
 * was provided.  'optarg' is the invalid argument string for the
 * command line option 'optopt', where 'optopt' = 'a' for the '-a'
 * option. A NULL 'optarg' indicates the required option was not
 * provided.
 */
static void
dcs_log_bad_alg(char optopt, char *optarg)
{
	if (optarg == NULL) {
		dcs_log_msg(LOG_ERR, DCS_BAD_OPT_ARG, optopt,
		    "empty string", "an argument is required, exiting");
	} else {
		dcs_log_msg(LOG_ERR, DCS_BAD_OPT_ARG, optopt,
		    optarg, "exiting");
	}
}


/*
 * init_server:
 *
 * Perform all the operations that are required to initialize the
 * transport endpoint used by the DCS. After this routine succeeds,
 * the DCS is ready to accept session requests on its well known
 * port.
 */
static int
init_server(struct pollfd *pfd, uint8_t ah_auth_alg, uint8_t esp_encr_alg,
	uint8_t esp_auth_alg)
{
	struct servent		*se;
	struct sockaddr_storage	ss;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	struct linger		ling;
	ipsec_req_t		ipsec_req;
	int			req_port;
	int			act_port;
	int			init_status;
	int			num_sock_opts;
	int			sock_opts[] = { SO_REUSEADDR };


	assert(pfd);
	pfd->fd = dcsfd;
	pfd->events = POLLIN | POLLPRI;
	pfd->revents = 0;


	/*
	 * In standalone mode, we have to initialize the transport
	 * endpoint for our reserved port. In daemon mode, inetd
	 * starts the DCS and hands off STDIN_FILENO connected to
	 * our reserved port.
	 */

	if (inetd == B_FALSE || standalone) {
		/* in standalone mode, init fd for reserved port */
		if ((dcsfd = rdr_open(use_family)) == -1) {
			DCS_DBG(DBG_ALL, "rdr_open failed");
			return (-1);
		}
		pfd->fd = dcsfd;

		/*
		 * Enable per-socket IPsec if the user specified an
		 * AH or ESP algorithm to use and global policy is not in
		 * effect.
		 */
		if (!dcs_global_policy() &&
		    (ah_auth_alg != SADB_AALG_NONE ||
		    esp_encr_alg != SADB_EALG_NONE ||
		    esp_auth_alg != SADB_AALG_NONE)) {
			int err;

			bzero(&ipsec_req, sizeof (ipsec_req));

			/* Hardcoded values */
			ipsec_req.ipsr_self_encap_req	= SELF_ENCAP_REQ;
			/* User defined */
			ipsec_req.ipsr_auth_alg		= ah_auth_alg;
			ipsec_req.ipsr_esp_alg		= esp_encr_alg;
			if (ah_auth_alg != SADB_AALG_NONE)
				ipsec_req.ipsr_ah_req = AH_REQ;
			if (esp_encr_alg != SADB_EALG_NONE ||
			    esp_auth_alg != SADB_AALG_NONE) {
				ipsec_req.ipsr_esp_req		= ESP_REQ;
				ipsec_req.ipsr_esp_auth_alg	= esp_auth_alg;
			}

			err = rdr_setsockopt(pfd->fd, IPPROTO_IPV6,
			    IPV6_SEC_OPT, (void *)&ipsec_req,
			    sizeof (ipsec_req));

			if (err != RDR_OK) {
				DCS_DBG(DBG_ALL, "rdr_setsockopt failed");
				return (-1);
			}
		}
	}

	/*
	 * Look up our service to get the reserved port number
	 */
	if ((se = getservbyname(DCS_SERVICE, "tcp")) == NULL) {
		dcs_log_msg(LOG_NOTICE, DCS_NO_SERV, DCS_SERVICE);

		/* use the known port if service wasn't found */
		req_port = SUN_DR_PORT;
	} else {
		req_port = se->s_port;
	}

	(void) memset(&ss, 0, sizeof (ss));
	if (use_family == AF_INET) {
		/* initialize our local address */
		sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(req_port);
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		/* initialize our local address */
		sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(req_port);
		sin6->sin6_addr = in6addr_any;
	}

	num_sock_opts = sizeof (sock_opts) / sizeof (*sock_opts);

	init_status = rdr_init(pfd->fd, (struct sockaddr *)&ss,
	    sock_opts, num_sock_opts, DCS_BACKLOG);

	if (init_status != RDR_OK) {
		return (-1);
	}

	/*
	 * Set the SO_LINGER socket option so that TCP aborts the connection
	 * when the socket is closed.  This avoids encountering a TIME_WAIT
	 * state if the daemon ever crashes and is instantly restarted.
	 */
	ling.l_onoff = 1;
	ling.l_linger = 0;
	if (setsockopt(pfd->fd, SOL_SOCKET, SO_LINGER, &ling, sizeof (ling))) {
		return (-1);
	}

	switch (ss.ss_family) {
	case AF_INET:
		DCS_DBG(DBG_ALL, "using AF_INET socket");
		sin = (struct sockaddr_in *)&ss;
		act_port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		DCS_DBG(DBG_ALL, "using AF_INET6 socket");
		/* sin6 already set correctly */
		act_port = ntohs(sin6->sin6_port);
		break;
	default:
		DCS_DBG(DBG_ALL, "unknown socket type");
		return (-1);
	}

	/* check that we got the requested port */
	if (req_port != act_port) {
		dcs_log_msg(LOG_ERR, DCS_NO_PORT, req_port);
		return (-1);
	}

	return (0);
}


/*
 * init_signals:
 *
 * Initialize signals for the current session. All signals will be
 * blocked with two possible exceptions. SIGINT is not blocked in
 * standalone mode, and ses_init_signals() is called to selectively
 * unblock any signals required to handle concurrent sessions.
 */
static void
init_signals(void)
{
	sigset_t		mask;


	/* block all signals */
	sigfillset(&mask);

	/* in standalone, allow user to abort */
	if (standalone) {
		sigdelset(&mask, SIGINT);
	}

	ses_init_signals(&mask);

	(void) sigprocmask(SIG_BLOCK, &mask, NULL);
}


/*
 * dcs_dispatch_message:
 *
 * This function dispatches a message to the correct function. The
 * correct handler is determined by the opcode field of the message
 * header.
 */
int
dcs_dispatch_message(rdr_msg_hdr_t *hdr, cfga_params_t *params)
{
	session_t	*sp;


	assert(hdr);
	assert(params);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/* check the message */
	if (invalid_msg(hdr)) {
		dcs_log_msg(LOG_ERR, DCS_MSG_INVAL);
		ses_close(DCS_MSG_INVAL);
		return (-1);
	}

	/* save the current message */
	sp->curr_msg.hdr = hdr;
	sp->curr_msg.params = params;

	/*
	 * hdr->message_opcode is unsigned so don't need
	 * to check for values less than zero
	 */
	if (hdr->message_opcode >= RDR_NUM_OPS) {
		dcs_unknown_op(hdr, params);
		ses_close(DCS_MSG_INVAL);
		return (-1);
	}

	PRINT_MSG_DBG(DCS_RECEIVE, hdr);

	/* dispatch the message */
	if ((*dcs_cmd[hdr->message_opcode])(hdr, params) == -1) {
		dcs_log_msg(LOG_ERR, DCS_OP_FAILED);
		ses_close(DCS_ERROR);
		return (-1);
	}

	return (0);
}


/*
 * init_msg:
 *
 * Initialize the message header with information from the current
 * session. Fields not set directly are initialized to zero.
 */
void
init_msg(rdr_msg_hdr_t *hdr)
{
	session_t	*sp;


	assert(hdr);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return;
	}

	(void) memset(hdr, 0, sizeof (rdr_msg_hdr_t));

	/* set the session information */
	hdr->random_req = sp->random_req;
	hdr->random_resp = sp->random_resp;

	/* set the version being used */
	hdr->major_version = sp->major_version;
	hdr->minor_version = sp->minor_version;
}


/*
 * invalid_msg:
 *
 * Check if the message is valid for the current session. This
 * is accomplished by checking various information in the header
 * against the information for the current session.
 */
static int
invalid_msg(rdr_msg_hdr_t *hdr)
{
	session_t	*sp;


	assert(hdr);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/*
	 * Only perform the following checks if the message
	 * is not a session request. The information to check
	 * will not be set at the time a session request is
	 * received.
	 */
	if (hdr->message_opcode != RDR_SES_REQ) {

		/* check major and minor version */
		if ((sp->major_version != hdr->major_version) ||
		    (sp->minor_version != hdr->minor_version)) {
			DCS_DBG(DBG_MSG, "unsupported version %d.%d",
			    hdr->major_version, hdr->minor_version);
			return (-1);
		}

		/* check session identifiers */
		if ((sp->random_req != hdr->random_req) ||
		    (sp->random_resp != hdr->random_resp)) {
			DCS_DBG(DBG_MSG, "invalid session identifiers: "
			    "<%d, %d>", hdr->random_req, hdr->random_resp);
			return (-1);
		}
	}

	return (0);
}


/*
 * dcs_ses_req:
 *
 * Handle a session request message (RDR_SES_REQ).
 */
static int
dcs_ses_req(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t	*sp;
	rdr_msg_hdr_t	reply_hdr;
	cfga_params_t	reply_param;
	dcs_ver_t	act_ver;
	int		snd_status;
	static char 	*op_name = "session request";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/* make sure that a session hasn't been requested yet */
	if (sp->state != DCS_CONNECTED) {
		dcs_log_msg(LOG_ERR, DCS_SES_SEQ_INVAL);
		ses_close(DCS_SES_SEQ_INVAL);
		return (-1);
	}

	ses_setlocale(param->req.locale_str);

	/* get the best matching version supported */
	act_ver = resolve_version(hdr->major_version, hdr->minor_version);

	/* initialize session information */
	sp->random_req = hdr->random_req;
	sp->major_version = act_ver.major;
	sp->minor_version = act_ver.minor;

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_SES_REQ;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = DCS_OK;

	/* prepare session request specific data */
	(void) memset(&reply_param, 0, sizeof (cfga_params_t));
	reply_param.req.session_id = sp->id;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, &reply_param,
	    DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
		return (-1);
	}

	sp->state = DCS_SES_REQ;
	return (0);
}


/*
 * dcs_ses_estbl:
 *
 * Handle a session establishment message (RDR_SES_ESTBL).
 */
/* ARGSUSED */
static int
dcs_ses_estbl(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t	*sp;
	dcs_ver_t	act_ver;


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/*
	 * Make sure that a session has not been
	 * established yet, and that a session
	 * request has already been processed.
	 */
	if (sp->state != DCS_SES_REQ) {
		dcs_log_msg(LOG_ERR, DCS_SES_SEQ_INVAL);
		ses_close(DCS_SES_SEQ_INVAL);
		return (-1);
	}

	/* get the best matching version supported */
	act_ver = resolve_version(hdr->major_version, hdr->minor_version);

	if ((act_ver.major != hdr->major_version) ||
	    (act_ver.minor != hdr->minor_version)) {

		/* end the session because protocol not supported */
		dcs_log_msg(LOG_ERR, DCS_VER_INVAL, hdr->major_version,
		    hdr->minor_version);
		ses_close(DCS_VER_INVAL);
		return (-1);
	}

	DCS_DBG(DBG_SES, "Session Established");
	sp->state = DCS_SES_ESTBL;

	return (0);
}


/*
 * dcs_ses_end:
 *
 * Handle a session end message (RDR_SES_END).
 */
static int
dcs_ses_end(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t	*sp;
	rdr_msg_hdr_t	reply_hdr;
	cfga_params_t	reply_param;
	int		snd_status;
	static char	*op_name = "session end";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/*
	 * Session end is valid from any state. However, only
	 * send back a reply if the error code is zero. A non-zero
	 * error code indicates that the session is being terminated
	 * under an error condition, and no acknowledgement is
	 * required.
	 */
	if (param->end.error_code == 0) {

		/* prepare header information */
		init_msg(&reply_hdr);
		reply_hdr.message_opcode = RDR_SES_END;
		reply_hdr.data_type = RDR_REPLY;
		reply_hdr.status = DCS_OK;

		/* return empty data - no information needed in reply */
		(void) memset(&reply_param, 0, sizeof (cfga_params_t));

		PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

		snd_status = rdr_snd_msg(sp->fd, &reply_hdr, &reply_param,
		    DCS_SND_TIMEOUT);

		if (snd_status == RDR_ABORTED) {
			abort_handler();
		}

		if (snd_status != RDR_OK) {
			dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
		}
	}

	sp->state = DCS_SES_END;

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_change_state:
 *
 * Handle a change state request message (RDR_CONF_CHANGE_STATE).
 */
static int
dcs_change_state(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	change_state_params_t	*op_data;
	struct cfga_confirm 	local_conf_cb;
	struct cfga_msg		local_msg_cb;
	int			cfga_status = 0;
	int			snd_status;
	char			*err_str;
	unsigned int		curr_attempt;
	unsigned int		num_attempts;
	char			retry_msg[MAX_MSG_LEN];
	static char		*op_name = "config_change_state";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->change;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	/* initialize local confirm callback */
	local_conf_cb.confirm = dcs_confirm_callback;
	local_conf_cb.appdata_ptr = (void *)op_data->confp;

	/* initialize local message callback */
	local_msg_cb.message_routine = dcs_message_callback;
	local_msg_cb.appdata_ptr = (void *)op_data->msgp;

	/* verify retry value */
	if (op_data->retries < 0) {
		dcs_log_msg(LOG_NOTICE, DCS_BAD_RETRY_VAL, op_data->retries);
		op_data->retries = 0;
	}

	/* verify timeout value */
	if (op_data->timeval < 0) {
		dcs_log_msg(LOG_NOTICE, DCS_BAD_TIME_VAL, op_data->timeval);
		op_data->timeval = 0;
	}

	num_attempts = 1 + op_data->retries;
	curr_attempt = 0;

	while (curr_attempt < num_attempts) {

		/* don't sleep the first time around */
		if (curr_attempt != 0) {

			/* log the error message and alert the user */
			err_str = dcs_cfga_str(op_data->errstring, cfga_status);
			if (err_str) {
				dcs_log_msg(LOG_ERR, DCS_CFGA_ERR, op_name,
				    err_str);
				dcs_message_callback((void *)op_data->msgp,
				    err_str);
				free((void *)err_str);
			} else {
				dcs_log_msg(LOG_ERR, DCS_CFGA_UNKNOWN);
				dcs_message_callback((void *)op_data->msgp,
				    dcs_strerror(DCS_CFGA_UNKNOWN));
			}

			if (op_data->errstring && *op_data->errstring) {
				free((void *)*op_data->errstring);
				*op_data->errstring = NULL;
			}

			/* sleep with abort enabled */
			ses_sleep(op_data->timeval);

			/* log the retry attempt and alert the user */
			dcs_log_msg(LOG_INFO, DCS_RETRY, curr_attempt);
			snprintf(retry_msg, MAX_MSG_LEN,
			    dcs_strerror(DCS_RETRY), curr_attempt);
			dcs_message_callback((void *)op_data->msgp, retry_msg);
		}

		sp->state = DCS_CONF_PENDING;

		/*
		 * Call into libcfgadm
		 */
		ses_abort_enable();

		cfga_status = config_change_state(op_data->state_change,
		    op_data->num_ap_ids, op_data->ap_ids, op_data->options,
		    &local_conf_cb, &local_msg_cb, op_data->errstring,
		    op_data->flags);

		ses_abort_disable();

		/*
		 * Retry only the operations that have a chance to
		 * succeed if retried. All libcfgadm errors not
		 * included below will always fail, regardless of
		 * a retry.
		 */
		if ((cfga_status != CFGA_BUSY) &&
		    (cfga_status != CFGA_SYSTEM_BUSY) &&
		    (cfga_status != CFGA_ERROR)) {
			break;
		}

		/* prepare for another attempt */
		++curr_attempt;
	}

	sp->state = DCS_CONF_DONE;

	/* log any libcfgadm errors */
	if (cfga_status != CFGA_OK) {
		err_str = dcs_cfga_str(op_data->errstring, cfga_status);
		if (err_str) {
			dcs_log_msg(LOG_ERR, DCS_CFGA_ERR, op_name, err_str);
			free((void *)err_str);
		}
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_CHANGE_STATE;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = cfga_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	/* clean up */
	if (op_data->errstring && *op_data->errstring) {
		free((void *)*op_data->errstring);
		*op_data->errstring = NULL;
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_private_func:
 *
 * Handle a private function request message (RDR_CONF_PRIVATE_FUNC).
 */
static int
dcs_private_func(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	private_func_params_t	*op_data;
	struct cfga_confirm 	local_conf_cb;
	struct cfga_msg		local_msg_cb;
	int			cfga_status;
	int			snd_status;
	char			*err_str;
	static char		*op_name = "config_private_func";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->priv;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	/* initialize local confirm callback */
	local_conf_cb.confirm = dcs_confirm_callback;
	local_conf_cb.appdata_ptr = (void *)op_data->confp;

	/* initialize local message callback */
	local_msg_cb.message_routine = dcs_message_callback;
	local_msg_cb.appdata_ptr = (void *)op_data->msgp;

	sp->state = DCS_CONF_PENDING;

	/*
	 * Call into libcfgadm
	 */
	ses_abort_enable();

	cfga_status = config_private_func(op_data->function,
	    op_data->num_ap_ids, op_data->ap_ids, op_data->options,
	    &local_conf_cb, &local_msg_cb, op_data->errstring, op_data->flags);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/* log any libcfgadm errors */
	if (cfga_status != CFGA_OK) {
		err_str = dcs_cfga_str(op_data->errstring, cfga_status);
		if (err_str) {
			dcs_log_msg(LOG_ERR, DCS_CFGA_ERR, op_name, err_str);
			free((void *)err_str);
		}
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_PRIVATE_FUNC;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = cfga_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	if (op_data->errstring && *op_data->errstring) {
		free((void *)*op_data->errstring);
		*op_data->errstring = NULL;
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_test:
 *
 * Handle a test request message (RDR_CONF_TEST).
 */
static int
dcs_test(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	test_params_t		*op_data;
	struct cfga_msg		local_msg_cb;
	int			cfga_status;
	int			snd_status;
	char			*err_str;
	static char		*op_name = "config_test";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->test;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	/* initialize local message callback */
	local_msg_cb.message_routine = dcs_message_callback;
	local_msg_cb.appdata_ptr = op_data->msgp;

	sp->state = DCS_CONF_PENDING;

	/*
	 * Call into libcfgadm
	 */
	ses_abort_enable();

	cfga_status = config_test(op_data->num_ap_ids, op_data->ap_ids,
	    op_data->options, &local_msg_cb, op_data->errstring,
	    op_data->flags);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/* log any libcfgadm errors */
	if (cfga_status != CFGA_OK) {
		err_str = dcs_cfga_str(op_data->errstring, cfga_status);
		if (err_str) {
			dcs_log_msg(LOG_ERR, DCS_CFGA_ERR, op_name, err_str);
			free((void *)err_str);
		}
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_TEST;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = cfga_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	if (op_data->errstring && *op_data->errstring) {
		free((void *)*op_data->errstring);
		*op_data->errstring = NULL;
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_list_ext:
 *
 * Handle a list request message (RDR_CONF_LIST_EXT).
 */
static int
dcs_list_ext(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	list_ext_params_t	*op_data;
	int			cfga_status;
	int			snd_status;
	char			*err_str;
	static char		*op_name = "config_list_ext";
	cfga_list_data_t	*ap_ids;


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->list_ext;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	/*
	 * Make sure that we can retrieve the data
	 * from libcfgadm. If not, report the error.
	 */
	if (op_data->ap_id_list == NULL) {
		dcs_log_msg(LOG_ERR, DCS_MSG_INVAL);
		ses_close(DCS_MSG_INVAL);
		return (-1);
	}

	sp->state = DCS_CONF_PENDING;

	/*
	 * Call into libcfgadm
	 */
	ses_abort_enable();

	cfga_status = config_list_ext(op_data->num_ap_ids, op_data->ap_ids,
	    &ap_ids, op_data->nlist, op_data->options, op_data->listopts,
	    op_data->errstring, op_data->flags);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/*
	 * Log any libcfgadm errors at a low priority level.
	 * Since a status request does not modify the system
	 * in any way, we do not need to worry about these
	 * errors here on the host.
	 */
	if (cfga_status != CFGA_OK) {
		err_str = dcs_cfga_str(op_data->errstring, cfga_status);
		if (err_str) {
			dcs_log_msg(LOG_INFO, DCS_CFGA_ERR, op_name, err_str);
			free((void *)err_str);
		}
	}

	/*
	 * Filter ap ids to return only appropriate information
	 */
	filter_list_data(op_data->permissions, op_data->nlist, ap_ids);

	/* if all aps were filtered out, return an error */
	if ((cfga_status == CFGA_OK) && (*op_data->nlist == 0)) {
		cfga_status = CFGA_APID_NOEXIST;
	}

	/* calculate the sort order */
	if (cfga_status == CFGA_OK) {

		*op_data->ap_id_list = generate_sort_order(ap_ids,
		    *op_data->nlist);

		if (*op_data->ap_id_list == NULL) {
			cfga_status = CFGA_LIB_ERROR;
		}
	}

	/* ensure that nlist is 0 for errors */
	if (cfga_status != CFGA_OK) {
		*op_data->nlist = 0;
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_LIST_EXT;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = cfga_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	if (op_data->errstring && *op_data->errstring) {
		free((void *)*op_data->errstring);
		*op_data->errstring = NULL;
	}

	if (ap_ids != NULL) {
		free((void *)ap_ids);
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_help:
 *
 * Handle a help request message (RDR_CONF_HELP).
 */
static int
dcs_help(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	help_params_t		*op_data;
	struct cfga_msg		local_msg_cb;
	int			cfga_status;
	int			snd_status;
	char			*err_str;
	static char		*op_name = "config_help";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->help;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	/* initialize local message callback */
	local_msg_cb.message_routine = dcs_message_callback;
	local_msg_cb.appdata_ptr = op_data->msgp;

	sp->state = DCS_CONF_PENDING;

	/*
	 * Call into libcfgadm
	 */
	ses_abort_enable();

	cfga_status = config_help(op_data->num_ap_ids, op_data->ap_ids,
	    &local_msg_cb, op_data->options, op_data->flags);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/*
	 * Log any libcfgadm errors at a low priority level.
	 * Since a help request does not modify the system
	 * in any way, we do not need to worry about these
	 * errors here on the host.
	 */
	if (cfga_status != CFGA_OK) {
		err_str = dcs_cfga_str(NULL, cfga_status);
		if (err_str) {
			dcs_log_msg(LOG_INFO, DCS_CFGA_ERR, op_name, err_str);
			free((void *)err_str);
		}
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_HELP;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = cfga_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_ap_id_cmp:
 *
 * Handle an attachment point comparison request message (RDR_AP_ID_CMP).
 */
static int
dcs_ap_id_cmp(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t 		reply_hdr;
	ap_id_cmp_params_t	*op_data;
	int			snd_status;
	int			cmp_result;
	static char		*op_name = "config_ap_id_cmp";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = &param->cmp;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	sp->state = DCS_CONF_PENDING;

	/*
	 * Call into libcfgadm
	 */
	ses_abort_enable();

	cmp_result = config_ap_id_cmp(op_data->ap_log_id1, op_data->ap_log_id2);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_AP_ID_CMP;
	reply_hdr.data_type = RDR_REPLY;

	/*
	 * Return result of comparison as error code.
	 * Since all values are valid, it is impossible
	 * to report an error.
	 */
	reply_hdr.status = cmp_result;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_abort_cmd:
 *
 * Handle an abort request message (RDR_CONF_ABORT_CMD).
 */
/* ARGSUSED */
static int
dcs_abort_cmd(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t		reply_hdr;
	abort_cmd_params_t	*op_data;
	int			op_status = RDR_SUCCESS;
	int			snd_status;
	static char		*op_name = "abort command";


	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = (abort_cmd_params_t *)param;

	op_status = ses_abort(op_data->session_id);

	if (op_status == -1) {
		dcs_log_msg(LOG_ERR, DCS_ABORT_ERR, op_data->session_id);
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_CONF_ABORT_CMD;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = op_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	sp->state = DCS_CONF_DONE;

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_rsrc_info:
 *
 * Handle a resource info request message (RDR_RSRC_INFO).
 */
static int
dcs_rsrc_info(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t		*sp;
	rdr_msg_hdr_t		reply_hdr;
	rsrc_info_params_t	*op_data;
	int			rsrc_status;
	int			snd_status;
	static char		*op_name = "resource info init";

	assert(hdr);
	assert(param);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	op_data = (rsrc_info_params_t *)&param->rsrc_info;

	/* make sure we have a session established */
	if (sp->state != DCS_SES_ESTBL) {
		dcs_log_msg(LOG_ERR, DCS_NO_SES_ESTBL, op_name);
		ses_close(DCS_NO_SES_ERR);
		return (-1);
	}

	sp->state = DCS_CONF_PENDING;

	/*
	 * Request resource info data.
	 */
	ses_abort_enable();

	rsrc_status = ri_init(op_data->num_ap_ids, op_data->ap_ids,
	    op_data->flags, &op_data->hdl);

	ses_abort_disable();

	sp->state = DCS_CONF_DONE;

	/* log errors */
	if (rsrc_status != RI_SUCCESS) {
		dcs_log_msg(LOG_ERR, DCS_RSRC_ERR, rsrc_status);
	}

	/* prepare header information */
	init_msg(&reply_hdr);
	reply_hdr.message_opcode = RDR_RSRC_INFO;
	reply_hdr.data_type = RDR_REPLY;
	reply_hdr.status = rsrc_status;

	PRINT_MSG_DBG(DCS_SEND, &reply_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &reply_hdr, param, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	ri_fini(op_data->hdl);

	return ((snd_status != RDR_OK) ? -1 : 0);
}


/*
 * dcs_unknown_op:
 *
 * Handle all unknown requests.
 */
/* ARGSUSED */
static int
dcs_unknown_op(rdr_msg_hdr_t *hdr, cfga_params_t *param)
{
	session_t	*sp;


	assert(hdr);
	assert(param);

	assert(hdr);

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	dcs_log_msg(LOG_ERR, DCS_UNKNOWN_OP, hdr->message_opcode);

	sp->state = DCS_CONF_DONE;

	return (-1);
}


/*
 * dcs_confirm_callback:
 *
 * Perform a confirm callback and wait for the reply. As defined
 * in the config_admin(3CFGADM) man page, 1 is returned if the
 * operation should be allowed to continue and 0 otherwise.
 */
static int
dcs_confirm_callback(void *appdata_ptr, const char *message)
{
	session_t		*sp;
	rdr_msg_hdr_t		req_hdr;
	cfga_params_t		req_data;
	struct cfga_confirm	*cb_data;
	rdr_msg_hdr_t		reply_hdr;
	cfga_params_t		reply_data;
	int			snd_status;
	int			rcv_status;
	static char		*op_name = "confirm callback";


	/* sanity check */
	if (appdata_ptr == NULL) {
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	cb_data = (struct cfga_confirm *)appdata_ptr;

	/* prepare header information */
	init_msg(&req_hdr);
	req_hdr.message_opcode = RDR_CONF_CONFIRM_CALLBACK;
	req_hdr.data_type = RDR_REQUEST;

	/* prepare confirm callback specific data */
	(void) memset(&req_data, 0, sizeof (req_data));
	req_data.conf_cb.confp = cb_data;
	req_data.conf_cb.message = (char *)message;

	PRINT_MSG_DBG(DCS_SEND, &req_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &req_hdr, &req_data, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	/*
	 * Wait for response
	 */
	rcv_status = rdr_rcv_msg(sp->fd, &reply_hdr, &reply_data,
	    DCS_RCV_CB_TIMEOUT);

	if (rcv_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	/*
	 * Perform several checks to see if we have a
	 * valid response to the confirm callback.
	 */
	if (invalid_msg(&reply_hdr)) {
		dcs_log_msg(LOG_ERR, DCS_MSG_INVAL);
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	/* check the opcode and type */
	if ((reply_hdr.message_opcode != RDR_CONF_CONFIRM_CALLBACK) ||
	    (reply_hdr.data_type != RDR_REPLY)) {
		DCS_DBG(DBG_MSG, "bad opcode or message type");
		dcs_log_msg(LOG_ERR, DCS_MSG_INVAL);
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	PRINT_MSG_DBG(DCS_RECEIVE, &reply_hdr);

	/* check for incorrect callback id */
	if (reply_data.conf_cb.confp->confirm != cb_data->confirm) {
		dcs_log_msg(LOG_ERR, DCS_MSG_INVAL);
		dcs_log_msg(LOG_NOTICE, DCS_CONF_CB_ERR);
		return (0);
	}

	/*
	 * Got back valid response: return the user's answer
	 */
	return (reply_data.conf_cb.response);
}


/*
 * dcs_message_callback:
 *
 * Perform a message callback to display a string to the user.
 *
 * Note: There is no documentation about possible return values
 * for the message callback. It is assumed that the value returned
 * is ignored, so 0 is returned for all cases.
 */
static int
dcs_message_callback(void *appdata_ptr, const char *message)
{
	session_t	*sp;
	rdr_msg_hdr_t	req_hdr;
	cfga_params_t	req_data;
	struct cfga_msg	*cb_data;
	int		snd_status;
	static char	*op_name = "message callback";


	/* sanity check */
	if (appdata_ptr == NULL) {
		dcs_log_msg(LOG_NOTICE, DCS_MSG_CB_ERR);
		return (0);
	}

	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		dcs_log_msg(LOG_NOTICE, DCS_MSG_CB_ERR);
		return (0);
	}

	cb_data = (struct cfga_msg *)appdata_ptr;

	/* prepare header information */
	init_msg(&req_hdr);
	req_hdr.message_opcode = RDR_CONF_MSG_CALLBACK;
	req_hdr.data_type = RDR_REQUEST;

	/* prepare message callback specific data */
	(void) memset(&req_data, 0, sizeof (req_data));
	req_data.msg_cb.msgp = cb_data;
	req_data.msg_cb.message = (char *)message;

	PRINT_MSG_DBG(DCS_SEND, &req_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &req_hdr, (cfga_params_t *)&req_data,
	    DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
		dcs_log_msg(LOG_NOTICE, DCS_MSG_CB_ERR);
	}

	return (0);
}


/*
 * resolve_version:
 *
 * Consult the list of supported versions and find the highest supported
 * version that is less than or equal to the version requested in the
 * parameters. This assumes that the list of supported versions is ordered
 * so that the highest supported version is the first element, and that
 * the versions are strictly decreasing.
 */
static dcs_ver_t
resolve_version(ushort_t req_major, ushort_t req_minor)
{
	int		i;
	dcs_ver_t	act_ver;
	int		num_vers;


	num_vers = sizeof (ver_supp) / sizeof (*ver_supp);

	/* default to the lowest version */
	act_ver = ver_supp[num_vers - 1];

	for (i = 0; i < num_vers; i++) {

		if (req_major == ver_supp[i].major) {

			if (req_minor >= ver_supp[i].minor) {
				/*
				 * The major version matches and the
				 * minor version either matches, or
				 * is the best match that we have.
				 */
				act_ver = ver_supp[i];
				break;
			}

		} else if (req_major > ver_supp[i].major) {
			/*
			 * The requested major version is larger than
			 * the current version we are checking. There
			 * is not going to be a better match.
			 */
			act_ver = ver_supp[i];
			break;
		}
	}

	DCS_DBG(DBG_SES, "requested ver: %d.%d, closest match: %d.%d",
	    req_major, req_minor, act_ver.major, act_ver.minor);

	return (act_ver);
}


/*
 * filter_list_data:
 *
 * Check a list of cfga_list_data_t structures to filter out the ones
 * that don't have other-read permissions. All valid entries are placed
 * at the beginning of the array and the count of entries is updated.
 */
static void
filter_list_data(int perm, int *nlistp, cfga_list_data_t *linfo)
{
	int		num_aps;
	int		num_aps_ret;
	int		curr_ap;
	int		next_aval;
	int		end_block;
	int		block_size;
	struct stat	ap_info;


	DCS_DBG(DBG_MSG, "list access = %s", (perm == RDR_PRIVILEGED) ?
	    "RDR_PRIVILEGED" : "RDR_NOT_PRIVILEGED");

	/*
	 * Check if the user has priviledged access
	 * to view all attachment points
	 */
	if (perm == RDR_PRIVILEGED) {
		return;
	}

	if (*nlistp < 0) {
		*nlistp = 0;
	}

	/*
	 * No priviledged access, check each attachment point to
	 * see if the user has access (other:read) to view it.
	 */
	num_aps = *nlistp;
	next_aval = 0;
	num_aps_ret = 0;
	curr_ap = 0;

	/*
	 * Use a simple algorithm to compact the array so that
	 * all attachment points that can be viewed are at the
	 * beginning of the array. Adjust the count of the
	 * attachment points accordingly.
	 */
	while (curr_ap < num_aps) {

		stat(linfo[curr_ap].ap_phys_id, &ap_info);

		/* check for unrestricted read permission */
		if (ap_info.st_mode & S_IROTH) {

			end_block = curr_ap + 1;

			/*
			 * Check if this is the beginning of a
			 * block of consecutive ap ids that can
			 * be returned.
			 */
			while (end_block < num_aps) {

				stat(linfo[end_block].ap_phys_id, &ap_info);

				/* search until the end of the block */
				if (ap_info.st_mode & S_IROTH) {
					end_block++;
				} else {
					break;
				}
			}

			block_size = end_block - curr_ap;

			/* make sure a copy is necessary */
			if (curr_ap != next_aval) {

				/* copy the block of ap ids all at once */
				(void) memmove(&linfo[next_aval],
				    &linfo[curr_ap],
				    block_size * sizeof (cfga_list_data_t));
			}

			/* move past the copied block */
			next_aval += block_size;
			curr_ap = end_block;

			num_aps_ret += block_size;
		} else {
			curr_ap++;
		}
	}

	DCS_DBG(DBG_ALL, "filtered %d of %d ap ids", (*nlistp - num_aps_ret),
	    *nlistp);

	/*
	 * return the number of aps that have the correct
	 * access permissions.
	 */
	*nlistp = num_aps_ret;
}


/*
 * generate_sort_order:
 *
 * Determine the sort order of an array of cfga_list_data_t structures
 * and create an array of rdr_list_t structures that contain the original
 * elements tagged with the sort order.
 *
 * This function is used to eliminate unnecessary network traffic that
 * might occur if the client needs the output of config_list_ext(3CFGADM)
 * sorted. Since a comparison is performed in a platform specific manner
 * using config_ap_id_cmp(3CFGADM), a client must establish a new session
 * for each comparison. For a long lists of attachment points, this can
 * slow down a simple list_ext operation significantly. With the sort
 * information included in the array of rdr_list_t structures, the client
 * can perform the sort operation locally, thus eliminating a great deal
 * of network traffic.
 */
static rdr_list_t *
generate_sort_order(cfga_list_data_t *listp, int nlist)
{
	int			curr_ap;
	rdr_list_t		*datalp;
	cfga_list_data_t	*sortlp;
	cfga_list_data_t	*match;


	assert(listp);

	if (nlist <= 0) {
		return (NULL);
	}

	/* create our new array */
	datalp = (rdr_list_t *)malloc(nlist * sizeof (rdr_list_t));

	if (datalp == NULL) {
		return (NULL);
	}


	/* copy over the elements, preserving the original order */
	for (curr_ap = 0; curr_ap < nlist; curr_ap++) {
		datalp[curr_ap].ap_id_info = listp[curr_ap];
	}

	/* handle a one element list */
	if (nlist == 1) {
		datalp[0].sort_order = 0;
		return (datalp);
	}

	/* sort the cfga_list_data_t array */
	qsort(listp, nlist, sizeof (listp[0]), ldata_compare);

	sortlp = listp;

	/* process each item in the original list */
	for (curr_ap = 0; curr_ap < nlist; curr_ap++) {

		/* look up the sort order in the sorted list */
		match = bsearch(&datalp[curr_ap].ap_id_info, sortlp,
		    nlist, sizeof (cfga_list_data_t), ldata_compare);

		/* found a match */
		if (match != NULL) {
			datalp[curr_ap].sort_order = match - sortlp;
		} else {
			/*
			 * Should never get here. Since we did a
			 * direct copy of the array, we should always
			 * be able to find the ap id that we were
			 * looking for.
			 */
			DCS_DBG(DBG_ALL, "could not find a matching "
			    "ap id in the sorted list");
			datalp[curr_ap].sort_order = 0;
		}
	}

	return (datalp);
}


/*
 * ldata_compare:
 *
 * Compare the two inputs to produce a strcmp(3C) style result. It uses
 * config_ap_id_cmp(3CFGADM) to perform the comparison.
 *
 * This function is passed to qsort(3C) in generate_sort_order() to sort a
 * list of attachment points.
 */
static int
ldata_compare(const void *ap1, const void *ap2)
{
	cfga_list_data_t *ap_id1;
	cfga_list_data_t *ap_id2;

	ap_id1 = (cfga_list_data_t *)ap1;
	ap_id2 = (cfga_list_data_t *)ap2;

	return (config_ap_id_cmp(ap_id1->ap_log_id, ap_id2->ap_log_id));
}


/*
 * basename:
 *
 * Find short path name of a full path name. If a short path name
 * is passed in, the original pointer is returned.
 */
static char *
basename(char *cp)
{
	char *sp;

	if ((sp = strrchr(cp, '/')) != NULL) {
		return (sp + 1);
	}

	return (cp);
}

/*
 * is_socket:
 *
 * determine if fd represents a socket file type.
 */
static boolean_t
is_socket(int fd)
{
	struct stat statb;
	if (fstat(fd, &statb) < 0) {
		return (B_FALSE);
	}
	return (S_ISSOCK(statb.st_mode));
}

/*
 * has_dcs_token
 *
 * Look for "?port [sun-dr|665]" in input buf.
 * Assume only a single thread calls here.
 */
static boolean_t
has_dcs_token(char *buf)
{
	char 		*token;
	char		*delims = "{} \t\n";
	boolean_t 	port = B_FALSE;

	while ((token = strtok(buf, delims)) != NULL) {
		buf = NULL;
		if (port == B_TRUE) {
			if (strcmp(token, "sun-dr") == 0 ||
			    strcmp(token, "665") == 0) {
				return (B_TRUE);
			} else {
				return (B_FALSE);
			}
		}
		if (strlen(token) == 5) {
			token++;
			if (strcmp(token, "port") == 0) {
				port = B_TRUE;
				continue;
			}
		}
	}
	return (B_FALSE);
}

/*
 * dcs_global_policy
 *
 * Check global policy file for dcs entry. Just covers common cases.
 */
static boolean_t
dcs_global_policy()
{
	FILE		*fp;
	char		buf[256];
	boolean_t	rv = B_FALSE;

	fp = fopen("/etc/inet/ipsecinit.conf", "r");
	if (fp == NULL)
		return (B_FALSE);
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		if (buf[0] == '#')
			continue;
		if (has_dcs_token(buf)) {
			rv = B_TRUE;
			syslog(LOG_NOTICE, "dcs using global policy");
			break;
		}
	}
	(void) fclose(fp);
	return (rv);
}
