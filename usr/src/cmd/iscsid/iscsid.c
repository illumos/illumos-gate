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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <locale.h>
#include <syslog.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <door.h>
#include <libsysevent.h>
#include <wait.h>
#include <semaphore.h>
#include <libscf.h>

#include <sys/scsi/adapters/iscsi_door.h>
#include <sys/scsi/adapters/iscsi_if.h>

/*
 * Local Defines
 * -------------
 */
#define	ISCSI_DOOR_DAEMON_SYSLOG_PP		"iscsid"
#define	ISCSI_DISCOVERY_POLL_DELAY1		1	/* Seconds */
#define	ISCSI_DISCOVERY_POLL_DELAY2		60	/* Seconds */
#define	ISCSI_SMF_OFFLINE_DELAY			10	/* Seconds */
#define	ISCSI_SMF_OFFLINE_MAX_RETRY_TIMES	60

#if !defined(SMF_EXIT_ERR_OTHER)
#define	SMF_EXIT_ERR_OTHER	-1
#endif

/*
 * Global Variables related to the synchronization of the child process
 * --------------------------------------------------------------------
 */
static	pid_t		iscsi_child_pid;
static	sem_t		iscsi_child_sem;
static	int		iscsi_child_door_handle;
static	int		iscsi_child_smf_exit_code;

/*
 * Global Variables related to the door accessed by the kernel
 * -----------------------------------------------------------
 */
static	int		iscsi_dev_handle;
static	int		iscsi_kernel_door_handle;

/*
 * Prototypes of Functions the body of which is defined farther down
 * in this file.
 * -----------------------------------------------------------------
 */
static	void		call_child_door(int value);
static	void		sigchld_handler(int sig);
static	boolean_t	discovery_event_wait(int did);
static	void		signone(int, siginfo_t *, void *);

static
void
iscsi_child_door(
	void			*cookie,
	char			*args,
	size_t			alen,
	door_desc_t		*ddp,
	uint_t			ndid
);

static
void
iscsi_kernel_door(
	void			*cookie,
	char			*args,
	size_t			alen,
	door_desc_t		*ddp,
	uint_t			ndid
);

static
iscsi_door_cnf_t *
_getipnodebyname_req(
	getipnodebyname_req_t	*req,
	int			req_len,
	size_t			*pcnf_len
);

/*
 * main -- Entry point of the iSCSI door server daemon
 *
 * This function forks, waits for the child process feedback and exits.
 */
/* ARGSUSED */
int
main(
	int	argc,
	char	*argv[]
)
{
	int			i;
	int			sig;
	int			ret = -1;
	int			retry = 0;
	sigset_t		sigs, allsigs;
	struct sigaction	act;
	uint32_t		rval;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.
	 */
	(void) setlocale(LC_ALL, "");
	openlog("ISCSI_DOOR_DAEMON_SYSLOG_PP", LOG_PID, LOG_DAEMON);

	/* The child semaphore is created. */
	if (sem_init(&iscsi_child_sem, 0, 0) == -1) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* The door for the child is created. */
	iscsi_child_door_handle = door_create(iscsi_child_door, NULL, 0);
	if (iscsi_child_door_handle == -1) {
		(void) sem_destroy(&iscsi_child_sem);
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* A signal handler is set for SIGCHLD. */
	(void) signal(SIGCHLD, sigchld_handler);

	/*
	 * Here begins the daemonizing code
	 * --------------------------------
	 */
	iscsi_child_pid = fork();
	if (iscsi_child_pid < 0) {
		/* The fork failed. */
		syslog(LOG_DAEMON | LOG_ERR, gettext("Cannot fork"));
		(void) sem_destroy(&iscsi_child_sem);
		exit(SMF_EXIT_ERR_OTHER);
	}

	if (iscsi_child_pid) {
		/*
		 * The parent exits after the child has provided feedback. This
		 * waiting phase is to meet one of greenline's requirements.
		 * We shouldn't return till we are sure the service is ready to
		 * be provided.
		 */
		(void) sem_wait(&iscsi_child_sem);
		(void) sem_destroy(&iscsi_child_sem);
		exit(iscsi_child_smf_exit_code);
	}

	/*
	 * stdout and stderr are redirected to "/dev/null".
	 */
	i = open("/dev/null", O_RDWR);
	(void) dup2(i, 1);
	(void) dup2(i, 2);

	/*
	 * Here ends the daemonizing code
	 * ------------------------------
	 */

	/*
	 * Block out all signals
	 */
	(void) sigfillset(&allsigs);
	(void) pthread_sigmask(SIG_BLOCK, &allsigs, NULL);

	/* setup the door handle */
	iscsi_kernel_door_handle = door_create(iscsi_kernel_door, NULL, 0);
	if (iscsi_kernel_door_handle == -1) {
		perror(gettext("door_create failed"));
		syslog(LOG_DAEMON | LOG_ERR, gettext("door_create failed"));
		exit(SMF_EXIT_ERR_OTHER);
	}

	/*
	 * The iSCSI driver is opened.
	 */
	iscsi_dev_handle = open(ISCSI_DRIVER_DEVCTL, O_RDWR);
	if (iscsi_dev_handle == -1) {
		/* The driver couldn't be opened. */
		perror(gettext("iscsi device open failed"));
		exit(SMF_EXIT_ERR_OTHER);
	}

	if (ioctl(
	    iscsi_dev_handle,
	    ISCSI_SMF_ONLINE,
	    &iscsi_kernel_door_handle) == -1) {
		(void) close(iscsi_dev_handle);
		perror(gettext("ioctl: enable iscsi initiator"));
		exit(SMF_EXIT_ERR_OTHER);
	}

	/*
	 * Keep the dev open, so to keep iscsi module from unloaded.
	 * This is crutial to guarantee the consistency of the
	 * door_handle and service state in kernel.
	 */

	/* We have to wait for the discovery process to finish. */
	(void) discovery_event_wait(iscsi_dev_handle);

	/* We let the parent know that everything is ok. */
	call_child_door(SMF_EXIT_OK);

	/* now set up signals we care about */

	(void) sigemptyset(&sigs);
	(void) sigaddset(&sigs, SIGTERM);
	(void) sigaddset(&sigs, SIGINT);
	(void) sigaddset(&sigs, SIGQUIT);

	/* make sure signals to be enqueued */
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signone;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGQUIT, &act, NULL);

	/* wait and process signals */
	for (;;) {
		sig = sigwait(&sigs);
		if (sig < 0)
			continue;
		switch (sig) {
		case SIGQUIT:
		case SIGINT:
		case SIGTERM:
			do {
				ret = ioctl(iscsi_dev_handle,
				    ISCSI_SMF_OFFLINE, &rval);
				if (ret == -1) {
					/*
					 * Keep retrying if unable
					 * to stop
					 */
					(void) sleep(ISCSI_SMF_OFFLINE_DELAY);
					retry++;
				}
			} while ((ret == -1) &&
			    (retry < ISCSI_SMF_OFFLINE_MAX_RETRY_TIMES));
			(void) close(iscsi_dev_handle);
			if (rval == B_FALSE) {
				syslog(LOG_DAEMON, gettext("iSCSI initiator"
				    " service exited with sessions left."));
			}
			return (0);
		default:
			break;
		}
	}
}

/*
 * sigchld_handler -- SIGCHLD Handler
 *
 */
/* ARGSUSED */
static
void
sigchld_handler(
	int	sig
)
{
	int	status;
	pid_t	ret_pid;

	/* This is the default code. */
	iscsi_child_smf_exit_code = SMF_EXIT_ERR_OTHER;

	ret_pid = waitpid(iscsi_child_pid, &status, WNOHANG);

	if (ret_pid == iscsi_child_pid) {
		if (WIFEXITED(status)) {
			iscsi_child_smf_exit_code = WEXITSTATUS(status);
		}
	}
	(void) sem_post(&iscsi_child_sem);
}

/*
 * iscsi_child_door -- Child process door entry point
 *
 * This function is executed when a driver calls door_ki_upcall().
 */
/* ARGSUSED */
static
void
iscsi_child_door(
	void		*cookie,
	char		*args,
	size_t		alen,
	door_desc_t	*ddp,
	uint_t		ndid
)
{
	int		*ptr = (int *)args;

	iscsi_child_smf_exit_code = SMF_EXIT_ERR_OTHER;

	if (alen >= sizeof (iscsi_child_smf_exit_code)) {
		iscsi_child_smf_exit_code = *ptr;
	}
	(void) sem_post(&iscsi_child_sem);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * iscsi_kernel_door -- Kernel door entry point
 *
 * This function is executed when a driver calls door_ki_upcall().
 */
/* ARGSUSED */
static
void
iscsi_kernel_door(
	void		*cookie,
	char		*args,
	size_t		alen,
	door_desc_t	*ddp,
	uint_t		ndid
)
{
	iscsi_door_msg_hdr_t	err_ind;
	iscsi_door_req_t	*req;
	iscsi_door_cnf_t	*cnf;
	size_t			cnf_len;
	char			*err_txt;
	int			err_code;

	/* Local variables pre-initialization */
	err_ind.signature = ISCSI_DOOR_REQ_SIGNATURE;
	err_ind.version	  = ISCSI_DOOR_REQ_VERSION_1;
	err_ind.opcode	  = ISCSI_DOOR_ERROR_IND;

	req = (iscsi_door_req_t *)args;
	cnf = (iscsi_door_cnf_t *)&err_ind;
	cnf_len = sizeof (err_ind);

	/*
	 * The validity of the request is checked before going any farther.
	 */
	if (req == NULL) {
		/*
		 * A request has to be passed.
		 */
		err_ind.status = ISCSI_DOOR_STATUS_REQ_INVALID;
	} else if (alen < sizeof (iscsi_door_msg_hdr_t)) {
		/*
		 * The buffer containing the request must be at least as big
		 * as message header.
		 */
		err_ind.status = ISCSI_DOOR_STATUS_REQ_LENGTH;
	} else if (req->hdr.signature != ISCSI_DOOR_REQ_SIGNATURE) {
		/*
		 * The request must be correctly signed.
		 */
		err_ind.status = ISCSI_DOOR_STATUS_REQ_INVALID;
	} else if (req->hdr.version != ISCSI_DOOR_REQ_VERSION_1) {
		/*
		 * The version of the request must be supported by the server.
		 */
		err_ind.status = ISCSI_DOOR_STATUS_REQ_VERSION;
	} else {
		/*
		 * The request is treated according to the opcode.
		 */
		switch (req->hdr.opcode) {

		case ISCSI_DOOR_GETIPNODEBYNAME_REQ:
			cnf = _getipnodebyname_req(
			    &req->ginbn_req,
			    alen,
			    &cnf_len);
			break;
		default:
			err_ind.status = ISCSI_DOOR_STATUS_REQ_INVALID;
			break;
		}
	}
	err_code = door_return((char *)cnf, cnf_len, NULL, 0);

	switch (err_code) {
	case E2BIG:
		err_txt = "E2BIG";
		break;
	case EFAULT:
		err_txt = "EFAULT";
		break;
	case EINVAL:
		err_txt = "EINVAL";
		break;
	case EMFILE:
		err_txt = "EMFILE";
		break;
	default:
		err_txt = "?";
		break;
	}
	(void) fprintf(stderr, "door_return error(%s,%d)", err_txt, err_code);
	syslog(
	    LOG_DAEMON | LOG_ERR,
	    gettext("!door_return error(%s,%d)"),
	    err_txt,
	    err_code);
}

/*
 * _getipnodebyname_req
 *
 * This function executes the request ISCSI_DOOR_GETIPNODEBYNAME_REQ.  It
 * calls getipnodebyname() but doesn't return all the information.  The
 * confirmation structure only contains one IP address of the list returned
 * by getipnodebyname().
 */
static
iscsi_door_cnf_t *
_getipnodebyname_req(
	getipnodebyname_req_t	*req,
	int			req_len,
	size_t			*pcnf_len
) {
	getipnodebyname_cnf_t	*cnf = (getipnodebyname_cnf_t *)req;
	size_t			cnf_len;
	struct hostent		*hptr;
	char			*name;

	/* The opcode is changed immediately. */
	cnf->hdr.opcode = ISCSI_DOOR_GETIPNODEBYNAME_CNF;

	/* The size of the request is checked against the minimum required. */
	if (req_len < sizeof (getipnodebyname_cnf_t)) {
		cnf->hdr.status = ISCSI_DOOR_STATUS_REQ_FORMAT;
		*pcnf_len = req_len;
		return ((iscsi_door_cnf_t *)cnf);
	}

	name = (char *)req + req->name_offset;

	/*
	 * The pointer to the name has to stay inside the request but
	 * after the header.
	 */
	if ((name < ((char *)req + sizeof (getipnodebyname_req_t))) ||
	    ((name + req->name_length) > ((char *)req + req_len))) {
		cnf->hdr.status = ISCSI_DOOR_STATUS_REQ_FORMAT;
		*pcnf_len = req_len;
		return ((iscsi_door_cnf_t *)cnf);
	}

	/* The library function is called. */
	hptr = getipnodebyname(
			name,
			(int)req->af,
			(int)req->flags,
			(int *)&cnf->error_num);

	if (hptr) {
		/*
		 * The call was successful. Now starts the painful work of
		 * parsing the data.  However, for version 1 we will only
		 * return the first address.
		 */
		cnf_len = sizeof (getipnodebyname_cnf_t);
		cnf->h_size_needed = sizeof (getipnodebyname_cnf_t);
		cnf->h_alias_list_length = 0;
		cnf->h_alias_list_offset = 0;
		cnf->h_name_len = 0;
		cnf->h_name_offset = 0;

		cnf->h_addrlen = (uint32_t)hptr->h_length;
		cnf->h_addrtype = (uint32_t)hptr->h_addrtype;
		cnf->h_addr_list_offset = sizeof (getipnodebyname_cnf_t);

		if (*hptr->h_addr_list != NULL) {
			(void) memcpy(
				((char *)cnf + sizeof (getipnodebyname_cnf_t)),
				*hptr->h_addr_list,
				hptr->h_length);
			cnf->h_addr_list_length = 1;
			cnf->h_size_needed += cnf->h_addrlen;
			cnf_len += hptr->h_length;
		} else {
			cnf->h_addr_list_length = 0;
			cnf->h_size_needed += hptr->h_length;
		}
		*pcnf_len = cnf_len;
		cnf->hdr.status = ISCSI_DOOR_STATUS_SUCCESS;
		freehostent(hptr);
	} else {
		cnf->hdr.status = ISCSI_DOOR_STATUS_SUCCESS;
		cnf->h_addrlen = 0;
		cnf->h_addrtype = 0;
		cnf->h_addr_list_offset = sizeof (getipnodebyname_cnf_t);
		cnf->h_addr_list_length = 0;
		cnf->h_name_offset = sizeof (getipnodebyname_cnf_t);
		cnf->h_name_len = 0;
		cnf->h_alias_list_offset = sizeof (getipnodebyname_cnf_t);
		cnf->h_alias_list_length = 0;
		cnf->h_size_needed = sizeof (getipnodebyname_cnf_t);
		*pcnf_len = sizeof (getipnodebyname_cnf_t);
	}
	return ((iscsi_door_cnf_t *)cnf);
}

/*
 * call_child_door -- This function calls the child door with the value
 *		      provided by the caller.
 *
 */
static
void
call_child_door(
	int		value
)
{
	door_arg_t	door_arg;

	(void) memset(&door_arg, 0, sizeof (door_arg));
	door_arg.data_ptr = (char *)&value;
	door_arg.data_size = sizeof (value);
	(void) door_call(iscsi_child_door_handle, &door_arg);
}

/*
 * get_luns_count --
 */
static
uint32_t
get_luns_count(
	int		did
)
{
	iscsi_lun_list_t	*lun_list;
	iscsi_lun_list_t	*tmp;
	size_t			len;
	uint32_t		lun_count;

	lun_list = (iscsi_lun_list_t *)malloc(sizeof (*lun_list));

	(void) memset(lun_list, 0, sizeof (*lun_list));
	lun_list->ll_vers = ISCSI_INTERFACE_VERSION;
	lun_list->ll_in_cnt = 1;
	lun_list->ll_all_tgts = B_TRUE;

	for (;;) {

		if (ioctl(
		    did,
		    ISCSI_LUN_OID_LIST_GET,
		    lun_list) == -1) {
			free(lun_list);
			/* The Ioctl didn't go well. */
			return (0);
		}
		if (lun_list->ll_in_cnt >= lun_list->ll_out_cnt) {
			/* We got it all. */
			break;
		}
		/*
		 * We didn't get all the targets. Let's build a new Ioctl with
		 * a new size.
		 */
		tmp  = lun_list;
		len  = tmp->ll_out_cnt * sizeof (tmp->ll_luns);
		len += sizeof (*tmp) - sizeof (tmp->ll_luns);
		lun_list = (iscsi_lun_list_t *)malloc(len);
		if (lun_list == NULL) {
			/* No resources. */
			free(tmp);
			return (0);
		}
		(void) memset(lun_list, 0, len);
		lun_list->ll_vers = ISCSI_INTERFACE_VERSION;
		lun_list->ll_in_cnt = tmp->ll_out_cnt;
		lun_list->ll_all_tgts = B_TRUE;
		free(tmp);
	}
	lun_count = lun_list->ll_out_cnt;
	free(lun_list);
	return (lun_count);
}

/*
 * discovery_event_wait -- Waits for the discovery process to finish.
 *
 */
static
boolean_t
discovery_event_wait(
	int		did
)
{
	boolean_t		rc;
	uint32_t		lun_count;
	uint32_t		lun_timer;
	uint32_t		tmp;
	iSCSIDiscoveryMethod_t  discovery_flags;
	iSCSIDiscoveryMethod_t  discovery_all;

	rc = B_FALSE;
	lun_count = 0;
	lun_timer = 0;
	discovery_flags = 0;
	discovery_all = iSCSIDiscoveryMethodStatic |
	    iSCSIDiscoveryMethodSLP |
	    iSCSIDiscoveryMethodISNS |
	    iSCSIDiscoveryMethodSendTargets;

	for (;;) {

		/* The status discovery flags are read. */
		if (ioctl(
		    did,
		    ISCSI_DISCOVERY_EVENTS,
		    &discovery_flags) == -1) {
			/* IO problem */
			break;
		}

		if (discovery_flags == discovery_all) {
			/* Discovery over */
			rc = B_TRUE;
			break;
		}

		if (lun_timer >= ISCSI_DISCOVERY_POLL_DELAY2) {
			/* Let's check if the driver is making progress. */
			tmp = get_luns_count(did);
			if (tmp <= lun_count) {
				/* No progress */
				break;
			}
			lun_count = tmp;
			lun_timer = 0;
		}
		(void) sleep(ISCSI_DISCOVERY_POLL_DELAY1);
		lun_timer += ISCSI_DISCOVERY_POLL_DELAY1;
	}
	return (rc);
}

/*ARGSUSED*/
static void
signone(int sig, siginfo_t *sip, void *utp)
{
}
