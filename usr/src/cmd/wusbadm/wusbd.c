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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <stdio.h>
#include <signal.h>
#include <door.h>
#include <libsysevent.h>
#include <sys/sunddi.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <syslog.h>
#include <pthread.h>
#include <dirent.h>
#include <locale.h>
#include <alloca.h> /* alloca */
#include <errno.h>
#include <pwd.h>

#include <priv_utils.h>
#include <priv.h>

#include <sys/usb/usba/wusba_io.h>
#include <sys/usb/clients/wusb_ca/wusb_ca.h>
#include "crypto_util.h"
#include "wusbd.h"


/* deamon exit status code */
#define	CONFIG_ERROR	1
#define	FATAL_ERROR	2

#define	PKTOKEN 	"Sun Software PKCS#11 softtoken  "
#define	TOKENDIR 	"/etc/usb"

/* Restrict the max number association for one host to 200 */
#define	HOST_MAX	100
#define	DEV_MAX		200

/* global mutext for door service */
static pthread_mutex_t 	mutex_cclock = PTHREAD_MUTEX_INITIALIZER;
static void 		wusbd_daemon_enter();
static void 		wusbd_daemon_leave(char *, int);


static wusb_cc_list_t 	*global_cclist = NULL;
static	uint32_t	cc_cnt		= 0;
static wusb_cc_list_t 	*devids[HOST_MAX][DEV_MAX];


/* cc utility funcs */
static int 	save_cc(const wusb_cc_info_t *);
static int 	save_cc_to_list(const wusb_cc_info_t *);
static int 	save_cc_to_store(const wusb_cc_info_t *);


static void 	refresh(int);
static void 	event_handler(sysevent_t *);

/* daemon init functions */
static int 	wusbd_daemonize_init(void);
static void 	wusbd_daemonize_fini(int, int);
static int 	init_daemon_pid();
static int 	init_sys_evnt();
static int 	init_door_srv();
static int 	init_global_cc_list();
static void	print_prv();

static void 	exit_clean(int);

/* walk on all hosts in system */
typedef void (* host_func)(const char *);
static void 	all_hosts_iterate(host_func);


/* walk on all cc list */
typedef int (* cc_list_func)(wusb_cc_list_t *, void *);
static void 	global_list_iterate(cc_list_func, void *);
static void 	add_to_global_list(wusb_cc_list_t *);
static void 	remove_from_global_list(wusb_cc_list_t *);

/* update cc list device status */
static void  	clean_all_cc_list();
static void 	update_cc_list(const char *);
static void 	update_all_cc_list();
static int  	update_cc_file();

static int  	add_all_cc_to_host(const char *, uint8_t);
static int 	remove_cc_from_host(uint8_t, uint16_t);
static int	remove_all_cc_from_host(uint8_t);

static int  	create_host_cc(const char *);
static void 	check_host(const char *);
static void 	check_all_host();
static void 	stop_all_host();

/* cc list entry funcs */
static int  	clean_cc_list(wusb_cc_list_t *, void *);
static int  	print_cc_list(wusb_cc_list_t *, void *);
static int  	copy_cc_list(wusb_cc_list_t *, void *);
static int  	write_cc_list(wusb_cc_list_t *, void *);

/* door service utility funcs */
static void 	door_srv(void *, char *, size_t, door_desc_t *, uint_t);
static int	wusbd_check_auth(const char *);


/* daemon log utilities */
static void 	wusbd_info(const char *, ...);
static void 	wusbd_warn(const char *, ...);
static void 	wusbd_log(const char *, ...);

/* host-id / dev-id util funcs */
static uint8_t 	assign_host_id(void);
static uint16_t assign_dev_id(uint8_t);
static void 	free_dev_id(uint8_t, uint16_t);

static int	get_host_path(int, char *);

static int 	load_host_mac(const char *, uint8_t *);

/* searching helper funcs */
static int 		find_host_id(uint8_t *);
static wusb_cc_info_t 	*find_dev_cc(uint8_t, uint8_t *);
static wusb_cc_info_t 	*find_host_cc(uint8_t);
static void 		copy_list_back(char *);


/* enable/disable host funcs */
static int	start_host(const char *);
static int	stop_host(const char *);


/* remove dev funcs */
static int 	remove_one_dev(uint8_t, uint16_t);
static int 	remove_all_dev(uint8_t);

/* dev_ctrl check funcs */
static uint16_t check_dev_ctrl(wusb_dev_ctrl_t *);
static uint16_t check_host_ctrl(wusb_dev_ctrl_t *);

static int	wusbd_do_ca(const char *, const char *, wusb_cc_info_t *, char);
static int	wusbd_do_host(char *, size_t, door_desc_t *, uint_t, int);

/* cc generation methods */
static int 	generate_wusb_CDID(CK_SESSION_HANDLE, wusb_cc_t *);
static int 	generate_wusb_CK(CK_SESSION_HANDLE, wusb_cc_t *);
static int 	generate_wusb_CC(wusb_cc_t *);
static int 	generate_wusb_CHID(wusb_cc_t *, uint8_t *);

static int	wusbd_do_list(char *, size_t, door_desc_t *, uint_t);
static int	wusbd_do_association(char *, size_t, door_desc_t *, uint_t);
static int	wusbd_do_remove_host(char *, size_t, door_desc_t *, uint_t);
static int	wusbd_do_remove_dev(char *, size_t, door_desc_t *, uint_t);
static int	wusbd_do_enable_host(char *, size_t, door_desc_t *, uint_t);
static int	wusbd_do_disable_host(char *, size_t, door_desc_t *, uint_t);

typedef struct {
	const char *auth;
	int (* dfunc)(char *, size_t, door_desc_t *, uint_t);
} wusbd_door_func_t;
static wusbd_door_func_t dfuncs[] =
{
		{ WUSB_AUTH_READ,	wusbd_do_list		},
		{ WUSB_AUTH_MODIFY,	wusbd_do_association	},
		{ WUSB_AUTH_MODIFY,	wusbd_do_remove_dev	},
		{ WUSB_AUTH_HOST,	wusbd_do_remove_host	},
		{ WUSB_AUTH_HOST,	wusbd_do_enable_host	},
		{ WUSB_AUTH_HOST,	wusbd_do_disable_host	},
};


static void
wusbd_sig_handler(int sigval)
{
	wusbd_info("received signal %d\n", sigval);
	switch (sigval) {
		case 0:
		case SIGPIPE:
			wusbd_info("SIG PIPE received");
			break;

		case SIGHUP:
			wusbd_info("Refreshing dameon");
			/* Refresh config was triggered */
			refresh(sigval);
			break;

		default:
			(void) pthread_mutex_lock(&mutex_cclock);
			wusbd_info("Stop all host before exit");
			stop_all_host();
			(void) pthread_mutex_unlock(&mutex_cclock);
			exit_clean(0);
			break;
	}

}


/*
 * Daemon.
 *    use "--daemon" to start daemon
 */
void
daemonize() {

	int pfd = -1;

	struct sigaction	act;
	sigset_t		set;

	openlog("wusbd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);

	(void) sigfillset(&act.sa_mask);
	act.sa_handler = wusbd_sig_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGPIPE, &act, NULL);

	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGPIPE);

	pfd = wusbd_daemonize_init();

	wusbd_info("daemonize: start daemon ");
	if (pthread_mutex_init(&mutex_cclock, NULL) != 0) {
		wusbd_log("daemonize: mutext cclock init failed!");
		exit(FATAL_ERROR);
	}
	if (init_daemon_pid() < 0) {
		wusbd_log("daemonize: init daemon pid fail");
		goto fail;
	}
	if (init_global_cc_list() < 0) {
		wusbd_log("daemonize: init global cc fail");
		goto fail;
	}

	check_all_host();

	if (init_sys_evnt() < 0) {
		wusbd_log("daemonize: init sys evnt fail");
		goto fail;
	}

	if (init_door_srv() < 0) {
		wusbd_log("daemonize: init door serv fail");
		goto fail;
	}

	wusbd_daemonize_fini(pfd, 0);

	/*CONSTCOND*/
	while (1) {
		(void) pause();
	}
fail:

	exit_clean(FATAL_ERROR);
}

/* Respond client's list request. */
/*ARGSUSED*/
static int
wusbd_do_list(char *argp, size_t arg_size,
	door_desc_t *dp, uint_t n_desc)
{

	char *buf = NULL;
	size_t buflen = 0;

	uint16_t rval = WUSBADM_OK;
	wusbd_daemon_enter();

	/* update CC status */
	clean_all_cc_list();
	update_all_cc_list();

	/* 2 bytes command result */
	buflen += sizeof (uint16_t);

	/* 4 bytes cc list number */
	buflen += sizeof (uint32_t);

	/* length of all clists */
	buflen += sizeof (wusb_device_info_t) * cc_cnt;

	/* use alloca here */
	if ((buf = (char *)alloca(buflen)) == NULL) {
		wusbd_warn("wusb_do_list: alloca buffer failed");

		rval = WUSBADM_FAILURE;
		wusbd_daemon_leave((char *)&rval, sizeof (uint16_t));

		return (WUSBA_FAILURE);
	}
	bzero(buf, buflen);

	/* command result */
	(void) memcpy(buf, &rval, sizeof (uint16_t));

	/* cc number */
	(void) memcpy(buf + sizeof (uint16_t), &cc_cnt, sizeof (uint32_t));

	/* wusb_device_info_t * cc_cnt */
	copy_list_back(buf + sizeof (uint16_t) + sizeof (uint32_t));

	/* debug only */
	global_list_iterate(print_cc_list, NULL);

	/*
	 * Update the cc file because we may get the device type if
	 * device is connected
	 */
	(void) update_cc_file();

	wusbd_daemon_leave(buf, buflen);

	return (WUSBA_SUCCESS);

}

/* Respond client's associate request. */
/* ARGSUSED */
static int
wusbd_do_association(char *argp, size_t arg_size,
	door_desc_t *dp, uint_t n_desc)
{
	uint16_t rval = WUSBADM_OK;
	wusb_cc_info_t *host_cc = NULL;
	wusb_door_call_t *dcall;
	wusb_asso_ctrl_t *asso_ctrl;
	char host_path[MAXPATHLEN];

	/* get associate request */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dcall = (wusb_door_call_t *)argp;
	asso_ctrl = (wusb_asso_ctrl_t *)dcall->buf;

	wusbd_daemon_enter();

	/* check if host id exist */
	if ((host_cc = find_host_cc(asso_ctrl->host)) == NULL) {
		wusbd_warn("wusbd_do_association:asso_ctrl.host = %d err = %s",
		    asso_ctrl->host, strerror(errno));
		rval = WUSBADM_INVAL_HOSTID;
		goto done;
	}
	if (get_host_path(asso_ctrl->host, host_path) < 0) {
		wusbd_warn("wusbd_do_association:host = %d not attached",
		    asso_ctrl->host);
		rval = WUSBADM_HOST_NOT_ATTACH;
		goto done;
	}

	/* check if it is cable device */
	if (asso_ctrl->type != ASSO_TYPE_CABLE) {
		wusbd_warn("wusbd_do_association: asso_ctrl.type = %d",
		    asso_ctrl->type);
		rval = WUSBADM_NO_SUPPORT;
		goto done;
	}
	/* do assocation now */
	if (wusbd_do_ca(host_path, asso_ctrl->path,
	    host_cc, asso_ctrl->onetime) < 0) {
		wusbd_warn("wusbd_do_association: wusbd_do_ca failed");
		rval = WUSBADM_FAILURE;
		goto done;
	}

done:
	wusbd_daemon_leave((char *)&rval, sizeof (uint16_t));

	return (rval);
}

/* Respond client's remove-dev request. */
/* ARGSUSED */
static int
wusbd_do_remove_dev(char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc)
{
	wusb_door_call_t *dcall;
	wusb_dev_ctrl_t *rmctrl;
	uint16_t rval = WUSBADM_OK;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dcall = (wusb_door_call_t *)argp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	rmctrl = (wusb_dev_ctrl_t *)dcall->buf;

	wusbd_daemon_enter();

	if ((rval = check_dev_ctrl(rmctrl)) != WUSBADM_OK) {
		wusbd_warn("wusbd_do_remove_dev: dev-id = %d.%d failed",
		    rmctrl->host, rmctrl->dev);
		goto done;
	}

	if (rmctrl->dev) {
		/* remove only one device */
		if (remove_one_dev(rmctrl->host, rmctrl->dev) < 0) {
			wusbd_warn("wusbd_do_remove_dev: dev-id = %d.%d failed",
			    rmctrl->host, rmctrl->dev);
			rval = WUSBADM_FAILURE;
			goto done;
		}
	} else {
		/* remove all the device associated to the host */
		if (remove_all_dev(rmctrl->host) < 0) {
			wusbd_warn("wusbd_do_remove_dev: host-id = %d failed",
			    rmctrl->host);
			rval = WUSBADM_FAILURE;
			goto done;
		}
	}

	if (update_cc_file() < 0) {
		wusbd_warn("wusbd_do_remove_dev: update cc file failed");
		rval = WUSBADM_CCSTORE_ACC;
		goto done;
	}


done:
	wusbd_daemon_leave((char *)&rval, sizeof (uint16_t));

	return (rval);
}

/* Respond client's remove-host request. */
/* ARGSUSED */
static int
wusbd_do_remove_host(char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc)
{
	wusb_door_call_t *dcall;
	wusb_dev_ctrl_t *host_ctrl;
	uint16_t rval = WUSBADM_OK;

	char host_path[MAXPATHLEN];

	wusbd_daemon_enter();
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dcall = (wusb_door_call_t *)argp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	host_ctrl = (wusb_dev_ctrl_t *)dcall->buf;
	wusbd_info("wusbd_do_remove_host start: hostid = %d", host_ctrl->host);

	if ((rval = check_host_ctrl(host_ctrl)) != WUSBADM_OK) {
		wusbd_warn("wusbd_do_remove_host :host_ctrl->host = %d failed",
		    host_ctrl->host);
		goto done;
	}

	if (remove_all_dev(host_ctrl->host) < 0) {
		wusbd_warn("wusbd_do_remove_host :host_ctrl->host = %d failed",
		    host_ctrl->host);
		rval = WUSBADM_FAILURE;
		goto done;
	}

	if (get_host_path(host_ctrl->host, host_path) < 0) {
		wusbd_warn("wusbd_do_host:host_ctrl->host = %d not attached",
		    host_ctrl->host);
	} else {

		/*
		 * Stop host if possible, if the host can not
		 * be stoped we just remove the host cc from
		 * system, this means the host should be re-plugged
		 * before any new association since the CHID info is
		 * gone.
		 */
		if (stop_host(host_path) < 0) {
			wusbd_warn("wusbd_do_remove_host: host_path = %s",
			    host_path);
		}
	}

	/* remove the last CC for host */
	remove_from_global_list(devids[host_ctrl->host][0]);
	free_dev_id(host_ctrl->host, 0);

	if (update_cc_file() < 0) {
		wusbd_warn("wusbd_do_remove_host: update cc failed");
		rval = WUSBADM_CCSTORE_ACC;
		goto done;
	}
	wusbd_info("wusbd_do_remove_host complete ");

done:
	wusbd_daemon_leave((char *)&rval, sizeof (uint16_t));

	return (rval);


}

/* Respond client's enable-host request. */
static int
wusbd_do_enable_host(char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc)
{
	(void) wusbd_do_host(argp, arg_size, dp, n_desc, 1);

	return (WUSBA_SUCCESS);
}

/* Respond client's disable-host request. */
static int
wusbd_do_disable_host(char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc)
{
	(void) wusbd_do_host(argp, arg_size, dp, n_desc, 0);

	return (WUSBA_SUCCESS);
}

/*
 * wusbd_do_host is the only wrapper for any host related cmds.
 * It will call door_return, so it will
 * not return and its return val should be omitted by callers
 */
/* ARGSUSED */
static int
wusbd_do_host(char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc, int flag)
{
	wusb_door_call_t *dcall;
	wusb_dev_ctrl_t *host_ctrl;
	uint16_t rval = WUSBADM_OK;

	char host_path[MAXPATHLEN];

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dcall = (wusb_door_call_t *)argp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	host_ctrl = (wusb_dev_ctrl_t *)dcall->buf;

	wusbd_daemon_enter();
	if ((rval = check_host_ctrl(host_ctrl)) != WUSBADM_OK) {
		wusbd_warn("wusbd_do_host:  host-id = %d failed",
		    host_ctrl->host);
		goto done;
	}

	if (get_host_path(host_ctrl->host, host_path) < 0) {
		wusbd_warn("wusbd_do_host:host_ctrl->host = %d not attached",
		    host_ctrl->host);
		rval = WUSBADM_HOST_NOT_ATTACH;
		goto done;
	}

	wusbd_info("wusbd_do_host: host = %s flag = %d", host_path, flag);
	if (!flag) {
		if (stop_host(host_path) < 0) {
			wusbd_warn("wusbd_do_host: host_path = %s stop failed",
			    host_path);
			rval = WUSBADM_HOST_NOT_ATTACH;
			goto done;
		}
	} else {
		(void) add_all_cc_to_host(host_path, host_ctrl->host);
		/* start the host */
		if (start_host(host_path) < 0) {
			wusbd_warn("wusbd_do_host: host = %s start failed",
			    host_path);
			rval = WUSBADM_HOST_NOT_ATTACH;
			goto done;
		}

	}

done:
	wusbd_daemon_leave((char *)&rval, sizeof (uint16_t));

	return (rval);


}
/*
 * door server handler
 * Do not allocate memory dynamically in this function. Upon
 * door_return(), the server is blocked in the kernel context. No
 * place to free that memory. see
 * http://blogs.sun.com/tucker/entry/door_api_details
 */
/* ARGSUSED */
static void
door_srv(void *cookie, char *argp, size_t arg_size,
		door_desc_t *dp, uint_t n_desc)
{
	wusb_door_call_t *dcall;

	uint16_t rval = WUSBADM_FAILURE;

	/* check if it is an valid wusb door call */
	if (argp == NULL || arg_size != sizeof (wusb_door_call_t)) {

		wusbd_warn("door_srv: argp = 0x%p arg_size = %d",
		    argp, arg_size);
		rval = WUSBADM_FAILURE;
		goto fail;
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	dcall = (wusb_door_call_t *)argp;

	if (dcall->cmdss >= (sizeof (dfuncs)/sizeof (wusbd_door_func_t))) {
		wusbd_warn("door_srv: dcall->cmdss = %d",
		    dcall->cmdss);
		rval = WUSBADM_NO_SUPPORT;

		goto fail;
	}

	/* chk auths should be done first for any cmd */
	if (wusbd_check_auth(dfuncs[dcall->cmdss].auth) < 0) {
		wusbd_warn("door_srv: cmdss = %d, auth = %s",
		    dcall->cmdss, dfuncs[dcall->cmdss].auth);
		rval = WUSBADM_AUTH_FAILURE;

		goto fail;
	}


	/*
	 * Any wusbd_do_xx will return the door service
	 */
	dfuncs[dcall->cmdss].dfunc(argp, arg_size, dp, n_desc);

	return;

fail:
	(void) door_return((char *)&rval, sizeof (uint16_t), NULL, 0);

}

/*
 * Check the status of every CC. And update it in the list so that
 * client can know if it's connected/disconnected.
 */
static void
update_cc_list(const char *host)
{
	uint8_t mac[WUSB_DEV_MAC_LENGTH];
	wusb_hc_get_dstate_t dstate;
	wusb_cc_list_t *list = NULL;
	int hostid = 0;
	int hstate = -1;
	int fd = -1;
	int i;

	wusbd_info("update_cc_list: host = %s", host);
	if (load_host_mac(host, mac) < 0) {
		wusbd_warn("update_cc_list: host = %s failed", host);

		return;
	}

	if ((hostid = find_host_id(mac)) == 0) {

		return;
	}

	if ((fd = open(host, O_RDONLY)) == -1) {
		wusbd_warn("update_cc_list: host = %s, err =  %s",
		    host, strerror(errno));

		return;
	}

	/* update host states */
	if (ioctl(fd, WUSB_HC_GET_HSTATE, &hstate) < 0) {
		wusbd_warn("update_cc_list: WUSB_HC_GET_HSTATE, err =  %s",
		    strerror(errno));
		(void) close(fd);

		return;
	}

	list = devids[hostid][0];
	list->stat = hstate;

	bzero(&dstate, sizeof (wusb_hc_get_dstate_t));

	for (i = 1; i < DEV_MAX; i++) {
		if ((list = devids[hostid][i]) == NULL) {
			continue;
		}
		(void) memcpy(dstate.cdid, list->info.cc.CDID, 16);
		if (ioctl(fd, WUSB_HC_GET_DSTATE, &dstate) == 0) {
			list = devids[hostid][i];
			list->stat = dstate.state;
			if (dstate.state == WUSB_STATE_CONFIGURED) {
				(void) snprintf(list->info.type, WUSB_TYPE_LEN,
				    "%s", dstate.nodename);
			}
			wusbd_info("update_cc_list: type = %s, state = %d",
			    dstate.nodename, dstate.state);
		}

	}

	(void) close(fd);
}
/* find the host cc infor with host id */
static wusb_cc_info_t *
find_host_cc(uint8_t host_id)
{
	wusb_cc_list_t *list = NULL;

	if (host_id == 0 || host_id >= HOST_MAX) {

		return (NULL);
	}

	list = devids[host_id][0];

	return (list? &(list->info):NULL);
}

/* find the device CDID with host id */
static wusb_cc_info_t *
find_dev_cc(uint8_t host_id, uint8_t *CDID)
{
	wusb_cc_list_t *list = NULL;
	int j = 0;

	for (j = 1; j < DEV_MAX; j++) {
		list = devids[host_id][j];
		if (list && (memcmp(list->info.cc.CDID, CDID, 16) == 0)) {

			return (&list->info);
		}
	}
	return (NULL);
}

/* find the host id with mac address */
static int
find_host_id(uint8_t *mac)
{
	wusb_cc_list_t *list = NULL;
	int i = 0;

	for (i = 1; i < HOST_MAX; i++) {
		list = devids[i][0];
		if (list && memcmp(mac,
		    list->info.mac, WUSB_DEV_MAC_LENGTH) == 0) {
			return (i);
		}
	}

	return (0);
}

/* Save the cc infor from dame to /etc/usb/wusbcc */
static int
update_cc_file()
{
	int ccfd = -1;

	if ((ccfd = open(WUSB_CC, O_RDWR|O_TRUNC)) < 0) {
		wusbd_warn("update_cc_file: CC store file = %s, %s",
		    WUSB_CC, strerror(errno));

		return (WUSBA_FAILURE);
	}

	global_list_iterate(write_cc_list, &ccfd);
	(void) close(ccfd);

	return (WUSBA_SUCCESS);

}
/*
 * ca_****: Cable Assocation helpers
 * to setup an association for host and device
 */
static int
ca_get_info(int fd, wusb_cbaf_asso_info_t *first)
{
	bzero(first, sizeof (wusb_cbaf_asso_info_t));
	if (0 != ioctl(fd, CBAF_IOCTL_GET_ASSO_INFO, first)) {
		wusbd_warn("ca_get_info: CBAF_IOCTL_GET_ASSO_INFO: err = %s",
		    strerror(errno));

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

static int
ca_set_host(int fd, wusb_cc_info_t *info)
{
	wusb_cbaf_host_info_t host_info;

	host_info.AssociationTypeId = 1;
	host_info.AssociationSubTypeId = 0;
	host_info.LangID = 0;

	(void) memcpy(host_info.CHID, info->cc.CHID, 16);
	(void) memset(host_info.HostFriendlyName, 0, 64);

	mac_to_label(info->mac, host_info.HostFriendlyName);

	if (0 != ioctl(fd, CBAF_IOCTL_SET_HOST_INFO, &host_info)) {
		wusbd_warn("ca_set_host: CBAF_IOCTL_SET_HOST_INFO: err = %s",
		    strerror(errno));

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

static int
ca_get_req(int fd, wusb_cbaf_asso_info_t *first)
{
	void *ca_buf;
	wusb_cbaf_asso_info_t *ca_info;

	wusbd_info("ca_get_req: NumAssociates = %d",
	    first->NumAssociationRequests);

	ca_buf =  malloc(sizeof (wusb_cbaf_asso_info_t) +
	    first->NumAssociationRequests * sizeof (wusb_cbaf_asso_req_t));

	if (ca_buf == NULL) {
		wusbd_warn("ca_get_req: ca_buf = NULL");

		return (WUSBA_FAILURE);
	}

	ca_info = (wusb_cbaf_asso_info_t *)ca_buf;
	(void) memcpy(ca_info, first, sizeof (wusb_cbaf_asso_info_t));

	if (0 != ioctl(fd, CBAF_IOCTL_GET_ASSO_REQS, ca_buf)) {
		wusbd_warn("ca_get_req: CBAF_IOCTL_GET_ASSO_REQS: err = %s",
		    strerror(errno));
		free(ca_info);

		return (WUSBA_FAILURE);
	}
	/* currently not used */
	free(ca_buf);

	return (WUSBA_SUCCESS);

}

static int
ca_get_devinfo(int fd, wusb_cbaf_device_info_t *device_info)
{
	bzero(device_info, sizeof (wusb_cbaf_device_info_t));
	if (0 != ioctl(fd, CBAF_IOCTL_GET_DEVICE_INFO, device_info)) {
		wusbd_warn("ca_get_dev failed");

		return (WUSBA_FAILURE);
	}
	wusbd_info("ca_get_devinfo: DeviceFriendlyName =  %s",
	    device_info->DeviceFriendlyName);
	wusbd_info("ca_get_devinfo: bandgroup = %d",
	    device_info->BandGroups);
	wusbd_info("ca_get_devinfo: LangID = %d",
	    device_info->LangID);

	print_array("CDID from device", device_info->CDID, 16);

	return (WUSBA_SUCCESS);
}

static int
ca_connect_cc(int fd, wusb_cc_info_t *newinfo,
		wusb_cbaf_device_info_t *device_info)
{
	wusb_cbaf_cc_data_t cc_data;

	cc_data.AssociationTypeId = 1;
	cc_data.AssociationSubTypeId = 1;
	cc_data.Length = WUSB_CC_DATA_SIZE;
	cc_data.BandGroups = device_info->BandGroups;
	(void) memcpy(&(cc_data.CC), &(newinfo->cc), sizeof (wusb_cc_t));


	if (0 != ioctl(fd, CBAF_IOCTL_SET_CONNECTION, &cc_data)) {
		wusbd_warn("ca_connect_cc: CBAF_IOCTL_SET_CONNECTION: err = %s",
		    strerror(errno));

		return (WUSBA_FAILURE);
	}
	print_array("New CC to device", cc_data.CC.CHID, 48);

	return (WUSBA_SUCCESS);
}

static int
ca_create_cc(wusb_cc_info_t *newinfo, wusb_cc_info_t *host_cc)
{
	(void) memcpy(newinfo->cc.CHID, host_cc->cc.CHID, 16);

	if (generate_wusb_CC(&(newinfo->cc)) < 0) {
		wusbd_warn("ca_create_cc: generate cc failed!");

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

static int
ca_add_cc(wusb_cc_info_t *newinfo, const char *filename)
{
	int fd = -1;
	int hstate = -1;

	wusbd_info("ca_add_cc: filename = %s start", filename);

	if ((fd = open(filename, O_RDONLY)) == -1) {
		wusbd_warn("ca_add_cc: filename = %s, err = %s",
		    filename, strerror(errno));

		return (WUSBA_FAILURE);
	}
	if (ioctl(fd, WUSB_HC_ADD_CC, &(newinfo->cc)) != 0) {
		wusbd_warn("ca_add_cc: ioctl = WUSB_HC_ADD_CC, err = %s",
		    strerror(errno));
		goto fail;
	}
	if (ioctl(fd, WUSB_HC_GET_HSTATE, &hstate) < 0) {
		wusbd_warn("ca_add_cc: ioctl = WUSB_HC_GET_HSTATE, err =  %s",
		    strerror(errno));
		goto fail;
	}
	if (hstate != WUSB_HC_STARTED) {
		if (ioctl(fd, WUSB_HC_START, WUSB_HC_INITIAL_START) == -1) {
			wusbd_warn("ca_add_cc: ioctl = WUSB_HC_START, err = %s",
			    strerror(errno));
			goto fail;
		}
	}

	(void) close(fd);

	print_array("New CC to host", newinfo->cc.CHID, 48);

	return (WUSBA_SUCCESS);

fail:
	(void) close(fd);

	return (WUSBA_FAILURE);
}

static int
ca_save_cc(wusb_cc_info_t *newinfo, wusb_cc_info_t *hostinfo)
{
	newinfo->host = hostinfo->host;
	if ((newinfo->dev  = assign_dev_id(newinfo->host)) == 0) {
		wusbd_warn("ca_save_cc: host-id:%d", newinfo->host);

		return (WUSBA_FAILURE);
	}

	if (save_cc(newinfo) < 0) {
		wusbd_warn("ca_save_cc: save cc failed");

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

static int
wusbd_do_ca(const char *host_path, const char *ca_dev,
		wusb_cc_info_t *host_cc, char onetime)
{
	wusb_cbaf_asso_info_t first;
	wusb_cbaf_device_info_t device_info;
	wusb_cc_info_t newinfo;
	int fd;
	wusb_cc_info_t *old_cc = NULL;

	wusbd_info("wusbd_do_ca start\n");
	/* IMPORTANT: Do NOT open it with O_RDWR */
	fd = open(ca_dev, O_RDONLY);
	if (fd == -1) {
		wusbd_warn("wusbd_do_ca: ca_dev = %s err = %s", ca_dev,
		    strerror(errno));

		return (WUSBA_FAILURE);
	}
	/*
	 * The first parts to set up a cable associaiton.
	 * Refer to: [Association Models Supplement to the
	 * Certified Wireless Universal Serial Bus Specification]
	 * chapter 4.
	 *
	 * 1. Send GET_ASSOCIATION_INFORMATION to the cable device
	 * and get the number of association requests.
	 *
	 * 2. Send GET_ASSOCIATION_INFORMATION again to get the
	 * all the association requests.
	 *
	 * 3. Send SET_ASSOCIATION_RESPONSE with the host CHID
	 *
	 * 4. Send GET_ASSOCIATION_REQUEST to get the exisiting CC
	 * infor from the device.
	 *
	 */
	if (ca_get_info(fd, &first) < 0) {
		wusbd_warn("wusbd_do_ca: get asso info failed!");
		goto cleanup;
	}
	if (ca_get_req(fd, &first) < 0) {
		wusbd_warn("wusbd_do_ca: get asso req failed!");
		goto cleanup;
	}
	if (ca_set_host(fd, host_cc)) {
		wusbd_warn("wusbd_do_ca: set host info failred");
		goto cleanup;
	}
	if (ca_get_devinfo(fd, &device_info)) {
		wusbd_warn("wusbd_do_ca: get device infor failed");
		goto cleanup;
	}


	(void) snprintf(newinfo.type, WUSB_TYPE_LEN, "unknown");
	newinfo.flag = onetime;

	/*
	 * The second part to setup cable association.
	 *
	 * 1. Create a CC from exsiting host_cc for the devices
	 *
	 * 2. Send new cc to the cable device to save in its hardware
	 *
	 * 3. Add new cc to the host controller
	 *
	 * 4. Save the cc to the cc list and cc store file
	 *
	 * Done!
	 */
	if (ca_create_cc(&newinfo, host_cc) < 0) {
		wusbd_warn("wusbd_do_ca: ca create cc failed!");
		goto cleanup;
	}
	/*
	 * Check if CDID exist in the host cc list, if so, We need to update
	 * the exisiting cc infor with a new ck, do the association with the
	 * updated cc.
	 * See "Association Models Supplement to the WUSB Specification"
	 * Chapter 4
	 */
	old_cc = find_dev_cc(host_cc->host, device_info.CDID);
	if (old_cc) {
		wusbd_warn("wusbd_do_ca: Association exist, use old CDID");
		(void) remove_cc_from_host(old_cc->host, old_cc->dev);

		/* update old cc with the new ck and copy back */
		(void) memcpy(old_cc->cc.CK, newinfo.cc.CK, 16);
		(void) memcpy(&(newinfo.cc), &(old_cc->cc), sizeof (wusb_cc_t));
	}
	if (ca_connect_cc(fd, &newinfo, &device_info) < 0) {
		wusbd_warn("wusbd_do_ca: ca connect cc failed!");
		goto cleanup;
	}

	(void) close(fd);

	if (ca_add_cc(&newinfo, host_path) < 0) {
		wusbd_warn("wusbd_do_ca: ca add cc failed!");

		return (WUSBA_FAILURE);
	}

	if (!old_cc) {
		/* a new cc save to file */
		if (ca_save_cc(&newinfo, host_cc) < 0) {
			wusbd_warn("wusbd_do_ca: ca save cc failed!");

			return (WUSBA_FAILURE);
		}
	} else {
		/* Just update the cc file */
		if (update_cc_file() < 0) {
			wusbd_warn("wusbd_do_ca: update old cc failed");

			return (WUSBA_FAILURE);
		}
	}

	wusbd_info("wusbd_do_ca: Set cable connection complete!");

	return (WUSBA_SUCCESS);

cleanup:
	(void) close(fd);

	return (WUSBA_FAILURE);
}
/*
 * wusb cc infor generation helpers
 * generate_wusb_CC: Generate CC infor for a device and host
 * generate_wusb_CHID: Generate CHID for a host
 * generate_wusb_CDID: Generate CDID for a device
 * generate_wusb_CK  : Generate CK for an assocation
 */

static int
generate_wusb_CC(wusb_cc_t *cc)
{
	CK_SESSION_HANDLE pkhandle;
	KMF_HANDLE_T kmfhandle;
	int rval = WUSBA_SUCCESS;
	wusbd_info("generate_wusb_CC: start");

	if (wusb_crypto_init(&kmfhandle, &pkhandle, PKTOKEN, TOKENDIR) != 0) {
		wusbd_warn("generate_wusb_CC: Crypto init failed");

		return (WUSBA_FAILURE);
	}
	if (generate_wusb_CDID(pkhandle, cc) < 0) {
		wusbd_warn("generate_wusb_CC: crate cdid failed");
		rval = WUSBA_FAILURE;

		goto done;
	}
	if (generate_wusb_CK(pkhandle, cc) < 0) {
		wusbd_warn("generate_wusb_CC: crate ck failed");
		rval = WUSBA_FAILURE;

		goto done;
	}
done:
	wusb_crypto_fini(kmfhandle);

	wusbd_info("generate_wusb_CC: complete");

	return (rval);
}


static int
generate_wusb_CHID(wusb_cc_t *cc, uint8_t *mac)
{
	/*
	 * CHID construction :
	 * 0 - 5  : MAC serial
	 * 6 - 7  : arbitrary
	 * 8 - 15 : random from seed = (MAC..) || (hostid||time)) || hrtime
	 */
	uint8_t *p = cc->CHID;
	uint8_t seed[24];
	time_t tt;
	uint64_t prod, hrtime;
	int rval = WUSBA_SUCCESS;

	KMF_HANDLE_T kmfhandle;
	CK_SESSION_HANDLE pkhandle;

	wusbd_info("generate_wusb_CHID: start");
	if (wusb_crypto_init(&kmfhandle, &pkhandle, PKTOKEN, TOKENDIR) != 0) {
		wusbd_warn("generate_wusb_CHID: Crypto init failed");
		rval = WUSBA_FAILURE;
		goto done;
	}

	(void) memcpy(p, mac, WUSB_DEV_MAC_LENGTH);
	p += 8;

	(void) time(&tt);
	prod = gethostid();
	prod = (prod << 32) | tt;
	hrtime = gethrtime();

	(void) memcpy(seed, cc->CHID, 8);
	(void) memcpy(seed + 8, &prod, 8);
	(void) memcpy(seed + 16, &hrtime, 8);

	if (wusb_random(pkhandle, seed, 24, p, 8) < 0) {
		wusbd_warn("generate_wusb_CHID: random failed");
		rval = WUSBA_FAILURE;
	}
	wusb_crypto_fini(kmfhandle);
	wusbd_info("generate_wusb_CHID complete");
done:

	return (rval);
}

static int
generate_wusb_CDID(CK_SESSION_HANDLE pkhandle, wusb_cc_t *cc)
{
	/* TODO : need better generation mechanism */
	return (wusb_random(pkhandle, NULL, 0, cc->CDID, 16));

}

static int
generate_wusb_CK(CK_SESSION_HANDLE pkhandle,  wusb_cc_t *cc)
{
	/* TODO : need better generation mechanism */
	return (wusb_random(pkhandle, NULL, 0, cc->CK, 16));
}

/* Log to dmesg and smf log */
static void
wusbd_warn(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	va_start(alist, format);
	(void) fprintf(stderr, gettext("[WUSBD]"));
	(void) vfprintf(stderr, format, alist);
	(void) fputc('\n', stderr);
	va_end(alist);
}
static void
wusbd_log(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	va_start(alist, format);
	(void) vsyslog(LOG_WARNING, format, alist);
	va_end(alist);
}


/* Log to smf log in DEBUG version */
/* ARGSUSED */
static void
wusbd_info(const char *format, ...)
{
#ifdef DEBUG
	va_list alist;

	format = gettext(format);
	va_start(alist, format);
	(void) fprintf(stderr, gettext("[WUSBD]"));
	(void) vfprintf(stderr, format, alist);
	(void) fputc('\n', stderr);
	va_end(alist);
#endif
}

/*
 * Find an unused host id and return it.
 * The wusbadm use two digits to represent a host. This means
 * hostid can't be greater than 99.
 */
static uint8_t
assign_host_id(void)
{
	uint8_t i;
	for (i = 1; i < HOST_MAX; i++) {
		if (devids[i][0] == 0) {
			wusbd_info("assign_host_id:  rval = %d", i);

			return (i);
		}
	}

	return (0); /* illegal value */
}

/*
 * traverse the CC store, search in the specified host,
 * find an unused device id, return it.
 * The wusbadm use 3 digits to represent a device. This means
 * devid can't be greater than 999.
 */
static uint16_t
assign_dev_id(uint8_t hostid)
{
	uint16_t i;
	if (hostid >= HOST_MAX) {

		return (0);
	}
	for (i = 1; i < DEV_MAX; i++) {
		if (devids[hostid][i] == 0) {
			wusbd_info("assign_dev_id: devid = %d.%d", hostid, i);

			return (i);
		}
	}

	return (0); /* illegal value */
}

/* Release a dev id, eg: remove dev */
static void
free_dev_id(uint8_t hostid, uint16_t devid)
{
	if (hostid >= HOST_MAX || devid >= DEV_MAX) {

		return;
	}
	devids[hostid][devid] = 0;
}

/*
 * init_door_srv.
 * Create the door file and attach door service
 * to the door file
 */
static int
init_door_srv()
{
	int fd, dd;

	(void) fdetach(DOOR_FILE);
	(void) unlink(DOOR_FILE);

	if ((dd = door_create(door_srv, 0, 0)) < 0) {
		wusbd_warn("init_door_srv: door_creat: err = %s",
		    strerror(errno));

		goto fail;
	}
	if ((fd = creat(DOOR_FILE, S_IRUSR | S_IRGRP | S_IROTH)) < 0) {
		wusbd_warn("init_door_srv: creat: err = %s",
		    strerror(errno));

		goto fail;
	}

	(void) close(fd);

	wusbd_info("init_door_srv: file = %s created", DOOR_FILE);

	if (fattach(dd, DOOR_FILE) < 0) {
		wusbd_warn("init_door_srv: fattach err = %s",
		    strerror(errno));

		goto fail;
	}

	return (WUSBA_SUCCESS);
fail:

	return (WUSBA_FAILURE);
}


/* Print a cc list entry */
/* ARGSUSED */
static int
print_cc_list(wusb_cc_list_t *list, void *data)
{
	wusbd_info("list:%x", list);
	wusbd_info("\thostid:%x", list->info.host);
	wusbd_info("\tdevid:%x", list->info.dev);

	return (WUSBA_SUCCESS);
}

/* write a cc list entry back to file fd */
static int
write_cc_list(wusb_cc_list_t *list, void *data)
{
	int ccfd =  *((int *)data);
	wusbd_info("write_cc_list: host-id = %d dev-id = %d",
	    list->info.host, list->info.dev);

	if (list->info.flag) {

		return (WUSBA_SUCCESS);
	}
	if (write(ccfd, &(list->info), sizeof (wusb_cc_info_t)) !=
	    sizeof (wusb_cc_info_t)) {
		wusbd_warn("write_cc_list: write err = %s ",
		    strerror(errno));

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

/* clean up the status of the cc list entry */
/* ARGSUSED */
static int
clean_cc_list(wusb_cc_list_t *list, void *data)
{
	list->stat = list->info.dev? DEV_STAT_DISCONN:WUSB_HC_DISCONNTED;

	return (WUSBA_SUCCESS);
}

/* copy a cc list entry to a device info buffer */
static int
copy_cc_list(wusb_cc_list_t *list, void *data)
{
	char **buf 	= (char **)data;

	wusb_device_info_t devinfo;
	devinfo.dev 	= list->info.dev;
	devinfo.host 	= list->info.host;
	devinfo.stat 	= list->stat;

	(void) snprintf(devinfo.type, WUSB_TYPE_LEN, "%s", list->info.type);
	(void) memcpy(*buf, &devinfo, sizeof (wusb_device_info_t));

	*buf += sizeof (wusb_device_info_t);

	return (WUSBA_SUCCESS);

}

/* save cc to list and file */
static int
save_cc(const wusb_cc_info_t *ccinfo)
{
	/* save CC to file */
	if (save_cc_to_store(ccinfo) < 0) {
		wusbd_warn("save_cc: Failed to save CC to file");

		return (WUSBA_FAILURE);
	}

	/* save cc to global list */
	if (save_cc_to_list(ccinfo) < 0) {
		wusbd_warn("save_cc: Failed to save CC to list");

		return (WUSBA_FAILURE);

	}

	return (WUSBA_SUCCESS);
}

/* create cc list entry and add to global list */
static int
save_cc_to_list(const wusb_cc_info_t *ccinfo)
{
	wusb_cc_list_t *newlist =
	    (wusb_cc_list_t *)malloc(sizeof (wusb_cc_list_t));
	if (newlist == NULL) {
		wusbd_warn("save_cc_to_list: newlist = NULL");

		return (WUSBA_FAILURE);
	}
	bzero(newlist, sizeof (wusb_cc_list_t));
	(void) memcpy(&(newlist->info), ccinfo, sizeof (wusb_cc_info_t));
	devids[ccinfo->host][ccinfo->dev] = newlist;

	add_to_global_list(newlist);

	return (WUSBA_SUCCESS);

}

/* save cc info to the host */
static int
save_cc_to_store(const wusb_cc_info_t *ccinfo)
{
	int rval = WUSBA_FAILURE;
	int ccfd = -1;

	/*
	 * If a device association is just used for one time
	 * we will not save it to the store file. See wusbadm(1)
	 */
	if (ccinfo->flag) {

		return (WUSBA_SUCCESS);
	}

	/* open cc file */
	if ((ccfd = open(WUSB_CC, O_RDWR)) < 0) {
		wusbd_warn("save_cc_to_store:CC file = %s, err = %s",
		    WUSB_CC, strerror(errno));
		goto done;
	}

	/* seek to the end of the file */
	if ((rval = lseek(ccfd, 0, SEEK_END)) == (offset_t)-1) {
		wusbd_warn("save_cc_to_store: seek fail err = %s",
		    strerror(errno));
		(void) close(ccfd);
		goto done;
	}

	/* save ccinfo to cc file */
	if ((rval = write(ccfd, ccinfo, sizeof (wusb_cc_info_t))) !=
	    sizeof (wusb_cc_info_t)) {
		wusbd_warn("write to store fail: %s - %d",
		    strerror(errno), rval);
		(void) close(ccfd);
		goto done;
	}

	(void) close(ccfd);
	rval = WUSBA_SUCCESS;

done:
	wusbd_info("save_cc_to_store: complete");

	return (rval);

}
/*
 * load all the cc to the host controller
 *     1. walk thru the cc list and find the device cc info
 *        related to this host.
 *     2. add the cc to the host controller
 *     3. start the host controller
 */
static int
add_all_cc_to_host(const char *host_path, uint8_t hostid)
{
	wusb_cc_list_t *list = NULL;
	int fd = -1;
	int j = 0;
	wusbd_warn("add_all_cc_to_host: host = %s", host_path);
	/* open host file */
	if ((fd = open(host_path, O_RDONLY)) == -1) {
		wusbd_warn("add_all_cc_to_host: host = %s err = %s",
		    host_path, strerror(errno));

		return (WUSBA_FAILURE);
	}

	/* Find all the device cc and add cc to host controler */
	for (j = 0; j < DEV_MAX; j++) {
		if ((list = devids[hostid][j]) == NULL) {
			continue;
		}
		if (ioctl(fd, WUSB_HC_ADD_CC, &list->info.cc) == -1) {
			wusbd_warn(" add_all_cc_to_host: ioctl = WUSB_HC_ADD_CC"
			    "hostid = %d, fail  ", hostid);
			(void) close(fd);

			return (WUSBA_FAILURE);
		}
	}

	(void) close(fd);

	wusbd_info("add_all_cc_to_host complete");

	return (WUSBA_SUCCESS);
}

/* Remove all the cc infor from a host device */
static int
remove_all_cc_from_host(uint8_t hostid)
{
	int fd = -1;
	int rval = 0;
	char host_path[MAXPATHLEN];

	if (get_host_path(hostid, host_path) < 0) {
		wusbd_warn("remove_all_cc_from_host:hostid = %d not attached",
		    hostid);

		return (WUSBA_FAILURE);
	}


	if ((fd = open(host_path, O_RDONLY)) == -1) {
		wusbd_warn("remove_all_cc_from host: host = %s err = %s",
		    host_path, strerror(errno));

		return (WUSBA_FAILURE);
	}
	rval = ioctl(fd, WUSB_HC_STOP, WUSB_HC_REM_ALL_CC | WUSB_HC_FINAL_STOP);

	if (rval < 0) {
		wusbd_warn("remove_all_cc_from_host: WUSB_HC_STOP: err = %s",
		    strerror(errno));
		(void) close(fd);

		return (WUSBA_FAILURE);
	}
	(void) close(fd);

	return (WUSBA_SUCCESS);
}
/*
 * Initialize the global cc list from the store file
 * "/etc/usb/wusbcc", the hostid/devid would also be
 * set in the global devids
 */
static int
init_global_cc_list(void)
{
	wusb_cc_list_t *list = NULL;
	char buf[sizeof (wusb_cc_list_t) + 1];
	int ccfd = -1;

	bzero(devids, HOST_MAX * DEV_MAX * sizeof (wusb_cc_list_t *));

	/*
	 * open the cc file. when daemon starts for the first time
	 * cc file will be created in /etc/usb, all the wusb host
	 * and device Conection Context informaion is stored in this
	 * file. global cc list is the map in the dameon for the
	 * file.
	 */
	wusbd_info("init_global_cc_list: load cc from %s", WUSB_CC);
	if ((ccfd = open(WUSB_CC, O_RDWR|O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
		wusbd_warn("init_global_cc_list: CC store file = %s, err = %s",
		    WUSB_CC, strerror(errno));

		goto fail;
	}

	(void) lseek(ccfd, 0, SEEK_SET);

	/* initialize globle cc list from cc file */
	while ((read(ccfd, buf, sizeof (wusb_cc_info_t))) > 0) {

		list = (wusb_cc_list_t *)calloc(sizeof (wusb_cc_list_t), 1);

		if (list == NULL) {
			wusbd_warn("init_global_cc_list: list = NULL");
			(void) close(ccfd);
			goto fail;
		}

		(void) memcpy(&(list->info), buf, sizeof (wusb_cc_info_t));

		/* set devids */
		devids[list->info.host][list->info.dev] = list;

		/* add the list to the global cc list */
		add_to_global_list(list);
	}
	(void) close(ccfd);

	return (WUSBA_SUCCESS);
fail:

	return (WUSBA_FAILURE);
}

/* destroy the global CC list */
static void
destroy_global_cc_list(void)
{
	wusb_cc_list_t *list = NULL;
	wusb_cc_list_t *next = NULL;

	for (list = global_cclist; list; list = next) {
		next = list->next;
		free(list);
		cc_cnt--;
	}
	global_cclist = NULL;
	wusbd_info("destroy_global_cc_list: cc_cnt = %d", cc_cnt);
	cc_cnt = 0;
	bzero(devids, HOST_MAX * DEV_MAX * sizeof (wusb_cc_list_t *));
}

/*
 * Add a new list to the global cc list.
 * The new cc list will be inserted in an hostid/devid
 * incremental order.
 */
static void
add_to_global_list(wusb_cc_list_t *list)
{

	wusb_cc_list_t *tmp;
	wusb_cc_list_t *next;


	wusbd_info("add_to_global_list: start");
	wusbd_info("host-id = %d, dev-id = %d, type = %s",
	    list->info.host, list->info.dev, list->info.type);

	/* first cc list */
	if (global_cclist == NULL) {
		global_cclist = list;
		list->next = NULL;

		goto done;
	}

	/* new cc list header */
	tmp = global_cclist;
	if (tmp->info.host > list->info.host) {
		list->next = tmp;
		global_cclist = list;
		goto done;
	}

	/* find where to insert the new cc */
	for (tmp = global_cclist; tmp->next; tmp = tmp->next) {
		next = tmp->next;
		if (next->info.host < list->info.host) {
			continue;
		}
		if (next->info.host == list->info.host) {
			if (next->info.dev < list->info.dev)
				continue;
		}
		break;
	}
	list->next = tmp->next;
	tmp->next = list;

done:
	cc_cnt++;
	wusbd_info("add_to_global_list: complete");
}

/* Remove a list from the global cc list */
static void
remove_from_global_list(wusb_cc_list_t *list)
{

	wusb_cc_list_t *tmp = NULL;

	wusbd_info("remove_from_global_list: host-id:%d, dev-id:%d, path:%s",
	    list->info.host, list->info.dev, list->info.type);

	/* first list */
	if (global_cclist == list) {
		global_cclist = list->next;
		goto found;
	}

	for (tmp = global_cclist; tmp; tmp = tmp->next) {
		if (tmp->next  == list) {
			tmp->next = list->next;
			goto found;
		}
	}

	wusbd_warn("remove_from_global_list: cc not found ");
	return;
found:
	free(list);
	cc_cnt--;
	wusbd_info("remove_from_global_list: complete");
}

/*
 * It is useful make a wrapper to work thru each entry in the global
 * lists. it is used widely for to travers the whole list
 */
static void
global_list_iterate(cc_list_func func, void *data)
{
	wusb_cc_list_t *list = global_cclist;
	while (list) {
		if (func(list, (void*)data) < 0)
			break;
		list = list->next;
	}
}

/* Set all the device/host state to be disabled or disconnected */
static void
clean_all_cc_list()
{
	wusbd_info("clean_all_cc_list: start");
	global_list_iterate(clean_cc_list, NULL);
	wusbd_info("clean_all_cc_list: complete");
}

/* Copy the cc list to buffer */
static void
copy_list_back(char *buf)
{
	global_list_iterate(copy_cc_list, &buf);
}

/* work on each entry in the /dev/usb/whost */
static void
all_hosts_iterate(host_func func)
{
	struct dirent *entry;
	char filename[MAXPATHLEN];
	DIR *dirp = NULL;

	if ((dirp = opendir(WUSB_HOST_PATH)) == NULL) {
		wusbd_warn("all_hosts_iterate: dir = %s, err = %s",
		    WUSB_HOST_PATH, strerror(errno));

		return;
	}
	while ((entry = readdir(dirp)) != NULL) {
		if (strstr(entry->d_name, WUSB_HOST_NAME)) {

			(void) snprintf(filename, MAXPATHLEN, "%s/%s",
			    WUSB_HOST_PATH, entry->d_name);
			func(filename);
		}
	}
	(void) closedir(dirp);
}

/* Get the host file path in /dev/usb from a host id */
static int
get_host_path(int hostid, char *path)
{
	struct dirent *entry;
	char filename[MAXPATHLEN];
	DIR *dirp = NULL;
	uint8_t mac[WUSB_DEV_MAC_LENGTH];
	int rval = WUSBA_FAILURE;

	wusbd_info("get_host_path :host = %d", hostid);
	if ((dirp = opendir(WUSB_HOST_PATH)) == NULL) {
		wusbd_warn("all_hosts_iterate: dir = %s, err = %s",
		    WUSB_HOST_PATH, strerror(errno));

		return (rval);
	}
	while ((entry = readdir(dirp)) != NULL) {
		if (strstr(entry->d_name, WUSB_HOST_NAME)) {
			(void) snprintf(filename, MAXPATHLEN, "%s/%s",
			    WUSB_HOST_PATH, entry->d_name);
			if (load_host_mac(filename, mac) < 0) {
				wusbd_warn("get_host_path: host = %s failed",
				    filename);

				continue;
			}

			if (hostid == find_host_id(mac)) {
				(void) snprintf(path, MAXPATHLEN, "%s",
				    filename);
				rval = WUSBA_SUCCESS;


				break;
			}


		}
	}
	(void) closedir(dirp);

	return (rval);
}

/* Check all the host device */
static void
check_all_host()
{
	wusbd_info("check_all_host :start");
	all_hosts_iterate(check_host);
	wusbd_info("check_all_host :finished");
}

/* Stop the host device */
static void
stop_all_host()
{
	wusbd_info("stop_all_host :start");
	all_hosts_iterate((host_func)stop_host);
	wusbd_info("stop_all_host :finished");
}

/*
 * update the cc list information
 *    stat of the device and host, device nodename
 */
static void
update_all_cc_list()
{
	wusbd_info("update_all_cc_list :start");
	if (global_cclist) {
		all_hosts_iterate(update_cc_list);
	} else {
		wusbd_info("update_all_cc_list :global_cclist = NULL");
	}
	wusbd_info("update_all_cc_list :complete");
}

/*
 * Get credential of the door_call client and check
 * authorizations of caller's uid/euid
 */
static int
wusbd_check_auth(const char *auth_str)
{
	uid_t	uid;
	ucred_t	*pcred = NULL;
	if (door_ucred(&pcred) < 0) {
		wusbd_warn("chk_auths: door_ucred: err = %s ", strerror(errno));

		return (WUSBA_FAILURE);
	}

	uid = ucred_geteuid(pcred);

	/* remember to do this */
	ucred_free(pcred);

	if (chk_auths(uid, auth_str) < 0) {

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);
}

static int
load_host_mac(const char *filename, uint8_t *mac)
{
	int fd = -1;
	int rval = WUSBA_FAILURE;

	wusbd_info("load_host_mac: host = %s\n", filename);
	/* open host/dev file */
	if ((fd = open(filename, O_RDONLY)) == -1) {
		wusbd_warn("load_host_mac: filename = %s , err = %s", filename,
		    strerror(errno));
		goto done;
	}

	/* Get the mac address of the host */
	if (ioctl(fd, WUSB_HC_GET_MAC_ADDR, mac) == -1) {
		wusbd_warn("load_host_mac: WUSB_HC_GET_MAC_ADDR: err = %s",
		    strerror(errno));
		(void) close(fd);
		goto done;
	}

	(void) close(fd);


	rval = WUSBA_SUCCESS;
done:
	wusbd_info("load_host_mac complete");

	return (rval);
}

/*
 * create host cc
 *    1. create the cc for host
 *    2. save the cc to list & cc store file
 */
static int
create_host_cc(const char *filename)
{
	wusb_cc_info_t ccinfo;
	uint8_t mac[WUSB_DEV_MAC_LENGTH];
	wusbd_info("create host cc for :%s", filename);

	if (load_host_mac(filename, mac) < 0) {
		wusbd_warn("create_host_cc: host = %s, load mac failed",
		    filename);

		return (WUSBA_FAILURE);
	}

	bzero(&ccinfo, sizeof (wusb_cc_info_t));

	/* assign CHID */
	if (generate_wusb_CHID(&(ccinfo.cc), mac) < 0) {

		wusbd_warn("create_host_cc: host = %s, reate chid failed",
		    filename);

		return (WUSBA_FAILURE);
	}

	print_array("New CC for host:", ccinfo.cc.CHID, 48);

	(void) memcpy(ccinfo.mac, mac, WUSB_DEV_MAC_LENGTH);

	/* Todo: only support hwa */
	(void) snprintf(ccinfo.type, WUSB_TYPE_LEN, "hwa");

	/* don't allocate dev id here , for host, dev id set to 0 */
	if ((ccinfo.host = assign_host_id()) == 0) {
		wusbd_warn("create_host_cc: assign_host_id = 0");

		return (WUSBA_FAILURE);
	}
	ccinfo.dev = 0;

	/* save cc infor to host and cc file */
	if (save_cc(&ccinfo) < 0) {
		wusbd_warn("create_host_cc: save_cc failed");

		return (WUSBA_FAILURE);
	}

	return (WUSBA_SUCCESS);

}

/*
 * Add CCs to hosts upon startup
 * OR add CCs to the host which is newly hotplugged in
 */
static void
check_host(const char *host)
{
	int hostid = 0;

	uint8_t mac[WUSB_DEV_MAC_LENGTH];

	wusbd_info("check_host: host = %s", host);
	if (load_host_mac(host, mac) < 0) {
		wusbd_warn("check_host: host = %s load mac fail", host);

		return;
	}
	if ((hostid = find_host_id(mac)) != 0) {
		wusbd_info("check_host: host = %s host-id = %d found",
		    host, hostid);
		(void) add_all_cc_to_host(host, hostid);
		/* start the host */
		(void) start_host(host);

	} else {
		wusbd_info("check_host: newhost = %s found", host);
		if (WUSBA_SUCCESS == create_host_cc(host)) {
			/* check host again */
			(void) check_host(host);
		}
	}
}

/*
 * Remove one cc from host
 * Args:
 *	hostid - hostid for the cc
 *	devid - devid for the cc
 */
static int
remove_cc_from_host(uint8_t hostid, uint16_t devid)
{
	int fd = -1;
	wusb_cc_list_t *list = devids[hostid][0];
	char host_path[MAXPATHLEN];

	if (get_host_path(hostid, host_path) < 0) {
		wusbd_warn("remove_cc_from_host:hostid = %d not attached",
		    hostid);

		return (WUSBA_FAILURE);
	}

	if ((fd = open(host_path, O_RDWR)) == -1) {
		wusbd_warn("remove_cc_from_host: host = %s err = %s",
		    host_path, strerror(errno));

		return (WUSBA_FAILURE);
	}

	list = devids[hostid][devid];
	if (ioctl(fd, WUSB_HC_REM_CC, &(list->info.cc)) != 0) {
		wusbd_warn("remove_cc_from_host: WUSB_HC_REM_CC err = %s",
		    strerror(errno));
		(void) close(fd);

		return (WUSBA_FAILURE);
	}
	(void) close(fd);

	return (WUSBA_SUCCESS);
}

/* Stop/disable a host device */
static int
stop_host(const char *host)
{
	int fd = -1;
	int hstate = -1;
	wusbd_info("stop_host: host = %s", host);
	if ((fd = open(host, O_RDONLY)) == -1) {
		wusbd_warn("stop_host:host = %s err = %s", host,
		    strerror(errno));

		return (WUSBA_FAILURE);
	}
	/*
	 * We'll only send the cmd to stop host while host has already
	 * been startd. start/stop host takes time becasue host controller
	 * need to reset hardware or may cause issue while it it is stopping.
	 * So just do it at the right time.
	 */
	if (ioctl(fd, WUSB_HC_GET_HSTATE, &hstate) < 0) {
		wusbd_warn("stop_host: WUSB_HC_GET_HSTATE: err = %s",
		    strerror(errno));
		goto fail;
	}

	if (hstate == WUSB_HC_STARTED) {
		if (ioctl(fd, WUSB_HC_STOP, WUSB_HC_FINAL_STOP) != 0) {
			wusbd_warn("stop_host: WUSB_HC_STOP: err = %s",
			    strerror(errno));
			goto fail;
		}
	}
	(void) close(fd);

	return (WUSBA_SUCCESS);
fail:
	(void) close(fd);

	return (WUSBA_FAILURE);
}

/* start/enable a host device */
static int
start_host(const char *host)
{
	int fd = -1;
	int hstate = -1;
	wusbd_warn("start_host : host = %s", host);
	if ((fd = open(host, O_RDONLY)) == -1) {
		wusbd_warn("start_host: host = %s err = %s", host,
		    strerror(errno));

		return (WUSBA_FAILURE);
	}
	/*
	 * Check if the host is already start. if the host has been started.
	 * it is not proper to send the start command to the host controller,
	 * because it may cause some issue for host contoller reset the
	 * hardware
	 */
	if (ioctl(fd, WUSB_HC_GET_HSTATE, &hstate) < 0) {
		wusbd_warn("start_host: ioctl = WUSB_HC_GET_HSTATE err = %s",
		    strerror(errno));
		goto fail;
	}

	if (hstate != WUSB_HC_STARTED) {
		if (ioctl(fd, WUSB_HC_START, WUSB_HC_INITIAL_START) == -1) {
			wusbd_warn("start_host: WUSB_HC_START: err = %s",
			    strerror(errno));
			goto fail;
		}
	}
	(void) close(fd);
	wusbd_info("start_host: complete");

	return (WUSBA_SUCCESS);
fail:
	(void) close(fd);

	return (WUSBA_FAILURE);
}

/* Check the args of a dev ctrl door call request */
static uint16_t
check_dev_ctrl(wusb_dev_ctrl_t *dev_ctrl)
{
	if ((dev_ctrl->host == 0) || (dev_ctrl->host >= HOST_MAX)) {
		wusbd_warn("check_dev_ctrl: host-id = %02d", dev_ctrl->host);

		return (WUSBADM_INVAL_HOSTID);
	}
	if (!devids[dev_ctrl->host][0]) {
		wusbd_warn("check_dev_ctrl: host-id = %02d cc = NULL",
		    dev_ctrl->host);

		return (WUSBADM_NO_HOST);
	}
	if (dev_ctrl->dev >= DEV_MAX) {
		wusbd_warn("check_dev_ctrl: dev-id = %03d, max: %d",
		    dev_ctrl->dev, DEV_MAX);

		return (WUSBADM_INVAL_DEVID);

	}
	if (!devids[dev_ctrl->host][dev_ctrl->dev]) {
		wusbd_warn("check_dev_ctl: dev-id = %02d.%03d, cc = NULL",
		    dev_ctrl->host, dev_ctrl->dev);

		return (WUSBADM_NO_DEVICE);
	}

	return (WUSBADM_OK);
}

/* Check the args of a host ctrl door call request */
static uint16_t
check_host_ctrl(wusb_dev_ctrl_t *dev_ctrl)
{
	if ((dev_ctrl->host == 0) || (dev_ctrl->host >= HOST_MAX)) {
		wusbd_warn("check_host_ctrl: host-id = %02d", dev_ctrl->host);

		return (WUSBADM_INVAL_HOSTID);
	}
	if (!devids[dev_ctrl->host][0]) {
		wusbd_warn("check_host_ctrl: host-id = %02d, cc = NULL",
		    dev_ctrl->host);

		return (WUSBADM_NO_HOST);
	}
	if (dev_ctrl->dev != 0) {
		wusbd_warn("check_host_ctrl: dev-id = %03d no zero",
		    dev_ctrl->dev);

		return (WUSBADM_INVAL_DEVID);
	}

	return (WUSBADM_OK);
}

/* Remove one dev from the cc list */
static int
remove_one_dev(uint8_t hostid, uint16_t devid)
{
	wusb_cc_list_t *list = NULL;
	if (remove_cc_from_host(hostid, devid) < 0) {
		wusbd_warn("remove_one_dev: hostid = %d, devid = %d"
		"remove cc from host failed", hostid, devid);
	}
	list = devids[hostid][devid];
	remove_from_global_list(list);

	free_dev_id(hostid, devid);

	return (WUSBA_SUCCESS);

}

/* Remove all dev from the cc list */
static int
remove_all_dev(uint8_t hostid)
{
	int i = 0;
	wusbd_warn("remove_all_dev enter, hostid = %d", hostid);
	if (remove_all_cc_from_host(hostid) < 0) {
		wusbd_warn("remove_all_dev: hostid = %d. remove all cc failed",
		    hostid);
	}
	for (i = 1; i < DEV_MAX; i++) {
		wusb_cc_list_t *list = devids[hostid][i];
		if (list) {
			remove_from_global_list(list);
			free_dev_id(hostid, i);
		}
	}
	wusbd_warn("remove_all_dev  complete");

	return (WUSBA_SUCCESS);
}

/* register device add/remove event to update the cc list */
static int
init_sys_evnt()
{
	sysevent_handle_t *shp;
	const char *subclass_list[] = {
	    ESC_DEVFS_DEVI_ADD,
	    0
	};
	if ((shp = sysevent_bind_handle(event_handler)) == NULL) {
		wusbd_warn("init_sys_evnt: sysevent bind handle: err = %s",
		    strerror(errno));
		goto fail;
	}
	if (sysevent_subscribe_event(shp, EC_DEVFS, subclass_list, 1) != 0) {
		wusbd_warn("init_sys_evnt: sysevent subscribe: err = %s",
		    strerror(errno));
		sysevent_unbind_handle(shp);
		goto fail;
	}

	return (WUSBA_SUCCESS);
fail:

	return (WUSBA_FAILURE);
}

/*
 * Only one daemon is running in the system
 * Create pid file to save the pid of the daemon
 * process, the pid file is also used by svcadm to
 * stop the daemon
 */
static int
init_daemon_pid()
{
	int fd;
	char pid[20];

	if ((fd = open(PID_FILE, O_RDWR|O_CREAT|O_EXCL, S_IRUSR | S_IWUSR))
	    == -1) {
		wusbd_warn("dameon is already running! ");

		return (WUSBA_FAILURE);
	}

	/* save pid to the file */
	(void) snprintf(pid, 19, "%d", getpid());

	if (write(fd, pid, strlen(pid)) != strlen(pid)) {
		wusbd_warn("write pid file failed! ");
		(void) close(fd);

		return (WUSBA_FAILURE);

	}
	(void) close(fd);

	return (WUSBA_SUCCESS);

}

static void
exit_clean(int ret)
{
	wusbd_warn("Remove door file, pid file");
	(void) fdetach(DOOR_FILE);
	(void) unlink(DOOR_FILE);
	(void) unlink(PID_FILE);

	(void) pthread_mutex_destroy(&mutex_cclock);

	closelog();

	exit(ret);
}

/*
 * Refresh daemon. svcadm restart will send a SIGHUP to the daemon
 * destroy the cc list and reload it from cc now. Update the status
 * of each cc list by checking all the hosts in the system.
 */
/* ARGSUSED */
static void
refresh(int signo)
{
	wusbd_info("refresh: daemon is restarting..");

	(void) pthread_mutex_lock(&mutex_cclock);

	destroy_global_cc_list();
	(void) init_global_cc_list();
	check_all_host();

	(void) pthread_mutex_unlock(&mutex_cclock);

	wusbd_info("refresh: daemon is ok now");
}

/* update host CC when a wireless host is plugged */
static void
event_handler(sysevent_t *ev)
{
	nvlist_t *attr_list = NULL;
	char *path = NULL;

	if (sysevent_get_attr_list(ev, &attr_list) != 0) {
		wusbd_warn("event_handler: can not get attr list");

		return;
	}

	(void) nvlist_lookup_string(attr_list, DEVFS_PATHNAME, &path);

	wusbd_info("event_handler: device path  %s", path);


	/* check if the device is host device and update cc list */
	if (path && strstr(path, WUSB_HWA_HOST_NODE)) {
		char filename[MAXPATHLEN];
		(void) snprintf(filename, MAXPATHLEN, "/devices%s:hwahc", path);

		(void) pthread_mutex_lock(&mutex_cclock);
		check_host(filename);
		(void) pthread_mutex_unlock(&mutex_cclock);
	}

	nvlist_free(attr_list);
}


/* For debug only */
void
print_prv()
{
#ifdef DEBUG
	priv_set_t *tt = priv_allocset();
	if (getppriv(PRIV_PERMITTED, tt) == 0) {
		wusbd_info("PRIV_PERMITTED:\n");
		wusbd_info("\t%s\n",
		    priv_set_to_str(tt, ',', PRIV_STR_SHORT));
	}
	if (getppriv(PRIV_EFFECTIVE, tt) == 0) {
		wusbd_info("PRIV_EFFECTIVE:\n");
		wusbd_info("\t%s\n",
		    priv_set_to_str(tt, ',', PRIV_STR_SHORT));
	}
	if (getppriv(PRIV_INHERITABLE, tt) == 0) {
		wusbd_info("PRIV_INHERITABLE:\n");
		wusbd_info("\t%s\n",
		    priv_set_to_str(tt, ',', PRIV_STR_SHORT));
	}
	if (getppriv(PRIV_LIMIT, tt) == 0) {
		wusbd_info("PRIV_LIMIT:\n");
		wusbd_info("\t%s\n",
		    priv_set_to_str(tt, ',', PRIV_STR_SHORT));
	}
	priv_freeset(tt);
#endif
}

/* wusb daemon init */
static int
wusbd_daemonize_init()
{
	int status, pfds[2];
	sigset_t set, oset;
	pid_t pid;
	int rc;

	/*
	 * Remove all the privs not needed for the daemon.
	 *    PRIV_SYS_MOUNT: requred by starting door serv.
	 *    PRIV_FILE_DAC_WRITE: requred by attach door file.
	 *    PRIV_SYS_CONFIG, required by register sys event.
	 *    PRIV_SYS_DEVICES, required by driver ioctl.
	 */
	rc =  __init_daemon_priv(PU_RESETGROUPS | PU_CLEARLIMITSET,
	    0, 0,
	    PRIV_SYS_MOUNT,
	    PRIV_FILE_DAC_WRITE,
	    PRIV_SYS_CONFIG,
	    PRIV_SYS_DEVICES,
	    NULL);

	if (rc != 0) {
		wusbd_warn("insufficient privileges");
		exit(FATAL_ERROR);
	}

	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	if (pipe(pfds) == -1) {
		wusbd_warn("unable to create pipe");
		closelog();
		exit(FATAL_ERROR);
	}

	closelog();


	if ((pid = fork()) == -1) {
		openlog("wusbd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
		wusbd_warn("unable to fork");
		closelog();
		exit(FATAL_ERROR);
	}

	/*
	 * If we're the parent process, wait for either the child to send us
	 * the appropriate exit status over the pipe or for the read to fail
	 * (presumably with 0 for EOF if our child terminated abnormally).
	 * If the read fails, exit with either the child's exit status if it
	 * exited or with SMF_EXIT_ERR_FATAL if it died from a fatal signal.
	 */
	if (pid != 0) {
		(void) close(pfds[1]);

		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);

		if (waitpid(pid, &status, 0) == pid && WIFEXITED(status))
			_exit(WEXITSTATUS(status));

		_exit(FATAL_ERROR);
	}
	openlog("wusbd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
	(void) umask(022);
	(void) close(pfds[0]);

	return (pfds[1]);
}

/* wusb daemon fini */
static void
wusbd_daemonize_fini(int fd, int exit_status)
{
	/*
	 * Now that we're running, if a pipe fd was specified, write an exit
	 * status to it to indicate that our parent process can safely detach.
	 * Then proceed to loading the remaining non-built-in modules.
	 */
	if (fd >= 0) {
		(void) write(fd, &exit_status, sizeof (exit_status));
	}

	(void) close(fd);
	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		(void) fcntl(fd, F_DUP2FD, STDIN_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDOUT_FILENO);
#if 0
		/* Leave the stderr for smf log */
		(void) fcntl(fd, F_DUP2FD, STDERR_FILENO);
#endif
		(void) close(fd);
	}
	/* Remove all the privs not needed. leave SYS_DEVICE only */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY,
	    PRIV_PROC_INFO,
	    PRIV_FILE_DAC_WRITE,
	    PRIV_SYS_MOUNT,
	    PRIV_SYS_CONFIG,
	    (char *)NULL);


	print_prv();
}
/* Each door call handler should get the lock */
static void
wusbd_daemon_enter()
{
	wusbd_info("wusbd_daemon_enter: enter");
	(void) pthread_mutex_lock(&mutex_cclock);
}
/* Each door call handler should release the lock */
static void
wusbd_daemon_leave(char *buf, int len)
{
	wusbd_info("wusbd_daemon_leave");
	(void) pthread_mutex_unlock(&mutex_cclock);
	(void) door_return(buf, len, NULL, 0);
}
