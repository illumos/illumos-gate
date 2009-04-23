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


#include <stdio.h>
#include <stdarg.h>
#include <sys/param.h>
#include <locale.h>
#include <dirent.h>
#include <fcntl.h>
#include <door.h>
#include <errno.h>
#include <sys/mman.h>
#include <getopt.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/usb/usba/wusba_io.h>
#include <sys/usb/clients/wusb_ca/wusb_ca.h>
#include "crypto_util.h"
#include "wusbd.h"

/*
 * EXIT STATUS
 *    The following exit values are returned:
 *         0    Successful operation
 *	   1    Error: the operation failed.
 *         2    Usage error.
 */
#define	WUSB_EXIT_SUCCESS	0
#define	WUSB_EXIT_FAILURE	1
#define	WUSB_EXIT_USAGE		2



#define	ASSO_CABLE_NAME		"wusb_ca"

#define	WUSB_MAX_LEN 				255

#define	WUSB_HOSTID_LEN		2
#define	WUSB_DEVID_LEN		6

/* wusba admin list options */
#define	WUSB_FIELD_WIDTH 		20

#define	WUSB_LIST_HOST	0x01
#define	WUSB_LIST_DEV	0x02
#define	WUSB_LIST_HD	(WUSB_LIST_HOST | WUSB_LIST_DEV)
#define	WUSB_LIST_ID	0x04
#define	WUSB_LIST_TYPE	0x08
#define	WUSB_LIST_STATE 0x10
#define	WUSB_LIST_ALL	(WUSB_LIST_ID | WUSB_LIST_TYPE | WUSB_LIST_STATE)

/* cable device list */
typedef struct dev_list {
	char 			path[MAXPATHLEN];
	struct dev_list 	*next;
} dev_list_t;

static wusb_device_info_t   *dev_lists = NULL;
static uint32_t	cnt	   = 0;

/* log and debug helpers */
static	void 	wusb_prt(const char *, ...);
static	void 	wusb_usage(const char *, ...);
static	void 	wusb_fail(const char *, ...);
static	void 	wusb_opterr(int, int);



/* load host/dev list helpers */
static void 	wusb_load_list(wusb_device_info_t **, uint32_t *cnt);
static void 	wusb_free_list(wusb_device_info_t *);

/* door call helpers */
static int  	wusb_door_req(int, door_arg_t *, char *, int);
static void  	wusb_door_free(door_arg_t *);
static uint16_t wusb_door_result(door_arg_t *da);

/* check auths */
static void	wusb_check_auth(const char *);
/* usr input funcs */
static void 	user_confirm(char *);
static void 	user_input(char *, char *, int);

/* string translation helpers */
static uint32_t str2id(char *);
static void 	usage();

/* list */
static const struct option wusb_list_opts[] = {
	{ "host",    	no_argument, 		NULL, 'h'},
	{ "device",  	no_argument, 		NULL, 'd'},
	{ "output",  	required_argument, 	NULL, 'o'},
	{0, 0, 0, 0}
};
static const char *WUSB_LIST_HEADER[] = {
	"ID",			/* host-id or dev-id		*/
	"STATE", 		/* host or device states 	*/
	"TYPE",  		/* host or deivce types  	*/
	NULL
};

static void    	do_list(int, char **);
static void    	do_list_args(int, char **, char *);

static void    	parse_subopts(char *, const char *);
static int    	parse_option(char *, const char *);

static void   	wusb_prt_titles(char);
static void   	wusb_prt_lists(char, wusb_device_info_t *);


static int	find_dev_id(uint8_t, uint16_t);
static void	parse_dev_id(const char *, wusb_dev_ctrl_t *);
static void	parse_host_id(char *, uint8_t  *);

/* associate */
static struct option wusb_asso_opts[] = {
	{ "host",   		required_argument, 	NULL, 'h'},
	{ "cable",   		no_argument, 		NULL, 'c'},
	{ "numeric", 		required_argument, 	NULL, 'n'},
	{ "force",   		no_argument, 		NULL, 'f'},
	{ "onetime", 		no_argument, 		NULL, 'o'},
	{ 0, 0, 0, 0}
};
static void 	do_associate(int, char **);
static void 	do_asso_args(int, char **, wusb_asso_ctrl_t *);

static int 	input_host_id(uint8_t *);
static void 	input_dev_id(wusb_dev_ctrl_t *);
#ifdef NUMERIC_ENABLED
static int 	input_asso_type(uint8_t *);
#endif
static int 	select_cable_device(char *);

/* remove dev */
static struct option wusb_rmdev_opts[] = {
	{ "host",   		required_argument, 	NULL, 'h'},
	{ "device", 		required_argument, 	NULL, 'd'},
	{ "force",  		no_argument, 		NULL, 'f'},
	{ 0, 0, 0, 0}
};

/* remove/enable/disable host */
static struct option wusb_host_opts[] = {
	{ "host",  		required_argument,	NULL, 'h'},
	{ "force", 		no_argument, 		NULL, 'f'},
	{ 0, 0, 0, 0}
};

static void 	do_host(int, char **, int);
static void 	do_host_args(int, char **, int, wusb_dev_ctrl_t *);
static void 	do_remove_host(int, char **);
static void 	do_enable_host(int, char **);
static void 	do_disable_host(int, char **);

static void 	do_remove_dev(int, char **);
static void 	do_remove_dev_args(int, char **, wusb_dev_ctrl_t *);



/* error message maps */
struct errormsgs {
	int code;
	char *errmsg;
} wusb_errors[] = {
	{ WUSBADM_OK,			"success" },
	{ WUSBADM_AUTH_FAILURE,		"permisson denied" },
	{ WUSBADM_NO_HOST,		"host does not exist" },
	{ WUSBADM_NO_DEVICE,		"device does not exist" },
	{ WUSBADM_CCSTORE_ACC,		"fail to access CC store" },
	{ WUSBADM_NO_SUPPORT,		"command not supported" },
	{ WUSBADM_INVAL_HOSTID,		"invalid host id" },
	{ WUSBADM_INVAL_DEVID,		"invalid device id" },
	{ WUSBADM_HOST_NOT_ATTACH,	"host not attached" },
	{ WUSBADM_FAILURE,		"unknown error"}
};

char *
wusb_strerror(int err)
{
	if (err < 0 || err > WUSBADM_FAILURE) {

		return (wusb_errors[WUSBADM_FAILURE].errmsg);
	}

	return (wusb_errors[err].errmsg);
}


/*
 * wusbadm cmd line tool is used for used to administrate the wireless usb
 * host and wireless usb devices.
 * list 	- List the device and host status
 * associated 	- Setup assocaition between host and devices.
 * remove-dev 	- Remove the assocation of device
 * remove-host 	- Remove the host information and all the devices assocaiton to
 *                the host
 * enable-host 	- Enable a host to be ready to accept wireless devices
 * disable-host - Disable a host, host will not accpet connections
 */

int
main(int argc, char **argv)
{
	int i;
	static struct {
		const char *cmd;
		void (*func)(int, char **);
		const char *auth;
	} cmd_list[] = {
		{ "list",	  do_list,		WUSB_AUTH_READ},
		{ "associate",	  do_associate,		WUSB_AUTH_MODIFY},
		{ "remove-dev",	  do_remove_dev,	WUSB_AUTH_MODIFY},
		{ "remove-host",  do_remove_host,	WUSB_AUTH_HOST},
		{ "enable-host",  do_enable_host,	WUSB_AUTH_HOST},
		{ "disable-host", do_disable_host,	WUSB_AUTH_HOST},
		{ NULL, NULL}
	};


	(void) setlocale(LC_ALL, "");

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc <= 1) {
		usage();
		exit(WUSB_EXIT_USAGE);
	}

	/* start wusb damemon */
	if (strcmp(argv[1], "--daemon") == 0) {
		(void) daemonize();
		exit(WUSB_EXIT_SUCCESS);
	}


	/* wusbadm entry */
	for (i = 0; cmd_list[i].cmd; i++) {
		if (strcmp(cmd_list[i].cmd, argv[1]) == 0) {
			break;
		}
	}
	if (!cmd_list[i].cmd) {
		wusb_usage("unknown option %s", argv[1]);
	}
	wusb_check_auth(cmd_list[i].auth);

	wusb_load_list(&dev_lists, &cnt);

	cmd_list[i].func(argc - 1, &argv[1]);

	wusb_free_list(dev_lists);
	return (WUSB_EXIT_SUCCESS);
}

static void
usage()
{
	wusb_prt("\nUsage:\twusbadm sub-command args ...\n\n");
	wusb_prt("\tlist         [-h | -d] [-o field[,...]]\n");
	wusb_prt("\tassociate    [-h host-id] [[-c [-f]] | -n] [-o]\n");
	wusb_prt("\tremove-dev   [[-d dev-id] | [-h host-id]] [-f]\n");
	wusb_prt("\tremove-host  [-h host-id] [-f]\n");
	wusb_prt("\tenable-host  [-h host-id]\n");
	wusb_prt("\tdisable-host [-h host-id] [-f]\n");
	wusb_prt("\n");
}

/*
 * list command routine.
 * 	wusbadmin list [-h | -d] [-o field[,...]]
 * 	1. parse the options
 * 	2. load host/deivce info from daemon
 * 	3. print titles accoding to list  options
 * 	4. print host/deivce list one by one
 */
static void
do_list(int argc, char **argv)
{
	char		fields	   = 0x0;
	int i;

	/* parse the list options */
	do_list_args(argc, argv, &fields);


	/* print list title */
	wusb_prt_titles(fields);

	/* print out the result */
	for (i = 0; i < cnt; i++) {
		wusb_prt_lists(fields, &dev_lists[i]);
	}


}

/*
 * associate command routine
 * 	wusbadmin associate [-h host-id] [[-c [-f] | -n] [-o]
 * 	1. Parse the options and get user input
 * 	2. Send the asso infor the daemon
 */
static void
do_associate(int argc, char **argv)
{
	door_arg_t da;
	wusb_asso_ctrl_t  asso_ctrl;
	uint16_t rval = 0;

	/* Get association options */
	bzero(&asso_ctrl, sizeof (wusb_asso_ctrl_t));
	do_asso_args(argc, argv, &asso_ctrl);

	/* open door file */
	(void) wusb_door_req(WUSB_DCMD_ASSOCIATE, &da,
	    (char *)&asso_ctrl, sizeof (wusb_asso_ctrl_t));

	/* association result */
	rval = wusb_door_result(&da);

	wusb_door_free(&da);

	if (rval != WUSBADM_OK) {
		wusb_fail("%s", wusb_strerror(rval));
	}

}
/*
 * remove-dev command routine
 * 	remove-dev   [[-d dev-id] | [-h host-id]] [-f]
 * 	1. parse options/user input
 * 	2. send message to daemon.
 *	dev-id != 0 means remove one dev
 *	dev-id == 0 means remove all dev with a host
 */
static void
do_remove_dev(int argc, char **argv)
{
	wusb_dev_ctrl_t  devctrl;
	door_arg_t	 da;

	uint16_t rval = WUSBADM_OK;

	/* parse options */
	bzero(&devctrl, sizeof (wusb_dev_ctrl_t));
	do_remove_dev_args(argc, argv, &devctrl);

	/* send command to daemon */
	(void) wusb_door_req(WUSB_DCMD_REMOVE_DEV, &da,
	    (char *)&devctrl, sizeof (wusb_dev_ctrl_t));


	rval = wusb_door_result(&da);

	wusb_door_free(&da);

	if (rval != WUSBADM_OK) {
		wusb_fail("%s", wusb_strerror(rval));
	}


}

/*
 * Send the LOAD_CC request to daemon. Daemon will allocate memory and put
 * all CCs in that block of memory. We need to free the memory here.
 * CCs are in data array format.
 */
static void
wusb_load_list(wusb_device_info_t **cc_list, uint32_t *cnt)
{
	door_arg_t da;

	size_t	 buflen = 0;
	uint32_t num  	= 0;
	uint16_t rval 	= WUSBADM_OK;

	/* send command to daemon */
	(void) wusb_door_req(WUSB_DCMD_LIST_DATA, &da, 0, 0);

	rval = wusb_door_result(&da);
	if (rval != WUSBADM_OK) {
		wusb_door_free(&da);

		wusb_fail("%s", wusb_strerror(rval));
	}

	/* number of the devinfo list */
	(void) memcpy(&num, da.data_ptr+sizeof (uint16_t), sizeof (uint32_t));

	if (num) {

		buflen = (num) * sizeof (wusb_device_info_t);
		if ((*cc_list = malloc(buflen)) == NULL) {
			wusb_door_free(&da);

			wusb_fail("list: malloc buffer failed");
		}

		(void) memcpy(*cc_list,
		    da.data_ptr + sizeof (uint32_t) + sizeof (uint16_t),
		    buflen);
	}
	*cnt = num;

	/* unmap the buffer */
	wusb_door_free(&da);
}
static void
wusb_free_list(wusb_device_info_t *cc_list)
{
	if (cc_list) {
		free(cc_list);
	}
	cnt = 0;
}

/*
 * This is a wrapper of door call for wusb adm tool.
 * Mandatory:
 * 	cmd     - wusb admin command (WUSB_DCMD_*).
 * 	da      - door call arg.
 * Optional:
 * 	databuf - data send to daemon.
 * 	size    - data buf size.
 */
static int
wusb_door_req(int cmd, door_arg_t *da, char *databuf, int size)
{
	wusb_door_call_t dcall;
	int fd = -1;

	bzero(&dcall, sizeof (wusb_door_call_t));
	dcall.cmdss = cmd;

	/* copy data buffer */
	if (databuf) {
		(void) memcpy(dcall.buf, databuf, size);
	}

	/* set rbuf to 0, unmap the data buf later */
	bzero(da, sizeof (door_arg_t));
	da->data_ptr	= (char *)&dcall;
	da->data_size	= sizeof (wusb_door_call_t);
	da->rbuf	= 0;
	da->rsize	= 0;

	/* open door file */
	if ((fd = open(DOOR_FILE, O_RDONLY)) < 0) {

		wusb_fail("daemon not started");
	}

	/* make door call */
	if (door_call(fd, da) != 0) {
		(void) close(fd);

		wusb_fail("daemon out of service:%s", strerror(errno));
	}

	(void) close(fd);

	if (da->data_size == 0) {

		wusb_fail("no data from daemon");
	}

	return (WUSBA_SUCCESS);
}

/*
 * After each door call return, the first 2 bytes of the data
 * returned is encoded as the door call result from daemon.
 * This is a wrapper to get the door call result
 */
uint16_t
wusb_door_result(door_arg_t *da) {
	uint16_t rval = 0;
	(void) memcpy(&rval, da->data_ptr, sizeof (uint16_t));

	return (rval);
}

/*
 * Unmap the buffer after door call.
 * It is mandatory after any wusb_door_call since we set the rbuf to NULL
 * in the wusb_door_call. So any buffer returned is from the client proces.
 * See  door_call(3C) for more infor
 */
static void
wusb_door_free(door_arg_t *da)
{
	(void) munmap(da->rbuf, da->rsize);
}

/*
 * wusbadmin remove-host routine
 *    remove-host  [-h host-id] [-f]
 */
static void
do_remove_host(int argc, char **argv)
{
	do_host(argc, argv, WUSB_DCMD_REMOVE_HOST);
}

/*
 *  wusbadmin enable-host routine
 *	enable-host  [-h host-id]
 */
static void
do_enable_host(int argc, char **argv)
{
	do_host(argc, argv, WUSB_DCMD_ENABLE_HOST);
}

/*
 *  wusbadmin disable-host routine
 *	disable-host [-h host-id] [-f]
 */
static void
do_disable_host(int argc, char **argv)
{
	do_host(argc, argv, WUSB_DCMD_DISABLE_HOST);
}

/*
 * wusb do host routine. The wrapper for all host related
 * subcommand (enable-host, disable-host, remove-host).
 *   	1. parser options/user input
 *   	2. send wusb command to daemon
 */
static void
do_host(int argc, char **argv, int cmd)
{
	wusb_dev_ctrl_t		hostctrl;
	door_arg_t		da;

	uint16_t rval = 0;

	/* parse options */
	bzero(&hostctrl, sizeof (wusb_dev_ctrl_t));
	do_host_args(argc, argv, cmd, &hostctrl);

	/* door call to daemon */
	(void) wusb_door_req(cmd, &da,
	    (char *)&hostctrl, sizeof (wusb_dev_ctrl_t));

	rval = wusb_door_result(&da);
	wusb_door_free(&da);

	if (rval != WUSBADM_OK) {
		wusb_fail("%s", wusb_strerror(rval));
	}
}

/*
 * wusb list option parser
 * 	wusbadmin list [-h | -d] [-o field[,...]]
 */
static void
do_list_args(int argc, char **argv, char *option)
{
	char fields = 0x0;
	int c;

	while ((c = getopt_long(argc, argv, ":hdo:",
	    wusb_list_opts, NULL)) != -1) {
		switch (c) {
			case 'h':
				if (fields & WUSB_LIST_HOST) {
					wusb_usage("too many -h specified");
				}
				if (fields & WUSB_LIST_DEV) {
					wusb_usage("-h and -d used together");
				}
				fields |= WUSB_LIST_HOST;
				break;
			case 'd':
				if (fields & WUSB_LIST_HOST) {
					wusb_usage("-h and -d used together");
				}
				if (fields & WUSB_LIST_DEV) {
					wusb_usage("too many -d specified");
				}
				fields |= WUSB_LIST_DEV;
				break;
			case 'o':
				if (strlen(optarg) > 63) {
					wusb_usage("options too long");
				}
				(void) parse_option(&fields, optarg);
				break;
			default:
				wusb_opterr(optopt, c);
				break;
		}
	}

	if (optind < argc) {
		wusb_usage("unrecognized options:%s", argv[optind++]);
	}

	/* if no option specified,print out all fields */
	fields |= (fields & WUSB_LIST_HD)? 0x00:WUSB_LIST_HD;
	fields |= (fields & WUSB_LIST_ALL)? 0x00:WUSB_LIST_ALL;

	*option = fields;


}
/*
 * Print the header for list subcommand.
 * Each title is right aligned with length of WUSB_FIELD_WIDTH
 * The following titles will be printed if the relative tags
 * marked in the fields option.
 * 	ID 	STATE   	TYPE
 */
static void
wusb_prt_titles(char fields)
{
	int i = 0;
	char option;
	for (option = WUSB_LIST_ID;
	    option <= WUSB_LIST_STATE;
	    option <<= 1, i++) {
		if (fields & option) {
			wusb_prt("%-*s", WUSB_FIELD_WIDTH,
			    WUSB_LIST_HEADER[i]);
		}
	}

	(void) putchar('\n');

}
/*
 * Append the host-id / dev-id to the output buf.
 *   host-id  - 2 digits number (XX)
 *   dev-id   - 5 digits number (XX.XXX)
 *   See wusbadm (1M) for more
 */
static void
append_id(char *buf, wusb_device_info_t *devinfo)
{
	char tmp[WUSB_MAX_LEN] = {'\0'};

	if (devinfo->dev) {
		(void) snprintf(tmp, WUSB_MAX_LEN, "%02d.%03d",
		    devinfo->host, devinfo->dev);
	} else {
		(void) snprintf(tmp, WUSB_MAX_LEN, "%02d", devinfo->host);
	}
	(void) snprintf(buf, WUSB_MAX_LEN, "%s%-*s",
	    buf, WUSB_FIELD_WIDTH, tmp);
}
/*
 * Append state to the output buf.
 *   host  	-  enabled/disabled
 *   device  	-  connected/disconnected
 *   See wusbadm (1M) for more
 */
static void
append_state(char *buf, wusb_device_info_t *devinfo)
{
	const char *WUSB_DEV_STATE_MSG[] = {
		"disconnected",		/* WUSB_STATE_UNCONNTED 	*/
		"connected",		/* WUSB_STATE_CONNTING		*/
		"connected",		/* WUSB_STATE_UNAUTHENTICATED 	*/
		"connected",		/* WUSB_STATE_DEFAULT 		*/
		"connected",		/* WUSB_STATE_ADDRESSED 	*/
		"connected",		/* WUSB_STATE_CONFIGURED 	*/
		"connected",		/* WUSB_STATE_SLEEPING 		*/
		"connected",		/* WUSB_STATE_RECONNTING 	*/
		NULL
	};
	const char *WUSB_HOST_STATE_MSG[] = {
		"disconnected",		/* WUSB_HC_DISCONNTED 		*/
		"disabled",		/* WUSB_HC_STOPPED 		*/
		"enabled",		/* WUSB_HC_STARTED 		*/
		"disabled",		/* WUSB_HC_CH_STOPPED 		*/
		NULL
	};
	char tmp[WUSB_MAX_LEN] = {'\0'};

	if (devinfo->dev) {

		/* append the state for device */
		if (devinfo->stat > WUSB_STATE_RECONNTING) {
			(void) snprintf(tmp, WUSB_MAX_LEN, "%s", "unknown");
		} else {
			(void) snprintf(tmp, WUSB_MAX_LEN, "%s",
			    WUSB_DEV_STATE_MSG[devinfo->stat]);
		}
	} else {
		/* append the state for host */
		if (devinfo->stat > WUSB_HC_CH_STOPPED) {
			(void) snprintf(tmp, WUSB_MAX_LEN, "%s", "unknown");
		} else {
			(void) snprintf(tmp, WUSB_MAX_LEN, "%s",
			    WUSB_HOST_STATE_MSG[devinfo->stat]);
		}
	}
	(void) snprintf(buf, WUSB_MAX_LEN, "%s%-*s",
	    buf, WUSB_FIELD_WIDTH, tmp);
}


/*
 * Appenend host/dev type to the ouput buf string
 * Currently map the file name to specific types
 * TODO: how to define the type
 */
static void
append_type(char *buf, wusb_device_info_t *devinfo)
{
	(void) snprintf(buf, WUSB_MAX_LEN, "%s%-*s", buf, WUSB_FIELD_WIDTH,
	    devinfo->type);
}


/*
 * This is core func to print wireless device list on systems.
 * Print the devinfo list entry with  option field
 */
static void
wusb_prt_lists(char fields, wusb_device_info_t *devinfo)
{
	char buf[WUSB_MAX_LEN+1] = {'\0'};
	int i = 0;
	char opt = 0;
	void (*append_funcs[])(char *, wusb_device_info_t *) = {
		append_id,
		append_state,
		append_type,
		NULL
	};

	/* check if dev or host need to be print out */
	if ((devinfo->dev && !(fields & WUSB_LIST_DEV)) ||
	    (!devinfo->dev && !(fields & WUSB_LIST_HOST))) {
		return;
	}

	/* Append all the enabled fields to the output buf */
	for (i = 0, opt = WUSB_LIST_ID;
	    opt <= WUSB_LIST_STATE;
	    opt <<= 1, i++) {
		if (fields & opt) {
			append_funcs[i](buf, devinfo);
		}
	}

	wusb_prt("%s\n", buf);
}

/*
 * wusb association option parser
 * 	wusbadmin association [-h host-id] [[-c [-f] | -n] [-o]
 * 	Note:Only cable association is supported now
 */
static void
do_asso_args(int argc, char **argv, wusb_asso_ctrl_t *asso_ctrl)
{
	int c;
	int force = 0;

	while ((c = getopt_long(argc, argv, ":h:cfno", wusb_asso_opts, 0))
	    != -1) {
		switch (c) {
			case 'h':
				parse_host_id(optarg, &(asso_ctrl->host));
				break;
			case 'c':
				asso_ctrl->type |= ASSO_TYPE_CABLE;
				break;
			case 'n':
				asso_ctrl->type |= ASSO_TYPE_NUMERIC;
				break;
			case 'f':
				force = 1;
				break;
			case 'o':
				asso_ctrl->onetime = 1;
				break;
			default:
				wusb_opterr(optopt, c);
				break;
		}
	}

	if (optind < argc) {
		wusb_usage("unrecognized options:%s", argv[optind++]);
	}

	/* TODO: support cable association */
	if (asso_ctrl->type & ASSO_TYPE_NUMERIC) {

		wusb_fail("Numeric association not supported");
	}

	/* get user input host id */
	if (!asso_ctrl->host) {
		(void) input_host_id(&asso_ctrl->host);
	}

	/* get user input association type */
	if (!asso_ctrl->type) {
		asso_ctrl->type |= ASSO_TYPE_CABLE;
		/* Todo: Will be enabled after Numberic Assocation support */

#ifdef NUMERIC_ENABLED
		(void) input_asso_type(&asso_ctrl->type);
#endif
	}

	/* get user input cable device to associate */
	if (asso_ctrl->type == ASSO_TYPE_CABLE) {
		(void) select_cable_device(asso_ctrl->path);
	}

	/* confirm with user to continue or not */
	if (!force) {
		wusb_prt("Associate device (%s) with host (%02d) via cable\n",
		    asso_ctrl->path, asso_ctrl->host);
		user_confirm("Continue ");
	}

}
/*
 * Convert a string to an id (host-id/dev-id/cable-dev-id)
 * Fail if 0 returned, since each id is indexed from 1.
 * Widely used to handle user input ids.
 */
static uint32_t
str2id(char *arg)
{
	uint32_t id = 0;

	/* check the string and generate int result */
	while (*arg) {
		if (*arg < '0' || *arg > '9') {

			return (0);
		}
		id = id*10+(*arg-'0');
		arg++;
	}

	return (id);
}

static void
parse_host_id(char *arg, uint8_t *host) {
	int len = strlen(arg);

	if ((len > WUSB_HOSTID_LEN) || (len == 0)) {
		wusb_fail("host-id should be 2 digits");
	}
	if ((*host = str2id(arg)) == 0) {
		wusb_fail("invalid host id:%s", arg);
	}
	if (find_dev_id(*host, 0) < 0) {
		wusb_fail("host-id does not exist: %02d ", *host);
	}

	return;

}
/*
 * Get the host from user input.
 * 	1. list all the host id from the daemon
 * 	2. Ask user to input the host id
 * 	3. Check host id and return
 */
static int
input_host_id(uint8_t *host)
{

	char fields  = WUSB_LIST_HOST | WUSB_LIST_ALL;
	char buf[WUSB_MAX_LEN] = {'\0'};
	int i = 0;



	/* show avaialbe host id to usr */
	wusb_prt_titles(fields);
	for (i = 0; i < cnt; i++) {
		wusb_prt_lists(fields, &dev_lists[i]);
	}

	/* get user input of host id */
	user_input("Please select 2 digits host-id:", buf, WUSB_MAX_LEN-1);
	parse_host_id(buf, host);

	return (WUSBA_SUCCESS);
}
static void
input_dev_id(wusb_dev_ctrl_t *devctrl)
{

	char fields  = WUSB_LIST_DEV | WUSB_LIST_ALL;
	char buf[WUSB_MAX_LEN] = {'\0'};
	int i = 0;



	/* show avaialbe host id to usr */
	wusb_prt_titles(fields);
	for (i = 0; i < cnt; i++) {
		wusb_prt_lists(fields, &dev_lists[i]);
	}

	/* get user input of host id */
	user_input("Please select dev-id:", buf, WUSB_MAX_LEN-1);

	parse_dev_id(buf, devctrl);
}
static int
find_dev_id(uint8_t host, uint16_t dev)
{
	int rval = WUSBA_FAILURE;
	int i;

	for (i = 0; i < cnt; i++) {
		if ((dev_lists[i].dev == dev) &&
		    (dev_lists[i].host == host)) {
			rval = WUSBA_SUCCESS;

			break;
		}
	}

	return (rval);
}

/*
 * Select assocation type.
 *     - Cable
 *     - Numeric Not supported
 */
#ifdef NUMERIC_ENABLED
static int
input_asso_type(uint8_t *asso_type)
{
	char buf[15] = {'\0'};

	user_input("Select association type (c/n) :", buf, 14);
	if (strcasecmp(buf, "c") == 0) {
		*asso_type = ASSO_TYPE_CABLE;

	} else if (strcasecmp(buf, "n") == 0) {
		*asso_type = ASSO_TYPE_NUMERIC;

	} else {

		wusb_usage("invalid association type");
	}
	return (WUSBA_SUCCESS);
}
#endif

/*
 * Create a list contains all the cable devices on the system
 */
static void
init_cable_devices(dev_list_t **dev_lists, int *num)
{
	struct dirent *entry = NULL;
	dev_list_t *_devlist = NULL;

	DIR *dirp = opendir(WUSB_HOST_PATH);
	char filename[MAXPATHLEN] = {'\0'};

	*num = 0;
	/*
	 * walk on all the filename in the /dev/usb, check the filename
	 * to see if it is a cable asso filename and add it to the devinfo
	 * list if so
	 */
	if (!dirp) {
		wusb_fail("cable device not available");
	}
	while ((entry = readdir(dirp)) != NULL) {
		/* searching for cable node */
		if (strstr(entry->d_name, ASSO_CABLE_NAME) == NULL) {
			continue;
		}
		(void) snprintf(filename, MAXPATHLEN, "%s/%s",
		    WUSB_HOST_PATH, entry->d_name);

		/* add the filename to the dev list */
		if (_devlist == NULL) {
			_devlist = malloc(sizeof (dev_list_t));
			*dev_lists = _devlist;
		} else {
			_devlist->next = malloc(sizeof (dev_list_t));
			_devlist = _devlist->next;
		}
		/* this need to be freed */
		(void) snprintf(_devlist->path, MAXPATHLEN,
		    "%s", filename);

		_devlist->next = NULL;

		/* increase the list number */
		(*num)++;
	}
	(void) closedir(dirp);
}
/* Free the devlist created for cable device */
static void
free_devlist(dev_list_t *dev_list)
{
	dev_list_t *head = dev_list;
	while (head) {
		head = dev_list->next;
		free(dev_list);
		dev_list = head;
	}
}

/* find the cable dev with the user-inputed index */
static dev_list_t *
get_cable_dev(dev_list_t *dev_list, int index)
{
	int i = 1;
	while ((i != index) && dev_list) {
		dev_list = dev_list->next;
		i++;
	}

	return (dev_list);
}
/* print the cable devlist with index */
static void
show_devlist(dev_list_t *dev_list)
{
	/* show all the cable devices to user */
	int index = 1;
	wusb_prt("Cable devices on the system:\n");
	while (dev_list) {
		wusb_prt("%03d. %s\n", index, dev_list->path);
		dev_list = dev_list->next;
		index++;
	}

}
/*
 * when doing association, all the cable devices on the system
 * should be print out to the user
 */
static int
select_cable_device(char *device)
{
	/* cable association */
	char buf[32];
	int cableid = 1;

	dev_list_t *head = NULL;
	dev_list_t *tmp  = NULL;
	int devnum = 0;

	/* get all the cable dev on the system */
	init_cable_devices(&head, &devnum);

	/* Get the device name as user input */
	if (!head) {
		wusb_fail("no cable devices found ");
	}

	if (devnum != 1) {
		show_devlist(head);

		/* get the user input of the cable dev index */
		user_input("Select cable device to associate:", buf, 19);
		if (strlen(buf) != 3) {
			wusb_fail("cable device id should be 3 digits");
		}
		cableid = str2id(buf);

		/* check user iput */
		if ((cableid <= 0) || (cableid > devnum)) {
			free_devlist(head);

			wusb_fail("invalid cable device ");
		}

	} else {
		/* if only one dev exist, use it without asking user */
		cableid = 1;
	}

	/* find the device to associate */
	tmp = get_cable_dev(head, cableid);
	(void) snprintf(device, MAXPATHLEN, "%s", tmp->path);

	/* free the list */
	free_devlist(head);

	return (WUSBA_SUCCESS);

}
/*
 * Parse the -o option for wusbadm list
 */
static int
parse_option(char *fields, const char *optarg)
{

	char *lasts = NULL, *token = NULL;
	char buf[64] = { '\0' };

	(void) snprintf(buf, 64, "%s", optarg);
	if ((token = strtok_r(buf, ",", &lasts)) != 0) {
		parse_subopts(fields, token);
		while ((token = strtok_r(NULL, ",", &lasts))) {
			parse_subopts(fields, token);
		}
	}

	return (WUSBA_SUCCESS);

}

/*
 * wusbadmin list
 * parse the sub option extracted from -o options
 */
static void
parse_subopts(char *fields, const char *str)
{
	int i;
	char opt;
	for (i = 0, opt = WUSB_LIST_ID; opt <= WUSB_LIST_STATE; i++) {
		if (strcasecmp(str, WUSB_LIST_HEADER[i]) == 0) {
			*fields |= opt;
			break;
		}
		opt = opt << 1;
	}

	if (opt > WUSB_LIST_STATE) {

		wusb_usage("unrecognized options:%s", str);
	}

}

/*
 * Device id parser for remove-dev
 * dev id is 5 digits with format XX.XXX
 */
void
parse_dev_id(const char *arg, wusb_dev_ctrl_t *devctrl)
{
	char buf[WUSB_DEVID_LEN+1] = {'\0'};
	char *tmp = NULL;

	if (strlen(arg) > WUSB_DEVID_LEN) goto fail;

	(void) snprintf(buf, WUSB_DEVID_LEN+1, "%s", arg);

	if ((tmp = strchr(buf, '.')) == NULL) goto fail;
	/* get host id */
	*tmp = '\0';
	if ((devctrl->host = str2id(buf)) == 0) {
		goto fail;
	}

	/* get device id */
	if ((devctrl->dev = str2id(tmp+1)) == 0) {
		goto fail;
	}

	if (find_dev_id(devctrl->host, devctrl->dev) < 0) {
		wusb_fail("dev-id does not exist: %02d.%03d ",
		    devctrl->host, devctrl->dev);
	}

	return;
fail:
	wusb_fail("unknown device id:%s", arg);

}
/*
 * remove-dev options parser
 * 	remove-dev   [[-d dev-id] | [-h host-id]] [-f]
 */
static void
do_remove_dev_args(int argc, char **argv, wusb_dev_ctrl_t *devctrl)
{
	int c;
	int force = 0;
	bzero(devctrl, sizeof (wusb_dev_ctrl_t));

	while ((c = getopt_long(argc, argv, ":h:d:f",
	    wusb_rmdev_opts, NULL)) != -1) {
		switch (c) {
			case 'h':
				if (devctrl->dev) {
					wusb_usage("-h -d can not be"
					    "used together");
				}
				if (devctrl->host) {
					wusb_usage("multi -h is not allowed");
				}

				/* get 2 digit host id */
				parse_host_id(optarg, &(devctrl->host));

				break;

			case 'd':
				if (devctrl->dev) {
					wusb_usage("multi -d is not allowed");
				}
				if (devctrl->host) {
					wusb_usage("-h -d can not be"
					    "used together");
				}
				/* parse devid */
				(void) parse_dev_id(optarg, devctrl);
				break;
			case 'f':
				force = 1;
				break;
			default:
				wusb_opterr(optopt, c);
				break;

		}
	}

	if (optind < argc) {
		wusb_usage("unrecognized options:%s", argv[optind++]);
	}
	if ((devctrl->host == 0) && (devctrl->dev == 0)) {
		input_dev_id(devctrl);
	}

	/* confirm with user to continue or not */
	if (!force) {
		if (devctrl->dev) {
			wusb_prt("Remove the device's association information"
			    " of device (%02d.%03d) from system.\nThis device"
			    " can not be connected with the host until it is"
			    " associated again.\n",
			    devctrl->host, devctrl->dev);
		} else {
			wusb_prt("Remove the information of all the devices "
			    "associated with host (%02d) from the system\n"
			    "All the devices asociated with the host can not"
			    " be connected with it until they are associated"
			    " again.\n", devctrl->host);
		}
		user_confirm("Continue ");
	}
}
/*
 * Confirm with user continue or not
 *    info: the information shown to user before input
 */
static void
user_confirm(char *info)
{
	char yesorno[20];

	wusb_prt(info);
	user_input("(yes/no): ", yesorno, 19);
	if (strcasecmp(yesorno, "no") == 0) {
		wusb_fail("");
	}
	if (strcasecmp(yesorno, "n") == 0) {
		wusb_fail("");
	}
	if (strcasecmp(yesorno, "yes") == 0) {
		return;
	}
	if (strcasecmp(yesorno, "y") == 0) {
		return;
	}
	wusb_fail("illegal input: %s", yesorno);
}
/*
 * Get user input
 *   msg(in): infor shown to user before input
 *   length(in): buf size to save uer input
 *   buf(out): user input saved in buffer
 */
static void
user_input(char *msg, char *buf, int length)
{
	int i = 0, b;

	wusb_prt(msg);
	/*CONSTCOND*/
	while (1) {
		b = getc(stdin);
		if (b == '\n' || b == '\0' || b == EOF) {
			if (i < length)
				buf[i] = 0;
			break;
		}
		if (i < length)
			buf[i] = b;
		i++;
	}
	if (i >= length) {
		buf[length] = 0;
	}

}
/*
 * do host options parser
 *      remove-host  [-h host-id] [-f]
 *      enable-host  [-h host-id]
 *      disable-host [-h host-id] [-f]
 */
static void
do_host_args(int argc, char **argv, int cmd, wusb_dev_ctrl_t *hostctrl)
{
	int c;
	int force = 0;

	while ((c = getopt_long(argc, argv, ":h:f",
	    wusb_host_opts, NULL)) != -1) {
		switch (c) {
			case 'h':
				if (hostctrl->host) {
					wusb_usage("multi -h is not allowed");
				}
				/* 2 digits host id */
				parse_host_id(optarg, &(hostctrl->host));

				break;

			case 'f':
				/* enable host does not need -f */
				if (cmd == WUSB_DCMD_ENABLE_HOST) {
					wusb_opterr(optopt, c);
				}
				force = 1;
				break;
			default:
				wusb_opterr(optopt, c);
				break;

		}
	}
	if (optind < argc) {
		wusb_usage("unrecognized options:%s", argv[optind++]);
	}
	/*
	 * all the host related command can be used without a specific
	 * host-id, so list all the hosts avalable to users for selection
	 */
	if (hostctrl->host == 0) {
		(void) input_host_id(&(hostctrl->host));
	}


	/* confirm with user to continue or not */
	if (!force && (cmd != WUSB_DCMD_ENABLE_HOST)) {
		switch (cmd) {
			case WUSB_DCMD_DISABLE_HOST:
				wusb_prt("Disable host (%02d).\nAll the"
				    " devices connected with the host will be"
				    " disconnected\n", hostctrl->host);
				break;

			case WUSB_DCMD_REMOVE_HOST:
				wusb_prt("Remove host (%02d).\nAll the"
				    " association with the host will be"
				    " removed\n", hostctrl->host);
				break;
			default:
				break;
		}
		user_confirm("Continue");
	}

}

static void
wusb_check_auth(const char *auth) {

	uid_t	uid = geteuid();
	if (chk_auths(uid, auth) < 0) {
		wusb_fail("%s", wusb_strerror(WUSBADM_AUTH_FAILURE));
	}

}
/*
 * wusb exit helper funcstion
 *     wusb_fail or wusb_usage
 */
static void
wusb_fail(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("wusbadm: "));
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, "\n");

	wusb_free_list(dev_lists);
	exit(WUSB_EXIT_FAILURE);
}
static void
wusb_usage(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("wusbadm: "));
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, "\n");
	usage();

	wusb_free_list(dev_lists);
	exit(WUSB_EXIT_USAGE);
}


/* wusb print helper func */
static void
wusb_prt(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	va_start(alist, format);
	(void) vfprintf(stdout, format, alist);
	va_end(alist);
}

/* wusb option failuer func */
static void
wusb_opterr(int opt, int opterr)
{
	switch (opterr) {
		case ':':
			wusb_usage("option '-%c' requires a value", opt);
			break;
		case '?':
		default:
			wusb_usage("unrecognized option '-%c'", opt);
			break;
	}
}
