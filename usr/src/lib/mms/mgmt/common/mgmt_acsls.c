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


#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <procfs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <dlfcn.h>

#include "mgmt_acsls.h"
#include "mgmt_library.h"
#include "mgmt_media.h"
#include "mms_cfg.h"

static char *_SrcFile = __FILE__; /* Using __FILE__ makes duplicate strings */

/*
 * This code represents a ACS client application and communicates with the ACS
 * library via the ACSAPI interface. ACSAPI procedures communicate via IPC
 * with the SSI process running on this same client machine. Each client app
 * can send multiple requests to the ACS Library Manager via this SSI. The SSI
 * receives requests from one or more clients, places them on a queue, and sends
 * the requests to the CSI to relay them to the ACS Library Manager. Multiple
 * heterogeneous clients can communicate and manage the ACSLS Library via the
 * same SSI. The SSI also relays the responses back to the appropriate client
 * application. The CSI and SSI talk to each other via RPC. The same RPC program
 * number is used for all instances of SSI and CSI connections. So there is a
 * limitation that a client cannot connect to multiple ACSLS.
 *
 * The ACSAPI resides on the client machine as a set of three C language library
 * object modules to be linked with a client application. These modules are  the
 * formal interface, and the functions that carry out the IPC for requests and
 * responses.
 *
 */

static int acs_dlsym(void);

pthread_mutex_t	acs_mutex = PTHREAD_MUTEX_INITIALIZER;
static boolean_t acs_init = B_FALSE;
static STATUS (*dl_acs_display)(SEQ_NO, TYPE, DISPLAY_XML_DATA) = NULL;
static STATUS (*dl_acs_response)(int, SEQ_NO *, REQ_ID *, ACS_RESPONSE_TYPE *,
    ALIGNED_BYTES) = NULL;

/* Display configuration and status */
static int acs_display_info(int query_type, char *cmdarg, mms_list_t *lst);
static int parse_drv_resp(void *buf, mms_list_t *lst);
static int parse_lsm_resp(void *buf, mms_list_t *lst);
static int parse_vol_resp(void *buf, mms_list_t *vol_list);
static int parse_f(char *f, char *s, size_t len);
static int parse_f_int(char *f, uint32_t *s);
static int parse_f_date(char *f, time_t *t);

static acs_query_cmdresp_t acs_query_cmdresp_tbl[] = {
	{ACS_DISPLAY_CAP,		ACS_XMLREQ_CAP,		NULL},
	{ACS_DISPLAY_CELL,		ACS_XMLREQ_CELL,	NULL},
	{ACS_DISPLAY_DRIVE,		ACS_XMLREQ_DRIVE,	parse_drv_resp},
	{ACS_DISPLAY_LOCK,		ACS_XMLREQ_LOCK,	NULL},
	{ACS_DISPLAY_LSM,		ACS_XMLREQ_LSM,		parse_lsm_resp},
	{ACS_DISPLAY_PANEL,		ACS_XMLREQ_PANEL,	NULL},
	{ACS_DISPLAY_POOL,		ACS_XMLREQ_POOL,	NULL},
	{ACS_DISPLAY_VOL,		ACS_XMLREQ_VOL,		parse_vol_resp},
	{ACS_DISPLAY_VOL_BY_MEDIA,	ACS_XMLREQ_VOL_BY_MEDIA, NULL},
	{ACS_DISPLAY_VOL_CLEANING,	ACS_XMLREQ_VOL_CLEANING, NULL},
	{ACS_DISPLAY_VOL_ACCESSED,	ACS_XMLREQ_VOL_ACCESSED, NULL},
	{ACS_DISPLAY_VOL_ENTERED,	ACS_XMLREQ_VOL_ENTERED,	NULL},
	{ACS_DISPLAY_UNSUPPORTED,	"",			NULL}
};


/*
 *  As ACSLS is a separate product, all functions must be retrieved
 *  using dlopen/dlsym().  Do it once for the duration of the exe.
 */
static int
acs_dlsym(void)
{
	int		st = 0;
	void		*hdl = NULL;
	char		buf[2048];
	char		acspath[2048];

	st = mms_cfg_getvar(MMS_CFG_LIBAPI_PATH, acspath);
	if (st != 0) {
		return (st);
	}

	(void) pthread_mutex_lock(&acs_mutex);
	if (!acs_init) {
		(void) snprintf(buf, sizeof (buf), "%s/%s",
		    acspath, "libapi.so");
		hdl = dlopen(buf, RTLD_LAZY);
		if (hdl == NULL) {
			/* not there, try the normal locations */
			hdl = dlopen("libapi.so", RTLD_LAZY);
			if (hdl == NULL) {  /* still no luck */
				(void) pthread_mutex_unlock(&acs_mutex);
				return (MMS_MGMT_ACSLS_NOT_FOUND);
			}
		}
		dl_acs_display = (STATUS (*)(SEQ_NO, TYPE, DISPLAY_XML_DATA))
		    dlsym(hdl, "acs_display");

		dl_acs_response = (STATUS (*)(int, SEQ_NO *, REQ_ID *,
		    ACS_RESPONSE_TYPE *, ALIGNED_BYTES))dlsym(hdl,
		    "acs_response");

		if ((!dl_acs_display) || (!dl_acs_response)) {
			st = MMS_MGMT_ACSLS_NOT_FOUND;
		} else {
			acs_init = B_TRUE;
		}
	}
	(void) pthread_mutex_unlock(&acs_mutex);

	return (st);
}

/*
 * Interface to control the lifecycle of the SSI process and its children
 *
 * Any priviledged client of ACSLS can start the SSI process. The same process
 * is to be used by all ACS clients on this machine to communicate within the
 * ACSLS library. Do not start multiple SSI process.
 *
 * The envva ACSAPI_SSI_SOCKET is the local port number of the SSI
 */
int
acs_start_ssi(char *acshost, char *ssiport)
{
	int	st;
	mms_list_t	proclist;
	pid_t   pid;
	char    env_acshost[MAXHOSTNAMELEN + 13]; /* CSI_HOSTNAME=<hostname> */
	char    env_acsport[128];
	int	status;
	char	acspath[2048];
	char	ssibuf[1024];
	char	sockbuf[1024];
	char	*cmd[3];
	char	*bufp;

	if (acshost == NULL) {
		return (MMS_MGMT_NOARG);
	}

	st = mms_cfg_getvar(MMS_CFG_SSI_PATH, acspath);
	if (st != 0) {
		return (st);
	}

	(void) snprintf(ssibuf, sizeof (ssibuf), "%s/%s", acspath, "ssi");
	if (find_process(ssibuf, &proclist) == 0) {
		if (!mms_list_empty(&proclist)) {
			mms_list_free_and_destroy(&proclist, free);
			return (0);
		}
	}

	(void) snprintf(env_acshost, sizeof (env_acshost), "CSI_HOSTNAME=%s",
	    acshost);
	bufp = strrchr(env_acshost, ':');
	if (bufp != NULL) {
		*bufp = '\0';
		bufp++;
	}

	if (!bufp) {
		/* use default port */
		bufp = "50004";
	}

	(void) snprintf(env_acsport, sizeof (env_acsport), "CSI_HOSTPORT=%s",
	    bufp);


	(void) snprintf(ssibuf, sizeof (ssibuf), "MMS_SSI_PATH=%s", acspath);

	if (ssiport) {
		(void) snprintf(sockbuf, sizeof (sockbuf),
		    "ACSAPI_SSI_SOCKET=%s", ssiport);
	} else {
		(void) snprintf(sockbuf, sizeof (sockbuf),
		    "ACSAPI_SSI_SOCKET=%s", "50004");
	}

	/* set required envvars */
	(void) putenv(env_acshost);
	(void) putenv(env_acsport);
	(void) putenv(sockbuf);
	(void) putenv(ssibuf);

	cmd[0] = "/usr/bin/mmsssi.sh";
	cmd[1] = "1";
	cmd[2] = NULL;

	pid = exec_mgmt_cmd(NULL, NULL, 0, 0, B_TRUE, cmd);

	status  = check_exit(pid, NULL);

	if (status != 0) {
		mms_trace(MMS_ERR,
		    "Could not start ACSLS client daemon, exec status = %d",
		    status);
	}

	return (status);
}


/*
 * get the configuration of the acs library, given the name of the acsls
 * hostname and port.
 *
 * If get_drives is TRUE, get information about drives as well as libraries
 */
int
get_acs_library_cfg(
	char *acshost,
	boolean_t get_drives,
	mms_list_t *lsm_list
)
{
	int		st;
	char		location[128];
	mms_acslib_t	*lsm = NULL;

	if ((acshost == NULL) || (lsm_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	mms_list_create(lsm_list, sizeof (mms_acslib_t),
	    offsetof(mms_acslib_t, lib_link));

	/* check if the acsls host is accessible and start if it not */
	if (acs_start_ssi(acshost, NULL) != 0) {
		return (MMS_MGMT_ERR_EXEC_SSI);
	}

	/* get all the acs-lsm */
	st = acs_display_info(ACS_DISPLAY_LSM, NULL, lsm_list);
	if (st != 0) {
		return (st);
	}

	if (get_drives) {
		mms_list_foreach(lsm_list, lsm) {
			/* get the drives in each library */
			(void) snprintf(location, sizeof (location),
			    "%d,%d,*,*", lsm->acs, lsm->lsm);

			st = acs_display_info(ACS_DISPLAY_DRIVE, location,
			    &lsm->drive_list);
			if (st != 0) {
				break;
			}
		}
	}

	return (st);
}

static int
wait_for_response(
	int	seq,
	int	(*parse_acs_resp)(void *, mms_list_t *),
	mms_list_t *lst)
{

	STATUS			st;
	SEQ_NO			rseq;
	REQ_ID			reqid;
	int			ret;
	ALIGNED_BYTES		rbuf[MAX_MESSAGE_SIZE / sizeof (ALIGNED_BYTES)];
	ACS_RESPONSE_TYPE	type;

	if ((parse_acs_resp == NULL) || (lst == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	/*
	 * call acs_response() repeatedly until the FINAL packet for this
	 * request has been received
	 */
	do {
		(void) memset(rbuf, 0, sizeof (rbuf));

		st = dl_acs_response(
		    10, /* Block for 10 seconds */
		    &rseq,
		    &reqid,
		    &type,
		    rbuf);

		if (st == STATUS_IPC_FAILURE) {
			return (MMS_MGMT_ERR_ACSLS_RSP);
		}

		if (rseq != seq) {
			mms_trace(MMS_ERR, "Invalid ACS Sequence number, %d",
			    rseq);
			return (MMS_MGMT_ERR_ACSLS_RSP);
		}

		if ((type == RT_INTERMEDIATE) || (type == RT_FINAL)) {
			ret = parse_acs_resp(rbuf, lst);
			if (ret != 0) {
				ret = MMS_MGMT_ERR_ACSLS_PARSE;
				break;
			}
		}
	} while (type != RT_FINAL);

	return (ret);
}


/*
 * To get the configuration of the components in an ACSLS library, or their
 * status, use the 'display' command to create complex or detailed queries
 * using XML as the Query language. The XML request is then sent to the SSI
 * using the acs_display() ACSAPI and the responses are awaited and parsed.
 *
 * The SSI process must be running before this API can be used.
 */
int
acs_display_info(
	int	query_type,	/* type of query */
	char	*cmdarg,	/* arguments for the XML request */
	mms_list_t	*lst)		/* response parsed as a list */
{

	int			st = 0;
	SEQ_NO			seq;
	DISPLAY_XML_DATA	cmd;
	char			*s = "*";
	size_t			len;

	if (lst == NULL) {
		return (MMS_MGMT_NOARG);
	}

	st = acs_dlsym();
	if (st != 0) {
		return (st);
	}

	if (cmdarg && (strlen(cmdarg) > 0)) {
		s = cmdarg;
	}

	/* LINTED [E_SEC_PRINTF_VAR_FMT] */
	len = snprintf(cmd.xml_data, sizeof (cmd.xml_data),
	    acs_query_cmdresp_tbl[query_type].xmlreq, s);
	cmd.length = strlen(cmd.xml_data);

	if (len > MAX_XML_DATA_SIZE) {
		return (ENAMETOOLONG);
	}

	/*
	 * generate a sequence number, this uniquely identifies the response
	 * with the request.  SEQ_NO is defined as a short int.
	 */
	seq = (SEQ_NO)(time(NULL));

	if ((dl_acs_display(seq, TYPE_DISPLAY, cmd)) != STATUS_SUCCESS) {
		return (MMS_MGMT_ERR_ACSLS_PARSE);
	}

	st = wait_for_response(seq, (int (*)(void *, mms_list_t *))
	    acs_query_cmdresp_tbl[query_type].parse_resp, lst);

	if (st != 0) {
		mms_trace(MMS_INFO, "get acs display info failed %d", st);
		return (st);
	} else {
		mms_trace(MMS_INFO, "get acs display info success");
	}

	return (st);
}


/*
 * parse_drive_resp() assumes the format of the data response, the
 * following information is expected in the drive data:
 * acs, lsm, panel, drive, type, status, state and serial number
 */
static int
parse_drv_resp(
	void	*buf,
	mms_list_t	*drive_list)
{

	ACS_DISPLAY_RESPONSE	*res;
	size_t			l;
	char			*ptr1, *ptr2;
	mms_drive_t		*drive;
	char			junkbuf[1024];

	if ((buf == NULL) || (drive_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	res = (ACS_DISPLAY_RESPONSE *)buf;
	if (res->display_status != STATUS_SUCCESS) {
		return (MMS_MGMT_ERR_ACSLS_RSP);
	}

	ptr1 = &res->display_xml_data.xml_data[0];

	ptr2 = strstr(ptr1, "</data></display></response>");
	if (ptr2 != NULL) {
		*ptr2 = NULL;
	};

	mms_trace(MMS_DEBUG, "Display ACS response: %s", ptr1);

	/*
	 * <r> marks the start of a drive entry, <f> marks the start of a field
	 *
	 * <r>
	 * <f maxlen="3">acs</f>
	 * <f maxlen="3">lsm</f>
	 * <f maxlen="5">panel</f>
	 * <f maxlen="5">drive</f>
	 * <f maxlen="9">status</f>
	 * <f maxlen="10">state</f>
	 * <f maxlen="6">volume</f>
	 * <f maxlen="9">type</f>
	 * <f maxlen="5">lock</f>
	 * <f maxlen="32">serial_num</f>
	 * <f maxlen="14">condition</f>
	 * </r>
	 */

	if ((ptr2 = strstr(ptr1, "<data>")) != NULL) {

		if (drive_list->list_size == 0) {
			mms_list_create(drive_list, sizeof (mms_drive_t),
			    offsetof(mms_drive_t, drive_link));
		}

		while ((ptr2 = strstr(ptr1, "<r>")) != NULL) {

			drive = calloc(1, sizeof (mms_drive_t));
			if (drive == NULL) {
				return (ENOMEM);
			}

			/* extract string from <f ....>..</f> */
			ptr2 += 3; /* skip past <r> */
			l = parse_f_int(ptr2, &drive->acs);
			ptr2 += l;
			l = parse_f_int(ptr2, &drive->lsm);
			ptr2 += l;
			l = parse_f_int(ptr2, &drive->panel);
			ptr2 += l;
			l = parse_f_int(ptr2, &drive->drive);
			ptr2 += l;
			/* properly convert flags and provide for volume */
			/* status */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			/* state */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			/* volume */
			l = parse_f(ptr2, drive->volid, sizeof (drive->volid));
			ptr2 += l;
			l = parse_f(ptr2, drive->type, sizeof (drive->type));
			ptr2 += l;
			/* lock */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			l = parse_f(ptr2, drive->serialnum,
			    sizeof (drive->serialnum));
			ptr2 += l;
			/* condition */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;

			mms_list_insert_tail(drive_list, drive);

			ptr2 += 4; /* advance to the start of the next drive */
			ptr1 = ptr2;
		}
	}
	return (0);
}


/*
 * parse_vol_resp() assumes the format of the data response, the
 * following information is expected in the volume data:
 * vol_id, acs, lsm, panel, row, column, pool, status, media, and type
 */
static int
parse_vol_resp(void *buf, mms_list_t *vol_list)
{

	ACS_DISPLAY_RESPONSE	*res;
	size_t			l;
	char			*ptr1, *ptr2;
	mms_acscart_t		*vol;
	char			junkbuf[1024];

	if ((buf == NULL) || (vol_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	res = (ACS_DISPLAY_RESPONSE *)buf;
	if (res->display_status != STATUS_SUCCESS) {
		return (MMS_MGMT_ERR_ACSLS_RSP);
	}

	ptr1 = &res->display_xml_data.xml_data[0];

	ptr2 = strstr(ptr1, "</data></display></response>");
	if (ptr2 != NULL) {
		*ptr2 = NULL;
	};

	mms_trace(MMS_DEBUG, "Display ACS response: %s", ptr1);

	if ((ptr2 = strstr(ptr1, "<data>")) != NULL) {

		/* only create the list if it's the first time through */
		if (vol_list->list_size == 0) {
			mms_list_create(vol_list, sizeof (mms_acscart_t),
			    offsetof(mms_acscart_t, next));
		}

		while ((ptr2 = strstr(ptr1, "<r>")) != NULL) {
			vol = calloc(1, sizeof (mms_acscart_t));
			if (vol == NULL) {
				return (ENOMEM);
			}
			/* extract string from <f ....>..</f> */
			ptr2 += 3; /* skip past <r> */

			l = parse_f(ptr2, vol->label, sizeof (vol->label));
			ptr2 += l;
			l = parse_f_int(ptr2, (uint32_t *)&vol->libacs);
			ptr2 += l;
			l = parse_f_int(ptr2, (uint32_t *)&vol->liblsm);
			ptr2 += l;
			/* drive */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			/* type - cleaning|data */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			l = parse_f(ptr2, vol->mtype, sizeof (vol->mtype));
			ptr2 += l;
			/* status */
			l = parse_f(ptr2, junkbuf, sizeof (junkbuf));
			ptr2 += l;
			l = parse_f_date(ptr2, &vol->access);
			ptr2 += l;

			mms_list_insert_tail(vol_list, vol);

			/* advance to the start of the next volume */
			ptr2 = strstr(ptr2, "</r>");
			if (ptr2 == NULL) {
				/* malformed response */
				break;
			}
			ptr1 = ptr2 + 4;
		}
	}
	return (0);
}


/*
 * parse_lsm_resp() parses the response data assuming a particular
 * format for the data. The following information is expected in the
 * response:- acs, lsm, status, state and serial number
 *
 */
static int
parse_lsm_resp(
	void	*buf,
	mms_list_t	*lsm_list)
{
	ACS_DISPLAY_RESPONSE	*res;
	size_t			l;
	char			*ptr1, *ptr2;
	mms_acslib_t		*lsm;
	char			status[1024];
	char			state[1024];

	if ((buf == NULL) || (lsm_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	res = (ACS_DISPLAY_RESPONSE *)buf;
	if (res->display_status != STATUS_SUCCESS) {
		return (MMS_MGMT_ERR_ACSLS_RSP);
	}

	ptr1 = &res->display_xml_data.xml_data[0];

	ptr2 = strstr(ptr1, "</data></display></response>");
	if (ptr2 != NULL) {
		*ptr2 = NULL;
	};

	mms_trace(MMS_DEBUG, "Display response: %s", ptr1);

	if ((ptr2 = strstr(ptr1, "<data>")) != NULL) {
		if (lsm_list->list_size == 0) {
			mms_list_create(lsm_list, sizeof (mms_acslib_t),
			    offsetof(mms_acslib_t, lib_link));
		}

		while ((ptr2 = strstr(ptr1, "<r>")) != NULL) {

			lsm = calloc(1, sizeof (mms_acslib_t));
			if (lsm == NULL) {
				return (ENOMEM);
			}

			ptr2 += 3; /* skip past <r> */
			l = parse_f_int(ptr2, &lsm->acs);
			ptr2 += l;
			l = parse_f_int(ptr2, &lsm->lsm);
			ptr2 += l;
			/* parse status and state to flags */
			l = parse_f(ptr2, status, sizeof (status));
			ptr2 += l;
			l = parse_f(ptr2, state, sizeof (state));
			ptr2 += l;
			l = parse_f(ptr2, lsm->serialnum,
			    sizeof (lsm->serialnum));
			ptr2 += l;
			l = parse_f(ptr2, lsm->type, sizeof (lsm->type));
			ptr2 += l;

			mms_list_insert_tail(lsm_list, lsm);

			/* advance to the start of the next drive */
			ptr2 = strstr(ptr2, "</r>");
			if (ptr2 == NULL) {
				/* malformed response */
				break;
			}
			ptr1 = ptr2 + 4;
		}
	}
	return (0);
}

static int /* return number of characters parsed */
parse_f(char *f, char *s, size_t len) {

	size_t n;
	char *ptr;

	if (f == NULL || strlen(f) == 0) {
		return (0);
	}

	ptr = strstr(f, "</f>");
	if (ptr != NULL) {
		*ptr = '\0';
	}
	n = strlen(f);

	ptr = strchr(f, '>');
	if (ptr == NULL) {
		return (0);
	}

	ptr++;

	(void) strlcpy(s, ptr, len);

	return (n + 4);
}

/* parse just a single char */
static int
parse_f_int(char *f, uint32_t *i)
{
	char	*ptr;
	char	*ptr2;
	size_t	n;
	char	buf[4];
	int	j;

	if (!f || !i) {
		return (0);
	}

	ptr = strchr(f, '>');
	if (ptr == NULL) {
		return (0);
	}

	ptr++;

	for (j = 0; j < 4; j++, ptr++) {
		if (!isdigit(*ptr)) {
			break;
		}
		buf[j] = *ptr;
	}

	ptr2 = strchr(ptr, '>');
	if (ptr2 == NULL) {
		return (0);
	}
	n = (++ptr2 - f);

	*i = atoi(buf);

	return (n);
}

static int
parse_f_date(char *f, time_t *t)
{
	struct tm	tm;
	char		*ptr;
	size_t		n;

	if (!f || !t) {
		return (0);
	}

	ptr = strchr(f, '>');
	if (ptr == NULL) {
		return (0);
	}

	ptr++;

	ptr = strptime(ptr, "%Y-%m-%d %T", &tm);

	ptr = strstr(ptr, "</f>");
	if (ptr == NULL) {
		return (0);
	}
	ptr += 4;

	n = ptr - f;

	*t = mktime(&tm);
return (n);
}

/*
 * get volumes from an acs library, given the name of the acsls
 * hostname and port.
 *
 * in_vols is optional, allows the requester to ask for only
 * those volumes he/she is interested in.
 *
 */
int
get_acs_volumes(
	char *acshost,
	char *in_vols,
	mms_list_t *vol_list
)
{
	int		st;

	if ((acshost == NULL) || (vol_list == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	/* check if the acsls host is accessible and start if it not */
	if (acs_start_ssi(acshost, NULL) != 0) {
		return (MMS_MGMT_ERR_EXEC_SSI);
	}

	st = acs_display_info(ACS_DISPLAY_VOL, in_vols, vol_list);
	if (st != 0) {
		return (st);
	}

	return (st);
}
