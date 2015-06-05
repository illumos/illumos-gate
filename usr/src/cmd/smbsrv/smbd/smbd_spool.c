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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * CUPS support for the SMB and SPOOLSS print services.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/atomic.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <synch.h>
#include <dlfcn.h>
#include <errno.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_share.h>
#include "smbd.h"

#ifdef	HAVE_CUPS
#include <cups/cups.h>

#define	SMB_SPOOL_WAIT			2
#define	SMBD_PJOBLEN			256
#define	SMBD_PRINTER			"Postscript"
#define	SMBD_FN_PREFIX			"cifsprintjob-"
#define	SMBD_CUPS_SPOOL_DIR		"//var//spool//cups"
#define	SMBD_CUPS_DOCNAME		"generic_doc"

typedef struct smbd_printjob {
	pid_t		pj_pid;
	int		pj_sysjob;
	int		pj_fd;
	time_t		pj_start_time;
	int		pj_status;
	size_t		pj_size;
	int		pj_page_count;
	boolean_t	pj_isspooled;
	boolean_t	pj_jobnum;
	char		pj_filename[SMBD_PJOBLEN];
	char		pj_jobname[SMBD_PJOBLEN];
	char		pj_username[SMBD_PJOBLEN];
	char		pj_queuename[SMBD_PJOBLEN];
} smbd_printjob_t;

typedef struct smb_cups_ops {
	void		*cups_hdl;
	cups_lang_t	*(*cupsLangDefault)();
	const char	*(*cupsLangEncoding)(cups_lang_t *);
	void		(*cupsLangFree)(cups_lang_t *);
	ipp_status_t	(*cupsLastError)();
	int		(*cupsGetDests)(cups_dest_t **);
	void		(*cupsFreeDests)(int, cups_dest_t *);
	ipp_t		*(*cupsDoFileRequest)(http_t *, ipp_t *,
	    const char *, const char *);
	ipp_t		*(*ippNew)();
	void		(*ippDelete)();
	char		*(*ippErrorString)();
	ipp_attribute_t	*(*ippAddString)();
	void		(*httpClose)(http_t *);
	http_t		*(*httpConnect)(const char *, int);
} smb_cups_ops_t;

static uint32_t smbd_cups_jobnum = 1;
static smb_cups_ops_t smb_cups;
static mutex_t smbd_cups_mutex;

static void *smbd_spool_monitor(void *);
static smb_cups_ops_t *smbd_cups_ops(void);
static void smbd_print_share_comment(smb_share_t *, cups_dest_t *);
static void *smbd_share_printers(void *);
static void smbd_spool_copyfile(smb_inaddr_t *, char *, char *, char *);

extern smbd_t smbd;

/*
 * Start the spool thread.
 * Returns 0 on success, an error number if thread creation fails.
 */
void
smbd_spool_start(void)
{
	pthread_attr_t	attr;
	int		rc;

	if (!smb_config_getbool(SMB_CI_PRINT_ENABLE))
		return;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&smbd.s_spool_tid, &attr, smbd_spool_monitor, NULL);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		syslog(LOG_NOTICE,
		    "failed to start print monitor: %s", strerror(errno));
}

/*
 * A single pthread_kill should be sufficient but we include
 * a couple of retries to avoid implementation idiosyncrasies
 * around signal delivery.
 */
void
smbd_spool_stop(void)
{
	int	i;

	if (pthread_self() == smbd.s_spool_tid)
		return;

	for (i = 0; i < 3 && smbd.s_spool_tid != 0; ++i) {
		if (pthread_kill(smbd.s_spool_tid, SIGTERM) == ESRCH)
			break;

		(void) sleep(1);
	}
}

/*
 * This thread blocks waiting for close print file in the kernel.
 * It then uses the data returned from the ioctl to copy the spool file
 * into the cups spooler.
 *
 * This mechanism is really only used by Windows Vista and Windows 7.
 * Other versions of Windows create a zero size file, which is removed
 * by smbd_spool_copyfile.
 */
/*ARGSUSED*/
static void *
smbd_spool_monitor(void *arg)
{
	uint32_t	spool_num;
	char		username[MAXNAMELEN];
	char		path[MAXPATHLEN];
	smb_inaddr_t	ipaddr;
	int		error_retry_cnt = 5;

	smbd_online_wait("smbd_spool_monitor");

	spoolss_register_copyfile(smbd_spool_copyfile);

	while (!smbd.s_shutting_down && (error_retry_cnt > 0)) {
		errno = 0;

		if (smb_kmod_get_spool_doc(&spool_num, username,
		    path, &ipaddr) == 0) {
			smbd_spool_copyfile(&ipaddr,
			    username, path, SMBD_CUPS_DOCNAME);
			error_retry_cnt = 5;
		} else {
			if (errno == ECANCELED)
				break;
			if ((errno != EINTR) && (errno != EAGAIN))
				error_retry_cnt--;
			(void) sleep(SMB_SPOOL_WAIT);
		}
	}

	spoolss_register_copyfile(NULL);
	smbd.s_spool_tid = 0;
	return (NULL);
}

/*
 * All versions of windows use this function to spool files to a printer
 * via the cups interface
 */
static void
smbd_spool_copyfile(smb_inaddr_t *ipaddr, char *username, char *path,
    char *doc_name)
{
	smb_cups_ops_t	*cups;
	http_t		*http = NULL;		/* HTTP connection to server */
	ipp_t		*request = NULL;	/* IPP Request */
	ipp_t		*response = NULL;	/* IPP Response */
	cups_lang_t	*language = NULL;	/* Default language */
	char		uri[HTTP_MAX_URI];	/* printer-uri attribute */
	char		new_jobname[SMBD_PJOBLEN];
	smbd_printjob_t	pjob;
	char		clientname[INET6_ADDRSTRLEN];
	struct stat 	sbuf;
	int		rc = 1;

	if (stat(path, &sbuf)) {
		syslog(LOG_INFO, "smbd_spool_copyfile: %s: %s",
		    path, strerror(errno));
		return;
	}

	/*
	 * Remove zero size files and return; these were inadvertantly
	 * created by XP or 2000.
	 */
	if (sbuf.st_size == 0) {
		if (remove(path) != 0)
			syslog(LOG_INFO,
			    "smbd_spool_copyfile: cannot remove %s: %s",
			    path, strerror(errno));
		return;
	}

	if ((cups = smbd_cups_ops()) == NULL)
		return;

	if ((http = cups->httpConnect("localhost", 631)) == NULL) {
		syslog(LOG_INFO,
		    "smbd_spool_copyfile: cupsd not running");
		return;
	}

	if ((request = cups->ippNew()) == NULL) {
		syslog(LOG_INFO,
		    "smbd_spool_copyfile: ipp not running");
		return;
	}

	request->request.op.operation_id = IPP_PRINT_JOB;
	request->request.op.request_id = 1;
	language = cups->cupsLangDefault();

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
	    "attributes-charset", NULL, cups->cupsLangEncoding(language));

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
	    "attributes-natural-language", NULL, language->language);

	(void) snprintf(uri, sizeof (uri), "ipp://localhost/printers/%s",
	    SMBD_PRINTER);
	pjob.pj_pid = pthread_self();
	pjob.pj_sysjob = 10;
	(void) strlcpy(pjob.pj_filename, path, SMBD_PJOBLEN);
	pjob.pj_start_time = time(NULL);
	pjob.pj_status = 2;
	pjob.pj_size = sbuf.st_blocks * 512;
	pjob.pj_page_count = 1;
	pjob.pj_isspooled = B_TRUE;
	pjob.pj_jobnum = smbd_cups_jobnum;

	(void) strlcpy(pjob.pj_jobname, doc_name, SMBD_PJOBLEN);
	(void) strlcpy(pjob.pj_username, username, SMBD_PJOBLEN);
	(void) strlcpy(pjob.pj_queuename, SMBD_CUPS_SPOOL_DIR, SMBD_PJOBLEN);

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
	    "printer-uri", NULL, uri);

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "requesting-user-name", NULL, pjob.pj_username);

	if (smb_inet_ntop(ipaddr, clientname,
	    SMB_IPSTRLEN(ipaddr->a_family)) == NULL) {
		syslog(LOG_INFO,
		    "smbd_spool_copyfile: %s: unknown client", clientname);
		goto out;
	}

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "job-originating-host-name", NULL, clientname);

	(void) snprintf(new_jobname, SMBD_PJOBLEN, "%s%d",
	    SMBD_FN_PREFIX, pjob.pj_jobnum);
	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "job-name", NULL, new_jobname);

	(void) snprintf(uri, sizeof (uri) - 1, "/printers/%s", SMBD_PRINTER);

	response = cups->cupsDoFileRequest(http, request, uri,
	    pjob.pj_filename);
	if (response != NULL) {
		if (response->request.status.status_code >= IPP_OK_CONFLICT) {
			syslog(LOG_ERR,
			    "smbd_spool_copyfile: printer %s: %s",
			    SMBD_PRINTER,
			    cups->ippErrorString(cups->cupsLastError()));
		} else {
			atomic_inc_32(&smbd_cups_jobnum);
			rc = 0;
		}
	} else {
		syslog(LOG_ERR,
		    "smbd_spool_copyfile: unable to print to %s",
		    cups->ippErrorString(cups->cupsLastError()));
	}

	if (rc == 0)
		(void) unlink(pjob.pj_filename);

out:
	if (response)
		cups->ippDelete(response);

	if (language)
		cups->cupsLangFree(language);

	if (http)
		cups->httpClose(http);
}

int
smbd_cups_init(void)
{
	(void) mutex_lock(&smbd_cups_mutex);

	if (smb_cups.cups_hdl != NULL) {
		(void) mutex_unlock(&smbd_cups_mutex);
		return (0);
	}

	if ((smb_cups.cups_hdl = dlopen("libcups.so.2", RTLD_NOW)) == NULL) {
		(void) mutex_unlock(&smbd_cups_mutex);
		syslog(LOG_DEBUG,
		    "smbd_cups_init: cannot open libcups");
		return (ENOENT);
	}

	smb_cups.cupsLangDefault =
	    (cups_lang_t *(*)())dlsym(smb_cups.cups_hdl, "cupsLangDefault");
	smb_cups.cupsLangEncoding = (const char *(*)(cups_lang_t *))
	    dlsym(smb_cups.cups_hdl, "cupsLangEncoding");
	smb_cups.cupsDoFileRequest =
	    (ipp_t *(*)(http_t *, ipp_t *, const char *, const char *))
	    dlsym(smb_cups.cups_hdl, "cupsDoFileRequest");
	smb_cups.cupsLastError = (ipp_status_t (*)())
	    dlsym(smb_cups.cups_hdl, "cupsLastError");
	smb_cups.cupsLangFree = (void (*)(cups_lang_t *))
	    dlsym(smb_cups.cups_hdl, "cupsLangFree");
	smb_cups.cupsGetDests = (int (*)(cups_dest_t **))
	    dlsym(smb_cups.cups_hdl, "cupsGetDests");
	smb_cups.cupsFreeDests = (void (*)(int, cups_dest_t *))
	    dlsym(smb_cups.cups_hdl, "cupsFreeDests");

	smb_cups.httpClose = (void (*)(http_t *))
	    dlsym(smb_cups.cups_hdl, "httpClose");
	smb_cups.httpConnect = (http_t *(*)(const char *, int))
	    dlsym(smb_cups.cups_hdl, "httpConnect");

	smb_cups.ippNew = (ipp_t *(*)())dlsym(smb_cups.cups_hdl, "ippNew");
	smb_cups.ippDelete = (void (*)())dlsym(smb_cups.cups_hdl, "ippDelete");
	smb_cups.ippErrorString = (char *(*)())
	    dlsym(smb_cups.cups_hdl, "ippErrorString");
	smb_cups.ippAddString = (ipp_attribute_t *(*)())
	    dlsym(smb_cups.cups_hdl, "ippAddString");

	if (smb_cups.cupsLangDefault == NULL ||
	    smb_cups.cupsLangEncoding == NULL ||
	    smb_cups.cupsDoFileRequest == NULL ||
	    smb_cups.cupsLastError == NULL ||
	    smb_cups.cupsLangFree == NULL ||
	    smb_cups.cupsGetDests == NULL ||
	    smb_cups.cupsFreeDests == NULL ||
	    smb_cups.ippNew == NULL ||
	    smb_cups.httpClose == NULL ||
	    smb_cups.httpConnect == NULL ||
	    smb_cups.ippDelete == NULL ||
	    smb_cups.ippErrorString == NULL ||
	    smb_cups.ippAddString == NULL) {
		(void) dlclose(smb_cups.cups_hdl);
		smb_cups.cups_hdl = NULL;
		(void) mutex_unlock(&smbd_cups_mutex);
		syslog(LOG_DEBUG,
		    "smbd_cups_init: cannot load libcups");
		return (ENOENT);
	}

	(void) mutex_unlock(&smbd_cups_mutex);
	return (0);
}

void
smbd_cups_fini(void)
{
	(void) mutex_lock(&smbd_cups_mutex);

	if (smb_cups.cups_hdl != NULL) {
		(void) dlclose(smb_cups.cups_hdl);
		smb_cups.cups_hdl = NULL;
	}

	(void) mutex_unlock(&smbd_cups_mutex);
}

static smb_cups_ops_t *
smbd_cups_ops(void)
{
	if (smb_cups.cups_hdl == NULL)
		return (NULL);

	return (&smb_cups);
}

void
smbd_load_printers(void)
{
	pthread_t	tid;
	pthread_attr_t	attr;
	int		rc;

	if (!smb_config_getbool(SMB_CI_PRINT_ENABLE))
		return;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &attr, smbd_share_printers, &tid);
	(void) pthread_attr_destroy(&attr);

	if (rc != 0)
		syslog(LOG_NOTICE,
		    "unable to load printer shares: %s", strerror(errno));
}

/*
 * All print shares use the path from print$.
 */
/*ARGSUSED*/
static void *
smbd_share_printers(void *arg)
{
	cups_dest_t	*dests;
	cups_dest_t	*dest;
	smb_cups_ops_t	*cups;
	smb_share_t	si;
	uint32_t	nerr;
	int		num_dests;
	int		i;

	if (!smb_config_getbool(SMB_CI_PRINT_ENABLE))
		return (NULL);

	if ((cups = smbd_cups_ops()) == NULL)
		return (NULL);

	if (smb_shr_get(SMB_SHARE_PRINT, &si) != NERR_Success) {
		syslog(LOG_DEBUG,
		    "smbd_share_printers unable to load %s", SMB_SHARE_PRINT);
		return (NULL);
	}

	num_dests = cups->cupsGetDests(&dests);

	for (i = num_dests, dest = dests; i > 0; i--, dest++) {
		if (dest->instance != NULL)
			continue;

		(void) strlcpy(si.shr_name, dest->name, MAXPATHLEN);
		smbd_print_share_comment(&si, dest);
		si.shr_type = STYPE_PRINTQ;

		nerr = smb_shr_add(&si);
		if (nerr == NERR_Success || nerr == NERR_DuplicateShare)
			syslog(LOG_DEBUG,
			    "shared printer: %s", si.shr_name);
		else
			syslog(LOG_DEBUG,
			    "smbd_share_printers: unable to add share %s: %u",
			    si.shr_name, nerr);
	}

	cups->cupsFreeDests(num_dests, dests);
	return (NULL);
}

static void
smbd_print_share_comment(smb_share_t *si, cups_dest_t *dest)
{
	cups_option_t	*options;
	char		*comment;
	char		*name;
	char		*value;
	int		i;

	comment = "Print Share";

	if ((options = dest->options) == NULL) {
		(void) strlcpy(si->shr_cmnt, comment, SMB_SHARE_CMNT_MAX);
		return;
	}

	for (i = 0; i < dest->num_options; ++i) {
		name = options[i].name;
		value = options[i].value;

		if (name == NULL || value == NULL ||
		    *name == '\0' || *value == '\0')
			continue;

		if (strcasecmp(name, "printer-info") == 0) {
			comment = value;
			break;
		}
	}

	(void) strlcpy(si->shr_cmnt, comment, SMB_SHARE_CMNT_MAX);
}

#else	/* HAVE_CUPS */

/*
 * If not HAVE_CUPS, just provide a few "stubs".
 */

int
smbd_cups_init(void)
{
	return (ENOENT);
}

void
smbd_cups_fini(void)
{
}

void
smbd_load_printers(void)
{
}

void
smbd_spool_init(void)
{
}

void
smbd_spool_fini(void)
{
}

void
smbd_spool_start(void)
{
}

void
smbd_spool_stop(void)
{
}

#endif 	/* HAVE_CUPS */
