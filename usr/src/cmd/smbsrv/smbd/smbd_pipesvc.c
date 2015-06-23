/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This is the named pipe service for smbd.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <synch.h>
#include <unistd.h>
#include <fcntl.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_xdr.h>
#include "smbd.h"

struct pipe_listener {
	const char *name;
	int max_allowed;
	int max_seen;
	int current;
	pthread_t tid;
};

static void *pipesvc_listener(void *);
static void *pipesvc_worker(void *);
static int pipe_send(ndr_pipe_t *, void *, size_t);
static int pipe_recv(ndr_pipe_t *, void *, size_t);

mutex_t  pipesvc_mutex = DEFAULTMUTEX;
int pipesvc_workers_max = 500;
int pipesvc_workers_cur = 0;

uint16_t pipe_max_msgsize = SMB_PIPE_MAX_MSGSIZE;

/*
 * Allow more opens on SRVSVC because that's used by many clients
 * to get the share list, etc.
 */
#define	SRVSVC_MAX_OPENS	200
#define	DEF_MAX_OPENS		50

#define	NLISTENERS	11
static struct pipe_listener
pipe_listeners[NLISTENERS] = {
	{ "eventlog",	DEF_MAX_OPENS, 0, 0 },
	{ "lsarpc",	DEF_MAX_OPENS, 0, 0 },
	{ "lsass",	DEF_MAX_OPENS, 0, 0 },
	{ "netdfs",	DEF_MAX_OPENS, 0, 0 },
	{ "netlogon",	DEF_MAX_OPENS, 0, 0 },
	{ "samr",	DEF_MAX_OPENS, 0, 0 },
	{ "spoolss",	DEF_MAX_OPENS, 0, 0 },
	{ "srvsvc",	SRVSVC_MAX_OPENS, 0, 0 },
	{ "svcctl",	DEF_MAX_OPENS, 0, 0 },
	{ "winreg",	DEF_MAX_OPENS, 0, 0 },
	{ "wkssvc",	DEF_MAX_OPENS, 0, 0 },
};

static ndr_pipe_t *
np_new(struct pipe_listener *pl, int fid)
{
	ndr_pipe_t *np;
	size_t len;

	/*
	 * Allocating ndr_pipe_t + smb_netuserinfo_t as one.
	 * We could just make that part of ndr_pipe_t, but
	 * that struct is opaque to libmlrpc.
	 */
	len = sizeof (*np) + sizeof (smb_netuserinfo_t);
	np = malloc(len);
	if (np == NULL)
		return (NULL);

	bzero(np, len);
	np->np_listener = pl;
	np->np_endpoint = pl->name;
	np->np_user = (void*)(np + 1);
	np->np_send = pipe_send;
	np->np_recv = pipe_recv;
	np->np_fid = fid;
	np->np_max_xmit_frag = pipe_max_msgsize;
	np->np_max_recv_frag = pipe_max_msgsize;

	return (np);
}

static void
np_free(ndr_pipe_t *np)
{
	(void) close(np->np_fid);
	free(np);
}

/*
 * Create the smbd opipe door service.
 * Returns the door descriptor on success.  Otherwise returns -1.
 */
int
smbd_pipesvc_start(void)
{
	pthread_t tid;
	pthread_attr_t tattr;
	struct pipe_listener *pl;
	int i, rc;

	if (mlsvc_init() != 0) {
		smbd_report("msrpc initialization failed");
		return (-1);
	}

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

	for (i = 0; i < NLISTENERS; i++) {
		pl = &pipe_listeners[i];
		pl->max_seen = 0;

		if (strcasecmp(pl->name, "spoolss") == 0 &&
		    smb_config_getbool(SMB_CI_PRINT_ENABLE) == B_FALSE)
			continue;

		rc = pthread_create(&tid, &tattr, pipesvc_listener, pl);
		if (rc != 0)
			break;
		pipe_listeners[i].tid = tid;
	}

	if (rc != 0) {
		smbd_report("pipesvc pthread_create, %d", rc);
	}

	(void) pthread_attr_destroy(&tattr);

	return (rc);
}

void
smbd_pipesvc_stop(void)
{
	int i;

	(void) mutex_lock(&pipesvc_mutex);
	for (i = 0; i < NLISTENERS; i++) {
		if (pipe_listeners[i].tid == 0)
			continue;
		(void) pthread_kill(pipe_listeners[i].tid, SIGTERM);
		pipe_listeners[i].tid = 0;
	}
	(void) mutex_unlock(&pipesvc_mutex);
}

static void *
pipesvc_listener(void *varg)
{
	struct sockaddr_un sa;
	int err, listen_fd, newfd, snlen;
	struct pipe_listener *pl = varg;
	ndr_pipe_t *np;
	pthread_t tid;
	int rc;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		smbd_report("pipesvc_listener, so_create: %d", errno);
		return (NULL);
	}

	bzero(&sa, sizeof (sa));
	sa.sun_family = AF_UNIX;
	(void) snprintf(sa.sun_path, sizeof (sa.sun_path),
	    "%s/%s", SMB_PIPE_DIR, pl->name);

	/* Bind it to a listening name. */
	(void) unlink(sa.sun_path);
	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof (sa)) < 0) {
		smbd_report("pipesvc_listener, so_bind: %d", errno);
		(void) close(listen_fd);
		return (NULL);
	}

	if (listen(listen_fd, SOMAXCONN) < 0) {
		smbd_report("pipesvc_listener, listen: %d", errno);
		(void) close(listen_fd);
		return (NULL);
	}

	for (;;) {

		snlen = sizeof (sa);
		newfd = accept(listen_fd, (struct sockaddr *)&sa, &snlen);
		if (newfd < 0) {
			err = errno;
			switch (err) {
			case ECONNABORTED:
				continue;
			case EINTR:
				/* normal termination */
				goto out;
			default:
				smbd_report("pipesvc_listener, "
				    "accept failed: %d", errno);
			}
			smbd_report("pipesvc_listener, accept: %d", err);
			break;
		}

		np = np_new(pl, newfd);
		if (np == NULL) {
			smbd_report("pipesvc_listener, alloc1 failed");
			(void) close(newfd);
			continue;
		}

		rc = pthread_create(&tid, NULL, pipesvc_worker, np);
		if (rc != 0) {
			smbd_report("pipesvc_listener, pthread_create: %d",
			    errno);
			np_free(np);
			continue;
		}
		(void) pthread_detach(tid);

		/* Note: np_free in pipesvc_worker */
		np = NULL;
	}

out:
	(void) close(listen_fd);
	pl->tid = 0;
	return (NULL);
}

static void *
pipesvc_worker(void *varg)
{
	XDR xdrs;
	smb_pipehdr_t phdr;
	ndr_pipe_t *np = varg;
	struct pipe_listener *pl = np->np_listener;
	void *buf = NULL;
	uint32_t status;
	ssize_t rc;

	(void) mutex_lock(&pipesvc_mutex);
	if (pipesvc_workers_cur >= pipesvc_workers_max ||
	    pl->current >= pl->max_allowed) {
		(void) mutex_unlock(&pipesvc_mutex);
		status = NT_STATUS_PIPE_NOT_AVAILABLE;
		(void) send(np->np_fid, &status, sizeof (status), 0);
		goto out_free_np;
	}
	pipesvc_workers_cur++;
	pl->current++;
	if (pl->max_seen < pl->current)
		pl->max_seen = pl->current;
	(void) mutex_unlock(&pipesvc_mutex);

	/*
	 * The smbsrv kmod sends us one initial message containing an
	 * XDR encoded smb_netuserinfo_t that we read and decode here,
	 * all unbeknownst to libmlrpc.
	 *
	 * Might be nice to enhance getpeerucred() so it can give us
	 * all the info smb_netuserinfo_t carries, and then use that,
	 * which would allow using a more generic RPC service.
	 */
	rc = pipe_recv(np, &phdr, sizeof (phdr));
	if (rc != 0) {
		smbd_report("pipesvc_worker, recv1: %d", rc);
		goto out_decr;
	}
	if (phdr.ph_magic != SMB_PIPE_HDR_MAGIC ||
	    phdr.ph_uilen > 8192) {
		smbd_report("pipesvc_worker, bad hdr");
		goto out_decr;
	}
	buf = malloc(phdr.ph_uilen);
	if (buf == NULL) {
		smbd_report("pipesvc_worker, alloc1 failed");
		goto out_decr;
	}
	rc = pipe_recv(np, buf, phdr.ph_uilen);
	if (rc != 0) {
		smbd_report("pipesvc_worker, recv2: %d", rc);
		goto out_decr;
	}

	xdrmem_create(&xdrs, buf, phdr.ph_uilen, XDR_DECODE);
	if (!smb_netuserinfo_xdr(&xdrs, np->np_user)) {
		smbd_report("pipesvc_worker, bad uinfo");
		goto out_free_buf;
	}

	/*
	 * Later, could disallow opens of some pipes by
	 * anonymous users, etc.  For now, reply "OK".
	 */
	status = 0;
	rc = pipe_send(np, &status, sizeof (status));
	if (rc != 0) {
		smbd_report("pipesvc_worker, send1: %d", rc);
		goto out_free_buf;
	}

	/*
	 * Run the RPC service loop worker, which
	 * returns when it sees the pipe close.
	 */
	ndr_pipe_worker(np);

	xdrs.x_op = XDR_FREE;
	(void) smb_netuserinfo_xdr(&xdrs, np->np_user);

out_free_buf:
	free(buf);
	xdr_destroy(&xdrs);

out_decr:
	(void) mutex_lock(&pipesvc_mutex);
	pipesvc_workers_cur--;
	pl->current--;
	(void) mutex_unlock(&pipesvc_mutex);

out_free_np:
	/* Cleanup what came in by varg. */
	(void) shutdown(np->np_fid, SHUT_RDWR);
	np_free(np);
	return (NULL);
}

/*
 * These are the transport get/put callback functions provided
 * via the ndr_pipe_t object to the libmlrpc`ndr_pipe_worker.
 * These are called only with known PDU sizes and should
 * loop as needed to transfer the entire message.
 */
static int
pipe_recv(ndr_pipe_t *np, void *buf, size_t len)
{
	int x;

	while (len > 0) {
		x = recv(np->np_fid, buf, len, 0);
		if (x < 0)
			return (errno);
		if (x == 0)
			return (EIO);
		buf = (char *)buf + x;
		len -= x;
	}

	return (0);
}

static int
pipe_send(ndr_pipe_t *np, void *buf, size_t len)
{
	int x;

	while (len > 0) {
		x = send(np->np_fid, buf, len, 0);
		if (x < 0)
			return (errno);
		if (x == 0)
			return (EIO);
		buf = (char *)buf + x;
		len -= x;
	}

	return (0);
}
