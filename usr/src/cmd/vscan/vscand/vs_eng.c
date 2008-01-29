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

/*
 * vs_eng.c manages the vs_engines array of scan engine.
 * Access to the array and other private data is protected by vs_eng_mutex.
 * A caller can wait for an available engine connection on vs_eng_cv
 *
 */

#include <sys/types.h>
#include <sys/synch.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/debug.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>

#include "vs_incl.h"


typedef struct vs_engine {
	vs_props_se_t vse_cfg;	/* host, port, maxcon */
	int vse_in_use;	/* # connections in use */
	int vse_error;
	vs_eng_conn_t vse_conn_root;
} vs_engine_t;

static vs_engine_t vs_engines[VS_SE_MAX];

static int vs_eng_next;		/* round-robin "finger" */
static int vs_eng_count;	/* how many configured engines */
static int vs_eng_total_maxcon;	/* total configured connections */
static int vs_eng_total_inuse;	/* total connections in use */
static int vs_eng_wait_count;	/* # threads waiting for connection */

static pthread_mutex_t vs_eng_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vs_eng_cv;
static pthread_cond_t vs_eng_shutdown_cv;

static time_t vs_eng_wait = VS_ENG_WAIT_DFLT;

/* local functions */
static int vs_eng_check_errors(void);
static int vs_eng_find_next(int);
static void vs_eng_add_connection(vs_eng_conn_t *);
static void vs_eng_remove_connection(vs_eng_conn_t *);
static void vs_eng_close_connections(void);
static int vs_eng_compare(int, char *, int);


#ifdef FIONBIO
/* non-blocking connect */
static int nbio_connect(vs_eng_conn_t *, const struct sockaddr *, int);
int vs_connect_timeout = 5000; /* milliseconds */
#endif /* FIONBIO */


/*
 * vs_eng_init
 */
void
vs_eng_init()
{
	(void) pthread_cond_init(&vs_eng_cv, NULL);
	(void) pthread_cond_init(&vs_eng_shutdown_cv, NULL);
	(void) pthread_mutex_lock(&vs_eng_mutex);

	(void) memset(vs_engines, 0,
	    sizeof (vs_engine_t) * VS_SE_MAX);
	vs_eng_total_maxcon = 0;
	vs_eng_total_inuse = 0;
	vs_eng_count = 0;
	vs_eng_next = 0;

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_config
 *
 * Configure scan engine connections.
 *
 * If a scan engine has been reconfigured (different host or port)
 * the scan engine's error count is reset.
 *
 * vs_icap_config is invoked to reset engine-specific data stored
 * in vs_icap.
 *
 */
void
vs_eng_config(vs_props_all_t *config)
{
	int i;
	vs_props_se_t *cfg;
	vs_engine_t *eng;

	(void) pthread_mutex_lock(&vs_eng_mutex);

	vs_eng_count = 0;
	vs_eng_total_maxcon = 0;

	for (i = 0; i < VS_SE_MAX; i++) {
		cfg = &config->va_se[i];
		eng = &vs_engines[i];

		if (vs_eng_compare(i, cfg->vep_host, cfg->vep_port) != 0)
			eng->vse_error = 0;

		if (cfg->vep_enable) {
			eng->vse_cfg = *cfg;
			vs_eng_total_maxcon += cfg->vep_maxconn;
			vs_eng_count++;
		} else {
			(void) memset(&eng->vse_cfg, 0, sizeof (vs_props_se_t));
		}

		vs_icap_config(i, eng->vse_cfg.vep_host, eng->vse_cfg.vep_port);
	}

	if ((vs_eng_total_maxcon <= 0) || (vs_eng_count == 0))
		syslog(LOG_WARNING, "Scan Engine - no engines configured");

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_fini
 *
 * Close all scan engine connections to abort in-progress scans,
 * and wait until all to sessions are complete, and there are no
 * waiting threads.
 * Set vs_eng_total_maxcon to 0 to ensure no new engine sessions
 * can be initiated while we're waiting.
 */
void
vs_eng_fini()
{
	(void) pthread_mutex_lock(&vs_eng_mutex);

	vs_eng_total_maxcon = 0;

	vs_eng_close_connections();

	while (vs_eng_total_inuse > 0 || vs_eng_wait_count > 0)
		(void) pthread_cond_wait(&vs_eng_shutdown_cv, &vs_eng_mutex);

	(void) pthread_mutex_unlock(&vs_eng_mutex);
	(void) pthread_cond_destroy(&vs_eng_cv);
	(void) pthread_cond_destroy(&vs_eng_shutdown_cv);
}


/*
 * vs_eng_set_error
 *
 * If the engine identified in conn (host, port) matches the
 * engine in vs_engines set or clear the error state of the
 * engine and update the error statistics.
 *
 * If error == 0, clear the error state(0), else set the error
 * state (1)
 */
void
vs_eng_set_error(vs_eng_conn_t *conn, int error)
{
	int idx = conn->vsc_idx;

	(void) pthread_mutex_lock(&vs_eng_mutex);

	if (vs_eng_compare(idx, conn->vsc_host, conn->vsc_port) == 0)
		vs_engines[idx].vse_error = error ? 1 : 0;

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}



/*
 * vs_eng_get
 * Get next available scan engine connection.
 * If retry != 0 look for a scan engine with no errors.
 *
 * Returns: 0 - success
 *         -1 - error
 */
int
vs_eng_get(vs_eng_conn_t *conn, int retry)
{
	struct timespec tswait;
	int idx;

	(void) pthread_mutex_lock(&vs_eng_mutex);

	/*
	 * If no engines connections configured or
	 * retry and only one engine configured, give up
	 */
	if ((vs_eng_total_maxcon <= 0) || (retry && (vs_eng_count <= 1))) {
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		return (-1);
	}

	tswait.tv_sec = vs_eng_wait;
	tswait.tv_nsec = 0;

	while ((vscand_get_state() != VS_STATE_SHUTDOWN) &&
	    ((idx = vs_eng_find_next(retry)) == -1)) {
		/* If retry and all configured engines have errors, give up */
		if (retry && vs_eng_check_errors()) {
			(void) pthread_mutex_unlock(&vs_eng_mutex);
			return (-1);
		}

		/* wait for a connection to become available */
		vs_eng_wait_count++;
		if (pthread_cond_reltimedwait_np(&vs_eng_cv, &vs_eng_mutex,
		    &tswait) < 0) {
			syslog(LOG_WARNING, "Scan Engine "
			    "- timeout waiting for available engine");
			vs_eng_wait_count--;
			if (vscand_get_state() == VS_STATE_SHUTDOWN)
				(void) pthread_cond_signal(&vs_eng_shutdown_cv);
			(void) pthread_mutex_unlock(&vs_eng_mutex);
			return (-1);
		}
		vs_eng_wait_count--;
	}

	if (vscand_get_state() == VS_STATE_SHUTDOWN) {
		(void) pthread_cond_signal(&vs_eng_shutdown_cv);
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		return (-1);
	}

	conn->vsc_idx = idx;
	(void) strlcpy(conn->vsc_engid,  vs_engines[idx].vse_cfg.vep_engid,
	    sizeof (conn->vsc_engid));
	(void) strlcpy(conn->vsc_host, vs_engines[idx].vse_cfg.vep_host,
	    sizeof (conn->vsc_host));
	conn->vsc_port = vs_engines[idx].vse_cfg.vep_port;

	/* update in use counts */
	vs_engines[idx].vse_in_use++;
	vs_eng_total_inuse++;

	/* add to connections list for engine */
	vs_eng_add_connection(conn);

	/* update round-robin index */
	if (!retry)
		vs_eng_next = (idx == VS_SE_MAX) ? 0 : idx + 1;

	(void) pthread_mutex_unlock(&vs_eng_mutex);

	return (0);
}


/*
 * vs_eng_check_errors
 *
 * Check if there are any engines, with maxcon > 0,
 * which are not in error state
 *
 * Returns: 1 - all (valid) engines are in error state
 *          0 - otherwise
 */
static int
vs_eng_check_errors()
{
	int i;

	for (i = 0; i < VS_SE_MAX; i++) {
		if (vs_engines[i].vse_cfg.vep_maxconn > 0 &&
		    (vs_engines[i].vse_error == 0))
			return (0);
	}

	return (1);
}


/*
 * vs_eng_find_next
 *
 * Returns: -1 no engine connections available
 *			idx of engine to use
 */
static int
vs_eng_find_next(int retry)
{
	int i;

	for (i = vs_eng_next; i < VS_SE_MAX; i++) {
		if (vs_engines[i].vse_in_use <
		    vs_engines[i].vse_cfg.vep_maxconn) {
			if (!retry || (vs_engines[i].vse_error == 0))
				return (i);
		}
	}

	for (i = 0; i < vs_eng_next; i++) {
		if (vs_engines[i].vse_in_use <
		    vs_engines[i].vse_cfg.vep_maxconn) {
			if (!retry || (vs_engines[i].vse_error == 0))
				return (i);
		}
	}

	return (-1);
}


/*
 * vs_eng_release
 */
void
vs_eng_release(vs_eng_conn_t *conn)
{
	int idx = conn->vsc_idx;

	/* disconnect */
	if (conn->vsc_sockfd != -1) {
		(void) close(conn->vsc_sockfd);
		conn->vsc_sockfd = -1;
	}

	(void) pthread_mutex_lock(&vs_eng_mutex);

	/* decrement in use counts */
	vs_engines[idx].vse_in_use--;
	vs_eng_total_inuse--;

	/* remove from connections list for engine */
	vs_eng_remove_connection(conn);

	/* wake up next thread waiting for a connection */
	(void) pthread_cond_signal(&vs_eng_cv);

	/* if shutdown, send shutdown signal */
	if (vscand_get_state() == VS_STATE_SHUTDOWN)
		(void) pthread_cond_signal(&vs_eng_shutdown_cv);

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_add_connection
 * Add a connection into appropriate engine's connections list
 */
static void
vs_eng_add_connection(vs_eng_conn_t *conn)
{
	vs_eng_conn_t *conn_root;

	conn_root = &(vs_engines[conn->vsc_idx].vse_conn_root);
	conn->vsc_prev = conn_root;
	conn->vsc_next = conn_root->vsc_next;
	if (conn->vsc_next)
		(conn->vsc_next)->vsc_prev = conn;
	conn_root->vsc_next = conn;
}


/*
 * vs_eng_remove_connection
 * Remove a connection from appropriate engine's connections list
 */
static void
vs_eng_remove_connection(vs_eng_conn_t *conn)
{
	(conn->vsc_prev)->vsc_next = conn->vsc_next;
	if (conn->vsc_next)
		(conn->vsc_next)->vsc_prev = conn->vsc_prev;
}


/*
 * vs_eng_close_connections
 * Close all open connections to abort in-progress scans.
 */
static void
vs_eng_close_connections(void)
{
	int i;
	vs_eng_conn_t *conn;

	for (i = 0; i < VS_SE_MAX; i++) {
		conn = vs_engines[i].vse_conn_root.vsc_next;
		while (conn) {
			(void) close(conn->vsc_sockfd);
			conn->vsc_sockfd = -1;
			conn = conn->vsc_next;
		}
	}
}


/*
 * vs_eng_connect
 * open socket connection to remote scan engine
 */
int
vs_eng_connect(vs_eng_conn_t *conn)
{
	int rc, sock_opt, err_num;
	struct sockaddr_in addr;
	struct hostent *hp;

	if ((conn->vsc_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return (-1);

	hp = getipnodebyname(conn->vsc_host, AF_INET, 0, &err_num);
	if (hp == NULL)
		return (-1);

	(void) memset(&addr, 0, sizeof (addr));
	(void) memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
	addr.sin_port = htons(conn->vsc_port);
	addr.sin_family = hp->h_addrtype;
	freehostent(hp);

#ifdef FIONBIO /* Use non-blocking mode for connect. */
	rc = nbio_connect(conn, (struct sockaddr *)&addr,
	    sizeof (struct sockaddr));
#else
	rc = connect(conn->vsc_sockfd, (struct sockaddr *)&addr,
	    sizeof (struct sockaddr));
#endif

	sock_opt = 1;

	if ((rc < 0) || (vscand_get_state() == VS_STATE_SHUTDOWN) ||
	    (setsockopt(conn->vsc_sockfd, IPPROTO_TCP, TCP_NODELAY,
	    &sock_opt, sizeof (sock_opt)) < 0) ||
	    (setsockopt(conn->vsc_sockfd, SOL_SOCKET, SO_KEEPALIVE,
	    &sock_opt, sizeof (sock_opt)) < 0)) {
		syslog(LOG_WARNING, "Scan Engine - connection error (%s:%d) %s",
		    conn->vsc_host, conn->vsc_port, strerror(errno));
		(void) close(conn->vsc_sockfd);
		conn->vsc_sockfd = -1;
		return (-1);
	}

	return (0);
}


/*
 * nbio_connect
 *
 * Attempt to do a non-blocking connect call.
 * Wait for a maximum of "vs_connect_timeout" millisec, then check for
 * socket error to determine if connect successful or not.
 */
#ifdef FIONBIO
static int
nbio_connect(vs_eng_conn_t *conn, const struct sockaddr *sa, int sa_len)
{
	struct pollfd pfd;
	int nbio, rc;
	int soc = conn->vsc_sockfd;
	int error, len = sizeof (error);

	nbio = 1;
	if ((ioctl(soc, FIONBIO, &nbio)) < 0)
		return (connect(soc, sa, sa_len));

	if ((rc = connect(soc, sa, sa_len)) != 0) {
		if (errno == EINPROGRESS || errno == EINTR) {
			pfd.fd = soc;
			pfd.events = POLLOUT;
			pfd.revents = 0;

			if ((rc = poll(&pfd, 1, vs_connect_timeout)) <= 0) {
				if (rc == 0)
					errno = ETIMEDOUT;
				rc = -1;
			} else {
				rc = getsockopt(soc, SOL_SOCKET, SO_ERROR,
				    &error, &len);
				if (rc != 0 || error != 0)
					rc = -1;
			}
		}
	}

	nbio = 0;
	(void) ioctl(soc, FIONBIO, &nbio);

	return (rc);
}
#endif


/*
 * vs_eng_scanstamp_current
 *
 * Check if scanstamp matches that of ANY engine with no errors.
 * We cannot include engines with errors as they may have been
 * inaccessible for a long time and thus we may have an old
 * scanstamp value for them.
 * If a match is found the scanstamp is considered to be current
 *
 * returns: 1 if current, 0 otherwise
 */
int
vs_eng_scanstamp_current(vs_scanstamp_t scanstamp)
{
	int i;

	/* if scan stamp is null, not current */
	if (scanstamp[0] == '\0')
		return (0);

	/* if scanstamp matches that of any enabled engine with no errors */
	(void) pthread_mutex_lock(&vs_eng_mutex);
	for (i = 0; i < VS_SE_MAX; i++) {
		if ((vs_engines[i].vse_cfg.vep_enable) &&
		    (vs_engines[i].vse_error == 0) &&
		    (vs_icap_compare_scanstamp(i, scanstamp) == 0))
			break;
	}
	(void) pthread_mutex_unlock(&vs_eng_mutex);

	return ((i < VS_SE_MAX) ? 1 : 0);
}


/*
 * vs_eng_compare
 * compare host and port with that stored for engine idx
 *
 * Returns: 0 - if equal
 */
static int
vs_eng_compare(int idx, char *host, int port)
{
	if (vs_engines[idx].vse_cfg.vep_port != port)
		return (-1);

	if (strcmp(vs_engines[idx].vse_cfg.vep_host, host) != 0)
		return (-1);

	return (0);
}
