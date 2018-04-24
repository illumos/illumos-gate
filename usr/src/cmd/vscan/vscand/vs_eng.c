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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

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
#include <sys/time.h>
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

#include <signal.h>
#include <thread.h>

#include "vs_incl.h"

/* max connections per scan engine */
#define	VS_CXN_MAX	VS_VAL_SE_MAXCONN_MAX

/*
 * vs_eng_state_t - connection state
 *
 * Each configured scan engine supports up to vse_cfg.vep_maxconn
 * connections. These connections are represented by a vs_connection_t
 * which defines the connection state, associated socket descriptor
 * and how long the connection has been available. A connection
 * that has been available but unused for vs_inactivity_timeout
 * seconds will be closed by the housekeeper thread.
 *
 * When a scan engine is reconfigured to have less connections
 * (or is disabled) any of the superflous connections which are in
 * AVAILABLE state are closed (DISCONNECTED). Others are set to
 * CLOSE_PENDING to be closed (DISCONNECTED) when the engine is
 * released (when the current request completes).
 *
 *              +---------------------+
 *  |---------->| VS_ENG_DISCONNECTED |<-----------------|
 *  |           +---------------------+                  |
 *  |              |                                     |
 *  |              | eng_get                             |
 *  |              v                                     | release/
 *  | shutdown  +---------------------+   reconfig       | shutdown
 *  |<----------| VS_ENG_RESERVED     | -----------|     |
 *  |           +---------------------+            |     |
 *  |              |                               v     |
 *  |              |                       +----------------------+
 *  |              | connect               | VS_ENG_CLOSE_PENDING |
 *  |              |                       +----------------------+
 *  |              v                               ^
 *  | shutdown  +---------------------+            |
 *  |<----------| VS_ENG_INUSE        |------------|
 *  |           +---------------------+  reconfig/error
 *  |              |           ^
 *  |              | release   | eng_get
 *  | reconfig/    |           |
 *  | timeout/     v           |
 *  | shutdown  +---------------------+
 *  |<----------| VS_ENG_AVAILABLE    |
 *              +---------------------+
 *
 */

typedef enum {
	VS_ENG_DISCONNECTED = 0,
	VS_ENG_RESERVED,
	VS_ENG_INUSE,
	VS_ENG_AVAILABLE,
	VS_ENG_CLOSE_PENDING
} vs_eng_state_t;

typedef struct vs_connection {
	vs_eng_state_t vsc_state;
	int vsc_sockfd;
	struct timeval vsc_avail_time;
} vs_connection_t;

typedef struct vs_engine {
	vs_props_se_t vse_cfg;	/* host, port, maxconn */
	int vse_inuse;		/* # connections in use */
	boolean_t vse_error;
	vs_connection_t vse_cxns[VS_CXN_MAX];
} vs_engine_t;

static vs_engine_t vs_engines[VS_SE_MAX];

static int vs_eng_next;		/* round-robin "finger" */
static int vs_eng_count;	/* how many configured engines */
static int vs_eng_total_maxcon;	/* total configured connections */
static int vs_eng_total_inuse;	/* total connections in use */
static int vs_eng_wait_count;	/* # threads waiting for connection */

static pthread_mutex_t vs_eng_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vs_eng_cv;
int vs_inactivity_timeout = 60; /* seconds */
int vs_reuse_connection = 1;

time_t vs_eng_wait = VS_ENG_WAIT_DFLT;

/* local functions */
static int vs_eng_connect(char *, int);
static boolean_t vs_eng_check_errors(void);
static int vs_eng_find_connection(int *, int *, boolean_t);
static int vs_eng_find_next(boolean_t);
static int vs_eng_compare(int, char *, int);
static void vs_eng_config_close(vs_engine_t *, int);
static void *vs_eng_housekeeper(void *);


#ifdef FIONBIO
/* non-blocking connect */
static int nbio_connect(int, const struct sockaddr *, int);
int vs_connect_timeout = 5000; /* milliseconds */
#endif /* FIONBIO */


/*
 * vs_eng_init
 */
void
vs_eng_init()
{
	pthread_t tid;

	(void) pthread_cond_init(&vs_eng_cv, NULL);
	(void) pthread_mutex_lock(&vs_eng_mutex);

	(void) memset(vs_engines, 0, sizeof (vs_engine_t) * VS_SE_MAX);

	vs_eng_total_maxcon = 0;
	vs_eng_total_inuse = 0;
	vs_eng_count = 0;
	vs_eng_next = 0;

	(void) pthread_mutex_unlock(&vs_eng_mutex);

	(void) pthread_create(&tid, NULL, vs_eng_housekeeper, NULL);
}


/*
 * vs_eng_config
 *
 * Configure scan engine connections.
 *
 * If a scan engine has been reconfigured (different host or port)
 * the scan engine's error count is reset.
 *
 * If the host/port has changed, the engine has been disabled
 * or less connections are configured now, connections need
 * to be closed or placed in CLOSE_PENDING state (vs_eng_config_close)
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

		if (vs_eng_compare(i, cfg->vep_host, cfg->vep_port) != 0) {
			vs_eng_config_close(eng, 0);
			eng->vse_error = B_FALSE;
		}

		if (cfg->vep_enable) {
			if (cfg->vep_maxconn < eng->vse_cfg.vep_maxconn)
				vs_eng_config_close(eng, cfg->vep_maxconn);

			eng->vse_cfg = *cfg;
			vs_eng_total_maxcon += cfg->vep_maxconn;
			vs_eng_count++;
		} else {
			vs_eng_config_close(eng, 0);
			(void) memset(&eng->vse_cfg, 0, sizeof (vs_props_se_t));
		}

		vs_icap_config(i, eng->vse_cfg.vep_host, eng->vse_cfg.vep_port);
	}

	if ((vs_eng_total_maxcon <= 0) || (vs_eng_count == 0))
		syslog(LOG_NOTICE, "Scan Engine - no engines configured");

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_config_close
 *
 *	If the host/port has changed, the engine has been disabled
 *	or less connections are configured now, connections need
 *	to be closed or placed in CLOSE_PENDING state
 */
static void
vs_eng_config_close(vs_engine_t *eng, int start_idx)
{
	int i;
	vs_connection_t *cxn;

	for (i = start_idx; i < eng->vse_cfg.vep_maxconn; i++) {
		cxn = &(eng->vse_cxns[i]);

		switch (cxn->vsc_state) {
		case VS_ENG_RESERVED:
		case VS_ENG_INUSE:
			cxn->vsc_state = VS_ENG_CLOSE_PENDING;
			break;
		case VS_ENG_AVAILABLE:
			(void) close(cxn->vsc_sockfd);
			cxn->vsc_sockfd = -1;
			cxn->vsc_state = VS_ENG_DISCONNECTED;
			break;
		case VS_ENG_CLOSE_PENDING:
		case VS_ENG_DISCONNECTED:
			break;
		}
	}
}


/*
 * vs_eng_fini
 */
void
vs_eng_fini()
{
	(void) pthread_cond_destroy(&vs_eng_cv);
}


/*
 * vs_eng_housekeeper
 *
 * Wakeup every (vs_inactivity_timeout / 2) seconds and close
 * any connections that are in AVAILABLE state but have not
 * been used for vs_inactivity_timeout seconds.
 */
/* ARGSUSED */
static void *
vs_eng_housekeeper(void *arg)
{
	struct timeval now;
	long expire;
	int i, j;
	vs_engine_t *eng;
	vs_connection_t *cxn;

	for (;;) {
		(void) sleep(vs_inactivity_timeout / 2);

		if (vscand_get_state() == VS_STATE_SHUTDOWN)
			break;

		(void) gettimeofday(&now, NULL);
		expire = now.tv_sec - vs_inactivity_timeout;

		(void) pthread_mutex_lock(&vs_eng_mutex);
		for (i = 0; i < VS_SE_MAX; i++) {
			eng = &(vs_engines[i]);
			for (j = 0; j < eng->vse_cfg.vep_maxconn; j++) {
				cxn = &(eng->vse_cxns[j]);

				if ((cxn->vsc_state == VS_ENG_AVAILABLE) &&
				    (cxn->vsc_avail_time.tv_sec < expire)) {
					(void) close(cxn->vsc_sockfd);
					cxn->vsc_sockfd = -1;
					cxn->vsc_state = VS_ENG_DISCONNECTED;
				}
			}
		}
		(void) pthread_mutex_unlock(&vs_eng_mutex);
	}

	return (NULL);
}


/*
 * vs_eng_set_error
 *
 * If the engine identified in conn (host, port) matches the
 * engine in vs_engines set or clear the error state of the
 * engine and update the error statistics.
 *
 * If error == 0, clear the error state(B_FALSE), else set
 * the error state (B_TRUE) and increment engine error stats
 */
void
vs_eng_set_error(vs_eng_ctx_t *eng_ctx, int error)
{
	int eidx = eng_ctx->vse_eidx;
	int cidx =  eng_ctx->vse_cidx;
	vs_engine_t *eng;

	(void) pthread_mutex_lock(&vs_eng_mutex);

	eng = &(vs_engines[eidx]);

	if (vs_eng_compare(eidx, eng_ctx->vse_host, eng_ctx->vse_port) == 0)
		eng->vse_error = (error == 0) ? B_FALSE : B_TRUE;

	if (error != 0) {
		eng->vse_cxns[cidx].vsc_state = VS_ENG_CLOSE_PENDING;
		vs_stats_eng_err(eng_ctx->vse_engid);
	}

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_get
 * Get next available scan engine connection.
 * If retry == B_TRUE look for a scan engine with no errors.
 *
 * Returns: 0 - success
 *         -1 - error
 */
int
vs_eng_get(vs_eng_ctx_t *eng_ctx, boolean_t retry)
{
	struct timespec tswait;
	int eidx, cidx, sockfd;
	vs_engine_t *eng;
	vs_connection_t *cxn;

	(void) pthread_mutex_lock(&vs_eng_mutex);

	/*
	 * If no engines connections configured OR
	 * retry and only one engine configured, give up
	 */
	if ((vs_eng_total_maxcon <= 0) ||
	    ((retry == B_TRUE) && (vs_eng_count <= 1))) {
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		return (-1);
	}

	tswait.tv_sec = vs_eng_wait;
	tswait.tv_nsec = 0;

	while ((vscand_get_state() != VS_STATE_SHUTDOWN) &&
	    (vs_eng_find_connection(&eidx, &cidx, retry) == -1)) {
		/* If retry and all configured engines have errors, give up */
		if (retry && vs_eng_check_errors() == B_TRUE) {
			(void) pthread_mutex_unlock(&vs_eng_mutex);
			return (-1);
		}

		/* wait for a connection to become available */
		vs_eng_wait_count++;
		if (pthread_cond_reltimedwait_np(&vs_eng_cv, &vs_eng_mutex,
		    &tswait) < 0) {
			syslog(LOG_NOTICE, "Scan Engine "
			    "- timeout waiting for available engine");
			vs_eng_wait_count--;
			(void) pthread_mutex_unlock(&vs_eng_mutex);
			return (-1);
		}
		vs_eng_wait_count--;
	}

	if (vscand_get_state() == VS_STATE_SHUTDOWN) {
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		return (-1);
	}

	eng = &(vs_engines[eidx]);
	cxn = &(eng->vse_cxns[cidx]);

	/* update in use counts */
	eng->vse_inuse++;
	vs_eng_total_inuse++;

	/* update round-robin index */
	if (!retry)
		vs_eng_next = (eidx == VS_SE_MAX) ? 0 : eidx + 1;

	/* populate vs_eng_ctx_t */
	eng_ctx->vse_eidx = eidx;
	eng_ctx->vse_cidx = cidx;
	(void) strlcpy(eng_ctx->vse_engid, eng->vse_cfg.vep_engid,
	    sizeof (eng_ctx->vse_engid));
	(void) strlcpy(eng_ctx->vse_host, eng->vse_cfg.vep_host,
	    sizeof (eng_ctx->vse_host));
	eng_ctx->vse_port = eng->vse_cfg.vep_port;
	eng_ctx->vse_sockfd = cxn->vsc_sockfd;

	if (cxn->vsc_state == VS_ENG_INUSE) {
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		return (0);
	}

	/* state == VS_ENG_RESERVED, need to connect */

	(void) pthread_mutex_unlock(&vs_eng_mutex);

	sockfd = vs_eng_connect(eng_ctx->vse_host, eng_ctx->vse_port);

	/* retry a failed connection once */
	if (sockfd == -1) {
		(void) sleep(1);
		sockfd = vs_eng_connect(eng_ctx->vse_host, eng_ctx->vse_port);
	}

	if (sockfd == -1) {
		syslog(LOG_NOTICE, "Scan Engine - connection error (%s:%d) %s",
		    eng_ctx->vse_host, eng_ctx->vse_port,
		    errno ? strerror(errno) : "");
		vs_eng_set_error(eng_ctx, 1);
		vs_eng_release(eng_ctx);
		return (-1);
	}

	(void) pthread_mutex_lock(&vs_eng_mutex);
	switch (cxn->vsc_state) {
	case VS_ENG_DISCONNECTED:
		/* SHUTDOWN occured */
		(void) pthread_mutex_unlock(&vs_eng_mutex);
		vs_eng_release(eng_ctx);
		return (-1);
	case VS_ENG_RESERVED:
		cxn->vsc_state = VS_ENG_INUSE;
		break;
	case VS_ENG_CLOSE_PENDING:
		/* reconfigure occured. Connection will be closed after use */
		break;
	case VS_ENG_INUSE:
	case VS_ENG_AVAILABLE:
	default:
		ASSERT(0);
		break;
	}

	cxn->vsc_sockfd = sockfd;
	eng_ctx->vse_sockfd = sockfd;

	(void) pthread_mutex_unlock(&vs_eng_mutex);
	return (0);
}


/*
 * vs_eng_check_errors
 *
 * Check if all engines with maxconn > 0 are in error state
 *
 * Returns: B_TRUE  - all (valid) engines are in error state
 *          B_FALSE - otherwise
 */
static boolean_t
vs_eng_check_errors()
{
	int i;

	for (i = 0; i < VS_SE_MAX; i++) {
		if (vs_engines[i].vse_cfg.vep_maxconn > 0 &&
		    (vs_engines[i].vse_error == B_FALSE))
			return (B_FALSE);
	}

	return (B_TRUE);
}


/*
 * vs_eng_find_connection
 *
 * Identify the next engine to be used (vs_eng_find_next()).
 * Select the engine's first connection in AVAILABLE state.
 * If no connection is in AVAILABLE state, select the first
 * that is in DISCONNECTED state.
 *
 * Returns: 0 success
 *         -1 no engine connections available (eng_idx & cxn_idx undefined)
 */
static int
vs_eng_find_connection(int *eng_idx, int *cxn_idx, boolean_t retry)
{
	int i, idx;
	vs_engine_t *eng;
	vs_connection_t *cxn;

	/* identify engine */
	if ((idx = vs_eng_find_next(retry)) == -1)
		return (-1);

	eng = &(vs_engines[idx]);
	*eng_idx = idx;

	/* identify connection */
	idx = -1;
	for (i = 0; i < eng->vse_cfg.vep_maxconn; i++) {
		cxn = &(eng->vse_cxns[i]);
		if (cxn->vsc_state == VS_ENG_AVAILABLE) {
			*cxn_idx = i;
			cxn->vsc_state = VS_ENG_INUSE;
			return (0);
		}

		if ((idx == -1) &&
		    (cxn->vsc_state == VS_ENG_DISCONNECTED)) {
			idx = i;
		}
	}

	if (idx == -1)
		return (-1);

	eng->vse_cxns[idx].vsc_state = VS_ENG_RESERVED;
	*cxn_idx = idx;
	return (0);
}


/*
 * vs_eng_find_next
 *
 * Returns: -1 no engine connections available
 *          idx of engine to use
 */
static int
vs_eng_find_next(boolean_t retry)
{
	int i;

	for (i = vs_eng_next; i < VS_SE_MAX; i++) {
		if (vs_engines[i].vse_inuse <
		    vs_engines[i].vse_cfg.vep_maxconn) {
			if (!retry || (vs_engines[i].vse_error == B_FALSE))
				return (i);
		}
	}

	for (i = 0; i < vs_eng_next; i++) {
		if (vs_engines[i].vse_inuse <
		    vs_engines[i].vse_cfg.vep_maxconn) {
			if (!retry || (vs_engines[i].vse_error == B_FALSE))
				return (i);
		}
	}

	return (-1);
}


/*
 * vs_eng_release
 */
void
vs_eng_release(const vs_eng_ctx_t *eng_ctx)
{
	int eidx = eng_ctx->vse_eidx;
	int cidx = eng_ctx->vse_cidx;
	vs_connection_t *cxn;

	(void) pthread_mutex_lock(&vs_eng_mutex);
	cxn = &(vs_engines[eidx].vse_cxns[cidx]);

	switch (cxn->vsc_state) {
	case VS_ENG_DISCONNECTED:
		break;
	case VS_ENG_RESERVED:
		cxn->vsc_state = VS_ENG_DISCONNECTED;
		break;
	case VS_ENG_INUSE:
		if (vs_reuse_connection) {
			cxn->vsc_state = VS_ENG_AVAILABLE;
			(void) gettimeofday(&cxn->vsc_avail_time, NULL);
			break;
		}
		/* FALLTHROUGH */
	case VS_ENG_CLOSE_PENDING:
		(void) close(cxn->vsc_sockfd);
		cxn->vsc_sockfd = -1;
		cxn->vsc_state = VS_ENG_DISCONNECTED;
		break;
	case VS_ENG_AVAILABLE:
	default:
		ASSERT(0);
		break;
	}

	/* decrement in use counts */
	vs_engines[eidx].vse_inuse--;
	vs_eng_total_inuse--;

	/* wake up next thread waiting for a connection */
	(void) pthread_cond_signal(&vs_eng_cv);

	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_close_connections
 *
 * Set vs_eng_total_maxcon to 0 to ensure no new engine sessions
 * can be initiated.
 * Close all open connections to abort in-progress scans.
 * Set connection state to DISCONNECTED.
 */
void
vs_eng_close_connections(void)
{
	int i, j;
	vs_connection_t *cxn;

	(void) pthread_mutex_lock(&vs_eng_mutex);
	vs_eng_total_maxcon = 0;

	for (i = 0; i < VS_SE_MAX; i++) {
		for (j = 0; j < VS_CXN_MAX; j++) {
			cxn = &(vs_engines[i].vse_cxns[j]);

			switch (cxn->vsc_state) {
			case VS_ENG_INUSE:
			case VS_ENG_AVAILABLE:
			case VS_ENG_CLOSE_PENDING:
				(void) close(cxn->vsc_sockfd);
				cxn->vsc_sockfd = -1;
				break;
			case VS_ENG_DISCONNECTED:
			case VS_ENG_RESERVED:
			default:
				break;

			}

			cxn->vsc_state = VS_ENG_DISCONNECTED;
		}
	}
	(void) pthread_mutex_unlock(&vs_eng_mutex);
}


/*
 * vs_eng_connect
 * open socket connection to remote scan engine
 *
 * Returns: sockfd or -1 (error)
 */
static int
vs_eng_connect(char *host, int port)
{
	int rc, sockfd, opt_nodelay, opt_keepalive, opt_reuseaddr, err_num;
	struct sockaddr_in addr;
	struct hostent *hp;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return (-1);

	hp = getipnodebyname(host, AF_INET, 0, &err_num);
	if (hp == NULL) {
		(void) close(sockfd);
		return (-1);
	}

	(void) memset(&addr, 0, sizeof (addr));
	(void) memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = hp->h_addrtype;
	freehostent(hp);

#ifdef FIONBIO /* Use non-blocking mode for connect. */
	rc = nbio_connect(sockfd, (struct sockaddr *)&addr,
	    sizeof (struct sockaddr));
#else
	rc = connect(sockfd, (struct sockaddr *)&addr,
	    sizeof (struct sockaddr));
#endif

	opt_nodelay = 1;
	opt_keepalive = 1;
	opt_reuseaddr = 1;

	if ((rc < 0) ||
	    (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,
	    &opt_nodelay, sizeof (opt_nodelay)) < 0) ||
	    (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
	    &opt_keepalive, sizeof (opt_keepalive)) < 0) ||
	    (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
	    &opt_reuseaddr, sizeof (opt_reuseaddr)) < 0)) {
		(void) close(sockfd);
		return (-1);
	}

	return (sockfd);
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
nbio_connect(int sockfd, const struct sockaddr *sa, int sa_len)
{
	struct pollfd pfd;
	int nbio, rc;
	int error, len = sizeof (error);

	nbio = 1;
	if ((ioctl(sockfd, FIONBIO, &nbio)) < 0)
		return (connect(sockfd, sa, sa_len));

	if ((rc = connect(sockfd, sa, sa_len)) != 0) {
		if (errno == EINPROGRESS || errno == EINTR) {
			errno = 0;
			pfd.fd = sockfd;
			pfd.events = POLLOUT;
			pfd.revents = 0;

			if ((rc = poll(&pfd, 1, vs_connect_timeout)) <= 0) {
				if (rc == 0)
					errno = ETIMEDOUT;
				rc = -1;
			} else {
				if ((pfd.revents &
				    (POLLHUP | POLLERR | POLLNVAL)) ||
				    (!(pfd.revents & POLLOUT))) {
					rc = -1;
				} else {
					rc = getsockopt(sockfd, SOL_SOCKET,
					    SO_ERROR, &error, &len);
					if (rc != 0 || error != 0)
						rc = -1;
					if (error != 0)
						errno = error;
				}
			}
		}
	}

	nbio = 0;
	(void) ioctl(sockfd, FIONBIO, &nbio);

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
		    (vs_engines[i].vse_error == B_FALSE) &&
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
