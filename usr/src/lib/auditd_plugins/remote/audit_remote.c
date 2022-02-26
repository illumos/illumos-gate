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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * send audit records to remote host
 *
 */

/*
 * auditd_plugin_open(), auditd_plugin() and auditd_plugin_close()
 * implement a replaceable library for use by auditd; they are a
 * project private interface and may change without notice.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <audit_plugin.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <gssapi/gssapi.h>
#include <libintl.h>
#include <netdb.h>
#include <pthread.h>
#include <rpc/rpcsec_gss.h>
#include <secdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

#include "audit_remote.h"

#define	DEFAULT_TIMEOUT	5	/* default connection timeout (in secs) */
#define	NOSUCCESS_DELAY	20	/* unsuccessful delivery to all p_hosts */

#define	FL_SET		B_TRUE	/* set_fdfl(): set the flag */
#define	FL_UNSET	B_FALSE	/* set_fdfl(): unset the flag */

static int	nosuccess_cnt;	/* unsuccessful delivery counter */

static int	retries;		/* connection retries */
int		timeout;		/* connection timeout */
static int	timeout_p_timeout;	/* p_timeout attr storage */

/* semi-exponential timeout back off; x .. attempts, y .. timeout */
#define	BOFF_TIMEOUT(x, y)	(x < 3 ? y * 2 * x : y * 8)

/* general plugin lock */
pthread_mutex_t	plugin_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct hostlist_s	*current_host;
static struct hostlist_s	*hosts;
static struct hostlist_s	*hosts_prev;

extern struct transq_hdr_s	transq_hdr;
static long			transq_count_max;
extern pthread_mutex_t		transq_lock;

extern pthread_t	recv_tid;

extern boolean_t	notify_pipe_ready;
extern int		notify_pipe[2];

#if DEBUG
FILE		*dfile;		/* debug file */
#endif

/*
 * set_transq_count_max() - sets the transq_count_max value based on kernel
 * audit queue high water mark. This is backup solution for a case, when the
 * the default qsize zero value is (intentionally) set in the audit_remote(7)
 * plugin configuration.
 */
static auditd_rc_t
set_transq_count_max()
{
	struct au_qctrl	qctrl;

	if (auditon(A_GETQCTRL, (caddr_t)&qctrl, 0) != -1) {
		transq_count_max = qctrl.aq_hiwater;
		DPRINT((dfile, "Transmission queue max length set to %ld\n",
		    transq_count_max));
		return (AUDITD_SUCCESS);
	}

	DPRINT((dfile, "Setting the transmission queue max length failed\n"));
	return (AUDITD_RETRY);
}

/*
 * get_port_default() - set the default port number; note, that "solaris-audit"
 * used below in the code is the IANA assigned service name for the secure
 * remote solaris audit logging.
 */
static auditd_rc_t
get_port_default(int *port_default)
{

	struct servent  serventry;
	char  		serventry_buf[1024];

	if (getservbyname_r("solaris-audit", "tcp", &serventry,
	    (char *)&serventry_buf, sizeof (serventry_buf)) == NULL) {
		DPRINT((dfile, "unable to get default port number\n"));
#if DEBUG
		if (errno == ERANGE) {
			DPRINT((dfile, "low on buffer\n"));
		}
#endif
		return (AUDITD_INVALID);
	}
	*port_default = ntohs(serventry.s_port);
	DPRINT((dfile, "default port: %d\n", *port_default));

	return (AUDITD_SUCCESS);
}

/*
 * trim_me() - trims the white space characters around the specified string.
 * Inputs - pointer to the beginning of the string (str_ptr); returns - pointer
 * to the trimmed string. Function returns NULL pointer in case of received
 * empty string, NULL pointer or in case the pointed string consists of white
 * space characters only.
 */
static char *
trim_me(char *str_ptr) {

	char	*str_end;

	if (str_ptr == NULL || *str_ptr == '\0') {
		return (NULL);
	}

	while (isspace(*str_ptr)) {
		str_ptr++;
	}
	if (*str_ptr == '\0') {
		return (NULL);
	}

	str_end = str_ptr + strlen(str_ptr);

	while (str_end > str_ptr && isspace(str_end[-1])) {
		str_end--;
	}
	*str_end = '\0';

	return (str_ptr);
}

/*
 * Frees host list - should be called while keeping auditd_mutex.
 */
static void
freehostlist(hostlist_t **hostlist_ptr)
{
	hostlist_t *h, *n;

	h = *hostlist_ptr;

	while (h != NULL)  {
		n = h->next_host;
		freehostent(h->host);
		free(h);
		h = n;
	}
	*hostlist_ptr = NULL;
}

/*
 * parsehosts() end parses the host string (hosts_str)
 */
static auditd_rc_t
parsehosts(char *hosts_str, char **error)
{
	char 		*hostportmech, *hpm;
	char		*hostname;
	char		*port_str;
	char		*mech_str;
	int		port;
	int		port_default = -1;
	gss_OID		mech_oid;
	char 		*lasts_hpm;
	hostlist_t 	*lasthost = NULL;
	hostlist_t 	*hosts_new = NULL;
	hostlist_t	*newhost;
	struct hostent 	*hostentry;
	int		error_num;
	int		rc;
#if DEBUG
	char 		addr_buf[INET6_ADDRSTRLEN];
	int		num_of_hosts = 0;
#endif

	DPRINT((dfile, "parsing %s\n", hosts_str));
	while ((hostportmech = strtok_r(hosts_str, ",", &lasts_hpm)) != NULL) {

		hosts_str = NULL;
		hostname = NULL;
		port_str = NULL;
		port = port_default;
		mech_str = NULL;
		mech_oid = GSS_C_NO_OID;

		DPRINT((dfile, "parsing host:port:mech %s\n", hostportmech));

		if (strncmp(hostportmech, ":", 1 == 0)) { /* ":port:" case */
			*error = strdup(gettext("no hostname specified"));
			return (AUDITD_INVALID);
		}

		/* parse single host:port:mech target */
		while ((hpm = strsep(&hostportmech, ":")) != NULL) {

			if (hostname == NULL) {
				hostname = hpm;
				continue;
			}
			if (port_str == NULL) {
				port_str = hpm;
				continue;
			}
			if (mech_str == NULL) {
				mech_str = hpm;
				continue;
			}

			/* too many colons in the hostportmech string */
			*error = strdup(gettext("invalid host:port:mech "
			    "specification"));
			return (AUDITD_INVALID);
		}

		if (hostname == NULL || *hostname == '\0') {
			*error = strdup(gettext("invalid hostname "
			    "specification"));
			return (AUDITD_INVALID);
		}

		/* trim hostname */
		hostname = trim_me(hostname);
		if (hostname == NULL || *hostname == '\0') {
			*error = strdup(gettext("empty hostname "
			    "specification"));
			return (AUDITD_INVALID);
		}

		DPRINT((dfile, "resolving address for %s\n", hostname));

		hostentry = getipnodebyname(hostname, AF_INET6, 0, &error_num);
		if (!hostentry) {
			hostentry = getipnodebyname(hostname, AF_INET, 0,
			    &error_num);
		}
		if (!hostentry) {
			if (error_num == TRY_AGAIN) {
				*error = strdup(gettext("host not found, "
				    "try later"));
				return (AUDITD_RETRY);
			} else {
				*error = strdup(gettext("host not found"));
				return (AUDITD_INVALID);
			}
		}
		DPRINT((dfile, "hostentry: h_name=%s, addr_len=%d, addr=%s\n",
		    hostentry->h_name, hostentry->h_length,
		    inet_ntop(hostentry->h_addrtype,
		    hostentry->h_addr_list[0], addr_buf,
		    INET6_ADDRSTRLEN)));

		/* trim port */
		port_str = trim_me(port_str);
		if (port_str == NULL || *port_str == '\0') {
			if (port_default == -1 &&
			    (rc = get_port_default(&port_default))
			    != AUDITD_SUCCESS) {
				*error = strdup(gettext(
				    "unable to get default port number"));
				return (rc);
			}
			port = port_default;
			DPRINT((dfile, "port: %d (default)\n", port));
		} else {
			errno = 0;
			port = atoi(port_str);
			if (errno != 0 || port < 1 || port > USHRT_MAX) {
				*error = strdup(gettext("invalid port number"));
				return (AUDITD_INVALID);
			}
			DPRINT((dfile, "port: %d\n", port));
		}

		/* trim mechanism */
		mech_str = trim_me(mech_str);
		if (mech_str != NULL && *mech_str != '\0') {
			if (rpc_gss_mech_to_oid(mech_str, &mech_oid) != TRUE) {
				*error = strdup(gettext("unknown mechanism"));
				return (AUDITD_INVALID);
			}
			DPRINT((dfile, "mechanism: %s\n", mech_str));
#if DEBUG
		} else {
			DPRINT((dfile, "mechanism: null (default)\n"));
#endif
		}

		/* add this host to host list */
		newhost = malloc(sizeof (hostlist_t));
		if (newhost == NULL) {
			*error = strdup(gettext("no memory"));
			return (AUDITD_NO_MEMORY);
		}
		newhost->host = hostentry;
		newhost->port = htons(port);
		newhost->mech = mech_oid;
		newhost->next_host = NULL;
		if (lasthost != NULL) {
			lasthost->next_host = newhost;
			lasthost = lasthost->next_host;
		} else {
			lasthost = newhost;
			hosts_new = newhost;
		}
#if DEBUG
		num_of_hosts++;
#endif
	}

	(void) pthread_mutex_lock(&plugin_mutex);
	if (hosts_prev == NULL) {
		hosts_prev = hosts;
	}
	hosts = hosts_new;
	current_host = hosts;
	(void) pthread_mutex_unlock(&plugin_mutex);

	DPRINT((dfile, "Configured %d hosts.\n", num_of_hosts));

	return (AUDITD_SUCCESS);
}


#if DEBUG
static char *
auditd_message(auditd_rc_t msg_code) {
	char 	*rc_msg;

	switch (msg_code) {
	case AUDITD_SUCCESS:
		rc_msg = strdup("ok");
		break;
	case AUDITD_RETRY:
		rc_msg = strdup("retry after a delay");
		break;
	case AUDITD_NO_MEMORY:
		rc_msg = strdup("can't allocate memory");
		break;
	case AUDITD_INVALID:
		rc_msg = strdup("bad input");
		break;
	case AUDITD_COMM_FAIL:
		rc_msg = strdup("communications failure");
		break;
	case AUDITD_FATAL:
		rc_msg = strdup("other error");
		break;
	case AUDITD_FAIL:
		rc_msg = strdup("other non-fatal error");
		break;
	}
	return (rc_msg);
}
#endif

/*
 * rsn_to_msg() - translation of the reason of closure identifier to the more
 * human readable/understandable form.
 */
static char *
rsn_to_msg(close_rsn_t reason)
{
	char 	*rc_msg;

	switch (reason) {
	case RSN_UNDEFINED:
		rc_msg = strdup(gettext("not defined reason of failure"));
		break;
	case RSN_INIT_POLL:
		rc_msg = strdup(gettext("poll() initialization failed"));
		break;
	case RSN_TOK_RECV_FAILED:
		rc_msg = strdup(gettext("token receiving failed"));
		break;
	case RSN_TOK_TOO_BIG:
		rc_msg = strdup(gettext("unacceptable token size"));
		break;
	case RSN_TOK_UNVERIFIABLE:
		rc_msg = strdup(gettext("received unverifiable token"));
		break;
	case RSN_SOCKET_CLOSE:
		rc_msg = strdup(gettext("closed socket"));
		break;
	case RSN_SOCKET_CREATE:
		rc_msg = strdup(gettext("socket creation failed"));
		break;
	case RSN_CONNECTION_CREATE:
		rc_msg = strdup(gettext("connection creation failed"));
		break;
	case RSN_PROTOCOL_NEGOTIATE:
		rc_msg = strdup(gettext("protocol negotiation failed"));
		break;
	case RSN_GSS_CTX_ESTABLISH:
		rc_msg = strdup(gettext("context establishing failed"));
		break;
	case RSN_GSS_CTX_EXP:
		rc_msg = strdup(gettext("context expired"));
		break;
	case RSN_UNKNOWN_AF:
		rc_msg = strdup(gettext("unknown address family"));
		break;
	case RSN_MEMORY_ALLOCATE:
		rc_msg = strdup(gettext("memory allocation failed"));
		break;
	default:	/* RSN_OTHER_ERR */
		rc_msg = strdup(gettext("other, not classified error"));
		break;
	}
	return (rc_msg);
}

/*
 * set_fdfl() - based on set_fl (FL_SET/FL_UNSET) un/sets the fl flag associated
 * with fd file descriptor.
 */
static boolean_t
set_fdfl(int fd, int fl, boolean_t set_fl)
{
	int	flags;

	/* power of two test - only single bit flags are allowed */
	if (!fl || (fl & (fl-1))) {
		DPRINT((dfile, "incorrect flag - %d isn't power of two\n", fl));
		return (B_FALSE);
	}

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		DPRINT((dfile, "cannot get file descriptor flags\n"));
		return (B_FALSE);
	}

	if (set_fl) {	/* set the fl flag */
		if (flags & fl) {
			return (B_TRUE);
		}

		flags |= fl;

	} else {	/* unset the fl flag */
		if (~flags & fl) {
			return (B_TRUE);
		}

		flags &= ~fl;
	}

	if (fcntl(fd, F_SETFL, flags) == -1) {
		DPRINT((dfile, "cannot %s file descriptor flags\n",
		    (set_fl ? "set" : "unset")));
		return (B_FALSE);
	}

	DPRINT((dfile, "fd: %d - flag: 0%o was %s\n", fd, fl,
	    (set_fl ? "set" : "unset")));
	return (B_TRUE);
}


/*
 * create_notify_pipe() - creates the notification pipe. Function returns
 * B_TRUE/B_FALSE on success/failure.
 */
static boolean_t
create_notify_pipe(int *notify_pipe, char **error)
{

	if (pipe(notify_pipe) < 0) {
		DPRINT((dfile, "Cannot create notify pipe: %s\n",
		    strerror(errno)));
		*error = strdup(gettext("failed to create notification pipe"));
		return (B_FALSE);
	} else {
		DPRINT((dfile, "Pipe created in:%d out:%d\n", notify_pipe[0],
		    notify_pipe[1]));
		/* make (only) the pipe "in" end nonblocking */
		if (!set_fdfl(notify_pipe[0], O_NONBLOCK, FL_UNSET) ||
		    !set_fdfl(notify_pipe[1], O_NONBLOCK, FL_SET)) {
			DPRINT((dfile, "Cannot prepare blocking scheme on top "
			    "of the notification pipe: %s\n", strerror(errno)));
			(void) close(notify_pipe[0]);
			(void) close(notify_pipe[1]);

			*error = strdup(gettext("failed to prepare blocking "
			    "scheme on top of the notification pipe"));
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}


/*
 * auditd_plugin() sends a record via a tcp connection.
 *
 * Operation:
 *   - 1 tcp connection opened at a time, referenced by current_host->sockfd
 *   - tries to (open and) send a record to the current_host where its address
 *     is taken from the first hostent h_addr_list entry
 *   - if connection times out, tries second host
 *   - if all hosts where tried tries again for retries number of times
 *   - if everything fails, it bails out with AUDITD_RETRY
 *
 *   Note, that space on stack allocated for any error message returned along
 *   with AUDITD_RETRY is subsequently freed by auditd.
 *
 */
auditd_rc_t
auditd_plugin(const char *input, size_t in_len, uint64_t sequence, char **error)
{
	int 		rc = AUDITD_FAIL;
	int 		send_record_rc = SEND_RECORD_FAIL;
	hostlist_t 	*start_host;
	int 		attempts = 0;
	char		*ext_error;	/* extended error string */
	close_rsn_t	err_rsn = RSN_UNDEFINED;
	char		*rsn_msg;

#if DEBUG
	char		*rc_msg;
	static uint64_t	last_sequence = 0;

	if ((last_sequence > 0) && (sequence != last_sequence + 1)) {
		DPRINT((dfile, "audit_remote: buffer sequence=%llu "
		    "but prev=%llu\n", sequence, last_sequence));
	}
	last_sequence = sequence;

	DPRINT((dfile, "audit_remote: input seq=%llu, len=%d\n",
	    sequence, in_len));
#endif

	(void) pthread_mutex_lock(&transq_lock);

	if (transq_hdr.count == transq_count_max) {
		DPRINT((dfile, "Transmission queue is full (%ld)\n",
		    transq_hdr.count));
		(void) pthread_mutex_unlock(&transq_lock);
		*error = strdup(gettext("retransmission queue is full"));
		return (AUDITD_RETRY);
	}
	(void) pthread_mutex_unlock(&transq_lock);


	(void) pthread_mutex_lock(&plugin_mutex);

	/* cycle over the hosts and possibly deliver the record */
	start_host = current_host;
	while (rc != AUDITD_SUCCESS) {
		DPRINT((dfile, "Trying to send record to %s [attempt:%d/%d]\n",
		    current_host->host->h_name, attempts + 1, retries));

		send_record_rc = send_record(current_host, input, in_len,
		    sequence, &err_rsn);
		DPRINT((dfile, "send_record() returned %d - ", send_record_rc));

		switch (send_record_rc) {
		case SEND_RECORD_SUCCESS:
			DPRINT((dfile, "success\n"));
			nosuccess_cnt = 0;
			rc = AUDITD_SUCCESS;
			if (hosts_prev != NULL) {
				freehostlist(&hosts_prev);
				DPRINT((dfile, "stale host list freed\n"));
			}
			break;
		case SEND_RECORD_NEXT:
			DPRINT((dfile, "retry the same host: %s (penalty) "
			    "rsn:%d\n", current_host->host->h_name, err_rsn));
			attempts++;
			break;
		case SEND_RECORD_RETRY:
			DPRINT((dfile, "retry the same host: %s (no penalty) "
			    "rsn:%d\n", current_host->host->h_name, err_rsn));
			break;
		}

		if (send_record_rc == SEND_RECORD_NEXT) {

			/* warn about unsuccessful auditd record delivery */
			rsn_msg = rsn_to_msg(err_rsn);
			(void) asprintf(&ext_error,
			    "retry %d connection %s:%d %s", attempts + 1,
			    current_host->host->h_name,
			    ntohs(current_host->port), rsn_msg);
			if (ext_error == NULL) {
				free(rsn_msg);
				*error = strdup(gettext("no memory"));
				rc = AUDITD_NO_MEMORY;
				break;
			}
			__audit_dowarn2("plugin", "audit_remote.so", "retry",
			    ext_error, attempts + 1);
			free(rsn_msg);
			free(ext_error);

			if (attempts < retries) {
				/* semi-exponential timeout back off */
				timeout = BOFF_TIMEOUT(attempts, timeout);
				DPRINT((dfile, "New timeout=%d\n", timeout));
			} else {
				/* get next host */
				current_host = current_host->next_host;
				if (current_host == NULL) {
					current_host = hosts;
				}
				timeout = timeout_p_timeout;
				DPRINT((dfile, "New timeout=%d\n", timeout));
				attempts = 0;
			}

			/* one cycle finished */
			if (current_host == start_host && attempts == 0) {
				nosuccess_cnt++;
				(void) asprintf(&ext_error, "all hosts defined "
				    "as p_hosts were tried to deliver "
				    "the audit record to with no success "
				    "- sleeping for %d seconds",
				    NOSUCCESS_DELAY);
				if (ext_error == NULL) {
					*error = strdup(gettext("no memory"));
					rc = AUDITD_NO_MEMORY;
					break;
				}
				__audit_dowarn2("plugin", "audit_remote.so",
				    "retry", ext_error, nosuccess_cnt);
				free(ext_error);
				(void) sleep(NOSUCCESS_DELAY);
			}

		} /* if (send_record_rc == SEND_RECORD_NEXT) */

		err_rsn = RSN_UNDEFINED;

	} /* while (rc != AUDITD_SUCCESS) */

	(void) pthread_mutex_unlock(&plugin_mutex);

#if DEBUG
	rc_msg = auditd_message(rc);
	DPRINT((dfile, "audit_remote: returning: %s\n", rc_msg));
	free(rc_msg);
#endif

	return (rc);
}

/*
 * auditd_plugin_open() may be called multiple times; on initial open or
 * `audit -s`, then kvlist != NULL; on `audit -n`, then kvlist == NULL.
 * For more information see audit(8).
 *
 * Note, that space on stack allocated for any error message returned along
 * with AUDITD_RETRY is subsequently freed by auditd.
 *
 */
auditd_rc_t
auditd_plugin_open(const kva_t *kvlist, char **ret_list, char **error)
{
	kva_t	*kv;
	char	*val_str;
	int	val;
	long	val_l;
	int	rc = 0;

	*error = NULL;
	*ret_list = NULL;
	kv = (kva_t *)kvlist;

#if DEBUG
	dfile = __auditd_debug_file_open();
#endif

	/* initial open or audit -s */
	if (kvlist != NULL) {
		DPRINT((dfile, "Action: initial open or `audit -s`\n"));
		val_str = kva_match(kv, "p_timeout");
		if (val_str == NULL) {
			*error = strdup(
			    gettext("p_timeout attribute not found"));
			return (AUDITD_RETRY);
		}
		DPRINT((dfile, "val_str=%s\n", val_str));
		errno = 0;
		val = atoi(val_str);
		if (errno == 0 && val >= 1) {
			timeout_p_timeout = val;
			timeout = val;
		} else {
			timeout_p_timeout = DEFAULT_TIMEOUT;
			timeout = timeout_p_timeout;
			DPRINT((dfile, "p_timeout set to default value: %d\n",
			    timeout));
		}

		val_str = kva_match(kv, "p_retries");
		if (val_str == NULL) {
			*error = strdup(
			    gettext("p_retries attribute not found"));
			return (AUDITD_RETRY);
		}
		DPRINT((dfile, "val_str=%s\n", val_str));
		errno = 0;
		val = atoi(val_str);
		if (errno == 0 && val >= 0) {
			retries = val;
		}

		val_str = kva_match(kv, "qsize");
		if (val_str == NULL) {
			*error = strdup(gettext("qsize attribute not found"));
			return (AUDITD_RETRY);
		}
		DPRINT((dfile, "qsize=%s\n", val_str));
		errno = 0;
		val_l = atol(val_str);
		if (errno == 0 && val_l >= 0) {
			transq_count_max = val_l;
		}
		if (transq_count_max == 0 &&
		    (rc = set_transq_count_max()) != AUDITD_SUCCESS) {
			*error = strdup(gettext("cannot get kernel "
			    "auditd queue high water mark\n"));
			return (rc);
		}
		DPRINT((dfile, "timeout=%d, retries=%d, transq_count_max=%ld\n",
		    timeout, retries, transq_count_max));

		val_str = kva_match(kv, "p_hosts");
		if (val_str == NULL) {
			*error = strdup(gettext("no hosts configured"));
			return (AUDITD_RETRY);
		}
		if ((rc = parsehosts(val_str, error)) != AUDITD_SUCCESS) {
			return (rc);
		}

		/* create the notification pipe towards the receiving thread */
		if (!notify_pipe_ready) {
			if (create_notify_pipe(notify_pipe, error)) {
				notify_pipe_ready = B_TRUE;
			} else {
				return (AUDITD_RETRY);
			}
		}

#if DEBUG
	} else { /* audit -n */
		DPRINT((dfile, "Action: `audit -n`\n"));
#endif
	}

	return (AUDITD_SUCCESS);
}

/*
 * auditd_plugin_close() performs shutdown operations. The return values are
 * used by auditd to output warnings via the audit_warn(8) script and the
 * string returned via "error_text", is passed to audit_warn.
 *
 * Note, that space on stack allocated for any error message returned along
 * with AUDITD_RETRY is subsequently freed by auditd.
 *
 */
auditd_rc_t
auditd_plugin_close(char **error)
{
	reset_transport(DO_EXIT, DO_SYNC);
	if (pthread_join(recv_tid, NULL) != 0) {
		*error = strdup(gettext("unable to close receiving thread"));
		return (AUDITD_RETRY);
	}

	(void) pthread_mutex_lock(&plugin_mutex);
	freehostlist(&hosts);
	freehostlist(&hosts_prev);
	(void) pthread_mutex_unlock(&plugin_mutex);
	current_host = NULL;
	*error = NULL;
	return (AUDITD_SUCCESS);
}
