/*
 * Copyright (c) 1995-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  open.c
 */

#ifndef	lint
static char copyright[] = "@(#) Copyright (c) 1995 Regents of the "
	"University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* calloc(), free(), atoi() for Solaris */
#include <locale.h>
#include <thread.h>

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#if defined(DOS) || defined(_WIN32)
#include "msdos.h"
#include <stdlib.h>
#endif /* DOS */

#if !defined(MACOS) && !defined(DOS) && !defined(_WIN32)
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifndef VMS
#include <sys/param.h>
#endif
#include <netinet/in.h>
#endif
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef LDAP_DEBUG
int	ldap_debug;
#endif

#ifndef INADDR_LOOPBACK
#define	INADDR_LOOPBACK	((unsigned int) 0x7f000001)
#endif

#ifndef MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN  64
#endif

extern int thr_kill(thread_t, int);

/*
 * ldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 * "host" may be a space-separated list of hosts or IP addresses
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_open( hostname, port );
 */

LDAP *
ldap_open(char *host, int port)
{
	LDAP		*ld;
	int err;

	if ((ld = ldap_init(host, port)) == NULL) {
		return (NULL);
	}

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 113,
		"ldap_open (after ldap_init)\n"), 0, 0, 0);

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	if ((err = open_default_ldap_connection(ld)) != LDAP_SUCCESS) {
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
		ldap_ld_free(ld, 0);
		Debug(LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1275,
			"ldap_open failed, %s\n"),
			ldap_err2string(err), 0, 0);
		return (NULL);
	}

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 194,
		"ldap_open successful, ld_host is %s\n"),
		(ld->ld_host == NULL) ? "(null)" : ld->ld_host, 0, 0);
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (ld);

}

/*
 * Open the default connection
 * ld->ld_defconn MUST be null when calling this function,
 * ie the connection was never established
 * ld should be LOCKed before calling this function
 */
int
open_default_ldap_connection(LDAP *ld)
{
	LDAPServer	*srv;
	int err;

	if ((srv = (LDAPServer *)calloc(1, sizeof (LDAPServer))) ==
	    NULL || (ld->ld_defhost != NULL && (srv->lsrv_host =
	    strdup(ld->ld_defhost)) == NULL)) {
		return (LDAP_NO_MEMORY);
	}
	srv->lsrv_port = ld->ld_defport;

	if ((ld->ld_defconn = new_connection(ld, &srv, 1, 1, 0)) ==
		NULL) {
		err = ld->ld_errno;
		Debug(LDAP_DEBUG_ANY, catgets(slapdcat, 1, 1276,
		"Default connection to ldap server %s couldn't be "
		"opened (%d)\n"), ld->ld_defhost, err, 0);

		if (ld->ld_defhost != NULL)
			free(srv->lsrv_host);
		free((char *)srv);
		return (err);
	}

	/* so it never gets closed/freed */
	++ld->ld_defconn->lconn_refcnt;

	return (LDAP_SUCCESS);
}

static pthread_mutex_t ldap_thr_index_mutex = {0};
static pthread_t ldap_thr_table[MAX_THREAD_ID] = {0};

int
ldap_thr_index()
{
	int i = 0;
	int free = 0;
	pthread_t cur = thr_self();
	for (i = 1; i < MAX_THREAD_ID; ++i) {
		if (ldap_thr_table[i] == cur) {
			return (i);
		} /* end if */
	} /* end for */
	/*
	 * not in the table, allocate a new entry
	 */
	pthread_mutex_lock(&ldap_thr_index_mutex);
	for (i = 1; i < MAX_THREAD_ID; ++i) {
		if (ldap_thr_table[i] == 0 ||
			thr_kill(ldap_thr_table[i], 0) != 0) {
			ldap_thr_table[i] = cur;
			pthread_mutex_unlock(&ldap_thr_index_mutex);
			return (i);
		} /* end if */
	} /* end for */
	pthread_mutex_unlock(&ldap_thr_index_mutex);
	/* if table is full, return the first entry, so that it */
	/* doesn't core dump */
	return (0);
}

/*
 * ldap_init - initialize the LDAP library.  A magic cookie to be used for
 * future communication is returned on success, NULL on failure.
 * "defhost" may be a space-separated list of hosts or IP addresses
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_init( default_hostname, default_port );
 */
LDAP *
ldap_init(char *defhost, int defport)
{
	LDAP			*ld;
	char *locale;

	locale = setlocale(LC_ALL, "");
	i18n_catopen("sdserver");

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 195,
		"ldap_init\n"), 0, 0, 0);


	if ((ld = (LDAP *) calloc(1, sizeof (LDAP))) == NULL) {
		return (NULL);
	}

#ifdef _REENTRANT
	pthread_mutex_init(&ld->ld_ldap_mutex, DEFAULT_TYPE);
	pthread_mutex_init(&ld->ld_response_mutex, DEFAULT_TYPE);
	pthread_mutex_init(&ld->ld_poll_mutex, DEFAULT_TYPE);
	ld->ld_lockthread = 0;
#endif

	if ((ld->ld_selectinfo = new_select_info()) == NULL) {
		free((char *)ld);
		return (NULL);
	}
	ld->ld_follow_referral = 1;

	/*
	 * default to localhost when hostname is not specified
	 * or if null string is passed as hostname
	 */

	if ((defhost != NULL) && (*defhost != NULL) &&
		(ld->ld_defhost = strdup(defhost)) == NULL) {
		free_select_info(ld->ld_selectinfo);
		free((char *)ld);
		return (NULL);
	}

	ld->ld_defport = (defport == 0) ? LDAP_PORT : defport;
	ld->ld_version = LDAP_VERSION;
	ld->ld_lberoptions = LBER_USE_DER;
	ld->ld_refhoplimit = LDAP_DEFAULT_REFHOPLIMIT;
	ld->ld_connect_timeout = LDAP_X_IO_TIMEOUT_NO_TIMEOUT;

#if defined(STR_TRANSLATION) && defined(LDAP_DEFAULT_CHARSET)
	ld->ld_lberoptions |= LBER_TRANSLATE_STRINGS;
#if LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET
	ldap_set_string_translators(ld, ldap_8859_to_t61,
		ldap_t61_to_8859);
#endif /* LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET */
#endif /* STR_TRANSLATION && LDAP_DEFAULT_CHARSET */

	return (ld);
}


/* ARGSUSED */
int
open_ldap_connection(LDAP *ld, Sockbuf *sb, char *host, int defport,
	char **krbinstancep, int async)
{
	int 			rc, port;
	char			*p, *q, *r;
	char			*curhost, hostname[ 2*MAXHOSTNAMELEN ];
	int			bindTimeout;

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 196,
		"open_ldap_connection\n"), 0, 0, 0);

	defport = htons(defport);
	bindTimeout = ld->ld_connect_timeout;

	if (host != NULL) {
		for (p = host; p != NULL && *p != '\0'; p = q) {
			if ((q = strchr(p, ' ')) != NULL) {
				(void) strncpy(hostname, p, q - p);
				hostname[ q - p ] = '\0';
				curhost = hostname;
				while (*q == ' ') {
					++q;
				}
			} else {
				/* avoid copy if possible */
				curhost = p;
				q = NULL;
			}

			if ((r = strchr(curhost, ':')) != NULL) {
			    if (curhost != hostname) {
				/* now copy */
				(void) strcpy(hostname, curhost);
				r = hostname + (r - curhost);
				curhost = hostname;
			    }
			    *r++ = '\0';
			    port = htons((short)atoi(r));
			} else {
			    port = defport;
			}

			if ((rc = connect_to_host(sb, curhost, 0,
			    port, async, bindTimeout)) != -1) {
				break;
			}
		}
	} else {
		rc = connect_to_host(sb, NULL, htonl(INADDR_LOOPBACK),
			defport, async, bindTimeout);
	}

	if (rc == -1) {
		return (rc);
	}

	if (krbinstancep != NULL) {
#ifdef KERBEROS
		if ((*krbinstancep = host_connected_to(sb)) != NULL &&
			(p = strchr(*krbinstancep, '.')) != NULL) {
			*p = '\0';
		}
#else /* KERBEROS */
		krbinstancep = NULL;
#endif /* KERBEROS */
	}

	return (0);
}

/*
 * ldap_ssl_open - initialize and connect to an ssl secured ldap
 * server.  First ldap_open() is called and then ssl is layered on top
 * of the socket.  A magic cookie to be used for future communication
 * is returned on success, NULL on failure.  "host" may be a
 * space-separated list of hosts or IP addresses.  CAfile and CApath
 * are used first time through, subsequent calls are ignored and can
 * be NULL.
 *
 * Example:
 *	LDAP	*ld;
 * ld = ldap_ssl_open( hostname, port, key );
 */

#ifdef LDAP_SSL

#include "security/ssl.h"

int
establish_ssl_connection(LDAP *ld)
{
	SSL *ssl = NULL;	/* The Client's SSL connection */

	/*
	 * Creates a new SSL connection.  This holds information
	 * pertinent to this
	 * connection.
	 */
	if ((ssl = SSL_new()) == NULL) {
		Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 198,
			"SSL_new() failed: %s\n"),
			SSL_strerr(SSL_errno(ssl)), 0, 0);
		return (-1);
	}

	/* if keyname is non-null, set ssl keypackage name from it */
	if (ld->ld_ssl_key != NULL) {
		if (SSL_set_userid(ssl, ld->ld_ssl_key, 0) == NULL) {
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				199, "SSL_set_userid() failed: %s\n"),
				SSL_strerr(SSL_errno(ssl)), 0, 0);
			return (-1);
		}
	}

	/* Start the SSL connection */
	if (SSL_connect(ssl, ld->ld_sb.sb_sd) < 1) {
		Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 200,
			"SSL_connect() failed: %s\n"),
			SSL_strerr(SSL_errno(ssl)), 0, 0);
		return (-1);
	}

	ld->ld_sb.sb_ssl = ssl;
	return (0);
}


LDAP *
ldap_ssl_open(char *host, int port, char *keyname)
{
	LDAP		*ld;
	int rval;


	if (port == 0)
		port = SSL_LDAP_PORT;

	ld = ldap_open(host, port);

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 197,
		"ldap_ssl_open (after ldap_open)\n"), 0, 0, 0);

	if (ld == NULL)
		return (NULL);

	ld->ld_use_ssl = 1;
	if (keyname)
		ld->ld_ssl_key = strdup(keyname);

	if (establish_ssl_connection(ld) != 0) {
		ldap_ld_free(ld, 1);
		return (NULL);
	}

	return (ld);
}

LDAP *
ldap_ssl_init(char *defhost, int defport, char *keyname)
{
	LDAP		*ld;
	int rval;


	if (defport == 0)
		defport = SSL_LDAP_PORT;

	ld = ldap_init(defhost, defport);

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 197,
		"ldap_ssl_open (after ldap_open)\n"), 0, 0, 0);

	if (ld == NULL)
		return (NULL);
	ld->ld_use_ssl = 1;
	ld->ld_ssl_key = strdup(keyname);

	return (ld);
}

#endif /* LDAP_SSL */
