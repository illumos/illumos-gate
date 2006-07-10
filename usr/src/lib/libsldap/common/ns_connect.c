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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <synch.h>
#include <time.h>
#include <libintl.h>
#include <thread.h>
#include <syslog.h>
#include <sys/mman.h>
#include <nsswitch.h>
#include <nss_dbdefs.h>
#include "solaris-priv.h"
#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "ldappr.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <procfs.h>
#include <unistd.h>

extern unsigned int _sleep(unsigned int);
extern int ldap_sasl_cram_md5_bind_s(LDAP *, char *, struct berval *,
		LDAPControl **, LDAPControl **);
extern int ldapssl_install_gethostbyaddr(LDAP *ld, const char *skip);

static int openConnection(LDAP **, const char *, const ns_cred_t *,
		int, ns_ldap_error_t **, int, int);

static mutex_t	sessionPoolLock = DEFAULTMUTEX;

static Connection **sessionPool = NULL;
static int sessionPoolSize = 0;


static mutex_t	nscdLock = DEFAULTMUTEX;
static int	nscdChecked = 0;
static pid_t	checkedPid = -1;
static int	isNscd = 0;

/* Number of hostnames to allocate memory for */
#define	NUMTOMALLOC	32


/*
 * Check /proc/PID/psinfo to see if this process is nscd
 * If it is, treat connection as NS_LDAP_KEEP_CONN, to reduce
 * constant reconnects for many operations.
 * A more complete solution is to develop true connection pooling.
 * However, this is much better than a new connection for every request.
 */
static int
nscd_proc()
{
	pid_t		my_pid;
	psinfo_t	pinfo;
	char		fname[BUFSIZ];
	int		ret;
	int		fd;

	/* Don't bother checking if this process isn't root. */
	/* It can't be nscd */
	if (getuid() != 0)
		return (0);

	my_pid = getpid();
	if (nscdChecked && (my_pid == checkedPid)) {
		return (isNscd);
	}
	(void) mutex_lock(&nscdLock);
	if (nscdChecked && (my_pid == checkedPid)) {
		(void) mutex_unlock(&nscdLock);
		return (isNscd);
	}
	nscdChecked = 1;
	checkedPid = my_pid;
	isNscd = 0;
	if (snprintf(fname, BUFSIZ, "/proc/%d/psinfo", my_pid) != 0) {
		if ((fd = open(fname,  O_RDONLY)) > 0) {
			ret = read(fd, &pinfo, sizeof (psinfo_t));
			(void) close(fd);
			if (ret == sizeof (psinfo_t) &&
			    (strcmp(pinfo.pr_fname, "nscd") == 0)) {
				/* process runs as root and is named nscd */
				/* that's good enough for now */
				isNscd = 1;
			}
		}
	}
	(void) mutex_unlock(&nscdLock);
	return (isNscd);
}

/*
 * This function requests a server from the cache manager through
 * the door functionality
 */

static int
__s_api_requestServer(const char *request, const char *server,
	ns_server_info_t *ret, ns_ldap_error_t **error)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;
	ldap_data_t	*sptr;
	int		ndata;
	int		adata;
	char		errstr[MAXERROR];
	const char	*ireq;
	char		*rbuf, *ptr, *rest;
	char		*dptr;
	char		**mptr, **mptr1, **cptr, **cptr1;
	int		mcnt, ccnt;
	char		**servers;
	int		rc;

	if (ret == NULL || error == NULL) {
		return (NS_LDAP_OP_FAILED);
	}
	(void) memset(ret, 0, sizeof (ns_server_info_t));
	*error = NULL;

	(void) memset(space.s_b, 0, DOORBUFFERSIZE);

	if (request == NULL)
		ireq = NS_CACHE_NEW;
	else
		ireq = request;

	adata = (sizeof (ldap_call_t) + strlen(ireq) +1);
	if (server != NULL) {
		adata += strlen(DOORLINESEP) + 1;
		adata += strlen(server) + 1;
	}
	ndata = sizeof (space);
	space.s_d.ldap_call.ldap_callnumber = GETLDAPSERVER;
	(void) strcpy(space.s_d.ldap_call.ldap_u.domainname, ireq);
	if (server != NULL) {
		(void) strcat(space.s_d.ldap_call.ldap_u.domainname,
			DOORLINESEP);
		(void) strcat(space.s_d.ldap_call.ldap_u.domainname, server);
	}
	sptr = &space.s_d;

	switch (__ns_ldap_trydoorcall(&sptr, &ndata, &adata)) {
	case SUCCESS:
		break;
	/* this case is for when the $mgr is not running, but ldapclient */
	/* is trying to initialize things */
	case NOSERVER:
		/* get first server from config list unavailable otherwise */
		servers = NULL;
		rc = __s_api_getServers(&servers, error);
		if (rc != NS_LDAP_SUCCESS) {
			if (servers != NULL) {
				__s_api_free2dArray(servers);
				servers = NULL;
			}
			return (rc);
		}
		if (servers == NULL || servers[0] == NULL) {
			__s_api_free2dArray(servers);
			servers = NULL;
			(void) sprintf(errstr,
				gettext("No server found in configuration"));
			MKERROR(LOG_ERR, *error, NS_CONFIG_NODEFAULT,
				strdup(errstr), NULL);
			return (NS_LDAP_CONFIG);
		}
		ret->server = strdup(servers[0]);
		if (ret->server == NULL) {
			__s_api_free2dArray(servers);
			return (NS_LDAP_MEMORY);
		}
		ret->saslMechanisms = NULL;
		ret->controls = NULL;
		__s_api_free2dArray(servers);
		servers = NULL;
		return (NS_LDAP_SUCCESS);
	case NOTFOUND:
	default:
		return (NS_LDAP_OP_FAILED);
	}

	/* copy info from door call return structure here */
	rbuf =  space.s_d.ldap_ret.ldap_u.config;

	/* Get the host */
	ptr = strtok_r(rbuf, DOORLINESEP, &rest);
	if (ptr == NULL) {
		(void) sprintf(errstr, gettext("No server returned from "
			"ldap_cachemgr"));
		MKERROR(LOG_WARNING, *error, NS_CONFIG_CACHEMGR,
			strdup(errstr), NULL);
		return (NS_LDAP_OP_FAILED);
	}
	ret->server = strdup(ptr);
	if (ret->server == NULL) {
		return (NS_LDAP_MEMORY);
	}

	/* get the Supported Controls/SASL mechs */
	mptr = NULL;
	mcnt = 0;
	cptr = NULL;
	ccnt = 0;
	for (; ; ) {
		ptr = strtok_r(NULL, DOORLINESEP, &rest);
		if (ptr == NULL)
			break;
		if (strncasecmp(ptr, _SASLMECHANISM,
				_SASLMECHANISM_LEN) == 0) {
			dptr = strchr(ptr, '=');
			if (dptr == NULL)
				continue;
			dptr++;
			mptr1 = (char **)realloc((void *)mptr,
					sizeof (char *) * (mcnt+2));
			if (mptr1 == NULL) {
				__s_api_free2dArray(mptr);
				if (sptr != &space.s_d) {
				    (void) munmap((char *)sptr, ndata);
				}
				__s_api_free2dArray(cptr);
				free(ret->server);
				ret->server = NULL;
				return (NS_LDAP_MEMORY);
			}
			mptr = mptr1;
			mptr[mcnt] = strdup(dptr);
			if (mptr[mcnt] == NULL) {
				if (sptr != &space.s_d) {
				    (void) munmap((char *)sptr, ndata);
				}
				__s_api_free2dArray(cptr);
				cptr = NULL;
				__s_api_free2dArray(mptr);
				mptr = NULL;
				free(ret->server);
				ret->server = NULL;
				return (NS_LDAP_MEMORY);
			}
			mcnt++;
			mptr[mcnt] = NULL;
		}
		if (strncasecmp(ptr, _SUPPORTEDCONTROL,
			_SUPPORTEDCONTROL_LEN) == 0) {
			dptr = strchr(ptr, '=');
			if (dptr == NULL)
				continue;
			dptr++;
			cptr1 = (char **)realloc((void *)cptr,
					sizeof (char *) * (ccnt+2));
			if (cptr1 == NULL) {
				if (sptr != &space.s_d) {
				    (void) munmap((char *)sptr, ndata);
				}
				__s_api_free2dArray(cptr);
				__s_api_free2dArray(mptr);
				mptr = NULL;
				free(ret->server);
				ret->server = NULL;
				return (NS_LDAP_MEMORY);
			}
			cptr = cptr1;
			cptr[ccnt] = strdup(dptr);
			if (cptr[ccnt] == NULL) {
				if (sptr != &space.s_d) {
				    (void) munmap((char *)sptr, ndata);
				}
				__s_api_free2dArray(cptr);
				cptr = NULL;
				__s_api_free2dArray(mptr);
				mptr = NULL;
				free(ret->server);
				ret->server = NULL;
				return (NS_LDAP_MEMORY);
			}
			ccnt++;
			cptr[ccnt] = NULL;
		}
	}
	if (mptr != NULL) {
		ret->saslMechanisms = mptr;
	}
	if (cptr != NULL) {
		ret->controls = cptr;
	}


	/* clean up door call */
	if (sptr != &space.s_d) {
		(void) munmap((char *)sptr, ndata);
	}
	*error = NULL;

	return (NS_LDAP_SUCCESS);
}

#ifdef DEBUG

/*
 * printCred(): prints the credential structure
 */
static void
printCred(FILE *fp, const ns_cred_t *cred)
{
	if (fp == NULL) {
		(void) fprintf(fp, "printCred: fp is NULL\n");
		return;
	}
	if (cred == NULL) {
		(void) fprintf(fp, "printCred: cred is NULL\n");
		return;
	}

	(void) fprintf(fp, "AuthType=%d\n", cred->auth.type);
	(void) fprintf(fp, "TlsType=%d\n", cred->auth.tlstype);
	(void) fprintf(fp, "SaslMech=%d\n", cred->auth.saslmech);
	(void) fprintf(fp, "SaslOpt=%d\n", cred->auth.saslopt);
	if (cred->hostcertpath)
		(void) fprintf(fp, "hostCertPath=%s\n", cred->hostcertpath);
	if (cred->cred.unix_cred.userID)
		(void) fprintf(fp, "userID=%s\n", cred->cred.unix_cred.userID);
	if (cred->cred.unix_cred.passwd)
		(void) fprintf(fp, "passwd=%s\n", cred->cred.unix_cred.passwd);
}

/*
 * printConnection(): prints the connection structure
 */
static void
printConnection(FILE *fp, Connection *con)
{
	if (fp == NULL || con == NULL)
		return;

	(void) fprintf(fp, "connectionID=%d\n", con->connectionId);
	(void) fprintf(fp, "usedBit=%d\n", con->usedBit);
	(void) fprintf(fp, "threadID=%d\n", con->threadID);
	if (con->serverAddr) {
		(void) fprintf(fp, "serverAddr=%s\n", con->serverAddr);
	}
	printCred(fp, con->auth);
	(void) fprintf(fp, "-----------------------------------------------\n");
	fflush(fp);
}

#endif /* DEBUG */


/*
 * addConnection(): inserts a connection in the connection list.
 * It will also sets use bit and the thread Id for the thread
 * using the connection for the first time.
 * Returns: -1 = failure, new Connection ID = success
 */
static int
addConnection(Connection *con)
{
	int i;

	if (!con)
		return (-1);
#ifdef DEBUG
	(void) fprintf(stderr, "Adding connection thrid=%d\n", con->threadID);
#endif /* DEBUG */
	(void) mutex_lock(&sessionPoolLock);
	if (sessionPool == NULL) {
		sessionPoolSize = SESSION_CACHE_INC;
		sessionPool = calloc(sessionPoolSize,
				sizeof (struct connection **));
		if (!sessionPool) {
			(void) mutex_unlock(&sessionPoolLock);
			return (-1);
		}
#ifdef DEBUG
		(void) fprintf(stderr, "Initialized sessionPool\n");
#endif /* DEBUG */
	}
	for (i = 0; (i < sessionPoolSize) && (sessionPool[i] != NULL); ++i)
		;
	if (i == sessionPoolSize) {
		/* run out of array, need to increase sessionPool */
		Connection **cl;
		cl = (Connection **) realloc(sessionPool,
			(sessionPoolSize + SESSION_CACHE_INC) *
			sizeof (Connection *));
		if (!cl) {
			(void) mutex_unlock(&sessionPoolLock);
			return (-1);
		}
		(void) memset(cl + sessionPoolSize, 0,
			SESSION_CACHE_INC * sizeof (struct connection *));
		sessionPool = cl;
		sessionPoolSize += SESSION_CACHE_INC;
#ifdef DEBUG
		(void) fprintf(stderr, "Increased sessionPoolSize to: %d\n",
				sessionPoolSize);
#endif /* DEBUG */
	}
	sessionPool[i] = con;
	con->usedBit = B_TRUE;
	(void) mutex_unlock(&sessionPoolLock);
	con->connectionId = i + CONID_OFFSET;
#ifdef DEBUG
	(void) fprintf(stderr, "Connection added [%d]\n", i);
	printConnection(stderr, con);
#endif /* DEBUG */
	return (i + CONID_OFFSET);
}

/*
 * See if the specified session matches a currently available
 */

static int
findConnectionById(int flags, const ns_cred_t *auth, ConnectionID cID,
	Connection **conp)
{
	Connection *cp;
	int id;

	if ((conp == NULL) || (auth == NULL) || cID < CONID_OFFSET)
		return (-1);
	*conp = NULL;
	if (sessionPool == NULL)
		return (-1);
	id = cID - CONID_OFFSET;
	if (id < 0 || id >= sessionPoolSize)
		return (-1);

	(void) mutex_lock(&sessionPoolLock);
	if (sessionPool[id] == NULL) {
		(void) mutex_unlock(&sessionPoolLock);
		return (-1);
	}
	cp = sessionPool[id];

	/*
	 * Make sure the connection has the same type of authentication method
	 */
	if ((cp->usedBit) ||
	    (cp->auth->auth.type != auth->auth.type) ||
	    (cp->auth->auth.tlstype != auth->auth.tlstype) ||
	    (cp->auth->auth.saslmech != auth->auth.saslmech) ||
	    (cp->auth->auth.saslopt != auth->auth.saslopt)) {
		(void) mutex_unlock(&sessionPoolLock);
		return (-1);
	}
	if ((((cp->auth->auth.type == NS_LDAP_AUTH_SASL) &&
		((cp->auth->auth.saslmech == NS_LDAP_SASL_CRAM_MD5) ||
		(cp->auth->auth.saslmech == NS_LDAP_SASL_DIGEST_MD5))) ||
		(cp->auth->auth.type == NS_LDAP_AUTH_SIMPLE)) &&
		((cp->auth->cred.unix_cred.userID == NULL) ||
		(strcasecmp(cp->auth->cred.unix_cred.userID,
		auth->cred.unix_cred.userID) != 0))) {
		(void) mutex_unlock(&sessionPoolLock);
		return (-1);
	}
	/* An existing connection is found but it needs to be reset */
	if (flags & NS_LDAP_NEW_CONN) {
		(void) mutex_unlock(&sessionPoolLock);
		DropConnection(cID, 0);
		return (-1);
	}
	/* found an available connection */
	cp->usedBit = B_TRUE;
	(void) mutex_unlock(&sessionPoolLock);
	cp->threadID = thr_self();
	*conp = cp;
	return (cID);
}

/*
 * findConnection(): find an available connection from the list
 * that matches the criteria specified in Connection structure.
 * If serverAddr is NULL, then find a connection to any server
 * as long as it matches the rest of the parameters.
 * Returns: -1 = failure, the Connection ID found = success.
 */
static int
findConnection(const char *serverAddr, const ns_cred_t *auth, Connection **conp)
{
	Connection *cp;
	int i;

	if (auth == NULL || conp == NULL)
		return (-1);
	*conp = NULL;

#ifdef DEBUG
	(void) fprintf(stderr, "Find connection\n");
	(void) fprintf(stderr, "Looking for ....\n");
	if (serverAddr && *serverAddr)
		(void) fprintf(stderr, "serverAddr=%s\n", serverAddr);
	else
		(void) fprintf(stderr, "serverAddr=NULL\n");
	printCred(stderr, auth);
	fflush(stderr);
#endif /* DEBUG */
	if (sessionPool == NULL)
		return (-1);
	(void) mutex_lock(&sessionPoolLock);
	for (i = 0; i < sessionPoolSize; ++i) {
		if (sessionPool[i] == NULL)
			continue;
		cp = sessionPool[i];
#ifdef DEBUG
		(void) fprintf(stderr, "checking connection [%d] ....\n", i);
		printConnection(stderr, cp);
#endif /* DEBUG */
		if ((cp->usedBit) ||
		    (cp->auth->auth.type != auth->auth.type) ||
		    (cp->auth->auth.tlstype != auth->auth.tlstype) ||
		    (cp->auth->auth.saslmech != auth->auth.saslmech) ||
		    (cp->auth->auth.saslopt != auth->auth.saslopt) ||
		    (serverAddr && *serverAddr &&
		    (strcasecmp(serverAddr, cp->serverAddr) != 0)))
			continue;
		if ((((cp->auth->auth.type == NS_LDAP_AUTH_SASL) &&
		    ((cp->auth->auth.saslmech == NS_LDAP_SASL_CRAM_MD5) ||
		    (cp->auth->auth.saslmech == NS_LDAP_SASL_DIGEST_MD5))) ||
		    (cp->auth->auth.type == NS_LDAP_AUTH_SIMPLE)) &&
		    ((cp->auth->cred.unix_cred.userID == NULL) ||
		    (cp->auth->cred.unix_cred.passwd == NULL) ||
		    ((strcasecmp(cp->auth->cred.unix_cred.userID,
			    auth->cred.unix_cred.userID) != 0)) ||
		    ((strcmp(cp->auth->cred.unix_cred.passwd,
			    auth->cred.unix_cred.passwd) != 0))))
				continue;
		/* found an available connection */
		cp->usedBit = B_TRUE;
		(void) mutex_unlock(&sessionPoolLock);
		cp->threadID = thr_self();
		*conp = cp;
#ifdef DEBUG
		(void) fprintf(stderr, "Connection found cID=%d\n", i);
		fflush(stderr);
#endif /* DEBUG */
		return (i + CONID_OFFSET);
	}
	(void) mutex_unlock(&sessionPoolLock);
	return (-1);
}

/*
 * Free a Connection structure
 */
static void
freeConnection(Connection *con)
{
	if (con == NULL)
		return;
	if (con->serverAddr)
		free(con->serverAddr);
	if (con->auth)
		(void) __ns_ldap_freeCred(&(con->auth));
	if (con->saslMechanisms) {
		__s_api_free2dArray(con->saslMechanisms);
	}
	if (con->controls) {
		__s_api_free2dArray(con->controls);
	}
	free(con);
}

/*
 * Find a connection matching the passed in criteria.  If an open
 * connection with that criteria exists use it, otherwise open a
 * new connection.
 * Success: returns the pointer to the Connection structure
 * Failure: returns NULL, error code and message should be in errorp
 */

static int
makeConnection(Connection **conp, const char *serverAddr,
	const ns_cred_t *auth, ConnectionID *cID, int timeoutSec,
	ns_ldap_error_t **errorp, int fail_if_new_pwd_reqd,
	int nopasswd_acct_mgmt, char ***badsrvrs)
{
	Connection *con = NULL;
	ConnectionID id;
	char errmsg[MAXERROR];
	int rc, exit_rc = NS_LDAP_SUCCESS;
	ns_server_info_t sinfo;
	char *hReq, *host = NULL;
	LDAP *ld = NULL;
	int passwd_mgmt = 0;
	int totalbad = 0; /* Number of servers contacted unsuccessfully */
	short	memerr = 0; /* Variable for tracking memory allocation errors */

	if (conp == NULL || errorp == NULL || auth == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*errorp = NULL;
	*conp = NULL;
	sinfo.server = NULL;
	sinfo.controls = NULL;
	sinfo.saslMechanisms = NULL;

	if ((id = findConnection(serverAddr, auth, &con)) != -1) {
		/* connection found in cache */
#ifdef DEBUG
		(void) fprintf(stderr, "connection found in cache %d\n", id);
		fflush(stderr);
#endif /* DEBUG */
		*cID = id;
		*conp = con;
		return (NS_LDAP_SUCCESS);
	}

	if (serverAddr) {
		rc = openConnection(&ld, serverAddr, auth, timeoutSec, errorp,
				fail_if_new_pwd_reqd, passwd_mgmt);
		if (rc == NS_LDAP_SUCCESS || rc ==
				NS_LDAP_SUCCESS_WITH_INFO) {
			exit_rc = rc;
			rc = __s_api_requestServer(NS_CACHE_NEW, serverAddr,
				&sinfo, errorp);
			if (rc != NS_LDAP_SUCCESS || sinfo.server == NULL) {
				(void) snprintf(errmsg, sizeof (errmsg),
				gettext("makeConnection: unable to get "
				"server information for %s"), serverAddr);
				syslog(LOG_ERR, "libsldap: %s", errmsg);
				return (NS_LDAP_OP_FAILED);
			}
			goto create_con;
		} else {
			return (rc);
		}
	}

	/* No cached connection, create one */
	for (; ; ) {
		if (host == NULL)
			hReq = NS_CACHE_NEW;
		else
			hReq = NS_CACHE_NEXT;
		rc = __s_api_requestServer(hReq, host, &sinfo, errorp);
		if ((rc != NS_LDAP_SUCCESS) || (sinfo.server == NULL) ||
			(host && (strcasecmp(host, sinfo.server) == 0))) {
			/* Log the error */
			if (*errorp) {
				(void) snprintf(errmsg, sizeof (errmsg),
				"%s: (%s)", gettext("makeConnection: "
				"unable to make LDAP connection, "
				"request for a server failed"),
				    (*errorp)->message);
				syslog(LOG_ERR, "libsldap: %s", errmsg);
			}

			if (sinfo.server)
				free(sinfo.server);
			__s_api_free2dArray(sinfo.saslMechanisms);
			__s_api_free2dArray(sinfo.controls);
			if (host)
				free(host);
			return (NS_LDAP_OP_FAILED);
		}
		if (host)
			free(host);
		host = strdup(sinfo.server);
		if (host == NULL) {
			free(sinfo.server);
			__s_api_free2dArray(sinfo.saslMechanisms);
			__s_api_free2dArray(sinfo.controls);
			return (NS_LDAP_MEMORY);
		}

		/* check if server supports password management */
		passwd_mgmt = __s_api_contain_passwd_control_oid(
			sinfo.controls);
		/* check if server supports password less account mgmt */
		if (nopasswd_acct_mgmt &&
			!__s_api_contain_account_usable_control_oid(
			sinfo.controls)) {
			syslog(LOG_WARNING, "libsldap: server %s does not "
				"provide account information without password",
				host);
			free(host);
			free(sinfo.server);
			__s_api_free2dArray(sinfo.saslMechanisms);
			__s_api_free2dArray(sinfo.controls);
			return (NS_LDAP_OP_FAILED);
		}
		/* make the connection */
		rc = openConnection(&ld, host, auth, timeoutSec, errorp,
				fail_if_new_pwd_reqd, passwd_mgmt);
		/* if success, go to create connection structure */
		if (rc == NS_LDAP_SUCCESS ||
				rc == NS_LDAP_SUCCESS_WITH_INFO) {
			exit_rc = rc;
			break;
		}

		/*
		 * If not able to reach the server, inform the ldap
		 * cache manager that the server should be removed
		 * from its server list. Thus, the manager will not
		 * return this server on the next get-server request
		 * and will also reduce the server list refresh TTL,
		 * so that it will find out sooner when the server
		 * is up again.
		 */
		if (rc == NS_LDAP_INTERNAL && *errorp != NULL) {
			if ((*errorp)->status == LDAP_CONNECT_ERROR ||
				(*errorp)->status == LDAP_SERVER_DOWN) {
				/* Reset memory allocation error */
				memerr = 0;
				/*
				 * We contacted a server that we could
				 * not either authenticate to or contact.
				 * If it is due to authentication, then
				 * we need to try the server again. So,
				 * do not remove the server yet, but
				 * add it to the bad server list.
				 * The caller routine will remove
				 * the servers if:
				 *	a). A good server is found or
				 *	b). All the possible methods
				 *	    are tried without finding
				 *	    a good server
				 */
				if (*badsrvrs == NULL) {
				    if (!(*badsrvrs = (char **)malloc
					(sizeof (char *) * NUMTOMALLOC))) {
					memerr = 1;
				    }
				/* Allocate memory in chunks of NUMTOMALLOC */
				} else if ((totalbad % NUMTOMALLOC) ==
					    NUMTOMALLOC - 1) {
				    char **tmpptr;
				    if (!(tmpptr = (char **)realloc(*badsrvrs,
					    (sizeof (char *) * NUMTOMALLOC *
					    ((totalbad/NUMTOMALLOC) + 2))))) {
					memerr = 1;
				    } else {
					*badsrvrs = tmpptr;
				    }
				}
				/*
				 * Store host only if there were no unsuccessful
				 * memory allocations above
				 */
				if (!memerr &&
				    !((*badsrvrs)[totalbad++] = strdup(host))) {
					memerr = 1;
					totalbad--;
				}
				(*badsrvrs)[totalbad] = NULL;
			}
		}

		/* else, cleanup and go for the next server */
		if (sinfo.server) {
			free(sinfo.server);
			sinfo.server = NULL;
		}
		__s_api_free2dArray(sinfo.saslMechanisms);
		sinfo.saslMechanisms = NULL;
		__s_api_free2dArray(sinfo.controls);
		sinfo.controls = NULL;
		/* Return if we had memory allocation errors */
		if (memerr)
			return (NS_LDAP_MEMORY);
		if (*errorp) {
			/*
			 * If openConnection() failed due to
			 * password policy, or invalid credential,
			 * keep *errorp and exit
			 */
			if ((*errorp)->pwd_mgmt.status != NS_PASSWD_GOOD ||
			    (*errorp)->status == LDAP_INVALID_CREDENTIALS) {
				free(host);
				return (rc);
			} else {
				(void) __ns_ldap_freeError(errorp);
				*errorp = NULL;
			}
		}
	}

create_con:
	/* we have created ld, setup con structure */
	if (host)
		free(host);
	if ((con = calloc(1, sizeof (Connection))) == NULL) {
		if (sinfo.server)
			free(sinfo.server);
		__s_api_free2dArray(sinfo.saslMechanisms);
		__s_api_free2dArray(sinfo.controls);
		/*
		 * If password control attached in **errorp,
		 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
		 * free the error structure
		 */
		if (*errorp) {
			(void) __ns_ldap_freeError(errorp);
			*errorp = NULL;
		}
		return (NS_LDAP_MEMORY);
	}

	con->serverAddr = sinfo.server;
	con->saslMechanisms = sinfo.saslMechanisms;
	con->controls = sinfo.controls;

	con->auth = __ns_ldap_dupAuth(auth);
	if (con->auth == NULL) {
		free(con);
		/*
		 * If password control attached in **errorp,
		 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
		 * free the error structure
		 */
		if (*errorp) {
			(void) __ns_ldap_freeError(errorp);
			*errorp = NULL;
		}
		return (NS_LDAP_MEMORY);
	}

	con->threadID = thr_self();
	con->ld = ld;
	if ((id = addConnection(con)) == -1) {
		freeConnection(con);
		/*
		 * If password control attached in **errorp,
		 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
		 * free the error structure
		 */
		if (*errorp) {
			(void) __ns_ldap_freeError(errorp);
			*errorp = NULL;
		}
		return (NS_LDAP_MEMORY);
	}
#ifdef DEBUG
	(void) fprintf(stderr, "connection added into cache %d\n", id);
	fflush(stderr);
#endif /* DEBUG */
	*cID = id;
	*conp = con;
	return (exit_rc);
}

/*
 * Return the specified connection to the pool.  If necessary
 * delete the connection.
 */

static void
_DropConnection(ConnectionID cID, int flag, int fini)
{
	Connection *cp;
	int id;
	int use_mutex = !fini;

	id = cID - CONID_OFFSET;
	if (id < 0 || id >= sessionPoolSize)
		return;
#ifdef DEBUG
	(void) fprintf(stderr,
		"Dropping connection cID=%d flag=0x%x\n", cID, flag);
	fflush(stderr);
#endif /* DEBUG */
	if (use_mutex)
		(void) mutex_lock(&sessionPoolLock);

	cp = sessionPool[id];
	/* sanity check before removing */
	if (!cp || (!fini && (!cp->usedBit || cp->threadID != thr_self()))) {
		if (use_mutex)
			(void) mutex_unlock(&sessionPoolLock);
		return;
	}

	if (!fini &&
		((flag & NS_LDAP_NEW_CONN) == 0) &&
		((flag & NS_LDAP_KEEP_CONN) || nscd_proc())) {
		/* release Connection (keep alive) */
		cp->usedBit = B_FALSE;
		cp->threadID = 0;	/* unmark the threadID */
		if (use_mutex)
			(void) mutex_unlock(&sessionPoolLock);
	} else {
		/* delete Connection (disconnect) */
		sessionPool[id] = NULL;
		if (use_mutex)
			(void) mutex_unlock(&sessionPoolLock);
		(void) ldap_unbind(cp->ld);
		freeConnection(cp);
	}
}

void
DropConnection(ConnectionID cID, int flag)
{
	_DropConnection(cID, flag, 0);
}

/*
 * This routine is called after a bind operation is
 * done in openConnection() to process the password
 * management information, if any.
 *
 * Input:
 *   bind_type: "simple" or "sasl/DIGEST-MD5"
 *   ldaprc   : ldap rc from the ldap bind operation
 *   controls : controls returned by the server
 *   errmsg   : error message from the server
 *   fail_if_new_pwd_reqd:
 *              flag indicating if connection should be open
 *              when password needs to change immediately
 *   passwd_mgmt:
 *              flag indicating if server supports password
 *              policy/management
 *
 * Output     : ns_ldap_error structure, which may contain
 *              password status and number of seconds until
 *              expired
 *
 * return rc:
 * NS_LDAP_EXTERNAL: error, connection should not open
 * NS_LDAP_SUCCESS_WITH_INFO: OK to open but password info attached
 * NS_LDAP_SUCCESS: OK to open connection
 *
 */

static int
process_pwd_mgmt(char *bind_type, int ldaprc,
		LDAPControl **controls,
		char *errmsg, ns_ldap_error_t **errorp,
		int fail_if_new_pwd_reqd,
		int passwd_mgmt)
{
	char		errstr[MAXERROR];
	LDAPControl	**ctrl = NULL;
	int		exit_rc;
	ns_ldap_passwd_status_t	pwd_status = NS_PASSWD_GOOD;
	int		sec_until_exp = 0;

	/*
	 * errmsg may be an empty string,
	 * even if ldaprc is LDAP_SUCCESS,
	 * free the empty string if that's the case
	 */
	if (errmsg &&
		(*errmsg == '\0' || ldaprc == LDAP_SUCCESS)) {
		ldap_memfree(errmsg);
		errmsg = NULL;
	}

	if (ldaprc != LDAP_SUCCESS) {
		/*
		 * try to map ldap rc and error message to
		 * a password status
		 */
		if (errmsg) {
			if (passwd_mgmt)
				pwd_status =
					__s_api_set_passwd_status(
					ldaprc, errmsg);
			ldap_memfree(errmsg);
		}

		(void) snprintf(errstr, sizeof (errstr),
			gettext("openConnection: "
			"%s bind failed "
			"- %s"), bind_type, ldap_err2string(ldaprc));

		if (pwd_status != NS_PASSWD_GOOD) {
			MKERROR_PWD_MGMT(*errorp,
				ldaprc, strdup(errstr),
				pwd_status, 0, NULL);
		} else {
			MKERROR(LOG_ERR, *errorp, ldaprc, strdup(errstr),
				NULL);
		}
		if (controls)
			ldap_controls_free(controls);

		return (NS_LDAP_INTERNAL);
	}

	/*
	 * ldaprc is LDAP_SUCCESS,
	 * process the password management controls, if any
	 */
	exit_rc = NS_LDAP_SUCCESS;
	if (controls && passwd_mgmt) {
		/*
		 * The control with the OID
		 * 2.16.840.1.113730.3.4.4 (or
		 * LDAP_CONTROL_PWEXPIRED, as defined
		 * in the ldap.h header file) is the
		 * expired password control.
		 *
		 * This control is used if the server
		 * is configured to require users to
		 * change their passwords when first
		 * logging in and whenever the
		 * passwords are reset.
		 *
		 * If the user is logging in for the
		 * first time or if the user's
		 * password has been reset, the
		 * server sends this control to
		 * indicate that the client needs to
		 * change the password immediately.
		 *
		 * At this point, the only operation
		 * that the client can perform is to
		 * change the user's password. If the
		 * client requests any other LDAP
		 * operation, the server sends back
		 * an LDAP_UNWILLING_TO_PERFORM
		 * result code with an expired
		 * password control.
		 *
		 * The control with the OID
		 * 2.16.840.1.113730.3.4.5 (or
		 * LDAP_CONTROL_PWEXPIRING, as
		 * defined in the ldap.h header file)
		 * is the password expiration warning
		 * control.
		 *
		 * This control is used if the server
		 * is configured to expire user
		 * passwords after a certain amount
		 * of time.
		 *
		 * The server sends this control back
		 * to the client if the client binds
		 * using a password that will soon
		 * expire.  The ldctl_value field of
		 * the LDAPControl structure
		 * specifies the number of seconds
		 * before the password will expire.
		 */
		for (ctrl = controls; *ctrl; ctrl++) {

			if (strcmp((*ctrl)->ldctl_oid,
				LDAP_CONTROL_PWEXPIRED) == 0) {
				/*
				 * if the caller wants this bind
				 * to fail, set up the error info.
				 * If call to this function is
				 * for searching the LDAP directory,
				 * e.g., __ns_ldap_list(),
				 * there's really no sense to
				 * let a connection open and
				 * then fail immediately afterward
				 * on the LDAP search operation with
				 * the LDAP_UNWILLING_TO_PERFORM rc
				 */
				pwd_status =
					NS_PASSWD_CHANGE_NEEDED;
				if (fail_if_new_pwd_reqd) {
					(void) snprintf(errstr,
						sizeof (errstr),
						gettext(
						"openConnection: "
						"%s bind "
						"failed "
						"- password "
						"expired. It "
						" needs to change "
						"immediately!"),
						bind_type);
					MKERROR_PWD_MGMT(*errorp,
						LDAP_SUCCESS,
						strdup(errstr),
						pwd_status,
						0,
						NULL);
					exit_rc = NS_LDAP_INTERNAL;
				} else {
					MKERROR_PWD_MGMT(*errorp,
						LDAP_SUCCESS,
						NULL,
						pwd_status,
						0,
						NULL);
					exit_rc =
					NS_LDAP_SUCCESS_WITH_INFO;
				}
				break;
			} else if (strcmp((*ctrl)->ldctl_oid,
				LDAP_CONTROL_PWEXPIRING) == 0) {
				pwd_status =
					NS_PASSWD_ABOUT_TO_EXPIRE;
				if ((*ctrl)->
					ldctl_value.bv_len > 0 &&
					(*ctrl)->
						ldctl_value.bv_val)
					sec_until_exp =
						atoi((*ctrl)->
						ldctl_value.bv_val);
				MKERROR_PWD_MGMT(*errorp,
					LDAP_SUCCESS,
					NULL,
					pwd_status,
					sec_until_exp,
					NULL);
				exit_rc =
					NS_LDAP_SUCCESS_WITH_INFO;
				break;
			}
		}
	}

	if (controls)
		ldap_controls_free(controls);

	return (exit_rc);
}

static int
ldap_in_hosts_switch()
{
	enum __nsw_parse_err		pserr;
	struct __nsw_switchconfig	*conf;
	struct __nsw_lookup		*lkp;
	const char			*name;
	int				found = 0;

	conf = __nsw_getconfig("hosts", &pserr);
	if (conf == NULL) {
		return (-1);
	}

	/* check for skip and count other backends */
	for (lkp = conf->lookups; lkp != NULL; lkp = lkp->next) {
		name = lkp->service_name;
		if (strcmp(name, "ldap") == 0) {
			found = 1;
			break;
		}
	}
	__nsw_freeconfig(conf);
	return (found);
}

static int
openConnection(LDAP **ldp, const char *serverAddr, const ns_cred_t *auth,
	int timeoutSec, ns_ldap_error_t **errorp,
	int fail_if_new_pwd_reqd, int passwd_mgmt)
{
	LDAP		*ld = NULL;
	char		*binddn, *passwd;
	char		*digest_md5_name;
	const char	*s;
	int		ldapVersion = LDAP_VERSION3;
	int		derefOption = LDAP_DEREF_ALWAYS;
	int		zero = 0;
	int		rc;
	char		errstr[MAXERROR];
	int		errnum = 0;
	LDAPMessage	*resultMsg;
	int		msgId;
	int		useSSL = 0;
	struct timeval	tv;
	AuthType_t	bindType;
	int		timeoutMilliSec = timeoutSec * 1000;
	struct berval	cred;
	char		*sslServerAddr;
	char		*s1;
	char		*errmsg;
	LDAPControl	**controls;
	int		pwd_rc;

	*errorp = NULL;
	*ldp = NULL;

	switch (auth->auth.type) {
		case NS_LDAP_AUTH_NONE:
		case NS_LDAP_AUTH_SIMPLE:
		case NS_LDAP_AUTH_SASL:
			bindType = auth->auth.type;
			break;
		case NS_LDAP_AUTH_TLS:
			useSSL = 1;
			switch (auth->auth.tlstype) {
				case NS_LDAP_TLS_NONE:
					bindType = NS_LDAP_AUTH_NONE;
					break;
				case NS_LDAP_TLS_SIMPLE:
					bindType = NS_LDAP_AUTH_SIMPLE;
					break;
				case NS_LDAP_TLS_SASL:
					bindType = NS_LDAP_AUTH_SASL;
					break;
				default:
					(void) sprintf(errstr,
					gettext("openConnection: unsupported "
						"TLS authentication method "
						"(%d)"), auth->auth.tlstype);
					MKERROR(LOG_WARNING, *errorp,
						LDAP_AUTH_METHOD_NOT_SUPPORTED,
						strdup(errstr), NULL);
					return (NS_LDAP_INTERNAL);
			}
			break;
		default:
			(void) sprintf(errstr,
				gettext("openConnection: unsupported "
				"authentication method (%d)"), auth->auth.type);
			MKERROR(LOG_WARNING, *errorp,
				LDAP_AUTH_METHOD_NOT_SUPPORTED, strdup(errstr),
				NULL);
			return (NS_LDAP_INTERNAL);
	}

	if (useSSL) {
		const char	*hostcertpath;
		char		*alloc_hcp = NULL;
#ifdef DEBUG
		(void) fprintf(stderr, "+++TLS transport\n");
#endif /* DEBUG */

		if (prldap_set_session_option(NULL, NULL,
		    PRLDAP_OPT_IO_MAX_TIMEOUT,
		    timeoutMilliSec) != LDAP_SUCCESS) {
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: failed to initialize "
				"TLS security"));
			MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
				strdup(errstr), NULL);
			return (NS_LDAP_INTERNAL);
		}

		hostcertpath = auth->hostcertpath;
		if (hostcertpath == NULL) {
			alloc_hcp = __s_get_hostcertpath();
			hostcertpath = alloc_hcp;
		}

		if (hostcertpath == NULL)
			return (NS_LDAP_MEMORY);

		if ((rc = ldapssl_client_init(hostcertpath, NULL)) < 0) {
			if (alloc_hcp)
				free(alloc_hcp);
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: failed to initialize "
				"TLS security (%s)"),
				ldapssl_err2string(rc));
			MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
				strdup(errstr), NULL);
			return (NS_LDAP_INTERNAL);
		}
		if (alloc_hcp)
			free(alloc_hcp);

		/* determine if the host name contains a port number */
		s = strchr(serverAddr, ']');	/* skip over ipv6 addr */
		if (s == NULL)
			s = serverAddr;
		s = strchr(s, ':');
		if (s != NULL) {
			/*
			 * If we do get a port number, we will try stripping
			 * it. At present, referrals will always have a
			 * port number.
			 */
			sslServerAddr = strdup(serverAddr);
			if (sslServerAddr == NULL)
				return (NS_LDAP_MEMORY);
			s1 = strrchr(sslServerAddr, ':');
			if (s1 != NULL)
				*s1 = '\0';
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("openConnection: cannot use tls with %s. "
				"Trying %s"),
				serverAddr, sslServerAddr);
			syslog(LOG_ERR, "libsldap: %s", errstr);
		} else
			sslServerAddr = (char *)serverAddr;

		ld = ldapssl_init(sslServerAddr, LDAPS_PORT, 1);

		if (sslServerAddr != serverAddr)
			free(sslServerAddr);

		if (ld == NULL ||
		    ldapssl_install_gethostbyaddr(ld, "ldap") != 0) {
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: failed to connect "
				"using TLS (%s)"), strerror(errno));
			MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
				strdup(errstr), NULL);
			return (NS_LDAP_INTERNAL);
		}
	} else {
#ifdef DEBUG
		(void) fprintf(stderr, "+++Unsecure transport\n");
#endif /* DEBUG */
			/* Warning message IF cannot connect to host(s) */
		if ((ld = ldap_init((char *)serverAddr, LDAP_PORT)) == NULL) {
			char *p = strerror(errno);
			MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
				strdup(p), NULL);
			return (NS_LDAP_INTERNAL);
		} else {
			/* check and avoid gethostname recursion */
			if (ldap_in_hosts_switch() > 0 &&
				! __s_api_isipv4((char *)serverAddr) &&
				! __s_api_isipv6((char *)serverAddr)) {
				/* host: ldap - found, attempt to recover */
				if (ldap_set_option(ld, LDAP_X_OPT_DNS_SKIPDB,
						    "ldap") != 0) {
					(void) snprintf(errstr, sizeof (errstr),
						gettext("openConnection: "
						"unrecoverable gethostname "
						"recursion detected "
						"in /etc/nsswitch.conf"));
					MKERROR(LOG_WARNING, *errorp,
						LDAP_CONNECT_ERROR,
						strdup(errstr), NULL);
					(void) ldap_unbind(ld);
					return (NS_LDAP_INTERNAL);
				}
			}
		}
	}

	(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
	(void) ldap_set_option(ld, LDAP_OPT_DEREF, &derefOption);
	/*
	 * set LDAP_OPT_REFERRALS to OFF.
	 * This library will handle the referral itself
	 * based on API flags or configuration file
	 * specification. If this option is not set
	 * to OFF, libldap will never pass the
	 * referral info up to this library
	 */
	(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	(void) ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &zero);
	(void) ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &zero);
	/* setup TCP/IP connect timeout */
	(void) ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT,
							&timeoutMilliSec);
	/* retry if LDAP I/O was interrupted */
	(void) ldap_set_option(ld, LDAP_OPT_RESTART, LDAP_OPT_ON);

	switch (bindType) {
	case NS_LDAP_AUTH_NONE:
#ifdef DEBUG
		(void) fprintf(stderr, "+++Anonymous bind\n");
#endif /* DEBUG */
		break;
	case NS_LDAP_AUTH_SIMPLE:
		binddn = auth->cred.unix_cred.userID;
		passwd = auth->cred.unix_cred.passwd;
		if (passwd == NULL || *passwd == '\0' ||
		    binddn == NULL || *binddn == '\0') {
			(void) sprintf(errstr, gettext("openConnection: "
				"missing credentials for Simple bind"));
			MKERROR(LOG_WARNING, *errorp, LDAP_INVALID_CREDENTIALS,
				strdup(errstr), NULL);
			(void) ldap_unbind(ld);
			return (NS_LDAP_INTERNAL);
		}

#ifdef DEBUG
		(void) fprintf(stderr, "+++Simple bind\n");
#endif /* DEBUG */
		msgId = ldap_simple_bind(ld, binddn, passwd);

		if (msgId == -1) {
			(void) ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
				(void *)&errnum);
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: simple bind failed "
				"- %s"), ldap_err2string(errnum));
			(void) ldap_unbind(ld);
			MKERROR(LOG_WARNING, *errorp, errnum, strdup(errstr),
				NULL);
			return (NS_LDAP_INTERNAL);
		}

		tv.tv_sec = timeoutSec;
		tv.tv_usec = 0;
		rc = ldap_result(ld, msgId, 0, &tv, &resultMsg);

		if ((rc == -1) || (rc == 0)) {
			(void) ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
				(void *)&errnum);
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: simple bind failed "
				"- %s"), ldap_err2string(errnum));
			(void) ldap_msgfree(resultMsg);
			(void) ldap_unbind(ld);
			MKERROR(LOG_WARNING, *errorp, errnum, strdup(errstr),
				NULL);
			return (NS_LDAP_INTERNAL);
		}

		/*
		 * get ldaprc, controls, and error msg
		 */
		rc = ldap_parse_result(ld, resultMsg, &errnum, NULL,
				&errmsg, NULL, &controls, 1);

		if (rc != LDAP_SUCCESS) {
			(void) snprintf(errstr, sizeof (errstr),
				gettext("openConnection: simple bind failed "
				"- unable to parse result"));
			(void) ldap_unbind(ld);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
					strdup(errstr), NULL);
			return (NS_LDAP_INTERNAL);
		}

		/* process the password management info, if any */
		pwd_rc = process_pwd_mgmt("simple",
					errnum, controls, errmsg,
					errorp,
					fail_if_new_pwd_reqd,
					passwd_mgmt);

		if (pwd_rc == NS_LDAP_INTERNAL) {
			(void) ldap_unbind(ld);
			return (pwd_rc);
		}

		if (pwd_rc == NS_LDAP_SUCCESS_WITH_INFO) {
			*ldp = ld;
			return (pwd_rc);
		}

		break;
	case NS_LDAP_AUTH_SASL:
		/* We don't support any sasl options yet */
		if (auth->auth.saslopt != NS_LDAP_SASLOPT_NONE) {
			(void) sprintf(errstr,
				gettext("openConnection: SASL options are "
				"not supported (%d)"), auth->auth.saslopt);
			MKERROR(LOG_WARNING, *errorp,
				LDAP_AUTH_METHOD_NOT_SUPPORTED,
				strdup(errstr), NULL);
			(void) ldap_unbind(ld);
			return (NS_LDAP_INTERNAL);
		}
		binddn = auth->cred.unix_cred.userID;
		passwd = auth->cred.unix_cred.passwd;
		if (passwd == NULL || *passwd == '\0' ||
		    binddn == NULL || *binddn == '\0') {
			(void) sprintf(errstr,
				gettext("openConnection: missing credentials "
				"for SASL bind"));
			MKERROR(LOG_WARNING, *errorp, LDAP_INVALID_CREDENTIALS,
				strdup(errstr), NULL);
			(void) ldap_unbind(ld);
			return (NS_LDAP_INTERNAL);
		}
		cred.bv_val = passwd;
		cred.bv_len = strlen(passwd);

		switch (auth->auth.saslmech) {
		case NS_LDAP_SASL_CRAM_MD5:
			/*
			 * NOTE: if iDS changes to support cram_md5,
			 * please add password management code here.
			 * Since ldap_sasl_cram_md5_bind_s does not
			 * return anything that could be used to
			 * extract the ldap rc/errmsg/control to
			 * determine if bind failed due to password
			 * policy, a new cram_md5_bind API will need
			 * to be introduced. See
			 * ldap_x_sasl_digest_md5_bind() and case
			 * NS_LDAP_SASL_DIGEST_MD5 below for details.
			 */
			if ((rc = ldap_sasl_cram_md5_bind_s(ld, binddn,
				&cred, NULL, NULL)) != LDAP_SUCCESS) {
				(void) ldap_get_option(ld,
					LDAP_OPT_ERROR_NUMBER, (void *)&errnum);
				(void) snprintf(errstr, sizeof (errstr),
					gettext("openConnection: "
					"sasl/CRAM-MD5 bind failed - %s"),
					ldap_err2string(errnum));
				MKERROR(LOG_WARNING, *errorp, errnum,
					strdup(errstr), NULL);
				(void) ldap_unbind(ld);
				return (NS_LDAP_INTERNAL);
			}
			break;
		case NS_LDAP_SASL_DIGEST_MD5:
			digest_md5_name = malloc(strlen(binddn) + 5);
			/* 5 = strlen("dn: ") + 1 */
			if (digest_md5_name == NULL) {
				(void) ldap_unbind(ld);
				return (NS_LDAP_MEMORY);
			}
			(void) strcpy(digest_md5_name, "dn: ");
			(void) strcat(digest_md5_name, binddn);

			tv.tv_sec = timeoutSec;
			tv.tv_usec = 0;
			rc = ldap_x_sasl_digest_md5_bind(ld,
				digest_md5_name, &cred, NULL, NULL,
				&tv, &resultMsg);

			if (resultMsg == NULL) {
				free(digest_md5_name);
				(void) ldap_get_option(ld,
					LDAP_OPT_ERROR_NUMBER, (void *)&errnum);
				(void) snprintf(errstr, sizeof (errstr),
					gettext("openConnection: "
					"DIGEST-MD5 bind failed - %s"),
					ldap_err2string(errnum));
				(void) ldap_unbind(ld);
				MKERROR(LOG_WARNING, *errorp, errnum,
						strdup(errstr), NULL);
				return (NS_LDAP_INTERNAL);
			}

			/*
			 * get ldaprc, controls, and error msg
			 */
			rc = ldap_parse_result(ld, resultMsg, &errnum, NULL,
				&errmsg, NULL, &controls, 1);

			if (rc != LDAP_SUCCESS) {
				free(digest_md5_name);
				(void) snprintf(errstr, sizeof (errstr),
					gettext("openConnection: "
					"DIGEST-MD5 bind failed "
					"- unable to parse result"));
				(void) ldap_unbind(ld);
				MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
						strdup(errstr), NULL);
				return (NS_LDAP_INTERNAL);
			}

			/* process the password management info, if any */
			pwd_rc = process_pwd_mgmt("sasl/DIGEST-MD5",
						errnum, controls, errmsg,
						errorp,
						fail_if_new_pwd_reqd,
						passwd_mgmt);

			if (pwd_rc == NS_LDAP_INTERNAL) {
				free(digest_md5_name);
				(void) ldap_unbind(ld);
				return (pwd_rc);
			}

			if (pwd_rc == NS_LDAP_SUCCESS_WITH_INFO) {
				*ldp = ld;
				return (pwd_rc);
			}

			free(digest_md5_name);
			break;
		default:
			(void) ldap_unbind(ld);
			(void) sprintf(errstr,
				gettext("openConnection: unsupported SASL "
				"mechanism (%d)"), auth->auth.saslmech);
			MKERROR(LOG_WARNING, *errorp,
				LDAP_AUTH_METHOD_NOT_SUPPORTED, strdup(errstr),
				NULL);
			return (NS_LDAP_INTERNAL);
		}
	}

	*ldp = ld;
	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__s_api_getDefaultAuth
 *
 *	Constructs a credential for authentication using the config module.
 *
 * RETURN VALUES:
 *
 * NS_LDAP_SUCCESS	If successful
 * NS_LDAP_CONFIG	If there are any config errors.
 * NS_LDAP_MEMORY	Memory errors.
 * NS_LDAP_OP_FAILED	If there are no more authentication methods so can
 *			not build a new authp.
 * NS_LDAP_INVALID_PARAM This overloaded return value means that some of the
 *			necessary fields of a cred for a given auth method
 *			are not provided.
 * INPUT:
 *
 * cLevel	Currently requested credential level to be tried
 *
 * aMethod	Currently requested authentication method to be tried
 *
 * OUTPUT:
 *
 * authp		authentication method to use.
 */
static int
__s_api_getDefaultAuth(
	int	*cLevel,
	ns_auth_t *aMethod,
	ns_cred_t **authp)
{
	void		**paramVal = NULL;
	char		*modparamVal = NULL;
	int		getUid = 0;
	int		getPasswd = 0;
	int		getCertpath = 0;
	int		rc = 0;
	ns_ldap_error_t	*errorp = NULL;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getDefaultAuth START\n");
#endif

	if (aMethod == NULL) {
		/* Require an Auth */
		return (NS_LDAP_INVALID_PARAM);

	}

	/*
	 * Do not differentiate between (proxy/self) at this time, but
	 * reject self credential levels at this time
	 */
	if (cLevel && *cLevel == NS_LDAP_CRED_SELF)
		return (NS_LDAP_INVALID_PARAM);

	*authp = (ns_cred_t *)calloc(1, sizeof (ns_cred_t));
	if ((*authp) == NULL)
		return (NS_LDAP_MEMORY);

	(*authp)->auth = *aMethod;

	switch (aMethod->type) {
		case NS_LDAP_AUTH_NONE:
			return (NS_LDAP_SUCCESS);
		case NS_LDAP_AUTH_SIMPLE:
			getUid++;
			getPasswd++;
			break;
		case NS_LDAP_AUTH_SASL:
			if ((aMethod->saslmech == NS_LDAP_SASL_DIGEST_MD5) ||
			    (aMethod->saslmech == NS_LDAP_SASL_CRAM_MD5)) {
				getUid++;
				getPasswd++;
			} else {
				(void) __ns_ldap_freeCred(authp);
				*authp = NULL;
				return (NS_LDAP_INVALID_PARAM);
			}
			break;
		case NS_LDAP_AUTH_TLS:
			if ((aMethod->tlstype == NS_LDAP_TLS_SIMPLE) ||
			    ((aMethod->tlstype == NS_LDAP_TLS_SASL) &&
			    ((aMethod->saslmech == NS_LDAP_SASL_DIGEST_MD5) ||
			    (aMethod->saslmech == NS_LDAP_SASL_CRAM_MD5)))) {
				getUid++;
				getPasswd++;
				getCertpath++;
			} else if (aMethod->tlstype == NS_LDAP_TLS_NONE) {
				getCertpath++;
			} else {
				(void) __ns_ldap_freeCred(authp);
				*authp = NULL;
				return (NS_LDAP_INVALID_PARAM);
			}
			break;
	}

	if (getUid) {
		paramVal = NULL;
		if ((rc = __ns_ldap_getParam(NS_LDAP_BINDDN_P,
			&paramVal, &errorp)) != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeError(&errorp);
			*authp = NULL;
			return (rc);
		}

		if (paramVal == NULL || *paramVal == NULL) {
			(void) __ns_ldap_freeCred(authp);
			*authp = NULL;
			return (NS_LDAP_INVALID_PARAM);
		}

		(*authp)->cred.unix_cred.userID = strdup((char *)*paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
		if ((*authp)->cred.unix_cred.userID == NULL) {
			(void) __ns_ldap_freeCred(authp);
			*authp = NULL;
			return (NS_LDAP_MEMORY);
		}
	}
	if (getPasswd) {
		paramVal = NULL;
		if ((rc = __ns_ldap_getParam(NS_LDAP_BINDPASSWD_P,
			&paramVal, &errorp)) != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeError(&errorp);
			*authp = NULL;
			return (rc);
		}

		if (paramVal == NULL || *paramVal == NULL) {
			(void) __ns_ldap_freeCred(authp);
			*authp = NULL;
			return (NS_LDAP_INVALID_PARAM);
		}

		modparamVal = dvalue((char *)*paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
		if (modparamVal == NULL || (strlen((char *)modparamVal) == 0)) {
			(void) __ns_ldap_freeCred(authp);
			if (modparamVal != NULL)
				free(modparamVal);
			*authp = NULL;
			return (NS_LDAP_INVALID_PARAM);
		}

		(*authp)->cred.unix_cred.passwd = modparamVal;
	}
	if (getCertpath) {
		paramVal = NULL;
		if ((rc = __ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
			&paramVal, &errorp)) != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeError(&errorp);
			*authp = NULL;
			return (rc);
		}

		if (paramVal == NULL || *paramVal == NULL) {
			(void) __ns_ldap_freeCred(authp);
			*authp = NULL;
			return (NS_LDAP_INVALID_PARAM);
		}

		(*authp)->hostcertpath = strdup((char *)*paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
		if ((*authp)->hostcertpath == NULL) {
			(void) __ns_ldap_freeCred(authp);
			*authp = NULL;
			return (NS_LDAP_MEMORY);
		}
	}
	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__s_api_getConnection
 *
 *	Bind to the specified server or one from the server
 *	list and return the pointer.
 *
 *	This function can rebind or not (NS_LDAP_HARD), it can require a
 *	credential or bind anonymously
 *
 *	This function follows the DUA configuration schema algorithm
 *
 * RETURN VALUES:
 *
 * NS_LDAP_SUCCESS	A connection was made successfully.
 * NS_LDAP_SUCCESS_WITH_INFO
 * 			A connection was made successfully, but with
 *			password management info in *errorp
 * NS_LDAP_INVALID_PARAM If any invalid arguments were passed to the function.
 * NS_LDAP_CONFIG	If there are any config errors.
 * NS_LDAP_MEMORY	Memory errors.
 * NS_LDAP_INTERNAL	If there was a ldap error.
 *
 * INPUT:
 *
 * server	Bind to this LDAP server only
 * flags	If NS_LDAP_HARD is set function will not return until it has
 *		a connection unless there is a authentication problem.
 *		If NS_LDAP_NEW_CONN is set the function must force a new
 *              connection to be created
 *		If NS_LDAP_KEEP_CONN is set the connection is to be kept open
 * auth		Credentials for bind. This could be NULL in which case
 *		a default cred built from the config module is used.
 * sessionId	cookie that points to a previous session
 * fail_if_new_pwd_reqd
 *		a flag indicating this function should fail if the passwd
 *		in auth needs to change immediately
 * nopasswd_acct_mgmt
 *		a flag indicating that makeConnection should check before
 *		binding if server supports LDAP V3 password less
 *		account management
 *
 * OUTPUT:
 *
 * session	pointer to a session with connection information
 * errorp	Set if there are any INTERNAL, or CONFIG error.
 */
int
__s_api_getConnection(
	const char *server,
	const int flags,
	const ns_cred_t *cred,		/* credentials for bind */
	ConnectionID *sessionId,
	Connection **session,
	ns_ldap_error_t **errorp,
	int fail_if_new_pwd_reqd,
	int nopasswd_acct_mgmt)
{
	char		errmsg[MAXERROR];
	ns_auth_t	**aMethod = NULL;
	ns_auth_t	**aNext = NULL;
	int		**cLevel = NULL;
	int		**cNext = NULL;
	int		timeoutSec = NS_DEFAULT_BIND_TIMEOUT;
	int		rc;
	Connection	*con = NULL;
	int		sec = 1;
	ns_cred_t 	*authp = NULL;
	ns_cred_t	anon;
	int		version = NS_LDAP_V2;
	void		**paramVal = NULL;
	char		**badSrvrs = NULL; /* List of problem hostnames */

	if ((session == NULL) || (sessionId == NULL)) {
		return (NS_LDAP_INVALID_PARAM);
	}
	*session = NULL;

	/* if we already have a session id try to reuse connection */
	if (*sessionId > 0) {
		rc = findConnectionById(flags, cred, *sessionId, &con);
		if (rc == *sessionId && con) {
			*session = con;
			return (NS_LDAP_SUCCESS);
		}
		*sessionId = 0;
	}

	/* get profile version number */
	if ((rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P,
			&paramVal, errorp)) != NS_LDAP_SUCCESS)
		return (rc);
	if (paramVal == NULL) {
		(void) sprintf(errmsg, gettext("getConnection: no file "
			"version"));
		MKERROR(LOG_WARNING, *errorp, NS_CONFIG_FILE, strdup(errmsg),
			NS_LDAP_CONFIG);
		return (NS_LDAP_CONFIG);
	}
	if (strcasecmp((char *)*paramVal, NS_LDAP_VERSION_1) == 0)
		version = NS_LDAP_V1;
	(void) __ns_ldap_freeParam((void ***)&paramVal);

	/* Get the bind timeout value */
	(void) __ns_ldap_getParam(NS_LDAP_BIND_TIME_P, &paramVal, errorp);
	if (paramVal != NULL && *paramVal != NULL) {
		timeoutSec = **((int **)paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
	}
	if (*errorp)
		(void) __ns_ldap_freeError(errorp);

	if (cred == NULL) {
		/* Get the authentication method list */
		if ((rc = __ns_ldap_getParam(NS_LDAP_AUTH_P,
			(void ***)&aMethod, errorp)) != NS_LDAP_SUCCESS)
			return (rc);
		if (aMethod == NULL) {
			aMethod = (ns_auth_t **)calloc(2, sizeof (ns_auth_t *));
			if (aMethod == NULL)
				return (NS_LDAP_MEMORY);
			aMethod[0] = (ns_auth_t *)calloc(1, sizeof (ns_auth_t));
			if (aMethod[0] == NULL) {
				free(aMethod);
				return (NS_LDAP_MEMORY);
			}
			if (version == NS_LDAP_V1)
				(aMethod[0])->type = NS_LDAP_AUTH_SIMPLE;
			else {
				(aMethod[0])->type = NS_LDAP_AUTH_SASL;
				(aMethod[0])->saslmech =
					NS_LDAP_SASL_DIGEST_MD5;
				(aMethod[0])->saslopt = NS_LDAP_SASLOPT_NONE;
			}
		}

		/* Get the credential level list */
		if ((rc = __ns_ldap_getParam(NS_LDAP_CREDENTIAL_LEVEL_P,
			(void ***)&cLevel, errorp)) != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeParam((void ***)&aMethod);
			return (rc);
		}
		if (cLevel == NULL) {
			cLevel = (int **)calloc(2, sizeof (int *));
			if (cLevel == NULL)
				return (NS_LDAP_MEMORY);
			cLevel[0] = (int *)calloc(1, sizeof (int));
			if (cLevel[0] == NULL)
				return (NS_LDAP_MEMORY);
			if (version == NS_LDAP_V1)
				*(cLevel[0]) = NS_LDAP_CRED_PROXY;
			else
				*(cLevel[0]) = NS_LDAP_CRED_ANON;
		}
	}

	/* setup the anon credential for anonymous connection */
	(void) memset(&anon, 0, sizeof (ns_cred_t));
	anon.auth.type = NS_LDAP_AUTH_NONE;

	for (; ; ) {
		if (cred != NULL) {
			/* using specified auth method */
			rc = makeConnection(&con, server, cred,
				sessionId, timeoutSec, errorp,
				fail_if_new_pwd_reqd, nopasswd_acct_mgmt,
				&badSrvrs);
			if (rc == NS_LDAP_SUCCESS ||
				rc == NS_LDAP_SUCCESS_WITH_INFO) {
				*session = con;
				break;
			}
		} else {
			/* for every cred level */
			for (cNext = cLevel; *cNext != NULL; cNext++) {
				if (**cNext == NS_LDAP_CRED_ANON) {
					/*
					 * make connection anonymously
					 * Free the down server list before
					 * looping through
					 */
					if (badSrvrs && *badSrvrs) {
						__s_api_free2dArray(badSrvrs);
						badSrvrs = NULL;
					}
					rc = makeConnection(&con, server, &anon,
						sessionId, timeoutSec, errorp,
						fail_if_new_pwd_reqd,
						nopasswd_acct_mgmt, &badSrvrs);
					if (rc == NS_LDAP_SUCCESS ||
						rc ==
						NS_LDAP_SUCCESS_WITH_INFO) {
						*session = con;
						goto done;
					}
					continue;
				}
				/* for each cred level */
				for (aNext = aMethod; *aNext != NULL; aNext++) {
					/* make connection and authenticate */
					/* with default credentials */
					authp = NULL;
					rc = __s_api_getDefaultAuth(*cNext,
						*aNext, &authp);
					if (rc != NS_LDAP_SUCCESS) {
						continue;
					}
					/*
					 * Free the down server list before
					 * looping through
					 */
					if (badSrvrs && *badSrvrs) {
						__s_api_free2dArray(badSrvrs);
						badSrvrs = NULL;
					}
					rc = makeConnection(&con, server, authp,
						sessionId, timeoutSec, errorp,
						fail_if_new_pwd_reqd,
						nopasswd_acct_mgmt, &badSrvrs);
					(void) __ns_ldap_freeCred(&authp);
					if (rc == NS_LDAP_SUCCESS ||
						rc ==
						NS_LDAP_SUCCESS_WITH_INFO) {
						*session = con;
						goto done;
					}
				}
			}
		}
		if (flags & NS_LDAP_HARD) {
			if (sec < LDAPMAXHARDLOOKUPTIME)
				sec *= 2;
			_sleep(sec);
		} else {
			break;
		}
	}

done:
	(void) __ns_ldap_freeParam((void ***)&aMethod);
	(void) __ns_ldap_freeParam((void ***)&cLevel);

	if (badSrvrs && *badSrvrs) {
		/*
		 * At this point, either we have a successful
		 * connection or exhausted all the possible auths.
		 * and creds. Mark the problem servers as down
		 * so that the problem servers are not contacted
		 * again until the refresh_ttl expires.
		 */
		(void) __s_api_removeBadServers(badSrvrs);
		__s_api_free2dArray(badSrvrs);
	}
	return (rc);
}

#pragma fini(_free_sessionPool)
static void
_free_sessionPool()
{
	int id;

	(void) mutex_lock(&sessionPoolLock);
	if (sessionPool != NULL) {
		for (id = 0; id < sessionPoolSize; id++)
			_DropConnection(id + CONID_OFFSET, 0, 1);
		free(sessionPool);
		sessionPool = NULL;
		sessionPoolSize = 0;
	}
	(void) mutex_unlock(&sessionPoolLock);
}
