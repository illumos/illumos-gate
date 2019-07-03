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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

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
#include "solaris-int.h"
#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "ns_connmgmt.h"
#include "ldappr.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <procfs.h>
#include <unistd.h>

#define	USE_DEFAULT_PORT 0

static ns_ldap_return_code performBind(const ns_cred_t *,
					LDAP *,
					int,
					ns_ldap_error_t **,
					int,
					int);
static ns_ldap_return_code createSession(const ns_cred_t *,
					const char *,
					uint16_t,
					int,
					LDAP **,
					ns_ldap_error_t **);

extern int ldap_sasl_cram_md5_bind_s(LDAP *, char *, struct berval *,
		LDAPControl **, LDAPControl **);
extern int ldapssl_install_gethostbyaddr(LDAP *ld, const char *skip);

extern int __door_getconf(char **buffer, int *buflen,
		ns_ldap_error_t **error, int callnumber);
extern int __ns_ldap_freeUnixCred(UnixCred_t **credp);
extern int SetDoorInfoToUnixCred(char *buffer,
		ns_ldap_error_t **errorp,
		UnixCred_t **cred);

static int openConnection(LDAP **, const char *, const ns_cred_t *,
		int, ns_ldap_error_t **, int, int, ns_conn_user_t *, int);
static void
_DropConnection(ConnectionID cID, int flag, int fini);

static mutex_t sessionPoolLock = DEFAULTMUTEX;

static Connection **sessionPool = NULL;
static int sessionPoolSize = 0;

/*
 * SSF values are for SASL integrity & privacy.
 * JES DS5.2 does not support this feature but DS6 does.
 * The values between 0 and 65535 can work with both server versions.
 */
#define	MAX_SASL_SSF	65535
#define	MIN_SASL_SSF	0

/* Number of hostnames to allocate memory for */
#define	NUMTOMALLOC	32

/*
 * This function get the servers from the lists and returns
 * the first server with the empty lists of server controls and
 * SASL mechanisms. It is invoked if it is not possible to obtain a server
 * from ldap_cachemgr or the local list.
 */
static
ns_ldap_return_code
getFirstFromConfig(ns_server_info_t *ret, ns_ldap_error_t **error)
{
	char			**servers = NULL;
	ns_ldap_return_code	ret_code;
	char			errstr[MAXERROR];

	/* get first server from config list unavailable otherwise */
	ret_code = __s_api_getServers(&servers, error);
	if (ret_code != NS_LDAP_SUCCESS) {
		if (servers != NULL) {
			__s_api_free2dArray(servers);
		}
		return (ret_code);
	}

	if (servers == NULL || servers[0] == NULL) {
		__s_api_free2dArray(servers);
		(void) sprintf(errstr,
		    gettext("No server found in configuration"));
		MKERROR(LOG_ERR, *error, NS_CONFIG_NODEFAULT,
		    strdup(errstr), NS_LDAP_MEMORY);
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

	return (NS_LDAP_SUCCESS);
}

/* very similar to __door_getldapconfig() in ns_config.c */
static int
__door_getadmincred(char **buffer, int *buflen, ns_ldap_error_t **error)
{
	return (__door_getconf(buffer, buflen, error, GETADMINCRED));
}

/*
 * This function requests Admin credentials from the cache manager through
 * the door functionality
 */

static int
requestAdminCred(UnixCred_t **cred, ns_ldap_error_t **error)
{
	char	*buffer = NULL;
	int	buflen = 0;
	int	ret;

	*error = NULL;
	ret = __door_getadmincred(&buffer, &buflen, error);

	if (ret != NS_LDAP_SUCCESS) {
		if (*error != NULL && (*error)->message != NULL)
			syslog(LOG_WARNING, "libsldap: %s", (*error)->message);
		return (ret);
	}

	/* now convert from door format */
	ret = SetDoorInfoToUnixCred(buffer, error, cred);
	free(buffer);

	return (ret);
}

/*
 * This function requests a server from the cache manager through
 * the door functionality
 */

int
__s_api_requestServer(const char *request, const char *server,
	ns_server_info_t *ret, ns_ldap_error_t **error,  const char *addrType)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;
	ldap_data_t		*sptr;
	int			ndata;
	int			adata;
	char			errstr[MAXERROR];
	const char		*ireq;
	char			*rbuf, *ptr, *rest;
	char			*dptr;
	char			**mptr, **mptr1, **cptr, **cptr1;
	int			mcnt, ccnt;
	int			len;
	ns_ldap_return_code	ret_code;

	if (ret == NULL || error == NULL) {
		return (NS_LDAP_OP_FAILED);
	}
	(void) memset(ret, 0, sizeof (ns_server_info_t));
	*error = NULL;

	if (request == NULL)
		ireq = NS_CACHE_NEW;
	else
		ireq = request;

	/*
	 * In the 'Standalone' mode a server will be obtained
	 * from the local libsldap's list
	 */
	if (__s_api_isStandalone()) {
		if ((ret_code = __s_api_findRootDSE(ireq,
		    server,
		    addrType,
		    ret,
		    error)) != NS_LDAP_SUCCESS) {
			/*
			 * get first server from local list only once
			 * to prevent looping
			 */
			if (strcmp(ireq, NS_CACHE_NEW) != 0)
				return (ret_code);

			syslog(LOG_WARNING,
			    "libsldap (\"standalone\" mode): "
			    "can not find any available server. "
			    "Return the first one from the lists");
			if (*error != NULL) {
				(void) __ns_ldap_freeError(error);
			}

			ret_code = getFirstFromConfig(ret, error);
			if (ret_code != NS_LDAP_SUCCESS) {
				return (ret_code);
			}

			if (strcmp(addrType, NS_CACHE_ADDR_HOSTNAME) == 0) {
				ret_code = __s_api_ip2hostname(ret->server,
				    &ret->serverFQDN);
				if (ret_code != NS_LDAP_SUCCESS) {
					(void) snprintf(errstr,
					    sizeof (errstr),
					    gettext("The %s address "
					    "can not be resolved into "
					    "a host name. Returning "
					    "the address as it is."),
					    ret->server);
					MKERROR(LOG_ERR,
					    *error,
					    NS_CONFIG_NOTLOADED,
					    strdup(errstr),
					    NS_LDAP_MEMORY);
					free(ret->server);
					ret->server = NULL;
					return (NS_LDAP_INTERNAL);
				}
			}
		}

		return (NS_LDAP_SUCCESS);
	}

	(void) memset(space.s_b, 0, DOORBUFFERSIZE);

	adata = (sizeof (ldap_call_t) + strlen(ireq) + strlen(addrType) + 1);
	if (server != NULL) {
		adata += strlen(DOORLINESEP) + 1;
		adata += strlen(server) + 1;
	}
	ndata = sizeof (space);
	len = sizeof (space) - sizeof (space.s_d.ldap_call.ldap_callnumber);
	space.s_d.ldap_call.ldap_callnumber = GETLDAPSERVER;
	if (strlcpy(space.s_d.ldap_call.ldap_u.domainname, ireq, len) >= len)
		return (NS_LDAP_MEMORY);
	if (strlcat(space.s_d.ldap_call.ldap_u.domainname, addrType, len) >=
	    len)
		return (NS_LDAP_MEMORY);
	if (server != NULL) {
		if (strlcat(space.s_d.ldap_call.ldap_u.domainname,
		    DOORLINESEP, len) >= len)
			return (NS_LDAP_MEMORY);
		if (strlcat(space.s_d.ldap_call.ldap_u.domainname, server,
		    len) >= len)
			return (NS_LDAP_MEMORY);
	}
	sptr = &space.s_d;

	switch (__ns_ldap_trydoorcall(&sptr, &ndata, &adata)) {
	case NS_CACHE_SUCCESS:
		break;
	/* this case is for when the $mgr is not running, but ldapclient */
	/* is trying to initialize things */
	case NS_CACHE_NOSERVER:
		ret_code = getFirstFromConfig(ret, error);
		if (ret_code != NS_LDAP_SUCCESS) {
			return (ret_code);
		}

		if (strcmp(addrType, NS_CACHE_ADDR_HOSTNAME) == 0) {
			ret_code = __s_api_ip2hostname(ret->server,
			    &ret->serverFQDN);
			if (ret_code != NS_LDAP_SUCCESS) {
				(void) snprintf(errstr,
				    sizeof (errstr),
				    gettext("The %s address "
				    "can not be resolved into "
				    "a host name. Returning "
				    "the address as it is."),
				    ret->server);
				MKERROR(LOG_ERR,
				    *error,
				    NS_CONFIG_NOTLOADED,
				    strdup(errstr),
				    NS_LDAP_MEMORY);
				free(ret->server);
				ret->server = NULL;
				return (NS_LDAP_INTERNAL);
			}
		}
		return (NS_LDAP_SUCCESS);
	case NS_CACHE_NOTFOUND:
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
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_OP_FAILED);
	}
	ret->server = strdup(ptr);
	if (ret->server == NULL) {
		return (NS_LDAP_MEMORY);
	}
	/* Get the host FQDN format */
	if (strcmp(addrType, NS_CACHE_ADDR_HOSTNAME) == 0) {
		ptr = strtok_r(NULL, DOORLINESEP, &rest);
		if (ptr == NULL) {
			(void) sprintf(errstr, gettext("No server FQDN format "
			    "returned from ldap_cachemgr"));
			MKERROR(LOG_WARNING, *error, NS_CONFIG_CACHEMGR,
			    strdup(errstr), NS_LDAP_MEMORY);
			free(ret->server);
			ret->server = NULL;
			return (NS_LDAP_OP_FAILED);
		}
		ret->serverFQDN = strdup(ptr);
		if (ret->serverFQDN == NULL) {
			free(ret->server);
			ret->server = NULL;
			return (NS_LDAP_MEMORY);
		}
	}

	/* get the Supported Controls/SASL mechs */
	mptr = NULL;
	mcnt = 0;
	cptr = NULL;
	ccnt = 0;
	for (;;) {
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
				__s_api_free_server_info(ret);
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
				__s_api_free_server_info(ret);
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
				__s_api_free_server_info(ret);
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
				__s_api_free_server_info(ret);
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
	thread_t	t = thr_self();

	if (cred == NULL) {
		(void) fprintf(fp, "tid= %d: printCred: cred is NULL\n", t);
		return;
	}

	(void) fprintf(fp, "tid= %d: AuthType=%d\n", t, cred->auth.type);
	(void) fprintf(fp, "tid= %d: TlsType=%d\n", t, cred->auth.tlstype);
	(void) fprintf(fp, "tid= %d: SaslMech=%d\n", t, cred->auth.saslmech);
	(void) fprintf(fp, "tid= %d: SaslOpt=%d\n", t, cred->auth.saslopt);
	if (cred->hostcertpath)
		(void) fprintf(fp, "tid= %d: hostCertPath=%s\n",
		    t, cred->hostcertpath);
	if (cred->cred.unix_cred.userID)
		(void) fprintf(fp, "tid= %d: userID=%s\n",
		    t, cred->cred.unix_cred.userID);
	if (cred->cred.unix_cred.passwd)
		(void) fprintf(fp, "tid= %d: passwd=%s\n",
		    t, cred->cred.unix_cred.passwd);
}

/*
 * printConnection(): prints the connection structure
 */
static void
printConnection(FILE *fp, Connection *con)
{
	thread_t	t = thr_self();

	if (con == NULL)
		return;

	(void) fprintf(fp, "tid= %d: connectionID=%d\n", t, con->connectionId);
	(void) fprintf(fp, "tid= %d: usedBit=%d\n", t, con->usedBit);
	(void) fprintf(fp, "tid= %d: threadID=%d\n", t, con->threadID);
	if (con->serverAddr) {
		(void) fprintf(fp, "tid= %d: serverAddr=%s\n",
		    t, con->serverAddr);
	}
	printCred(fp, con->auth);
}
#endif

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
		    sizeof (Connection *));
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
		    SESSION_CACHE_INC * sizeof (Connection *));
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
 * findConnection(): find an available connection from the list
 * that matches the criteria specified in Connection structure.
 * If serverAddr is NULL, then find a connection to any server
 * as long as it matches the rest of the parameters.
 * Returns: -1 = failure, the Connection ID found = success.
 */
static int
findConnection(int flags, const char *serverAddr,
	const ns_cred_t *auth, Connection **conp)
{
	Connection *cp;
	int i;
#ifdef DEBUG
	thread_t t;
#endif /* DEBUG */

	if (auth == NULL || conp == NULL)
		return (-1);
	*conp = NULL;

	/*
	 * If a new connection is requested, no need to continue.
	 * If the process is not nscd and is not requesting keep
	 * connections alive, no need to continue.
	 */
	if ((flags & NS_LDAP_NEW_CONN) || (!__s_api_nscd_proc() &&
	    !__s_api_peruser_proc() && !(flags & NS_LDAP_KEEP_CONN)))
		return (-1);

#ifdef DEBUG
	t = thr_self();
	(void) fprintf(stderr, "tid= %d: Find connection\n", t);
	(void) fprintf(stderr, "tid= %d: Looking for ....\n", t);
	if (serverAddr && *serverAddr)
		(void) fprintf(stderr, "tid= %d: serverAddr=%s\n",
		    t, serverAddr);
	else
		(void) fprintf(stderr, "tid= %d: serverAddr=NULL\n", t);
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
		(void) fprintf(stderr,
		    "tid: %d: checking connection [%d] ....\n", t, i);
		printConnection(stderr, cp);
#endif /* DEBUG */
		if ((cp->usedBit) || (serverAddr && *serverAddr &&
		    (strcasecmp(serverAddr, cp->serverAddr) != 0)))
			continue;

		if (__s_api_is_auth_matched(cp->auth, auth) == B_FALSE)
			continue;

		/* found an available connection */
		cp->usedBit = B_TRUE;
		(void) mutex_unlock(&sessionPoolLock);
		cp->threadID = thr_self();
		*conp = cp;
#ifdef DEBUG
		(void) fprintf(stderr,
		    "tid %d: Connection found cID=%d\n", t, i);
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
void
__s_api_freeConnection(Connection *con)
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
	int nopasswd_acct_mgmt, int flags, char ***badsrvrs,
	ns_conn_user_t *conn_user)
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
	short	memerr = 0; /* Variable for tracking memory allocation */
	char *serverAddrType = NULL, **bindHost = NULL;


	if (conp == NULL || errorp == NULL || auth == NULL)
		return (NS_LDAP_INVALID_PARAM);
	if (*errorp)
		(void) __ns_ldap_freeError(errorp);
	*conp = NULL;
	(void) memset(&sinfo, 0, sizeof (sinfo));

	if ((id = findConnection(flags, serverAddr, auth, &con)) != -1) {
		/* connection found in cache */
#ifdef DEBUG
		(void) fprintf(stderr, "tid= %d: connection found in "
		    "cache %d\n", thr_self(), id);
		fflush(stderr);
#endif /* DEBUG */
		*cID = id;
		*conp = con;
		return (NS_LDAP_SUCCESS);
	}

	if (auth->auth.saslmech == NS_LDAP_SASL_GSSAPI) {
		serverAddrType = NS_CACHE_ADDR_HOSTNAME;
		bindHost = &sinfo.serverFQDN;
	} else {
		serverAddrType = NS_CACHE_ADDR_IP;
		bindHost = &sinfo.server;
	}

	if (serverAddr) {
		if (__s_api_isInitializing()) {
			/*
			 * When obtaining the root DSE, connect to the server
			 * passed here through the serverAddr parameter
			 */
			sinfo.server = strdup(serverAddr);
			if (sinfo.server == NULL)
				return (NS_LDAP_MEMORY);
			if (strcmp(serverAddrType,
			    NS_CACHE_ADDR_HOSTNAME) == 0) {
				rc = __s_api_ip2hostname(sinfo.server,
				    &sinfo.serverFQDN);
				if (rc != NS_LDAP_SUCCESS) {
					(void) snprintf(errmsg,
					    sizeof (errmsg),
					    gettext("The %s address "
					    "can not be resolved into "
					    "a host name. Returning "
					    "the address as it is."),
					    serverAddr);
					MKERROR(LOG_ERR,
					    *errorp,
					    NS_CONFIG_NOTLOADED,
					    strdup(errmsg),
					    NS_LDAP_MEMORY);
					__s_api_free_server_info(&sinfo);
					return (NS_LDAP_INTERNAL);
				}
			}
		} else {
			/*
			 * We're given the server address, just use it.
			 * In case of sasl/GSSAPI, serverAddr would need
			 * to be a FQDN.  We assume this is the case for now.
			 *
			 * Only the server address fields of sinfo structure
			 * are filled in since these are the only relevant
			 * data that we have. Other fields of this structure
			 * (controls, saslMechanisms) are kept to NULL.
			 */
			sinfo.server = strdup(serverAddr);
			if (sinfo.server == NULL)  {
				return (NS_LDAP_MEMORY);
			}
			if (auth->auth.saslmech == NS_LDAP_SASL_GSSAPI) {
				sinfo.serverFQDN = strdup(serverAddr);
				if (sinfo.serverFQDN == NULL) {
					free(sinfo.server);
					return (NS_LDAP_MEMORY);
				}
			}
		}
		rc = openConnection(&ld, *bindHost, auth, timeoutSec, errorp,
		    fail_if_new_pwd_reqd, passwd_mgmt, conn_user, flags);
		if (rc == NS_LDAP_SUCCESS || rc ==
		    NS_LDAP_SUCCESS_WITH_INFO) {
			exit_rc = rc;
			goto create_con;
		} else {
			if (auth->auth.saslmech == NS_LDAP_SASL_GSSAPI) {
				(void) snprintf(errmsg, sizeof (errmsg),
				    "%s %s", gettext("makeConnection: "
				    "failed to open connection using "
				    "sasl/GSSAPI to"), *bindHost);
			} else {
				(void) snprintf(errmsg, sizeof (errmsg),
				    "%s %s", gettext("makeConnection: "
				    "failed to open connection to"),
				    *bindHost);
			}
			syslog(LOG_ERR, "libsldap: %s", errmsg);
			__s_api_free_server_info(&sinfo);
			return (rc);
		}
	}

	/* No cached connection, create one */
	for (; ; ) {
		if (host == NULL)
			hReq = NS_CACHE_NEW;
		else
			hReq = NS_CACHE_NEXT;
		rc = __s_api_requestServer(hReq, host, &sinfo, errorp,
		    serverAddrType);
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

			__s_api_free_server_info(&sinfo);
			if (host)
				free(host);
			return (NS_LDAP_OP_FAILED);
		}
		if (host)
			free(host);
		host = strdup(sinfo.server);
		if (host == NULL) {
			__s_api_free_server_info(&sinfo);
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
			__s_api_free_server_info(&sinfo);
			return (NS_LDAP_OP_FAILED);
		}
		/* make the connection */
		rc = openConnection(&ld, *bindHost, auth, timeoutSec, errorp,
		    fail_if_new_pwd_reqd, passwd_mgmt, conn_user, flags);
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
					if (!(tmpptr = (char **)realloc(
					    *badsrvrs,
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
		__s_api_free_server_info(&sinfo);

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
		__s_api_free_server_info(&sinfo);
		/*
		 * If password control attached in **errorp,
		 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
		 * free the error structure
		 */
		if (*errorp) {
			(void) __ns_ldap_freeError(errorp);
			*errorp = NULL;
		}
		(void) ldap_unbind(ld);
		return (NS_LDAP_MEMORY);
	}

	con->serverAddr = sinfo.server; /* Store original format */
	if (sinfo.serverFQDN != NULL) {
		free(sinfo.serverFQDN);
		sinfo.serverFQDN = NULL;
	}
	con->saslMechanisms = sinfo.saslMechanisms;
	con->controls = sinfo.controls;

	con->auth = __ns_ldap_dupAuth(auth);
	if (con->auth == NULL) {
		(void) ldap_unbind(ld);
		__s_api_freeConnection(con);
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
	con->pid = getpid();

	con->ld = ld;
	/* add MT connection to the MT connection pool */
	if (conn_user != NULL && conn_user->conn_mt != NULL) {
		if (__s_api_conn_mt_add(con, conn_user, errorp) ==
		    NS_LDAP_SUCCESS) {
			*conp = con;
			return (exit_rc);
		} else {
			(void) ldap_unbind(ld);
			__s_api_freeConnection(con);
			return ((*errorp)->status);
		}
	}

	/* MT connection not supported or not required case */
	if ((id = addConnection(con)) == -1) {
		(void) ldap_unbind(ld);
		__s_api_freeConnection(con);
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
	(void) fprintf(stderr, "tid= %d: connection added into "
	    "cache %d\n", thr_self(), id);
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
	struct timeval	zerotime;
	LDAPMessage	*res;

	zerotime.tv_sec = zerotime.tv_usec = 0L;

	id = cID - CONID_OFFSET;
	if (id < 0 || id >= sessionPoolSize)
		return;
#ifdef DEBUG
	(void) fprintf(stderr,
	    "tid %d: Dropping connection cID=%d flag=0x%x\n",
	    thr_self(), cID, flag);
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
	    ((flag & NS_LDAP_KEEP_CONN) || __s_api_nscd_proc() ||
	    __s_api_peruser_proc())) {
		/* release Connection (keep alive) */
		cp->usedBit = B_FALSE;
		cp->threadID = 0;	/* unmark the threadID */
		/*
		 * Do sanity cleanup of remaining results.
		 */
		while (ldap_result(cp->ld, LDAP_RES_ANY, LDAP_MSG_ALL,
		    &zerotime, &res) > 0) {
			if (res != NULL)
				(void) ldap_msgfree(res);
		}
		if (use_mutex)
			(void) mutex_unlock(&sessionPoolLock);
	} else {
		/* delete Connection (disconnect) */
		sessionPool[id] = NULL;
		if (use_mutex)
			(void) mutex_unlock(&sessionPoolLock);
		(void) ldap_unbind(cp->ld);
		__s_api_freeConnection(cp);
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
			    pwd_status, 0, NS_LDAP_MEMORY);
		} else {
			MKERROR(LOG_ERR, *errorp, ldaprc, strdup(errstr),
			    NS_LDAP_MEMORY);
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
					    NS_LDAP_MEMORY);
					exit_rc = NS_LDAP_INTERNAL;
				} else {
					MKERROR_PWD_MGMT(*errorp,
					    LDAP_SUCCESS,
					    NULL,
					    pwd_status,
					    0,
					    NS_LDAP_MEMORY);
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
				    NS_LDAP_MEMORY);
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
ldap_in_nss_switch(char *db)
{
	enum __nsw_parse_err		pserr;
	struct __nsw_switchconfig	*conf;
	struct __nsw_lookup		*lkp;
	const char			*name;
	int				found = 0;

	conf = __nsw_getconfig(db, &pserr);
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
	(void) __nsw_freeconfig(conf);
	return (found);
}

static int
openConnection(LDAP **ldp, const char *serverAddr, const ns_cred_t *auth,
	int timeoutSec, ns_ldap_error_t **errorp,
	int fail_if_new_pwd_reqd, int passwd_mgmt,
	ns_conn_user_t *conn_user, int flags)
{
	LDAP			*ld = NULL;
	int			ldapVersion = LDAP_VERSION3;
	int			derefOption = LDAP_DEREF_ALWAYS;
	int			zero = 0;
	int			timeoutMilliSec = timeoutSec * 1000;
	uint16_t		port = USE_DEFAULT_PORT;
	char			*s;
	char			errstr[MAXERROR];
	int			followRef;

	ns_ldap_return_code	ret_code = NS_LDAP_SUCCESS;

	*errorp = NULL;
	*ldp = NULL;

	/* determine if the host name contains a port number */
	s = strchr(serverAddr, ']');	/* skip over ipv6 addr */
	s = strchr(s != NULL ? s : serverAddr, ':');
	if (s != NULL) {
		if (sscanf(s + 1, "%hu", &port) != 1) {
			(void) snprintf(errstr,
			    sizeof (errstr),
			    gettext("openConnection: cannot "
			    "convert %s into a valid "
			    "port number for the "
			    "%s server. A default value "
			    "will be used."),
			    s,
			    serverAddr);
			syslog(LOG_ERR, "libsldap: %s", errstr);
		} else {
			*s = '\0';
		}
	}

	ret_code = createSession(auth,
	    serverAddr,
	    port,
	    timeoutMilliSec,
	    &ld,
	    errorp);
	if (s != NULL) {
		*s = ':';
	}
	if (ret_code != NS_LDAP_SUCCESS) {
		return (ret_code);
	}

	/* check to see if the underlying libsldap supports MT connection */
	if (conn_user != NULL) {
		int rc;

		rc = __s_api_check_libldap_MT_conn_support(conn_user, ld,
		    errorp);
		if (rc != NS_LDAP_SUCCESS) {
			(void) ldap_unbind(ld);
			return (rc);
		}
	}

	(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
	(void) ldap_set_option(ld, LDAP_OPT_DEREF, &derefOption);
	/*
	 * This library will handle the referral itself based on API flags or
	 * configuration file specification. The LDAP bind operation is an
	 * exception where we rely on the LDAP library to follow the referal.
	 *
	 * The LDAP follow referral option must be set to OFF for the libldap5
	 * to pass the referral info up to this library. This option MUST be
	 * set to OFF after we have performed a sucessful bind. If we are not
	 * to follow referrals we MUST also set the LDAP follow referral option
	 * to OFF before we perform an LDAP bind.
	 */
	ret_code = __s_api_toFollowReferrals(flags, &followRef, errorp);
	if (ret_code != NS_LDAP_SUCCESS) {
		(void) ldap_unbind(ld);
		return (ret_code);
	}

	if (followRef)
		(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON);
	else
		(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

	(void) ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &zero);
	(void) ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &zero);
	/* setup TCP/IP connect timeout */
	(void) ldap_set_option(ld, LDAP_X_OPT_CONNECT_TIMEOUT,
	    &timeoutMilliSec);
	/* retry if LDAP I/O was interrupted */
	(void) ldap_set_option(ld, LDAP_OPT_RESTART, LDAP_OPT_ON);

	ret_code = performBind(auth,
	    ld,
	    timeoutSec,
	    errorp,
	    fail_if_new_pwd_reqd,
	    passwd_mgmt);

	if (ret_code == NS_LDAP_SUCCESS ||
	    ret_code == NS_LDAP_SUCCESS_WITH_INFO) {
		/*
		 * Turn off LDAP referral following so that this library can
		 * process referrals.
		 */
		(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
		*ldp = ld;
	}

	return (ret_code);
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
 * getAdmin	If non 0,  get Admin -i.e., not proxyAgent- DN and password
 *
 * OUTPUT:
 *
 * authp		authentication method to use.
 */
static int
__s_api_getDefaultAuth(
	int	*cLevel,
	ns_auth_t *aMethod,
	ns_cred_t **authp,
	int	getAdmin)
{
	void		**paramVal = NULL;
	char		*modparamVal = NULL;
	int		getUid = 0;
	int		getPasswd = 0;
	int		getCertpath = 0;
	int		rc = 0;
	ns_ldap_error_t	*errorp = NULL;
	UnixCred_t	*AdminCred = NULL;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getDefaultAuth START\n");
#endif

	if (aMethod == NULL) {
		/* Require an Auth */
		return (NS_LDAP_INVALID_PARAM);

	}
	/*
	 * credential level "self" can work with auth method sasl/GSSAPI only
	 */
	if (cLevel && *cLevel == NS_LDAP_CRED_SELF &&
	    aMethod->saslmech != NS_LDAP_SASL_GSSAPI)
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
			} else if (aMethod->saslmech != NS_LDAP_SASL_GSSAPI) {
				(void) __ns_ldap_freeCred(authp);
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
				return (NS_LDAP_INVALID_PARAM);
			}
			break;
	}

	if (getUid) {
		paramVal = NULL;
		if (getAdmin) {
			/*
			 * Assume AdminCred has been retrieved from
			 * ldap_cachemgr already. It will not work
			 * without userID or password. Flags getUid
			 * and getPasswd should always be set
			 * together.
			 */
			AdminCred = calloc(1, sizeof (UnixCred_t));
			if (AdminCred == NULL) {
				(void) __ns_ldap_freeCred(authp);
				return (NS_LDAP_MEMORY);
			}

			rc = requestAdminCred(&AdminCred, &errorp);
			if (rc != NS_LDAP_SUCCESS) {
				(void) __ns_ldap_freeCred(authp);
				(void) __ns_ldap_freeUnixCred(&AdminCred);
				(void) __ns_ldap_freeError(&errorp);
				return (rc);
			}

			if (AdminCred->userID == NULL) {
				(void) __ns_ldap_freeCred(authp);
				(void) __ns_ldap_freeUnixCred(&AdminCred);
				return (NS_LDAP_INVALID_PARAM);
			}
			(*authp)->cred.unix_cred.userID = AdminCred->userID;
			AdminCred->userID = NULL;
		} else {
			rc = __ns_ldap_getParam(NS_LDAP_BINDDN_P,
			    &paramVal, &errorp);
			if (rc != NS_LDAP_SUCCESS) {
				(void) __ns_ldap_freeCred(authp);
				(void) __ns_ldap_freeError(&errorp);
				return (rc);
			}

			if (paramVal == NULL || *paramVal == NULL) {
				(void) __ns_ldap_freeCred(authp);
				return (NS_LDAP_INVALID_PARAM);
			}

			(*authp)->cred.unix_cred.userID =
			    strdup((char *)*paramVal);
			(void) __ns_ldap_freeParam(&paramVal);
		}
		if ((*authp)->cred.unix_cred.userID == NULL) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeUnixCred(&AdminCred);
			return (NS_LDAP_MEMORY);
		}
	}
	if (getPasswd) {
		paramVal = NULL;
		if (getAdmin) {
			/*
			 * Assume AdminCred has been retrieved from
			 * ldap_cachemgr already. It will not work
			 * without the userID anyway because for
			 * getting admin credential, flags getUid
			 * and getPasswd should always be set
			 * together.
			 */
			if (AdminCred == NULL || AdminCred->passwd == NULL) {
				(void) __ns_ldap_freeCred(authp);
				(void) __ns_ldap_freeUnixCred(&AdminCred);
				return (NS_LDAP_INVALID_PARAM);
			}
			modparamVal = dvalue(AdminCred->passwd);
		} else {
			rc = __ns_ldap_getParam(NS_LDAP_BINDPASSWD_P,
			    &paramVal, &errorp);
			if (rc != NS_LDAP_SUCCESS) {
				(void) __ns_ldap_freeCred(authp);
				(void) __ns_ldap_freeError(&errorp);
				return (rc);
			}

			if (paramVal == NULL || *paramVal == NULL) {
				(void) __ns_ldap_freeCred(authp);
				return (NS_LDAP_INVALID_PARAM);
			}

			modparamVal = dvalue((char *)*paramVal);
			(void) __ns_ldap_freeParam(&paramVal);
		}

		if (modparamVal == NULL || (strlen((char *)modparamVal) == 0)) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeUnixCred(&AdminCred);
			if (modparamVal != NULL)
				free(modparamVal);
			return (NS_LDAP_INVALID_PARAM);
		}

		(*authp)->cred.unix_cred.passwd = modparamVal;
	}
	if (getCertpath) {
		paramVal = NULL;
		if ((rc = __ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
		    &paramVal, &errorp)) != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeUnixCred(&AdminCred);
			(void) __ns_ldap_freeError(&errorp);
			*authp = NULL;
			return (rc);
		}

		if (paramVal == NULL || *paramVal == NULL) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeUnixCred(&AdminCred);
			*authp = NULL;
			return (NS_LDAP_INVALID_PARAM);
		}

		(*authp)->hostcertpath = strdup((char *)*paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
		if ((*authp)->hostcertpath == NULL) {
			(void) __ns_ldap_freeCred(authp);
			(void) __ns_ldap_freeUnixCred(&AdminCred);
			*authp = NULL;
			return (NS_LDAP_MEMORY);
		}
	}
	(void) __ns_ldap_freeUnixCred(&AdminCred);
	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	getConnection
 *
 *	internal version of __s_api_getConnection()
 */
static int
getConnection(
	const char *server,
	const int flags,
	const ns_cred_t *cred,		/* credentials for bind */
	ConnectionID *sessionId,
	Connection **session,
	ns_ldap_error_t **errorp,
	int fail_if_new_pwd_reqd,
	int nopasswd_acct_mgmt,
	ns_conn_user_t *conn_user)
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
	int		version = NS_LDAP_V2, self_gssapi_only = 0;
	void		**paramVal = NULL;
	char		**badSrvrs = NULL; /* List of problem hostnames */

	if ((session == NULL) || (sessionId == NULL)) {
		return (NS_LDAP_INVALID_PARAM);
	}
	*session = NULL;

	/* reuse MT connection if needed and if available */
	if (conn_user != NULL) {
		rc = __s_api_conn_mt_get(server, flags, cred, session, errorp,
		    conn_user);
		if (rc != NS_LDAP_NOTFOUND)
			return (rc);
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

	for (;;) {
		if (cred != NULL) {
			/* using specified auth method */
			rc = makeConnection(&con, server, cred,
			    sessionId, timeoutSec, errorp,
			    fail_if_new_pwd_reqd,
			    nopasswd_acct_mgmt, flags, &badSrvrs, conn_user);
			/* not using bad server if credentials were supplied */
			if (badSrvrs && *badSrvrs) {
				__s_api_free2dArray(badSrvrs);
				badSrvrs = NULL;
			}
			if (rc == NS_LDAP_SUCCESS ||
			    rc == NS_LDAP_SUCCESS_WITH_INFO) {
				*session = con;
				break;
			}
		} else {
			self_gssapi_only = __s_api_self_gssapi_only_get();
			/* for every cred level */
			for (cNext = cLevel; *cNext != NULL; cNext++) {
				if (self_gssapi_only &&
				    **cNext != NS_LDAP_CRED_SELF)
					continue;
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
					    nopasswd_acct_mgmt, flags,
					    &badSrvrs, conn_user);
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
					if (self_gssapi_only &&
					    (*aNext)->saslmech !=
					    NS_LDAP_SASL_GSSAPI)
						continue;
					/*
					 * self coexists with sasl/GSSAPI only
					 * and non-self coexists with non-gssapi
					 * only
					 */
					if ((**cNext == NS_LDAP_CRED_SELF &&
					    (*aNext)->saslmech !=
					    NS_LDAP_SASL_GSSAPI) ||
					    (**cNext != NS_LDAP_CRED_SELF &&
					    (*aNext)->saslmech ==
					    NS_LDAP_SASL_GSSAPI))
						continue;
					/* make connection and authenticate */
					/* with default credentials */
					authp = NULL;
					rc = __s_api_getDefaultAuth(*cNext,
					    *aNext, &authp,
					    flags & NS_LDAP_READ_SHADOW);
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
					    nopasswd_acct_mgmt, flags,
					    &badSrvrs, conn_user);
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
			(void) sleep(sec);
		} else {
			break;
		}
	}

done:
	if (self_gssapi_only && rc == NS_LDAP_SUCCESS && *session == NULL) {
		/*
		 * self_gssapi_only is true but no self/sasl/gssapi is
		 * configured
		 */
		rc = NS_LDAP_CONFIG;
	}

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
	int nopasswd_acct_mgmt,
	ns_conn_user_t *conn_user)
{
	int rc;

	rc = getConnection(server, flags, cred, sessionId, session,
	    errorp, fail_if_new_pwd_reqd, nopasswd_acct_mgmt,
	    conn_user);

	if (rc != NS_LDAP_SUCCESS && rc != NS_LDAP_SUCCESS_WITH_INFO) {
		if (conn_user != NULL && conn_user->conn_mt != NULL)
			__s_api_conn_mt_remove(conn_user, rc, errorp);
	}

	return (rc);
}

void
__s_api_free_sessionPool()
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

/*
 * This function initializes a TLS LDAP session. On success LDAP* is returned
 * (pointed by *ldp). Otherwise, the function returns an NS error code and
 * provide an additional info pointed by *errorp.
 */
static
ns_ldap_return_code
createTLSSession(const ns_cred_t *auth, const char *serverAddr,
		    uint16_t port, int timeoutMilliSec,
		    LDAP **ldp, ns_ldap_error_t **errorp)
{
	const char	*hostcertpath;
	char		*alloc_hcp = NULL, errstr[MAXERROR];
	int		ldap_rc;

#ifdef DEBUG
	(void) fprintf(stderr, "tid= %d: +++TLS transport\n",
	    thr_self());
#endif /* DEBUG */

	if (prldap_set_session_option(NULL, NULL,
	    PRLDAP_OPT_IO_MAX_TIMEOUT,
	    timeoutMilliSec) != LDAP_SUCCESS) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("createTLSSession: failed to initialize "
		    "TLS security"));
		MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	hostcertpath = auth->hostcertpath;
	if (hostcertpath == NULL) {
		alloc_hcp = __s_get_hostcertpath();
		hostcertpath = alloc_hcp;
	}

	if (hostcertpath == NULL)
		return (NS_LDAP_MEMORY);

	if ((ldap_rc = ldapssl_client_init(hostcertpath, NULL)) < 0) {
		if (alloc_hcp != NULL) {
			free(alloc_hcp);
		}
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("createTLSSession: failed to initialize "
		    "TLS security (%s)"),
		    ldapssl_err2string(ldap_rc));
		MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}
	if (alloc_hcp)
		free(alloc_hcp);

	*ldp = ldapssl_init(serverAddr, port, 1);

	if (*ldp == NULL ||
	    ldapssl_install_gethostbyaddr(*ldp, "ldap") != 0) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("createTLSSession: failed to connect "
		    "using TLS (%s)"), strerror(errno));
		MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * Convert (resolve) hostname to IP address.
 *
 * INPUT:
 *
 * 	server	- \[IPv6_address\][:port]
 *		- IPv4_address[:port]
 *		- hostname[:port]
 *
 * 	newaddr - Buffer to which this function writes resulting address,
 *		including the port number, if specified in server argument.
 *
 * 	newaddr_size - Size of the newaddr buffer.
 *
 * 	errstr  - Buffer to which error string is written if error occurs.
 *
 * 	errstr_size - Size of the errstr buffer.
 *
 * OUTPUT:
 *
 * 	Returns 1 for success, 0 in case of error.
 *
 * 	newaddr - See above (INPUT section).
 *
 *	errstr	- See above (INPUT section).
 */
static int
cvt_hostname2ip(char *server, char *newaddr, int newaddr_size,
    char *errstr, int errstr_size)
{
	char	*s;
	unsigned short port = 0;
	int	err;
	char	buffer[NSS_BUFLEN_HOSTS];
	struct hostent	result;

	/* Determine if the host name contains a port number. */

	/* Skip over IPv6 address. */
	s = strchr(server, ']');
	s = strchr(s != NULL ? s : server, ':');
	if (s != NULL) {
		if (sscanf(s + 1, "%hu", &port) != 1) {
			/* Address misformatted. No port number after : */
			(void) snprintf(errstr, errstr_size, "%s",
			    gettext("Invalid host:port format"));
			return (0);
		} else
			/* Cut off the :<port> part. */
			*s = '\0';
	}

	buffer[0] = '\0';
	/*
	 * Resolve hostname and fill in hostent structure.
	 */
	if (!__s_api_hostname2ip(server, &result, buffer, NSS_BUFLEN_HOSTS,
	    &err)) {
		/*
		 * The only possible error here could be TRY_AGAIN if buffer was
		 * not big enough. NSS_BUFLEN_HOSTS should have been enough
		 * though.
		 */
		(void) snprintf(errstr, errstr_size, "%s",
		    gettext("Unable to resolve address."));
		return (0);
	}


	buffer[0] = '\0';
	/*
	 * Convert the address to string.
	 */
	if (!inet_ntop(result.h_addrtype, result.h_addr_list[0], buffer,
	    NSS_BUFLEN_HOSTS)) {
		/* There's not much we can do. */
		(void) snprintf(errstr, errstr_size, "%s",
		    gettext("Unable to convert address to string."));
		return (0);
	}

	/* Put together the address and the port */
	if (port > 0) {
		switch (result.h_addrtype) {
			case AF_INET6:
				(void) snprintf(newaddr,
				    /* [IP]:<port>\0 */
				    1 + strlen(buffer) + 1 + 1 + 5 + 1,
				    "[%s]:%hu",
				    buffer,
				    port);
				break;
			/* AF_INET */
			default :
				(void) snprintf(newaddr,
				    /* IP:<port>\0 */
				    strlen(buffer) + 1 + 5 + 1,
				    "%s:%hu",
				    buffer,
				    port);
				break;
		}
	} else {
		(void) strncpy(newaddr, buffer, newaddr_size);
	}

	return (1);
}


/*
 * This finction initializes a none-TLS LDAP session.  On success LDAP*
 * is returned (pointed by *ldp). Otherwise, the function returns
 * an NS error code and provides an additional info pointed by *errorp.
 */
static
ns_ldap_return_code
createNonTLSSession(const char *serverAddr,
		uint16_t port, int gssapi,
		LDAP **ldp, ns_ldap_error_t **errorp)
{
	char		errstr[MAXERROR];
	char		*addr;
	int		is_ip = 0;
			/* [INET6_ADDRSTRLEN]:<port>\0 */
	char		svraddr[1+INET6_ADDRSTRLEN+1+1+5+1];
#ifdef DEBUG
	(void) fprintf(stderr, "tid= %d: +++Unsecure transport\n",
	    thr_self());
#endif /* DEBUG */

	if (gssapi == 0) {
		is_ip = (__s_api_isipv4((char *)serverAddr) ||
		    __s_api_isipv6((char *)serverAddr));
	}

	/*
	 * Let's try to resolve IP address of server.
	 */
	if (is_ip == 0 && !gssapi && (ldap_in_nss_switch((char *)"hosts") > 0 ||
	    ldap_in_nss_switch((char *)"ipnodes") > 0)) {
		addr = strdup(serverAddr);
		if (addr == NULL)
			return (NS_LDAP_MEMORY);
		svraddr[0] = '\0';
		if (cvt_hostname2ip(addr, svraddr, sizeof (svraddr),
		    errstr, MAXERROR) == 1) {
			serverAddr = svraddr;
			free(addr);
		} else {
			free(addr);
			MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
			    strdup(errstr), NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
		}
	}

	/* Warning message IF cannot connect to host(s) */
	if ((*ldp = ldap_init((char *)serverAddr, port)) == NULL) {
		char *p = strerror(errno);
		MKERROR(LOG_WARNING, *errorp, LDAP_CONNECT_ERROR,
		    strdup(p), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * This finction initializes an LDAP session.
 *
 * INPUT:
 *     auth - a structure specified an authenticastion method and credentials,
 *     serverAddr - the address of a server to which a connection
 *                  will be established,
 *     port - a port being listened by the server,
 *     timeoutMilliSec - a timeout in milliseconds for the Bind operation.
 *
 * OUTPUT:
 *     ldp - a pointer to an LDAP structure which will be used
 *           for all the subsequent operations against the server.
 *     If an error occurs, the function returns an NS error code
 *     and provides an additional info pointed by *errorp.
 */
static
ns_ldap_return_code
createSession(const ns_cred_t *auth, const char *serverAddr,
		    uint16_t port, int timeoutMilliSec,
		    LDAP **ldp, ns_ldap_error_t **errorp)
{
	int	useSSL = 0, gssapi = 0;
	char	errstr[MAXERROR];

	switch (auth->auth.type) {
		case NS_LDAP_AUTH_NONE:
		case NS_LDAP_AUTH_SIMPLE:
		case NS_LDAP_AUTH_SASL:
			break;
		case NS_LDAP_AUTH_TLS:
			useSSL = 1;
			break;
		default:
			(void) sprintf(errstr,
			    gettext("openConnection: unsupported "
			    "authentication method (%d)"), auth->auth.type);
			MKERROR(LOG_WARNING, *errorp,
			    LDAP_AUTH_METHOD_NOT_SUPPORTED, strdup(errstr),
			    NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
	}

	if (port == USE_DEFAULT_PORT) {
		port = useSSL ? LDAPS_PORT : LDAP_PORT;
	}

	if (auth->auth.type == NS_LDAP_AUTH_SASL &&
	    auth->auth.saslmech == NS_LDAP_SASL_GSSAPI)
		gssapi = 1;

	if (useSSL)
		return (createTLSSession(auth, serverAddr, port,
		    timeoutMilliSec, ldp, errorp));
	else
		return (createNonTLSSession(serverAddr, port, gssapi,
		    ldp, errorp));
}

/*
 * This finction performs a non-SASL bind operation.  If an error accures,
 * the function returns an NS error code and provides an additional info
 * pointed by *errorp.
 */
static
ns_ldap_return_code
doSimpleBind(const ns_cred_t *auth,
		LDAP *ld,
		int timeoutSec,
		ns_ldap_error_t **errorp,
		int fail_if_new_pwd_reqd,
		int passwd_mgmt)
{
	char			*binddn, *passwd, errstr[MAXERROR], *errmsg;
	int			msgId, errnum = 0, ldap_rc;
	ns_ldap_return_code	ret_code;
	LDAPMessage		*resultMsg = NULL;
	LDAPControl		**controls;
	struct timeval		tv;

	binddn = auth->cred.unix_cred.userID;
	passwd = auth->cred.unix_cred.passwd;
	if (passwd == NULL || *passwd == '\0' ||
	    binddn == NULL || *binddn == '\0') {
		(void) sprintf(errstr, gettext("openConnection: "
		    "missing credentials for Simple bind"));
		MKERROR(LOG_WARNING, *errorp, LDAP_INVALID_CREDENTIALS,
		    strdup(errstr), NS_LDAP_MEMORY);
		(void) ldap_unbind(ld);
		return (NS_LDAP_INTERNAL);
	}

#ifdef DEBUG
	(void) fprintf(stderr, "tid= %d: +++Simple bind\n",
	    thr_self());
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
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	tv.tv_sec = timeoutSec;
	tv.tv_usec = 0;
	ldap_rc = ldap_result(ld, msgId, 0, &tv, &resultMsg);

	if ((ldap_rc == -1) || (ldap_rc == 0)) {
		(void) ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
		    (void *)&errnum);
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("openConnection: simple bind failed "
		    "- %s"), ldap_err2string(errnum));
		(void) ldap_msgfree(resultMsg);
		(void) ldap_unbind(ld);
		MKERROR(LOG_WARNING, *errorp, errnum, strdup(errstr),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	/*
	 * get ldaprc, controls, and error msg
	 */
	ldap_rc = ldap_parse_result(ld, resultMsg, &errnum, NULL,
	    &errmsg, NULL, &controls, 1);

	if (ldap_rc != LDAP_SUCCESS) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("openConnection: simple bind failed "
		    "- unable to parse result"));
		(void) ldap_unbind(ld);
		MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	/* process the password management info, if any */
	ret_code = process_pwd_mgmt("simple",
	    errnum, controls, errmsg,
	    errorp,
	    fail_if_new_pwd_reqd,
	    passwd_mgmt);

	if (ret_code == NS_LDAP_INTERNAL) {
		(void) ldap_unbind(ld);
	}

	return (ret_code);
}

/*
 * This finction performs a SASL bind operation.  If an error accures,
 * the function returns an NS error code and provides an additional info
 * pointed by *errorp.
 */
static
ns_ldap_return_code
doSASLBind(const ns_cred_t *auth,
		LDAP *ld,
		int timeoutSec,
		ns_ldap_error_t **errorp,
		int fail_if_new_pwd_reqd,
		int passwd_mgmt)
{
	char			*binddn, *passwd, *digest_md5_name,
	    errstr[MAXERROR], *errmsg;
	struct berval		cred;
	int			ldap_rc, errnum = 0;
	ns_ldap_return_code	ret_code;
	struct timeval		tv;
	LDAPMessage		*resultMsg;
	LDAPControl		**controls;
	int			min_ssf = MIN_SASL_SSF, max_ssf = MAX_SASL_SSF;
	ns_sasl_cb_param_t	sasl_param;

	if (auth->auth.saslopt != NS_LDAP_SASLOPT_NONE &&
	    auth->auth.saslmech != NS_LDAP_SASL_GSSAPI) {
		(void) sprintf(errstr,
		    gettext("openConnection: SASL options are "
		    "not supported (%d) for non-GSSAPI sasl bind"),
		    auth->auth.saslopt);
		MKERROR(LOG_WARNING, *errorp,
		    LDAP_AUTH_METHOD_NOT_SUPPORTED,
		    strdup(errstr), NS_LDAP_MEMORY);
		(void) ldap_unbind(ld);
		return (NS_LDAP_INTERNAL);
	}
	if (auth->auth.saslmech != NS_LDAP_SASL_GSSAPI) {
		binddn = auth->cred.unix_cred.userID;
		passwd = auth->cred.unix_cred.passwd;
		if (passwd == NULL || *passwd == '\0' ||
		    binddn == NULL || *binddn == '\0') {
			(void) sprintf(errstr,
			gettext("openConnection: missing credentials "
			    "for SASL bind"));
			MKERROR(LOG_WARNING, *errorp,
			    LDAP_INVALID_CREDENTIALS,
			    strdup(errstr), NS_LDAP_MEMORY);
			(void) ldap_unbind(ld);
			return (NS_LDAP_INTERNAL);
		}
		cred.bv_val = passwd;
		cred.bv_len = strlen(passwd);
	}

	ret_code = NS_LDAP_SUCCESS;

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
		if ((ldap_rc = ldap_sasl_cram_md5_bind_s(ld, binddn,
		    &cred, NULL, NULL)) != LDAP_SUCCESS) {
			(void) ldap_get_option(ld,
			    LDAP_OPT_ERROR_NUMBER, (void *)&errnum);
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("openConnection: "
			    "sasl/CRAM-MD5 bind failed - %s"),
			    ldap_err2string(errnum));
			MKERROR(LOG_WARNING, *errorp, errnum,
			    strdup(errstr), NS_LDAP_MEMORY);
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
		ldap_rc = ldap_x_sasl_digest_md5_bind(ld,
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
			    strdup(errstr), NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
		}

		/*
		 * get ldaprc, controls, and error msg
		 */
		ldap_rc = ldap_parse_result(ld, resultMsg, &errnum, NULL,
		    &errmsg, NULL, &controls, 1);

		if (ldap_rc != LDAP_SUCCESS) {
			free(digest_md5_name);
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("openConnection: "
			    "DIGEST-MD5 bind failed "
			    "- unable to parse result"));
			(void) ldap_unbind(ld);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
			    strdup(errstr), NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
		}

		/* process the password management info, if any */
		ret_code = process_pwd_mgmt("sasl/DIGEST-MD5",
		    errnum, controls, errmsg,
		    errorp,
		    fail_if_new_pwd_reqd,
		    passwd_mgmt);

		if (ret_code == NS_LDAP_INTERNAL) {
			(void) ldap_unbind(ld);
		}

		free(digest_md5_name);
		break;
	case NS_LDAP_SASL_GSSAPI:
		(void) memset(&sasl_param, 0,
		    sizeof (ns_sasl_cb_param_t));
		sasl_param.authid = NULL;
		sasl_param.authzid = "";
		(void) ldap_set_option(ld, LDAP_OPT_X_SASL_SSF_MIN,
		    (void *)&min_ssf);
		(void) ldap_set_option(ld, LDAP_OPT_X_SASL_SSF_MAX,
		    (void *)&max_ssf);

		ldap_rc = ldap_sasl_interactive_bind_s(
		    ld, NULL, "GSSAPI",
		    NULL, NULL, LDAP_SASL_INTERACTIVE,
		    __s_api_sasl_bind_callback,
		    &sasl_param);

		if (ldap_rc != LDAP_SUCCESS) {
			(void) snprintf(errstr, sizeof (errstr),
			    gettext("openConnection: "
			    "GSSAPI bind failed "
			    "- %d %s"),
			    ldap_rc,
			    ldap_err2string(ldap_rc));
			(void) ldap_unbind(ld);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
			    strdup(errstr), NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
		}

		break;
	default:
		(void) ldap_unbind(ld);
		(void) sprintf(errstr,
		    gettext("openConnection: unsupported SASL "
		    "mechanism (%d)"), auth->auth.saslmech);
		MKERROR(LOG_WARNING, *errorp,
		    LDAP_AUTH_METHOD_NOT_SUPPORTED, strdup(errstr),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	return (ret_code);
}

/*
 * This function performs an LDAP Bind operation proceeding
 * from a type of the connection specified by auth->auth.type.
 *
 * INPUT:
 *     auth - a structure specified an authenticastion method and credentials,
 *     ld - a pointer returned by the createSession() function,
 *     timeoutSec - a timeout in seconds for the Bind operation,
 *     fail_if_new_pwd_reqd - a flag indicating that the call should fail
 *                            if a new password is required,
 *     passwd_mgmt - a flag indicating that the server supports
 *                   password management.
 *
 * OUTPUT:
 *     If an error accures, the function returns an NS error code
 *     and provides an additional info pointed by *errorp.
 */
static
ns_ldap_return_code
performBind(const ns_cred_t *auth,
		LDAP *ld,
		int timeoutSec,
		ns_ldap_error_t **errorp,
		int fail_if_new_pwd_reqd,
		int passwd_mgmt)
{
	int	bindType;
	char	errstr[MAXERROR];

	ns_ldap_return_code (*binder)(const ns_cred_t *auth,
	    LDAP *ld,
	    int timeoutSec,
	    ns_ldap_error_t **errorp,
	    int fail_if_new_pwd_reqd,
	    int passwd_mgmt) = NULL;

	if (!ld) {
		(void) sprintf(errstr,
		    "performBind: LDAP session "
		    "is not initialized.");
		MKERROR(LOG_WARNING, *errorp,
		    LDAP_AUTH_METHOD_NOT_SUPPORTED,
		    strdup(errstr), NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	bindType = auth->auth.type == NS_LDAP_AUTH_TLS ?
	    auth->auth.tlstype : auth->auth.type;

	switch (bindType) {
		case NS_LDAP_AUTH_NONE:
#ifdef DEBUG
		(void) fprintf(stderr, "tid= %d: +++Anonymous bind\n",
		    thr_self());
#endif /* DEBUG */
			break;
		case NS_LDAP_AUTH_SIMPLE:
			binder = doSimpleBind;
			break;
		case NS_LDAP_AUTH_SASL:
			binder = doSASLBind;
			break;
		default:
			(void) sprintf(errstr,
			    gettext("openConnection: unsupported "
			    "authentication method "
			    "(%d)"), bindType);
			MKERROR(LOG_WARNING, *errorp,
			    LDAP_AUTH_METHOD_NOT_SUPPORTED,
			    strdup(errstr), NS_LDAP_MEMORY);
			(void) ldap_unbind(ld);
			return (NS_LDAP_INTERNAL);
	}

	if (binder != NULL) {
		return (*binder)(auth,
		    ld,
		    timeoutSec,
		    errorp,
		    fail_if_new_pwd_reqd,
		    passwd_mgmt);
	}

	return (NS_LDAP_SUCCESS);
}
