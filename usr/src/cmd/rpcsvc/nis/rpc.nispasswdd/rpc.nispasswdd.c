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
#include <stdlib.h>	/* getenv, exit */
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>
#include <syslog.h>
#include <stropts.h>
#include <netdir.h>
#include <synch.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/nis_dhext.h>
#include "npd_svcsubr.h"

int	verbose = 0;
bool_t	debug = FALSE;
/*
 * generate keys if none exist or if admin. is changing another
 * users password.
 */
bool_t	generatekeys = FALSE;
ulong_t	cache_time = 1800;	/* cache failed attempts for 30 mins */
int	max_attempts = 3;	/* max # of failed attempts allowed */
NIS_HASH_TABLE	upd_list;	/* cache of updates */
char	*ypfwd = (char *)NULL;	/* passwd map YP master machine */

static void __msgout(const char *msg);
static int __svc_priv_port_create(void);
static void nispasswd_prog(struct svc_req *rqstp, register SVCXPRT *transp);
static void nispasswd_prog_ver2(struct svc_req *rqstp,
				    register SVCXPRT *transp);
static void yppasswd_prog(struct svc_req *rqstp, register SVCXPRT *transp);
static void set_rpc_gss_svc_names(void);

int
main(int argc, char *argv[])
{
	pid_t	pid;
	int	i;
	int	c;
	int	mins;
	int	status;
	nis_tag		tags[2], *tagres;
	nis_server	*srv;
	int	connmaxrec = RPC_MAXDATASIZE;

	(void) memset((char *)&upd_list, 0, sizeof (upd_list));
	(void) chdir("/var/nis");	/* drop core here */
	while ((c = getopt(argc, argv, "a:c:DgvY:")) != -1) {
	switch (c) {
		case 'a':
			max_attempts = atoi(optarg);
			if (max_attempts < 0) {
				fprintf(stderr,
				"%s: invalid number of maximum attempts\n",
				    argv[0]);
				exit(1);
			}
			break;
		case 'c':
			mins = atoi(optarg);
			if (mins <= 0) {
				fprintf(stderr,
				    "%s: invalid cache time\n", argv[0]);
				exit(1);
			}
			cache_time = (ulong_t)mins * 60;
			break;
		case 'D':	/* debug mode */
			debug = TRUE;
			break;
		case 'g':	/* generate new keys if none exist */
			generatekeys = TRUE;
			break;
		case 'v':	/* verbose mode */
			verbose++;
			break;
		case 'Y':	/* YP forward mode */
			if (!(ypfwd = strdup(optarg))) {
				fprintf(stderr, "%s: out of memory\n", argv[0]);
				exit(1);
			}
			break;
		case '?':
			fprintf(stderr,
			"Usage: %s [-a attempts] [-c minutes] [-D] [-g] [-v]\n",
			    argv[0]);
			exit(1);
		}
	}

	/*
	 * this check should be removed if 'root' is not the
	 * owner of the table or if 'root' is not a member of
	 * the nis+ admins. group.
	 * of course: you also don't want someone to spoof the
	 * the daemon.
	 */
	if (geteuid() != (uid_t)0) {
		char err_string[256];
		snprintf(err_string, sizeof (err_string),
		    "must be superuser to run %s", argv[0]);
		__msgout(err_string);
		exit(1);
	}

	if (debug == FALSE) {
		pid = fork();
		if (pid < 0) {
			perror("cannot fork");
			exit(1);
		}
		if (pid)
			exit(0);
		closefrom(0);
		i = open("/dev/console", 2);
		(void) dup2(i, 1);
		(void) dup2(i, 2);
		(void) setsid();
	}
	openlog("rpc.nispasswdd", LOG_PID, LOG_DAEMON);

	/*
	 * should I be running ?
	 * Get the list of directories the local NIS+ server serves and
	 * check if it is the master server of any 'org_dir' listed.
	 */
	srv = __nis_host2nis_server(NULL, 0, &status);
	if (srv == NULL) {
		if (debug == TRUE)
			(void) fprintf(stderr,
			"no host/address information for local host, %d\n",
			    status);
		else
			syslog(LOG_ERR,
			"no host/address information for local host, %d",
			    status);
		__msgout("exiting ...");
		exit(1);
	}
	tags[0].tag_type = TAG_DIRLIST;
	tags[0].tag_val = "";
	tags[1].tag_type = TAG_NISCOMPAT;
	tags[1].tag_val = "";

	status = nis_stats(srv, tags, 2, &tagres);
	__free_nis_server(srv);
	if (status != NIS_SUCCESS) {
		if (verbose)
			nis_perror(status, "rpc.nispasswdd");
		else
			nis_lerror(status, "rpc.nispasswdd");
		__msgout(" ... exiting ...");
		exit(1);
	}
	if ((strcmp(tagres[0].tag_val, "<Unknown Statistics>") == 0) ||
	    (strcmp(tagres[1].tag_val, "<Unknown Statistics>") == 0)) {

		/* old server */
	__msgout("NIS+ server does not support the new statistics tags");
		exit(1);
	}

	if (__npd_am_master(nis_local_host(), tagres[0].tag_val) == FALSE) {
		__msgout("Local NIS+ server is not a master server");
		__msgout(" ... exiting ...");
		exit(1);
	}

	/* Specify maximum connection oriented RPC record size */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		__msgout("unable to set maximum RPC record size");
	}

	/*
	 * Check if NIS+ server is running in NIS compat mode.
	 * Register YPD only if this is the case.
	 */
	if (strcasecmp(tagres[1].tag_val, "ON") == 0) {
		if (rpcb_unset(YPPASSWDPROG, YPPASSWDVERS, 0) == FALSE) {
		__msgout("unable to de-register (YPPASSWDPROG, YPPASSWDVERS)");
			__msgout(" ... exiting ...");
			exit(1);
		}
		if (__svc_priv_port_create() == FALSE) {
		__msgout("unable to create (YPPASSWDPROG, YPPASSWDVERS)");
			/* continue */
		}
	}
	nis_freetags(tagres, 2);

	set_rpc_gss_svc_names();

	if (rpcb_unset(NISPASSWD_PROG, NISPASSWD_VERS, 0) == FALSE) {
	__msgout("unable to de-register (NISPASSWD_PROG, NISPASSWD_VERS)");
		__msgout(" ... exiting ...");
		exit(1);
	}
	if (svc_create(nispasswd_prog, NISPASSWD_PROG, NISPASSWD_VERS,
	    "circuit_v") == 0) {
		__msgout("unable to create (NISPASSWD_PROG, NISPASSWD_VERS)");
		__msgout(" ... exiting ...");
		exit(1);
	}

	if (rpcb_unset(NISPASSWD_PROG, NISPASSWD_VERS2, 0) == FALSE) {
	__msgout("unable to de-register (NISPASSWD_PROG, NISPASSWD_VERS2)");
		__msgout(" ... exiting ...");
		exit(1);
	}
	if (svc_create(nispasswd_prog_ver2, NISPASSWD_PROG, NISPASSWD_VERS2,
	    "circuit_v") == 0) {
		__msgout("unable to create (NISPASSWD_PROG, NISPASSWD_VERS2)");
		__msgout(" ... exiting ...");
		exit(1);
	}

	if (verbose == TRUE)
		__msgout("starting rpc.nispasswdd ...");
	svc_run();
	__msgout("svc_run returned");

	return (1);
}

static void
__msgout(const char *msg)
{
	if (debug == TRUE)
		(void) fprintf(stderr, "%s\n", msg);
	else
		syslog(LOG_ERR, msg);
}

static bool_t
__svc_priv_port_create()
{
	struct netconfig *nconf, *nconf4 = 0, *nconf6 = 0;
	void		*handlep;
	int		fd4 = -1, fd6 = -1;
	struct t_info	tinfo4, tinfo6;
	SVCXPRT		*transp4 = 0, *transp6 = 0;
	int		svc4 = 0, svc6 = 0;

	if ((handlep = setnetconfig()) == (void *) NULL) {
		(void) nc_perror("cannot get any transport information");
		return (FALSE);
	}

	while ((nconf = getnetconfig(handlep)) != 0 &&
	    (nconf4 == 0 || nconf6 == 0)) {
		if ((nconf->nc_semantics == NC_TPI_CLTS) &&
		    strcmp(nconf->nc_proto, NC_UDP) == 0) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
				nconf4 = nconf;
			else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
				nconf6 = nconf;
		}
	}

	if (nconf4 == 0 && nconf6 == 0) {
		(void) endnetconfig(handlep);
		__msgout("no NC_INET/NC_INET6 NC_TPI_CLTS/NC_UPD transports");
		return (FALSE);
	}

	if (nconf4 != 0)
		fd4 = t_open(nconf4->nc_device, O_RDWR, &tinfo4);
	if (nconf6 != 0)
		fd6 = t_open(nconf6->nc_device, O_RDWR, &tinfo6);
	if (fd4 == -1 && fd6 == -1) {
		__msgout("unable to open connection for NIS requests");
		(void) endnetconfig(handlep);
		return (FALSE);
	}

	if (fd4 != -1) {
		if (netdir_options(nconf4, ND_SET_RESERVEDPORT, fd4, 0)	== -1) {
			__msgout("unable to get reserved port for NC_INET");
			netdir_perror("");
			(void) endnetconfig(handlep);
			return (FALSE);
		}
		transp4 = svc_tli_create(fd4, nconf4, NULL, 0, 0);
	}

	if (fd6 != -1) {
		if (netdir_options(nconf6, ND_SET_RESERVEDPORT, fd6, 0)	== -1) {
			__msgout("unable to get reserved port for NC_INET6");
			netdir_perror("");
			(void) endnetconfig(handlep);
			return (FALSE);
		}
		transp6 = svc_tli_create(fd6, nconf6, NULL, 0, 0);
	}

	if (transp4 == 0 && transp6 == 0) {
		__msgout("unable to create (YPPASSWDPROG, YPPASSWDVERS)");
		(void) endnetconfig(handlep);
		return (FALSE);
	}

	if (transp4 != 0)
		svc4 = svc_reg(transp4, YPPASSWDPROG, YPPASSWDVERS,
		    yppasswd_prog, nconf4);
	if (transp6 != 0)
		svc6 = svc_reg(transp6, YPPASSWDPROG, YPPASSWDVERS,
		    yppasswd_prog, nconf6);
	if (svc4 == 0 && svc6 == 0) {
		__msgout("unable to register (YPPASSWDPROG, YPPASSWDVERS)");
		if (transp4 != 0)
			(void) svc_destroy(transp4);
		if (transp6 != 0)
			(void) svc_destroy(transp6);
		(void) endnetconfig(handlep);
		return (FALSE);
	}
	(void) endnetconfig(handlep);
	return (TRUE);
}

static void
nispasswd_prog(rqstp, transp)
struct svc_req	*rqstp;
register SVCXPRT *transp;
{
	union {
		npd_request nispasswd_authenticate_1_arg;
		npd_update nispasswd_update_1_arg;
	} argument;
	union {
		nispasswd_authresult nispasswd_authenticate_1_res;
		nispasswd_updresult nispasswd_update_1_res;
	} result;
	bool_t retval;
	xdrproc_t xdr_argument, xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		__msgout("received NIS+ null proc call");
		(void) svc_sendreply(transp,
			(xdrproc_t)xdr_void, (char *)NULL);
		return;

	case NISPASSWD_AUTHENTICATE:
		xdr_argument = (xdrproc_t)xdr_npd_request;
		xdr_result = (xdrproc_t)xdr_nispasswd_authresult;
		local = (bool_t (*) (char *, void *, struct svc_req *))
				nispasswd_authenticate_1_svc;
		break;

	case NISPASSWD_UPDATE:
		xdr_argument = (xdrproc_t)xdr_npd_update;
		xdr_result = (xdrproc_t)xdr_nispasswd_updresult;
		local = (bool_t (*) (char *, void *, struct svc_req *))
				nispasswd_update_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (svc_getargs(transp, xdr_argument, (caddr_t)&argument) == 0) {
		svcerr_decode(transp);
		return;
	}
	(void) memset((char *)&result, 0, sizeof (result));
	retval = (bool_t)(*local)((char *)&argument, (void *)&result, rqstp);
	if (retval == TRUE && (svc_sendreply(transp, xdr_result,
						(char *)&result) == 0)) {
		svcerr_systemerr(transp);
	}
	if (svc_freeargs(transp, xdr_argument, (caddr_t)&argument) == 0) {
		__msgout("unable to free arguments");
		exit(1);
	}
	if (nispasswd_prog_1_freeresult(transp, xdr_result,
				(caddr_t)&result) == 0)
		__msgout("unable to free results");

	/* NOTREACHED */
}

static void
nispasswd_prog_ver2(rqstp, transp)
struct svc_req	*rqstp;
register SVCXPRT *transp;
{

	union {
		npd_request nispasswd_authenticate_2_arg;
		npd_update2 nispasswd_update_2_arg;
	} argument;
	union {
		nispasswd_authresult nispasswd_authenticate_2_res;
		nispasswd_updresult nispasswd_update_2_res;
	} result;
	bool_t retval;
	xdrproc_t xdr_argument, xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		__msgout("received NIS+ null proc call");
		(void) svc_sendreply(transp,
			(xdrproc_t)xdr_void, (char *)NULL);
		return;

	case NISPASSWD_AUTHENTICATE:
		xdr_argument = (xdrproc_t)xdr_npd_request;
		xdr_result = (xdrproc_t)xdr_nispasswd_authresult;
		local = (bool_t (*) (char *, void *, struct svc_req *))
				nispasswd_authenticate_2_svc;
		break;

	case NISPASSWD_UPDATE:
		xdr_argument = (xdrproc_t)xdr_npd_update2;
		xdr_result = (xdrproc_t)xdr_nispasswd_updresult;
		local = (bool_t (*) (char *, void *, struct svc_req *))
				nispasswd_update_2_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (svc_getargs(transp, xdr_argument, (caddr_t)&argument) == 0) {
		svcerr_decode(transp);
		return;
	}
	(void) memset((char *)&result, 0, sizeof (result));
	retval = (bool_t)(*local)((char *)&argument, (void *)&result, rqstp);
	if (retval == TRUE && (svc_sendreply(transp, xdr_result,
						(char *)&result) == 0)) {
		svcerr_systemerr(transp);
	}
	if (svc_freeargs(transp, xdr_argument, (caddr_t)&argument) == 0) {
		__msgout("unable to free arguments");
		exit(1);
	}
	if (nispasswd_prog_2_freeresult(transp, xdr_result,
				(caddr_t)&result) == 0)
		__msgout("unable to free results");

	/* NOTREACHED */
}

static void
yppasswd_prog(rqstp, transp)
struct svc_req	*rqstp;
register SVCXPRT *transp;
{
	union {
		struct yppasswd yppasswdproc_update_1_arg;
	} argument;
	union {
		int yppasswdproc_update_1_res;
	} result;
	bool_t retval;
	xdrproc_t xdr_argument, xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);
#ifdef SHD_WE_ALWAYS
	struct netconfig	*nconf;
#endif

	switch (rqstp->rq_proc) {
	case NULLPROC:
		__msgout("received NIS null proc call");
		(void) svc_sendreply(transp,
			(xdrproc_t)xdr_void, (char *)NULL);
		return;

	case YPPASSWDPROC_UPDATE:
		xdr_argument = (xdrproc_t)xdr_yppasswd;
		xdr_result = (xdrproc_t)xdr_int;
		local = (bool_t (*) (char *, void *, struct svc_req *))
				yppasswdproc_update_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
#ifdef SHD_WE_ALWAYS
	/*
	 * update request received, lets just check the port
	 */
	nconf = (struct netconfig *)getnetconfigent(transp->xp_netid);
	if (nconf == (struct netconfig *)NULL) {
		(void) nc_perror("could not get transport information");
		svcerr_systemerr(transp);
		return;
	}

	if ((strcmp(nconf->nc_protofmly, NC_INET) != 0) ||
		(strcmp(nconf->nc_proto, NC_UDP) != 0) ||
		(netdir_options(nconf, ND_CHECK_RESERVEDPORT, transp->xp_fd,
			(void *) &(transp->xp_rtaddr)) != 0)) {

		if (nconf)
			(void) freenetconfigent(nconf);
		svcerr_weakauth(transp);
		return;
	}
	if (nconf)
		(void) freenetconfigent(nconf);
#endif
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}
	(void) memset((char *)&result, 0, sizeof (result));
	retval = (bool_t)(*local)((char *)&argument, (void *)&result, rqstp);
	if (retval == TRUE && !svc_sendreply(transp, xdr_result,
						(char *)&result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		__msgout("unable to free arguments");
		exit(1);
	}
}

/*
 * Loop thru mech list from security conf file and set
 * the RPC GSS service name(s).  Stop processing list if
 * the classic AUTH_DES compat entry is encountered.
 */
static void
set_rpc_gss_svc_names()
{
	mechanism_t **mechs;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		mechanism_t	**mpp;
				/* "nispasswd" + 1 = 10 */
		char		svc_name[NIS_MAXNAMELEN+10];
		int		slen;
		char		*lh = nis_local_host();

		if (! lh) {
			syslog(LOG_ERR,
		"can't set RPC GSS service name:  can't get local host name");
			__nis_release_mechanisms(mechs);
			return;
		}

		/* '@' + NUL = 2 */
		if (strlen(lh) + strlen(NIS_SVCNAME_NISPASSWD) + 2 >
		    sizeof (svc_name)) {
			syslog(LOG_ERR,
		"can't set RPC GSS service name:  svc_name bufsize too small");
			__nis_release_mechanisms(mechs);
			return;
		}
		/* service names are of the form svc@server.dom */
		(void) sprintf(svc_name, "%s@%s", NIS_SVCNAME_NISPASSWD, lh);
		/* remove trailing '.' */
		slen = strlen(svc_name);
		if (svc_name[slen - 1] == '.')
			svc_name[slen - 1] = '\0';

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;
			bool_t	val;

			if (AUTH_DES_COMPAT_CHK(mp))
				break;

			if (! VALID_MECH_ENTRY(mp))
				continue;

			val = rpc_gss_set_svc_name(svc_name,  mp->mechname,
			    0, NISPASSWD_PROG,
			    NISPASSWD_VERS);
			if (val) {
				if (verbose)
					syslog(LOG_INFO,
				"RPC GSS service name for mechanism '%s' set",
					    mp->mechname);
			} else {
				rpc_gss_error_t	err;

				rpc_gss_get_error(&err);
				syslog(LOG_ERR,
				    "can't set RPC GSS svc name '%s'"
				    "for mech '%s': RPC GSS err = %d,"
				    "sys err = %d",
				    svc_name, mp->mechname,
				    err.rpc_gss_error, err.system_error);
			}

			val = rpc_gss_set_svc_name(svc_name,  mp->mechname,
			    0, NISPASSWD_PROG,
			    NISPASSWD_VERS2);
			if (val) {
				if (verbose)
					syslog(LOG_INFO,
				"RPC GSS service name for mechanism '%s' set",
					    mp->mechname);
			} else {
				rpc_gss_error_t	err;

				rpc_gss_get_error(&err);
				syslog(LOG_ERR,
				    "can't set RPC GSS svc name '%s'"
				    "for mech '%s': RPC GSS err = %d,"
				    "sys err = %d",
				    svc_name, mp->mechname,
				    err.rpc_gss_error, err.system_error);
			}
		}
		__nis_release_mechanisms(mechs);
		return;
	}
}
