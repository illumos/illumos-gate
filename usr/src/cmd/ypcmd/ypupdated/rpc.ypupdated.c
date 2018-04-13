/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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
 * Copyright 2017 Joyent Inc
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * NIS update service
 */
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/file.h>
#include <ctype.h>
#define	PORTMAP
#include <rpc/rpc.h>
#include <rpc/auth_des.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/termio.h>
#include <sys/debug.h>
#include <strings.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <netdir.h>
#include <rpcsvc/ypupd.h>
#include <netdb.h>
#include "shim.h"
#include "yptol.h"

#define	RPC_INETDSOCK	0	/* socket descriptor if using inetd */
#define	debug(msg)	/* turn off debugging */

char YPDIR[] = "/var/yp";
char UPDATEFILE[] = "updaters";

void ypupdate_prog(struct svc_req *rqstp, SVCXPRT *transp);
void detachfromtty(void);

static int addr2netname(char *, SVCXPRT *);
static int issock(int);

int insecure;

int
main(int argc, char *argv[])
{
	char *cmd;
	int connmaxrec = RPC_MAXDATASIZE;
	struct stat filestat;

	/*
	 * Check if we are running in N2L mode. If so updated is unsuported.
	 * This could be done by calling is_yptol_mode(), from libnisdb, but it
	 * seems over complex to pull in an entire library for one check so
	 * do it in line. Just pull in the name of file to check.
	 */
	if (stat(NTOL_MAP_FILE, &filestat) != -1) {
		fprintf(stderr, "rpc.updated not supported in NIS to LDAP "
		    "transition mode.");
		exit(1);
	}


	cmd = argv[0];
	switch (argc) {
	case 0:
		cmd = "ypupdated";
		break;
	case 1:
		break;
	case 2:
		if (strcmp(argv[1], "-i") == 0) {
			insecure++;
			break;
		} else if (strcmp(argv[1], "-s") == 0) {
			insecure = 0;
			break;
		}
		/* FALLTHROUGH */
	default:
		fprintf(stderr, "%s: warning -- options ignored\n", cmd);
		break;
	}

	if (chdir(YPDIR) < 0) {
		fprintf(stderr, "%s: can't chdir to ", cmd);
		perror(YPDIR);
		exit(1);
	}

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		fprintf(stderr, "unable to set maximum RPC record size");
	}

	if (issock(RPC_INETDSOCK)) {
		SVCXPRT *transp;
		int proto = 0;
		transp = svctcp_create(RPC_INETDSOCK, 0, 0);
		if (transp == NULL) {
			fprintf(stderr, "%s: cannot create tcp service\n", cmd);
			exit(1);
		}
		if (!svc_register(transp, YPU_PROG, YPU_VERS, ypupdate_prog,
		    proto)) {
			fprintf(stderr, "%s: couldn't register service\n", cmd);
			exit(1);
		}
	} else {
		detachfromtty();
		(void) rpcb_unset(YPU_PROG, YPU_VERS, 0);
		if (!svc_create(ypupdate_prog, YPU_PROG, YPU_VERS, "tcp")) {
			fprintf(stderr, "%s: cannot create tcp service\n", cmd);
			exit(1);
		}
	}

	if (!svc_create(ypupdate_prog, YPU_PROG, YPU_VERS, "udp")) {
		fprintf(stderr, "%s: cannot create udp service\n", cmd);
		exit(1);
	}

	svc_run();
	abort();
	/* NOTREACHED */
	return (1);
}

/*
 * Determine if a descriptor belongs to a socket or not
 */
static int
issock(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == -1)
		return (0);
	else
		return (S_ISSOCK(fd));
}


void
detachfromtty(void)
{
	int tt;

	close(0);
	close(1);
	close(2);
	switch (fork()) {
	case -1:
		perror("fork");
		break;
	case 0:
		break;
	default:
		exit(0);
	}
	tt = open("/dev/tty", O_RDWR, 0);
	if (tt >= 0) {
		ioctl(tt, TIOCNOTTY, 0);
		close(tt);
	}
	open("/dev/null", O_RDWR, 0);
	dup(0);
	dup(0);
}

void
ypupdate_prog(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct ypupdate_args args;
	uint_t rslt;
	uint_t op;
	char *netname;
	char namebuf[MAXNETNAMELEN+1];
	struct authunix_parms *aup;

	CTASSERT(sizeof (struct authdes_cred) <= RQCRED_SIZE);
	CTASSERT(sizeof (struct authunix_parms) <= RQCRED_SIZE);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		svc_sendreply(transp, xdr_void, NULL);
		return;
	case YPU_CHANGE:
		op = YPOP_CHANGE;
		break;
	case YPU_DELETE:
		op = YPOP_DELETE;
		break;
	case YPU_INSERT:
		op = YPOP_INSERT;
		break;
	case YPU_STORE:
		op = YPOP_STORE;
		break;
	default:
		svcerr_noproc(transp);
		return;
	}

	switch (rqstp->rq_cred.oa_flavor) {
	case AUTH_DES:
		netname = ((struct authdes_cred *)
		    rqstp->rq_clntcred)->adc_fullname.name;
		break;
	case AUTH_UNIX:
		if (insecure) {
			aup = (struct authunix_parms *)rqstp->rq_clntcred;
			if (aup->aup_uid == 0) {
			/*
			 *	addr2netname(namebuf, svc_getcaller(transp));
			 */
				addr2netname(namebuf, transp);
			} else {
				user2netname(namebuf, aup->aup_uid, NULL);
			}
			netname = namebuf;
			break;
		}
		/* FALLTHROUGH */
	default:
		svcerr_weakauth(transp);
		return;
	}
	bzero(&args, sizeof (args));
	if (!svc_getargs(transp, xdr_ypupdate_args, (caddr_t)&args)) {
		svcerr_decode(transp);
		return;
	}
	rslt = update(netname,
	    args.mapname, op, args.key.yp_buf_len, args.key.yp_buf_val,
	    args.datum.yp_buf_len, args.datum.yp_buf_val);
	if (!svc_sendreply(transp, xdr_u_int, (const caddr_t)&rslt)) {
		debug("svc_sendreply failed");
	}
	if (!svc_freeargs(transp, xdr_ypupdate_args, (caddr_t)&args)) {
		debug("svc_freeargs failed");
	}
}

/*
 * Determine if requester is allowed to update the given map,
 * and update it if so. Returns the NIS status, which is zero
 * if there is no access violation.
 */
int
update(char *requester, char *mapname, uint_t op, uint_t keylen, char *key,
    uint_t datalen, char *data)
{
	char updater[MAXMAPNAMELEN + 40];
	FILE *childargs;
	FILE *childrslt;
	int status;
	int yperrno;
	int pid;
	char default_domain[YPMAXDOMAIN];
	int err;
	char fake_key[10];
	char *outval = NULL;
	int outval_len;

	if (getdomainname(default_domain, YPMAXDOMAIN)) {
		debug("Couldn't get default domain name");
		return (YPERR_YPERR);
	}

	/* check to see if we have a valid mapname */
	strncpy(fake_key, "junk", 4);
	err = yp_match(default_domain, mapname,
	    fake_key, strlen(fake_key), &outval, &outval_len);
	switch (err) {
		case 0:
		case YPERR_KEY:
			/* do nothing, only worry about above return code */
			break;
		default:
			/* defensive programming */
			return (YPERR_YPERR);
			break;
	}

	/* valid map - continue */
	sprintf(updater, "make -s -f %s %s", UPDATEFILE, mapname);
	pid = _openchild(updater, &childargs, &childrslt);
	if (pid < 0) {
		debug("openpipes failed");
		return (YPERR_YPERR);
	}

	/*
	 * Write to child
	 */
	fprintf(childargs, "%s\n", requester);
	fprintf(childargs, "%u\n", op);
	fprintf(childargs, "%u\n", keylen);
	fwrite(key, keylen, 1, childargs);
	fprintf(childargs, "\n");
	fprintf(childargs, "%u\n", datalen);
	fwrite(data, datalen, 1, childargs);
	fprintf(childargs, "\n");
	fclose(childargs);

	/*
	 * Read from child
	 */
	fscanf(childrslt, "%d", &yperrno);
	fclose(childrslt);

	wait(&status);
	if (!WIFEXITED(status)) {
		return (YPERR_YPERR);
	}
	return (yperrno);
}

#if 0
addr2netname(char *namebuf, struct sockaddr_in *addr)
{
	struct hostent *h;

	h = gethostbyaddr((const char *) &addr->sin_addr,
	    sizeof (addr->sin_addr), AF_INET);
	if (h == NULL) {
		host2netname(namebuf, (const char *) inet_ntoa(addr->sin_addr),
		    NULL);
	} else {
		host2netname(namebuf, h->h_name, NULL);
	}
}
#endif


static int
addr2netname(char *namebuf, SVCXPRT *transp)
{
	struct nd_hostservlist *hostservs = NULL;
	struct netconfig *nconf;
	struct netbuf *who;

	who = svc_getrpccaller(transp);
	if ((who == NULL) || (who->len == 0))
		return (-1);
	if ((nconf = getnetconfigent(transp->xp_netid)) == NULL)
		return (-1);
	if (netdir_getbyaddr(nconf, &hostservs, who) != 0) {
		(void) freenetconfigent(nconf);
		return (-1);
	}
	if (hostservs != NULL)
		strcpy(namebuf, hostservs->h_hostservs->h_host);

	(void) freenetconfigent(nconf);
	netdir_free((char *)hostservs, ND_HOSTSERVLIST);
	return (0);
}
