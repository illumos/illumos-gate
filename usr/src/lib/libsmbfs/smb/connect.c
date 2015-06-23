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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Functions to setup connections (TCP and/or NetBIOS)
 * This has the fall-back logic for IP6, IP4, NBT
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "private.h"

/*
 * SMB messages are up to 64K.
 * Let's leave room for two.
 */
static int smb_tcpsndbuf = 0x20000;
static int smb_tcprcvbuf = 0x20000;
static int smb_connect_timeout = 30; /* seconds */
int smb_recv_timeout = 30; /* seconds */

int conn_tcp6(struct smb_ctx *, const struct sockaddr *, int);
int conn_tcp4(struct smb_ctx *, const struct sockaddr *, int);
int conn_nbt(struct smb_ctx *, const struct sockaddr *, char *);

/*
 * Internal set sockopt for int-sized options.
 * Borrowed from: libnsl/rpc/ti_opts.c
 */
static int
smb_setopt_int(int fd, int level, int name, int val)
{
	struct t_optmgmt oreq, ores;
	struct {
		struct t_opthdr oh;
		int ival;
	} opts;

	/* opt header */
	opts.oh.len = sizeof (opts);
	opts.oh.level = level;
	opts.oh.name = name;
	opts.oh.status = 0;
	opts.ival = val;

	oreq.flags = T_NEGOTIATE;
	oreq.opt.buf = (void *)&opts;
	oreq.opt.len = sizeof (opts);

	ores.flags = 0;
	ores.opt.buf = NULL;
	ores.opt.maxlen = 0;

	if (t_optmgmt(fd, &oreq, &ores) < 0) {
		DPRINT("t_opgmgnt, t_errno = %d", t_errno);
		if (t_errno == TSYSERR)
			return (errno);
		return (EPROTO);
	}
	if (ores.flags != T_SUCCESS) {
		DPRINT("flags 0x%x, status 0x%x",
		    (int)ores.flags, (int)opts.oh.status);
		return (EPROTO);
	}

	return (0);
}

static int
smb_setopts(int fd)
{
	int err;

	/*
	 * Set various socket/TCP options.
	 * Failures here are not fatal -
	 * just log a complaint.
	 *
	 * We don't need these two:
	 *   SO_RCVTIMEO, SO_SNDTIMEO
	 */

	err = smb_setopt_int(fd, SOL_SOCKET, SO_SNDBUF, smb_tcpsndbuf);
	if (err) {
		DPRINT("set SO_SNDBUF, err %d", err);
	}

	err = smb_setopt_int(fd, SOL_SOCKET, SO_RCVBUF, smb_tcprcvbuf);
	if (err) {
		DPRINT("set SO_RCVBUF, err %d", err);
	}

	err = smb_setopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
	if (err) {
		DPRINT("set SO_KEEPALIVE, err %d", err);
	}

	err = smb_setopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);
	if (err) {
		DPRINT("set TCP_NODELAY, err %d", err);
	}

	/* Set the connect timeout (in milliseconds). */
	err = smb_setopt_int(fd, IPPROTO_TCP,
	    TCP_CONN_ABORT_THRESHOLD,
	    smb_connect_timeout * 1000);
	if (err) {
		DPRINT("set connect timeout, err %d", err);
	}
	return (0);
}


int
conn_tcp6(struct smb_ctx *ctx, const struct sockaddr *sa, int port)
{
	struct sockaddr_in6 sin6;
	char *dev = "/dev/tcp6";
	char paddrbuf[INET6_ADDRSTRLEN];
	struct t_call sndcall;
	int fd, err;

	if (sa->sa_family != AF_INET6) {
		DPRINT("bad af %d", sa->sa_family);
		return (EINVAL);
	}
	bcopy(sa, &sin6, sizeof (sin6));
	sin6.sin6_port = htons(port);

	DPRINT("tcp6: %s (%d)",
	    inet_ntop(AF_INET6, &sin6.sin6_addr,
	    paddrbuf, sizeof (paddrbuf)), port);

	fd = t_open(dev, O_RDWR, NULL);
	if (fd < 0) {
		/* Assume t_errno = TSYSERR */
		err = errno;
		perror(dev);
		return (err);
	}
	if ((err = smb_setopts(fd)) != 0)
		goto errout;
	if (t_bind(fd, NULL, NULL) < 0) {
		DPRINT("t_bind t_errno %d", t_errno);
		if (t_errno == TSYSERR)
			err = errno;
		else
			err = EPROTO;
		goto errout;
	}
	sndcall.addr.maxlen = sizeof (sin6);
	sndcall.addr.len = sizeof (sin6);
	sndcall.addr.buf = (void *) &sin6;
	sndcall.opt.len = 0;
	sndcall.udata.len = 0;
	if (t_connect(fd, &sndcall, NULL) < 0) {
		err = get_xti_err(fd);
		DPRINT("connect, err %d", err);
		goto errout;
	}

	DPRINT("tcp6: connected, fd=%d", fd);
	ctx->ct_tran_fd = fd;
	return (0);

errout:
	close(fd);
	return (err);
}

/*
 * This is used for both SMB over TCP (port 445)
 * and NetBIOS - see conn_nbt().
 */
int
conn_tcp4(struct smb_ctx *ctx, const struct sockaddr *sa, int port)
{
	struct sockaddr_in sin;
	char *dev = "/dev/tcp";
	char paddrbuf[INET_ADDRSTRLEN];
	struct t_call sndcall;
	int fd, err;

	if (sa->sa_family != AF_INET) {
		DPRINT("bad af %d", sa->sa_family);
		return (EINVAL);
	}
	bcopy(sa, &sin, sizeof (sin));
	sin.sin_port = htons(port);

	DPRINT("tcp4: %s (%d)",
	    inet_ntop(AF_INET, &sin.sin_addr,
	    paddrbuf, sizeof (paddrbuf)), port);

	fd = t_open(dev, O_RDWR, NULL);
	if (fd < 0) {
		/* Assume t_errno = TSYSERR */
		err = errno;
		perror(dev);
		return (err);
	}
	if ((err = smb_setopts(fd)) != 0)
		goto errout;
	if (t_bind(fd, NULL, NULL) < 0) {
		DPRINT("t_bind t_errno %d", t_errno);
		if (t_errno == TSYSERR)
			err = errno;
		else
			err = EPROTO;
		goto errout;
	}
	sndcall.addr.maxlen = sizeof (sin);
	sndcall.addr.len = sizeof (sin);
	sndcall.addr.buf = (void *) &sin;
	sndcall.opt.len = 0;
	sndcall.udata.len = 0;
	if (t_connect(fd, &sndcall, NULL) < 0) {
		err = get_xti_err(fd);
		DPRINT("connect, err %d", err);
		goto errout;
	}

	DPRINT("tcp4: connected, fd=%d", fd);
	ctx->ct_tran_fd = fd;
	return (0);

errout:
	close(fd);
	return (err);
}

/*
 * Open a NetBIOS connection (session, port 139)
 *
 * The optional name parameter, if passed, means
 * we found the sockaddr via NetBIOS name lookup,
 * and can just use that for our session request.
 * Otherwise (if name is NULL), we're connecting
 * by IP address, and need to come up with the
 * NetBIOS name by other means.
 */
int
conn_nbt(struct smb_ctx *ctx, const struct sockaddr *saarg, char *name)
{
	struct sockaddr_in sin;
	struct sockaddr *sa;
	char server[NB_NAMELEN];
	char workgroup[NB_NAMELEN];
	int err, nberr, port;

	bcopy(saarg, &sin, sizeof (sin));
	sa = (struct sockaddr *)&sin;

	switch (sin.sin_family) {
	case AF_NETBIOS:	/* our fake AF */
		sin.sin_family = AF_INET;
		break;
	case AF_INET:
		break;
	default:
		DPRINT("bad af %d", sin.sin_family);
		return (EINVAL);
	}
	port = IPPORT_NETBIOS_SSN;

	/*
	 * If we have a NetBIOS name, just use it.
	 * This is the path taken when we've done a
	 * NetBIOS name lookup on this name to get
	 * the IP address in the passed sa. Otherwise,
	 * we're connecting by IP address, and need to
	 * figure out what NetBIOS name to use.
	 */
	if (name) {
		strlcpy(server, name, sizeof (server));
		DPRINT("given name: %s", server);
	} else {
		/*
		 *
		 * Try a NetBIOS node status query,
		 * which searches for a type=[20] name.
		 * If that doesn't work, just use the
		 * (fake) "*SMBSERVER" name.
		 */
		DPRINT("try node status");
		server[0] = '\0';
		nberr = nbns_getnodestatus(ctx->ct_nb,
		    &sin.sin_addr, server, workgroup);
		if (nberr == 0 && server[0] != '\0') {
			/* Found the name.  Save for reconnect. */
			DPRINT("found name: %s", server);
			strlcpy(ctx->ct_srvname, server,
			    sizeof (ctx->ct_srvname));
		} else {
			DPRINT("getnodestatus, nberr %d", nberr);
			strlcpy(server, "*SMBSERVER", sizeof (server));
		}
	}

	/*
	 * Establish the TCP connection.
	 * Careful to close it on errors.
	 */
	if ((err = conn_tcp4(ctx, sa, port)) != 0) {
		DPRINT("TCP connect: err=%d", err);
		goto out;
	}

	/* Connected.  Do NetBIOS session request. */
	err = nb_ssn_request(ctx, server);
	if (err)
		DPRINT("ssn_rq, err %d", err);

out:
	if (err) {
		if (ctx->ct_tran_fd != -1) {
			close(ctx->ct_tran_fd);
			ctx->ct_tran_fd = -1;
		}
	}
	return (err);
}

/*
 * Make a new connection, or reconnect.
 */
int
smb_iod_connect(smb_ctx_t *ctx)
{
	struct sockaddr *sa;
	int err, err2;
	struct mbdata blob;

	memset(&blob, 0, sizeof (blob));

	if (ctx->ct_srvname[0] == '\0') {
		DPRINT("sername not set!");
		return (EINVAL);
	}
	DPRINT("server: %s", ctx->ct_srvname);

	if (smb_debug)
		dump_ctx("smb_iod_connect", ctx);

	/*
	 * This may be a reconnect, so
	 * cleanup if necessary.
	 */
	if (ctx->ct_tran_fd != -1) {
		close(ctx->ct_tran_fd);
		ctx->ct_tran_fd = -1;
	}

	/*
	 * Get local machine name.
	 * Full name - not a NetBIOS name.
	 */
	if (ctx->ct_locname == NULL) {
		err = smb_getlocalname(&ctx->ct_locname);
		if (err) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "can't get local name"), err);
			return (err);
		}
	}

	/*
	 * We're called with each IP address
	 * already copied into ct_srvaddr.
	 */
	ctx->ct_flags |= SMBCF_RESOLVED;

	sa = &ctx->ct_srvaddr.sa;
	switch (sa->sa_family) {

	case AF_INET6:
		err = conn_tcp6(ctx, sa, IPPORT_SMB);
		break;

	case AF_INET:
		err = conn_tcp4(ctx, sa, IPPORT_SMB);
		/*
		 * If port 445 was not listening, try port 139.
		 * Note: Not doing NetBIOS name lookup here.
		 * We already have the IP address.
		 */
		switch (err) {
		case ECONNRESET:
		case ECONNREFUSED:
			err2 = conn_nbt(ctx, sa, NULL);
			if (err2 == 0)
				err = 0;
		}
		break;

	case AF_NETBIOS:
		/* Like AF_INET, but use NetBIOS ssn. */
		err = conn_nbt(ctx, sa, ctx->ct_srvname);
		break;

	default:
		DPRINT("skipped family %d", sa->sa_family);
		err = EPROTONOSUPPORT;
		break;
	}


	if (err) {
		DPRINT("connect, err=%d", err);
		return (err);
	}

	/*
	 * Do SMB Negotiate Protocol.
	 */
	err = smb_negprot(ctx, &blob);
	if (err)
		goto out;

	/*
	 * Empty user name means an explicit request for
	 * NULL session setup, which is a special case.
	 * If negotiate determined that we want to do
	 * SMB signing, we have to turn that off for a
	 * NULL session. [MS-SMB 3.3.5.3].
	 */
	if (ctx->ct_user[0] == '\0') {
		/* Null user should have null domain too. */
		ctx->ct_domain[0] = '\0';
		ctx->ct_authflags = SMB_AT_ANON;
		ctx->ct_clnt_caps &= ~SMB_CAP_EXT_SECURITY;
		ctx->ct_vcflags &= ~SMBV_WILL_SIGN;
	}

	/*
	 * Do SMB Session Setup (authenticate)
	 *
	 * If the server negotiated extended security,
	 * run the SPNEGO state machine, otherwise do
	 * one of the old-style variants.
	 */
	if (ctx->ct_clnt_caps & SMB_CAP_EXT_SECURITY) {
		err = smb_ssnsetup_spnego(ctx, &blob);
	} else {
		/*
		 * Server did NOT negotiate extended security.
		 * Try NTLMv2, NTLMv1, or ANON (if enabled).
		 */
		if (ctx->ct_authflags & SMB_AT_NTLM2) {
			err = smb_ssnsetup_ntlm2(ctx);
		} else if (ctx->ct_authflags & SMB_AT_NTLM1) {
			err = smb_ssnsetup_ntlm1(ctx);
		} else if (ctx->ct_authflags & SMB_AT_ANON) {
			err = smb_ssnsetup_null(ctx);
		} else {
			/*
			 * Don't return EAUTH, because a new
			 * password prompt will not help.
			 */
			DPRINT("No NTLM authflags");
			err = ENOTSUP;
		}
	}

out:
	mb_done(&blob);

	if (err) {
		close(ctx->ct_tran_fd);
		ctx->ct_tran_fd = -1;
	} else {
		/* Tell library code we have a session. */
		ctx->ct_flags |= SMBCF_SSNACTIVE;
		DPRINT("tran_fd = %d", ctx->ct_tran_fd);
	}

	return (err);
}
