/*
 * Copyright (c) 2000, 2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: nb.c,v 1.1.1.2 2001/07/06 22:38:42 conrad Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <cflib.h>
#include <netsmb/netbios.h>
#include <netsmb/smb_lib.h>
#include <netsmb/nb_lib.h>

int nb_ctx_setwins(struct nb_ctx *, const char *, const char *);


/*
 * API for library consumer to set wins1, wins2
 */
int
smb_ctx_setwins(struct smb_ctx *ctx, const char *wins1, const char *wins2)
{
	struct nb_ctx *nb = ctx->ct_nb;

	if (nb == NULL)
		return (EINVAL);

	return (nb_ctx_setwins(nb, wins1, wins2));
}

/*
 * API for library consumer to set NB scope.
 */
int
smb_ctx_setscope(struct smb_ctx *ctx, const char *scope)
{
	struct nb_ctx *nb = ctx->ct_nb;

	if (nb == NULL)
		return (EINVAL);

	return (nb_ctx_setscope(nb, scope));
}

int
nb_ctx_create(struct nb_ctx **ctxpp)
{
	struct nb_ctx *ctx;

	ctx = malloc(sizeof (struct nb_ctx));
	if (ctx == NULL)
		return (ENOMEM);
	bzero(ctx, sizeof (struct nb_ctx));
	ctx->nb_flags = NBCF_NS_ENABLE | NBCF_BC_ENABLE;
	*ctxpp = ctx;
	return (0);
}

void
nb_ctx_done(struct nb_ctx *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->nb_scope)
		free(ctx->nb_scope);
	if (ctx)
		free(ctx);
}

int
nb_ctx_setwins(struct nb_ctx *ctx, const char *wins1, const char *wins2)
{
	struct in_addr ina;
	int error;

	if (wins1 == NULL) {
		ctx->nb_wins1 = 0;
		ctx->nb_wins2 = 0;
		return (0);
	}

	error = nb_resolvehost_in(wins1, &ina);
	if (error) {
		smb_error(dgettext(TEXT_DOMAIN, "can't resolve %s"),
		    error, wins1);
		return (error);
	}
	ctx->nb_wins1 = ina.s_addr;

	if (wins2 == NULL)
		ctx->nb_wins2 = 0;
	else {
		error = nb_resolvehost_in(wins2, &ina);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN, "can't resolve %s"),
			    error, wins2);
			return (error);
		}
		ctx->nb_wins2 = ina.s_addr;
	}
	return (0);
}

/*
 * This is called by "smbutil lookup" to handle the
 * "-w wins_server" option.  Let the semantics of
 * this option be: Use specified WINS server only.
 * If specified server is the broadcast address,
 * set broadcast mode (and no WINS servers).
 */
int
nb_ctx_setns(struct nb_ctx *ctx, const char *addr)
{
	int error;

	error = nb_ctx_setwins(ctx, addr, NULL);
	if (error)
		return (error);

	/* Deal with explicit request for broadcast. */
	if (ctx->nb_wins1 == INADDR_BROADCAST) {
		ctx->nb_wins1 = 0;
		ctx->nb_flags |= NBCF_BC_ENABLE;
	}
	return (0);
}

int
nb_ctx_setscope(struct nb_ctx *ctx, const char *scope)
{
	size_t slen = strlen(scope);

	if (slen >= 128) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "scope '%s' is too long"), 0, scope);
		return (ENAMETOOLONG);
	}
	if (ctx->nb_scope)
		free(ctx->nb_scope);
	ctx->nb_scope = malloc(slen + 1);
	if (ctx->nb_scope == NULL)
		return (ENOMEM);
	nls_str_upper(ctx->nb_scope, scope);
	return (0);
}

/*
 * Now get the WINS server IP addresses directly
 * when reading the RC files, so no longer need to
 * lookup any names here.
 */
int
nb_ctx_resolve(struct nb_ctx *ctx)
{
	ctx->nb_flags |= NBCF_RESOLVED;
	return (0);
}

/*
 * used level values:
 * 0 - default
 * 1 - server
 *
 * All of these are normally system-wide settings;
 * the checks are in rc_parse() in rcfile.c.
 */
int
nb_ctx_readrcsection(struct rcfile *rcfile, struct nb_ctx *ctx,
	const char *sname, int level)
{
	char *wins1, *wins2;
	int error;
	int nbns_enable;
	int nbns_broadcast;

	if (level > 1)
		return (EINVAL);

	/* External callers pass NULL to get the default. */
	if (rcfile == NULL)
		rcfile = smb_rc;

#ifdef NOT_DEFINED
	rc_getint(rcfile, sname, "nbtimeout", &ctx->nb_timo);
	rc_getstringptr(rcfile, sname, "nbscope", &p);
	if (p)
		nb_ctx_setscope(ctx, p);
#endif
	/*
	 * Get "wins1", "wins2" config strings.
	 * Also support legacy "nbns".
	 */
	rc_getstringptr(rcfile, sname, "wins1", &wins1);
	if (wins1 == NULL)
		rc_getstringptr(rcfile, sname, "nbns", &wins1);
	rc_getstringptr(rcfile, sname, "wins2", &wins2);

	if (wins1 != NULL) {
		error = nb_ctx_setwins(ctx, wins1, wins2);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "invalid address specified in the section %s"),
			    0, sname);
			return (error);
		}
	}
	error = rc_getbool(rcfile, sname, "nbns_enable", &nbns_enable);
	if (error == 0 && nbns_enable == 0)
		ctx->nb_flags &= ~NBCF_NS_ENABLE;
	error = rc_getbool(rcfile, sname, "nbns_broadcast", &nbns_broadcast);
	if (error == 0 && nbns_broadcast == 0)
		ctx->nb_flags &= ~NBCF_BC_ENABLE;
	return (0);
}

#ifdef I18N	/* never defined, permits xgettext(1) to pick out strings */
static const char *nb_err_rcode[] = {
	gettext("bad request/response format"),
	gettext("NBNS server failure"),
	gettext("no such name"),
	gettext("unsupported request"),
	gettext("request rejected"),
	gettext("name already registered)"
};

static const char *nb_err[] = {
	gettext("host not found"),
	gettext("too many redirects"),
	gettext("invalid response"),
	gettext("NETBIOS name too long"),
	gettext("no interface to broadcast on and no NBNS server specified")
};
#else
static const char *nb_err_rcode[] = {
	"bad request/response format",
	"NBNS server failure",
	"no such name",
	"unsupported request",
	"request rejected",
	"name already registered"
};

static const char *nb_err[] = {
	"host not found",
	"too many redirects",
	"invalid response",
	"NETBIOS name too long",
	"no interface to broadcast on and no NBNS server specified"
};
#endif

const char *
nb_strerror(int error)
{
	if (error == 0)
		return (NULL);
	if (error <= NBERR_ACTIVE)
		return (nb_err_rcode[error - 1]);
	else if (error >= NBERR_HOSTNOTFOUND && error < NBERR_MAX)
		return (nb_err[error - NBERR_HOSTNOTFOUND]);
	else
		return (NULL);
}
