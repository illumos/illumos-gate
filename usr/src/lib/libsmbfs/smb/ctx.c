/*
 * Copyright (c) 2000, Boris Popov
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
 * $Id: ctx.c,v 1.32.70.2 2005/06/02 00:55:40 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/byteorder.h>

#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <libintl.h>
#include <assert.h>
#include <nss_dbdefs.h>

#include <cflib.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "private.h"
#include "ntlm.h"

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

#define	SMB_AT_DEFAULT	(SMB_AT_KRB5 | SMB_AT_NTLM2)
#define	SMB_AT_MINAUTH	(SMB_AT_KRB5 | SMB_AT_NTLM2 | SMB_AT_NTLM1)

struct nv {
	char *name;
	int value;
};

/* These two may be set by commands. */
int smb_debug, smb_verbose;

/*
 * Was: STDPARAM_OPT - see smb_ctx_scan_argv, smb_ctx_opt
 */
const char smbutil_std_opts[] = "ABCD:E:I:L:M:NO:P:U:R:S:T:W:";

/*
 * Defaults for new contexts (connections to servers).
 * These are set by smbfs_set_default_...
 */
static char default_domain[SMBIOC_MAX_NAME];
static char default_user[SMBIOC_MAX_NAME];


/*
 * Give the RPC library a callback hook that will be
 * called whenever we destroy or reinit an smb_ctx_t.
 * The name rpc_cleanup_smbctx() is legacy, and was
 * originally a direct call into the RPC code.
 */
static smb_ctx_close_hook_t close_hook;
static void
rpc_cleanup_smbctx(struct smb_ctx *ctx)
{
	if (close_hook)
		(*close_hook)(ctx);
}
void
smb_ctx_set_close_hook(smb_ctx_close_hook_t hook)
{
	close_hook = hook;
}

void
dump_ctx_flags(int flags)
{
	printf(" Flags: ");
	if (flags == 0)
		printf("0");
	if (flags & SMBCF_NOPWD)
		printf("NOPWD ");
	if (flags & SMBCF_SRIGHTS)
		printf("SRIGHTS ");
	if (flags & SMBCF_LOCALE)
		printf("LOCALE ");
	if (flags & SMBCF_CMD_DOM)
		printf("CMD_DOM ");
	if (flags & SMBCF_CMD_USR)
		printf("CMD_USR ");
	if (flags & SMBCF_CMD_PW)
		printf("CMD_PW ");
	if (flags & SMBCF_RESOLVED)
		printf("RESOLVED ");
	if (flags & SMBCF_KCBAD)
		printf("KCBAD ");
	if (flags & SMBCF_KCFOUND)
		printf("KCFOUND ");
	if (flags & SMBCF_BROWSEOK)
		printf("BROWSEOK ");
	if (flags & SMBCF_AUTHREQ)
		printf("AUTHREQ ");
	if (flags & SMBCF_KCSAVE)
		printf("KCSAVE  ");
	if (flags & SMBCF_XXX)
		printf("XXX ");
	if (flags & SMBCF_SSNACTIVE)
		printf("SSNACTIVE ");
	if (flags & SMBCF_KCDOMAIN)
		printf("KCDOMAIN ");
	printf("\n");
}

void
dump_iod_ssn(smb_iod_ssn_t *is)
{
	static const char zeros[NTLM_HASH_SZ] = {0};
	struct smbioc_ossn *ssn = &is->iod_ossn;

	printf(" ct_srvname=\"%s\", ", ssn->ssn_srvname);
	dump_sockaddr(&ssn->ssn_srvaddr.sa);
	printf(" dom=\"%s\", user=\"%s\"\n",
	    ssn->ssn_domain, ssn->ssn_user);
	printf(" ct_vopt=0x%x, ct_owner=%d\n",
	    ssn->ssn_vopt, ssn->ssn_owner);
	printf(" ct_authflags=0x%x\n", is->iod_authflags);

	printf(" ct_nthash:");
	if (bcmp(zeros, &is->iod_nthash, NTLM_HASH_SZ))
		smb_hexdump(&is->iod_nthash, NTLM_HASH_SZ);
	else
		printf(" {0}\n");

	printf(" ct_lmhash:");
	if (bcmp(zeros, &is->iod_lmhash, NTLM_HASH_SZ))
		smb_hexdump(&is->iod_lmhash, NTLM_HASH_SZ);
	else
		printf(" {0}\n");
}

void
dump_ctx(char *where, struct smb_ctx *ctx)
{
	printf("context %s:\n", where);
	dump_ctx_flags(ctx->ct_flags);

	if (ctx->ct_locname)
		printf(" localname=\"%s\"", ctx->ct_locname);
	else
		printf(" localname=NULL");

	if (ctx->ct_fullserver)
		printf(" fullserver=\"%s\"", ctx->ct_fullserver);
	else
		printf(" fullserver=NULL");

	if (ctx->ct_srvaddr_s)
		printf(" srvaddr_s=\"%s\"\n", ctx->ct_srvaddr_s);
	else
		printf(" srvaddr_s=NULL\n");

	if (ctx->ct_addrinfo)
		dump_addrinfo(ctx->ct_addrinfo);
	else
		printf(" ct_addrinfo = NULL\n");

	dump_iod_ssn(&ctx->ct_iod_ssn);

	printf(" share_name=\"%s\", share_type=%d\n",
	    ctx->ct_origshare ? ctx->ct_origshare : "",
	    ctx->ct_shtype_req);

	printf(" ct_home=\"%s\"\n", ctx->ct_home);
	printf(" ct_rpath=\"%s\"\n", ctx->ct_rpath);
}

int
smb_ctx_alloc(struct smb_ctx **ctx_pp)
{
	smb_ctx_t *ctx;
	int err;

	ctx = malloc(sizeof (*ctx));
	if (ctx == NULL)
		return (ENOMEM);
	err = smb_ctx_init(ctx);
	if (err != 0) {
		free(ctx);
		return (err);
	}
	*ctx_pp = ctx;
	return (0);
}

/*
 * Initialize an smb_ctx struct (defaults)
 */
int
smb_ctx_init(struct smb_ctx *ctx)
{
	int error;

	bzero(ctx, sizeof (*ctx));

	error = nb_ctx_create(&ctx->ct_nb);
	if (error)
		return (error);

	ctx->ct_dev_fd = -1;
	ctx->ct_door_fd = -1;
	ctx->ct_tran_fd = -1;
	ctx->ct_parsedlevel = SMBL_NONE;
	ctx->ct_minlevel = SMBL_NONE;
	ctx->ct_maxlevel = SMBL_PATH;

	/* Fill in defaults */
	ctx->ct_vopt = SMBVOPT_EXT_SEC;
	ctx->ct_owner = SMBM_ANY_OWNER;
	ctx->ct_authflags = SMB_AT_DEFAULT;
	ctx->ct_minauth = SMB_AT_MINAUTH;

	/*
	 * Default domain, user, ...
	 */
	strlcpy(ctx->ct_domain, default_domain,
	    sizeof (ctx->ct_domain));
	strlcpy(ctx->ct_user, default_user,
	    sizeof (ctx->ct_user));

	return (0);
}

/*
 * "Scan" the command line args to find the server name,
 * user name, and share name, as needed.  We need these
 * before reading the RC files and/or sharectl values.
 *
 * The sequence for getting all the members filled in
 * has some tricky aspects.  Here's how it works:
 *
 * The search order for options is as follows:
 *   command line options
 *   values parsed from UNC path (cmd)
 *   values from RC file (per-user)
 *   values from SMF (system-wide)
 *   built-in defaults
 *
 * Normally, one would simply get all the values starting with
 * the bottom of the above list and working to the top, and
 * overwriting values as you go.  But we need an exception.
 *
 * In this function, we parse the UNC path and command line options,
 * because we need (at least) the server name when we're getting the
 * SMF and RC file values.  However, values we get from the command
 * should not be overwritten by SMF or RC file parsing, so we mark
 * values from the command as "from CMD" and the RC file parser
 * leaves in place any values so marked.  See: SMBCF_CMD_*
 *
 * The semantics of these flags are: "This value came from the
 * current command instance, not from sources that may apply to
 * multiple commands."  (Different from the old "FROMUSR" flag.)
 *
 * Note that smb_ctx_opt() is called later to handle the
 * remaining options, which should be ignored here.
 * The (magic) leading ":" in cf_getopt() makes it
 * ignore options not in the options string.
 */
int
smb_ctx_scan_argv(struct smb_ctx *ctx, int argc, char **argv,
	int minlevel, int maxlevel, int sharetype)
{
	int  ind, opt, error = 0;
	int aflg = 0, uflg = 0;
	const char *arg;

	/*
	 * Parse options, if any.  Values from here too
	 * are marked as "from CMD".
	 */
	if (argv == NULL)
		return (0);

	ctx->ct_minlevel = minlevel;
	ctx->ct_maxlevel = maxlevel;
	ctx->ct_shtype_req = sharetype;

	cf_opt_lock();
	/* Careful: no return/goto before cf_opt_unlock! */
	while (error == 0) {
		opt = cf_getopt(argc, argv, STDPARAM_OPT);
		if (opt == -1)
			break;
		arg = cf_optarg;
		/* NB: handle most in smb_ctx_opt */
		switch (opt) {
		case 'A':
			aflg = 1;
			error = smb_ctx_setuser(ctx, "", TRUE);
			ctx->ct_flags |= SMBCF_NOPWD;
			break;
		case 'U':
			uflg = 1;
			error = smb_ctx_setuser(ctx, arg, TRUE);
			break;
		default:
			DPRINT("skip opt=%c", opt);
			break;
		}
	}
	ind = cf_optind;
	arg = argv[ind];
	cf_optind = cf_optreset = 1;
	cf_opt_unlock();

	if (error)
		return (error);

	if (aflg && uflg)  {
		printf(gettext("-A and -U flags are exclusive.\n"));
		return (EINVAL);
	}

	/*
	 * Parse the UNC path.  Values from here are
	 * marked as "from CMD".
	 */
	for (; ind < argc; ind++) {
		arg = argv[ind];
		if (strncmp(arg, "//", 2) != 0)
			continue;
		error = smb_ctx_parseunc(ctx, arg,
		    minlevel, maxlevel, sharetype, &arg);
		if (error)
			return (error);
		break;
	}

	return (error);
}

void
smb_ctx_free(smb_ctx_t *ctx)
{
	smb_ctx_done(ctx);
	free(ctx);
}

void
smb_ctx_done(struct smb_ctx *ctx)
{

	rpc_cleanup_smbctx(ctx);

	if (ctx->ct_dev_fd != -1) {
		close(ctx->ct_dev_fd);
		ctx->ct_dev_fd = -1;
	}
	if (ctx->ct_door_fd != -1) {
		close(ctx->ct_door_fd);
		ctx->ct_door_fd = -1;
	}
	if (ctx->ct_tran_fd != -1) {
		close(ctx->ct_tran_fd);
		ctx->ct_tran_fd = -1;
	}
	if (ctx->ct_srvaddr_s) {
		free(ctx->ct_srvaddr_s);
		ctx->ct_srvaddr_s = NULL;
	}
	if (ctx->ct_nb) {
		nb_ctx_done(ctx->ct_nb);
		ctx->ct_nb = NULL;
	}
	if (ctx->ct_locname) {
		free(ctx->ct_locname);
		ctx->ct_locname = NULL;
	}
	if (ctx->ct_origshare) {
		free(ctx->ct_origshare);
		ctx->ct_origshare = NULL;
	}
	if (ctx->ct_fullserver) {
		free(ctx->ct_fullserver);
		ctx->ct_fullserver = NULL;
	}
	if (ctx->ct_addrinfo) {
		freeaddrinfo(ctx->ct_addrinfo);
		ctx->ct_addrinfo = NULL;
	}
	if (ctx->ct_home) {
		free(ctx->ct_home);
		ctx->ct_home = NULL;
	}
	if (ctx->ct_rpath) {
		free(ctx->ct_rpath);
		ctx->ct_rpath = NULL;
	}
	if (ctx->ct_srv_OS) {
		free(ctx->ct_srv_OS);
		ctx->ct_srv_OS = NULL;
	}
	if (ctx->ct_srv_LM) {
		free(ctx->ct_srv_LM);
		ctx->ct_srv_LM = NULL;
	}
	if (ctx->ct_mackey) {
		free(ctx->ct_mackey);
		ctx->ct_mackey = NULL;
	}
}

/*
 * Parse the UNC path.  Here we expect something like
 *   "//[[domain;]user[:password]@]host[/share[/path]]"
 * See http://ietf.org/internet-drafts/draft-crhertel-smb-url-07.txt
 * Values found here are marked as "from CMD".
 */
int
smb_ctx_parseunc(struct smb_ctx *ctx, const char *unc,
	int minlevel, int maxlevel, int sharetype,
	const char **next)
{
	char tmp[1024];
	char *host, *share, *path;
	char *dom, *usr, *pw, *p;
	int error;

	/*
	 * This may be called outside of _scan_argv,
	 * so make sure these get initialized.
	 */
	ctx->ct_minlevel = minlevel;
	ctx->ct_maxlevel = maxlevel;
	ctx->ct_shtype_req = sharetype;
	ctx->ct_parsedlevel = SMBL_NONE;

	dom = usr = pw = host = NULL;

	/* Work on a temporary copy, fix back slashes. */
	strlcpy(tmp, unc, sizeof (tmp));
	for (p = tmp; *p; p++)
		if (*p == '\\')
			*p = '/';

	if (tmp[0] != '/' || tmp[1] != '/') {
		smb_error(dgettext(TEXT_DOMAIN,
		    "UNC should start with '//'"), 0);
		error = EINVAL;
		goto out;
	}
	p = tmp + 2;	/* user@host... */

	/* Find the share part, if any. */
	share = strchr(p, '/');
	if (share)
		*share = '\0';
	(void) unpercent(p);	/* host component */

	/*
	 * Parse the "host" stuff right to left:
	 * 1: trailing "@hostname" (or whole field)
	 * 2: trailing ":password"
	 * 3: trailing "domain;user" (or just user)
	 */
	host = strrchr(p, '@');
	if (host == NULL) {
		host = p;	/* no user@ prefix */
	} else {
		*host++ = '\0';

		/* may have [[domain;]user[:passwd]] */
		pw = strchr(p, ':');
		if (pw)
			*pw++ = '\0';
		usr = strchr(p, ';');
		if (usr) {
			*usr++ = '\0';
			dom = p;
		} else
			usr = p;
	}

	if (*host == '\0') {
		smb_error(dgettext(TEXT_DOMAIN, "empty server name"), 0);
		error = EINVAL;
		goto out;
	}
	error = smb_ctx_setfullserver(ctx, host);
	if (error)
		goto out;
	ctx->ct_parsedlevel = SMBL_VC;

	if (dom != NULL) {
		error = smb_ctx_setdomain(ctx, dom, TRUE);
		if (error)
			goto out;
	}
	if (usr != NULL) {
		if (*usr == '\0') {
			smb_error(dgettext(TEXT_DOMAIN,
			    "empty user name"), 0);
			error = EINVAL;
			goto out;
		}
		if (ctx->ct_maxlevel < SMBL_VC) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "no user name required"), 0);
			error = EINVAL;
			goto out;
		}
		error = smb_ctx_setuser(ctx, usr, TRUE);
		if (error)
			goto out;
	}
	if (pw != NULL) {
		error = smb_ctx_setpassword(ctx, pw, TRUE);
		if (error)
			goto out;
	}

	if (share != NULL) {
		/* restore the slash */
		*share = '/';
		p = share + 1;

		/* Find the path part, if any. */
		path = strchr(p, '/');
		if (path)
			*path = '\0';
		(void) unpercent(p);	/* share component */

		if (*p == '\0') {
			smb_error(dgettext(TEXT_DOMAIN,
			    "empty share name"), 0);
			error = EINVAL;
			goto out;
		}
		if (ctx->ct_maxlevel < SMBL_SHARE) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "no share name required"), 0);
			error = EINVAL;
			goto out;
		}

		/*
		 * Special case UNC names like:
		 *	//host/PIPE/endpoint
		 * to have share: IPC$
		 */
		if (strcasecmp(p, "PIPE") == 0) {
			sharetype = USE_IPC;
			p = "IPC$";
		}
		error = smb_ctx_setshare(ctx, p, sharetype);
		if (error)
			goto out;
		ctx->ct_parsedlevel = SMBL_SHARE;

		if (path) {
			/* restore the slash */
			*path = '/';
			p = path + 1;
			(void) unpercent(p);	/* remainder */
			free(ctx->ct_rpath);
			ctx->ct_rpath = strdup(path);
		}
	} else if (ctx->ct_minlevel >= SMBL_SHARE) {
		smb_error(dgettext(TEXT_DOMAIN, "empty share name"), 0);
		error = EINVAL;
		goto out;
	}

	if (next)
		*next = NULL;

out:
	if (error == 0 && smb_debug > 0)
		dump_ctx("after smb_ctx_parseunc", ctx);

	return (error);
}

#ifdef KICONV_SUPPORT
int
smb_ctx_setcharset(struct smb_ctx *ctx, const char *arg)
{
	char *cp, *servercs, *localcs;
	int cslen = sizeof (ctx->ct_ssn.ioc_localcs);
	int scslen, lcslen, error;

	cp = strchr(arg, ':');
	lcslen = cp ? (cp - arg) : 0;
	if (lcslen == 0 || lcslen >= cslen) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "invalid local charset specification (%s)"), 0, arg);
		return (EINVAL);
	}
	scslen = (size_t)strlen(++cp);
	if (scslen == 0 || scslen >= cslen) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "invalid server charset specification (%s)"), 0, arg);
		return (EINVAL);
	}
	localcs = memcpy(ctx->ct_ssn.ioc_localcs, arg, lcslen);
	localcs[lcslen] = 0;
	servercs = strcpy(ctx->ct_ssn.ioc_servercs, cp);
	error = nls_setrecode(localcs, servercs);
	if (error == 0)
		return (0);
	smb_error(dgettext(TEXT_DOMAIN,
	    "can't initialize iconv support (%s:%s)"),
	    error, localcs, servercs);
	localcs[0] = 0;
	servercs[0] = 0;
	return (error);
}
#endif /* KICONV_SUPPORT */

int
smb_ctx_setauthflags(struct smb_ctx *ctx, int flags)
{
	ctx->ct_authflags = flags;
	return (0);
}

int
smb_ctx_setfullserver(struct smb_ctx *ctx, const char *name)
{
	char *p = strdup(name);

	if (p == NULL)
		return (ENOMEM);
	if (ctx->ct_fullserver)
		free(ctx->ct_fullserver);
	ctx->ct_fullserver = p;
	return (0);
}

int
smb_ctx_setserver(struct smb_ctx *ctx, const char *name)
{
	strlcpy(ctx->ct_srvname, name,
	    sizeof (ctx->ct_srvname));
	return (0);
}

int
smb_ctx_setuser(struct smb_ctx *ctx, const char *name, int from_cmd)
{

	if (strlen(name) >= sizeof (ctx->ct_user)) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "user name '%s' too long"), 0, name);
		return (ENAMETOOLONG);
	}

	/*
	 * Don't overwrite a value from the command line
	 * with one from anywhere else.
	 */
	if (!from_cmd && (ctx->ct_flags & SMBCF_CMD_USR))
		return (0);

	strlcpy(ctx->ct_user, name,
	    sizeof (ctx->ct_user));

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_USR;

	return (0);
}

/*
 * Don't overwrite a domain name from the
 * command line with one from anywhere else.
 * See smb_ctx_init() for notes about this.
 */
int
smb_ctx_setdomain(struct smb_ctx *ctx, const char *name, int from_cmd)
{

	if (strlen(name) >= sizeof (ctx->ct_domain)) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "workgroup name '%s' too long"), 0, name);
		return (ENAMETOOLONG);
	}

	/*
	 * Don't overwrite a value from the command line
	 * with one from anywhere else.
	 */
	if (!from_cmd && (ctx->ct_flags & SMBCF_CMD_DOM))
		return (0);

	strlcpy(ctx->ct_domain, name,
	    sizeof (ctx->ct_domain));

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_DOM;

	return (0);
}

int
smb_ctx_setpassword(struct smb_ctx *ctx, const char *passwd, int from_cmd)
{
	int err;

	if (passwd == NULL)
		return (EINVAL);
	if (strlen(passwd) >= sizeof (ctx->ct_password)) {
		smb_error(dgettext(TEXT_DOMAIN, "password too long"), 0);
		return (ENAMETOOLONG);
	}

	/*
	 * If called again after comand line parsing,
	 * don't overwrite a value from the command line
	 * with one from any stored config.
	 */
	if (!from_cmd && (ctx->ct_flags & SMBCF_CMD_PW))
		return (0);

	memset(ctx->ct_password, 0, sizeof (ctx->ct_password));
	if (strncmp(passwd, "$$1", 3) == 0)
		(void) smb_simpledecrypt(ctx->ct_password, passwd);
	else
		strlcpy(ctx->ct_password, passwd,
		    sizeof (ctx->ct_password));

	/*
	 * Compute LM hash, NT hash.
	 */
	if (ctx->ct_password[0]) {
		err = ntlm_compute_nt_hash(ctx->ct_nthash, ctx->ct_password);
		if (err != 0)
			return (err);
		err = ntlm_compute_lm_hash(ctx->ct_lmhash, ctx->ct_password);
		if (err != 0)
			return (err);
	}

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_PW;

	return (0);
}

/*
 * Use this to set NTLM auth. info (hashes)
 * when we don't have the password.
 */
int
smb_ctx_setpwhash(smb_ctx_t *ctx,
    const uchar_t *nthash, const uchar_t *lmhash)
{

	/* Need ct_password to be non-null. */
	if (ctx->ct_password[0] == '\0')
		strlcpy(ctx->ct_password, "$HASH",
		    sizeof (ctx->ct_password));

	/*
	 * Compute LM hash, NT hash.
	 */
	memcpy(ctx->ct_nthash, nthash, NTLM_HASH_SZ);

	/* The LM hash is optional */
	if (lmhash) {
		memcpy(ctx->ct_nthash, nthash, NTLM_HASH_SZ);
	}

	return (0);
}

int
smb_ctx_setshare(struct smb_ctx *ctx, const char *share, int stype)
{
	if (strlen(share) >= SMBIOC_MAX_NAME) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "share name '%s' too long"), 0, share);
		return (ENAMETOOLONG);
	}
	if (ctx->ct_origshare)
		free(ctx->ct_origshare);
	if ((ctx->ct_origshare = strdup(share)) == NULL)
		return (ENOMEM);

	ctx->ct_shtype_req = stype;

	return (0);
}

int
smb_ctx_setsrvaddr(struct smb_ctx *ctx, const char *addr)
{
	if (addr == NULL || addr[0] == 0)
		return (EINVAL);
	if (ctx->ct_srvaddr_s)
		free(ctx->ct_srvaddr_s);
	if ((ctx->ct_srvaddr_s = strdup(addr)) == NULL)
		return (ENOMEM);
	return (0);
}

/*
 * API for library caller to set signing enabled, required
 * Note: if not enable, ignore require
 */
int
smb_ctx_setsigning(struct smb_ctx *ctx, int enable, int require)
{
	ctx->ct_vopt &= ~SMBVOPT_SIGNING_MASK;
	if (enable) {
		ctx->ct_vopt |=	SMBVOPT_SIGNING_ENABLED;
		if (require)
			ctx->ct_vopt |=	SMBVOPT_SIGNING_REQUIRED;
	}
	return (0);
}

static int
smb_parse_owner(char *pair, uid_t *uid, gid_t *gid)
{
	struct group gr;
	struct passwd pw;
	char buf[NSS_BUFLEN_PASSWD];
	char *cp;

	cp = strchr(pair, ':');
	if (cp) {
		*cp++ = '\0';
		if (*cp && gid) {
			if (getgrnam_r(cp, &gr, buf, sizeof (buf)) != NULL) {
				*gid = gr.gr_gid;
			} else
				smb_error(dgettext(TEXT_DOMAIN,
				    "Invalid group name %s, ignored"), 0, cp);
		}
	}
	if (*pair) {
		if (getpwnam_r(pair, &pw, buf, sizeof (buf)) != NULL) {
			*uid = pw.pw_uid;
		} else
			smb_error(dgettext(TEXT_DOMAIN,
			    "Invalid user name %s, ignored"), 0, pair);
	}

	return (0);
}

/*
 * Suport a securty options arg, i.e. -S noext,lm,ntlm
 * for testing various type of authenticators.
 */
static struct nv
sectype_table[] = {
	/* noext - handled below */
	{ "anon",	SMB_AT_ANON },
	{ "lm",		SMB_AT_LM1 },
	{ "ntlm",	SMB_AT_NTLM1 },
	{ "ntlm2",	SMB_AT_NTLM2 },
	{ "krb5",	SMB_AT_KRB5 },
	{ NULL, 	0 },
};
int
smb_parse_secopts(struct smb_ctx *ctx, const char *arg)
{
	const char *sep = ":;,";
	const char *p = arg;
	struct nv *nv;
	int nlen, tlen;
	int authflags = 0;

	for (;;) {
		/* skip separators */
		tlen = strspn(p, sep);
		p += tlen;

		nlen = strcspn(p, sep);
		if (nlen == 0)
			break;

		if (nlen == 5 && 0 == strncmp(p, "noext", nlen)) {
			/* Don't offer extended security. */
			ctx->ct_vopt &= ~SMBVOPT_EXT_SEC;
			p += nlen;
			continue;
		}

		/* This is rarely called, so not optimized. */
		for (nv = sectype_table; nv->name; nv++) {
			tlen = strlen(nv->name);
			if (tlen == nlen && 0 == strncmp(p, nv->name, tlen))
				break;
		}
		if (nv->name == NULL) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "%s: invalid security options"), 0, p);
			return (EINVAL);
		}
		authflags |= nv->value;
		p += nlen;
	}

	if (authflags)
		ctx->ct_authflags = authflags;

	return (0);
}

/*
 * Commands use this with getopt.  See:
 *   STDPARAM_OPT, STDPARAM_ARGS
 * Called after smb_ctx_readrc().
 */
int
smb_ctx_opt(struct smb_ctx *ctx, int opt, const char *arg)
{
	int error = 0;
	char *p, *cp;
	char tmp[1024];

	switch (opt) {
	case 'A':
	case 'U':
		/* Handled in smb_ctx_init() */
		break;
	case 'I':
		error = smb_ctx_setsrvaddr(ctx, arg);
		break;
	case 'M':
		/* share connect rights - ignored */
		ctx->ct_flags |= SMBCF_SRIGHTS;
		break;
	case 'N':
		ctx->ct_flags |= SMBCF_NOPWD;
		break;
	case 'O':
		p = strdup(arg);
		cp = strchr(p, '/');
		if (cp)
			*cp = '\0';
		error = smb_parse_owner(cp, &ctx->ct_owner, NULL);
		free(p);
		break;
	case 'P':
/*		ctx->ct_vopt |= SMBCOPT_PERMANENT; */
		break;
	case 'R':
		/* retry count - ignored */
		break;
	case 'S':
		/* Security options (undocumented, just for tests) */
		error = smb_parse_secopts(ctx, arg);
		break;
	case 'T':
		/* timeout - ignored */
		break;
	case 'D':	/* domain */
	case 'W':	/* workgroup (legacy alias) */
		error = smb_ctx_setdomain(ctx, tmp, TRUE);
		break;
	}
	return (error);
}


/*
 * Original code injected iconv tables into the kernel.
 * Not sure if we'll need this or not...  REVISIT
 */
#ifdef KICONV_SUPPORT
static int
smb_addiconvtbl(const char *to, const char *from, const uchar_t *tbl)
{
	int error = 0;

	error = kiconv_add_xlat_table(to, from, tbl);
	if (error && error != EEXIST) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can not setup kernel iconv table (%s:%s)"),
		    error, from, to);
		return (error);
	}
	return (error);
}
#endif	/* KICONV_SUPPORT */

/*
 * Verify context info. before connect operation(s),
 * lookup specified server and try to fill all forgotten fields.
 * Legacy name used by commands.
 */
int
smb_ctx_resolve(struct smb_ctx *ctx)
{
	struct smbioc_ossn *ssn = &ctx->ct_ssn;
	int error = 0;
#ifdef KICONV_SUPPORT
	uchar_t cstbl[256];
	uint_t i;
#endif

	if (smb_debug)
		dump_ctx("before smb_ctx_resolve", ctx);

	ctx->ct_flags &= ~SMBCF_RESOLVED;

	if (ctx->ct_fullserver == NULL) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "no server name specified"), 0);
		return (EINVAL);
	}

	if (ctx->ct_minlevel >= SMBL_SHARE &&
	    ctx->ct_origshare == NULL) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "no share name specified for %s@%s"),
		    0, ssn->ssn_user, ctx->ct_fullserver);
		return (EINVAL);
	}
	error = nb_ctx_resolve(ctx->ct_nb);
	if (error)
		return (error);
#ifdef KICONV_SUPPORT
	if (ssn->ioc_localcs[0] == 0)
		strcpy(ssn->ioc_localcs, "default");	/* XXX: locale name ? */
	error = smb_addiconvtbl("tolower", ssn->ioc_localcs, nls_lower);
	if (error)
		return (error);
	error = smb_addiconvtbl("toupper", ssn->ioc_localcs, nls_upper);
	if (error)
		return (error);
	if (ssn->ioc_servercs[0] != 0) {
		for (i = 0; i < sizeof (cstbl); i++)
			cstbl[i] = i;
		nls_mem_toext(cstbl, cstbl, sizeof (cstbl));
		error = smb_addiconvtbl(ssn->ioc_servercs, ssn->ioc_localcs,
		    cstbl);
		if (error)
			return (error);
		for (i = 0; i < sizeof (cstbl); i++)
			cstbl[i] = i;
		nls_mem_toloc(cstbl, cstbl, sizeof (cstbl));
		error = smb_addiconvtbl(ssn->ioc_localcs, ssn->ioc_servercs,
		    cstbl);
		if (error)
			return (error);
	}
#endif	/* KICONV_SUPPORT */

	/*
	 * Lookup the IP address and fill in ct_addrinfo.
	 *
	 * Note: smb_ctx_getaddr() returns a EAI_xxx
	 * error value like getaddrinfo(3), but this
	 * function needs to return an errno value.
	 */
	error = smb_ctx_getaddr(ctx);
	if (error) {
		const char *ais = gai_strerror(error);
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't resolve name\"%s\", %s"),
		    0, ctx->ct_fullserver, ais);
		return (ENODATA);
	}
	assert(ctx->ct_addrinfo != NULL);

	/*
	 * If we have a user name but no password,
	 * check for a keychain entry.
	 * XXX: Only for auth NTLM?
	 */
	if (ctx->ct_user[0] != '\0') {
		/*
		 * Have a user name.
		 * If we don't have a p/w yet,
		 * try the keychain.
		 */
		if (ctx->ct_password[0] == '\0')
			(void) smb_get_keychain(ctx);
		/*
		 * Mask out disallowed auth types.
		 */
		ctx->ct_authflags &= ctx->ct_minauth;
	}
	if (ctx->ct_authflags == 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "no valid auth. types"), 0);
		return (ENOTSUP);
	}

	ctx->ct_flags |= SMBCF_RESOLVED;
	if (smb_debug)
		dump_ctx("after smb_ctx_resolve", ctx);

	return (0);
}

int
smb_open_driver()
{
	int fd;

	fd = open("/dev/"NSMB_NAME, O_RDWR);
	if (fd < 0) {
		return (-1);
	}

	/* This handle controls per-process resources. */
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	return (fd);
}

int
smb_ctx_gethandle(struct smb_ctx *ctx)
{
	int fd, err;
	uint32_t version;

	if (ctx->ct_dev_fd != -1) {
		rpc_cleanup_smbctx(ctx);
		close(ctx->ct_dev_fd);
		ctx->ct_dev_fd = -1;
		ctx->ct_flags &= ~SMBCF_SSNACTIVE;
	}

	fd = smb_open_driver();
	if (fd < 0) {
		err = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "failed to open driver"), err);
		return (err);
	}

	/*
	 * Check the driver version (paranoia)
	 */
	if (ioctl(fd, SMBIOC_GETVERS, &version) < 0)
		version = 0;
	if (version != NSMB_VERSION) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "incorrect driver version"), 0);
		close(fd);
		return (ENODEV);
	}

	ctx->ct_dev_fd = fd;
	return (0);
}


/*
 * Find or create a connection + logon session
 */
int
smb_ctx_get_ssn(struct smb_ctx *ctx)
{
	int err = 0;

	if ((ctx->ct_flags & SMBCF_RESOLVED) == 0)
		return (EINVAL);

	if (ctx->ct_dev_fd < 0) {
		if ((err = smb_ctx_gethandle(ctx)))
			return (err);
	}

	/*
	 * Check whether the driver already has a VC
	 * we can use.  If so, we're done!
	 */
	err = smb_ctx_findvc(ctx);
	if (err == 0) {
		DPRINT("found an existing VC");
	} else {
		/*
		 * This calls the IOD to create a new session.
		 */
		DPRINT("setup a new VC");
		err = smb_ctx_newvc(ctx);
		if (err != 0)
			return (err);

		/*
		 * Call findvc again.  The new VC sould be
		 * found in the driver this time.
		 */
		err = smb_ctx_findvc(ctx);
	}

	return (err);
}

/*
 * Find or create a tree connection
 */
int
smb_ctx_get_tree(struct smb_ctx *ctx)
{
	smbioc_tcon_t *tcon = NULL;
	int cmd, err = 0;

	if (ctx->ct_dev_fd < 0 ||
	    ctx->ct_origshare == NULL) {
		return (EINVAL);
	}

	cmd = SMBIOC_TREE_CONNECT;
	tcon = malloc(sizeof (*tcon));
	if (tcon == NULL)
		return (ENOMEM);
	bzero(tcon, sizeof (*tcon));
	tcon->tc_flags = SMBLK_CREATE;
	tcon->tc_opt = 0;

	/* The share name */
	strlcpy(tcon->tc_sh.sh_name, ctx->ct_origshare,
	    sizeof (tcon->tc_sh.sh_name));

	/* The share "use" type. */
	tcon->tc_sh.sh_use = ctx->ct_shtype_req;

	/*
	 * Todo: share passwords for share-level security.
	 *
	 * The driver does the actual TCON call.
	 */
	if (ioctl(ctx->ct_dev_fd, cmd, tcon) == -1) {
		err = errno;
		goto out;
	}

	/*
	 * Check the returned share type
	 */
	DPRINT("ret. sh_type: \"%d\"", tcon->tc_sh.sh_type);
	if (ctx->ct_shtype_req != USE_WILDCARD &&
	    ctx->ct_shtype_req != tcon->tc_sh.sh_type) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s: incompatible share type"),
		    0, ctx->ct_origshare);
	}

out:
	if (tcon != NULL)
		free(tcon);

	return (err);
}

/*
 * Return the hflags2 word for an smb_ctx.
 */
int
smb_ctx_flags2(struct smb_ctx *ctx)
{
	uint16_t flags2;

	if (ioctl(ctx->ct_dev_fd, SMBIOC_FLAGS2, &flags2) == -1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't get flags2 for a session"), errno);
		return (-1);
	}
	return (flags2);
}

/*
 * Get the transport level session key.
 * Must already have an active SMB session.
 */
int
smb_fh_getssnkey(int dev_fd, uchar_t *key, size_t len)
{
	if (len < SMBIOC_HASH_SZ)
		return (EINVAL);

	if (ioctl(dev_fd, SMBIOC_GETSSNKEY, key) == -1)
		return (errno);

	return (0);
}

/*
 * RC file parsing stuff
 */

static struct nv
minauth_table[] = {
	/* Allowed auth. types */
	{ "kerberos",	SMB_AT_KRB5 },
	{ "ntlmv2",	SMB_AT_KRB5|SMB_AT_NTLM2 },
	{ "ntlm",	SMB_AT_KRB5|SMB_AT_NTLM2|SMB_AT_NTLM1 },
	{ "lm",		SMB_AT_KRB5|SMB_AT_NTLM2|SMB_AT_NTLM1|SMB_AT_LM1 },
	{ "none",	SMB_AT_KRB5|SMB_AT_NTLM2|SMB_AT_NTLM1|SMB_AT_LM1|
			SMB_AT_ANON },
	{ NULL }
};


/*
 * level values:
 * 0 - default
 * 1 - server
 * 2 - server:user
 * 3 - server:user:share
 */
static int
smb_ctx_readrcsection(struct smb_ctx *ctx, const char *sname, int level)
{
	char *p;
	int error;

#ifdef	KICONV_SUPPORT
	if (level > 0) {
		rc_getstringptr(smb_rc, sname, "charsets", &p);
		if (p) {
			error = smb_ctx_setcharset(ctx, p);
			if (error)
				smb_error(dgettext(TEXT_DOMAIN,
	"charset specification in the section '%s' ignored"),
				    error, sname);
		}
	}
#endif

	if (level <= 1) {
		/* Section is: [default] or [server] */

		rc_getstringptr(smb_rc, sname, "minauth", &p);
		if (p) {
			/*
			 * "minauth" was set in this section; override
			 * the current minimum authentication setting.
			 */
			struct nv *nvp;
			for (nvp = minauth_table; nvp->name; nvp++)
				if (strcmp(p, nvp->name) == 0)
					break;
			if (nvp->name)
				ctx->ct_minauth = nvp->value;
			else {
				/*
				 * Unknown minimum authentication level.
				 */
				smb_error(dgettext(TEXT_DOMAIN,
"invalid minimum authentication level \"%s\" specified in the section %s"),
				    0, p, sname);
				return (EINVAL);
			}
		}

		rc_getstringptr(smb_rc, sname, "signing", &p);
		if (p) {
			/*
			 * "signing" was set in this section; override
			 * the current signing settings.  Note:
			 * setsigning flags are: enable, require
			 */
			if (strcmp(p, "disabled") == 0) {
				(void) smb_ctx_setsigning(ctx, FALSE, FALSE);
			} else if (strcmp(p, "enabled") == 0) {
				(void) smb_ctx_setsigning(ctx, TRUE, FALSE);
			} else if (strcmp(p, "required") == 0) {
				(void) smb_ctx_setsigning(ctx, TRUE, TRUE);
			} else {
				/*
				 * Unknown "signing" value.
				 */
				smb_error(dgettext(TEXT_DOMAIN,
"invalid signing policy \"%s\" specified in the section %s"),
				    0, p, sname);
				return (EINVAL);
			}
		}

		/*
		 * Domain name.  Allow both keywords:
		 * "workgroup", "domain"
		 *
		 * Note: these are NOT marked "from CMD".
		 * See long comment at smb_ctx_init()
		 */
		rc_getstringptr(smb_rc, sname, "workgroup", &p);
		if (p) {
			error = smb_ctx_setdomain(ctx, p, 0);
			if (error)
				smb_error(dgettext(TEXT_DOMAIN,
				    "workgroup specification in the "
				    "section '%s' ignored"), error, sname);
		}
		rc_getstringptr(smb_rc, sname, "domain", &p);
		if (p) {
			error = smb_ctx_setdomain(ctx, p, 0);
			if (error)
				smb_error(dgettext(TEXT_DOMAIN,
				    "domain specification in the "
				    "section '%s' ignored"), error, sname);
		}

		rc_getstringptr(smb_rc, sname, "user", &p);
		if (p) {
			error = smb_ctx_setuser(ctx, p, 0);
			if (error)
				smb_error(dgettext(TEXT_DOMAIN,
				    "user specification in the "
				    "section '%s' ignored"), error, sname);
		}
	}

	if (level == 1) {
		/* Section is: [server] */
		rc_getstringptr(smb_rc, sname, "addr", &p);
		if (p) {
			error = smb_ctx_setsrvaddr(ctx, p);
			if (error) {
				smb_error(dgettext(TEXT_DOMAIN,
				    "invalid address specified in section %s"),
				    0, sname);
				return (error);
			}
		}
	}

	rc_getstringptr(smb_rc, sname, "password", &p);
	if (p) {
		error = smb_ctx_setpassword(ctx, p, 0);
		if (error)
			smb_error(dgettext(TEXT_DOMAIN,
	    "password specification in the section '%s' ignored"),
			    error, sname);
	}

	return (0);
}

/*
 * read rc file as follows:
 * 0: read [default] section
 * 1: override with [server] section
 * 2: override with [server:user] section
 * 3: override with [server:user:share] section
 * Since absence of rcfile is not fatal, silently ignore this fact.
 * smb_rc file should be closed by caller.
 */
int
smb_ctx_readrc(struct smb_ctx *ctx)
{
	char pwbuf[NSS_BUFLEN_PASSWD];
	struct passwd pw;
	char *sname = NULL;
	int sname_max;
	int err = 0;

	/*
	 * If the user name is not specified some other way,
	 * use the current user name.  Also save the homedir.
	 * NB: ct_home=NULL is allowed, and we don't want to
	 * bail out with an error for a missing ct_home.
	 */
	if (getpwuid_r(getuid(), &pw, pwbuf, sizeof (pwbuf)) != NULL) {
		if (ctx->ct_user[0] == 0)
			(void) smb_ctx_setuser(ctx, pw.pw_name, B_FALSE);
		if (ctx->ct_home == NULL)
			ctx->ct_home = strdup(pw.pw_dir);
	}

	if ((err = smb_open_rcfile(ctx->ct_home)) != 0) {
		DPRINT("smb_open_rcfile, err=%d", err);
		/* ignore any error here */
		return (0);
	}

	sname_max = 3 * SMBIOC_MAX_NAME + 4;
	sname = malloc(sname_max);
	if (sname == NULL) {
		err = ENOMEM;
		goto done;
	}

	/*
	 * default parameters (level=0)
	 */
	smb_ctx_readrcsection(ctx, "default", 0);
	nb_ctx_readrcsection(smb_rc, ctx->ct_nb, "default", 0);

	/*
	 * If we don't have a server name, we can't read any of the
	 * [server...] sections.
	 */
	if (ctx->ct_fullserver == NULL)
		goto done;
	/*
	 * SERVER parameters.
	 */
	smb_ctx_readrcsection(ctx, ctx->ct_fullserver, 1);

	/*
	 * If we don't have a user name, we can't read any of the
	 * [server:user...] sections.
	 */
	if (ctx->ct_user[0] == 0)
		goto done;
	/*
	 * SERVER:USER parameters
	 */
	snprintf(sname, sname_max, "%s:%s",
	    ctx->ct_fullserver,
	    ctx->ct_user);
	smb_ctx_readrcsection(ctx, sname, 2);


	/*
	 * If we don't have a share name, we can't read any of the
	 * [server:user:share] sections.
	 */
	if (ctx->ct_origshare == NULL)
		goto done;
	/*
	 * SERVER:USER:SHARE parameters
	 */
	snprintf(sname, sname_max, "%s:%s:%s",
	    ctx->ct_fullserver,
	    ctx->ct_user,
	    ctx->ct_origshare);
	smb_ctx_readrcsection(ctx, sname, 3);

done:
	if (sname)
		free(sname);
	smb_close_rcfile();
	if (smb_debug)
		dump_ctx("after smb_ctx_readrc", ctx);
	if (err)
		DPRINT("err=%d\n", err);

	return (err);
}

void
smbfs_set_default_domain(const char *domain)
{
	strlcpy(default_domain, domain, sizeof (default_domain));
}

void
smbfs_set_default_user(const char *user)
{
	strlcpy(default_user, user, sizeof (default_user));
}
