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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <kerberosv5/krb5.h>
#include <kerberosv5/com_err.h>

extern uid_t real_uid, eff_uid;

#define	NB_NEEDRESOLVER

#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>
#include <cflib.h>
#include <charsets.h>

#include <spnego.h>
#include "derparse.h"

extern MECH_OID g_stcMechOIDList [];

#define	POWEROF2(x) (((x) & ((x)-1)) == 0)

/* These two may be set by commands. */
int smb_debug, smb_verbose;

/*
 * This used to call the DCE/RPC code.
 * We want more strict layering than this.
 * The redirector should simply export a
 * remote pipe API, comsumed by dce rpc.
 * Make it a no-op for now.
 */
#if 0
#include <rpc_cleanup.h>
#else
static void
rpc_cleanup_smbctx(struct smb_ctx *ctx)
{
}
#endif

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
dump_ctx_ssn(struct smbioc_ossn *ssn)
{
	printf(" srvname=\"%s\", dom=\"%s\", user=\"%s\", password=%s\n",
	    ssn->ioc_srvname, ssn->ioc_workgroup, ssn->ioc_user,
	    ssn->ioc_password[0] ? "(non-null)" : "NULL");
	printf(" timeout=%d, retry=%d, owner=%d, group=%d\n",
	    ssn->ioc_timeout, ssn->ioc_retrycount,
	    ssn->ioc_owner, ssn->ioc_group);
}

void
dump_ctx_sh(struct smbioc_oshare *sh)
{
	printf(" share_name=\"%s\", share_pw=\"%s\"\n",
	    sh->ioc_share, sh->ioc_password);
}

void
dump_ctx(char *where, struct smb_ctx *ctx)
{
	printf("context %s:\n", where);
	dump_ctx_flags(ctx->ct_flags);

	printf(" localname=\"%s\"", ctx->ct_locname);

	if (ctx->ct_fullserver)
		printf(" fullserver=\"%s\"", ctx->ct_fullserver);
	else
		printf(" fullserver=NULL");

	if (ctx->ct_srvaddr)
		printf(" srvaddr=\"%s\"\n", ctx->ct_srvaddr);
	else
		printf(" srvaddr=NULL\n");

	dump_ctx_ssn(&ctx->ct_ssn);
	dump_ctx_sh(&ctx->ct_sh);
}

/*
 * Initialize an smb_ctx struct.
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
smb_ctx_init(struct smb_ctx *ctx, int argc, char *argv[],
	int minlevel, int maxlevel, int sharetype)
{
	int  opt, error = 0;
	const char *arg, *cp;
	struct passwd pw;
	char pwbuf[NSS_BUFLEN_PASSWD];
	int aflg = 0, uflg = 0;

	bzero(ctx, sizeof (*ctx));
	if (sharetype == SMB_ST_DISK)
		ctx->ct_flags |= SMBCF_BROWSEOK;
	error = nb_ctx_create(&ctx->ct_nb);
	if (error)
		return (error);

	ctx->ct_fd = -1;
	ctx->ct_parsedlevel = SMBL_NONE;
	ctx->ct_minlevel = minlevel;
	ctx->ct_maxlevel = maxlevel;

	ctx->ct_ssn.ioc_opt = SMBVOPT_CREATE | SMBVOPT_MINAUTH_NTLM;
	ctx->ct_ssn.ioc_timeout = 15;
	ctx->ct_ssn.ioc_retrycount = 4;
	ctx->ct_ssn.ioc_owner = SMBM_ANY_OWNER;
	ctx->ct_ssn.ioc_group = SMBM_ANY_GROUP;
	ctx->ct_ssn.ioc_mode = SMBM_EXEC;
	ctx->ct_ssn.ioc_rights = SMBM_DEFAULT;

	ctx->ct_sh.ioc_opt = SMBVOPT_CREATE;
	ctx->ct_sh.ioc_owner = SMBM_ANY_OWNER;
	ctx->ct_sh.ioc_group = SMBM_ANY_GROUP;
	ctx->ct_sh.ioc_mode = SMBM_EXEC;
	ctx->ct_sh.ioc_rights = SMBM_DEFAULT;
	ctx->ct_sh.ioc_owner = SMBM_ANY_OWNER;
	ctx->ct_sh.ioc_group = SMBM_ANY_GROUP;

	nb_ctx_setscope(ctx->ct_nb, "");

	/*
	 * if the user name is not specified some other way,
	 * use the current user name (built-in default)
	 */
	if (getpwuid_r(geteuid(), &pw, pwbuf, sizeof (pwbuf)) != NULL)
		smb_ctx_setuser(ctx, pw.pw_name, 0);

	/*
	 * Set a built-in default domain (workgroup).
	 * XXX: What's the best default? Use "?" instead?
	 * Using the Windows/NT default for now.
	 */
	smb_ctx_setworkgroup(ctx, "WORKGROUP", 0);

	/*
	 * Parse the UNC path.  Values from here are
	 * marked as "from CMD".
	 */
	if (argv == NULL)
		goto done;
	for (opt = 1; opt < argc; opt++) {
		cp = argv[opt];
		if (strncmp(cp, "//", 2) != 0)
			continue;
		error = smb_ctx_parseunc(ctx, cp, sharetype, &cp);
		if (error)
			return (error);
		break;
	}

	/*
	 * Parse options, if any.  Values from here too
	 * are marked as "from CMD".
	 */
	while (error == 0 && (opt = cf_getopt(argc, argv, ":AU:E:L:")) != -1) {
		arg = cf_optarg;
		switch (opt) {
		case 'A':
			aflg = 1;
			error = smb_ctx_setuser(ctx, "", TRUE);
			error = smb_ctx_setpassword(ctx, "", TRUE);
			ctx->ct_flags |= SMBCF_NOPWD;
			break;
		case 'E':
#if 0 /* We don't support any "charset" stuff. (ignore -E) */
			error = smb_ctx_setcharset(ctx, arg);
			if (error)
				return (error);
#endif
			break;
		case 'L':
#if 0 /* Use the standard environment variables (ignore -L) */
			error = nls_setlocale(optarg);
			if (error)
				break;
#endif
			break;
		case 'U':
			uflg = 1;
			error = smb_ctx_setuser(ctx, arg, TRUE);
			break;
		}
	}
	if (aflg && uflg)  {
		printf(gettext("-A and -U flags are exclusive.\n"));
		return (1);
	}
	cf_optind = cf_optreset = 1;

done:
	if (smb_debug)
		dump_ctx("after smb_ctx_init", ctx);

	return (error);
}

void
smb_ctx_done(struct smb_ctx *ctx)
{

	rpc_cleanup_smbctx(ctx);

	/* Kerberos stuff.  See smb_ctx_krb5init() */
	if (ctx->ct_krb5ctx) {
		if (ctx->ct_krb5cp)
			krb5_free_principal(ctx->ct_krb5ctx, ctx->ct_krb5cp);
		krb5_free_context(ctx->ct_krb5ctx);
	}

	if (ctx->ct_fd != -1)
		close(ctx->ct_fd);
#if 0 /* XXX: not pointers anymore */
	if (&ctx->ct_ssn.ioc_server)
		nb_snbfree(&ctx->ct_ssn.ioc_server);
	if (&ctx->ct_ssn.ioc_local)
		nb_snbfree(&ctx->ct_ssn.ioc_local);
#endif
	if (ctx->ct_srvaddr)
		free(ctx->ct_srvaddr);
	if (ctx->ct_nb)
		nb_ctx_done(ctx->ct_nb);
	if (ctx->ct_secblob)
		free(ctx->ct_secblob);
	if (ctx->ct_origshare)
		free(ctx->ct_origshare);
	if (ctx->ct_fullserver)
		free(ctx->ct_fullserver);
}

static int
getsubstring(const char *p, uchar_t sep, char *dest, int maxlen,
    const char **next)
{
	int len;

	maxlen--;
	for (len = 0; len < maxlen && *p != sep; p++, len++, dest++) {
		if (*p == 0)
			return (EINVAL);
		*dest = *p;
	}
	*dest = 0;
	*next = *p ? p + 1 : p;
	return (0);
}

/*
 * Parse the UNC path.  Here we expect something like
 *   "//[workgroup;][user[:password]@]host[/share[/path]]"
 * See http://ietf.org/internet-drafts/draft-crhertel-smb-url-07.txt
 * Values found here are marked as "from CMD".
 */
int
smb_ctx_parseunc(struct smb_ctx *ctx, const char *unc, int sharetype,
	const char **next)
{
	const char *p = unc;
	char *p1, *colon, *servername;
	char tmp[1024];
	char tmp2[1024];
	int error;

	ctx->ct_parsedlevel = SMBL_NONE;
	if (*p++ != '/' || *p++ != '/') {
		smb_error(dgettext(TEXT_DOMAIN,
		    "UNC should start with '//'"), 0);
		return (EINVAL);
	}
	p1 = tmp;
	error = getsubstring(p, ';', p1, sizeof (tmp), &p);
	if (!error) {
		if (*p1 == 0) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "empty workgroup name"), 0);
			return (EINVAL);
		}
		nls_str_upper(tmp, tmp);
		error = smb_ctx_setworkgroup(ctx, unpercent(tmp), TRUE);
		if (error)
			return (error);
	}
	colon = (char *)p;
	error = getsubstring(p, '@', p1, sizeof (tmp), &p);
	if (!error) {
		if (ctx->ct_maxlevel < SMBL_VC) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "no user name required"), 0);
			return (EINVAL);
		}
		p1 = strchr(tmp, ':');
		if (p1) {
			colon += p1 - tmp;
			*p1++ = (char)0;
			error = smb_ctx_setpassword(ctx, unpercent(p1), TRUE);
			if (error)
				return (error);
			if (p - colon > 2)
				memset(colon+1, '*', p - colon - 2);
		}
		p1 = tmp;
		if (*p1 == 0) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "empty user name"), 0);
			return (EINVAL);
		}
		error = smb_ctx_setuser(ctx, unpercent(tmp), TRUE);
		if (error)
			return (error);
		ctx->ct_parsedlevel = SMBL_VC;
	}
	error = getsubstring(p, '/', p1, sizeof (tmp), &p);
	if (error) {
		error = getsubstring(p, '\0', p1, sizeof (tmp), &p);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "no server name found"), 0);
			return (error);
		}
	}
	if (*p1 == 0) {
		smb_error(dgettext(TEXT_DOMAIN, "empty server name"), 0);
		return (EINVAL);
	}


	/*
	 * It's safe to uppercase this string, which
	 * consists of ascii characters that should
	 * be uppercased, %s, and ascii characters representing
	 * hex digits 0-9 and A-F (already uppercased, and
	 * if not uppercased they need to be). However,
	 * it is NOT safe to uppercase after it has been
	 * converted, below!
	 */

	nls_str_upper(tmp2, tmp);

	/*
	 * scan for % in the string.
	 * If we find one, convert
	 * to the assumed codepage.
	 */

	if (strchr(tmp2, '%')) {
		/* use the 1st buffer, we don't need the old string */
		servername = tmp;
		if (!(servername = convert_utf8_to_wincs(unpercent(tmp2)))) {
			smb_error(dgettext(TEXT_DOMAIN, "bad server name"), 0);
			return (EINVAL);
		}
		/*
		 * Converts utf8 to win equivalent of
		 * what is configured on this machine.
		 * Note that we are assuming this is the
		 * encoding used on the server, and that
		 * assumption might be incorrect. This is
		 * the best we can do now, and we should
		 * move to use port 445 to avoid having
		 * to worry about server codepages.
		 */
	} else /* no conversion needed */
		servername = tmp2;

	smb_ctx_setserver(ctx, servername);
	error = smb_ctx_setfullserver(ctx, servername);

	if (error)
		return (error);
	if (sharetype == SMB_ST_NONE) {
		*next = p;
		return (0);
	}
	if (*p != 0 && ctx->ct_maxlevel < SMBL_SHARE) {
		smb_error(dgettext(TEXT_DOMAIN, "no share name required"), 0);
		return (EINVAL);
	}
	error = getsubstring(p, '/', p1, sizeof (tmp), &p);
	if (error) {
		error = getsubstring(p, '\0', p1, sizeof (tmp), &p);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "unexpected end of line"), 0);
			return (error);
		}
	}
	if (*p1 == 0 && ctx->ct_minlevel >= SMBL_SHARE &&
	    !(ctx->ct_flags & SMBCF_BROWSEOK)) {
		smb_error(dgettext(TEXT_DOMAIN, "empty share name"), 0);
		return (EINVAL);
	}
	*next = p;
	if (*p1 == 0)
		return (0);
	error = smb_ctx_setshare(ctx, unpercent(p1), sharetype);
	return (error);
}

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

int
smb_ctx_setfullserver(struct smb_ctx *ctx, const char *name)
{
	ctx->ct_fullserver = strdup(name);
	if (ctx->ct_fullserver == NULL)
		return (ENOMEM);
	return (0);
}

/*
 * XXX TODO FIXME etc etc
 * If the call to nbns_getnodestatus(...) fails we can try one of two other
 * methods; use a name of "*SMBSERVER", which is supported by Samba (at least)
 * or, as a last resort, try the "truncate-at-dot" heuristic.
 * And the heuristic really should attempt truncation at
 * each dot in turn, left to right.
 *
 * These fallback heuristics should be triggered when the attempt to open the
 * session fails instead of in the code below.
 *
 * See http://ietf.org/internet-drafts/draft-crhertel-smb-url-07.txt
 */
int
smb_ctx_getnbname(struct smb_ctx *ctx, struct sockaddr *sap)
{
	char server[SMB_MAXSRVNAMELEN + 1];
	char workgroup[SMB_MAXUSERNAMELEN + 1];
	int error;
#if 0
	char *dot;
#endif

	server[0] = workgroup[0] = '\0';
	error = nbns_getnodestatus(sap, ctx->ct_nb, server, workgroup);
	if (error == 0) {
		/*
		 * Used to set our domain name to be the same as
		 * the server's domain name.   Unnecessary at best,
		 * and wrong for accounts in a trusted domain.
		 */
#ifdef APPLE
		if (workgroup[0] && !ctx->ct_ssn.ioc_workgroup[0])
			smb_ctx_setworkgroup(ctx, workgroup, 0);
#endif
		if (server[0])
			smb_ctx_setserver(ctx, server);
	} else {
		if (smb_verbose)
			smb_error(dgettext(TEXT_DOMAIN,
			    "Failed to get NetBIOS node status."), 0);
		if (ctx->ct_ssn.ioc_srvname[0] == (char)0)
			smb_ctx_setserver(ctx, "*SMBSERVER");
	}
#if 0
	if (server[0] == (char)0) {
		dot = strchr(ctx->ct_fullserver, '.');
		if (dot)
			*dot = '\0';
		if (strlen(ctx->ct_fullserver) <= SMB_MAXSRVNAMELEN) {
			/*
			 * don't uppercase the server name. it comes from
			 * NBNS and uppercasing can clobber the characters
			 */
			strcpy(ctx->ct_ssn.ioc_srvname, ctx->ct_fullserver);
			error = 0;
		} else {
			error = -1;
		}
		if (dot)
			*dot = '.';
	}
#endif
	return (error);
}

/* this routine does not uppercase the server name */
void
smb_ctx_setserver(struct smb_ctx *ctx, const char *name)
{
	/* don't uppercase the server name */
	if (strlen(name) > SMB_MAXSRVNAMELEN) { /* NB limit is 15 */
		ctx->ct_ssn.ioc_srvname[0] = '\0';
	} else
		strcpy(ctx->ct_ssn.ioc_srvname, name);
}

int
smb_ctx_setuser(struct smb_ctx *ctx, const char *name, int from_cmd)
{

	if (strlen(name) >= SMB_MAXUSERNAMELEN) {
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

	/* don't uppercase the username, just copy it. */
	strcpy(ctx->ct_ssn.ioc_user, name);

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_USR;

	return (0);
}

/*
 * Never uppercase the workgroup
 * name here, because it might come
 * from a Windows codepage encoding.
 *
 * Don't overwrite a domain name from the
 * command line with one from anywhere else.
 * See smb_ctx_init() for notes about this.
 */
int
smb_ctx_setworkgroup(struct smb_ctx *ctx, const char *name, int from_cmd)
{

	if (strlen(name) >= SMB_MAXUSERNAMELEN) {
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

	strcpy(ctx->ct_ssn.ioc_workgroup, name);

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_DOM;

	return (0);
}

int
smb_ctx_setpassword(struct smb_ctx *ctx, const char *passwd, int from_cmd)
{

	if (passwd == NULL) /* XXX Huh? */
		return (EINVAL);
	if (strlen(passwd) >= SMB_MAXPASSWORDLEN) {
		smb_error(dgettext(TEXT_DOMAIN, "password too long"), 0);
		return (ENAMETOOLONG);
	}

	/*
	 * Don't overwrite a value from the command line
	 * with one from anywhere else.
	 */
	if (!from_cmd && (ctx->ct_flags & SMBCF_CMD_PW))
		return (0);

	if (strncmp(passwd, "$$1", 3) == 0)
		smb_simpledecrypt(ctx->ct_ssn.ioc_password, passwd);
	else
		strcpy(ctx->ct_ssn.ioc_password, passwd);
	strcpy(ctx->ct_sh.ioc_password, ctx->ct_ssn.ioc_password);

	/* Mark this as "from the command line". */
	if (from_cmd)
		ctx->ct_flags |= SMBCF_CMD_PW;

	return (0);
}

int
smb_ctx_setshare(struct smb_ctx *ctx, const char *share, int stype)
{
	if (strlen(share) >= SMB_MAXSHARENAMELEN) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "share name '%s' too long"), 0, share);
		return (ENAMETOOLONG);
	}
	if (ctx->ct_origshare)
		free(ctx->ct_origshare);
	if ((ctx->ct_origshare = strdup(share)) == NULL)
		return (ENOMEM);
	nls_str_upper(ctx->ct_sh.ioc_share, share);
	if (share[0] != 0)
		ctx->ct_parsedlevel = SMBL_SHARE;
	ctx->ct_sh.ioc_stype = stype;
	return (0);
}

int
smb_ctx_setsrvaddr(struct smb_ctx *ctx, const char *addr)
{
	if (addr == NULL || addr[0] == 0)
		return (EINVAL);
	if (ctx->ct_srvaddr)
		free(ctx->ct_srvaddr);
	if ((ctx->ct_srvaddr = strdup(addr)) == NULL)
		return (ENOMEM);
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
		if (*cp) {
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
		ctx->ct_ssn.ioc_rights = strtol(arg, &cp, 8);
		if (*cp == '/') {
			ctx->ct_sh.ioc_rights = strtol(cp + 1, &cp, 8);
			ctx->ct_flags |= SMBCF_SRIGHTS;
		}
		break;
	case 'N':
		ctx->ct_flags |= SMBCF_NOPWD;
		break;
	case 'O':
		p = strdup(arg);
		cp = strchr(p, '/');
		if (cp) {
			*cp++ = '\0';
			error = smb_parse_owner(cp, &ctx->ct_sh.ioc_owner,
			    &ctx->ct_sh.ioc_group);
		}
		if (*p && error == 0) {
			error = smb_parse_owner(cp, &ctx->ct_ssn.ioc_owner,
			    &ctx->ct_ssn.ioc_group);
		}
		free(p);
		break;
	case 'P':
/*		ctx->ct_ssn.ioc_opt |= SMBCOPT_PERMANENT; */
		break;
	case 'R':
		ctx->ct_ssn.ioc_retrycount = atoi(arg);
		break;
	case 'T':
		ctx->ct_ssn.ioc_timeout = atoi(arg);
		break;
	case 'W':
		nls_str_upper(tmp, arg);
		error = smb_ctx_setworkgroup(ctx, tmp, TRUE);
		break;
	}
	return (error);
}

#if 0
static void
smb_hexdump(const uchar_t *buf, int len) {
	int ofs = 0;

	while (len--) {
		if (ofs % 16 == 0)
			printf("\n%02X: ", ofs);
		printf("%02x ", *buf++);
		ofs++;
	}
	printf("\n");
}
#endif


static int
smb_addiconvtbl(const char *to, const char *from, const uchar_t *tbl)
{
	int error;

	/*
	 * Not able to find out what is the work of this routine till
	 * now. Still investigating.
	 * REVISIT
	 */
#ifdef KICONV_SUPPORT
	error = kiconv_add_xlat_table(to, from, tbl);
	if (error && error != EEXIST) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can not setup kernel iconv table (%s:%s)"),
		    error, from, to);
		return (error);
	}
#endif
	return (0);
}

/*
 * Verify context before connect operation(s),
 * lookup specified server and try to fill all forgotten fields.
 */
int
smb_ctx_resolve(struct smb_ctx *ctx)
{
	struct smbioc_ossn *ssn = &ctx->ct_ssn;
	struct smbioc_oshare *sh = &ctx->ct_sh;
	struct nb_name nn;
	struct sockaddr *sap;
	struct sockaddr_nb *salocal, *saserver;
	char *cp;
	uchar_t cstbl[256];
	uint_t i;
	int error = 0;
	int browseok = ctx->ct_flags & SMBCF_BROWSEOK;
	int renego = 0;

	ctx->ct_flags &= ~SMBCF_RESOLVED;
	if (isatty(STDIN_FILENO))
		browseok = 0;
	if (ctx->ct_fullserver == NULL || ctx->ct_fullserver[0] == 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "no server name specified"), 0);
		return (EINVAL);
	}
	if (ctx->ct_minlevel >= SMBL_SHARE && sh->ioc_share[0] == 0 &&
	    !browseok) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "no share name specified for %s@%s"),
		    0, ssn->ioc_user, ssn->ioc_srvname);
		return (EINVAL);
	}
	error = nb_ctx_resolve(ctx->ct_nb);
	if (error)
		return (error);
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
	/*
	 * If we have an explicit address set for the server in
	 * an "addr=X" setting in .nsmbrc or SMF, just try using a
	 * gethostbyname() lookup for it.
	 */
	if (ctx->ct_srvaddr) {
		error = nb_resolvehost_in(ctx->ct_srvaddr, &sap);
		if (error == 0)
			(void) smb_ctx_getnbname(ctx, sap);
	} else
		error = -1;

	/*
	 * Next try a gethostbyname() lookup on the original user-
	 * specified server name. This is similar to Windows
	 * NBT option "Use DNS for name resolution."
	 */
	if (error && ctx->ct_fullserver) {
		error = nb_resolvehost_in(ctx->ct_fullserver, &sap);
		if (error == 0)
			(void) smb_ctx_getnbname(ctx, sap);
	}

	/*
	 * Finally, try the shorter, upper-cased ssn->ioc_srvname
	 * with a NBNS/WINS lookup if the "nbns_enable" property is
	 * true (the default).  nbns_resolvename() may unicast to the
	 * "nbns" server or broadcast on the subnet.
	 */
	if (error && ssn->ioc_srvname[0] &&
	    ctx->ct_nb->nb_flags & NBCF_NS_ENABLE) {
		error = nbns_resolvename(ssn->ioc_srvname,
		    ctx->ct_nb, &sap);
		/*
		 * Used to get the NetBIOS node status here.
		 * Not necessary (we have the NetBIOS name).
		 */
	}
	if (error) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't get server address"), error);
		return (error);
	}

	/* XXX: no nls_str_upper(ssn->ioc_srvname) here? */

	assert(sizeof (nn.nn_name) == sizeof (ssn->ioc_srvname));
	memcpy(nn.nn_name, ssn->ioc_srvname, NB_NAMELEN);
	nn.nn_type = NBT_SERVER;
	nn.nn_scope = ctx->ct_nb->nb_scope;

	error = nb_sockaddr(sap, &nn, &saserver);
	memcpy(&ctx->ct_srvinaddr, sap, sizeof (struct sockaddr_in));
	nb_snbfree(sap);
	if (error) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't allocate server address"), error);
		return (error);
	}
	/* We know it's a NetBIOS address here. */
	bcopy(saserver, &ssn->ioc_server.nb,
	    sizeof (struct sockaddr_nb));
	if (ctx->ct_locname[0] == 0) {
		error = nb_getlocalname(ctx->ct_locname,
		    SMB_MAXUSERNAMELEN + 1);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "can't get local name"), error);
			return (error);
		}
		nls_str_upper(ctx->ct_locname, ctx->ct_locname);
	}

	/* XXX: no nls_str_upper(ctx->ct_locname); here? */

	memcpy(nn.nn_name, ctx->ct_locname, NB_NAMELEN);
	nn.nn_type = NBT_WKSTA;
	nn.nn_scope = ctx->ct_nb->nb_scope;

	error = nb_sockaddr(NULL, &nn, &salocal);
	if (error) {
		nb_snbfree((struct sockaddr *)saserver);
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't allocate local address"), error);
		return (error);
	}

	/* We know it's a NetBIOS address here. */
	bcopy(salocal, &ssn->ioc_local.nb,
	    sizeof (struct sockaddr_nb));

	error = smb_ctx_findvc(ctx, SMBL_VC, 0);
	if (error == 0) {
		/* re-use and existing VC */
		ctx->ct_flags |= SMBCF_RESOLVED | SMBCF_SSNACTIVE;
		return (0);
	}

	/* Make a new connection via smb_ctx_negotiate()... */
	error = smb_ctx_negotiate(ctx, SMBL_SHARE, SMBLK_CREATE,
	    ssn->ioc_workgroup);
	if (error)
		return (error);
	ctx->ct_flags &= ~SMBCF_AUTHREQ;
	if (!ctx->ct_secblob && browseok && !sh->ioc_share[0] &&
	    !(ctx->ct_flags & SMBCF_XXX)) {
		/* assert: anon share list is subset of overall server shares */
		error = smb_browse(ctx, 1);
		if (error) /* user cancel or other error? */
			return (error);
		/*
		 * A share was selected, authenticate button was pressed,
		 * or anon-authentication failed getting browse list.
		 */
	}
	if ((ctx->ct_secblob == NULL) && (ctx->ct_flags & SMBCF_AUTHREQ ||
	    (ssn->ioc_password[0] == '\0' &&
	    !(ctx->ct_flags & SMBCF_NOPWD)))) {
reauth:
		/*
		 * This function is implemented in both
		 * ui-apple.c and ui-sun.c so let's try to
		 * keep the same interface.  Not sure why
		 * they didn't just pass ssn here.
		 */
		error = smb_get_authentication(
		    ssn->ioc_workgroup, sizeof (ssn->ioc_workgroup) - 1,
		    ssn->ioc_user, sizeof (ssn->ioc_user) - 1,
		    ssn->ioc_password, sizeof (ssn->ioc_password) - 1,
		    ssn->ioc_srvname, ctx);
		if (error)
			return (error);
	}
	/*
	 * if we have a session it is either anonymous
	 * or from a stale authentication.  re-negotiating
	 * gets us ready for a fresh session
	 */
	if (ctx->ct_flags & SMBCF_SSNACTIVE || renego) {
		renego = 0;
		/* don't clobber workgroup name, pass null arg */
		error = smb_ctx_negotiate(ctx, SMBL_SHARE, SMBLK_CREATE, NULL);
		if (error)
			return (error);
	}
	if (browseok && !sh->ioc_share[0]) {
		ctx->ct_flags &= ~SMBCF_AUTHREQ;
		error = smb_browse(ctx, 0);
		if (ctx->ct_flags & SMBCF_KCFOUND && smb_autherr(error)) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "smb_ctx_resolve: bad keychain entry"), 0);
			ctx->ct_flags |= SMBCF_KCBAD;
			renego = 1;
			goto reauth;
		}
		if (error) /* auth, user cancel, or other error */
			return (error);
		/*
		 * Re-authenticate button was pressed?
		 */
		if (ctx->ct_flags & SMBCF_AUTHREQ)
			goto reauth;
		if (!sh->ioc_share[0] && !(ctx->ct_flags & SMBCF_XXX)) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "no share specified for %s@%s"),
			    0, ssn->ioc_user, ssn->ioc_srvname);
			return (EINVAL);
		}
	}
	ctx->ct_flags |= SMBCF_RESOLVED;

	if (smb_debug)
		dump_ctx("after smb_ctx_resolve", ctx);

	return (0);
}

int
smb_open_driver()
{
	char buf[20];
	int err, fd, i;
	uint32_t version;

	/*
	 * First try to open as clone
	 */
	fd = open("/dev/"NSMB_NAME, O_RDWR);
	if (fd >= 0)
		goto opened;

	err = errno; /* from open */
#ifdef APPLE
	/*
	 * well, no clone capabilities available - we have to scan
	 * all devices in order to get free one
	 */
	for (i = 0; i < 1024; i++) {
		snprintf(buf, sizeof (buf), "/dev/%s%d", NSMB_NAME, i);
		fd = open(buf, O_RDWR);
		if (fd >= 0)
			goto opened;
		if (i && POWEROF2(i+1))
			smb_error(dgettext(TEXT_DOMAIN,
			    "%d failures to open smb device"), errno, i+1);
	}
	err = ENOENT;
#endif
	smb_error(dgettext(TEXT_DOMAIN,
	    "failed to open %s"), err, "/dev/" NSMB_NAME);
	return (-1);

opened:
	/*
	 * Check the driver version (paranoia)
	 * Do this BEFORE any other ioctl calls.
	 */
	if (ioctl(fd, SMBIOC_GETVERS, &version) < 0) {
		err = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "failed to get driver version"), err);
		close(fd);
		return (-1);
	}
	if (version != NSMB_VERSION) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "incorrect driver version"), 0);
		close(fd);
		return (-1);
	}

	return (fd);
}

static int
smb_ctx_gethandle(struct smb_ctx *ctx)
{
	int err, fd;

	if (ctx->ct_fd != -1) {
		rpc_cleanup_smbctx(ctx);
		close(ctx->ct_fd);
		ctx->ct_fd = -1;
		ctx->ct_flags &= ~SMBCF_SSNACTIVE;
	}

	fd = smb_open_driver();
	if (fd < 0)
		return (ENODEV);

	ctx->ct_fd = fd;
	return (0);
}

int
smb_ctx_ioctl(struct smb_ctx *ctx, int inum, struct smbioc_lookup *rqp)
{
	size_t	siz = DEF_SEC_TOKEN_LEN;
	int	rc = 0;
	struct sockaddr sap1, sap2;
	int i;

	if (rqp->ioc_ssn.ioc_outtok)
		free(rqp->ioc_ssn.ioc_outtok);
	rqp->ioc_ssn.ioc_outtoklen = siz;
	rqp->ioc_ssn.ioc_outtok = malloc(siz+1);
	if (rqp->ioc_ssn.ioc_outtok == NULL)
		return (ENOMEM);
	bzero(rqp->ioc_ssn.ioc_outtok, siz+1);
	/* Note: No longer put length in outtok[0] */
	/* *((int *)rqp->ioc_ssn.ioc_outtok) = (int)siz; */

	seteuid(eff_uid); /* restore setuid root briefly */
	if (ioctl(ctx->ct_fd, inum, rqp) == -1) {
		rc = errno;
		goto out;
	}
	if (rqp->ioc_ssn.ioc_outtoklen <= siz)
		goto out;

	/*
	 * Operation completed, but our output token wasn't large enough.
	 * The re-call below only pulls the token from the kernel.
	 */
	siz = rqp->ioc_ssn.ioc_outtoklen;
	free(rqp->ioc_ssn.ioc_outtok);
	rqp->ioc_ssn.ioc_outtok = malloc(siz + 1);
	if (rqp->ioc_ssn.ioc_outtok == NULL) {
		rc = ENOMEM;
		goto out;
	}
	bzero(rqp->ioc_ssn.ioc_outtok, siz+1);
	/* Note: No longer put length in outtok[0] */
	/* *((int *)rqp->ioc_ssn.ioc_outtok) = siz; */
	if (ioctl(ctx->ct_fd, inum, rqp) == -1)
		rc = errno;
out:
	seteuid(real_uid); /* and back to real user */
	return (rc);
}

int
smb_ctx_findvc(struct smb_ctx *ctx, int level, int flags)
{
	struct smbioc_lookup	rq;
	int	error = 0;

	if ((error = smb_ctx_gethandle(ctx)))
		return (error);

	bzero(&rq, sizeof (rq));
	bcopy(&ctx->ct_ssn, &rq.ioc_ssn, sizeof (struct smbioc_ossn));
	bcopy(&ctx->ct_sh, &rq.ioc_sh, sizeof (struct smbioc_oshare));

	rq.ioc_flags = flags;
	rq.ioc_level = level;

	return (smb_ctx_ioctl(ctx, SMBIOC_FINDVC, &rq));
}

/*
 * adds a GSSAPI wrapper
 */
char *
smb_ctx_tkt2gtok(uchar_t *tkt, ulong_t tktlen,
    uchar_t **gtokp, ulong_t *gtoklenp)
{
	ulong_t		bloblen = tktlen;
	ulong_t		len;
	uchar_t		krbapreq[2] = "\x01\x00"; /* see RFC 1964 */
	char 		*failure;
	uchar_t 	*blob = NULL;		/* result */
	uchar_t 	*b;

	bloblen += sizeof (krbapreq);
	bloblen += g_stcMechOIDList[spnego_mech_oid_Kerberos_V5].iLen;
	len = bloblen;
	bloblen = ASNDerCalcTokenLength(bloblen, bloblen);
	failure = dgettext(TEXT_DOMAIN, "smb_ctx_tkt2gtok malloc");
	if (!(blob = malloc(bloblen)))
		goto out;
	b = blob;
	b += ASNDerWriteToken(b, SPNEGO_NEGINIT_APP_CONSTRUCT, NULL, len);
	b += ASNDerWriteOID(b, spnego_mech_oid_Kerberos_V5);
	memcpy(b, krbapreq, sizeof (krbapreq));
	b += sizeof (krbapreq);
	failure = dgettext(TEXT_DOMAIN, "smb_ctx_tkt2gtok insanity check");
	if (b + tktlen != blob + bloblen)
		goto out;
	memcpy(b, tkt, tktlen);
	*gtoklenp = bloblen;
	*gtokp = blob;
	failure = NULL;
out:;
	if (blob && failure)
		free(blob);
	return (failure);
}


/*
 * Initialization for Kerberos, pulled out of smb_ctx_principal2tkt.
 * This just gets our cached credentials, if we have any.
 * Based on the "klist" command.
 */
char *
smb_ctx_krb5init(struct smb_ctx *ctx)
{
	char *failure;
	krb5_error_code	kerr;
	krb5_context	kctx = NULL;
	krb5_ccache 	kcc = NULL;
	krb5_principal	kprin = NULL;

	kerr = krb5_init_context(&kctx);
	if (kerr) {
		failure = "krb5_init_context";
		goto out;
	}
	ctx->ct_krb5ctx = kctx;

	/* non-default would instead use krb5_cc_resolve */
	kerr = krb5_cc_default(kctx, &kcc);
	if (kerr) {
		failure = "krb5_cc_default";
		goto out;
	}
	ctx->ct_krb5cc = kcc;

	/*
	 * Get the client principal (ticket),
	 * or find out if we don't have one.
	 */
	kerr = krb5_cc_get_principal(kctx, kcc, &kprin);
	if (kerr) {
		failure = "krb5_cc_get_principal";
		goto out;
	}
	ctx->ct_krb5cp = kprin;

	if (smb_verbose) {
		fprintf(stderr, gettext("Ticket cache: %s:%s\n"),
		    krb5_cc_get_type(kctx, kcc),
		    krb5_cc_get_name(kctx, kcc));
	}
	failure = NULL;

out:
	return (failure);
}


/*
 * See "Windows 2000 Kerberos Interoperability" paper by
 * Christopher Nebergall.  RC4 HMAC is the W2K default but
 * Samba support lagged (not due to Samba itself, but due to OS'
 * Kerberos implementations.)
 *
 * Only session enc type should matter, not ticket enc type,
 * per Sam Hartman on krbdev.
 *
 * Preauthentication failure topics in krb-protocol may help here...
 * try "John Brezak" and/or "Clifford Neuman" too.
 */
static krb5_enctype kenctypes[] = {
	ENCTYPE_ARCFOUR_HMAC,	/* defined in Tiger krb5.h */
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_DES_CBC_CRC,
	ENCTYPE_NULL
};

/*
 * Obtain a kerberos ticket...
 * (if TLD != "gov" then pray first)
 */
char *
smb_ctx_principal2tkt(
	struct smb_ctx *ctx, char *prin,
	uchar_t **tktp, ulong_t *tktlenp)
{
	char 		*failure;
	krb5_context	kctx = NULL;
	krb5_error_code	kerr;
	krb5_ccache	kcc = NULL;
	krb5_principal	kprin = NULL, cprn = NULL;
	krb5_creds	kcreds, *kcredsp = NULL;
	krb5_auth_context	kauth = NULL;
	krb5_data	kdata, kdata0;
	uchar_t 		*tkt;

	memset((char *)&kcreds, 0, sizeof (kcreds));
	kdata0.length = 0;

	/* These shoud have been done in smb_ctx_krb5init() */
	if (ctx->ct_krb5ctx == NULL ||
	    ctx->ct_krb5cc == NULL ||
	    ctx->ct_krb5cp == NULL) {
		failure = "smb_ctx_krb5init";
		goto out;
	}
	kctx = ctx->ct_krb5ctx;
	kcc  = ctx->ct_krb5cc;
	cprn = ctx->ct_krb5cp;

	failure = "krb5_set_default_tgs_enctypes";
	if ((kerr = krb5_set_default_tgs_enctypes(kctx, kenctypes)))
		goto out;
	/*
	 * The following is an unrolling of krb5_mk_req.  Something like:
	 * krb5_mk_req(kctx, &kauth, 0, service(prin), hostname(prin),
	 *		&kdata0, kcc, &kdata);)
	 * ...except we needed krb5_parse_name not krb5_sname_to_principal.
	 */
	failure = "krb5_parse_name";
	if ((kerr = krb5_parse_name(kctx, prin, &kprin)))
		goto out;
	failure = "krb5_copy_principal(server)";
	if ((kerr = krb5_copy_principal(kctx, kprin, &kcreds.server)))
		goto out;
	failure = "krb5_copy_principal(client)";
	if ((kerr = krb5_copy_principal(kctx, cprn, &kcreds.client)))
		goto out;
	failure = "krb5_get_credentials";
	if ((kerr = krb5_get_credentials(kctx, 0, kcc, &kcreds, &kcredsp)))
		goto out;
	failure = "krb5_mk_req_extended";
	if ((kerr = krb5_mk_req_extended(kctx, &kauth, 0, &kdata0, kcredsp,
	    &kdata)))
		goto out;
	failure = "malloc";
	if (!(tkt = malloc(kdata.length))) {
		krb5_free_data_contents(kctx, &kdata);
		goto out;
	}
	*tktlenp = kdata.length;
	memcpy(tkt, kdata.data, kdata.length);
	krb5_free_data_contents(kctx, &kdata);
	*tktp = tkt;
	failure = NULL;
out:;
	if (kerr) {
		if (!failure)
			failure = "smb_ctx_principal2tkt";
		/*
		 * Avoid logging the typical "No credentials cache found"
		 */
		if (kerr != KRB5_FCC_NOFILE ||
		    strcmp(failure, "krb5_cc_get_principal"))
			com_err(__progname, kerr, failure);
	}
	if (kauth)
		krb5_auth_con_free(kctx, kauth);
	if (kcredsp)
		krb5_free_creds(kctx, kcredsp);
	if (kcreds.server || kcreds.client)
		krb5_free_cred_contents(kctx, &kcreds);
	if (kprin)
		krb5_free_principal(kctx, kprin);

	/* Free kctx in smb_ctx_done */

	return (failure);
}

char *
smb_ctx_principal2blob(
	struct smb_ctx *ctx,
	smbioc_ossn_t *ssn,
	char *prin)
{
	int		rc = 0;
	char 		*failure;
	uchar_t 	*tkt = NULL;
	ulong_t		tktlen;
	uchar_t 	*gtok = NULL;		/* gssapi token */
	ulong_t		gtoklen;		/* gssapi token length */
	SPNEGO_TOKEN_HANDLE  stok = NULL;	/* spnego token */
	void 	*blob = NULL;		/* result */
	ulong_t		bloblen;		/* result length */

	if ((failure = smb_ctx_principal2tkt(ctx, prin, &tkt, &tktlen)))
		goto out;
	if ((failure = smb_ctx_tkt2gtok(tkt, tktlen, &gtok, &gtoklen)))
		goto out;
	/*
	 * RFC says to send NegTokenTarg now.  So does MS docs.  But
	 * win2k gives ERRbaduid if we do...  we must send
	 * another NegTokenInit now!
	 */
	failure = "spnegoCreateNegTokenInit";
	if ((rc = spnegoCreateNegTokenInit(spnego_mech_oid_Kerberos_V5_Legacy,
	    0, gtok, gtoklen, NULL, 0, &stok)))
		goto out;
	failure = "spnegoTokenGetBinary(NULL)";
	rc = spnegoTokenGetBinary(stok, NULL, &bloblen);
	if (rc != SPNEGO_E_BUFFER_TOO_SMALL)
		goto out;
	failure = "malloc";
	if (!(blob = malloc((size_t)bloblen)))
		goto out;
	/* No longer store length at start of blob. */
	/* *blob = bloblen; */
	failure = "spnegoTokenGetBinary";
	if ((rc = spnegoTokenGetBinary(stok, blob, &bloblen)))
		goto out;
	ssn->ioc_intoklen = bloblen;
	ssn->ioc_intok = blob;
	failure = NULL;
out:;
	if (rc) {
		/* XXX better is to embed rc in failure */
		smb_error(dgettext(TEXT_DOMAIN,
		    "spnego principal2blob error %d"), 0, -rc);
		if (!failure)
			failure = "spnego";
	}
	if (blob && failure)
		free(blob);
	if (stok)
		spnegoFreeData(stok);
	if (gtok)
		free(gtok);
	if (tkt)
		free(tkt);
	return (failure);
}


#if 0
void
prblob(uchar_t *b, size_t len)
{
	while (len--)
		fprintf(stderr, "%02x", *b++);
	fprintf(stderr, "\n");
}
#endif


/*
 * We navigate the SPNEGO & ASN1 encoding to find a kerberos principal
 * Note: driver no longer puts length at start of blob.
 */
char *
smb_ctx_blob2principal(
	struct smb_ctx *ctx,
	smbioc_ossn_t *ssn,
	char **prinp)
{
	uchar_t		*blob = ssn->ioc_outtok;
	size_t		len = ssn->ioc_outtoklen;
	int		rc = 0;
	SPNEGO_TOKEN_HANDLE	stok = NULL;
	int		indx = 0;
	char 		*failure;
	uchar_t		flags = 0;
	unsigned long	plen = 0;
	uchar_t 	*prin;

#if 0
	fprintf(stderr, "blob from negotiate:\n");
	prblob(blob, len);
#endif

	/* Skip the GUID */
	assert(len >= SMB_GUIDLEN);
	blob += SMB_GUIDLEN;
	len  -= SMB_GUIDLEN;

	failure = "spnegoInitFromBinary";
	if ((rc = spnegoInitFromBinary(blob, len, &stok)))
		goto out;
	/*
	 * Needn't use new Kerberos OID - the Legacy one is fine.
	 */
	failure = "spnegoIsMechTypeAvailable";
	if (spnegoIsMechTypeAvailable(stok, spnego_mech_oid_Kerberos_V5_Legacy,
	    &indx))
		goto out;
	/*
	 * Ignoring optional context flags for now.  May want to pass
	 * them to krb5 layer.  XXX
	 */
	if (!spnegoGetContextFlags(stok, &flags))
		fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "spnego context flags 0x%x\n"), flags);
	failure = "spnegoGetMechListMIC(NULL)";
	rc = spnegoGetMechListMIC(stok, NULL, &plen);
	if (rc != SPNEGO_E_BUFFER_TOO_SMALL)
		goto out;
	failure = "malloc";
	if (!(prin = malloc(plen + 1)))
		goto out;
	failure = "spnegoGetMechListMIC";
	if ((rc = spnegoGetMechListMIC(stok, prin, &plen))) {
		free(prin);
		goto out;
	}
	prin[plen] = '\0';
	*prinp = (char *)prin;
	failure = NULL;
out:;
	if (stok)
		spnegoFreeData(stok);
	if (rc) {
		/* XXX better is to embed rc in failure */
		smb_error(dgettext(TEXT_DOMAIN,
		    "spnego blob2principal error %d"), 0, -rc);
		if (!failure)
			failure = "spnego";
	}
	return (failure);
}


int
smb_ctx_negotiate(struct smb_ctx *ctx, int level, int flags, char *workgroup)
{
	struct smbioc_lookup	rq;
	int	error = 0;
	char 	*failure = NULL;
	char	*principal = NULL;
	char c;
	int i;
	ssize_t *outtoklen;
	uchar_t *blob;

	/*
	 * We leave ct_secblob set iff extended security
	 * negotiation succeeds.
	 */
	if (ctx->ct_secblob) {
		free(ctx->ct_secblob);
		ctx->ct_secblob = NULL;
	}
#ifdef XXX
	if ((ctx->ct_flags & SMBCF_RESOLVED) == 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "smb_ctx_lookup() data is not resolved"), 0);
		return (EINVAL);
	}
#endif
	if ((error = smb_ctx_gethandle(ctx)))
		return (error);

	bzero(&rq, sizeof (rq));
	bcopy(&ctx->ct_ssn, &rq.ioc_ssn, sizeof (struct smbioc_ossn));
	bcopy(&ctx->ct_sh, &rq.ioc_sh, sizeof (struct smbioc_oshare));

	/*
	 * Find out if we have a Kerberos ticket,
	 * and only offer SPNEGO if we have one.
	 */
	failure = smb_ctx_krb5init(ctx);
	if (failure) {
		if (smb_verbose)
			smb_error(failure, 0);
		goto out;
	}

	rq.ioc_flags = flags;
	rq.ioc_level = level;
	rq.ioc_ssn.ioc_opt |= SMBVOPT_EXT_SEC;
	error = smb_ctx_ioctl(ctx, SMBIOC_NEGOTIATE, &rq);
	if (error) {
		failure = dgettext(TEXT_DOMAIN, "negotiate failed");
		smb_error(failure, error);
		if (error == ETIMEDOUT)
			return (error);
		goto out;
	}
	/*
	 * If the server capabilities did not include
	 * SMB_CAP_EXT_SECURITY then the driver clears
	 * the flag SMBVOPT_EXT_SEC for us.
	 * XXX: should add the capabilities to ioc_ssn
	 * XXX: see comment in driver - smb_usr.c
	 */
	failure = dgettext(TEXT_DOMAIN, "SPNEGO unsupported");
	if ((rq.ioc_ssn.ioc_opt & SMBVOPT_EXT_SEC) == 0) {
		if (smb_verbose)
			smb_error(failure, 0);
		/*
		 * Do regular (old style) NTLM or NTLMv2
		 * Nothing more to do here in negotiate.
		 */
		return (0);
	}

	/*
	 * Capabilities DO include SMB_CAP_EXT_SECURITY,
	 * so this should be an SPNEGO security blob.
	 * Parse the ASN.1/DER, prepare response(s).
	 * XXX: Handle STATUS_MORE_PROCESSING_REQUIRED?
	 * XXX: Requires additional session setup calls.
	 */
	if (rq.ioc_ssn.ioc_outtoklen <= SMB_GUIDLEN)
		goto out;
	/* some servers send padding junk */
	blob = rq.ioc_ssn.ioc_outtok;
	if (blob[0] == 0)
		goto out;

	failure = smb_ctx_blob2principal(
	    ctx, &rq.ioc_ssn, &principal);
	if (failure)
		goto out;
	failure = smb_ctx_principal2blob(
	    ctx, &rq.ioc_ssn, principal);
	if (failure)
		goto out;

	/* Success! Save the blob to send next. */
	ctx->ct_secblob = rq.ioc_ssn.ioc_intok;
	ctx->ct_secbloblen = rq.ioc_ssn.ioc_intoklen;
	rq.ioc_ssn.ioc_intok = NULL;

out:
	if (principal)
		free(principal);
	if (rq.ioc_ssn.ioc_intok)
		free(rq.ioc_ssn.ioc_intok);
	if (rq.ioc_ssn.ioc_outtok)
		free(rq.ioc_ssn.ioc_outtok);
	if (!failure)
		return (0);		/* Success! */

	/*
	 * Negotiate failed with "extended security".
	 *
	 * XXX: If we are doing SPNEGO correctly,
	 * we should never get here unless the user
	 * supplied invalid authentication data,
	 * or we saw some kind of protocol error.
	 *
	 * XXX: The error message below should be
	 * XXX: unconditional (remove "if verbose")
	 * XXX: but not until we have "NTLMSSP"
	 * Avoid spew for anticipated failure modes
	 * but enable this with the verbose flag
	 */
	if (smb_verbose) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s (extended security negotiate)"), error, failure);
	}

	/*
	 * XXX: Try again using NTLM (or NTLMv2)
	 * XXX: Normal clients don't do this.
	 * XXX: Should just return an error, but
	 * keep the fall-back to NTLM for now.
	 *
	 * Start over with a new connection.
	 */
	if ((error = smb_ctx_gethandle(ctx)))
		return (error);
	bzero(&rq, sizeof (rq));
	bcopy(&ctx->ct_ssn, &rq.ioc_ssn, sizeof (struct smbioc_ossn));
	bcopy(&ctx->ct_sh, &rq.ioc_sh, sizeof (struct smbioc_oshare));
	rq.ioc_flags = flags;
	rq.ioc_level = level;
	/* Note: NO SMBVOPT_EXT_SEC */
	error = smb_ctx_ioctl(ctx, SMBIOC_NEGOTIATE, &rq);
	if (error) {
		failure = dgettext(TEXT_DOMAIN, "negotiate failed");
		smb_error(failure, error);
		rpc_cleanup_smbctx(ctx);
		close(ctx->ct_fd);
		ctx->ct_fd = -1;
		return (error);
	}

	/*
	 * Used to copy the workgroup out of the SMB_NEGOTIATE response
	 * here, to default our domain name to be the same as the server.
	 * Not a good idea: Unnecessary at best, and sometimes wrong, i.e.
	 * when our account is in a trusted domain.
	 */

	return (error);
}


int
smb_ctx_tdis(struct smb_ctx *ctx)
{
	struct smbioc_lookup rq; /* XXX may be used, someday */
	int error = 0;

	if (ctx->ct_fd < 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "tree disconnect without handle?!"), 0);
		return (EINVAL);
	}
	if (!(ctx->ct_flags & SMBCF_SSNACTIVE)) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "tree disconnect without session?!"), 0);
		return (EINVAL);
	}
	bzero(&rq, sizeof (rq));
	bcopy(&ctx->ct_ssn, &rq.ioc_ssn, sizeof (struct smbioc_ossn));
	bcopy(&ctx->ct_sh, &rq.ioc_sh, sizeof (struct smbioc_oshare));
	if (ioctl(ctx->ct_fd, SMBIOC_TDIS, &rq) == -1) {
		error = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "tree disconnect failed"), error);
	}
	return (error);
}


int
smb_ctx_lookup(struct smb_ctx *ctx, int level, int flags)
{
	struct smbioc_lookup rq;
	int error = 0;
	char 	*failure = NULL;

	if ((ctx->ct_flags & SMBCF_RESOLVED) == 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "smb_ctx_lookup() data is not resolved"), 0);
		return (EINVAL);
	}
	if (ctx->ct_fd < 0) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "handle from smb_ctx_nego() gone?!"), 0);
		return (EINVAL);
	}
	if (!(flags & SMBLK_CREATE))
		return (0);
	bzero(&rq, sizeof (rq));
	bcopy(&ctx->ct_ssn, &rq.ioc_ssn, sizeof (struct smbioc_ossn));
	bcopy(&ctx->ct_sh, &rq.ioc_sh, sizeof (struct smbioc_oshare));
	rq.ioc_flags = flags;
	rq.ioc_level = level;

	/*
	 * Iff we have a security blob, we're using
	 * extended security...
	 */
	if (ctx->ct_secblob) {
		rq.ioc_ssn.ioc_opt |= SMBVOPT_EXT_SEC;
		if (!(ctx->ct_flags & SMBCF_SSNACTIVE)) {
			rq.ioc_ssn.ioc_intok = ctx->ct_secblob;
			rq.ioc_ssn.ioc_intoklen = ctx->ct_secbloblen;
			error = smb_ctx_ioctl(ctx, SMBIOC_SSNSETUP, &rq);
		}
		rq.ioc_ssn.ioc_intok = NULL;
		if (error) {
			failure = dgettext(TEXT_DOMAIN,
			    "session setup failed");
		} else {
			ctx->ct_flags |= SMBCF_SSNACTIVE;
			if ((error = smb_ctx_ioctl(ctx, SMBIOC_TCON, &rq)))
				failure = dgettext(TEXT_DOMAIN,
				    "tree connect failed");
		}
		if (rq.ioc_ssn.ioc_intok)
			free(rq.ioc_ssn.ioc_intok);
		if (rq.ioc_ssn.ioc_outtok)
			free(rq.ioc_ssn.ioc_outtok);
		if (!failure)
			return (0);
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s (extended security lookup2)"), error, failure);
		/* unwise to failback to NTLM now */
		return (error);
	}

	/*
	 * Otherwise we're doing plain old NTLM
	 */
	seteuid(eff_uid); /* restore setuid root briefly */
	if ((ctx->ct_flags & SMBCF_SSNACTIVE) == 0) {
		/*
		 * This is the magic that tells the driver to
		 * copy the password from the keychain, and
		 * whether to use the system name or the
		 * account domain to lookup the keychain.
		 */
		if (ctx->ct_flags & SMBCF_KCFOUND)
			rq.ioc_ssn.ioc_opt |= SMBVOPT_USE_KEYCHAIN;
		if (ctx->ct_flags & SMBCF_KCDOMAIN)
			rq.ioc_ssn.ioc_opt |= SMBVOPT_KC_DOMAIN;
		if (ioctl(ctx->ct_fd, SMBIOC_SSNSETUP, &rq) < 0) {
			error = errno;
			failure = dgettext(TEXT_DOMAIN, "session setup");
			goto out;
		}
		ctx->ct_flags |= SMBCF_SSNACTIVE;
	}
	if (ioctl(ctx->ct_fd, SMBIOC_TCON, &rq) == -1) {
		error = errno;
		failure = dgettext(TEXT_DOMAIN, "tree connect");
	}

out:
	seteuid(real_uid); /* and back to real user */
	if (failure) {
		error = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s phase failed"), error, failure);
	}
	return (error);
}

/*
 * Return the hflags2 word for an smb_ctx.
 */
int
smb_ctx_flags2(struct smb_ctx *ctx)
{
	uint16_t flags2;

	if (ioctl(ctx->ct_fd, SMBIOC_FLAGS2, &flags2) == -1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't get flags2 for a session"), errno);
		return (-1);
	}
	printf(dgettext(TEXT_DOMAIN, "Flags2 value is %d\n"), flags2);
	return (flags2);
}

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

#ifdef NOT_DEFINED
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

		rc_getint(smb_rc, sname, "timeout",
		    &ctx->ct_ssn.ioc_timeout);

#ifdef NOT_DEFINED
		rc_getint(smb_rc, sname, "retry_count",
		    &ctx->ct_ssn.ioc_retrycount);
		rc_getstringptr(smb_rc, sname, "use_negprot_domain", &p);
		if (p && strcmp(p, "NO") == 0)
			ctx->ct_flags |= SMBCF_NONEGDOM;
#endif

		rc_getstringptr(smb_rc, sname, "minauth", &p);
		if (p) {
			/*
			 * "minauth" was set in this section; override
			 * the current minimum authentication setting.
			 */
			ctx->ct_ssn.ioc_opt &= ~SMBVOPT_MINAUTH;
			if (strcmp(p, "kerberos") == 0) {
				/*
				 * Don't fall back to NTLMv2, NTLMv1, or
				 * a clear text password.
				 */
				ctx->ct_ssn.ioc_opt |= SMBVOPT_MINAUTH_KERBEROS;
			} else if (strcmp(p, "ntlmv2") == 0) {
				/*
				 * Don't fall back to NTLMv1 or a clear
				 * text password.
				 */
				ctx->ct_ssn.ioc_opt |= SMBVOPT_MINAUTH_NTLMV2;
			} else if (strcmp(p, "ntlm") == 0) {
				/*
				 * Don't send the LM response over the wire.
				 */
				ctx->ct_ssn.ioc_opt |= SMBVOPT_MINAUTH_NTLM;
			} else if (strcmp(p, "lm") == 0) {
				/*
				 * Fail if the server doesn't do encrypted
				 * passwords.
				 */
				ctx->ct_ssn.ioc_opt |= SMBVOPT_MINAUTH_LM;
			} else if (strcmp(p, "none") == 0) {
				/*
				 * Anything goes.
				 * (The following statement should be
				 * optimized away.)
				 */
				/* LINTED */
				ctx->ct_ssn.ioc_opt |= SMBVOPT_MINAUTH_NONE;
			} else {
				/*
				 * Unknown minimum authentication level.
				 */
				smb_error(dgettext(TEXT_DOMAIN,
"invalid minimum authentication level \"%s\" specified in the section %s"),
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
			nls_str_upper(p, p);
			error = smb_ctx_setworkgroup(ctx, p, 0);
			if (error)
				smb_error(dgettext(TEXT_DOMAIN,
				    "workgroup specification in the "
				    "section '%s' ignored"), error, sname);
		}
		rc_getstringptr(smb_rc, sname, "domain", &p);
		if (p) {
			nls_str_upper(p, p);
			error = smb_ctx_setworkgroup(ctx, p, 0);
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
	char sname[SMB_MAXSRVNAMELEN + SMB_MAXUSERNAMELEN +
	    SMB_MAXSHARENAMELEN + 4];

	if (smb_open_rcfile(ctx) != 0)
		goto done;

	/*
	 * default parameters (level=0)
	 */
	smb_ctx_readrcsection(ctx, "default", 0);
	nb_ctx_readrcsection(smb_rc, ctx->ct_nb, "default", 0);

	/*
	 * If we don't have a server name, we can't read any of the
	 * [server...] sections.
	 */
	if (ctx->ct_ssn.ioc_srvname[0] == 0)
		goto done;

	/*
	 * SERVER parameters.
	 */
	smb_ctx_readrcsection(ctx, ctx->ct_ssn.ioc_srvname, 1);

	/*
	 * If we don't have a user name, we can't read any of the
	 * [server:user...] sections.
	 */
	if (ctx->ct_ssn.ioc_user[0] == 0)
		goto done;

	/*
	 * SERVER:USER parameters
	 */
	snprintf(sname, sizeof (sname), "%s:%s",
	    ctx->ct_ssn.ioc_srvname,
	    ctx->ct_ssn.ioc_user);
	smb_ctx_readrcsection(ctx, sname, 2);

	/*
	 * If we don't have a share name, we can't read any of the
	 * [server:user:share] sections.
	 */
	if (ctx->ct_sh.ioc_share[0] != 0) {
		/*
		 * SERVER:USER:SHARE parameters
		 */
		snprintf(sname, sizeof (sname), "%s:%s:%s",
		    ctx->ct_ssn.ioc_srvname,
		    ctx->ct_ssn.ioc_user,
		    ctx->ct_sh.ioc_share);
		smb_ctx_readrcsection(ctx, sname, 3);
	}

done:
	if (smb_debug)
		dump_ctx("after smb_ctx_readrc", ctx);

	return (0);
}
