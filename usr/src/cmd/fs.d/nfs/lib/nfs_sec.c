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
/* LINTLIBRARY */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * nfs security related library routines.
 *
 * Some of the routines in this file are adopted from
 * lib/libnsl/netselect/netselect.c and are modified to be
 * used for accessing /etc/nfssec.conf.
 */

/* SVr4.0 1.18	*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <synch.h>
#include <rpc/rpc.h>
#include <nfs/nfs_sec.h>
#include <rpc/rpcsec_gss.h>
#ifdef WNFS_SEC_NEGO
#include "webnfs.h"
#endif

#define	GETBYNAME	1
#define	GETBYNUM	2

/*
 * mapping for /etc/nfssec.conf
 */
struct sc_data {
	char	*string;
	int	value;
};

static struct sc_data sc_service[] = {
	"default",	rpc_gss_svc_default,
	"-",		rpc_gss_svc_none,
	"none",		rpc_gss_svc_none,
	"integrity",	rpc_gss_svc_integrity,
	"privacy",	rpc_gss_svc_privacy,
	NULL,		SC_FAILURE
};

static mutex_t matching_lock = DEFAULTMUTEX;
static char *gettoken(char *, int);
extern	int atoi(const char *str);

extern	bool_t rpc_gss_get_principal_name(rpc_gss_principal_t *, char *,
			char *, char *, char *);

extern	bool_t rpc_gss_mech_to_oid(char *, rpc_gss_OID *);
extern	bool_t rpc_gss_qop_to_num(char *, char *, uint_t *);

/*
 *  blank() returns true if the line is a blank line, 0 otherwise
 */
static int
blank(cp)
char *cp;
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '\0');
}

/*
 *  comment() returns true if the line is a comment, 0 otherwise.
 */
static int
comment(cp)
char *cp;
{
	while (*cp && isspace(*cp)) {
		cp++;
	}
	return (*cp == '#');
}


/*
 *	getvalue() searches for the given string in the given array,
 *	and returns the integer value associated with the string.
 */
static unsigned long
getvalue(cp, sc_data)
char *cp;
struct sc_data sc_data[];
{
	int i;	/* used to index through the given struct sc_data array */

	for (i = 0; sc_data[i].string; i++) {
		if (strcmp(sc_data[i].string, cp) == 0) {
			break;
		}
	}
	return (sc_data[i].value);
}

/*
 *	shift1left() moves all characters in the string over 1 to
 *	the left.
 */
static void
shift1left(p)
char *p;
{
	for (; *p; p++)
		*p = *(p + 1);
}


/*
 *	gettoken() behaves much like strtok(), except that
 *	it knows about escaped space characters (i.e., space characters
 *	preceeded by a '\' are taken literally).
 *
 *	XXX We should make this MT-hot by making it more like strtok_r().
 */
static char *
gettoken(cp, skip)
char	*cp;
int skip;
{
	static char	*savep;	/* the place where we left off    */
	register char	*p;	/* the beginning of the new token */
	register char	*retp;	/* the token to be returned	  */


	/* Determine if first or subsequent call  */
	p = (cp == NULL)? savep: cp;

	/* Return if no tokens remain.  */
	if (p == 0) {
		return (NULL);
	}

	while (isspace(*p))
		p++;

	if (*p == '\0') {
		return (NULL);
	}

	/*
	 *	Save the location of the token and then skip past it
	 */

	retp = p;
	while (*p) {
		if (isspace(*p))
			if (skip == TRUE) {
				shift1left(p);
				continue;
			} else
				break;
		/*
		 *	Only process the escape of the space separator;
		 *	since the token may contain other separators,
		 *	let the other routines handle the escape of
		 *	specific characters in the token.
		 */

		if (*p == '\\' && *(p + 1) != '\n' && isspace(*(p + 1))) {
			shift1left(p);
		}
		p++;
	}
	if (*p == '\0') {
		savep = 0;	/* indicate this is last token */
	} else {
		*p = '\0';
		savep = ++p;
	}
	return (retp);
}

/*
 *  matchname() parses a line of the /etc/nfssec.conf file
 *  and match the sc_name with the given name.
 *  If there is a match, it fills the information into the given
 *  pointer of the seconfig_t structure.
 *
 *  Returns TRUE if a match is found.
 */
static bool_t
matchname(char *line, char *name, seconfig_t *secp)
{
	char	*tok1,	*tok2;	/* holds a token from the line */
	char	*secname, *gss_mech, *gss_qop; /* pointer to a secmode name */

	if ((secname = gettoken(line, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	if (strcmp(secname, name) != 0) {
		return (FALSE);
	}

	tok1 = tok2 = NULL;
	if (((tok1 = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_mech = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_qop = gettoken(NULL, FALSE)) == NULL) ||
	    ((tok2 = gettoken(NULL, FALSE)) == NULL) ||
	    ((secp->sc_service = getvalue(tok2, sc_service))
	    == SC_FAILURE)) {
		return (FALSE);
	}
	secp->sc_nfsnum = atoi(tok1);
	(void) strcpy(secp->sc_name, secname);
	(void) strcpy(secp->sc_gss_mech, gss_mech);
	secp->sc_gss_mech_type = NULL;
	if (secp->sc_gss_mech[0] != '-') {
		if (!rpc_gss_mech_to_oid(gss_mech, &secp->sc_gss_mech_type) ||
		    !rpc_gss_qop_to_num(gss_qop, gss_mech, &secp->sc_qop)) {
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 *  matchnum() parses a line of the /etc/nfssec.conf file
 *  and match the sc_nfsnum with the given number.
 *  If it is a match, it fills the information in the given pointer
 *  of the seconfig_t structure.
 *
 *  Returns TRUE if a match is found.
 */
static bool_t
matchnum(char *line, int num, seconfig_t *secp)
{
	char	*tok1,	*tok2;	/* holds a token from the line */
	char	*secname, *gss_mech, *gss_qop;	/* pointer to a secmode name */

	if ((secname = gettoken(line, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	tok1 = tok2 = NULL;
	if ((tok1 = gettoken(NULL, FALSE)) == NULL) {
		/* bad line */
		return (FALSE);
	}

	if ((secp->sc_nfsnum = atoi(tok1)) != num) {
		return (FALSE);
	}

	if (((gss_mech = gettoken(NULL, FALSE)) == NULL) ||
	    ((gss_qop = gettoken(NULL, FALSE)) == NULL) ||
	    ((tok2 = gettoken(NULL, FALSE)) == NULL) ||
	    ((secp->sc_service = getvalue(tok2, sc_service))
	    == SC_FAILURE)) {
		return (FALSE);
	}

	(void) strcpy(secp->sc_name, secname);
	(void) strcpy(secp->sc_gss_mech, gss_mech);
	if (secp->sc_gss_mech[0] != '-') {
		if (!rpc_gss_mech_to_oid(gss_mech, &secp->sc_gss_mech_type) ||
		    !rpc_gss_qop_to_num(gss_qop, gss_mech, &secp->sc_qop)) {
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 *  Fill in the RPC Protocol security flavor number
 *  into the sc_rpcnum of seconfig_t structure.
 *
 *  Mainly to map NFS secmod number to RPCSEC_GSS if
 *  a mechanism name is specified.
 */
static void
get_rpcnum(seconfig_t *secp)
{
	if (secp->sc_gss_mech[0] != '-') {
		secp->sc_rpcnum = RPCSEC_GSS;
	} else {
		secp->sc_rpcnum = secp->sc_nfsnum;
	}
}

/*
 *  Parse a given hostname (nodename[.domain@realm]) to
 *  instant name (nodename[.domain]) and realm.
 *
 *  Assuming user has allocated the space for inst and realm.
 */
static int
parsehostname(char *hostname, char *inst, char *realm)
{
	char *h, *r;

	if (!hostname)
		return (0);

	h = (char *)strdup(hostname);
	if (!h) {
		syslog(LOG_ERR, "parsehostname: no memory\n");
		return (0);
	}

	r = (char *)strchr(h, '@');
	if (!r) {
		(void) strcpy(inst, h);
		(void) strcpy(realm, "");
	} else {
		*r++ = '\0';
		(void) strcpy(inst, h);
		(void) strcpy(realm, r);
	}
	free(h);
	return (1);
}

/*
 *  Get the name corresponding to a qop num.
 */
char *
nfs_get_qop_name(seconfig_t *entryp)
{
	char	*tok;	/* holds a token from the line */
	char	*secname, *gss_qop = NULL; /* pointer to a secmode name */
	char	line[BUFSIZ];	/* holds each line of NFSSEC_CONF */
	FILE	*fp;		/* file stream for NFSSEC_CONF */

	(void) mutex_lock(&matching_lock);
	if ((fp = fopen(NFSSEC_CONF, "r")) == NULL) {
		(void) mutex_unlock(&matching_lock);
		return (NULL);
	}

	while (fgets(line, BUFSIZ, fp)) {
		if (!(blank(line) || comment(line))) {
			if ((secname = gettoken(line, FALSE)) == NULL) {
				/* bad line */
				continue;
			}
			if (strcmp(secname, entryp->sc_name) == 0) {
				tok = NULL;
				if ((tok = gettoken(NULL, FALSE)) == NULL) {
					/* bad line */
					goto err;
				}

				if (atoi(tok) != entryp->sc_nfsnum)
					goto err;

				if ((gettoken(NULL, FALSE) == NULL) ||
				    ((gss_qop = gettoken(NULL, FALSE))
				    == NULL)) {
					goto err;
				}
				break;
			}
		}
	}
err:
	(void) fclose(fp);
	(void) mutex_unlock(&matching_lock);
	return (gss_qop);
}

/*
 * This routine creates an auth handle assocaited with the
 * negotiated security flavor contained in nfs_sec.  The auth
 * handle will be used in the next LOOKUP request to fetch
 * the filehandle.
 */
AUTH *
nfs_create_ah(CLIENT *cl, char *hostname, seconfig_t *nfs_sec)
{
	char netname[MAXNETNAMELEN+1];
	char svc_name[MAXNETNAMELEN+1];
	char *gss_qop;
	static int window = 60;

	if (nfs_sec == NULL)
		goto err;

	switch (nfs_sec->sc_rpcnum) {
		case AUTH_UNIX:
		case AUTH_NONE:
			return (NULL);

		case AUTH_DES:
			if (!host2netname(netname, hostname, NULL))
				goto err;

			return (authdes_seccreate(netname, window, hostname,
			    NULL));

		case RPCSEC_GSS:
			if (cl == NULL)
				goto err;

			if (nfs_sec->sc_gss_mech_type == NULL) {
				syslog(LOG_ERR,
				"nfs_create_ah: need mechanism information\n");
				goto err;
			}

			/*
			 * RPCSEC_GSS service names are of the form svc@host.dom
			 */
			(void) sprintf(svc_name, "nfs@%s", hostname);

			gss_qop = nfs_get_qop_name(nfs_sec);
			if (gss_qop == NULL)
				goto err;

			return (rpc_gss_seccreate(cl, svc_name,
			    nfs_sec->sc_gss_mech, nfs_sec->sc_service, gss_qop,
			    NULL, NULL));

		default:
			syslog(LOG_ERR, "nfs_create_ah: unknown flavor\n");
			return (NULL);
	}
err:
	syslog(LOG_ERR, "nfs_create_ah: failed to make auth handle\n");
	return (NULL);
}

#ifdef WNFS_SEC_NEGO
/*
 * This routine negotiates sec flavors with server and returns:
 *	SNEGO_SUCCESS:		successful; sec flavors are
 *				returned in snego,
 *	SNEGO_DEF_VALID:	default sec flavor valid; no need
 *				to negotiate flavors,
 *	SNEGO_ARRAY_TOO_SMALL:	array too small,
 *	SNEGO_FAILURE:		failure
 */
/*
 * The following depicts how sec flavors are placed in an
 * overloaded V2 fhandle:
 *
 * Note that the first four octets contain the length octet,
 * the status octet, and two padded octets to make them XDR
 * four-octet aligned.
 *
 *   1   2   3   4                                          32
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+   +---+
 * | l | s |   |   |     sec_1     |...|     sec_n     |...|   |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+   +---+
 *
 * where
 *
 *   the status octet s indicates whether there are more security
 *   flavors(1 means yes, 0 means no) that require the client to
 *   perform another 0x81 LOOKUP to get them,
 *
 *   the length octet l is the length describing the number of
 *   valid octets that follow.  (l = 4 * n, where n is the number
 *
 * The following depicts how sec flavors are placed in an
 * overloaded V3 fhandle:
 *
 *  1        4
 * +--+--+--+--+
 * |    len    |
 * +--+--+--+--+
 *                                               up to 64
 * +--+--+--+--+--+--+--+--+--+--+--+--+     +--+--+--+--+
 * |s |  |  |  |   sec_1   |   sec_2   | ... |   sec_n   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+     +--+--+--+--+
 *
 * len = 4 * (n+1), where n is the number of security flavors
 * sent in the current overloaded filehandle.
 *
 * the status octet s indicates whether there are more security
 * mechanisms(1 means yes, 0 means no) that require the client
 * to perform another 0x81 LOOKUP to get them.
 *
 * Three octets are padded after the status octet.
 */
enum snego_stat
nfs_sec_nego(rpcprog_t vers, CLIENT *clnt, char *fspath, struct snego_t *snego)
{
	enum clnt_stat rpc_stat;
	static int MAX_V2_CNT = (WNL_FHSIZE/sizeof (int)) - 1;
	static int MAX_V3_CNT = (WNL3_FHSIZE/sizeof (int)) - 1;
	static struct timeval TIMEOUT = { 25, 0 };
	int status;

	if (clnt == NULL || fspath == NULL || snego == NULL)
		return (SNEGO_FAILURE);

	if (vers == WNL_V2) {
		wnl_diropargs arg;
		wnl_diropres clnt_res;

		memset((char *)&arg.dir, 0, sizeof (wnl_fh));
		arg.name = fspath;
		memset((char *)&clnt_res, 0, sizeof (clnt_res));
		rpc_stat = clnt_call(clnt, WNLPROC_LOOKUP,
		    (xdrproc_t)xdr_wnl_diropargs, (caddr_t)&arg,
		    (xdrproc_t)xdr_wnl_diropres, (caddr_t)&clnt_res,
		    TIMEOUT);
		if (rpc_stat == RPC_SUCCESS && clnt_res.status == WNL_OK)
			return (SNEGO_DEF_VALID);
		if (rpc_stat != RPC_AUTHERROR)
			return (SNEGO_FAILURE);

		{
			struct rpc_err e;
			wnl_diropres res;
			char *p;
			int tot = 0;

			CLNT_GETERR(clnt, &e);
			if (e.re_why != AUTH_TOOWEAK)
				return (SNEGO_FAILURE);

			if ((p = malloc(strlen(fspath)+3)) == NULL) {
				syslog(LOG_ERR, "no memory\n");
				return (SNEGO_FAILURE);
			}
			/*
			 * Do an x81 LOOKUP
			 */
			p[0] = (char)WNL_SEC_NEGO;
			strcpy(&p[2], fspath);
			do {
				p[1] = (char)(1+snego->cnt); /* sec index */
				arg.name = p;
				memset((char *)&res, 0, sizeof (wnl_diropres));
				if (wnlproc_lookup_2(&arg, &res, clnt) !=
				    RPC_SUCCESS || res.status != WNL_OK) {
					free(p);
					return (SNEGO_FAILURE);
				}

				/*
				 * retrieve flavors from filehandle:
				 *	1st byte: length
				 *	2nd byte: status
				 *	3rd & 4th: pad
				 *	5th and after: sec flavors.
				 */
				{
					char *c = (char *)&res.wnl_diropres_u.
					    wnl_diropres.file;
					int ii;
					int cnt = ((int)*c)/sizeof (uint_t);
					/* LINTED pointer alignment */
					int *ip = (int *)(c+sizeof (int));

					tot += cnt;
					if (tot >= MAX_FLAVORS) {
						free(p);
						return (SNEGO_ARRAY_TOO_SMALL);
					}
					status = (int)*(c+1);
					if (cnt > MAX_V2_CNT || cnt < 0) {
						free(p);
						return (SNEGO_FAILURE);
					}
					for (ii = 0; ii < cnt; ii++)
						snego->array[snego->cnt+ii] =
						    ntohl(*(ip+ii));
					snego->cnt += cnt;
				}
			} while (status);
			free(p);
			return (SNEGO_SUCCESS);
		}
	} else if (vers == WNL_V3) {
		WNL_LOOKUP3args arg;
		WNL_LOOKUP3res clnt_res;

		memset((char *)&arg.what.dir, 0, sizeof (wnl_fh3));
		arg.what.name = fspath;
		arg.what.dir.data.data_len = 0;
		arg.what.dir.data.data_val = 0;
		memset((char *)&clnt_res, 0, sizeof (clnt_res));
		rpc_stat = clnt_call(clnt, WNLPROC3_LOOKUP,
		    (xdrproc_t)xdr_WNL_LOOKUP3args, (caddr_t)&arg,
		    (xdrproc_t)xdr_WNL_LOOKUP3res, (caddr_t)&clnt_res,
		    TIMEOUT);
		if (rpc_stat == RPC_SUCCESS && clnt_res.status == WNL3_OK)
			return (SNEGO_DEF_VALID);
		if (rpc_stat != RPC_AUTHERROR)
			return (SNEGO_FAILURE);

		{
			struct rpc_err e;
			WNL_LOOKUP3res res;
			char *p;
			int tot = 0;

			CLNT_GETERR(clnt, &e);
			if (e.re_why != AUTH_TOOWEAK)
				return (SNEGO_FAILURE);

			if ((p = malloc(strlen(fspath)+3)) == NULL) {
				syslog(LOG_ERR, "no memory\n");
				return (SNEGO_FAILURE);
			}
			/*
			 * Do an x81 LOOKUP
			 */
			p[0] = (char)WNL_SEC_NEGO;
			strcpy(&p[2], fspath);
			do {
				p[1] = (char)(1+snego->cnt); /* sec index */
				arg.what.name = p;
				memset((char *)&res, 0,
				    sizeof (WNL_LOOKUP3res));
				if (wnlproc3_lookup_3(&arg, &res, clnt) !=
				    RPC_SUCCESS || res.status != WNL3_OK) {
					free(p);
					return (SNEGO_FAILURE);
				}

				/*
				 * retrieve flavors from filehandle:
				 *
				 * 1st byte: status
				 * 2nd thru 4th: pad
				 * 5th and after: sec flavors.
				 */
				{
					char *c = res.WNL_LOOKUP3res_u.
					    res_ok.object.data.data_val;
					int ii;
					int len = res.WNL_LOOKUP3res_u.res_ok.
					    object.data.data_len;
					int cnt;
					/* LINTED pointer alignment */
					int *ip = (int *)(c+sizeof (int));

					cnt = len/sizeof (uint_t) - 1;
					tot += cnt;
					if (tot >= MAX_FLAVORS) {
						free(p);
						return (SNEGO_ARRAY_TOO_SMALL);
					}
					status = (int)(*c);
					if (cnt > MAX_V3_CNT || cnt < 0) {
						free(p);
						return (SNEGO_FAILURE);
					}
					for (ii = 0; ii < cnt; ii++)
						snego->array[snego->cnt+ii] =
						    ntohl(*(ip+ii));
					snego->cnt += cnt;
				}
			} while (status);
			free(p);
			return (SNEGO_SUCCESS);
		}
	}
	return (SNEGO_FAILURE);
}
#endif

/*
 *  Get seconfig from /etc/nfssec.conf by name or by number or
 *  by descriptior.
 */
/* ARGSUSED */
static int
get_seconfig(int whichway, char *name, int num,
		rpc_gss_service_t service, seconfig_t *entryp)
{
	char	line[BUFSIZ];	/* holds each line of NFSSEC_CONF */
	FILE	*fp;		/* file stream for NFSSEC_CONF */

	if ((whichway == GETBYNAME) && (name == NULL))
		return (SC_NOTFOUND);

	(void) mutex_lock(&matching_lock);
	if ((fp = fopen(NFSSEC_CONF, "r")) == NULL) {
		(void) mutex_unlock(&matching_lock);
		return (SC_OPENFAIL);
	}

	while (fgets(line, BUFSIZ, fp)) {
		if (!(blank(line) || comment(line))) {
			switch (whichway) {
				case GETBYNAME:
					if (matchname(line, name, entryp)) {
						goto found;
					}
					break;

				case GETBYNUM:
					if (matchnum(line, num, entryp)) {
						goto found;
					}
					break;

				default:
					break;
			}
		}
	}
	(void) fclose(fp);
	(void) mutex_unlock(&matching_lock);
	return (SC_NOTFOUND);

found:
	(void) fclose(fp);
	(void) mutex_unlock(&matching_lock);
	(void) get_rpcnum(entryp);
	return (SC_NOERROR);
}


/*
 *  NFS project private API.
 *  Get a seconfig entry from /etc/nfssec.conf by nfs specific sec name,
 *  e.g. des, krb5p, etc.
 */
int
nfs_getseconfig_byname(char *secmode_name, seconfig_t *entryp)
{
	if (!entryp)
		return (SC_NOMEM);

	return (get_seconfig(GETBYNAME, secmode_name, 0, rpc_gss_svc_none,
	    entryp));
}

/*
 *  NFS project private API.
 *
 *  Get a seconfig entry from /etc/nfssec.conf by nfs specific sec number,
 *  e.g. AUTH_DES, AUTH_KRB5_P, etc.
 */
int
nfs_getseconfig_bynumber(int nfs_secnum, seconfig_t *entryp)
{
	if (!entryp)
		return (SC_NOMEM);

	return (get_seconfig(GETBYNUM, NULL, nfs_secnum, rpc_gss_svc_none,
	    entryp));
}

/*
 *  NFS project private API.
 *
 *  Get a seconfig_t entry used as the default for NFS operations.
 *  The default flavor entry is defined in /etc/nfssec.conf.
 *
 *  Assume user has allocate spaces for secp.
 */
int
nfs_getseconfig_default(seconfig_t *secp)
{
	if (secp == NULL)
		return (SC_NOMEM);

	return (nfs_getseconfig_byname("default", secp));
}


/*
 *  NFS project private API.
 *
 *  Free an sec_data structure.
 *  Free the parts that nfs_clnt_secdata allocates.
 */
void
nfs_free_secdata(sec_data_t *secdata)
{
	dh_k4_clntdata_t *dkdata;
	gss_clntdata_t *gdata;

	if (!secdata)
		return;

	switch (secdata->rpcflavor) {
		case AUTH_UNIX:
		case AUTH_NONE:
			break;

		case AUTH_DES:
			/* LINTED pointer alignment */
			dkdata = (dh_k4_clntdata_t *)secdata->data;
			if (dkdata) {
				if (dkdata->netname)
					free(dkdata->netname);
				if (dkdata->syncaddr.buf)
					free(dkdata->syncaddr.buf);
				free(dkdata);
			}
			break;

		case RPCSEC_GSS:
			/* LINTED pointer alignment */
			gdata = (gss_clntdata_t *)secdata->data;
			if (gdata) {
				if (gdata->mechanism.elements)
					free(gdata->mechanism.elements);
				free(gdata);
			}
			break;

		default:
			break;
	}

	free(secdata);
}

/*
 *  Make an client side sec_data structure and fill in appropriate value
 *  based on its rpc security flavor.
 *
 *  It is caller's responsibility to allocate space for seconfig_t,
 *  and this routine will allocate space for the sec_data structure
 *  and related data field.
 *
 *  Return the sec_data_t on success.
 *  If fail, return NULL pointer.
 */
sec_data_t *
nfs_clnt_secdata(seconfig_t *secp, char *hostname, struct knetconfig *knconf,
		struct netbuf *syncaddr, int flags)
{
	char netname[MAXNETNAMELEN+1];
	sec_data_t *secdata;
	dh_k4_clntdata_t *dkdata;
	gss_clntdata_t *gdata;

	secdata = malloc(sizeof (sec_data_t));
	if (!secdata) {
		syslog(LOG_ERR, "nfs_clnt_secdata: no memory\n");
		return (NULL);
	}
	(void) memset(secdata, 0, sizeof (sec_data_t));

	secdata->secmod = secp->sc_nfsnum;
	secdata->rpcflavor = secp->sc_rpcnum;
	secdata->uid = secp->sc_uid;
	secdata->flags = flags;

	/*
	 *  Now, fill in the information for client side secdata :
	 *
	 *  For AUTH_UNIX, AUTH_DES
	 *  hostname can be in the form of
	 *    nodename or
	 *    nodename.domain
	 *
	 *  For RPCSEC_GSS security flavor
	 *  hostname can be in the form of
	 *    nodename or
	 *    nodename.domain  or
	 *    nodename@realm (realm can be the same as the domain) or
	 *    nodename.domain@realm
	 */
	switch (secp->sc_rpcnum) {
		case AUTH_UNIX:
		case AUTH_NONE:
			secdata->data = NULL;
			break;

		case AUTH_DES:
			/*
			 *  If hostname is in the format of host.nisdomain
			 *  the netname will be constructed with
			 *  this nisdomain name rather than the default
			 *  domain of the machine.
			 */
			if (!host2netname(netname, hostname, NULL)) {
				syslog(LOG_ERR, "host2netname: %s: unknown\n",
				    hostname);
				goto err_out;
			}
			dkdata = malloc(sizeof (dh_k4_clntdata_t));
			if (!dkdata) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: no memory\n");
				goto err_out;
			}
			(void) memset((char *)dkdata, 0,
			    sizeof (dh_k4_clntdata_t));
			if ((dkdata->netname = strdup(netname)) == NULL) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: no memory\n");
				goto err_out;
			}
			dkdata->netnamelen = strlen(netname);
			dkdata->knconf = knconf;
			dkdata->syncaddr = *syncaddr;
			dkdata->syncaddr.buf = malloc(syncaddr->len);
			if (dkdata->syncaddr.buf == NULL) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: no memory\n");
				goto err_out;
			}
			(void) memcpy(dkdata->syncaddr.buf, syncaddr->buf,
			    syncaddr->len);
			secdata->data = (caddr_t)dkdata;
			break;

		case RPCSEC_GSS:
			if (secp->sc_gss_mech_type == NULL) {
				syslog(LOG_ERR,
			"nfs_clnt_secdata: need mechanism information\n");
				goto err_out;
			}

			gdata = malloc(sizeof (gss_clntdata_t));
			if (!gdata) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: no memory\n");
				goto err_out;
			}

			(void) strcpy(gdata->uname, "nfs");
			if (!parsehostname(hostname, gdata->inst,
			    gdata->realm)) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: bad host name\n");
				goto err_out;
			}

			gdata->mechanism.length =
			    secp->sc_gss_mech_type->length;
			if (!(gdata->mechanism.elements =
			    malloc(secp->sc_gss_mech_type->length))) {
				syslog(LOG_ERR,
				    "nfs_clnt_secdata: no memory\n");
				goto err_out;
			}
			(void) memcpy(gdata->mechanism.elements,
			    secp->sc_gss_mech_type->elements,
			    secp->sc_gss_mech_type->length);

			gdata->qop = secp->sc_qop;
			gdata->service = secp->sc_service;
			secdata->data = (caddr_t)gdata;
			break;

		default:
			syslog(LOG_ERR, "nfs_clnt_secdata: unknown flavor\n");
			goto err_out;
	}

	return (secdata);

err_out:
	free(secdata);
	return (NULL);
}

/*
 *  nfs_get_root_principal() maps a host name to its principal name
 *  based on the given security information.
 *
 *  input :  seconfig - security configuration information
 *		host - the host name which could be in the following forms:
 *		node
 *		node.namedomain
 *		node@secdomain (e.g. kerberos realm is a secdomain)
 *		node.namedomain@secdomain
 *  output : rootname_p - address of the principal name for the host
 *
 *  Currently, this routine is only used by share program.
 *
 */
bool_t
nfs_get_root_principal(seconfig_t *seconfig, char *host, caddr_t *rootname_p)
{
	char netname[MAXNETNAMELEN+1], node[MAX_NAME_LEN];
	char secdomain[MAX_NAME_LEN];
	rpc_gss_principal_t gssname;

	switch (seconfig->sc_rpcnum) {
		case AUTH_DES:
			if (!host2netname(netname, host, NULL)) {
				syslog(LOG_ERR,
			    "nfs_get_root_principal: unknown host: %s\n", host);
				return (FALSE);
			}
			*rootname_p = strdup(netname);
			if (!*rootname_p) {
				syslog(LOG_ERR,
				    "nfs_get_root_principal: no memory\n");
				return (FALSE);
			}
			break;

		case RPCSEC_GSS:
			if (!parsehostname(host, node, secdomain)) {
				syslog(LOG_ERR,
				    "nfs_get_root_principal: bad host name\n");
				return (FALSE);
			}
			if (!rpc_gss_get_principal_name(&gssname,
			    seconfig->sc_gss_mech, "root", node, secdomain)) {
				syslog(LOG_ERR,
	"nfs_get_root_principal: can not get principal name : %s\n", host);
				return (FALSE);
			}

			*rootname_p = (caddr_t)gssname;
			break;

		default:
			return (FALSE);
	}
	return (TRUE);
}


/*
 *  SYSLOG SC_* errors.
 */
int
nfs_syslog_scerr(int scerror, char msg[])
{
	switch (scerror) {
		case SC_NOMEM :
			sprintf(msg, "%s : no memory", NFSSEC_CONF);
			return (0);
		case SC_OPENFAIL :
			sprintf(msg, "can not open %s", NFSSEC_CONF);
			return (0);
		case SC_NOTFOUND :
			sprintf(msg, "has no entry in %s", NFSSEC_CONF);
			return (0);
		case SC_BADENTRIES :
			sprintf(msg, "bad entry in %s", NFSSEC_CONF);
			return (0);
		default:
			msg[0] = '\0';
			return (-1);
	}
}
