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


/*
 * This module contains the subroutines used by the server to manipulate
 * objects and names.
 */
#include "mt.h"
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <rpc/rpc.h>	/* Must be ahead of rpcb_clnt.h */
#include <rpc/svc.h>
#include <tiuser.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/rpcb_clnt.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include "nis_clnt.h"
#include <sys/systeminfo.h>
#include <nsswitch.h>

#define	MAXIPRINT	(11)	/* max length of printed integer */
/*
 * send and receive buffer size used for clnt_tli_create if not specified.
 * This is only used for "UDP" connection.
 * This limit can be changed from the application if this value is too
 * small for the application.  To use the maximum value for the transport,
 * set this value to 0.
 */
int __nisipbufsize = 8192;


/*
 * Static function prototypes.
 */
static struct local_names *__get_local_names(void);
static char *__map_addr(struct netconfig *, char *, rpcprog_t, rpcvers_t);

/*
 * nis_dir_cmp() -- the results can be read as:
 * 	"Name 'n1' is a $result than name 'n2'"
 */
name_pos
nis_dir_cmp(
	nis_name	n1,
	nis_name	n2)	/* See if these are the same domain */
{
	size_t		l1, l2;
	name_pos	result;

	if ((n1 == NULL) || (n2 == NULL))
		return (BAD_NAME);

	l1 = strlen(n1);
	l2 = strlen(n2);

	/* In this routine we're lenient and don't require a trailing '.' */
	/*   so we need to ignore it if it does appear.			  */
	/* ==== That's what the previous version did so this one does	  */
	/*   too, but why?  Is this inconsistent with rest of system?	  */
	if (l1 != 0 && n1[l1 - 1] == '.') {
		--l1;
	}
	if (l2 != 0 && n2[l2 - 1] == '.') {
		--l2;
	}

	if (l1 > l2) {
		result = LOWER_NAME;
	} else if (l1 == l2) {
		result = SAME_NAME;
	} else /* (l1 < l2); swap l1/l2 and n1/n2 */ {
		nis_name	ntmp;
		size_t		ltmp;
		ntmp = n1; n1 = n2; n2 = ntmp;
		ltmp = l1; l1 = l2; l2 = ltmp;

		result = HIGHER_NAME;
	}

	/* Now l1 >= l2 in all cases */
	if (l2 == 0) {
		/* Special case for n2 == "." or "" */
		return (result);
	}
	if (l1 > l2) {
		n1 += l1 - l2;
		if (n1[-1] != '.') {
			return (NOT_SEQUENTIAL);
		}
	}
	if (strncasecmp(n1, n2, l2) == 0) {
		return (result);
	}
	return (NOT_SEQUENTIAL);
}

#define	LN_BUFSIZE	(size_t)1024

struct principal_list {
	uid_t uid;
	char principal[LN_BUFSIZE];
	struct principal_list *next;
};


struct local_names {
	char domain[LN_BUFSIZE];
	char host[LN_BUFSIZE];
	char *rpcdomain;
	struct principal_list *principal_map;
	char group[LN_BUFSIZE];
};

static mutex_t ln_lock = DEFAULTMUTEX; /* lock level 2 */
static struct local_names *ln = NULL;
static struct local_names *__get_local_names1();

static struct local_names *
__get_local_names(void)
{
	struct local_names *names;

	sig_mutex_lock(&ln_lock);
	names = __get_local_names1();
	sig_mutex_unlock(&ln_lock);
	return (names);
}


static struct local_names *
__get_local_names1(void)
{
	char		*t;

	if (ln != NULL) {
		/* Second and subsequent calls go this way */
		return (ln);
	}
	/* First call goes this way */
	ln = calloc(1, sizeof (*ln));
	if (ln == NULL) {
		syslog(LOG_ERR, "__get_local_names: Out of heap.");
		return (NULL);
	}
	ln->principal_map = NULL;

	if (sysinfo(SI_SRPC_DOMAIN, ln->domain, LN_BUFSIZE) < 0)
		return (ln);
	/* If no dot exists, add one. */
	if (ln->domain[strlen(ln->domain)-1] != '.')
		(void) strcat(ln->domain, ".");
	if (sysinfo(SI_HOSTNAME, ln->host, LN_BUFSIZE) < 0)
		return (ln);

	/*
	 * Check for fully qualified hostname.  If it's a fully qualified
	 * hostname, strip off the domain part.  We always use the local
	 * domainname for the host principal name.
	 */
	t = strchr(ln->host, '.');
	if (t)
		*t = 0;
	if (ln->domain[0] != '.')
		(void) strcat(ln->host, ".");
	ln->rpcdomain = strdup(ln->domain);
	(void) strcat(ln->host, ln->domain);

	t = getenv("NIS_GROUP");
	if (t == NULL) {
		ln->group[0] = '\0';
	} else {
		size_t maxlen = LN_BUFSIZE-1;	/* max chars to copy */
		char *temp;			/* temp marker */

		/*
		 * Copy <= maximum characters from NIS_GROUP; strncpy()
		 * doesn't terminate, so we do that manually. #1223323
		 * Also check to see if it's "".  If it's the null string,
		 * we return because we don't want to add ".domain".
		 */
		(void) strncpy(ln->group, t, maxlen);
		if (strcmp(ln->group, "") == 0) {
			return (ln);
		}
		ln->group[maxlen] = '\0';

		/* Is the group name somewhat fully-qualified? */
		temp = strrchr(ln->group, '.');

		/* If not, we need to add ".domain" to the group */
		if ((temp == NULL) || (temp[1] != '\0')) {

			/* truncate to make room for ".domain" */
			ln->group[maxlen - (strlen(ln->domain)+1)] = '\0';

			/* concat '.' if domain doesn't already have it */
			if (ln->domain[0] != '.') {
				(void) strcat(ln->group, ".");
			}
			(void) strcat(ln->group, ln->domain);
		}
	}
	return (ln);
}

/*
 * nis_local_group()
 *
 * Return's the group name of the current user.
 */
nis_name
nis_local_group(void)
{
	struct local_names	*ln = __get_local_names();

	/* LOCK NOTE: Warning, after initialization, "ln" is expected	 */
	/* to stay constant, So no need to lock here. If this assumption */
	/* is changed, this code must be protected.			 */
	if (!ln)
		return (NULL);
	return (ln->group);
}

/*
 * __nis_nextsep_of()
 *
 * This internal funtion will accept a pointer to a NIS name string and
 * return a pointer to the next separator occurring in it (it will point
 * just past the first label).  It allows for labels to be "quoted" to
 * prevent the the dot character within them to be interpreted as a
 * separator, also the quote character itself can be quoted by using
 * it twice.  If the the name contains only one label and no trailing
 * dot character, a pointer to the terminating NULL is returned.
 */
nis_name
__nis_nextsep_of(char *s)
{
	char	*d;
	int	in_quotes = FALSE, quote_quote = FALSE;

	if (!s)
		return (NULL);

	for (d = s; (in_quotes && (*d != '\0')) ||
	    (!in_quotes && (*d != '.') && (*d != '\0')); d++) {
		if (quote_quote && in_quotes && (*d != '"')) {
			quote_quote = FALSE;
			in_quotes = FALSE;
			if (*d == '.')
				break;
		} else if (quote_quote && in_quotes && (*d == '"')) {
			quote_quote = FALSE;
		} else if (quote_quote && (*d != '"')) {
			quote_quote = FALSE;
			in_quotes = TRUE;
		} else if (quote_quote && (*d == '"')) {
			quote_quote = FALSE;
		} else if (in_quotes && (*d == '"')) {
			quote_quote = TRUE;
		} else if (!in_quotes && (*d == '"')) {
			quote_quote = TRUE;
		}
	}

	if (quote_quote || in_quotes) {
		syslog(LOG_DEBUG, "__nis_nextsep_of: "
		    "Mismatched quotes in %s", s);
	}

	return (d);
}

/*
 * nis_domain_of()
 *
 * This internal funtion will accept a pointer to a NIS name string and
 * return a pointer to the "domain" part of it.
 *
 * ==== We don't need nis_domain_of_r(), but should we provide one for
 *	uniformity?
 */
nis_name
nis_domain_of(char *s)
{
	char	*d;

	d = __nis_nextsep_of(s);
	if (d == NULL)
		return (NULL);
	if (*d == '.')
		d++;
	if (*d == '\0')	/* Don't return a zero length string */
		return ("."); /* return root domain instead */
	return (d);
}


/*
 * nis_leaf_of()
 *
 * Returns the first label of a name. (other half of __domain_of)
 */
nis_name
nis_leaf_of_r(
	const nis_name	s,
	char		*buf,
	size_t		bufsize)
{
	size_t		nchars;
	const char	*d = __nis_nextsep_of((char *)s);

	if (d == 0) {
		return (0);
	}
	nchars = d - s;
	if (bufsize < nchars + 1) {
		return (0);
	}
	(void) strncpy(buf, s, nchars);
	buf[nchars] = '\0';
	return (buf);
}

static pthread_key_t buf_key = PTHREAD_ONCE_KEY_NP;
static char buf_main[LN_BUFSIZE];

nis_name
nis_leaf_of(char *s)
{
	char *buf = thr_main()? buf_main :
	    thr_get_storage(&buf_key, LN_BUFSIZE, free);

	if (buf == NULL)
		return (NULL);
	return (nis_leaf_of_r(s, buf,  LN_BUFSIZE));
}

/*
 * nis_name_of()
 * This internal function will remove from the NIS name, the domain
 * name of the current server, this will leave the unique part in
 * the name this becomes the "internal" version of the name. If this
 * function returns NULL then the name we were given to resolve is
 * bad somehow.
 * NB: Uses static storage and this is a no-no with threads. XXX
 */

nis_name
nis_name_of_r(
	char	*s,	/* string with the name in it. */
	char		*buf,
	size_t		bufsize)
{
	char			*d;
	struct local_names 	*ln = __get_local_names();
	size_t			dl, sl;
	name_pos		p;

#ifdef lint
	bufsize = bufsize;
#endif /* lint */
	if ((!s) || (!ln))
		return (NULL);		/* No string, this can't continue */

	d  = &(ln->domain[0]);
	dl = strlen(ln->domain); 	/* _always dot terminated_   */

	sl = strlen(s);
	if (sl >= bufsize || (s[sl-1] != '.' && sl >= bufsize-1))
		return (NULL);
	(void) strcpy(buf, s);		/* Make a private copy of 's'   */
	if (buf[sl-1] != '.') {	/* Add a dot if necessary.  */
		(void) strcat(buf, ".");
		sl++;
	}

	if (dl == 1) {			/* We're the '.' directory   */
		buf[sl-1] = '\0';	/* Lose the 'dot'	  */
		return (buf);
	}

	p = nis_dir_cmp(buf, d);

	/* 's' is above 'd' in the tree */
	if ((p == HIGHER_NAME) || (p == NOT_SEQUENTIAL) || (p == SAME_NAME))
		return (NULL);

	/* Insert a NUL where the domain name starts in the string */
	buf[(sl - dl) - 1] = '\0';

	/* Don't return a zero length name */
	if (buf[0] == '\0')
		return (NULL);

	return (buf);
}

nis_name
nis_name_of(
	char	*s)	/* string with the name in it. */
{
	char *buf = thr_main()? buf_main :
	    thr_get_storage(&buf_key, LN_BUFSIZE, free);

	if (!buf)
		return (NULL);
	return (nis_name_of_r(s, buf,  LN_BUFSIZE));
}



/*
 * nis_local_directory()
 *
 * Return a pointer to a string with the local directory name in it.
 */
nis_name
nis_local_directory(void)
{
	struct local_names	*ln = __get_local_names();

	/* LOCK NOTE: Warning, after initialization, "ln" is expected	 */
	/* to stay constant, So no need to lock here. If this assumption */
	/* is changed, this code must be protected.			 */
	if (ln == NULL)
		return (NULL);
	return (ln->domain);
}

/*
 * __nis_rpc_domain()
 *
 * Return a pointer to a string with the rpc domain name in it.
 */
nis_name
__nis_rpc_domain()
{
	struct local_names	*ln = __get_local_names();

	/* LOCK NOTE: Warning, after initialization, "ln" is expected	 */
	/* to stay constant, So no need to lock here. If this assumption */
	/* is changed, this code must be protected.			 */
	if (ln == NULL)
		return (NULL);
	return (ln->rpcdomain);
}


/*
 * nis_local_host()
 * Generate the principal name for this host, "hostname"+"domainname"
 * unless the hostname already has "dots" in its name.
 */
nis_name
nis_local_host(void)
{
	struct local_names	*ln = __get_local_names();

	/* LOCK NOTE: Warning, after initialization, "ln" is expected	 */
	/* to stay constant, So no need to lock here. If this assumption */
	/* is changed, this code must be protected.			 */
	if (ln == NULL)
		return (NULL);

	return (ln->host);
}

/*
 * nis_destroy_object()
 * This function takes a pointer to a NIS object and deallocates it. This
 * is the inverse of __clone_object below. It must be able to correctly
 * deallocate partially allocated objects because __clone_object will call
 * it if it runs out of memory and has to abort. Everything is freed,
 * INCLUDING the pointer that is passed.
 */
void
nis_destroy_object(nis_object *obj)	/* The object to clone */
{
	if (obj == 0)
		return;
	xdr_free(xdr_nis_object, (char *)obj);
	free(obj);
} /* nis_destroy_object */

static void
destroy_nis_sdata(void *p)
{
	struct nis_sdata	*ns = p;

	if (ns->buf != 0)
		free(ns->buf);
	free(ns);
}

/* XXX Why are these static ? */
/* static XDR in_xdrs, out_xdrs; */


/*
 * __clone_object_r()
 * This function takes a pointer to a NIS object and clones it. This
 * duplicate object is now available for use in the local context.
 */
nis_object *
nis_clone_object_r(
	nis_object	*obj,	/* The object to clone */
	nis_object	*dest,	/* Use this pointer if non-null */
	struct nis_sdata *clone_buf_ptr)
{
	nis_object	*result; /* The clone itself */
	int		status; /* a counter variable */
	XDR		in_xdrs, out_xdrs;

	if (!nis_get_static_storage(clone_buf_ptr, 1,
	    xdr_sizeof(xdr_nis_object, obj)))
		return (NULL);

	(void) memset(&in_xdrs, 0, sizeof (in_xdrs));
	(void) memset(&out_xdrs, 0, sizeof (out_xdrs));
	xdrmem_create(&in_xdrs, clone_buf_ptr->buf, clone_buf_ptr->size,
	    XDR_ENCODE);
	xdrmem_create(&out_xdrs, clone_buf_ptr->buf, clone_buf_ptr->size,
	    XDR_DECODE);

	/* Allocate a basic NIS object structure */
	if (dest) {
		(void) memset(dest, 0, sizeof (nis_object));
		result = dest;
	} else
		result = calloc(1, sizeof (nis_object));

	if (result == NULL)
		return (NULL);

	/* Encode our object into the clone buffer */
	(void) xdr_setpos(&in_xdrs, 0);
	status = xdr_nis_object(&in_xdrs, obj);
	if (status == FALSE)
		return (NULL);

	/* Now decode the buffer into our result pointer ... */
	(void) xdr_setpos(&out_xdrs, 0);
	status = xdr_nis_object(&out_xdrs, result);
	if (status == FALSE)
		return (NULL);

	/* presto changeo, a new object */
	return (result);
} /* __clone_object_r */


nis_object *
nis_clone_object(
	nis_object	*obj,	/* The object to clone */
	nis_object	*dest)	/* Use this pointer if non-null */
{
	static pthread_key_t clone_buf_key = PTHREAD_ONCE_KEY_NP;
	static struct nis_sdata clone_buf_main;
	struct nis_sdata *clone_buf_ptr;

	clone_buf_ptr = thr_main()? &clone_buf_main :
	    thr_get_storage(&clone_buf_key, sizeof (struct nis_sdata),
	    destroy_nis_sdata);
	return (nis_clone_object_r(obj, dest, clone_buf_ptr));
} /* __clone_object */

/* Various subroutines used by the server code */
nis_object *
nis_read_obj(char *f)	/* name of the object to read */
{
	FILE	*rootfile;
	int	status;	/* Status of the XDR decoding */
	XDR	xdrs;	/* An xdr stream handle */
	nis_object	*res;

	res = calloc(1, sizeof (nis_object));
	if (!res)
		return (NULL);

	rootfile = fopen(f, "rF");
	if (rootfile == NULL) {
		/* This is ok if we are the root of roots. */
		free(res);
		return (NULL);
	}
	/* Now read in the object */
	xdrstdio_create(&xdrs, rootfile, XDR_DECODE);
	status = xdr_nis_object(&xdrs, res);
	xdr_destroy(&xdrs);
	(void) fclose(rootfile);
	if (!status) {
		syslog(LOG_ERR, "Object file %s is corrupt!", f);
		xdr_free(xdr_nis_object, (char *)res);
		free(res);
		return (NULL);
	}
	return (res);
}

int
nis_write_obj(
	char	*f,	/* name of the object to read */
	nis_object *o)	/* The object to write */
{
	FILE	*rootfile;
	int	status;	/* Status of the XDR decoding */
	XDR	xdrs;	/* An xdr stream handle */

	rootfile = fopen(f, "wF");
	if (rootfile == NULL) {
		return (0);
	}
	/* Now encode the object */
	xdrstdio_create(&xdrs, rootfile, XDR_ENCODE);
	status = xdr_nis_object(&xdrs, o);
	xdr_destroy(&xdrs);
	(void) fclose(rootfile);
	return (status);
}

/*
 * Transport INDEPENDENT RPC code. This code assumes you
 * are using the new RPC/tli code and will build
 * a ping handle on top of a datagram transport.
 */

/*
 * __map_addr()
 *
 * This is our internal function that replaces rpcb_getaddr(). We
 * build our own to prevent calling netdir_getbyname() which could
 * recurse to the nameservice.
 */
static char *
__map_addr(
	struct netconfig	*nc,		/* Our transport	*/
	char			*uaddr,		/* RPCBIND address */
	rpcprog_t		prog,		/* Name service Prog */
	rpcvers_t		ver)
{
	CLIENT *client;
	RPCB 		parms;		/* Parameters for RPC binder	  */
	enum clnt_stat	clnt_st;	/* Result from the rpc call	  */
	char 		*ua = NULL;	/* Universal address of service	  */
	char		*res = NULL;	/* Our result to the parent	  */
	struct timeval	tv;		/* Timeout for our rpcb call	  */
	int		ilen, olen;	/* buffer length for clnt_tli_create */

	/*
	 * If using "udp", use __nisipbufsize if inbuf and outbuf are set to 0.
	 */
	if (strcmp(NC_UDP, nc->nc_proto) == 0) {
			/* for udp only */
		ilen = olen = __nisipbufsize;
	} else {
		ilen = olen = 0;
	}
	client = __nis_clnt_create(RPC_ANYFD, nc, uaddr, 0, 0,
	    RPCBPROG, RPCBVERS, ilen, olen);
	if (!client)
		return (NULL);

	(void) clnt_control(client, CLSET_FD_CLOSE, NULL);

	/*
	 * Now make the call to get the NIS service address.
	 * We set the retry timeout to 3 seconds so that we
	 * will retry a few times.  Retries should be rare
	 * because we are usually only called when we know
	 * a server is available.
	 */
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	(void) clnt_control(client, CLSET_RETRY_TIMEOUT, (char *)&tv);

	tv.tv_sec = 10;
	tv.tv_usec = 0;
	parms.r_prog = prog;
	parms.r_vers = ver;
	parms.r_netid = nc->nc_netid;	/* not needed */
	parms.r_addr = "";	/* not needed; just for xdring */
	parms.r_owner = "";	/* not needed; just for xdring */
	clnt_st = clnt_call(client, RPCBPROC_GETADDR, xdr_rpcb, (char *)&parms,
	    xdr_wrapstring, (char *)&ua, tv);

	if (clnt_st == RPC_SUCCESS) {
		clnt_destroy(client);
		if (*ua == '\0') {
			free(ua);
			return (NULL);
		}
		res = strdup(ua);
		xdr_free(xdr_wrapstring, (char *)&ua);
		return (res);
	} else if (((clnt_st == RPC_PROGVERSMISMATCH) ||
	    (clnt_st == RPC_PROGUNAVAIL)) &&
	    (strcmp(nc->nc_protofmly, NC_INET) == 0)) {
		/*
		 * version 3 not available. Try version 2
		 * The assumption here is that the netbuf
		 * is arranged in the sockaddr_in
		 * style for IP cases.
		 *
		 * Note:	If the remote host doesn't support version 3,
		 *		we assume it doesn't know IPv6 either.
		 */
		ushort_t 		port;
		struct sockaddr_in	*sa;
		struct netbuf 		remote;
		int			protocol;
		char			buf[32];

		(void) clnt_control(client, CLGET_SVC_ADDR, (char *)&remote);
		/* LINTED pointer cast */
		sa = (struct sockaddr_in *)(remote.buf);
		protocol = strcmp(nc->nc_proto, NC_TCP) ?
		    IPPROTO_UDP : IPPROTO_TCP;
		port = (ushort_t)pmap_getport(sa, prog, ver, protocol);

		if (port != 0) {
			port = htons(port);
			(void) sprintf(buf, "%d.%d.%d.%d.%d.%d",
			    (sa->sin_addr.s_addr >> 24) & 0xff,
			    (sa->sin_addr.s_addr >> 16) & 0xff,
			    (sa->sin_addr.s_addr >>  8) & 0xff,
			    (sa->sin_addr.s_addr) & 0xff,
			    (port >> 8) & 0xff,
			    port & 0xff);
			res = strdup(buf);
		} else
			res = NULL;
		clnt_destroy(client);
		return (res);
	}
	if (clnt_st == RPC_TIMEDOUT)
		syslog(LOG_ERR, "NIS+ server not responding");
	else
		syslog(LOG_ERR, "NIS+ server could not be contacted: %s",
		    clnt_sperrno(clnt_st));
	clnt_destroy(client);
	return (NULL);
}


#define	MAX_EP (20)

extern int __can_use_af(sa_family_t af);

CLIENT *
__nis_clnt_create(int fd, struct netconfig *nc, char *uaddr,
			struct netbuf *addr, int domapaddr,
			int prog, int ver, int inbuf, int outbuf) {

	char		*svc_addr;
	CLIENT		*clnt;
	int		freeaddr = 0;

	/* Sanity check */
	if (nc == 0 || (addr == 0 && uaddr == 0)) {
		return (0);
	}

	/*
	 * Check if we have a useable interface for this address family.
	 * This check properly belongs in RPC (or even further down),
	 * but until they provide it, we roll our own.
	 */
	if (__can_use_af((strcmp(nc->nc_protofmly, NC_INET6) == 0) ?
			AF_INET6 : AF_INET) == 0) {
		return (0);
	}

	if (domapaddr) {
		svc_addr = __map_addr(nc, uaddr, prog, ver);
		if (svc_addr == 0)
			return (0);
		addr = uaddr2taddr(nc, svc_addr);
		freeaddr = 1;
		free(svc_addr);
	} else if (addr == 0) {
		addr = uaddr2taddr(nc, uaddr);
		freeaddr = 1;
	}

	if (addr == 0) {
		return (0);
	}

	clnt = clnt_tli_create(fd, nc, addr, prog, ver, outbuf, inbuf);

	if (clnt) {
		if (clnt_control(clnt, CLGET_FD, (char *)&fd))
			/* make it "close on exec" */
			(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
		(void) clnt_control(clnt, CLSET_FD_CLOSE, NULL);
	}

	if (freeaddr)
		netdir_free(addr, ND_ADDR);

	return (clnt);
}

static mutex_t __nis_ss_used_lock = DEFAULTMUTEX; /* lock level 3 */
int	__nis_ss_used = 0;

/*
 * nis_get_static_storage()
 *
 * This function is used by various functions in their effort to minimize the
 * hassles of memory management in an RPC daemon. Because the service doesn't
 * implement any hard limits, this function allows people to get automatically
 * growing buffers that meet their storage requirements. It returns the
 * pointer in the nis_sdata structure.
 *
 */
void *
nis_get_static_storage(
	struct nis_sdata	*bs,    /* User buffer structure */
	uint_t			el,	/* Sizeof elements	 */
	uint_t			nel)    /* Number of elements    */
{
	uint_t	sz;

	sz = nel * el;
	if (!bs)
		return (NULL);

	if (!bs->buf) {
		bs->buf = malloc(sz);
		if (!bs->buf)
			return (NULL);
		bs->size = sz;
		sig_mutex_lock(&__nis_ss_used_lock);
		__nis_ss_used += sz;
		sig_mutex_unlock(&__nis_ss_used_lock);
	} else if (bs->size < sz) {
		int	size_delta;

		free(bs->buf);
		size_delta = - (bs->size);
		bs->buf = malloc(sz);

		/* check the result of malloc() first   */
		/* then update the statistic.		*/
		if (!bs->buf)
			return (NULL);
		bs->size = sz;
		size_delta += sz;
		sig_mutex_lock(&__nis_ss_used_lock);
		__nis_ss_used += size_delta;
		sig_mutex_unlock(&__nis_ss_used_lock);
	}

	(void) memset(bs->buf, 0, sz); /* SYSV version of bzero() */
	return (bs->buf);
}
