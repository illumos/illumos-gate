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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include "nis_local.h"
#include <nsswitch.h>

#define	MAXIPRINT	(11)	/* max length of printed integer */
static char    *PKTABLE	  = "cred.org_dir";
#define	PKTABLE_LEN	12
/*
 * send and receive buffer size used for clnt_tli_create if not specified.
 * This is only used for "UDP" connection.
 * This limit can be changed from the application if this value is too
 * small for the application.  To use the maximum value for the transport,
 * set this value to 0.
 */
int __nisipbufsize = 8192;

/* Error result returned by nis_make_error() when malloc fails */
const nis_result	__nomem_nis_result = {NIS_NOMEMORY, {0, 0}, {0, 0},
						0, 0, 0, 0};

extern int __readColdStartFile();

/*
 * Static function prototypes.
 */
static struct local_names *__get_local_names(void);
static char *__map_addr(struct netconfig *, char *, rpcprog_t, rpcvers_t);

CLIENT * nis_make_rpchandle_uaddr(nis_server *,
		int, rpcprog_t, rpcvers_t, uint_t, int, int, char *);

#define	COMMA	','	/* Avoid cstyle bug */

/* __nis_data_directory is READ ONLY, so no locking is needed    */
/* Note: We make it static, so external caller can not access it */
/*	i.e we make sure it stay read only			*/
static char	__nis_data_directory[1024] = {"/var/nis/"};

/* These macros make the code easier to read */

#ifdef NOTIME
#define	__start_clock(n)
#define	__stop_clock(n)		n
#else
static struct timeval clocks[MAXCLOCKS];

#define	LOOP_UADDR "127.0.0.1.0.0"

/*
 * __start_clock()
 *
 * This function will start the "stopwatch" on the function calls.
 * It uses an array of time vals to keep track of the time. The
 * sister call __stop_clock() will return the number of microseconds
 * since the clock was started. This allows for keeping statistics
 * on the NIS calls and tuning the service. If the clock in question
 * is not "stopped" this function returns an error.
 */
int
__start_clock(
	int	clk)	/* The clock we want to start */
{
	if ((clk >= MAXCLOCKS) || (clk < 0) || (clocks[clk].tv_sec))
		return (FALSE);

	(void) gettimeofday(&clocks[clk], NULL);
	return (TRUE);
}

uint32_t
__stop_clock(int clk)
{
	struct timeval 		now;
	uint32_t		secs, micros;

	if ((clk >= MAXCLOCKS) || (clk < 0) || (!clocks[clk].tv_sec))
		return (0);
	(void) gettimeofday(&now, NULL);
	secs = (int)(now.tv_sec - clocks[clk].tv_sec);
	if (now.tv_usec < clocks[clk].tv_usec) {
		micros = (int)((now.tv_usec + 1000000) - clocks[clk].tv_usec);
		secs--; /* adjusted 'cuz we added a second above */
	} else {
		micros = (int)(now.tv_usec - clocks[clk].tv_usec);
	}
	micros = micros + (secs * 1000000); /* All micros now */
	clocks[clk].tv_sec = 0; /* Stop the clock. */
	return (micros);
}
#endif /* no time */

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

static char *
get_nis_domain(void)
{
	directory_obj dobj;
	enum __nsw_parse_err pserr;
	struct __nsw_switchconfig *conf;
	static int checked_domain = 0;
	static char *nisdomain = 0;

	if (!checked_domain) {
		checked_domain = 1;
		/*
		 * Check that nisplus is first in nsswitch.conf for publickey.
		 */
		conf = __nsw_getconfig("publickey", &pserr);
		if (conf == NULL)
			return (NULL);
		if (conf->num_lookups <= 0)
			return (NULL);
		if (strcasecmp(conf->lookups[0].service_name, "nisplus") != 0)
			return (NULL);

		/*
		 * Read cold-start file to determine directory where
		 * the machine's credentials are stored.
		 */
		if (!__readColdStartFile(&dobj))
			return (NULL);
		nisdomain = strdup(dobj.do_name);
		xdr_free((xdrproc_t)xdr_directory_obj, (char *)&dobj);
	}

	return (nisdomain);
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
	if ((ln->rpcdomain = get_nis_domain()) != NULL) {
		(void) strcat(ln->host, ln->rpcdomain);
	} else {
		ln->rpcdomain = strdup(ln->domain);
		(void) strcat(ln->host, ln->domain);
	}

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
	int	in_quotes = FALSE,
		quote_quote = FALSE;

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
 * nis_getprincipal:
 *   Return the prinicipal name of the given uid in string supplied.
 *   Returns status obtained from nis+.
 *
 * Look up the LOCAL mapping in the local cred table. Note that if the
 * server calls this, then the version of nis_list that will
 * will be bound here is the 'safe' one in the server code.
 *
 * The USE_DGRAM + NO_AUTHINFO is required to prevent a
 * recursion through the getnetname() interface which is
 * called by authseccreate_pk and authdes_pk_create().
 *
 * NOTE that if you really want to get the nis+ principal name,
 * you should not use this call.  You should do something similar
 * but use an authenticated handle.
 */


int
__nis_principal(char *principal_name, uid_t uid, char *directory)
{
	nis_result	*res;
	char		buf[NIS_MAXNAMELEN];
	int		status;

	if ((strlen(directory)+MAXIPRINT+PKTABLE_LEN+32) >
		(size_t)NIS_MAXNAMELEN) {
		return (NIS_BADNAME);
	}

	(void) snprintf(buf, sizeof (buf),
		"[auth_name=%d,auth_type=LOCAL],%s.%s",
		(int)uid, PKTABLE, directory);

	if (buf[strlen(buf)-1] != '.')
		(void) strcat(buf, ".");

	res = nis_list(buf,
			USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS+FOLLOW_PATH,
			NULL, NULL);
	status = res->status;
	if (status == NIS_SUCCESS || status == NIS_S_SUCCESS) {
		if (res->objects.objects_len > 1) {
			/*
			 * More than one principal with same uid?
			 * something wrong with cred table. Should be unique
			 * Warn user and continue.
			 */
			syslog(LOG_ERR,
		"nis_principal: LOCAL entry for %d in directory %s not unique",
				uid, directory);
		}
		(void) strcpy(principal_name,
			ENTRY_VAL(res->objects.objects_val, 0));
	}
	nis_freeresult(res);

	return (status);
}

/*
 * nis_local_principal()
 * Generate the principal name for this user by looking it up its LOCAL
 * entry in the cred table of the local direectory.
 * Does not use an authenticated call (to prevent recursion because
 * this is called by user2netname).
 *
 * NOTE: the principal strings returned by nis_local_principal are
 * never changed and never freed, so there is no need to copy them.
 * Also note that nis_local_principal can return NULL.
 */
nis_name
nis_local_principal(void)
{
	struct local_names *ln = __get_local_names();
	uid_t		uid;
	int 		status;
	char		*dirname;
	static mutex_t local_principal_lock = DEFAULTMUTEX;
	struct principal_list *p;

	if (ln == NULL)
		return (NULL);

	sig_mutex_lock(&local_principal_lock);
	uid = geteuid();
	p = ln->principal_map;
	while (p) {
		if (p->uid == uid) {
			ASSERT(*(p->principal) != 0);
			sig_mutex_unlock(&local_principal_lock);
			return (p->principal);
		}
		p = p->next;
	}
	if (uid == 0) {
		sig_mutex_unlock(&local_principal_lock);
		return (ln->host);
	}
	p = calloc(1, sizeof (*p));
	if (p == NULL)
		return (NULL);
	if (!ln->principal_map) {
		ln->principal_map = p;
	}
	dirname = nis_local_directory();
	if ((dirname == NULL) || (dirname[0] == NULL)) {
		(void) strcpy(p->principal, "nobody");
		p->uid = uid;
		sig_mutex_unlock(&local_principal_lock);
		return (p->principal);
	}
	switch (status = __nis_principal(p->principal, uid, dirname)) {
	case NIS_SUCCESS:
	case NIS_S_SUCCESS:
		break;
	case NIS_NOTFOUND:
	case NIS_PARTIAL:
	case NIS_NOSUCHNAME:
	case NIS_NOSUCHTABLE:
		(void) strcpy(p->principal, "nobody");
		break;
	default:
		/*
		 * XXX We should return 'nobody', but
		 * should we be remembering 'nobody' as our
		 * principal name here?  Some errors might be
		 * transient.
		 */
		syslog(LOG_ERR,
			"nis_local_principal: %s",
			nis_sperrno(status));
		(void) strcpy(p->principal, "nobody");
	}
	p->uid = uid;
	sig_mutex_unlock(&local_principal_lock);
	return (p->principal);
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


/*
 * __break_name() converts a NIS name into it's components, returns an
 * array of char pointers pointing to the components and INVERTS there
 * order so that they are root first, then down. The list is terminated
 * with a null pointer. Returned memory can be freed by freeing the last
 * pointer in the list and the pointer returned.
 */
char	**
__break_name(
	nis_name	name,
	int		*levels)
{
	char	**pieces;	/* pointer to the pieces */
	char	*s;		/* Temporary */
	char	*data;		/* actual data and first piece pointer. */
	int	components;	/* Number of estimated components */
	size_t	namelen;	/* Length of the original name. */
	int 	i;

	/* First check to see that name is not NULL */
	if (!name)
		return (NULL);
	if ((namelen = strlen(name)) == 0)
		return (NULL);	/* Null string */

	namelen = strlen(name);

	data = strdup(name);
	if (!data)
		return (NULL);	/* No memory! */

	/* Kill the optional trailing dot */
	if (*(data+namelen-1) == '.') {
		*(data+namelen-1) = '\0';
		namelen--;
	}
	s = data;
	components = 1;
	while (*s != '\0') {
		if (*s == '.') {
			*s = '\0';
			components++;
			s++;
		} else if (*s == '"') {
			if (*(s+1) == '"') { /* escaped quote */
				s += 2;
			} else {
				/* skip quoted string */
				s++;
				while ((*s != '"') && (*s != '\0'))
					s++;
				if (*s == '"') {
					s++;
				}
			}
		} else {
			s++;
		}
	}
	pieces = calloc(components+1, sizeof (char *));
	if (!pieces) {
		free(data);
		return (NULL);
	}

	/* store in pieces in inverted order */
	for (i = (components-1), s = data; i > -1; i--) {
		*(pieces+i) = s;
		while (*s != '\0')
			s++;
		s++;
	}
	*(pieces+components) = NULL;
	*levels = components;

	return (pieces);
}

void
__free_break_name(char **components, int levels)
{
	free(components[levels-1]);
	free(components);
}

int
__name_distance(
	char	**targ,	/* The target name */
	char	**test) /* the test name */
{
	int	distance = 0;

	/* Don't count common components */
	while ((*targ && *test) && (strcasecmp(*targ, *test) == 0)) {
		targ++;
		test++;
	}

	/* count off the legs of each name */
	while (*test != NULL) {
		test++;
		distance++;
	}

	while (*targ != NULL) {
		targ++;
		distance++;
	}

	return (distance);
}

int
__dir_same(char **test, char **targ)
{
	/* skip common components */
	while ((*targ && *test) && (strcasecmp(*targ, *test) == 0)) {
		targ++;
		test++;
	}

	return (*test == NULL && *targ == NULL);
}

void
__broken_name_print(char **name, int levels)
{
	int i;

	for (i = levels-1; i >= 0; --i)
		(void) printf("%s.", name[i]);
}


/*
 * For returning errors in a NIS result structure
 */
nis_result *
nis_make_error(
	nis_error	err,
	uint32_t	aticks,	/* Profile information for client */
	uint32_t	cticks,
	uint32_t	dticks,
	uint32_t	zticks)
{
	nis_result	*nres;

	nres = malloc(sizeof (nis_result));
	if (!nres)
		return ((nis_result *)&__nomem_nis_result);
	(void) memset(nres, 0, sizeof (nis_result));
	nres->status = err;
	nres->aticks = aticks;
	nres->zticks = zticks;
	nres->dticks = dticks;
	nres->cticks = cticks;
	return (nres);
}

#define	ZVAL zattr_val.zattr_val_val
#define	ZLEN zattr_val.zattr_val_len

/*
 * __cvt2attr()
 *
 * This function converts a search criteria of the form :
 *	[ <key>=<value>, <key>=<value>, ... ]
 * Into an array of nis_attr structures.
 */

nis_attr *
__cvt2attr(
	int	*na, 		/* Number of attributes 	*/
	char	**attrs) 	/* Strings associated with them */

{
	int		i;
	nis_attr	*zattrs;
	char		*s;

	zattrs = calloc(*na, sizeof (nis_attr));
	if (!zattrs)
		return (NULL);

	for (i = 0; i < *na; i++) {
		zattrs[i].zattr_ndx = *(attrs+i);
		for (s = zattrs[i].zattr_ndx; *s != '\0'; s++) {
			if (*s == '=') {
				*s = '\0';
				s++;
				zattrs[i].ZVAL = s;
				zattrs[i].ZLEN = (uint_t)strlen(s) + 1;
				break;
			} else if (*s == '"') {
				/* advance s to matching quote */
				s++;
				while ((*s != '"') && (*s != '\0'))
					s++;
				if (*s == '\0') {
					/* unterminated quote */
					free(zattrs);
					return (NULL);
				}
			}
		}
		/*
		 * POLICY : Missing value for an index name is an
		 *	    error. The other alternative is the missing
		 *	    value means "is present" unfortunately there
		 *	    is no standard "is present" indicator in the
		 *	    existing databases.
		 * ANSWER : Always return an error.
		 */
		if (!zattrs[i].ZVAL) {
			free(zattrs);
			return (NULL);
		}
	}
	return (zattrs);
}

/*
 * nis_free_request()
 *
 * Free memory associated with a constructed list request.
 */
void
nis_free_request(ib_request *req)
{
	if (req->ibr_srch.ibr_srch_len) {
		/* free the string memory */
		free(req->ibr_srch.ibr_srch_val[0].zattr_ndx);
		/* free the nis_attr array */
		free(req->ibr_srch.ibr_srch_val);
	}

	if (req->ibr_name)
		free(req->ibr_name);
}

/*
 * nis_get_request()
 *
 * This function takes a NIS name, and converts it into an ib_request
 * structure. The request can then be used in a call to the nis service
 * functions. If the name wasn't parseable it returns an appropriate
 * error. This function ends up allocating an array of nis_attr structures
 * and a duplicate of the name string passed. To free this memory you
 * can call nis_free_request(), or you can simply free the first nis_attr
 * zattr_ndx pointer (the string memory) and the nis_attr pointer which
 * is the array.
 */
nis_error
nis_get_request(
	nis_name	name,		/* search criteria + Table name	*/
	nis_object	*obj,		/* Object for (rem/modify/add)	*/
	netobj		*cookie,	/* Pointer to a cookie		*/
	ib_request	*req)		/* Request structure to fill in */
{
	char	*s, *t; 		/* Some string pointer temps */
	char	*p;			/* temp var */
	char	**attr;			/* Intermediate attributes */
	int	i;			/* Counter variable */
	char		*data;		/* pointer to malloc'd string */
	int		zn = 0;		/* Count of attributes		*/
	size_t datalen;			/* length of malloc'd data	*/
	char		namebuf[NIS_MAXNAMELEN];

	uchar_t		within_attr_val;
				/*
				 * a boolean to indicate the current parse
				 * location is within the attribute value
				 * - so that we can stop deleting white
				 * space within an attribute value
				 */

	(void) memset(req, 0, sizeof (ib_request));

	/*
	 * if we're passed an object but no name, use the name from
	 * the object instead.
	 */
	if (obj && !name) {
		if ((strlen(obj->zo_name)+strlen(obj->zo_domain)+2) >
			sizeof (namebuf)) {
			return (NIS_BADNAME);
		}
		(void) snprintf(namebuf, sizeof (namebuf),
					"%s.%s", obj->zo_name, obj->zo_domain);
		name = namebuf;
	}
	if (!name || (name[0] == '\0'))
		return (NIS_BADNAME);

	s = name;

	/* Move to the start of the components */
	while (isspace(*s))
		s++;

	if (*s == '[') {

		s++; /* Point past the opening bracket */

		datalen = strlen(s);
		data = calloc(1, datalen+1);
		if (!data)
			return (NIS_NOMEMORY);

		t = data; /* Point to the databuffer */
		while ((*s != '\0') && (*s != ']')) {
			while (isspace(*s)) {
				s++;
			}
			/* Check to see if we finished off the string */
			if ((*s == '\0') || (*s == ']'))
				break;

			/* If *s == comma its a null criteria */
			if (*s == COMMA) {
				s++;
				continue;
			}
			/* Not a space and not a comma, process an attr */
			zn++;
			within_attr_val = 0; /* not within attr_val right now */
			while ((*s != COMMA) && (*s != ']') && (*s != '\0')) {
				if (*s == '"') {
					if (*(s+1) == '"') { /* escaped quote */
						*t++ = *s; /* copy one quote */
						s += 2;
					} else {
						/* skip quoted string */
						s++;
						while ((*s != '"') &&
							(*s != '\0'))
							*t++ = *s++;
						if (*s == '"') {
							s++;
						}
					}
				} else if (*s == '=') {
					*t++ = *s++;
					within_attr_val = 1;
				} else if (isspace(*s) && !within_attr_val) {
					s++;
				} else
					*t++ = *s++;
			}
			*t++ = '\0'; /* terminate the attribute */
			if (*s == COMMA)
				s++;
		}
		if (*s == '\0') {
			free(data);
			return (NIS_BADATTRIBUTE);
		}

		/* It wasn't a '\0' so it must be the closing bracket. */
		s++;
		/* Skip any intervening white space and "comma" */
		while (isspace(*s) || (*s == COMMA)) {
			s++;
		}
		/* Copy the name into our malloc'd buffer */
		(void) strcpy(t, s);

		/*
		 * If we found any attributes we process them, the
		 * data string at this point is completely nulled
		 * out except for attribute data. We recover this
		 * data by scanning the string (we know how long it
		 * is) and saving to each chunk of non-null data.
		 */
		if (zn) {
			/* Save this as the table name */
			req->ibr_name = strdup(t);
			attr = calloc(zn+1, sizeof (char *));
			if (!attr) {
				free(data);
				free(req->ibr_name);
				req->ibr_name = 0;
				return (NIS_NOMEMORY);
			}

			/* store in pieces in attr array */
			for (i = 0, s = data; i < zn; i++) {
				*(attr+i) = s;
				/* Advance s past this component */
				while (*s != '\0')
					s++;
				s++;
			}
			*(attr+zn) = NULL;
		} else {
			free(data);
			req->ibr_name = strdup(s);
		}
	} else {
		/* Null search criteria */
		req->ibr_name = strdup(s);
		data = NULL;
	}

	if (zn) {
		req->ibr_srch.ibr_srch_len = zn;
		req->ibr_srch.ibr_srch_val = __cvt2attr(&zn, attr);
		free(attr); /* don't need this any more */
		if (!(req->ibr_srch.ibr_srch_val)) {
			req->ibr_srch.ibr_srch_len = 0;
			free(req->ibr_name);
			req->ibr_name = 0;
			free(data);
			return (NIS_BADATTRIBUTE);
		}
	}

	/* check for correct quotes in ibr_name (but leave them in) */
	for (p = req->ibr_name; *p; p++) {
		if (*p == '"') {
			/* advance p to the matching quote */
			p++;
			while (*p != '"' && *p != '\0') {
				p++;
			}
			if (*p == '\0') {
				req->ibr_srch.ibr_srch_len = 0;
				free(req->ibr_name);
				req->ibr_name = 0;
				free(data);
				return (NIS_BADNAME);
			}
		}
	}

	if (obj) {
		req->ibr_obj.ibr_obj_len = 1;
		req->ibr_obj.ibr_obj_val = obj;
	}
	if (cookie) {
		req->ibr_cookie = *cookie;
	}
	return (NIS_SUCCESS);
}

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
 * nis_make_rpchandle()
 *
 * This is a generic version of clnt_creat() for NIS. It localizes
 * _all_ of the changes needed to port to TLI RPC into this one
 * section of code.
 */

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

char *
__nis_get_server_address(struct netconfig *nc, endpoint *ep)
{
	return (__map_addr(nc, ep->uaddr, NIS_PROG, NIS_VERSION));
}

#define	MAX_EP (20)

int
__nis_get_callback_addresses(endpoint *ep, endpoint **ret_eps)
{
	int i;
	int n;
	int st;
	int nep = 0;
	endpoint *eps;
	struct nd_hostserv hs;
	struct nd_addrlist *addrs;
	struct nd_mergearg ma;
	void *lh;
	void *nch;
	struct netconfig *nc;

	eps = malloc(MAX_EP * sizeof (endpoint));
	if (eps == 0)
		return (0);

	hs.h_host = HOST_SELF;
	hs.h_serv = "rpcbind";	/* as good as any */

	lh = __inet_get_local_interfaces();

	nch = setnetconfig();
	while ((nc = getnetconfig(nch)) != NULL) {
		if (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0)
			continue;
		if (nc->nc_semantics != NC_TPI_COTS &&
		    nc->nc_semantics != NC_TPI_COTS_ORD)
			continue;
		st = netdir_getbyname(nc, &hs, &addrs);
		if (st != 0)
			continue;

		/*
		 *  The netdir_merge code does not work very well
		 *  for inet if the client and server are not
		 *  on the same network.  Instead, we try each local
		 *  address.
		 *
		 *  For other protocol families and for servers on a
		 *  local network, we use the regular merge code.
		 */

		if (strcmp(nc->nc_protofmly, NC_INET) == 0 &&
		    !__inet_uaddr_is_local(lh, nc, ep->uaddr)) {
			n = __inet_address_count(lh);
			for (i = 0; i < n; i++) {
				if (nep >= MAX_EP) {
					syslog(LOG_INFO,
		"__nis_get_callback_addresses: too many endpoints");
					goto full;
				}
				eps[nep].uaddr = __inet_get_uaddr(lh, nc, i);
				if (eps[nep].uaddr == 0)
					continue;
				if (strcmp(eps[nep].uaddr, LOOP_UADDR) == 0) {
					free(eps[nep].uaddr);
					continue;
				}
				__nis_netconfig2ep(nc, &(eps[nep]));
				nep++;
			}
		} else {
			ma.s_uaddr = ep->uaddr;
			ma.c_uaddr = taddr2uaddr(nc, addrs->n_addrs);
			ma.m_uaddr = 0;
			(void) netdir_options(nc, ND_MERGEADDR, 0, (void *)&ma);
			free(ma.s_uaddr);
			free(ma.c_uaddr);

			if (nep >= MAX_EP) {
					syslog(LOG_INFO,
		"__nis_get_callback_addresses: too many endpoints");
				goto full;
			}
			eps[nep].uaddr = ma.m_uaddr;
			__nis_netconfig2ep(nc, &(eps[nep]));
			nep++;
		}
		netdir_free((void *)addrs, ND_ADDRLIST);
	}

full:
	(void) endnetconfig(nch);
	__inet_free_local_interfaces(lh);

	*ret_eps = eps;
	return (nep);
}

/*
 * Try to create a RPC GSS security context (flavor RPCSEC_GSS).
 * Returns auth handle on success, else NULL.  Set flag 'try_auth_des'
 * to TRUE if the AUTH_DES compat line is found in the security conf file
 * or no valid mech entries are found in the conf file.
 */
static AUTH *
create_rpcgss_secctx(
	CLIENT		*clnt,		/* out */
	nis_server	*srv,
	char 		*gss_svc,
	bool_t		*try_auth_des)	/* out */
{
	mechanism_t		**mechs;	/* list of mechanisms	*/

	*try_auth_des = FALSE;
	if (mechs = __nis_get_mechanisms(TRUE)) {
		mechanism_t **mpp;
		char svc_name[NIS_MAXNAMELEN+1] = {0};

		/* Check RPC GSS service name buf size. */
		if ((strlen(gss_svc ? gss_svc : NIS_SVCNAME_NISD) + 1
			+ strlen(srv->name) + 1) > sizeof (svc_name)) {
			syslog(LOG_ERR,
		"nis_make_rpchandle_gss_svc: RPC GSS service name too long");
			__nis_release_mechanisms(mechs);
			return (NULL);
		}

		/* RPC GSS service names are of the form svc@host.dom */
		(void) snprintf(svc_name, sizeof (svc_name),
				"%s@%s", gss_svc ? gss_svc : NIS_SVCNAME_NISD,
				srv->name);

		/*
		 * Loop thru all the available mech entries until an
		 * RPC GSS security context is established or until
		 * the AUTH_DES compat entry is found.
		 */
		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp)) {
				__nis_release_mechanisms(mechs);
				*try_auth_des = TRUE;
				return (NULL);
			}

			if (!VALID_MECH_ENTRY(mp)) {
				syslog(LOG_ERR,
					"%s: invalid mechanism entry name '%s'",
					NIS_SEC_CF_PATHNAME,
					mp->mechname ? mp->mechname : "NULL");
				continue;
			}

			/*
			 * If the mechanism is of the public key crypto
			 * technology variety, let's make sure the server's
			 * public key exists and the clients secret key is set
			 * before going thru the expense of a RPC GSS security
			 * context creation attempt.
			 */
			if (MECH_PK_TECH(mp) &&
				((srv->key_type == NIS_PK_DHEXT &&
					!__nis_dhext_extract_pkey(&(srv->pkey),
					mp->keylen,  mp->algtype)) ||
					!key_secretkey_is_set_g(mp->keylen,
							mp->algtype))) {
#ifdef DHEXT_DEBUG
					(void) fprintf(stderr,
"nis_make_rpchandle_gss_svc: srv keytype = %d: No keys, skip mech '%s' ...\n",
							srv->key_type,
							mp->alias);
#endif
					continue;
			}

			clnt->cl_auth = rpc_gss_seccreate(clnt, svc_name,
						mp->mechname, mp->secserv,
						mp->qop, NULL, NULL);
			if (clnt->cl_auth) {
				__nis_release_mechanisms(mechs);
				return (clnt->cl_auth); /* we're in bizness */
#ifdef DHEXT_DEBUG
			} else {
				rpc_gss_error_t	err;

				rpc_gss_get_error(&err);
				(void) fprintf(stderr,
"nis_make_rpchandle_gss_svc: RPCGSS_SecCreat fail: gerr = %d serr = %d\n",
					err.rpc_gss_error, err.system_error);
#endif /* DHEXT_DEBUG */
			}
		}
		__nis_release_mechanisms(mechs);
	} else {
		/* no valid mechs, fallback to AUTH_DES */
		*try_auth_des = TRUE;
	}

	return (NULL);
}


CLIENT *
nis_make_rpchandle(
	nis_server	*srv,	/* NIS Server description 		*/
	int		cback,	/* Boolean indicating callback address	*/
	rpcprog_t	prog,	/* Program number			*/
	rpcvers_t	ver,	/* Version				*/
	uint_t		flags,	/* Flags, {VC, DG, AUTH}  		*/
	int		inbuf,	/* Preferred buffer sizes 		*/
	int		outbuf)	/* for input and output   		*/
{
	return (nis_make_rpchandle_uaddr(srv, cback, prog, ver, flags,
			inbuf, outbuf, 0));
}

CLIENT *
nis_make_rpchandle_uaddr(
	nis_server	*srv,	/* NIS Server description 		*/
	int		cback,	/* Boolean indicating callback address	*/
	rpcprog_t	prog,	/* Program number			*/
	rpcvers_t	ver,	/* Version				*/
	uint_t		flags,	/* Flags, {VC, DG, AUTH}  		*/
	int		inbuf,	/* Preferred buffer sizes 		*/
	int		outbuf,	/* for input and output   		*/
	char		*uaddr)	/* optional address of server		*/
{
	return (nis_make_rpchandle_gss_svc(srv, cback, prog, ver, flags,
			inbuf, outbuf, uaddr, NULL));
}

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


typedef struct {
	endpoint		*ep;
	struct netconfig	*nc;
} alt_ep_t;

/*
 * Construct an rpc handle.
 *
 * If the gss_svc arg is NULL, then default to "nisd" (rpc.nisd).
 */
static CLIENT *
nis_make_rpchandle_gss_svc_ext(
	nis_server	*srv,	  /* NIS Server description 		*/
	int		cback,	  /* Boolean indicating callback address */
	rpcprog_t	prog,	  /* Program number			*/
	rpcvers_t	ver,	  /* Version				*/
	uint_t		flags,	  /* Flags, {VC, DG, AUTH}  		*/
	int		inbuf,	  /* Preferred buffer sizes 		*/
	int		outbuf,	  /* for input and output   		*/
	char		*uaddr,	  /* optional address of server		*/
	char		*gss_svc, /* RPC GSS service name		*/
	int		use_realid) /* 1: Use REAL id, 0: use Eff. ids	*/
{
	CLIENT			*clnt = 0;	/* Client handle 	*/
	void			*nc_handle;	/* Netconfig "state"	*/
	struct netconfig	*nc;		/* Various handles	*/
	endpoint		*ep;		/* useful endpoints	*/
	int			epl, i;		/* counters		*/
	int			uid, gid;	/* Effective uid/gid	*/
	char			netname[MAXNETNAMELEN+1]; /* our netname */
	char			*hexkey = NULL; /* hex public key for DHEXT */
	netobj			xpkey = { NULL, 0};
	bool_t			try_auth_des;
	alt_ep_t		*altep = 0;


	nc_handle = (void *) setnetconfig();
	if (!nc_handle)
		return (NULL);

	ep = srv->ep.ep_val;
	epl = srv->ep.ep_len;

	if (uaddr) {

		char	*fmly = (strchr(uaddr, ':') == 0) ? NC_INET : NC_INET6;

		while ((nc = getnetconfig(nc_handle)) != NULL) {
			/* Is it a visible transport ? */
			if ((nc->nc_flag & NC_VISIBLE) == 0)
				continue;
			/* Does the protocol family match the uaddr ? */
			if (strcmp(nc->nc_protofmly, fmly) != 0)
				continue;
			for (i = 0; i < epl; i++) {
				if (__nis_netconfig_matches_ep(nc, &ep[i])) {
					break;
				}
			}
			/* Did we find a matching endpoint ? */
			if (i < epl)
				break;
		}
		if (nc == 0) {
			syslog(LOG_ERR,
	"nis_make_rpchandle: can't find netconfig entry for %s, %s",
				uaddr, fmly);
			return (0);
		}

		clnt = __nis_clnt_create(RPC_ANYFD, nc, uaddr, 0, 0, prog, ver,
					inbuf, outbuf);

	} else {

		altep = calloc(epl, sizeof (*altep));

		/*
		 * The transport policies :
		 * Selected transport must be visible.
		 * Must have requested or better semantics.
		 * Must be correct protocol.
		 */
		while ((nc = getnetconfig(nc_handle)) != 0) {

			/* Is it a visible transport ? */
			if ((nc->nc_flag & NC_VISIBLE) == 0)
				continue;

			/* If we asked for a virtual circuit, is it ? */
			if (((flags & ZMH_VC) != 0) &&
			    (nc->nc_semantics != NC_TPI_COTS) &&
			    (nc->nc_semantics != NC_TPI_COTS_ORD))
				continue;

			/* Check to see is we talk this protofmly, protocol */
			for (i = 0; i < epl; i++) {
				if (__nis_netconfig_matches_ep(nc, &(ep[i])))
					break;
			}

			/* Was it one of our transports ? */
			if (i == epl)
				continue;	/* No */

			/*
			 * If it is one of our supported transports, but isn't
			 * a datagram and we want a datagram, keep looking but
			 * remember this one as a possibility.
			 */
			if (((flags & ZMH_DG) != 0) &&
				(nc->nc_semantics != NC_TPI_CLTS) &&
					altep != 0) {
				altep[i].nc = nc;
				altep[i].ep = &ep[i]; /* This endpoint */
				continue;
			}

			/* We've got a candidate; see if it works */
			clnt = __nis_clnt_create(RPC_ANYFD, nc, ep[i].uaddr, 0,
						(cback == 0), prog, ver, inbuf,
						outbuf);

			if (clnt != 0)
				break;
		}

		if (altep != 0 && (!(flags & ZMH_NOFALLBACK))) {
			/* If primary choices failed, try the alternates */
			for (i = 0; clnt == 0 && i < epl; i++) {
				if (altep[i].ep == 0)
					continue;
				clnt = __nis_clnt_create(RPC_ANYFD,
					altep[i].nc, altep[i].ep->uaddr, 0,
					(cback == 0), prog, ver, inbuf,
					outbuf);
			}
			free(altep);
		}

	}

	/* Done with the netconfig handle regardless */
	(void) endnetconfig(nc_handle);

	/* If we still don't have a client handle, we're sunk */
	if (clnt == 0) {
		return (0);
	}

	/*
	 * No auth requested or it's a callback (which is not authenticated),
	 * so we're done.
	 */
	if (!(flags & ZMH_AUTH) || cback)
		return (clnt);

	/*
	 * Setup authentication.  Try the RPCSEC_GSS flavor first, then
	 * fallback to AUTH_DES (if requested) and, if need be, AUTH_SYS.
	 */
	if (create_rpcgss_secctx(clnt, srv, gss_svc, &try_auth_des))
		return (clnt);

	if (!try_auth_des)
		/* XXXX what's the meaning of going into a switch stmt??? */
		goto auth_sys;

	switch (srv->key_type) {
	case NIS_PK_DHEXT :
		/*
		 * We're doing AUTH_DES, but the server might
		 * have multiple keys so let's get the 192-0 one.
		 */
		if ((hexkey = __nis_dhext_extract_pkey(&(srv->pkey),
							192, 0)) == NULL)
			goto auth_sys;
		xpkey.n_len = strlen(hexkey) + 1;
		xpkey.n_bytes = hexkey;
		/*FALLTHROUGH*/
	case NIS_PK_DH :
		(void) host2netname(netname, srv->name, NULL);
		clnt->cl_auth = (AUTH *)authdes_pk_seccreate(netname,
					xpkey.n_len ? &xpkey : &(srv->pkey),
					15, NULL, NULL, srv);
		if (xpkey.n_len)
			free(xpkey.n_bytes);
		if (clnt->cl_auth)
			break;
		/*FALLTHROUGH*/
	case NIS_PK_NONE :
auth_sys:
	uid = use_realid ? getuid() : geteuid();
	gid = use_realid ? getgid() : getegid();

	clnt->cl_auth = authsys_create(nis_local_host(), uid, gid, 0, NULL);
	if (clnt->cl_auth)
		break;
	/*FALLTHROUGH*/
	default :
		clnt->cl_auth = authnone_create();
		if (clnt->cl_auth)
			break;
		syslog(LOG_CRIT,
			"nis_make_rpchandle_uaddr: cannot create cred.");
		abort();
		break;
	}

	if (clnt->cl_auth)
		return (clnt);

	clnt_destroy(clnt);
	return (NULL);
}

CLIENT *
nis_make_rpchandle_gss_svc(nis_server *srv, int cback, rpcprog_t prog,
    rpcvers_t ver, uint_t flags, int inbuf, int outbuf, char *uaddr,
    char *gss_svc)
{
	return (nis_make_rpchandle_gss_svc_ext(srv, cback, prog, ver, flags,
	    inbuf, outbuf, uaddr, gss_svc, 0));
}

CLIENT *
nis_make_rpchandle_gss_svc_ruid(nis_server *srv, int cback, rpcprog_t prog,
    rpcvers_t ver, uint_t flags, int inbuf, int outbuf, char *uaddr,
    char *gss_svc)
{
	return (nis_make_rpchandle_gss_svc_ext(srv, cback, prog, ver, flags,
	    inbuf, outbuf, uaddr, gss_svc, 1));
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
	struct nis_sdata 	*bs, 	/* User buffer structure */
	uint_t			el,	/* Sizeof elements	 */
	uint_t			nel)	/* Number of elements	 */
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
		int 	size_delta;

		free(bs->buf);
		size_delta = - (bs->size);
		bs->buf = malloc(sz);

		/* check the result of malloc() first	*/
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

char *
nis_old_data_r(
	char	*s,
	struct nis_sdata	*bs_ptr)
{
	char			*buf;
	char			temp[1024];
	size_t			len = 0;

	buf = (char *)nis_get_static_storage(bs_ptr, 1, 1024);

	if (!buf)
		return (NULL);

	/*
	 * this saving of 's' is because the routines that call nis_data()
	 * are not very careful about what they pass in.  Sometimes what they
	 * pass in are 'static' returned from some of the routines called
	 * below nis_leaf_of(),  nis_local_host() and so on.
	 */
	if (s) {
		len = strlen(s) + 1;
		if (len >= sizeof (temp))
			return (NULL);
		(void) snprintf(temp, sizeof (temp), "/%s", s);
	}
	if (len + strlen(__nis_data_directory) +
		strlen(nis_leaf_of(nis_local_host())) >= bs_ptr->size)
		return (NULL);
	(void) strcpy(buf, __nis_data_directory);
	(void) strcat(buf, nis_leaf_of(nis_local_host()));
	if (s)
		(void) strcat(buf, temp);

	for (s = buf; *s; s++) {
		if (isupper(*s))
			*s = tolower(*s);
	}

	return (buf);
}

char *
nis_old_data(char *s)
{
	static pthread_key_t 	bs_key = PTHREAD_ONCE_KEY_NP;
	static struct nis_sdata	bs_main;
	struct nis_sdata	*bs_ptr;

	bs_ptr = thr_main()? &bs_main :
		thr_get_storage(&bs_key, sizeof (struct nis_sdata),
		    destroy_nis_sdata);
	return (nis_old_data_r(s, bs_ptr));
}


char *
nis_data_r(char *s, struct nis_sdata *bs_ptr)
{
	char			*buf;
	char			temp[1024];
	size_t			len = 0;

	buf = (char *)nis_get_static_storage(bs_ptr, 1, 1024);

	if (!buf)
		return (NULL);

	/*
	 * this saving of 's' is because the routines that call nis_data()
	 * are not very careful about what they pass in.  Sometimes what they
	 * pass in are 'static' returned from some of the routines called
	 * below nis_leaf_of(),  nis_local_host() and so on.
	 */
	if (s) {
		len = strlen(s) + 1;
		if (len >= sizeof (temp))
			return (NULL);
		(void) snprintf(temp, sizeof (temp), "/%s", s);
	}
	if (len + strlen(__nis_data_directory) +
		strlen(NIS_DIR) >= bs_ptr->size)
		return (NULL);
	(void) strcpy(buf, __nis_data_directory);
	(void) strcat(buf, NIS_DIR);
	if (s)
		(void) strcat(buf, temp);

	for (s = buf; *s; s++) {
		if (isupper(*s))
			*s = tolower(*s);
	}

	return (buf);
}

char *
nis_data(char *s)
{
	static pthread_key_t 	bs_key = PTHREAD_ONCE_KEY_NP;
	static struct nis_sdata	bs_main;
	struct nis_sdata	*bs_ptr;

	bs_ptr = thr_main()? &bs_main :
		thr_get_storage(&bs_key, sizeof (struct nis_sdata),
		    destroy_nis_sdata);
	return (nis_data_r(s, bs_ptr));
}

/*
 * Return the directory name of the root_domain of the caller's NIS+
 * domain.
 *
 * This routine is a temporary implementation and should be
 * provided as part of the the NIS+ project.  See RFE:  1103216
 * Required for root replication.
 *
 * XXX MT safing: local_root_lock protects the local_root structure.
 *
 * It tries to determine the root domain
 * name by "walking" the path up the NIS+ directory tree, starting
 * at nis_local_directory() until a NIS_NOSUCHNAME or NIS_NOTFOUND error
 * is obtained.  Returns 0 on fatal errors obtained before this point,
 * or if it exhausts the domain name without ever obtaining one of
 * of these errors.
 */

static nis_name local_root = 0;
static mutex_t local_root_lock = DEFAULTMUTEX;

nis_name
__nis_local_root(void)
{
	char *dir;
	int found_root = 0;
	int try_count = 0;
	int fatal_error = 0;
	char *prev_testdir;
	char *testdir;

	sig_mutex_lock(&local_root_lock);
	if (local_root) {
		sig_mutex_unlock(&local_root_lock);
		return (local_root);
	}
	local_root = calloc(1, LN_BUFSIZE);

	if (!local_root) {
		sig_mutex_unlock(&local_root_lock);
		return (0);
	}
	/*  walk up NIS+ tree till we find the root. */
	dir = strdup(__nis_rpc_domain());
	prev_testdir = dir;
	testdir = nis_domain_of(prev_testdir);

	while (testdir && !found_root && !fatal_error) {
	    /* try lookup */
	    nis_result* nis_ret = nis_lookup(testdir, 0);
	    /* handle return status */
	    switch (nis_ret->status) {
	    case NIS_SUCCESS:
	    case NIS_S_SUCCESS:
		try_count = 0;
		prev_testdir = testdir;
		testdir = nis_domain_of(prev_testdir);
		break;
	    case NIS_NOSUCHNAME:
	    case NIS_NOTFOUND:
	    case NIS_NOT_ME:
	    case NIS_FOREIGNNS:
		found_root = 1;
		break;
	    case NIS_TRYAGAIN:
	    case NIS_CACHEEXPIRED:
		/* sleep 1 second and try same name again, up to 10 times */
		/* REMIND: This is arbitrary! BAD! */
		(void) sleep(1);
		fatal_error = (try_count++ > 9);
		break;
	    case NIS_NAMEUNREACHABLE:
	    case NIS_SYSTEMERROR:
	    case NIS_RPCERROR:
	    case NIS_NOMEMORY:
	    default:
		fatal_error = 1;
		break;
	    }
	    if (nis_ret) nis_freeresult(nis_ret);
	}

	if (!found_root) {
		free(dir);
		sig_mutex_unlock(&local_root_lock);
		return (0);
	}
	(void) strcpy(local_root, prev_testdir);
	free(dir);
	sig_mutex_unlock(&local_root_lock);
	return (local_root);
}

extern	void __pkey_cache_add(char *, char *, keylen_t, algtype_t);
extern	int bin2hex(int, unsigned char *, char *);

/*
 * __nis_cache_server_pkeys
 *
 * Add the public keys for the servers of the directory object to the
 * per-process public key cache.
 */
void
__nis_cache_server_pkeys(directory_obj *dir) {

	int		i;
	nis_server	*srv;
	char		netname[MAXNETNAMELEN+1];
	char		pkey[MAX_NETOBJ_SZ+1];
	extdhkey_t	*key;
	uint_t		s;

	if (dir == NULL)
		return;

	for (i = 0; i < dir->do_servers.do_servers_len; i++) {

		srv = &(dir->do_servers.do_servers_val[i]);

		switch (srv->key_type) {
		case NIS_PK_DH:
			if (srv->pkey.n_len < sizeof (pkey) &&
				host2netname(netname, srv->name, NULL)) {
				(void) memcpy(pkey, srv->pkey.n_bytes,
					srv->pkey.n_len);
				pkey[srv->pkey.n_len] = '\0';
				__pkey_cache_add(netname, pkey, 192, 0);
			}
			break;
		case NIS_PK_DHEXT:
			if (!host2netname(netname, srv->name, NULL))
				break;
			for (s = 0; s < srv->pkey.n_len; ) {
				keylen_t	k, kpadlen;
				algtype_t	a;
				/* LINTED pointer cast */
				key = (extdhkey_t *)&(srv->pkey.n_bytes[s]);
				k = ntohs(key->keylen);
				if (k == 0)
					break;
				kpadlen = ((((k+7)/8)+3)/4)*4;
				a = ntohs(key->algtype);
				if (kpadlen <= sizeof (pkey)) {
					(void) bin2hex((k+7)/8, key->key, pkey);
					__pkey_cache_add(netname, pkey, k, a);
				}
				s += 2*sizeof (ushort_t) + kpadlen;
			}
			break;
		default:
			break;
		}

	}
}
