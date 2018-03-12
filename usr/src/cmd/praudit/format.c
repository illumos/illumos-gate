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


#define	_REENTRANT

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <libintl.h>
#include <netdb.h>
#include <time.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <arpa/inet.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <security/pam_appl.h>

#include <sys/inttypes.h>
#include <sys/mkdev.h>
#include <sys/types.h>
#include <aclutils.h>

#include "praudit.h"
#include "toktable.h"
#include "adt_xlate.h"

static void	convertascii(char *p, char *c, int size);
static int	convertbinary(char *p, char *c, int size);
static void	eventmodifier2string(au_emod_t emodifier, char *modstring,
    size_t modlen);
static int	do_mtime32(pr_context_t *context, int status, int flag,
    uint32_t scale);
static int	do_mtime64(pr_context_t *context, int status, int flag,
    uint64_t scale);

/*
 * for uid/gid caches
 */
static uid_t		lastuid	= (uid_t)-1;
static gid_t		lastgid = (gid_t)-1;
static char		*lastuname = NULL;
static char		*lastgname = NULL;
static char		*getname(uid_t);
static char		*getgroup(gid_t);
static struct cachenode *findincache(struct cachenode **, long);
#include <utmpx.h>

struct	utmpx utmp;

#define	NMAX	(sizeof (utmp.ut_name))
#define	SCPYN(a, b)	(void) strncpy(a, b, NMAX)

struct cachenode {		/* this struct must be zeroed before using */
	struct cachenode *lesschild;	/* subtree whose entries < val */
	struct cachenode *grtrchild;	/* subtree whose entries > val */
	long val;			/* the uid or gid of this entry */
	int initted;			/* name has been filled in */
	char name[NMAX+1];		/* the string that val maps to */
};
static struct cachenode *names, *groups;

static struct cachenode *
findincache(struct cachenode **head, long val)
{
	struct cachenode **parent = head;
	struct cachenode *c = *parent;

	while (c != NULL) {
		if (val == c->val) {
			/* found it */
			return (c);
		} else if (val < c->val) {
			parent = &c->lesschild;
			c = c->lesschild;
		} else {
			parent = &c->grtrchild;
			c = c->grtrchild;
		}
	}

	/* not in the cache, make a new entry for it */
	c = calloc(1, sizeof (struct cachenode));
	if (c == NULL) {
		perror("praudit");
		exit(2);
	}
	*parent = c;
	c->val = val;
	return (c);
}

/*
 * get name from cache, or passwd file for a given uid;
 * lastuid is set to uid.
 */
static char *
getname(uid_t uid)
{
	struct passwd *pwent;
	struct cachenode *c;

	if ((uid == lastuid) && lastuname)
		return (lastuname);

	c = findincache(&names, uid);
	if (c->initted == 0) {
		if ((pwent = getpwuid(uid)) != NULL) {
			SCPYN(&c->name[0], pwent->pw_name);
		} else {
			(void) sprintf(&c->name[0], "%u", (int)uid);
		}
		c->initted = 1;
	}
	lastuid = uid;
	lastuname = &c->name[0];
	return (lastuname);
}

/*
 * get name from cache, or group file for a given gid;
 * lastgid is set to gid.
 */
static char *
getgroup(gid_t gid)
{
	struct group *grent;
	struct cachenode *c;

	if ((gid == lastgid) && lastgname)
		return (lastgname);

	c = findincache(&groups, gid);
	if (c->initted == 0) {
		if ((grent = getgrgid(gid)) != NULL) {
			SCPYN(&c->name[0], grent->gr_name);
		} else {
			(void) sprintf(&c->name[0], "%u", (int)gid);
		}
		c->initted = 1;
	}
	lastgid = gid;
	lastgname = &c->name[0];
	return (lastgname);
}

/*
 * ------------------------------------------------------
 * field widths for arbitrary data token type
 * ------------------------------------------------------
 */
static struct fw {
	char	basic_unit;
	struct {
		char	print_base;
		int	field_width;
	} pwidth[5];
} fwidth[] = {
	/* character data type, 8 bits */
		AUR_CHAR,	AUP_BINARY,	12,
				AUP_OCTAL,	 6,
				AUP_DECIMAL,	 6,
				AUP_HEX,	 6,
				AUP_STRING,	 1,
		AUR_BYTE,	AUP_BINARY,	12,
				AUP_OCTAL,	 6,
				AUP_DECIMAL,	 6,
				AUP_HEX,	 6,
				AUP_STRING,	 1,
		AUR_SHORT,	AUP_BINARY,	20,
				AUP_OCTAL,	10,
				AUP_DECIMAL,	10,
				AUP_HEX,	 8,
				AUP_STRING,	 6,
		AUR_INT32,	AUP_BINARY,	36,
				AUP_OCTAL,	18,
				AUP_DECIMAL,	18,
				AUP_HEX,	12,
				AUP_STRING,	10,
		AUR_INT64,	AUP_BINARY,	68,
				AUP_OCTAL,	34,
				AUP_DECIMAL,	34,
				AUP_HEX,	20,
				AUP_STRING,	20};


static int	numwidthentries = sizeof (fwidth)
			/ sizeof (struct fw);


/*
 * -----------------------------------------------------------------------
 * do_newline:
 *		  Print a newline, if needed according to various formatting
 *		  rules.
 * return codes :   0 - success
 *		:  -1 - error
 * -----------------------------------------------------------------------
 */
int
do_newline(pr_context_t *context, int flag)
{
	int	retstat = 0;

	if (!(context->format & PRF_ONELINE) && (flag == 1))
		retstat = pr_putchar(context, '\n');
	else if (!(context->format & PRF_XMLM))
		retstat = pr_printf(context, "%s", context->SEPARATOR);

	return (retstat);
}

int
open_tag(pr_context_t *context, int tagnum)
{
	int		err = 0;
	token_desc_t	*tag;

	/* no-op if not doing XML format */
	if (!(context->format & PRF_XMLM))
		return (0);

	tag = &tokentable[tagnum];

	/*
	 * First if needed do an implicit finish of a pending open for an
	 * extended tag.  I.e., for the extended tag xxx:
	 *	<xxx a=".." b=".."> ...  </xxx>
	 * -- insert a close bracket after the last attribute
	 * (in other words, when the 1st non-attribute is opened while
	 * this is pending). Note that only one tag could be pending at
	 * a given time -- it couldn't be nested.
	 */
	if (context->pending_flag && (tag->t_type != T_ATTRIBUTE)) {
		/* complete pending extended open */
		err = pr_putchar(context, '>');
		if (err != 0)
			return (err);
		context->pending_flag = 0;
	}

	if (is_header_token(tagnum) || is_file_token(tagnum)) {
		/* File token or new record on new line */
		err = pr_putchar(context, '\n');
	} else if (is_token(tagnum)) {
		/* Each token on new line if possible */
		err = do_newline(context, 1);
	}
	if (err != 0)
		return (err);

	switch (tag->t_type) {
	case T_ATTRIBUTE:
		err = pr_printf(context, " %s=\"", tag->t_tagname);
		break;
	case T_ELEMENT:
		err = pr_printf(context, "<%s>", tag->t_tagname);
		break;
	case T_ENCLOSED:
		err = pr_printf(context, "<%s", tag->t_tagname);
		break;
	case T_EXTENDED:
		err = pr_printf(context, "<%s", tag->t_tagname);
		if (err == 0)
			context->pending_flag = tagnum;
		break;
	default:
		break;
	}

	if (is_header_token(tagnum) && (err == 0))
		context->current_rec = tagnum;	/* set start of new record */

	return (err);
}

/*
 * Do an implicit close of a record when needed.
 */
int
check_close_rec(pr_context_t *context, int tagnum)
{
	int	err = 0;

	/* no-op if not doing XML format */
	if (!(context->format & PRF_XMLM))
		return (0);

	/*
	 * If we're opening a header or the file token (i.e., starting a new
	 * record), if there's a current record in progress do an implicit
	 * close of it.
	 */
	if ((is_header_token(tagnum) || is_file_token(tagnum)) &&
	    context->current_rec) {
		err = do_newline(context, 1);
		if (err == 0)
			err = close_tag(context, context->current_rec);
	}

	return (err);
}

/*
 * explicit finish of a pending open for an extended tag.
 */
int
finish_open_tag(pr_context_t *context)
{
	int	err = 0;

	/* no-op if not doing XML format */
	if (!(context->format & PRF_XMLM))
		return (0);

	if (context->pending_flag) {
		/* complete pending extended open */
		err = pr_putchar(context, '>');
		if (err == 0)
			context->pending_flag = 0;
	}
	return (err);
}

int
close_tag(pr_context_t *context, int tagnum)
{
	int		err = 0;
	token_desc_t	*tag;

	/* no-op if not doing XML format */
	if (!(context->format & PRF_XMLM))
		return (0);

	tag = &tokentable[tagnum];

	switch (tag->t_type) {
	case T_ATTRIBUTE:
		err = pr_putchar(context, '\"');
		break;
	case T_ELEMENT:
		err = pr_printf(context, "</%s>", tag->t_tagname);
		break;
	case T_ENCLOSED:
		err = pr_printf(context, "/>");
		break;
	case T_EXTENDED:
		err = pr_printf(context, "</%s>", tag->t_tagname);
		break;
	default:
		break;
	}

	if (is_header_token(tagnum) && (err == 0))
		context->current_rec = 0;	/* closing rec; none current */

	return (err);
}

/*
 * -----------------------------------------------------------------------
 * process_tag:
 *		  Calls the routine corresponding to the tag
 *		  Note that to use this mechanism, all such routines must
 *		  take 2 ints for their parameters; the first of these is
 *		  the current status.
 *
 *		  flag = 1 for newline / delimiter, else 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
process_tag(pr_context_t *context, int tagnum, int status, int flag)
{
	int retstat;

	retstat = status;

	if (retstat)
		return (retstat);

	if ((tagnum > 0) && (tagnum <= MAXTAG) &&
	    (tokentable[tagnum].func != NOFUNC)) {
		retstat = open_tag(context, tagnum);
		if (!retstat)
			retstat = (*tokentable[tagnum].func)(context, status,
			    flag);
		if (!retstat)
			retstat = close_tag(context, tagnum);
		return (retstat);
	}
	/* here if token id is not in table */
	(void) fprintf(stderr, gettext("praudit: No code associated with "
	    "tag id %d\n"), tagnum);
	return (0);
}

void
get_Hname(uint32_t addr, char *buf, size_t buflen)
{
	extern char	*inet_ntoa(const struct in_addr);
	struct hostent *phe;
	struct in_addr ia;

	phe = gethostbyaddr((const char *)&addr, 4, AF_INET);
	if (phe == (struct hostent *)0) {
		ia.s_addr = addr;
		(void) snprintf(buf, buflen, "%s", inet_ntoa(ia));
		return;
	}
	ia.s_addr = addr;
	(void) snprintf(buf, buflen, "%s", phe->h_name);
}

void
get_Hname_ex(uint32_t *addr, char *buf, size_t buflen)
{
	struct hostent *phe;
	int err;

	phe = getipnodebyaddr((const void *)addr, 16, AF_INET6, &err);

	if (phe == (struct hostent *)0) {
		(void) inet_ntop(AF_INET6, (void *)addr, buf, buflen);
	} else
		(void) snprintf(buf, buflen, "%s", phe->h_name);

	if (phe)
		freehostent(phe);
}

int
pa_hostname(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	uint32_t	ip_addr;
	struct in_addr ia;
	uval_t uval;
	char	buf[256];

	if (status <  0)
		return (status);

	if ((returnstat = pr_adr_char(context, (char *)&ip_addr, 4)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;

	if (!(context->format & PRF_RAWM)) {
		uval.string_val = buf;
		get_Hname(ip_addr, buf, sizeof (buf));
		returnstat = pa_print(context, &uval, flag);
	} else {
		ia.s_addr = ip_addr;
		if ((uval.string_val = inet_ntoa(ia)) == NULL)
			return (-1);
		returnstat = pa_print(context, &uval, flag);
	}
	return (returnstat);
}

int
pa_hostname_ex(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	uint32_t	ip_type;
	uint32_t	ip_addr[4];
	struct in_addr ia;
	char buf[256];
	uval_t uval;

	if (status <  0)
		return (status);

	/* get ip type */
	if ((returnstat = pr_adr_int32(context, (int32_t *)&ip_type, 1)) != 0)
		return (returnstat);

	/* only IPv4 and IPv6 addresses are legal */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get ip address */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
			return (returnstat);

	if ((returnstat = open_tag(context, TAG_HOSTID)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	if (ip_type == AU_IPv4) {		/* ipv4 address */
		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname(ip_addr[0], buf, sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		} else {
			ia.s_addr = ip_addr[0];
			if ((uval.string_val = inet_ntoa(ia)) == NULL)
				return (-1);
			returnstat = pa_print(context, &uval, flag);
		}
	} else if (ip_type == AU_IPv6) {	/* IPv6 addresss (128 bits) */
		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname_ex(ip_addr, buf, sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		} else {
			uval.string_val = (char *)buf;
			(void) inet_ntop(AF_INET6, (void *)ip_addr, buf,
			    sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		}
	}

	if (returnstat != 0)
		return (returnstat);
	return (close_tag(context, TAG_HOSTID));
}

int
pa_hostname_so(pr_context_t *context, int status, int flag)
{
	int		returnstat;
	short		ip_type;
	ushort_t	ip_port;
	uint32_t	ip_addr[4];
	struct in_addr ia;
	char buf[256];
	uval_t uval;

	if (status <  0)
		return (status);

	/* get ip type */
	if ((returnstat = pr_adr_short(context, &ip_type, 1)) != 0)
		return (returnstat);

	/* only IPv4 and IPv6 addresses are legal */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get local ip port */
	if ((returnstat = pr_adr_u_short(context, &ip_port, 1)) != 0)
		return (returnstat);

	if ((returnstat = open_tag(context, TAG_SOCKEXLPORT)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	uval.string_val = hexconvert((char *)&ip_port, sizeof (ip_port),
	    sizeof (ip_port));
	if (uval.string_val) {
		returnstat = pa_print(context, &uval, 0);
		free(uval.string_val);
	} else
		returnstat = -1;
	if (returnstat)
		return (returnstat);

	if ((returnstat = close_tag(context, TAG_SOCKEXLPORT)) != 0)
		return (returnstat);

	/* get local ip address */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
			return (returnstat);

	if ((returnstat = open_tag(context, TAG_SOCKEXLADDR)) != 0)
		return (returnstat);

	if (ip_type == AU_IPv4) {		/* ipv4 address */

		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname(ip_addr[0], buf, sizeof (buf));
			returnstat = pa_print(context, &uval, 0);
		} else {
			ia.s_addr = ip_addr[0];
			if ((uval.string_val = inet_ntoa(ia)) == NULL)
				return (-1);
			returnstat = pa_print(context, &uval, 0);
		}

	} else if (ip_type == AU_IPv6) {	/* IPv6 addresss (128 bits) */

		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname_ex(ip_addr, buf, sizeof (buf));
			returnstat = pa_print(context, &uval, 0);
		} else {
			uval.string_val = (char *)buf;
			(void) inet_ntop(AF_INET6, (void *)ip_addr, buf,
			    sizeof (buf));
			returnstat = pa_print(context, &uval, 0);
		}
	} else
		returnstat = -1;

	if (returnstat)
		return (returnstat);

	if ((returnstat = close_tag(context, TAG_SOCKEXLADDR)) != 0)
		return (returnstat);

	/* get foreign ip port */
	if ((returnstat = pr_adr_u_short(context, &ip_port, 1)) != 0)
		return (returnstat);

	if ((returnstat = open_tag(context, TAG_SOCKEXFPORT)) != 0)
		return (returnstat);

	uval.string_val = hexconvert((char *)&ip_port, sizeof (ip_port),
	    sizeof (ip_port));
	if (uval.string_val) {
		returnstat = pa_print(context, &uval, 0);
		free(uval.string_val);
	} else
		returnstat = -1;

	if (returnstat)
		return (returnstat);

	if ((returnstat = close_tag(context, TAG_SOCKEXFPORT)) != 0)
		return (returnstat);

	/* get foreign ip address */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
			return (returnstat);

	if ((returnstat = open_tag(context, TAG_SOCKEXFADDR)) != 0)
		return (returnstat);

	if (ip_type == AU_IPv4) {		/* ipv4 address */

		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname(ip_addr[0], buf, sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		} else {
			ia.s_addr = ip_addr[0];
			if ((uval.string_val = inet_ntoa(ia)) == NULL)
				return (-1);
			returnstat = pa_print(context, &uval, flag);
		}

	} else if (ip_type == AU_IPv6) {	/* IPv6 addresss (128 bits) */

		if (!(context->format & PRF_RAWM)) {
			uval.string_val = buf;
			get_Hname_ex(ip_addr, buf, sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		} else {
			uval.string_val = (char *)buf;
			(void) inet_ntop(AF_INET6, (void *)ip_addr, buf,
			    sizeof (buf));
			returnstat = pa_print(context, &uval, flag);
		}
	} else
		returnstat = -1;

	if (returnstat)
		return (returnstat);

	if ((returnstat = close_tag(context, TAG_SOCKEXFADDR)) != 0)
		return (returnstat);

	return (returnstat);
}


#define	NBITSMAJOR64	32	/* # of major device bits in 64-bit Solaris */
#define	NBITSMINOR64	32	/* # of minor device bits in 64-bit Solaris */
#define	MAXMAJ64	0xfffffffful	/* max major value */
#define	MAXMIN64	0xfffffffful	/* max minor value */

#define	NBITSMAJOR32	14	/* # of SVR4 major device bits */
#define	NBITSMINOR32	18	/* # of SVR4 minor device bits */
#define	NMAXMAJ32	0x3fff	/* SVR4 max major value */
#define	NMAXMIN32	0x3ffff	/* MAX minor for 3b2 software drivers. */


static int32_t
minor_64(uint64_t dev)
{
	if (dev == NODEV) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(dev & MAXMIN64);
}

static int32_t
major_64(uint64_t dev)
{
	uint32_t maj;

	maj = (uint32_t)(dev >> NBITSMINOR64);

	if (dev == NODEV || maj > MAXMAJ64) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(maj);
}

static int32_t
minor_32(uint32_t dev)
{
	if (dev == NODEV) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(dev & MAXMIN32);
}

static int32_t
major_32(uint32_t dev)
{
	uint32_t maj;

	maj = (uint32_t)(dev >> NBITSMINOR32);

	if (dev == NODEV || maj > MAXMAJ32) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(maj);
}


/*
 * -----------------------------------------------------------------------
 * pa_tid() 	: Process terminal id and display contents
 * return codes	: -1 - error
 *		:  0 - successful
 *
 *	terminal id port		adr_int32
 *	terminal id machine		adr_int32
 * -----------------------------------------------------------------------
 */
int
pa_tid32(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	int32_t dev_maj_min;
	uint32_t	ip_addr;
	struct in_addr ia;
	char	*ipstring;
	char	buf[256];
	uval_t	uval;

	if (status <  0)
		return (status);

	if ((returnstat = pr_adr_int32(context, &dev_maj_min, 1)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_char(context, (char *)&ip_addr, 4)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	uval.string_val = buf;

	if (!(context->format & PRF_RAWM)) {
		char	hostname[256];

		get_Hname(ip_addr, hostname, sizeof (hostname));
		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_32(dev_maj_min),
		    minor_32(dev_maj_min),
		    hostname);
		return (pa_print(context, &uval, flag));
	}

	ia.s_addr = ip_addr;
	if ((ipstring = inet_ntoa(ia)) == NULL)
		return (-1);

	(void) snprintf(buf, sizeof (buf), "%d %d %s", major_32(dev_maj_min),
	    minor_32(dev_maj_min),
	    ipstring);

	return (pa_print(context, &uval, flag));
}

int
pa_tid32_ex(pr_context_t *context, int status, int flag)
{
	int		returnstat;
	int32_t		dev_maj_min;
	uint32_t	ip_addr[16];
	uint32_t	ip_type;
	struct in_addr	ia;
	char		*ipstring;
	char		hostname[256];
	char		buf[256];
	char		tbuf[256];
	uval_t		uval;

	if (status <  0)
		return (status);

	/* get port info */
	if ((returnstat = pr_adr_int32(context, &dev_maj_min, 1)) != 0)
		return (returnstat);

	/* get address type */
	if ((returnstat = pr_adr_u_int32(context, &ip_type, 1)) != 0)
		return (returnstat);

	/* legal address types are either AU_IPv4 or AU_IPv6 only */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get address (4/16) */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	if (ip_type == AU_IPv4) {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname(ip_addr[0], hostname, sizeof (hostname));
			(void) snprintf(buf, sizeof (buf), "%d %d %s",
			    major_32(dev_maj_min), minor_32(dev_maj_min),
			    hostname);
			return (pa_print(context, &uval, flag));
		}

		ia.s_addr = ip_addr[0];
		if ((ipstring = inet_ntoa(ia)) == NULL)
			return (-1);

		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_32(dev_maj_min), minor_32(dev_maj_min), ipstring);

		return (pa_print(context, &uval, flag));
	} else {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname_ex(ip_addr, hostname, sizeof (hostname));
			(void) snprintf(buf, sizeof (buf), "%d %d %s",
			    major_32(dev_maj_min), minor_32(dev_maj_min),
			    hostname);
			return (pa_print(context, &uval, flag));
		}

		(void) inet_ntop(AF_INET6, (void *) ip_addr, tbuf,
		    sizeof (tbuf));

		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_32(dev_maj_min), minor_32(dev_maj_min), tbuf);

		return (pa_print(context, &uval, flag));
	}
}

int
pa_ip_addr(pr_context_t *context, int status, int flag)
{
	int		returnstat;
	uval_t		uval;
	uint32_t	ip_addr[4];
	uint32_t	ip_type;
	struct in_addr	ia;
	char		*ipstring;
	char		hostname[256];
	char		buf[256];
	char		tbuf[256];

	if (status <  0)
		return (status);

	/* get address type */
	if ((returnstat = pr_adr_u_int32(context, &ip_type, 1)) != 0)
		return (returnstat);

	/* legal address type is AU_IPv4 or AU_IPv6 */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get address (4/16) */
	if ((returnstat = pr_adr_char(context, (char *)ip_addr, ip_type)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	if (ip_type == AU_IPv4) {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname(ip_addr[0], hostname, sizeof (hostname));
			(void) snprintf(buf, sizeof (buf), "%s", hostname);
			return (pa_print(context, &uval, flag));
		}

		ia.s_addr = ip_addr[0];
		if ((ipstring = inet_ntoa(ia)) == NULL)
			return (-1);

		(void) snprintf(buf, sizeof (buf), "%s", ipstring);

		return (pa_print(context, &uval, flag));
	} else {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname_ex(ip_addr, hostname, sizeof (hostname));
			(void) snprintf(buf, sizeof (buf), "%s",
			    hostname);
			return (pa_print(context, &uval, flag));
		}

		(void) inet_ntop(AF_INET6, (void *) ip_addr, tbuf,
		    sizeof (tbuf));

		(void) snprintf(buf, sizeof (buf), "%s", tbuf);

		return (pa_print(context, &uval, flag));
	}

}

int
pa_tid64(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	int64_t dev_maj_min;
	uint32_t	ip_addr;
	struct in_addr ia;
	char	*ipstring;
	char	buf[256];
	uval_t	uval;

	if (status <  0)
		return (status);

	if ((returnstat = pr_adr_int64(context, &dev_maj_min, 1)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_char(context, (char *)&ip_addr, 4)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	uval.string_val = buf;

	if (!(context->format & PRF_RAWM)) {
		char	hostname[256];

		get_Hname(ip_addr, hostname, sizeof (hostname));
		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_64(dev_maj_min), minor_64(dev_maj_min), hostname);
		return (pa_print(context, &uval, flag));
	}

	ia.s_addr = ip_addr;
	if ((ipstring = inet_ntoa(ia)) == NULL)
		return (-1);

	(void) snprintf(buf, sizeof (buf), "%d %d %s",
	    major_64(dev_maj_min), minor_64(dev_maj_min), ipstring);

	return (pa_print(context, &uval, flag));
}

int
pa_tid64_ex(pr_context_t *context, int status, int flag)
{
	int		returnstat;
	int64_t		dev_maj_min;
	uint32_t	ip_addr[4];
	uint32_t	ip_type;
	struct in_addr	ia;
	char		*ipstring;
	char		hostname[256];
	char		buf[256];
	char		tbuf[256];
	uval_t		uval;

	if (status <  0)
		return (status);

	/* get port info */
	if ((returnstat = pr_adr_int64(context, &dev_maj_min, 1)) != 0)
		return (returnstat);

	/* get address type */
	if ((returnstat = pr_adr_u_int32(context, &ip_type, 1)) != 0)
		return (returnstat);

	/* legal address types are either AU_IPv4 or AU_IPv6 only */
	if ((ip_type != AU_IPv4) && (ip_type != AU_IPv6))
		return (-1);

	/* get address (4/16) */
	if ((returnstat = pr_adr_char(context, (char *)&ip_addr, ip_type)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_STRING;
	if (ip_type == AU_IPv4) {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname(ip_addr[0], hostname, sizeof (hostname));
			uval.string_val = buf;
			(void) snprintf(buf, sizeof (buf), "%d %d %s",
			    major_64(dev_maj_min), minor_64(dev_maj_min),
			    hostname);
			return (pa_print(context, &uval, flag));
		}

		ia.s_addr = ip_addr[0];
		if ((ipstring = inet_ntoa(ia)) == NULL)
			return (-1);

		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_64(dev_maj_min), minor_64(dev_maj_min), ipstring);

		return (pa_print(context, &uval, flag));
	} else {
		uval.string_val = buf;

		if (!(context->format & PRF_RAWM)) {
			get_Hname_ex(ip_addr, hostname, sizeof (hostname));
			(void) snprintf(buf, sizeof (buf), "%d %d %s",
			    major_64(dev_maj_min), minor_64(dev_maj_min),
			    hostname);
			return (pa_print(context, &uval, flag));
		}

		(void) inet_ntop(AF_INET6, (void *)ip_addr, tbuf,
		    sizeof (tbuf));

		(void) snprintf(buf, sizeof (buf), "%d %d %s",
		    major_64(dev_maj_min), minor_64(dev_maj_min), tbuf);

		return (pa_print(context, &uval, flag));
	}
}


/*
 * ----------------------------------------------------------------
 * findfieldwidth:
 * Returns the field width based on the basic unit and print mode.
 * This routine is called to determine the field width for the
 * data items in the arbitrary data token where the tokens are
 * to be printed in more than one line.  The field width can be
 * found in the fwidth structure.
 *
 * Input parameters:
 * basicunit	Can be one of AUR_CHAR, AUR_BYTE, AUR_SHORT,
 *		AUR_INT32, or AUR_INT64
 * howtoprint	Print mode. Can be one of AUP_BINARY, AUP_OCTAL,
 *		AUP_DECIMAL, or AUP_HEX.
 * ----------------------------------------------------------------
 */
int
findfieldwidth(char basicunit, char howtoprint)
{
	int	i, j;

	for (i = 0; i < numwidthentries; i++) {
		if (fwidth[i].basic_unit == basicunit) {
			for (j = 0; j <= 4; j++) {
				if (fwidth[i].pwidth[j].print_base ==
				    howtoprint) {
					return (
					    fwidth[i].pwidth[j].field_width);
				}
			}
			/*
			 * if we got here, then we didn't get what we were after
			 */
			return (0);
		}
	}
	/* if we got here, we didn't get what we wanted either */
	return (0);
}


/*
 * -----------------------------------------------------------------------
 * pa_cmd: Retrieves the cmd item from the input stream.
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_cmd(pr_context_t *context, int status, int flag)
{
	char	*cmd;  /* cmd */
	short	length;
	int	returnstat;
	uval_t	uval;

	/*
	 * We need to know how much space to allocate for our string, so
	 * read the length first, then call pr_adr_char to read those bytes.
	 */
	if (status >= 0) {
		if (pr_adr_short(context, &length, 1) == 0) {
			if ((cmd = (char *)malloc(length + 1)) == NULL)
				return (-1);
			if (pr_adr_char(context, cmd, length) == 0) {
				uval.uvaltype = PRA_STRING;
				uval.string_val = cmd;
				returnstat = pa_print(context, &uval, flag);
			} else {
				returnstat = -1;
			}
			free(cmd);
			return (returnstat);
		} else
			return (-1);
	} else
		return (status);
}



/*
 * -----------------------------------------------------------------------
 * pa_adr_byte	: Issues pr_adr_char to retrieve the next ADR item from
 *		  the input stream pointed to by audit_adr, and prints it
 *		  as an integer if status >= 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_byte(pr_context_t *context, int status, int flag)
{
	char	c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_char(context, &c, 1) == 0) {
			uval.uvaltype = PRA_BYTE;
			uval.char_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_charhex: Issues pr_adr_char to retrieve the next ADR item from
 *			the input stream pointed to by audit_adr, and prints it
 *			in hexadecimal if status >= 0
 * return codes  : -1 - error
 *		 :  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_charhex(pr_context_t *context, int status, int flag)
{
	char	p[2];
	int	returnstat;
	uval_t	uval;

	if (status >= 0) {
		p[0] = p[1] = 0;

		if ((returnstat = pr_adr_char(context, p, 1)) == 0) {
			uval.uvaltype = PRA_STRING;
			uval.string_val = hexconvert(p, sizeof (char),
			    sizeof (char));
			if (uval.string_val) {
				returnstat = pa_print(context, &uval, flag);
				free(uval.string_val);
			}
		}
		return (returnstat);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_int32	: Issues pr_adr_int32 to retrieve the next ADR item from the
 *		  input stream pointed to by audit_adr, and prints it
 *		  if status >= 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_int32(pr_context_t *context, int status, int flag)
{
	int32_t	c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_int32(context, &c, 1) == 0) {
			uval.uvaltype = PRA_INT32;
			uval.int32_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}




/*
 * -----------------------------------------------------------------------
 * pa_adr_int64	: Issues pr_adr_int64 to retrieve the next ADR item from the
 *		  input stream pointed to by audit_adr, and prints it
 *		  if status >= 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_int64(pr_context_t *context, int status, int flag)
{
	int64_t	c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_int64(context, &c, 1) == 0) {
			uval.uvaltype = PRA_INT64;
			uval.int64_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_int64hex: Issues pr_adr_int64 to retrieve the next ADR item from the
 *			input stream pointed to by audit_adr, and prints it
 *			in hexadecimal if status >= 0
 * return codes  : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_int32hex(pr_context_t *context, int status, int flag)
{
	int32_t	l;
	int	returnstat;
	uval_t	uval;

	if (status >= 0) {
		if ((returnstat = pr_adr_int32(context, &l, 1)) == 0) {
			uval.uvaltype = PRA_HEX32;
			uval.int32_val = l;
			returnstat = pa_print(context, &uval, flag);
		}
		return (returnstat);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_int64hex: Issues pr_adr_int64 to retrieve the next ADR item from the
 *			input stream pointed to by audit_adr, and prints it
 *			in hexadecimal if status >= 0
 * return codes  : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_int64hex(pr_context_t *context, int status, int flag)
{
	int64_t	l;
	int	returnstat;
	uval_t	uval;

	if (status >= 0) {
		if ((returnstat = pr_adr_int64(context, &l, 1)) == 0) {
			uval.uvaltype = PRA_HEX64;
			uval.int64_val = l;
			returnstat = pa_print(context, &uval, flag);
		}
		return (returnstat);
	} else
		return (status);
}


/*
 * -------------------------------------------------------------------
 * bu2string: Maps a print basic unit type to a string.
 * returns  : The string mapping or "unknown basic unit type".
 * -------------------------------------------------------------------
 */
char *
bu2string(char basic_unit)
{
	register int	i;

	struct bu_map_ent {
		char	basic_unit;
		char	*string;
	};

	/*
	 * TRANSLATION_NOTE
	 * These names are data units when displaying the arbitrary data
	 * token.
	 */

	static struct bu_map_ent bu_map[] = {
				{ AUR_BYTE, "byte" },
				{ AUR_CHAR, "char" },
				{ AUR_SHORT, "short" },
				{ AUR_INT32, "int32" },
				{ AUR_INT64, "int64" } 	};

	for (i = 0; i < sizeof (bu_map) / sizeof (struct bu_map_ent); i++)
		if (basic_unit == bu_map[i].basic_unit)
			return (gettext(bu_map[i].string));

	return (gettext("unknown basic unit type"));
}


/*
 * -------------------------------------------------------------------
 * eventmodifier2string: Maps event modifier flags to a readable string.
 * returns: The string mapping or "none".
 * -------------------------------------------------------------------
 */
static void
eventmodifier2string(au_emod_t emodifier, char *modstring, size_t modlen)
{
	register int	i, j;

	struct em_map_ent {
		int	mask;
		char	*string;
	};

	/*
	 * TRANSLATION_NOTE
	 * These abbreviations represent the event modifier field of the
	 * header token.  To gain a better understanding of each modifier,
	 * read
	 * System Administration Guide: Security Services >> Solaris Auditing
	 * at http://docs.sun.com.
	 */

	static struct em_map_ent em_map[] = {
		{ (int)PAD_READ,	"rd" },	/* data read from object */
		{ (int)PAD_WRITE,	"wr" },	/* data written to object */
		{ (int)PAD_SPRIVUSE,	"sp" },	/* successfully used priv */
		{ (int)PAD_FPRIVUSE,	"fp" },	/* failed use of priv */
		{ (int)PAD_NONATTR,	"na" },	/* non-attributable event */
		{ (int)PAD_FAILURE,	"fe" }	/* fail audit event */
	};

	modstring[0] = '\0';

	for (i = 0, j = 0; i < sizeof (em_map) / sizeof (struct em_map_ent);
	    i++) {
		if ((int)emodifier & em_map[i].mask) {
			if (j++)
				(void) strlcat(modstring, ":", modlen);
			(void) strlcat(modstring, em_map[i].string, modlen);
		}
	}
}


/*
 * ---------------------------------------------------------
 * convert_char_to_string:
 *   Converts a byte to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		  AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		  c, which is the byte to convert
 * output	: p, which is a pointer to the location where
 *		  the resulting string is to be stored
 *  ----------------------------------------------------------
 */

int
convert_char_to_string(char printmode, char c, char *p)
{
	union {
		char	c1[4];
		int	c2;
	} dat;

	dat.c2 = 0;
	dat.c1[3] = c;

	if (printmode == AUP_BINARY)
		(void) convertbinary(p, &c, sizeof (char));
	else if (printmode == AUP_OCTAL)
		(void) sprintf(p, "%o", (int)dat.c2);
	else if (printmode == AUP_DECIMAL)
		(void) sprintf(p, "%d", c);
	else if (printmode == AUP_HEX)
		(void) sprintf(p, "0x%x", (int)dat.c2);
	else if (printmode == AUP_STRING)
		convertascii(p, &c, sizeof (char));
	return (0);
}

/*
 * --------------------------------------------------------------
 * convert_short_to_string:
 * Converts a short integer to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		c, which is the short integer to convert
 * output	: p, which is a pointer to the location where
 *		the resulting string is to be stored
 * ---------------------------------------------------------------
 */
int
convert_short_to_string(char printmode, short c, char *p)
{
	union {
		short	c1[2];
		int	c2;
	} dat;

	dat.c2 = 0;
	dat.c1[1] = c;

	if (printmode == AUP_BINARY)
		(void) convertbinary(p, (char *)&c, sizeof (short));
	else if (printmode == AUP_OCTAL)
		(void) sprintf(p, "%o", (int)dat.c2);
	else if (printmode == AUP_DECIMAL)
		(void) sprintf(p, "%hd", c);
	else if (printmode == AUP_HEX)
		(void) sprintf(p, "0x%x", (int)dat.c2);
	else if (printmode == AUP_STRING)
		convertascii(p, (char *)&c, sizeof (short));
	return (0);
}

/*
 * ---------------------------------------------------------
 * convert_int32_to_string:
 * Converts a integer to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		c, which is the integer to convert
 * output	: p, which is a pointer to the location where
 *		the resulting string is to be stored
 * ----------------------------------------------------------
 */
int
convert_int32_to_string(char printmode, int32_t c, char *p)
{
	if (printmode == AUP_BINARY)
		(void) convertbinary(p, (char *)&c, sizeof (int32_t));
	else if (printmode == AUP_OCTAL)
		(void) sprintf(p, "%o", c);
	else if (printmode == AUP_DECIMAL)
		(void) sprintf(p, "%d", c);
	else if (printmode == AUP_HEX)
		(void) sprintf(p, "0x%x", c);
	else if (printmode == AUP_STRING)
		convertascii(p, (char *)&c, sizeof (int));
	return (0);
}

/*
 * ---------------------------------------------------------
 * convert_int64_to_string:
 * Converts a integer to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		c, which is the integer to convert
 * output	: p, which is a pointer to the location where
 *		the resulting string is to be stored
 * ----------------------------------------------------------
 */
int
convert_int64_to_string(char printmode, int64_t c, char *p)
{
	if (printmode == AUP_BINARY)
		(void) convertbinary(p, (char *)&c, sizeof (int64_t));
	else if (printmode == AUP_OCTAL)
		(void) sprintf(p, "%"PRIo64, c);
	else if (printmode == AUP_DECIMAL)
		(void) sprintf(p, "%"PRId64, c);
	else if (printmode == AUP_HEX)
		(void) sprintf(p, "0x%"PRIx64, c);
	else if (printmode == AUP_STRING)
		convertascii(p, (char *)&c, sizeof (int64_t));
	return (0);
}


/*
 * -----------------------------------------------------------
 * convertbinary:
 * Converts a unit c of 'size' bytes long into a binary string
 * and returns it into the position pointed to by p
 * ------------------------------------------------------------
 */
int
convertbinary(char *p, char *c, int size)
{
	char	*s, *t, *ss;
	int	i, j;

	if ((s = (char *)malloc(8 * size + 1)) == NULL)
		return (0);

	ss = s;

	/* first convert to binary */
	t = s;
	for (i = 0; i < size; i++) {
		for (j = 0; j < 8; j++)
			(void) sprintf(t++, "%d", ((*c >> (7 - j)) & (0x01)));
		c++;
	}
	*t = '\0';

	/* now string leading zero's if any */
	j = strlen(s) - 1;
	for (i = 0; i < j; i++) {
		if (*s != '0')
			break;
			else
			s++;
	}

	/* now copy the contents of s to p */
	t = p;
	for (i = 0; i < (8 * size + 1); i++) {
		if (*s == '\0') {
			*t = '\0';
			break;
		}
		*t++ = *s++;
	}
	free(ss);

	return (1);
}


static char hex[] = "0123456789abcdef";
/*
 * -------------------------------------------------------------------
 * hexconvert	: Converts a string of (size) bytes to hexadecimal, and
 *		returns the hexadecimal string.
 * returns	: - NULL if memory cannot be allocated for the string, or
 *		- pointer to the hexadecimal string if successful
 * -------------------------------------------------------------------
 */
char *
hexconvert(char *c, int size, int chunk)
{
	register char	*s, *t;
	register int	i, j, k;
	int	numchunks;
	int	leftovers;

	if (size <= 0)
		return (NULL);

	if ((s = (char *)malloc((size * 5) + 1)) == NULL)
		return (NULL);

	if (chunk > size || chunk <= 0)
		chunk = size;

	numchunks = size / chunk;
	leftovers = size % chunk;

	t = s;
	for (i = j = 0; i < numchunks; i++) {
		if (j++) {
			*t++ = ' ';
		}
		*t++ = '0';
		*t++ = 'x';
		for (k = 0; k < chunk; k++) {
			*t++ = hex[(uint_t)((uchar_t)*c >> 4)];
			*t++ = hex[(uint_t)((uchar_t)*c & 0xF)];
			c++;
		}
	}

	if (leftovers) {
		*t++ = ' ';
		*t++ = '0';
		*t++ = 'x';
		for (i = 0; i < leftovers; i++) {
			*t++ = hex[(uint_t)((uchar_t)*c >> 4)];
			*t++ = hex[(uint_t)((uchar_t)*c & 0xF)];
			c++;
		}
	}

	*t = '\0';
	return (s);
}


/*
 * -------------------------------------------------------------------
 * htp2string: Maps a print suggestion to a string.
 * returns   : The string mapping or "unknown print suggestion".
 * -------------------------------------------------------------------
 */
char *
htp2string(char print_sugg)
{
	register int	i;

	struct htp_map_ent {
		char	print_sugg;
		char	*print_string;
	};

	/*
	 * TRANSLATION_NOTE
	 * These names are data types when displaying the arbitrary data
	 * token.
	 */

	static struct htp_map_ent htp_map[] = {
				{ AUP_BINARY, "binary" },
				{ AUP_OCTAL, "octal" },
				{ AUP_DECIMAL, "decimal" },
				{ AUP_HEX, "hexadecimal" },
				{ AUP_STRING, "string" } 	};

	for (i = 0; i < sizeof (htp_map) / sizeof (struct htp_map_ent); i++)
		if (print_sugg == htp_map[i].print_sugg)
			return (gettext(htp_map[i].print_string));

	return (gettext("unknown print suggestion"));
}

/*
 * ----------------------------------------------------------------------
 * pa_adr_short: Issues pr_adr_short to retrieve the next ADR item from the
 *		input stream pointed to by audit_adr, and prints it
 *		if status >= 0
 * return codes: -1 - error
 *		:  0 - successful
 * ----------------------------------------------------------------------
 */
int
pa_adr_short(pr_context_t *context, int status, int flag)
{
	short	c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_short(context, &c, 1) == 0) {
			uval.uvaltype = PRA_SHORT;
			uval.short_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_shorthex: Issues pr_adr_short to retrieve the next ADR item from the
 *			input stream pointed to by audit_adr, and prints it
 *			in hexadecimal if status >= 0
 * return codes  : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_shorthex(pr_context_t *context, int status, int flag)
{
	short	s;
	int	returnstat;
	uval_t	uval;

	if (status >= 0) {
		if ((returnstat = pr_adr_short(context, &s, 1)) == 0) {
			uval.uvaltype = PRA_STRING;
			uval.string_val = hexconvert((char *)&s, sizeof (s),
			    sizeof (s));
			if (uval.string_val) {
				returnstat = pa_print(context, &uval, flag);
				free(uval.string_val);
			}
		}
		return (returnstat);
	} else
		return (status);
}


/*
 * -----------------------------------------------------------------------
 * pa_adr_string: Retrieves a string from the input stream and prints it
 *		  if status >= 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_string(pr_context_t *context, int status, int flag)
{
	char	*c;
	short	length;
	int	returnstat;
	uval_t	uval;

	/*
	 * We need to know how much space to allocate for our string, so
	 * read the length first, then call pr_adr_char to read those bytes.
	 */
	if (status < 0)
		return (status);

	if ((returnstat = pr_adr_short(context, &length, 1)) != 0)
		return (returnstat);
	if ((c = (char *)malloc(length + 1)) == NULL)
		return (-1);
	if ((returnstat = pr_adr_char(context, c, length)) != 0) {
		free(c);
		return (returnstat);
	}

	uval.uvaltype = PRA_STRING;
	uval.string_val = c;
	returnstat = pa_print(context, &uval, flag);
	free(c);
	return (returnstat);
}

/*
 * -----------------------------------------------------------------------
 * pa_file_string: Retrieves a file string from the input stream and prints it
 *		  if status >= 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_file_string(pr_context_t *context, int status, int flag)
{
	char	*c;
	char	*p;
	short	length;
	int	returnstat;
	uval_t	uval;

	/*
	 * We need to know how much space to allocate for our string, so
	 * read the length first, then call pr_adr_char to read those bytes.
	 */
	if (status < 0)
		return (status);

	if ((returnstat = pr_adr_short(context, &length, 1)) != 0)
		return (returnstat);
	if ((c = (char *)malloc(length + 1)) == NULL)
		return (-1);
	if ((p = (char *)malloc((length * 4) + 1)) == NULL) {
		free(c);
		return (-1);
	}
	if ((returnstat = pr_adr_char(context, c, length)) != 0) {
		free(c);
		free(p);
		return (returnstat);
	}

	if (is_file_token(context->tokenid))
		context->audit_rec_len += length;

	convertascii(p, c, length - 1);
	uval.uvaltype = PRA_STRING;
	uval.string_val = p;

	if (returnstat == 0)
		returnstat = finish_open_tag(context);

	if (returnstat == 0)
		returnstat = pa_print(context, &uval, flag);

	free(c);
	free(p);
	return (returnstat);
}

static int
pa_putstr_xml(pr_context_t *context, int printable, char *str, size_t len)
{
	int	err;

	if (!printable) {
		/*
		 * Unprintable chars should always be converted to the
		 * visible form. If there are unprintable characters which
		 * require special treatment in xml, those should be
		 * handled here.
		 */
		do {
			err = pr_printf(context, "\\%03o",
			    (unsigned char)*str++);
		} while (err == 0 && --len != 0);
		return (err);
	}
	/* printable characters */
	if (len == 1) {
		/*
		 * check for the special chars only when char size was 1
		 * ie, ignore special chars appear in the middle of multibyte
		 * sequence.
		 */

		/* Escape for XML */
		switch (*str) {
		case '&':
			err = pr_printf(context, "%s", "&amp;");
			break;

		case '<':
			err = pr_printf(context, "%s", "&lt;");
			break;

		case '>':
			err = pr_printf(context, "%s", "&gt;");
			break;

		case '\"':
			err = pr_printf(context, "%s", "&quot;");
			break;

		case '\'':
			err = pr_printf(context, "%s", "&apos;");
			break;

		default:
			err = pr_putchar(context, *str);
			break;
		}
		return (err);
	}
	do {
		err = pr_putchar(context, *str++);
	} while (err == 0 && --len != 0);
	return (err);
}

static int
pa_putstr(pr_context_t *context, int printable, char *str, size_t len)
{
	int	err;

	if (context->format & PRF_XMLM)
		return (pa_putstr_xml(context, printable, str, len));

	if (!printable) {
		do {
			err = pr_printf(context, "\\%03o",
			    (unsigned char)*str++);
		} while (err == 0 && --len != 0);
		return (err);
	}
	do {
		err = pr_putchar(context, *str++);
	} while (err == 0 && --len != 0);
	return (err);
}

int
pa_string(pr_context_t *context, int status, int flag)
{
	int	rstat, wstat;
	int	i, printable, eos;
	int	mlen, rlen;
	int	mbmax = MB_CUR_MAX;
	wchar_t	wc;
	char	mbuf[MB_LEN_MAX + 1];
	char	c;

	if (status < 0)
		return (status);

	rstat = wstat = 0;

	if (mbmax == 1) {
		while (wstat == 0) {
			if ((rstat = pr_adr_char(context, &c, 1)) < 0)
				break;
			if (c == '\0')
				break;
			printable = isprint((unsigned char)c);
			wstat = pa_putstr(context, printable, &c, 1);
		}
		goto done;
	}

	mlen = eos = 0;
	while (wstat == 0) {
		rlen = 0;
		do {
			if (!eos) {
				rstat = pr_adr_char(context, &c, 1);
				if (rstat != 0 || c == '\0')
					eos = 1;
				else
					mbuf[mlen++] = c;
			}
			rlen = mbtowc(&wc, mbuf, mlen);
		} while (!eos && mlen < mbmax && rlen <= 0);

		if (mlen == 0)
			break;	/* end of string */

		if (rlen <= 0) { /* no good sequence */
			rlen = 1;
			printable = 0;
		} else {
			printable = iswprint(wc);
		}
		wstat = pa_putstr(context, printable, mbuf, rlen);
		mlen -= rlen;
		if (mlen > 0) {
			for (i = 0; i < mlen; i++)
				mbuf[i] = mbuf[rlen + i];
		}
	}

done:
	if (wstat == 0)
		wstat = do_newline(context, flag);

	return ((rstat != 0 || wstat != 0) ? -1 : 0);
}

/*
 * -----------------------------------------------------------------------
 * pa_adr_u_int32: Issues pr_adr_u_int32 to retrieve the next ADR item from
 *		  the input stream pointed to by audit_adr, and prints it
 *		  if status = 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */


int
pa_adr_u_int32(pr_context_t *context, int status, int flag)
{
	uint32_t c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_u_int32(context, &c, 1) == 0) {
			uval.uvaltype = PRA_UINT32;
			uval.uint32_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}



/*
 * -----------------------------------------------------------------------
 * pa_adr_u_int64: Issues pr_adr_u_int64 to retrieve the next ADR item from the
 *		  input stream pointed to by audit_adr, and prints it
 *		  if status = 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_u_int64(pr_context_t *context, int status, int flag)
{
	uint64_t c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_u_int64(context, &c, 1) == 0) {
			uval.uvaltype = PRA_UINT64;
			uval.uint64_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}


/*
 * -----------------------------------------------------------------------
 * pa_adr_u_short: Issues pr_adr_u_short to retrieve the next ADR item from
 *			the input stream pointed to by audit_adr, and prints it
 *			if status = 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_adr_u_short(pr_context_t *context, int status, int flag)
{
	ushort_t c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_u_short(context, &c, 1) == 0) {
			uval.uvaltype = PRA_USHORT;
			uval.ushort_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_reclen: Issues pr_adr_u_long to retrieve the length of the record
 *		  from the input stream pointed to by audit_adr,
 *		  and prints it (unless format is XML) if status = 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_reclen(pr_context_t *context, int status)
{
	uint32_t c;
	uval_t	uval;

	if (status >= 0) {
		if ((int)pr_adr_u_int32(context, &c, 1) == 0) {
			context->audit_rec_len = c;

			/* Don't print this for XML format */
			if (context->format & PRF_XMLM) {
				return (0);
			} else {
				uval.uvaltype = PRA_UINT32;
				uval.uint32_val = c;
				return (pa_print(context, &uval, 0));
			}
		} else
			return (-1);
	} else
		return (status);
}

/*
 * -----------------------------------------------------------------------
 * pa_mode	: Issues pr_adr_u_short to retrieve the next ADR item from
 *		the input stream pointed to by audit_adr, and prints it
 *		in octal if status = 0
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_mode(pr_context_t *context, int status, int flag)
{
	uint32_t c;
	uval_t	uval;

	if (status >= 0) {
		if (pr_adr_u_int32(context, &c, 1) == 0) {
			uval.uvaltype = PRA_LOCT;
			uval.uint32_val = c;
			return (pa_print(context, &uval, flag));
		} else
			return (-1);
	} else
		return (status);
}

static int
pa_print_uid(pr_context_t *context, uid_t uid, int status, int flag)
{
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	if (context->format & PRF_RAWM) {
		/* print in integer form */
		uval.uvaltype = PRA_INT32;
		uval.int32_val = uid;
		returnstat = pa_print(context, &uval, flag);
	} else {
		/* print in ASCII form */
		uval.uvaltype = PRA_STRING;
		uval.string_val = getname(uid);
		returnstat = pa_print(context, &uval, flag);
	}
	return (returnstat);
}


/*
 * -----------------------------------------------------------------------
 * pa_pw_uid()	: Issues pr_adr_u_int32 to reads uid from input stream
 *		pointed to by audit_adr, and displays it in either
 *		raw form or its ASCII representation, if status >= 0.
 * return codes : -1 - error
 * 		:  1 - warning, passwd entry not found
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_pw_uid(pr_context_t *context, int status, int flag)
{
	uint32_t uid;

	if (status < 0)
		return (status);

	if (pr_adr_u_int32(context, &uid, 1) != 0)
		/* cannot retrieve uid */
		return (-1);

	return (pa_print_uid(context, uid, status, flag));
}

static int
pa_print_gid(pr_context_t *context, gid_t gid, int status, int flag)
{
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	if (context->format & PRF_RAWM) {
		/* print in integer form */
		uval.uvaltype = PRA_INT32;
		uval.int32_val = gid;
		returnstat = pa_print(context, &uval, flag);
	} else {
		/* print in ASCII form */
		uval.uvaltype = PRA_STRING;
		uval.string_val = getgroup(gid);
		returnstat = pa_print(context, &uval, flag);
	}
	return (returnstat);
}


/*
 * -----------------------------------------------------------------------
 * pa_gr_uid()	: Issues pr_adr_u_int32 to reads group uid from input stream
 *			pointed to by audit_adr, and displays it in either
 *			raw form or its ASCII representation, if status >= 0.
 * return codes : -1 - error
 * 		:  1 - warning, passwd entry not found
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_gr_uid(pr_context_t *context, int status, int flag)
{
	uint32_t gid;

	if (status < 0)
		return (status);

	if (pr_adr_u_int32(context, &gid, 1) != 0)
		/* cannot retrieve gid */
		return (-1);

	return (pa_print_gid(context, gid, status, flag));
}


/*
 * -----------------------------------------------------------------------
 * pa_pw_uid_gr_gid()	: Issues pr_adr_u_int32 to reads uid or group uid
 *			from input stream
 *			pointed to by audit_adr, and displays it in either
 *			raw form or its ASCII representation, if status >= 0.
 * return codes : -1 - error
 * 		:  1 - warning, passwd entry not found
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_pw_uid_gr_gid(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	uint32_t	value;
	uval_t		uval;

	if (status < 0)
		return (status);

	/* get value of a_type */
	if ((returnstat = pr_adr_u_int32(context, &value, 1)) != 0)
		return (returnstat);

	if ((returnstat = open_tag(context, TAG_ACLTYPE)) != 0)
		return (returnstat);

	uval.uvaltype = PRA_UINT32;
	uval.uint32_val = value;
	if ((returnstat = pa_print(context, &uval, flag)) != 0)
		return (returnstat);

	if ((returnstat = close_tag(context, TAG_ACLTYPE)) != 0)
		return (returnstat);

	if ((returnstat = open_tag(context, TAG_ACLVAL)) != 0)
		return (returnstat);
	/*
	 * TRANSLATION_NOTE
	 * The "mask" and "other" strings refer to the class mask
	 * and other (or world) entries in an ACL.
	 * The "unrecognized" string refers to an unrecognized ACL
	 * entry.
	 */
	switch (value) {
		case USER_OBJ:
		case USER:
			returnstat = pa_pw_uid(context, returnstat, flag);
			break;
		case GROUP_OBJ:
		case GROUP:
			returnstat = pa_gr_uid(context, returnstat, flag);
			break;
		case CLASS_OBJ:
			returnstat = pr_adr_u_int32(context, &value, 1);
			if (returnstat != 0)
				return (returnstat);

			if (!(context->format & PRF_RAWM)) {
				uval.uvaltype = PRA_STRING;
				uval.string_val = gettext("mask");
				returnstat = pa_print(context, &uval, flag);
			} else {
				uval.uvaltype = PRA_UINT32;
				uval.uint32_val = value;
				if ((returnstat =
				    pa_print(context, &uval, flag)) != 0) {
					return (returnstat);
				}
			}
			break;
		case OTHER_OBJ:
			returnstat = pr_adr_u_int32(context, &value, 1);
			if (returnstat != 0)
				return (returnstat);

			if (!(context->format & PRF_RAWM)) {
				uval.uvaltype = PRA_STRING;
				uval.string_val = gettext("other");
				returnstat = pa_print(context, &uval, flag);
			} else {
				uval.uvaltype = PRA_UINT32;
				uval.uint32_val = value;
				if ((returnstat =
				    pa_print(context, &uval, flag)) != 0) {
					return (returnstat);
				}
			}
			break;
		default:
			returnstat = pr_adr_u_int32(context, &value, 1);
			if (returnstat != 0)
				return (returnstat);

			if (!(context->format & PRF_RAWM)) {
				uval.uvaltype = PRA_STRING;
				uval.string_val = gettext("unrecognized");
				returnstat = pa_print(context, &uval, flag);
			} else {
				uval.uvaltype = PRA_UINT32;
				uval.uint32_val = value;
				if ((returnstat =
				    pa_print(context, &uval, flag)) != 0) {
					return (returnstat);
				}
			}
	}

	if ((returnstat = close_tag(context, TAG_ACLVAL)) != 0)
		return (returnstat);

	return (returnstat);
}


/*
 * -----------------------------------------------------------------------
 * pa_event_modifier(): Issues pr_adr_u_short to retrieve the next ADR item from
 *		  the input stream pointed to by audit_adr.  This is the
 *		  event type, and is displayed in hex;
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_event_modifier(pr_context_t *context, int status,  int flag)
{
	int	returnstat;
	au_emod_t emodifier;
	uval_t	uval;
	char	modstring[64];

	if (status < 0)
		return (status);

	if ((returnstat = pr_adr_u_short(context, &emodifier, 1)) != 0)
		return (returnstat);

	/* For XML, only print when modifier is non-zero */
	if (!(context->format & PRF_XMLM) || (emodifier != 0)) {
		uval.uvaltype = PRA_STRING;

		returnstat = open_tag(context, TAG_EVMOD);

		if (returnstat >= 0) {
			if (!(context->format & PRF_RAWM)) {
				eventmodifier2string(emodifier, modstring,
				    sizeof (modstring));
				uval.string_val = modstring;
				returnstat = pa_print(context, &uval, flag);
			} else {
				uval.string_val = hexconvert((char *)&emodifier,
				    sizeof (emodifier), sizeof (emodifier));
				if (uval.string_val) {
					returnstat = pa_print(context, &uval,
					    flag);
					free(uval.string_val);
				}
			}
		}
		if (returnstat >= 0)
			returnstat = close_tag(context, TAG_EVMOD);
	}

	return (returnstat);
}


/*
 * -----------------------------------------------------------------------
 * pa_event_type(): Issues pr_adr_u_short to retrieve the next ADR item from
 *		  the input stream pointed to by audit_adr.  This is the
 *		  event type, and is displayed in either raw or
 *		  ASCII form as appropriate
 * return codes : -1 - error
 *		:  0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_event_type(pr_context_t *context, int status,  int flag)
{
	au_event_t etype;
	int	returnstat;
	au_event_ent_t *p_event = NULL;
	uval_t	uval;

	if (status >= 0) {
		if ((returnstat = pr_adr_u_short(context, &etype, 1)) == 0) {
			if (!(context->format & PRF_RAWM)) {
				uval.uvaltype = PRA_STRING;
				if (context->format & PRF_NOCACHE) {
					p_event = getauevnum(etype);
				} else {
					(void) cacheauevent(&p_event, etype);
				}
				if (p_event != NULL) {
					if (context->format & PRF_SHORTM)
						uval.string_val =
						    p_event->ae_name;
					else
						uval.string_val =
						    p_event->ae_desc;
				} else {
					uval.string_val =
					    gettext("invalid event number");
				}
				returnstat = pa_print(context, &uval, flag);
			} else {
				uval.uvaltype = PRA_USHORT;
				uval.ushort_val = etype;
				returnstat = pa_print(context, &uval, flag);
			}
		}
		return (returnstat);
	} else
		return (status);

}


/*
 * Print time from struct timeval to millisecond resolution.
 *
 *	typedef long	time_t;		time of day in seconds
 *	typedef	long	useconds_t;	signed # of microseconds
 *
 * struct timeval {
 *	time_t		tv_sec;		seconds
 *	suseconds_t	tv_usec;	and microseconds
 * };
 */

int
pa_utime32(pr_context_t *context, int status, int flag)
{
	uint32_t scale = 1000;		/* usec to msec */

	return (do_mtime32(context, status, flag, scale));
}

/*
 * Print time from timestruc_t to millisecond resolution.
 *
 *	typedef struct timespec timestruct_t;
 * struct timespec{
 *	time_t	tv_sec;		seconds
 *	long	tv_nsec;	and nanoseconds
 * };
 */
int
pa_ntime32(pr_context_t *context, int status, int flag)
{
	uint32_t scale = 1000000;	/* nsec to msec */

	return (do_mtime32(context, status, flag, scale));
}

/*
 * Format the timezone +/- HH:MM and terminate the string
 * Note tm and tv_sec are the same time.
 * Too bad strftime won't produce an ISO 8601 time zone numeric
 */

#define	MINS	(24L * 60)
static void
tzone(struct tm *tm, time_t *tv_sec, char *p)
{
	struct tm *gmt;
	int min_off;

	gmt = gmtime(tv_sec);

	min_off = ((tm->tm_hour - gmt->tm_hour) * 60) +
	    (tm->tm_min - gmt->tm_min);

	if (tm->tm_year < gmt->tm_year)		/* cross new year */
		min_off -= MINS;
	else if (tm->tm_year > gmt->tm_year)
		min_off += MINS;
	else if (tm->tm_yday < gmt->tm_yday)	/* cross dateline */
		min_off -= MINS;
	else if (tm->tm_yday > gmt->tm_yday)
		min_off += MINS;

	if (min_off < 0) {
		min_off = -min_off;
		*p++ = '-';
	} else {
		*p++ = '+';
	}

	*p++ = min_off / 600 + '0';		/* 10s of hours */
	min_off = min_off - min_off / 600 * 600;
	*p++ = min_off / 60 % 10 + '0';		/* hours */
	min_off = min_off - min_off / 60 * 60;
	*p++ = ':';
	*p++ = min_off / 10 + '0';		/* 10s of minutes */
	*p++ = min_off % 10 + '0';		/* minutes */
	*p = '\0';
}

/*
 * Format the milliseconds in place in the string.
 * Borrowed from strftime.c:itoa()
 */
static void
msec32(uint32_t msec, char *p)
{
	*p++ = msec / 100 + '0';
	msec  = msec - msec / 100 * 100;
	*p++ = msec / 10 + '0';
	*p++ = msec % 10 +'0';
}

/*
 * Format time and print relative to scale factor from micro/nano seconds.
 */
static int
do_mtime32(pr_context_t *context, int status, int flag, uint32_t scale)
{
	uint32_t t32;
	time_t tv_sec;
	struct tm tm;
	char	time_created[sizeof ("YYYY-MM-DD HH:MM:SS.sss -HH:MM")];
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	if ((returnstat = open_tag(context, TAG_ISO)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_u_int32(context,
	    (uint32_t *)&tv_sec, 1)) != 0)
		return (returnstat);
	if ((returnstat = pr_adr_u_int32(context, &t32, 1)) == 0) {
		if (!(context->format & PRF_RAWM)) {
			(void) localtime_r(&tv_sec, &tm);
			(void) strftime(time_created,
			    sizeof ("YYYY-MM-DD HH:MM:SS.xxx "),
			    "%Y-%m-%d %H:%M:%S.xxx ", &tm);
			msec32(t32/scale,
			    &time_created[sizeof ("YYYY-MM-DD HH:MM:SS.")-1]);
			tzone(&tm, &tv_sec,
			    &time_created[
			    sizeof ("YYYY-MM-DD HH:MM:SS.xxx ")-1]);
			uval.uvaltype = PRA_STRING;
			uval.string_val = time_created;
		} else {
			uval.uvaltype = PRA_UINT32;
			uval.uint32_val = (uint32_t)tv_sec;
			(void) pa_print(context, &uval, 0);
			if (context->format & PRF_XMLM) {
				uval.uvaltype = PRA_CHAR;
				uval.char_val = '.';
				(void) pa_print(context, &uval, 0);
			}
			uval.uvaltype = PRA_UINT32;
			uval.uint32_val = t32;
		}
		returnstat = pa_print(context, &uval, flag);
	}

	if (returnstat == 0)
		return (close_tag(context, TAG_ISO));
	else
		return (returnstat);
}

/*
 * Print time from struct timeval to millisecond resolution.
 *
 *	typedef long	time_t;		time of day in seconds
 *	typedef	long	useconds_t;	signed # of microseconds
 *
 * struct timeval {
 *	time_t		tv_sec;		seconds
 *	suseconds_t	tv_usec;	and microseconds
 * };
 */

int
pa_utime64(pr_context_t *context, int status, int flag)
{
	uint64_t scale = 1000;		/* usec to msec */

	return (do_mtime64(context, status, flag, scale));
}

/*
 * Print time from timestruc_t to millisecond resolution.
 *
 *	typedef struct timespec timestruct_t;
 * struct timespec{
 *	time_t	tv_sec;		seconds
 *	long	tv_nsec;	and nanoseconds
 * };
 */
int
pa_ntime64(pr_context_t *context, int status, int flag)
{
	uint64_t scale = 1000000;	/* nsec to msec */

	return (do_mtime64(context, status, flag, scale));
}

/*
 * Format the milliseconds in place in the string.
 * Borrowed from strftime.c:itoa()
 */
static void
msec64(uint64_t msec, char *p)
{
	*p++ = msec / 100 + '0';
	msec = msec - msec / 100 * 100;
	*p++ = msec / 10 + '0';
	*p++ = msec % 10 +'0';
}

/*
 * Format time and print relative to scale factor from micro/nano seconds.
 */
static int
do_mtime64(pr_context_t *context, int status, int flag, uint64_t scale)
{
	uint64_t t64_sec;
	uint64_t t64_msec;
	time_t tv_sec;
	struct tm tm;
	char	time_created[sizeof ("YYYY-MM-DD HH:MM:SS.sss -HH:MM")];
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	if ((returnstat = open_tag(context, TAG_ISO)) != 0)
		return (returnstat);

	if ((returnstat = pr_adr_u_int64(context, &t64_sec, 1)) != 0)
		return (returnstat);
	if ((returnstat = pr_adr_u_int64(context, &t64_msec, 1)) == 0) {
		if (!(context->format & PRF_RAWM)) {
#ifndef	_LP64
			/*
			 * N.B.
			 * This fails for years from 2038
			 * The Y2K+38 problem
			 */
#endif	/* !_LP64 */
			tv_sec = (time_t)t64_sec;
			(void) localtime_r(&tv_sec, &tm);
			(void) strftime(time_created,
			    sizeof ("YYYY-MM-DD HH:MM:SS.xxx "),
			    "%Y-%m-%d %H:%M:%S.xxx ", &tm);
			msec64(t64_msec/scale,
			    &time_created[sizeof ("YYYY-MM-DD HH:MM:SS.")-1]);
			tzone(&tm, &tv_sec,
			    &time_created[
			    sizeof ("YYYY-MM-DD HH:MM:SS.xxx ")-1]);
			uval.uvaltype = PRA_STRING;
			uval.string_val = time_created;
		} else {
			uval.uvaltype = PRA_UINT64;
			uval.uint64_val = t64_sec;
			(void) pa_print(context, &uval, 0);
			if (context->format & PRF_XMLM) {
				uval.uvaltype = PRA_CHAR;
				uval.char_val = '.';
				(void) pa_print(context, &uval, 0);
			}
			uval.uvaltype = PRA_UINT64;
			uval.uint64_val = t64_msec;
		}
		returnstat = pa_print(context, &uval, flag);
	}

	if (returnstat < 0)
		return (returnstat);

	return (close_tag(context, TAG_ISO));
}

/*
 * -----------------------------------------------------------------------
 * pa_error()   :  convert the return token error code.
 *
 * output	: buf string representing return token error code.
 *
 * -----------------------------------------------------------------------
 */
void
pa_error(const uchar_t err, char *buf, size_t buflen)
{
	if (err == ADT_SUCCESS) {
		(void) strlcpy(buf, gettext("success"), buflen);
	} else if ((char)err == ADT_FAILURE) {
		(void) strlcpy(buf, gettext("failure"), buflen);
	} else {
		char *emsg = strerror(err);

		if (emsg != NULL) {
			(void) strlcpy(buf, gettext("failure: "), buflen);
			(void) strlcat(buf, emsg, buflen);
		} else {
			(void) snprintf(buf, buflen, "%s%d",
			    gettext("failure: "), err);
		}
	}
}

/*
 * -----------------------------------------------------------------------
 * pa_retval()  :  convert the return token return value code.
 *
 * input	: err, for kernel success 0, or
 *			failure errno: 0 > & < sys_nerr.
 *			for userland success ADT_SUCCESS (0) or
 *			failure ADT_FAILURE (-1).
 *		pa_error() above has already converted err.
 *
 *		: retval, for kernel arbitrary return value for success, or
 *			failure: -1.
 *			for userland,
 *			>= ADT_FAIL_VALUE < ADT_FAIL_PAM, an adt message code;
 *			>= ADT_FAIL_PAM, a pam_strerror value;
 *			< ADT_FAIL_VALUE, supposed to be an errno.
 *
 * output	: buf string representing return token error code.
 *
 * -----------------------------------------------------------------------
 */
void
pa_retval(const uchar_t err, const int32_t retval, char *buf, size_t buflen)
{
	struct msg_text *msglist;
	char *emsg;

	/* success or kernel failure */
	if (((char)err == ADT_SUCCESS) ||
	    (retval < 0)) {

		(void) snprintf(buf, buflen, "%d", retval);
		return;
	}

	/* userland failure */
	msglist = &adt_msg_text[ADT_LIST_FAIL_VALUE];

	if ((retval + msglist->ml_offset >= msglist->ml_min_index) &&
	    (retval + msglist->ml_offset <= msglist->ml_max_index)) {

		(void) strlcpy(buf,
		    gettext(msglist->ml_msg_list[retval + msglist->ml_offset]),
		    buflen);
	} else if ((retval >= ADT_FAIL_PAM) &&
	    (retval < ADT_FAIL_PAM + PAM_TOTAL_ERRNUM)) {

		(void) strlcpy(buf, pam_strerror(NULL, retval - ADT_FAIL_PAM),
		    buflen);
	} else if ((emsg = strerror(retval)) != NULL) {

		(void) strlcpy(buf, emsg, buflen);
	} else {

		(void) snprintf(buf, buflen, "%d", retval);
	}
}

/*
 * -----------------------------------------------------------------------
 * pa_printstr()	:  print a given string, translating unprintables
 *			:  as needed.
 */
static int
pa_printstr(pr_context_t *context, char *str)
{
	int	err = 0;
	int	len, printable;
	int	mbmax = MB_CUR_MAX;
	wchar_t	wc;
	char	c;

	if (mbmax == 1) {
		/* fast path */
		while (err == 0 && *str != '\0') {
			c = *str++;
			printable = isprint((unsigned char)c);
			err = pa_putstr(context, printable, &c, 1);
		}
		return (err);
	}
	while (err == 0 && *str != '\0') {
		len = mbtowc(&wc, str, mbmax);
		if (len <= 0) {
			len = 1;
			printable = 0;
		} else {
			printable = iswprint(wc);
		}
		err = pa_putstr(context, printable, str, len);
		str += len;
	}
	return (err);
}

/*
 * -----------------------------------------------------------------------
 * pa_print()	:  print as one str or formatted for easy reading.
 * 		: flag - indicates whether to output a new line for
 *		: multi-line output.
 * 		:		= 0; no new line
 *		:		= 1; new line if regular output
 * output	: The audit record information is displayed in the
 *		  type specified by uvaltype and value specified in
 *		  uval.  The printing of the delimiter or newline is
 *		  determined by PRF_ONELINE, and the flag value,
 *		  as follows:
 *			+--------+------+------+-----------------+
 *			|ONELINE | flag | last | Action          |
 *			+--------+------+------+-----------------+
 *			|    Y   |   Y  |   T  | print new line  |
 *			|    Y   |   Y  |   F  | print delimiter |
 *			|    Y   |   N  |   T  | print new line  |
 *			|    Y   |   N  |   F  | print delimiter |
 *			|    N   |   Y  |   T  | print new line  |
 *			|    N   |   Y  |   F  | print new line  |
 *			|    N   |   N  |   T  | print new line  |
 *			|    N   |   N  |   F  | print delimiter |
 *			+--------+------+------+-----------------+
 *
 * return codes : -1 - error
 *		0 - successful
 * -----------------------------------------------------------------------
 */
int
pa_print(pr_context_t *context, uval_t *uval, int flag)
{
	int	returnstat = 0;
	int	last;

	switch (uval->uvaltype) {
	case PRA_INT32:
		returnstat = pr_printf(context, "%d", uval->int32_val);
		break;
	case PRA_UINT32:
		returnstat = pr_printf(context, "%u", uval->uint32_val);
		break;
	case PRA_INT64:
		returnstat = pr_printf(context, "%"PRId64, uval->int64_val);
		break;
	case PRA_UINT64:
		returnstat = pr_printf(context, "%"PRIu64, uval->uint64_val);
		break;
	case PRA_SHORT:
		returnstat = pr_printf(context, "%hd", uval->short_val);
		break;
	case PRA_USHORT:
		returnstat = pr_printf(context, "%hu", uval->ushort_val);
		break;
	case PRA_CHAR:
		returnstat = pr_printf(context, "%c", uval->char_val);
		break;
	case PRA_BYTE:
		returnstat = pr_printf(context, "%d", uval->char_val);
		break;
	case PRA_STRING:
		returnstat = pa_printstr(context, uval->string_val);
		break;
	case PRA_HEX32:
		returnstat = pr_printf(context, "0x%x", uval->int32_val);
		break;
	case PRA_HEX64:
		returnstat = pr_printf(context, "0x%"PRIx64, uval->int64_val);
		break;
	case PRA_SHEX:
		returnstat = pr_printf(context, "0x%hx", uval->short_val);
		break;
	case PRA_OCT:
		returnstat = pr_printf(context, "%ho", uval->ushort_val);
		break;
	case PRA_LOCT:
		returnstat = pr_printf(context, "%o", (int)uval->uint32_val);
		break;
	default:
		(void) fprintf(stderr, gettext("praudit: Unknown type.\n"));
		returnstat = -1;
		break;
	}
	if (returnstat < 0)
		return (returnstat);

	last = (context->audit_adr->adr_now ==
	    (context->audit_rec_start + context->audit_rec_len));

	if (!(context->format & PRF_XMLM)) {
		if (!(context->format & PRF_ONELINE)) {
			if ((flag == 1) || last)
				returnstat = pr_putchar(context, '\n');
			else
				returnstat = pr_printf(context, "%s",
				    context->SEPARATOR);
		} else {
			if (!last)
				returnstat = pr_printf(context, "%s",
				    context->SEPARATOR);
			else
				returnstat = pr_putchar(context, '\n');
		}
	}
	return (returnstat);
}

static struct cntrl_mapping {
	char from;
	char to;
} cntrl_map[] = {
	'\0', '0',
	'\a', 'a',
	'\b', 'b',
	'\t', 't',
	'\f', 'f',
	'\n', 'n',
	'\r', 'r',
	'\v', 'v'
};

static int cntrl_map_entries = sizeof (cntrl_map)
	/ sizeof (struct cntrl_mapping);

/*
 * Convert binary data to ASCII for printing.
 */
void
convertascii(char *p, char *c, int size)
{
	int	i, j, uc;

	for (i = 0; i < size; i++) {
		uc = (unsigned char)*(c + i);
		if (isascii(uc)) {
			if (iscntrl(uc)) {
				for (j = 0; j < cntrl_map_entries; j++) {
					if (cntrl_map[j].from == uc) {
						*p++ = '\\';
						*p++ = cntrl_map[j].to;
						break;
					}
				}
				if (j == cntrl_map_entries) {
					*p++ = '^';
					*p++ = (char)(uc ^ 0100);
				}
			} else {
				*p++ = (char)uc;
			}
		} else {
			p += sprintf(p, "\\%03o", uc);
		}
	}
	*p = '\0';
}

/*
 * -----------------------------------------------------------------------
 * pa_xgeneric: Process Xobject token and display contents
 *		      This routine will handle many of the attribute
 *		      types introduced in TS 2.x, such as:
 *
 *		      AUT_XCOLORMAP, AUT_XCURSOR, AUT_XFONT,
 *		      AUT_XGC, AUT_XPIXMAP, AUT_XWINDOW
 *
 * NOTE: At the time of call, the token id has been retrieved
 *
 * return codes		: -1 - error
 *			:  0 - successful
 * NOTE: At the time of call, the xatom token id has been retrieved
 *
 * Format of xobj
 *	text token id		adr_char
 * 	XID 			adr_u_int32
 * 	creator uid		adr_pw_uid
 * -----------------------------------------------------------------------
 */
int
pa_xgeneric(pr_context_t *context)
{
	int	returnstat;

	returnstat = process_tag(context, TAG_XID, 0, 0);
	return (process_tag(context, TAG_XCUID, returnstat, 1));
}


/*
 * ------------------------------------------------------------------------
 * pa_liaison : Issues pr_adr_char to retrieve the next ADR item from the
 *			input stream pointed to by audit_adr, and prints it
 *			if status >= 0 either in ASCII or raw form
 * return codes : -1 - error
 *		: 0 - successful
 *		: 1 - warning, unknown label type
 * -----------------------------------------------------------------------
 */
int
pa_liaison(pr_context_t *context, int status, int flag)
{
	int	returnstat;
	int32_t	li;
	uval_t	uval;

	if (status >= 0) {
		if ((returnstat = pr_adr_int32(context, &li, 1)) != 0) {
			return (returnstat);
		}
		if (!(context->format & PRF_RAWM)) {
			uval.uvaltype = PRA_UINT32;
			uval.uint32_val = li;
			returnstat = pa_print(context, &uval, flag);
		}
		/* print in hexadecimal form */
		if ((context->format & PRF_RAWM) || (returnstat == 1)) {
			uval.uvaltype = PRA_HEX32;
			uval.uint32_val = li;
			returnstat = pa_print(context, &uval, flag);
		}
		return (returnstat);
	} else
		return (status);
}

/*
 * ------------------------------------------------------------------------
 * pa_xid : Issues pr_adr_int32 to retrieve the XID from the input
 *	      stream pointed to by audit_adr, and prints it if
 *	      status >= 0 either in ASCII or raw form
 * return codes : -1 - error
 *		:  0 - successful
 *		:  1 - warning, unknown label type
 * ------------------------------------------------------------------------
 */

int
pa_xid(pr_context_t *context, int status, int flag)
{
	int returnstat;
	int32_t xid;
	uval_t	uval;

	if (status < 0)
		return (status);

	/* get XID from stream */
	if ((returnstat = pr_adr_int32(context, (int32_t *)&xid, 1)) != 0)
		return (returnstat);

	if (!(context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_STRING;
		uval.string_val = hexconvert((char *)&xid, sizeof (xid),
		    sizeof (xid));
		if (uval.string_val) {
			returnstat = pa_print(context, &uval, flag);
			free(uval.string_val);
		}
	} else {
		uval.uvaltype = PRA_INT32;
		uval.int32_val = xid;
		returnstat = pa_print(context, &uval, flag);
	}

	return (returnstat);
}

static int
pa_ace_flags(pr_context_t *context, ace_t *ace, int status, int flag)
{
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	/*
	 * TRANSLATION_NOTE
	 * ace->a_flags refers to access flags of ZFS/NFSv4 ACL entry.
	 */
	if ((returnstat = open_tag(context, TAG_ACEFLAGS)) != 0)
		return (returnstat);
	if (!(context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_STRING;
		switch (ace->a_flags & ACE_TYPE_FLAGS) {
		case ACE_OWNER:
			uval.string_val = gettext(OWNERAT_TXT);
			break;
		case ACE_GROUP | ACE_IDENTIFIER_GROUP:
			uval.string_val = gettext(GROUPAT_TXT);
			break;
		case ACE_IDENTIFIER_GROUP:
			uval.string_val = gettext(GROUP_TXT);
			break;
		case ACE_EVERYONE:
			uval.string_val = gettext(EVERYONEAT_TXT);
			break;
		case 0:
			uval.string_val = gettext(USER_TXT);
			break;
		default:
			uval.uvaltype = PRA_USHORT;
			uval.uint32_val = ace->a_flags;
		}
	} else {
		uval.uvaltype = PRA_USHORT;
		uval.uint32_val = ace->a_flags;
	}
	if ((returnstat = pa_print(context, &uval, flag)) != 0)
		return (returnstat);
	return (close_tag(context, TAG_ACEFLAGS));
}

static int
pa_ace_who(pr_context_t *context, ace_t *ace, int status, int flag)
{
	int		returnstat;

	if (status < 0)
		return (status);

	/*
	 * TRANSLATION_NOTE
	 * ace->a_who refers to user id or group id of ZFS/NFSv4 ACL entry.
	 */
	if ((returnstat = open_tag(context, TAG_ACEID)) != 0)
		return (returnstat);
	switch (ace->a_flags & ACE_TYPE_FLAGS) {
	case ACE_IDENTIFIER_GROUP:	/* group id */
		returnstat = pa_print_gid(context, ace->a_who, returnstat,
		    flag);
		break;
	default:			/* user id */
		returnstat = pa_print_uid(context, ace->a_who, returnstat,
		    flag);
		break;
	}
	if (returnstat < 0)
		return (returnstat);
	return (close_tag(context, TAG_ACEID));
}

/*
 * Appends what to str, (re)allocating str if necessary.
 */
#define	INITIAL_ALLOC	256
static int
strappend(char **str, char *what, size_t *alloc)
{
	char	*s, *newstr;
	size_t	needed;

	s = *str;

	if (s == NULL) {
		s = malloc(INITIAL_ALLOC);
		if (s == NULL) {
			*alloc = 0;
			return (-1);
		}
		*alloc = INITIAL_ALLOC;
		s[0] = '\0';
		*str = s;
	}

	needed = strlen(s) + strlen(what) + 1;
	if (*alloc < needed) {
		newstr = realloc(s, needed);
		if (newstr == NULL)
			return (-1);
		s = newstr;
		*alloc = needed;
		*str = s;
	}
	(void) strlcat(s, what, *alloc);

	return (0);
}

static int
pa_ace_access_mask(pr_context_t *context, ace_t *ace, int status, int flag)
{
	int	returnstat, i;
	uval_t	uval;
	char	*permstr = NULL;
	size_t	permstr_alloc = 0;

	if (status < 0)
		return (status);

	/*
	 * TRANSLATION_NOTE
	 * ace->a_access_mask refers to access mask of ZFS/NFSv4 ACL entry.
	 */
	if ((returnstat = open_tag(context, TAG_ACEMASK)) != 0)
		return (returnstat);
	if (context->format & PRF_SHORTM &&
	    ((permstr = malloc(15)) != NULL)) {
		for (i = 0; i < 14; i++)
			permstr[i] = '-';

		if (ace->a_access_mask & ACE_READ_DATA)
			permstr[0] = 'r';
		if (ace->a_access_mask & ACE_WRITE_DATA)
			permstr[1] = 'w';
		if (ace->a_access_mask & ACE_EXECUTE)
			permstr[2] = 'x';
		if (ace->a_access_mask & ACE_APPEND_DATA)
			permstr[3] = 'p';
		if (ace->a_access_mask & ACE_DELETE)
			permstr[4] = 'd';
		if (ace->a_access_mask & ACE_DELETE_CHILD)
			permstr[5] = 'D';
		if (ace->a_access_mask & ACE_READ_ATTRIBUTES)
			permstr[6] = 'a';
		if (ace->a_access_mask & ACE_WRITE_ATTRIBUTES)
			permstr[7] = 'A';
		if (ace->a_access_mask & ACE_READ_NAMED_ATTRS)
			permstr[8] = 'R';
		if (ace->a_access_mask & ACE_WRITE_NAMED_ATTRS)
			permstr[9] = 'W';
		if (ace->a_access_mask & ACE_READ_ACL)
			permstr[10] = 'c';
		if (ace->a_access_mask & ACE_WRITE_ACL)
			permstr[11] = 'C';
		if (ace->a_access_mask & ACE_WRITE_OWNER)
			permstr[12] = 'o';
		if (ace->a_access_mask & ACE_SYNCHRONIZE)
			permstr[13] = 's';
		permstr[14] = '\0';
		uval.uvaltype = PRA_STRING;
		uval.string_val = permstr;
	} else if (!(context->format & PRF_RAWM)) {

		/*
		 * Note this differs from acltext.c:ace_perm_txt()
		 * because we don't know if the acl belongs to a file
		 * or directory. ace mask value are the same
		 * nonetheless, see sys/acl.h
		 */
		if (ace->a_access_mask & ACE_LIST_DIRECTORY) {
			returnstat = strappend(&permstr, gettext(READ_DIR_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_ADD_FILE) {
			returnstat = strappend(&permstr, gettext(ADD_FILE_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_ADD_SUBDIRECTORY) {
			returnstat = strappend(&permstr, gettext(ADD_DIR_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_READ_NAMED_ATTRS) {
			returnstat = strappend(&permstr,
			    gettext(READ_XATTR_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_WRITE_NAMED_ATTRS) {
			returnstat = strappend(&permstr,
			    gettext(WRITE_XATTR_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_EXECUTE) {
			returnstat = strappend(&permstr,
			    gettext(EXECUTE_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_DELETE_CHILD) {
			returnstat = strappend(&permstr,
			    gettext(DELETE_CHILD_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_READ_ATTRIBUTES) {
			returnstat = strappend(&permstr,
			    gettext(READ_ATTRIBUTES_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_WRITE_ATTRIBUTES) {
			returnstat = strappend(&permstr,
			    gettext(WRITE_ATTRIBUTES_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_DELETE) {
			returnstat = strappend(&permstr, gettext(DELETE_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_READ_ACL) {
			returnstat = strappend(&permstr, gettext(READ_ACL_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_WRITE_ACL) {
			returnstat = strappend(&permstr, gettext(WRITE_ACL_TXT),
			    &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_WRITE_OWNER) {
			returnstat = strappend(&permstr,
			    gettext(WRITE_OWNER_TXT), &permstr_alloc);
		}
		if (ace->a_access_mask & ACE_SYNCHRONIZE) {
			returnstat = strappend(&permstr,
			    gettext(SYNCHRONIZE_TXT), &permstr_alloc);
		}
		if (permstr[strlen(permstr) - 1] == '/')
			permstr[strlen(permstr) - 1] = '\0';
		uval.uvaltype = PRA_STRING;
		uval.string_val = permstr;
	}
	if ((permstr == NULL) || (returnstat != 0) ||
	    (context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_UINT32;
		uval.uint32_val = ace->a_access_mask;
	}
	returnstat = pa_print(context, &uval, flag);

	if (permstr != NULL)
		free(permstr);
	if (returnstat != 0)
		return (returnstat);
	return (close_tag(context, TAG_ACEMASK));
}

static int
pa_ace_type(pr_context_t *context, ace_t *ace, int status, int flag)
{
	int	returnstat;
	uval_t	uval;

	if (status < 0)
		return (status);

	/*
	 * TRANSLATION_NOTE
	 * ace->a_type refers to access type of ZFS/NFSv4 ACL entry.
	 */
	if ((returnstat = open_tag(context, TAG_ACETYPE)) != 0)
		return (returnstat);
	if (!(context->format & PRF_RAWM)) {
		uval.uvaltype = PRA_STRING;
		switch (ace->a_type) {
		case ACE_ACCESS_ALLOWED_ACE_TYPE:
			uval.string_val = gettext(ALLOW_TXT);
			break;
		case ACE_ACCESS_DENIED_ACE_TYPE:
			uval.string_val = gettext(DENY_TXT);
			break;
		case ACE_SYSTEM_AUDIT_ACE_TYPE:
			uval.string_val = gettext(AUDIT_TXT);
			break;
		case ACE_SYSTEM_ALARM_ACE_TYPE:
			uval.string_val = gettext(ALARM_TXT);
			break;
		default:
			uval.string_val = gettext(UNKNOWN_TXT);
		}
	} else {
		uval.uvaltype = PRA_USHORT;
		uval.uint32_val = ace->a_type;
	}
	if ((returnstat = pa_print(context, &uval, flag)) != 0)
		return (returnstat);
	return (close_tag(context, TAG_ACETYPE));
}

int
pa_ace(pr_context_t *context, int status, int flag)
{
	int		returnstat;
	ace_t		ace;

	if (status < 0)
		return (status);

	if ((returnstat = pr_adr_u_int32(context, &ace.a_who, 1)) != 0)
		return (returnstat);
	if ((returnstat = pr_adr_u_int32(context, &ace.a_access_mask, 1)) != 0)
		return (returnstat);
	if ((returnstat = pr_adr_u_short(context, &ace.a_flags, 1)) != 0)
		return (returnstat);
	if ((returnstat = pr_adr_u_short(context, &ace.a_type, 1)) != 0)
		return (returnstat);

	if ((returnstat = pa_ace_flags(context, &ace, returnstat, 0)) != 0)
		return (returnstat);
	/* pa_ace_who can returns 1 if uid/gid is not found */
	if ((returnstat = pa_ace_who(context, &ace, returnstat, 0)) < 0)
		return (returnstat);
	if ((returnstat = pa_ace_access_mask(context, &ace,
	    returnstat, 0)) != 0)
		return (returnstat);
	return (pa_ace_type(context, &ace, returnstat, flag));
}
