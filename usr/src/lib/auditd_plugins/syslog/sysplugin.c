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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * convert binary audit records to syslog messages and
 * send them off to syslog
 *
 */

/*
 * auditd_plugin_open(), auditd_plugin() and auditd_plugin_close()
 * implement a replacable library for use by auditd; they are a
 * project private interface and may change without notice.
 *
 */
#define	DEBUG	0
#if DEBUG
#define	DPRINT(x) {fprintf x; }
#else
#define	DPRINT(x)
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libintl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <security/auditd.h>

#include "toktable.h"
#include "sysplugin.h"
#include "systoken.h"
#include <audit_plugin.h>

#if DEBUG
static FILE	*dbfp;			/* debug file */
#endif

extern void init_tokens();
extern int parse_token(parse_context_t *);

static au_mask_t	mask;
static int		initialized = 0;
static size_t		maxavail;
static pthread_mutex_t	log_mutex;

#define	ELLIPSIS	"..."
#define	ELLIPSIS_SIZE	(sizeof (ELLIPSIS) - 1)

/*
 * simple hashing for uid and hostname lookup
 *
 * performance tests showed that cacheing the hostname, uid, and gid
 * make about a 40% difference for short audit records and regularly
 * repeating hostname, uid, etc
 *
 * ht_type and ht_ip are only used for hostname lookup cacheing.
 */
typedef struct hashtable {
	uint32_t	ht_key;
	uint32_t	ht_type;
	uint32_t	ht_ip[4];
	char		*ht_value;
	size_t		ht_length;
} hashtable_t;
#define	HOSTHASHSIZE	128
#define	UIDHASHSIZE	128
#define	GIDHASHSIZE	32

static hashtable_t	uidhash[UIDHASHSIZE];
static hashtable_t	gidhash[GIDHASHSIZE];
static hashtable_t	hosthash[HOSTHASHSIZE];

#define	STRCONSTARGS(s)	(s), (sizeof (s) - 1)
/*
 * the hash "handles" collisions by overwriting the old
 * hash entry with the new.  Perfection is not the goal.
 *
 * the key (s) is a 32 bit integer, handled here as
 * four bytes.  If the hash size is increased beyond
 * 256, this macro will need some work.
 */
#define	HASH(s,  r, m)	{\
				uint32_t	_mush = 0;\
				int		_i;\
				for (_i = 0; _i < 4; _i++) {\
					_mush ^= *(s)++;\
				}\
				r = _mush % m;\
			}


/*
 * The default mask for sysplugin is to reject all record types.
 * The parameters input here select which classes to allow.
 *
 * getauditflgsbin() outputs error messages to syslog.
 *
 * caller must hold log_mutex
 */

static auditd_rc_t
setmask(const char *flags)
{
	au_mask_t tmask;
	char	*input, *ip, c;
	auditd_rc_t	rc = AUDITD_SUCCESS;

	mask.am_success = 0x0;
	mask.am_failure = 0x0;

	if (flags != NULL) {
		/*
		 * getauditflagsbin doesn't like blanks, but admins do
		 */
		input = malloc(strlen(flags) + 1);
		if (input == NULL)
			return (AUDITD_NO_MEMORY);

		ip = input;

		for (; (c = *flags) != '\0'; flags++) {
			if (c == ' ')
				continue;
			*ip++ = c;
		}
		*ip = '\0';
		if (getauditflagsbin(input, &tmask) == 0) {
			mask.am_success |= tmask.am_success;
			mask.am_failure |= tmask.am_failure;
		}
	}
	if ((mask.am_success | mask.am_failure) == 0) {
		rc = AUDITD_INVALID;
		__audit_syslog("audit_syslog.so", LOG_CONS | LOG_NDELAY,
		    LOG_DAEMON, LOG_ERR,
		    gettext("plugin is configured with empty class mask\n"));
	}
	free(input);
	return (rc);
}

/*
 * based on the current value of mask, either keep or toss the
 * current audit record.  The input is 1 for success, -1 for
 * failure.  0 means no exit or return token was seen.
 *
 * au_preselect returns 1 for keep it, 0 for delete it, and
 * -1 for some sort of error.  Here, 1 and -1 are considered
 * equivalent.  tossit() returns 1 for delete it and 0 for
 * keep it.
 */

static int
tossit(au_event_t id, int passfail)
{
	int	rc;
	int	selFlag;

	switch (passfail) {
	case 1:
		selFlag = AU_PRS_SUCCESS;
		break;
	case -1:
		selFlag = AU_PRS_FAILURE;
		break;
	default:		/* no exit or return token */
		selFlag = AU_PRS_BOTH;
		break;
	}
	(void) pthread_mutex_lock(&log_mutex);
	rc = au_preselect(id, &mask, selFlag, AU_PRS_USECACHE);
	(void) pthread_mutex_unlock(&log_mutex);

	return (rc == 0);
}

/*
 * the three bytes for ellipsis could potentially be longer than the
 * space available for text if maxavail is within two bytes of
 * OUTPUT_BUF_SIZE, which can happen if the hostname is one or two
 * characters long.  If there isn't room for ellipsis, there isn't
 * room for the data, so it is simply dropped.
 */

static size_t
fromleft(char *p, size_t avail, char *attrname, size_t attrlen, char *txt,
	size_t txtlen)
{
	size_t	len;

	if (avail < attrlen + ELLIPSIS_SIZE)
		return (0);

	(void) memcpy(p, attrname, attrlen);
	p += attrlen;
	avail -= attrlen;
	if (txtlen > avail) {
		(void) memcpy(p, ELLIPSIS, ELLIPSIS_SIZE);
		txt += txtlen - (avail - ELLIPSIS_SIZE);
		(void) memcpy(p + ELLIPSIS_SIZE, txt, avail - ELLIPSIS_SIZE);
		len = attrlen + avail;
		p += avail;
	} else {
		(void) memcpy(p, txt, txtlen);
		len = attrlen + txtlen;
		p += txtlen;
	}
	*p = '\0';
	return (len);
}

static size_t
fromright(char *p, size_t avail, char *attrname, size_t attrlen, char *txt,
	size_t txtlen)
{
	size_t	len;

	if (avail < attrlen + ELLIPSIS_SIZE)
		return (0);

	(void) memcpy(p, attrname, attrlen);
	p += attrlen;
	avail -= attrlen;
	if (txtlen > avail) {
		(void) memcpy(p, txt, avail - ELLIPSIS_SIZE);
		(void) memcpy(p + (avail - ELLIPSIS_SIZE),
		    ELLIPSIS, ELLIPSIS_SIZE);
		len = attrlen + avail;
		p += avail;
	} else {
		(void) memcpy(p, txt, txtlen);
		p += txtlen;
		len = attrlen + txtlen;
	}
	*p = '\0';
	return (len);
}

static int
init_hash(hashtable_t *table, int bad_key, int table_length,
    size_t max_value)
{
	int	i;

	for (i = 0; i < table_length; i++) {
		table[i].ht_value = malloc(max_value + 1);
		table[i].ht_key = bad_key;
		table[i].ht_length = 0;
		if (table[i].ht_value == NULL) {
			int	j;
			for (j = 0; j < i; j++)
				free(table[j].ht_value);
			return (-1);
		}
		*(table[i].ht_value) = '\0';
	}
	return (0);
}

static void
free_hash(hashtable_t *table, int table_length)
{
	int	i;

	for (i = 0; i < table_length; i++) {
		free(table[i].ht_value);
	}
}


/*
 * do IP -> hostname lookup
 */
#define	UNKNOWN		"unknown"
#define	UNKNOWN_LEN	(sizeof (UNKNOWN))

static size_t
gethname(au_tid_addr_t *tid, char *p, size_t max, char *prefix,
    size_t prefix_len)
{
	size_t			len, l;
	struct hostent		*host;
	int			rc;
	int			af;
	int			ix;
	char			*hash_key;
	uint32_t		key;
	int			match;

	if (prefix_len > max)
		return (0);

	(void) memcpy(p, prefix, prefix_len);
	p += prefix_len;
	max -= prefix_len;

	if (tid->at_type == AU_IPv6) {
		key = tid->at_addr[0] ^
			tid->at_addr[1] ^
			tid->at_addr[2] ^
			tid->at_addr[3];
	} else
		key = (tid->at_addr[0]);

	hash_key = (char *)&key;

	HASH(hash_key, ix, HOSTHASHSIZE);

	match = 0;

	if (key == 0) {
		l = UNKNOWN_LEN;	/* includes end of string */
		if (l > max)
			l = max;
		len = prefix_len + strlcpy(p, UNKNOWN, l);
		return (len);
	}

	if (tid->at_type == AU_IPv6) {
		if ((key == hosthash[ix].ht_key) &&
		    (hosthash[ix].ht_type == tid->at_type)) {
			int i;
			match = 1;
			for (i = 0; i < 4; i++) {
				if (hosthash[ix].ht_ip[i] != tid->at_addr[i]) {
					match = 0;
					break;
				}
			}
		}
	} else if (key == hosthash[ix].ht_key) {
		match = 1;
	}
	if (!match) {
		hosthash[ix].ht_key = key;
		hosthash[ix].ht_type = tid->at_type;

		if (tid->at_type == AU_IPv4) {
			hosthash[ix].ht_ip[0] = tid->at_addr[0];
			af = AF_INET;
		} else {
			(void) memcpy((char *)hosthash[ix].ht_ip,
			    (char *)tid->at_addr, AU_IPv6);
			af = AF_INET6;
		}
		host = getipnodebyaddr((const void *)tid->at_addr,
		    tid->at_type, af, &rc);

		if (host == NULL) {
			(void) inet_ntop(af, (void *)tid->at_addr,
			    hosthash[ix].ht_value, MAXHOSTNAMELEN);
			hosthash[ix].ht_length = strlen(hosthash[ix].ht_value);
		} else {
			hosthash[ix].ht_length = strlcpy(hosthash[ix].ht_value,
			    host->h_name,  MAXHOSTNAMELEN);
			freehostent(host);
		}
	}
	l = hosthash[ix].ht_length + 1;
	if (l > max)
		l = max;

	len = prefix_len + strlcpy(p, hosthash[ix].ht_value, l);

	return (len);
}
/*
 * the appropriate buffer length for getpwuid_r() isn't documented;
 * 1024 should be enough.
 */
#define	GETPWUID_BUFF_LEN	1024
#define	USERNAMELEN		256
#define	GIDNAMELEN		256

static size_t
getuname(uid_t uid, gid_t gid, char *p, size_t max, char *prefix,
    size_t prefix_len)
{
	struct passwd		pw;
	char			pw_buf[GETPWUID_BUFF_LEN];
	size_t			len, l;
	struct group		gr;
	int			ix;
	char			*hash_key;

	if (prefix_len > max)
		return (0);

	len = prefix_len;

	(void) memcpy(p, prefix, len);
	p += len;
	max -= len;

	hash_key = (char *)&uid;

	HASH(hash_key, ix, UIDHASHSIZE);

	if (uid != uidhash[ix].ht_key) {
		uidhash[ix].ht_key = uid;

		if ((getpwuid_r(uid, &pw, pw_buf, GETPWUID_BUFF_LEN)) == NULL)
			l = snprintf(uidhash[ix].ht_value, USERNAMELEN,
			    "%d", uid);
		else
			l = strlcpy(uidhash[ix].ht_value, pw.pw_name,
			    USERNAMELEN);

		uidhash[ix].ht_length = l;
	}
	l = uidhash[ix].ht_length + 1;
	if (l > max)
		l = max;
	(void) memcpy(p, uidhash[ix].ht_value, l);
	len += l - 1;

	if (gid != (gid_t)-2) {
		p += l - 1;
		max -= l - 1;
		if (max < 2)
			return (len);

		hash_key = (char *)&gid;
		HASH(hash_key, ix, GIDHASHSIZE);

		if (gid != gidhash[ix].ht_key) {
			gidhash[ix].ht_key = gid;

			if (getgrgid_r(gid, &gr,  pw_buf, GETPWUID_BUFF_LEN) ==
			    NULL)
				gidhash[ix].ht_length =
				    snprintf(gidhash[ix].ht_value, GIDNAMELEN,
					"%d", gid);
			else
				gidhash[ix].ht_length =
				    strlcpy(gidhash[ix].ht_value,
				    gr.gr_name, GIDNAMELEN);
		}
		*p++ = ':';
		len++;
		max--;

		l = gidhash[ix].ht_length + 1;
		if (l > max)
			l = max;
		(void) memcpy(p, gidhash[ix].ht_value, l);
		len += l - 1;
	}
	return (len);
}

/*
 * filter() parse input; toss if not wanted.
 *
 * the input value sequence is a number generated when the buffer
 * was queued.  ctx.out.sf_sequence, if not -1, is the sequence number
 * generated in c2audit.  It is not part of the "official" syslog
 * output but is included if DEBUG is on.
 */
#define	EVENT_NAME_LEN	32

static auditd_rc_t
filter(const char *input, uint32_t sequence, char *output,
    size_t in_len, size_t out_len)
{
	parse_context_t		ctx;
	char			*bp;
	auditd_rc_t		rc = AUDITD_SUCCESS;
	auditd_rc_t		rc_ret = AUDITD_SUCCESS;
	size_t			used, remaining;
	char			*last_adr; /* infinite loop check */
	int			token_count = 0;
	int			parse_rc;

	static parse_context_t	initial_ctx;
	static int		first = 1;

	if (first) {
		first = 0;

		/*
		 * Any member or submember of parse_context_t which utilizes
		 * allocated memory must free() the memory after calling
		 * parse_token() for both the preselected and non-preselected
		 * cases.
		 * New additions to parse_context_t or its submembers need to
		 * have this same treatment.
		 */
		initial_ctx.out.sf_eventid = 0;
		initial_ctx.out.sf_reclen = 0;
		initial_ctx.out.sf_pass = 0;
		initial_ctx.out.sf_asid = 0;
		initial_ctx.out.sf_auid = (uid_t)-2;
		initial_ctx.out.sf_euid = (uid_t)-2;
		initial_ctx.out.sf_egid = (gid_t)-2;
		initial_ctx.out.sf_tid.at_type = 0;
		initial_ctx.out.sf_pauid = (uid_t)-2;
		initial_ctx.out.sf_peuid = (uid_t)2;
		initial_ctx.out.sf_uauthlen = 0;
		initial_ctx.out.sf_uauth = NULL;
		initial_ctx.out.sf_pathlen = 0;
		initial_ctx.out.sf_path = NULL;
		initial_ctx.out.sf_atpathlen = 0;
		initial_ctx.out.sf_atpath = NULL;
		initial_ctx.out.sf_textlen = 0;
		initial_ctx.out.sf_text = NULL;
		initial_ctx.out.sf_sequence = -1;
		initial_ctx.out.sf_zonelen = 0;
		initial_ctx.out.sf_zonename = NULL;

		init_tokens();		/* cmd/praudit/toktable.c */
	}
	(void) memcpy(&ctx, &initial_ctx, sizeof (parse_context_t));
	ctx.id = sequence;
	ctx.adr.adr_stream = (char *)input;
	ctx.adr.adr_now = (char *)input;

	last_adr = NULL;
	while ((ctx.adr.adr_now - ctx.adr.adr_stream) < in_len) {
		assert(last_adr != ctx.adr.adr_now);
		token_count++;
		last_adr = ctx.adr.adr_now;
		if ((parse_rc = parse_token(&ctx)) != 0) {
			char	message[256];
			au_event_ent_t	*event;
			char	event_name[EVENT_NAME_LEN];
			char	sequence_str[EVENT_NAME_LEN];

			if (cacheauevent(&event, ctx.out.sf_eventid) < 0)
				(void) snprintf(event_name, EVENT_NAME_LEN,
				    "%hu", ctx.out.sf_eventid);
			else
				(void) strlcpy(event_name, event->ae_desc,
				    EVENT_NAME_LEN);

			if (token_count < 2)
				/* leave rc_ret unchanged */
				rc = AUDITD_INVALID;

			if (ctx.out.sf_sequence != -1)
				(void) snprintf(sequence_str, EVENT_NAME_LEN,
				    " (seq=%u) ", ctx.out.sf_sequence);
			else
				sequence_str[0] = '\0';

			(void) snprintf(message, 256,
			    gettext("error before token %d (previous token=%d)"
			    " of record type %s%s\n"),
			    token_count, parse_rc, event_name, sequence_str);

			DPRINT((dbfp, message));

			__audit_syslog("audit_syslog.so",
			    LOG_PID | LOG_ODELAY | LOG_CONS,
			    LOG_DAEMON, LOG_ALERT, message);
			break;
		}
	}
	if (rc == AUDITD_SUCCESS) {
		if (tossit(ctx.out.sf_eventid, ctx.out.sf_pass)) {
#if DEBUG
			if (ctx.out.sf_sequence != -1)
				fprintf(dbfp,
				    "syslog tossed (event=%hu) record %u "
				    "/ buffer %u\n",
				    ctx.out.sf_eventid, ctx.out.sf_sequence,
				    sequence);
			else
				fprintf(dbfp,
				    "syslog tossed (event=%hu) buffer %u\n",
				    ctx.out.sf_eventid, sequence);
#endif

			/*
			 * Members or submembers of parse_context_t which
			 * utilize allocated memory need to free() the memory
			 * here to handle the case of not being preselected as
			 * well as below for when the event is preselected.
			 * New additions to parse_context_t or any of its
			 * submembers need to get the same treatment.
			 */
			if (ctx.out.sf_uauthlen > 0) {
				free(ctx.out.sf_uauth);
				ctx.out.sf_uauth = NULL;
				ctx.out.sf_uauthlen = 0;
			}
			if (ctx.out.sf_pathlen > 0) {
				free(ctx.out.sf_path);
				ctx.out.sf_path = NULL;
				ctx.out.sf_pathlen = 0;
			}
			if (ctx.out.sf_atpathlen > 0) {
				free(ctx.out.sf_atpath);
				ctx.out.sf_atpath = NULL;
				ctx.out.sf_atpathlen = 0;
			}
			if (ctx.out.sf_textlen > 0) {
				free(ctx.out.sf_text);
				ctx.out.sf_text = NULL;
				ctx.out.sf_textlen = 0;
			}
			if (ctx.out.sf_zonelen > 0) {
				free(ctx.out.sf_zonename);
				ctx.out.sf_zonename = NULL;
				ctx.out.sf_zonelen = 0;
			}

			return (-1);	/* tell caller it was tossed */
		}
		bp = output;
		remaining = out_len;

		if (ctx.out.sf_eventid != 0) {
			au_event_ent_t	*event;

			if (cacheauevent(&event, ctx.out.sf_eventid) < 0)
				used = snprintf(bp, remaining, "%hu",
				    ctx.out.sf_eventid);
			else
				used = strlcpy(bp, event->ae_desc, remaining);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_pass != 0) {
			if (ctx.out.sf_pass < 0)
				used = strlcpy(bp, " failed", remaining);
			else
				used = strlcpy(bp, " ok", remaining);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_asid != 0) {
			used = snprintf(bp, remaining, " session %u",
			    ctx.out.sf_asid);
			remaining -= used;
			bp += used;
		}
		if (ctx.out.sf_auid != (uid_t)-2) {
			used = getuname(ctx.out.sf_auid, -2, bp, remaining,
			    STRCONSTARGS(" by "));
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_euid != (uid_t)-2) {
			/* 4 = strlen(" as ") */
			used = getuname(ctx.out.sf_euid, ctx.out.sf_egid, bp,
			    remaining, STRCONSTARGS(" as "));
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_zonename != NULL) {
			used = fromright(bp, remaining,
			    STRCONSTARGS(" in "),
			    ctx.out.sf_zonename, ctx.out.sf_zonelen);
			free(ctx.out.sf_zonename);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_tid.at_type != 0) {
			/* 6 = strlen(" from ") */
			used = gethname(&(ctx.out.sf_tid), bp, remaining,
			    STRCONSTARGS(" from "));
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_pauid != (uid_t)-2) {
			/* 11 = strlen(" proc_auid ") */
			used = getuname(ctx.out.sf_pauid, -2, bp, remaining,
			    STRCONSTARGS(" proc_auid "));
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_peuid != (uid_t)-2) {
			used = getuname(ctx.out.sf_peuid, -2, bp, remaining,
			    STRCONSTARGS(" proc_uid "));
			bp += used;
			remaining -= used;
		}
#if DEBUG
		/*
		 * with performance testing, this has the effect of
		 * making that each message is unique, so syslogd
		 * won't collect a series of messages as "last message
		 * repeated n times," another reason why DEBUG 0
		 * should perform better than DEBUG 1.  However the
		 * intention is to help debug lost data problems
		 */
		if (ctx.out.sf_sequence != -1) {
			fprintf(dbfp,
			    "syslog writing record %u / buffer %u\n",
			    ctx.out.sf_sequence, sequence);
			used = snprintf(bp, remaining, "  seq %u",
			    ctx.out.sf_sequence, sequence);
			remaining -= used;
			bp += used;
		} else
			fprintf(dbfp, "syslog writing buffer %u\n", sequence);
#endif
		/*
		 * Long fields that may need truncation go here in
		 * order of decreasing priority.  Paths are truncated
		 * from the left, text from the right.
		 */
		if (ctx.out.sf_path != NULL) {
			used = fromleft(bp, remaining, STRCONSTARGS(" obj "),
			    ctx.out.sf_path, ctx.out.sf_pathlen);
			free(ctx.out.sf_path);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_atpath != NULL) {
			used = fromleft(bp, remaining,
			    STRCONSTARGS(" attr_obj "),
			    ctx.out.sf_atpath, ctx.out.sf_atpathlen);
			free(ctx.out.sf_atpath);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_uauth != NULL) {
			used = fromright(bp, remaining, STRCONSTARGS(" uauth "),
			    ctx.out.sf_uauth, ctx.out.sf_uauthlen);
			free(ctx.out.sf_path);
			bp += used;
			remaining -= used;
		}
		if (ctx.out.sf_text != NULL) {
			used = fromright(bp, remaining,
			    STRCONSTARGS(AU_TEXT_NAME),
			    ctx.out.sf_text, ctx.out.sf_textlen);
			free(ctx.out.sf_text);
			bp += used;
			remaining -= used;
		}
	}
	return (rc_ret);
}

/*
 * 1024 is max syslog record size, 48 is minimum header length,
 * assuming a hostname length of 0.  maxavail reduces use of the
 * allocated space by the length of the hostname (see maxavail)
 */
#define	OUTPUT_BUF_SIZE	1024 - 48

/* ARGSUSED */
auditd_rc_t
auditd_plugin(const char *input, size_t in_len, uint32_t sequence, char **error)
{
	char		*outbuf;
	auditd_rc_t	rc = AUDITD_SUCCESS;
#if DEBUG
	static	uint32_t	last_sequence = 0;
	static	uint32_t	write_count = 0;
	static	uint32_t	toss_count = 0;

	if ((last_sequence > 0) && (sequence != last_sequence + 1))
		fprintf(dbfp, "syslog: buffer sequence=%d but prev=%d\n",
				sequence, last_sequence);
	last_sequence = sequence;
#endif

	*error = NULL;

	outbuf = malloc(OUTPUT_BUF_SIZE);
	if (outbuf == NULL) {
		DPRINT((dbfp, "syslog: out of memory; seq=%u\n",
		    sequence));
		rc = AUDITD_NO_MEMORY;
		*error = strdup(gettext("Can't allocate buffers"));
	} else {
		rc = filter(input, sequence, outbuf, in_len, maxavail);

		if (rc == AUDITD_SUCCESS) {
			__audit_syslog("audit", LOG_NDELAY,
			    LOG_AUDIT, LOG_NOTICE, outbuf);
			DPRINT((dbfp, "syslog: write_count=%u, "
			    "buffer=%u, tossed=%d\n",
			    ++write_count, sequence, toss_count));
		} else if (rc > 0) {	/* -1 == discard it */
			DPRINT((dbfp, "syslog: parse failed for buffer %u\n",
			    sequence));
			*error = strdup(gettext(
			    "Unable to parse audit record"));
		} else {
			DPRINT((dbfp, "syslog: rc = %d (-1 is discard), "
			    "sequence=%u, toss_count=%d\n",
			    rc, sequence, ++toss_count));
			rc = 0;
		}
		free(outbuf);
	}
	return (rc);
}

auditd_rc_t
auditd_plugin_open(const kva_t *kvlist, char **ret_list, char **error)
{
	char		localname[MAXHOSTNAMELEN + 1];
	auditd_rc_t	rc;
	char		*value;
	/* kva_match doesn't do const, so copy the pointer */
	kva_t		*kva = (kva_t *)kvlist;

	*error = NULL;
	*ret_list = NULL;

	if ((kvlist == NULL) || ((value = kva_match(kva, "p_flags")) == NULL)) {
		*error = strdup(gettext(
		    "The \"p_flags\" attribute is missing."));
		return (AUDITD_INVALID);
	}
	if (!initialized) {
#if DEBUG
		dbfp = __auditd_debug_file_open();
#endif
		initialized = 1;
		(void) pthread_mutex_init(&log_mutex, NULL);
		/*
		 * calculate length of the local hostname for adjusting the
		 * estimate of how much space is taken by the syslog header.
		 * If the local hostname isn't available, leave some room
		 * anyway.  (The -2 is for the blanks on either side of the
		 * hostname in the syslog message.)
		 */
		(void) pthread_mutex_lock(&log_mutex);
		if (gethostname(localname, MAXHOSTNAMELEN))
			maxavail = OUTPUT_BUF_SIZE - 20;
		else
			maxavail = OUTPUT_BUF_SIZE - strlen(localname) - 2;
		(void) pthread_mutex_unlock(&log_mutex);

		if (init_hash(hosthash, 0, HOSTHASHSIZE, MAXHOSTNAMELEN))
			return (AUDITD_NO_MEMORY);

		if (init_hash(uidhash, -2, UIDHASHSIZE, USERNAMELEN))
			return (AUDITD_NO_MEMORY);

		if (init_hash(gidhash, -2, GIDHASHSIZE, GIDNAMELEN))
			return (AUDITD_NO_MEMORY);
	}
	(void) pthread_mutex_lock(&log_mutex);
	if ((rc = setmask(value)) != AUDITD_SUCCESS)
		*error = strdup(gettext(
		    "incorrect p_flags setting; no records will be output"));

	(void) pthread_mutex_unlock(&log_mutex);

	return (rc);
}

auditd_rc_t
auditd_plugin_close(char **error)
{
	*error = NULL;

	if (initialized) {
		(void) pthread_mutex_destroy(&log_mutex);

		free_hash(hosthash, HOSTHASHSIZE);
		free_hash(uidhash, UIDHASHSIZE);
		free_hash(gidhash, GIDHASHSIZE);
	}
	initialized = 0;

	return (AUDITD_SUCCESS);
}
