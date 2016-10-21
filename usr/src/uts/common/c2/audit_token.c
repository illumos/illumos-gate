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
 */

/*
 * Support routines for building audit records.
 */

#include <sys/param.h>
#include <sys/systm.h>		/* for rval */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/user.h>
#include <sys/session.h>
#include <sys/acl.h>
#include <sys/ipc_impl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>
#include <sys/model.h>		/* for model_t */
#include <sys/vmparam.h>	/* for USRSTACK/USRSTACK32 */
#include <sys/vfs.h>		/* for sonode */
#include <sys/socketvar.h>	/* for sonode */
#include <sys/zone.h>
#include <sys/tsol/label.h>

/*
 * These are the control tokens
 */

/*
 * au_to_header
 * returns:
 *	pointer to au_membuf chain containing a header token.
 */
token_t *
au_to_header(int byte_count, au_event_t e_type, au_emod_t e_mod)
{
	adr_t adr;			/* adr memory stream header */
	token_t *m;			/* au_membuf pointer */
#ifdef _LP64
	char data_header = AUT_HEADER64;	/* header for this token */
	static int64_t zerotime[2];
#else
	char data_header = AUT_HEADER32;
	static int32_t zerotime[2];
#endif
	char version = TOKEN_VERSION;	/* version of token family */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);	/* token ID */
	adr_int32(&adr, (int32_t *)&byte_count, 1);	/* length of */
							/* audit record */
	adr_char(&adr, &version, 1);		/* version of audit tokens */
	adr_ushort(&adr, &e_type, 1);		/* event ID */
	adr_ushort(&adr, &e_mod, 1);		/* event ID modifier */
#ifdef _LP64
	adr_int64(&adr, zerotime, 2);		/* time & date space */
#else
	adr_int32(&adr, zerotime, 2);
#endif
	m->len = adr_count(&adr);

	return (m);
}

token_t *
au_to_header_ex(int byte_count, au_event_t e_type, au_emod_t e_mod)
{
	adr_t adr;			/* adr memory stream header */
	token_t *m;			/* au_membuf pointer */
	au_kcontext_t	*kctx = GET_KCTX_PZ;

#ifdef _LP64
	char data_header = AUT_HEADER64_EX;	/* header for this token */
	static int64_t zerotime[2];
#else
	char data_header = AUT_HEADER32_EX;
	static int32_t zerotime[2];
#endif
	char version = TOKEN_VERSION;	/* version of token family */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);	/* token ID */
	adr_int32(&adr, (int32_t *)&byte_count, 1);	/* length of */
							/* audit record */
	adr_char(&adr, &version, 1);		/* version of audit tokens */
	adr_ushort(&adr, &e_type, 1);		/* event ID */
	adr_ushort(&adr, &e_mod, 1);		/* event ID modifier */
	adr_uint32(&adr, &kctx->auk_info.ai_termid.at_type, 1);
	adr_char(&adr, (char *)&kctx->auk_info.ai_termid.at_addr[0],
	    (int)kctx->auk_info.ai_termid.at_type);
#ifdef _LP64
	adr_int64(&adr, zerotime, 2);		/* time & date */
#else
	adr_int32(&adr, zerotime, 2);
#endif
	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_trailer
 * returns:
 *	pointer to au_membuf chain containing a trailer token.
 */
token_t *
au_to_trailer(int byte_count)
{
	adr_t adr;				/* adr memory stream header */
	token_t *m;				/* au_membuf pointer */
	char data_header = AUT_TRAILER;		/* header for this token */
	short magic = (short)AUT_TRAILER_MAGIC; /* trailer magic number */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);		/* token ID */
	adr_short(&adr, &magic, 1);			/* magic number */
	adr_int32(&adr, (int32_t *)&byte_count, 1);	/* length of */
							/* audit record */

	m->len = adr_count(&adr);

	return (m);
}
/*
 * These are the data tokens
 */

/*
 * au_to_data
 * returns:
 *	pointer to au_membuf chain containing a data token.
 */
token_t *
au_to_data(char unit_print, char unit_type, char unit_count, char *p)
{
	adr_t adr;			/* adr memory stream header */
	token_t *m;			/* au_membuf pointer */
	char data_header = AUT_DATA;	/* header for this token */

	ASSERT(p != NULL);
	ASSERT(unit_count != 0);

	switch (unit_type) {
	case AUR_SHORT:
		if (sizeof (short) * unit_count >= AU_BUFSIZE)
			return (au_to_text("au_to_data: unit count too big"));
		break;
	case AUR_INT32:
		if (sizeof (int32_t) * unit_count >= AU_BUFSIZE)
			return (au_to_text("au_to_data: unit count too big"));
		break;
	case AUR_INT64:
		if (sizeof (int64_t) * unit_count >= AU_BUFSIZE)
			return (au_to_text("au_to_data: unit count too big"));
		break;
	case AUR_BYTE:
	default:
#ifdef _CHAR_IS_UNSIGNED
		if (sizeof (char) * unit_count >= AU_BUFSIZE)
			return (au_to_text("au_to_data: unit count too big"));
#endif
		/*
		 * we used to check for this:
		 * sizeof (char) * (int)unit_count >= AU_BUFSIZE).
		 * but the compiler is smart enough to see that
		 * will never be >= AU_BUFSIZE, since that's 128
		 * and unit_count maxes out at 127 (signed char),
		 * and complain.
		 */
		break;
	}

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &unit_print, 1);
	adr_char(&adr, &unit_type, 1);
	adr_char(&adr, &unit_count, 1);

	switch (unit_type) {
	case AUR_SHORT:
		adr_short(&adr, (short *)p, unit_count);
		break;
	case AUR_INT32:
		adr_int32(&adr, (int32_t *)p, unit_count);
		break;
	case AUR_INT64:
		adr_int64(&adr, (int64_t *)p, unit_count);
		break;
	case AUR_BYTE:
	default:
		adr_char(&adr, p, unit_count);
		break;
	}

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_process
 * au_to_subject
 * returns:
 *	pointer to au_membuf chain containing a process token.
 */
static token_t *au_to_any_process(char, uid_t, gid_t, uid_t, gid_t,
    pid_t, au_id_t, au_asid_t, const au_tid_addr_t *atid);

token_t *
au_to_process(uid_t uid, gid_t gid, uid_t ruid, gid_t rgid, pid_t pid,
    au_id_t auid, au_asid_t asid, const au_tid_addr_t *atid)
{
	char data_header;

#ifdef _LP64
	if (atid->at_type == AU_IPv6)
		data_header = AUT_PROCESS64_EX;
	else
		data_header = AUT_PROCESS64;
#else
	if (atid->at_type == AU_IPv6)
		data_header = AUT_PROCESS32_EX;
	else
		data_header = AUT_PROCESS32;
#endif

	return (au_to_any_process(data_header, uid, gid, ruid,
	    rgid, pid, auid, asid, atid));
}

token_t *
au_to_subject(uid_t uid, gid_t gid, uid_t ruid, gid_t rgid, pid_t pid,
    au_id_t auid, au_asid_t asid, const au_tid_addr_t *atid)
{
	char data_header;

#ifdef _LP64
	if (atid->at_type == AU_IPv6)
		data_header = AUT_SUBJECT64_EX;
	else
		data_header = AUT_SUBJECT64;
#else
	if (atid->at_type == AU_IPv6)
		data_header = AUT_SUBJECT32_EX;
	else
		data_header = AUT_SUBJECT32;
#endif
	return (au_to_any_process(data_header, uid, gid, ruid,
	    rgid, pid, auid, asid, atid));
}


static token_t *
au_to_any_process(char data_header,
    uid_t uid, gid_t gid, uid_t ruid, gid_t rgid, pid_t pid,
    au_id_t auid, au_asid_t asid, const au_tid_addr_t *atid)
{
	token_t *m;	/* local au_membuf */
	adr_t adr;	/* adr memory stream header */
	int32_t value;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	value = (int32_t)auid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)uid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)gid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)ruid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)rgid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)pid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)asid;
	adr_int32(&adr, &value, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&(atid->at_port), 1);
#else
	adr_int32(&adr, (int32_t *)&(atid->at_port), 1);
#endif
	if (atid->at_type == AU_IPv6) {
		adr_uint32(&adr, (uint_t *)&atid->at_type, 1);
		adr_char(&adr, (char *)&atid->at_addr[0], 16);
	} else {
		adr_char(&adr, (char *)&(atid->at_addr[0]), 4);
	}

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_text
 * returns:
 *	pointer to au_membuf chain containing a text token.
 */
token_t *
au_to_text(const char *text)
{
	token_t *token;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_TEXT;	/* header for this token */
	short bytes;			/* length of string */

	token = au_getclr();

	bytes = (short)strlen(text) + 1;
	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);

	token->len = (char)adr_count(&adr);
	/*
	 * Now attach the text
	 */
	(void) au_append_buf(text, bytes, token);

	return (token);
}

/*
 * au_zonename_length
 * returns:
 * -	length of zonename token to be generated
 * -	zone name up to ZONENAME_MAX + 1 in length
 */
#define	ZONE_TOKEN_OVERHEAD 3
	/*
	 * the zone token is
	 * token id (1 byte)
	 * string length (2 bytes)
	 * the string (strlen(zonename) + 1)
	 */
size_t
au_zonename_length(zone_t *zone)
{
	if (zone == NULL)
		zone = curproc->p_zone;
	return (strlen(zone->zone_name) + 1 +
	    ZONE_TOKEN_OVERHEAD);
}

/*
 * au_to_zonename
 *
 * A length of zero input to au_to_zonename means the length is not
 * pre-calculated.
 *
 * The caller is responsible for checking the AUDIT_ZONENAME policy
 * before calling au_zonename_length() and au_to_zonename().  If
 * the policy changes between the calls, no harm is done, so the
 * policy only needs to be checked once.
 *
 * returns:
 *	pointer to au_membuf chain containing a zonename token; NULL if
 *	policy is off.
 *
 *	if the zonename token is generated at token generation close time,
 *	the length of the token is already known and it is ASSERTed that
 *	it has not changed.  If not precalculated, zone_length must be
 *	zero.
 */
token_t *
au_to_zonename(size_t zone_length, zone_t *zone)
{
	token_t *token;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ZONENAME;	/* header for this token */
	short bytes;			/* length of string */

	token = au_getclr();

	if (zone == NULL)
		zone = curproc->p_zone;
	bytes = (short)strlen(zone->zone_name) + 1;
	/*
	 * If zone_length != 0, it was precalculated and is
	 * the token length, not the string length.
	 */
	ASSERT((zone_length == 0) ||
	    (zone_length == (bytes + ZONE_TOKEN_OVERHEAD)));

	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);

	token->len = (char)adr_count(&adr);
	(void) au_append_buf(zone->zone_name, bytes, token);

	return (token);
}

/*
 * au_to_strings
 * returns:
 *	pointer to au_membuf chain containing a strings array token.
 */
token_t *
au_to_strings(
	char header,		/* token type */
	const char *kstrp,	/* kernel string pointer */
	ssize_t count)		/* count of arguments */
{
	token_t *token;			/* local au_membuf */
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	size_t len;
	int32_t tlen;

	token = au_getclr();

	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &header, 1);
	tlen = (int32_t)count;
	adr_int32(&adr, &tlen, 1);

	token->len = (char)adr_count(&adr);

	while (count-- > 0) {
		m = au_getclr();
		len = strlen(kstrp) + 1;
		(void) au_append_buf(kstrp, len, m);
		(void) au_append_rec((token_t *)token, (token_t *)m, AU_PACK);
		kstrp += len;
	}

	return (token);
}

/*
 * au_to_exec_args
 * returns:
 *	pointer to au_membuf chain containing a argv token.
 */
token_t *
au_to_exec_args(const char *kstrp, ssize_t argc)
{
	return (au_to_strings(AUT_EXEC_ARGS, kstrp, argc));
}

/*
 * au_to_exec_env
 * returns:
 *	pointer to au_membuf chain containing a arge token.
 */
token_t *
au_to_exec_env(const char *kstrp, ssize_t envc)
{
	return (au_to_strings(AUT_EXEC_ENV, kstrp, envc));
}

/*
 * au_to_arg32
 *	char   n;	argument # being used
 *	char  *text;	text describing argument
 *	uint32_t v;	argument value
 * returns:
 *	pointer to au_membuf chain containing an argument token.
 */
token_t *
au_to_arg32(char n, char *text, uint32_t v)
{
	token_t *token;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ARG32;	/* header for this token */
	short bytes;			/* length of string */

	token = au_getclr();

	bytes = strlen(text) + 1;
	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);	/* token type */
	adr_char(&adr, &n, 1);			/* argument id */
	adr_uint32(&adr, &v, 1);		/* argument value */
	adr_short(&adr, &bytes, 1);

	token->len = adr_count(&adr);
	/*
	 * Now add the description
	 */
	(void) au_append_buf(text, bytes, token);

	return (token);
}


/*
 * au_to_arg64
 *	char		n;	argument # being used
 *	char		*text;	text describing argument
 *	uint64_t	v;	argument value
 * returns:
 *	pointer to au_membuf chain containing an argument token.
 */
token_t *
au_to_arg64(char n, char *text, uint64_t v)
{
	token_t *token;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ARG64;	/* header for this token */
	short bytes;			/* length of string */

	token = au_getclr();

	bytes = strlen(text) + 1;
	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);	/* token type */
	adr_char(&adr, &n, 1);			/* argument id */
	adr_uint64(&adr, &v, 1);		/* argument value */
	adr_short(&adr, &bytes, 1);

	token->len = adr_count(&adr);
	/*
	 * Now the description
	 */
	(void) au_append_buf(text, bytes, token);

	return (token);
}


/*
 * au_to_path
 * returns:
 *	pointer to au_membuf chain containing a path token.
 */
token_t *
au_to_path(struct audit_path *app)
{
	token_t *token;			/* local au_membuf */
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_PATH;	/* header for this token */
	short bytes;			/* length of string */
	char *path = app->audp_sect[0];

	bytes = (short)(app->audp_sect[1] - app->audp_sect[0]);

	/*
	 * generate path token header
	 */
	m = au_getclr();
	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	m->len = adr_count(&adr);

	/* append path string */
	token = m;
	(void) au_append_buf(path, bytes, token);

	if (app->audp_cnt > 1) {
		/* generate attribute path strings token */
		m = au_to_strings(AUT_XATPATH, app->audp_sect[1],
		    app->audp_cnt - 1);

		token = au_append_token(token, m);
	}

	return (token);
}

/*
 * au_to_ipc
 * returns:
 *	pointer to au_membuf chain containing a System V IPC token.
 */
token_t *
au_to_ipc(char type, int id)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IPC;	/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &type, 1);		/* type of IPC object */
	adr_int32(&adr, (int32_t *)&id, 1);

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_return32
 * returns:
 *	pointer to au_membuf chain containing a return value token.
 */
token_t *
au_to_return32(int error, int32_t rv)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_RETURN32; /* header for this token */
	int32_t val;
	char ed = error;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &ed, 1);

	if (error) {
		val = -1;
		adr_int32(&adr, &val, 1);
	} else {
		adr_int32(&adr, &rv, 1);
	}
	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_return64
 * returns:
 *	pointer to au_membuf chain containing a return value token.
 */
token_t *
au_to_return64(int error, int64_t rv)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_RETURN64; /* header for this token */
	int64_t val;
	char ed = error;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &ed, 1);

	if (error) {
		val = -1;
		adr_int64(&adr, &val, 1);
	} else {
		adr_int64(&adr, &rv, 1);
	}
	m->len = adr_count(&adr);

	return (m);
}

#ifdef	AU_MAY_USE_SOMEDAY
/*
 * au_to_opaque
 * returns:
 *	pointer to au_membuf chain containing a opaque token.
 */
token_t *
au_to_opaque(short bytes, char *opaque)
{
	token_t *token;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_OPAQUE;	/* header for this token */

	token = au_getclr();

	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);

	token->len = adr_count(&adr);

	/*
	 * Now attach the data
	 */
	(void) au_append_buf(opaque, bytes, token);

	return (token);
}
#endif	/* AU_MAY_USE_SOMEDAY */

/*
 * au_to_ip
 * returns:
 *	pointer to au_membuf chain containing a ip header token
 */
token_t *
au_to_ip(struct ip *ipp)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IP;	/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, (char *)ipp, 2);
	adr_short(&adr, (short *)&(ipp->ip_len), 3);
	adr_char(&adr, (char *)&(ipp->ip_ttl), 2);
	adr_short(&adr, (short *)&(ipp->ip_sum), 1);
	adr_int32(&adr, (int32_t *)&(ipp->ip_src), 2);

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_iport
 * returns:
 *	pointer to au_membuf chain containing a ip path token
 */
token_t *
au_to_iport(ushort_t iport)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IPORT;	/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_ushort(&adr, &iport, 1);

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_in_addr
 * returns:
 *	pointer to au_membuf chain containing a ip path token
 */
token_t *
au_to_in_addr(struct in_addr *internet_addr)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IN_ADDR;	/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, (char *)internet_addr, sizeof (struct in_addr));

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_in_addr_ex
 * returns:
 *	pointer to au_membuf chain containing an ipv6 token
 */
token_t *
au_to_in_addr_ex(int32_t *internet_addr)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header_v4 = AUT_IN_ADDR;	/* header for v4 token */
	char data_header_v6 = AUT_IN_ADDR_EX;	/* header for v6 token */
	int32_t type = AU_IPv6;

	m = au_getclr();
	adr_start(&adr, memtod(m, char *));

	if (IN6_IS_ADDR_V4MAPPED((in6_addr_t *)internet_addr)) {
		ipaddr_t in4;

		/*
		 * An IPv4-mapped IPv6 address is really an IPv4 address
		 * in IPv6 format.
		 */
		IN6_V4MAPPED_TO_IPADDR((in6_addr_t *)internet_addr, in4);

		adr_char(&adr, &data_header_v4, 1);
		adr_char(&adr, (char *)&in4, sizeof (ipaddr_t));
	} else {
		adr_char(&adr, &data_header_v6, 1);
		adr_int32(&adr, &type, 1);
		adr_char(&adr, (char *)internet_addr, sizeof (struct in6_addr));
	}

	m->len = adr_count(&adr);

	return (m);
}

/*
 * The Modifier tokens
 */

/*
 * au_to_attr
 * returns:
 *	pointer to au_membuf chain containing an attribute token.
 */
token_t *
au_to_attr(struct vattr *attr)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
#ifdef _LP64
	char data_header = AUT_ATTR64;	/* header for this token */
#else
	char data_header = AUT_ATTR32;
#endif
	int32_t value;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	value = (int32_t)attr->va_mode;
	value |= (int32_t)(VTTOIF(attr->va_type));
	adr_int32(&adr, &value, 1);
	value = (int32_t)attr->va_uid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)attr->va_gid;
	adr_int32(&adr, &value, 1);
	adr_int32(&adr, (int32_t *)&(attr->va_fsid), 1);
	adr_int64(&adr, (int64_t *)&(attr->va_nodeid), 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&(attr->va_rdev), 1);
#else
	adr_int32(&adr, (int32_t *)&(attr->va_rdev), 1);
#endif

	m->len = adr_count(&adr);

	return (m);
}

token_t *
au_to_acl(struct acl *aclp)
{
	token_t *m;				/* local au_membuf */
	adr_t adr;				/* adr memory stream header */
	char data_header = AUT_ACL;		/* header for this token */
	int32_t value;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);

	value = (int32_t)aclp->a_type;
	adr_int32(&adr, &value, 1);
	value = (int32_t)aclp->a_id;
	adr_int32(&adr, &value, 1);
	value = (int32_t)aclp->a_perm;
	adr_int32(&adr, &value, 1);

	m->len = adr_count(&adr);
	return (m);
}

token_t *
au_to_ace(ace_t *acep)
{
	token_t *m;				/* local au_membuf */
	adr_t adr;				/* adr memory stream header */
	char data_header = AUT_ACE;		/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);

	adr_uint32(&adr, &(acep->a_who), 1);
	adr_uint32(&adr, &(acep->a_access_mask), 1);
	adr_ushort(&adr, &(acep->a_flags), 1);
	adr_ushort(&adr, &(acep->a_type), 1);

	m->len = adr_count(&adr);
	return (m);
}

/*
 * au_to_ipc_perm
 * returns:
 *	pointer to au_membuf chain containing a System V IPC attribute token.
 */
token_t *
au_to_ipc_perm(struct kipc_perm *perm)
{
	token_t *m;				/* local au_membuf */
	adr_t adr;				/* adr memory stream header */
	char data_header = AUT_IPC_PERM;	/* header for this token */
	int32_t value;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	value = (int32_t)perm->ipc_uid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)perm->ipc_gid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)perm->ipc_cuid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)perm->ipc_cgid;
	adr_int32(&adr, &value, 1);
	value = (int32_t)perm->ipc_mode;
	adr_int32(&adr, &value, 1);
	value = 0;			/* seq is now obsolete */
	adr_int32(&adr, &value, 1);
	value = (int32_t)perm->ipc_key;
	adr_int32(&adr, &value, 1);

	m->len = adr_count(&adr);

	return (m);
}

token_t *
au_to_groups(const gid_t *crgroups, uint_t crngroups)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_NEWGROUPS;	/* header for this token */
	short n_groups;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	n_groups = (short)crngroups;
	adr_short(&adr, &n_groups, 1);
	adr_int32(&adr, (int32_t *)crgroups, (int)crngroups);

	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_socket_ex
 * returns:
 *	pointer to au_membuf chain containing a socket token.
 */
token_t *
au_to_socket_ex(short dom, short type, char *l, char *f)
{
	adr_t adr;
	token_t *m;
	char data_header = AUT_SOCKET_EX;
	struct sockaddr_in6 *addr6;
	struct sockaddr_in  *addr4;
	short size;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &dom, 1);		/* dom of socket */
	adr_short(&adr, &type, 1);		/* type of socket */

	if (dom == AF_INET6) {
		size = AU_IPv6;
		adr_short(&adr, &size, 1);	/* type of addresses */
		addr6 = (struct sockaddr_in6 *)l;
		adr_short(&adr, (short *)&addr6->sin6_port, 1);
		adr_char(&adr, (char *)&addr6->sin6_addr, size);
		addr6 = (struct sockaddr_in6 *)f;
		adr_short(&adr, (short *)&addr6->sin6_port, 1);
		adr_char(&adr, (char *)&addr6->sin6_addr, size);
	} else if (dom == AF_INET) {
		size = AU_IPv4;
		adr_short(&adr, &size, 1);	/* type of addresses */
		addr4 = (struct sockaddr_in *)l;
		adr_short(&adr, (short *)&addr4->sin_port, 1);
		adr_char(&adr, (char *)&addr4->sin_addr, size);
		addr4 = (struct sockaddr_in *)f;
		adr_short(&adr, (short *)&addr4->sin_port, 1);
		adr_char(&adr, (char *)&addr4->sin_addr, size);
	}


	m->len = adr_count(&adr);

	return (m);
}

/*
 * au_to_seq
 * returns:
 *	pointer to au_membuf chain containing a sequence token.
 */
token_t *
au_to_seq()
{
	adr_t adr;
	token_t *m;
	char data_header = AUT_SEQ;
	static int32_t zerocount;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));

	adr_char(&adr, &data_header, 1);

	adr_int32(&adr, &zerocount, 1);

	m->len = adr_count(&adr);

	return (m);
}

token_t *
au_to_sock_inet(struct sockaddr_in *s_inet)
{
	adr_t adr;
	token_t *m;
	char data_header = AUT_SOCKET;

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, (short *)&s_inet->sin_family, 1);
	adr_short(&adr, (short *)&s_inet->sin_port, 1);

	/* remote addr */
	adr_int32(&adr, (int32_t *)&s_inet->sin_addr.s_addr, 1);

	m->len = (uchar_t)adr_count(&adr);

	return (m);
}

extern int maxprivbytes;

token_t *
au_to_privset(
    const char *set,
    const priv_set_t *pset,
    char data_header,
    int success)
{
	token_t *token, *m;
	adr_t adr;
	int priv;
	const char *pname;
	char sf = (char)success;
	char *buf, *q;
	short sz;
	boolean_t full;

	token = au_getclr();

	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);
	/*
	 * set is not used for AUT_UPRIV and sf (== success) is not
	 * used for AUT_PRIV
	 */
	if (data_header == AUT_UPRIV) {
		adr_char(&adr, &sf, 1);
	} else {
		sz = strlen(set) + 1;
		adr_short(&adr, &sz, 1);

		token->len = (uchar_t)adr_count(&adr);
		m = au_getclr();

		(void) au_append_buf(set, sz, m);
		(void) au_append_rec(token, m, AU_PACK);
		adr.adr_now += sz;
	}

	full = priv_isfullset(pset);

	if (full) {
		buf = "ALL";
		sz = strlen(buf) + 1;
	} else {
		q = buf = kmem_alloc(maxprivbytes, KM_SLEEP);
		*buf = '\0';

		for (priv = 0; (pname = priv_getbynum(priv)) != NULL; priv++) {
			if (priv_ismember(pset, priv)) {
				if (q != buf)
					*q++ = ',';
				(void) strcpy(q, pname);
				q += strlen(q);
			}
		}
		sz = (q - buf) + 1;
	}

	adr_short(&adr, &sz, 1);
	token->len = (uchar_t)adr_count(&adr);

	m = au_getclr();
	(void) au_append_buf(buf, sz, m);
	(void) au_append_rec(token, m, AU_PACK);

	if (!full)
		kmem_free(buf, maxprivbytes);

	return (token);
}

token_t *
au_to_secflags(const char *which, secflagset_t set)
{
	token_t *token, *m;
	adr_t adr;
	char data_header = AUT_SECFLAGS;
	short sz;
	char secstr[1024];

	token = au_getclr();

	adr_start(&adr, memtod(token, char *));
	adr_char(&adr, &data_header, 1);

	sz = strlen(which) + 1;
	adr_short(&adr, &sz, 1);

	token->len = (uchar_t)adr_count(&adr);
	m = au_getclr();
	(void) au_append_buf(which, sz, m);
	(void) au_append_rec(token, m, AU_PACK);
	adr.adr_now += sz;

	secflags_to_str(set, secstr, sizeof (secstr));
	sz = strlen(secstr) + 1;
	adr_short(&adr, &sz, 1);
	token->len = (uchar_t)adr_count(&adr);
	m = au_getclr();
	(void) au_append_buf(secstr, sz, m);
	(void) au_append_rec(token, m, AU_PACK);

	return (token);
}

/*
 * au_to_label
 * returns:
 *	pointer to au_membuf chain containing a label token.
 */
token_t *
au_to_label(bslabel_t *label)
{
	token_t *m;			/* local au_membuf */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_LABEL;	/* header for this token */

	m = au_getclr();

	adr_start(&adr, memtod(m, char *));
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, (char *)label, sizeof (_mac_label_impl_t));

	m->len = adr_count(&adr);

	return (m);
}
