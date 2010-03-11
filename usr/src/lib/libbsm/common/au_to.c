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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <unistd.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <priv.h>
#include <sys/ipc.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <malloc.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <string.h>
#include <ucred.h>
#include <zone.h>
#include <sys/tsol/label.h>

#define	NGROUPS		16	/* XXX - temporary */

token_t *au_to_arg(char n, char *text, uint32_t v);
#pragma weak au_to_arg = au_to_arg32
token_t *au_to_return(char number, uint32_t value);
#pragma weak au_to_return = au_to_return32

static token_t *au_to_exec(char **, char);

static token_t *
get_token(int s)
{
	token_t *token;	/* Resultant token */

	if ((token = (token_t *)malloc(sizeof (token_t))) == NULL)
		return (NULL);
	if ((token->tt_data = malloc(s)) == NULL) {
		free(token);
		return (NULL);
	}
	token->tt_size = s;
	token->tt_next = NULL;
	return (token);
}

/*
 * au_to_header
 * return s:
 *	pointer to header token.
 */
token_t *
au_to_header(au_event_t e_type, au_emod_t e_mod)
{
	adr_t adr;			/* adr memory stream header */
	token_t *token;			/* token pointer */
	char version = TOKEN_VERSION;	/* version of token family */
	int32_t byte_count;
	struct timeval tv;
#ifdef _LP64
	char data_header = AUT_HEADER64;	/* header for this token */

	token = get_token(2 * sizeof (char) + sizeof (int32_t) +
	    2 * sizeof (int64_t) + 2 * sizeof (short));
#else
	char data_header = AUT_HEADER32;

	token = get_token(2 * sizeof (char) + 3 * sizeof (int32_t) +
	    2 * sizeof (short));
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);	/* token ID */
	adr_int32(&adr, &byte_count, 1);	/* length of audit record */
	adr_char(&adr, &version, 1);		/* version of audit tokens */
	adr_ushort(&adr, &e_type, 1);		/* event ID */
	adr_ushort(&adr, &e_mod, 1);		/* event ID modifier */
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tv, 2);	/* time & date */
#else
	adr_int32(&adr, (int32_t *)&tv, 2);	/* time & date */
#endif
	return (token);
}

/*
 * au_to_header_ex
 * return s:
 *	pointer to header token.
 */
token_t *
au_to_header_ex(au_event_t e_type, au_emod_t e_mod)
{
	adr_t adr;			/* adr memory stream header */
	token_t *token;			/* token pointer */
	char version = TOKEN_VERSION;	/* version of token family */
	int32_t byte_count;
	struct timeval tv;
	auditinfo_addr_t audit_info;
	au_tid_addr_t	*host_info = &audit_info.ai_termid;
#ifdef _LP64
	char data_header = AUT_HEADER64_EX;	/* header for this token */
#else
	char data_header = AUT_HEADER32_EX;
#endif

	/* If our host address can't be determined, revert to un-extended hdr */

	if (auditon(A_GETKAUDIT, (caddr_t)&audit_info,
	    sizeof (audit_info)) < 0)
		return (au_to_header(e_type, e_mod));

	if (host_info->at_type == AU_IPv6)
		if (IN6_IS_ADDR_UNSPECIFIED((in6_addr_t *)host_info->at_addr))
			return (au_to_header(e_type, e_mod));
	else
		if (host_info->at_addr[0] == htonl(INADDR_ANY))
			return (au_to_header(e_type, e_mod));

#ifdef _LP64
	token = get_token(2 * sizeof (char) + sizeof (int32_t) +
	    2 * sizeof (int64_t) + 2 * sizeof (short) +
	    sizeof (int32_t) + host_info->at_type);
#else
	token = get_token(2 * sizeof (char) + 3 * sizeof (int32_t) +
	    2 * sizeof (short) + sizeof (int32_t) + host_info->at_type);
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);	/* token ID */
	adr_int32(&adr, &byte_count, 1);	/* length of audit record */
	adr_char(&adr, &version, 1);		/* version of audit tokens */
	adr_ushort(&adr, &e_type, 1);		/* event ID */
	adr_ushort(&adr, &e_mod, 1);		/* event ID modifier */
	adr_int32(&adr, (int32_t *)&host_info->at_type, 1);
	adr_char(&adr, (char *)host_info->at_addr,
	    (int)host_info->at_type);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tv, 2);	/* time & date */
#else
	adr_int32(&adr, (int32_t *)&tv, 2);	/* time & date */
#endif
	return (token);
}

/*
 * au_to_trailer
 * return s:
 *	pointer to a trailer token.
 */
token_t *
au_to_trailer(void)
{
	adr_t adr;				/* adr memory stream header */
	token_t *token;				/* token pointer */
	char data_header = AUT_TRAILER;		/* header for this token */
	short magic = (short)AUT_TRAILER_MAGIC;	/* trailer magic number */
	int32_t byte_count;

	token = get_token(sizeof (char) + sizeof (int32_t) + sizeof (short));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);	/* token ID */
	adr_short(&adr, &magic, 1);		/* magic number */
	adr_int32(&adr, &byte_count, 1);	/* length of audit record */

	return (token);
}

/*
 * au_to_arg32
 * return s:
 *	pointer to an argument token.
 */
token_t *
au_to_arg32(char n, char *text, uint32_t v)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ARG32;	/* header for this token */
	short bytes;			/* length of string */

	bytes = strlen(text) + 1;

	token = get_token((int)(2 * sizeof (char) + sizeof (int32_t) +
	    sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);	/* token type */
	adr_char(&adr, &n, 1);			/* argument id */
	adr_int32(&adr, (int32_t *)&v, 1);	/* argument value */
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, text, bytes);

	return (token);
}

/*
 * au_to_arg64
 * return s:
 *	pointer to an argument token.
 */
token_t *
au_to_arg64(char n, char *text, uint64_t v)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ARG64;	/* header for this token */
	short bytes;			/* length of string */

	bytes = strlen(text) + 1;

	token = get_token((int)(2 * sizeof (char) + sizeof (int64_t) +
	    sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);	/* token type */
	adr_char(&adr, &n, 1);			/* argument id */
	adr_int64(&adr, (int64_t *)&v, 1);	/* argument value */
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, text, bytes);

	return (token);
}


/*
 * au_to_attr
 * return s:
 *	pointer to an attribute token.
 */
token_t *
au_to_attr(struct vattr *attr)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	int32_t value;
#ifdef _LP64
	char data_header = AUT_ATTR64;	/* header for this token */

	token = get_token(sizeof (char) +
	    sizeof (int32_t) * 4 +
	    sizeof (int64_t) * 2);
#else
	char data_header = AUT_ATTR32;

	token = get_token(sizeof (char) + sizeof (int32_t) * 5 +
	    sizeof (int64_t));
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	value = (int32_t)attr->va_mode;
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

	return (token);
}

/*
 * au_to_data
 * return s:
 *	pointer to a data token.
 */
token_t *
au_to_data(char unit_print, char unit_type, char unit_count, char *p)
{
	adr_t adr;			/* adr memory stream header */
	token_t *token;			/* token pointer */
	char data_header = AUT_DATA;	/* header for this token */
	int byte_count;			/* number of bytes */

	if (p == NULL || unit_count < 1)
		return (NULL);

	/*
	 * Check validity of print type
	 */
	if (unit_print < AUP_BINARY || unit_print > AUP_STRING)
		return (NULL);

	switch (unit_type) {
	case AUR_SHORT:
		byte_count = unit_count * sizeof (short);
		break;
	case AUR_INT32:
		byte_count = unit_count * sizeof (int32_t);
		break;
	case AUR_INT64:
		byte_count = unit_count * sizeof (int64_t);
		break;
	/* case AUR_CHAR: */
	case AUR_BYTE:
		byte_count = unit_count * sizeof (char);
		break;
	default:
		return (NULL);
	}

	token = get_token((int)(4 * sizeof (char) + byte_count));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &unit_print, 1);
	adr_char(&adr, &unit_type, 1);
	adr_char(&adr, &unit_count, 1);

	switch (unit_type) {
	case AUR_SHORT:
		/* LINTED */
		adr_short(&adr, (short *)p, unit_count);
		break;
	case AUR_INT32:
		/* LINTED */
		adr_int32(&adr, (int32_t *)p, unit_count);
		break;
	case AUR_INT64:
		/* LINTED */
		adr_int64(&adr, (int64_t *)p, unit_count);
		break;
	/* case AUR_CHAR: */
	case AUR_BYTE:
		adr_char(&adr, p, unit_count);
		break;
	}

	return (token);
}

/*
 * au_to_privset
 *
 * priv_type (LIMIT, INHERIT...) is the first string and privilege
 * in translated into the second string.  The format is as follows:
 *
 *	token id	adr_char
 *	priv type	adr_string (short, string)
 *	priv set	adr_string (short, string)
 *
 * return s:
 *	pointer to a AUT_PRIV token.
 */
token_t *
au_to_privset(const char *priv_type, const priv_set_t *privilege)
{
	token_t	*token;			/* local token */
	adr_t	adr;			/* adr memory stream header */
	char	data_header = AUT_PRIV;	/* header for this token */
	short	t_bytes;		/* length of type string */
	short	p_bytes;		/* length of privilege string */
	char	*priv_string;		/* privilege string */

	t_bytes = strlen(priv_type) + 1;

	if ((privilege == NULL) || (priv_string =
	    priv_set_to_str(privilege, ',',
	    PRIV_STR_LIT)) == NULL)
		return (NULL);

	p_bytes = strlen(priv_string) + 1;

	token = get_token((int)(sizeof (char) + (2 * sizeof (short)) + t_bytes
	    + p_bytes));
	if (token == NULL)
		return (NULL);

	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &t_bytes, 1);
	adr_char(&adr, (char *)priv_type, t_bytes);
	adr_short(&adr, &p_bytes, 1);
	adr_char(&adr, priv_string, p_bytes);

	free(priv_string);

	return (token);
}

/*
 * au_to_process
 * return s:
 *	pointer to a process token.
 */

token_t *
au_to_process(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid, gid_t rgid,
    pid_t pid, au_asid_t sid, au_tid_t *tid)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
#ifdef _LP64
	char data_header = AUT_PROCESS64;	/* header for this token */

	token = get_token(sizeof (char) + 8 * sizeof (int32_t) +
	    sizeof (int64_t));
#else
	char data_header = AUT_PROCESS32;

	token = get_token(sizeof (char) + 9 * sizeof (int32_t));
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&auid, 1);
	adr_int32(&adr, (int32_t *)&euid, 1);
	adr_int32(&adr, (int32_t *)&egid, 1);
	adr_int32(&adr, (int32_t *)&ruid, 1);
	adr_int32(&adr, (int32_t *)&rgid, 1);
	adr_int32(&adr, (int32_t *)&pid, 1);
	adr_int32(&adr, (int32_t *)&sid, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tid->port, 1);
#else
	adr_int32(&adr, (int32_t *)&tid->port, 1);
#endif
	adr_int32(&adr, (int32_t *)&tid->machine, 1);

	return (token);
}

/*
 * au_to_process_ex
 * return s:
 *	pointer to a process_ex token.
 */
token_t *
au_to_process_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid, gid_t rgid,
    pid_t pid, au_asid_t sid, au_tid_addr_t *tid)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header;		/* header for this token */

#ifdef _LP64
	if (tid->at_type == AU_IPv6) {
		data_header = AUT_PROCESS64_EX;
		token = get_token(sizeof (char) + sizeof (int64_t) +
		    12 * sizeof (int32_t));
	} else {
		data_header = AUT_PROCESS64;
		token = get_token(sizeof (char) + sizeof (int64_t) +
		    8 * sizeof (int32_t));
	}
#else
	if (tid->at_type == AU_IPv6) {
		data_header = AUT_PROCESS32_EX;
		token = get_token(sizeof (char) + 13 * sizeof (int32_t));
	} else {
		data_header = AUT_PROCESS32;
		token = get_token(sizeof (char) + 9 * sizeof (int32_t));
	}
#endif
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&auid, 1);
	adr_int32(&adr, (int32_t *)&euid, 1);
	adr_int32(&adr, (int32_t *)&egid, 1);
	adr_int32(&adr, (int32_t *)&ruid, 1);
	adr_int32(&adr, (int32_t *)&rgid, 1);
	adr_int32(&adr, (int32_t *)&pid, 1);
	adr_int32(&adr, (int32_t *)&sid, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tid->at_port, 1);
#else
	adr_int32(&adr, (int32_t *)&tid->at_port, 1);
#endif
	if (tid->at_type == AU_IPv6) {
		adr_int32(&adr, (int32_t *)&tid->at_type, 1);
		adr_char(&adr, (char *)tid->at_addr, 16);
	} else {
		adr_char(&adr, (char *)tid->at_addr, 4);
	}

	return (token);
}

/*
 * au_to_seq
 * return s:
 *	pointer to token chain containing a sequence token
 */
token_t *
au_to_seq(int audit_count)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_SEQ;	/* header for this token */

	token = get_token(sizeof (char) + sizeof (int32_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&audit_count, 1);

	return (token);
}

/*
 * au_to_socket
 * return s:
 *	pointer to mbuf chain containing a socket token.
 */
token_t *
au_to_socket(struct oldsocket *so)
{
	adr_t adr;
	token_t *token;
	char data_header = AUT_SOCKET;
	struct inpcb *inp = so->so_pcb;

	token = get_token(sizeof (char) + sizeof (short) * 3 +
	    sizeof (int32_t) * 2);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, (short *)&so->so_type, 1);
	adr_short(&adr, (short *)&inp->inp_lport, 1);
	adr_int32(&adr, (int32_t *)&inp->inp_laddr, 1);
	adr_short(&adr, (short *)&inp->inp_fport, 1);
	adr_int32(&adr, (int32_t *)&inp->inp_faddr, 1);

	return (token);
}

/*
 * au_to_subject
 * return s:
 *	pointer to a process token.
 */

token_t *
au_to_subject(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid, gid_t rgid,
    pid_t pid, au_asid_t sid, au_tid_t *tid)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
#ifdef _LP64
	char data_header = AUT_SUBJECT64;	/* header for this token */

	token = get_token(sizeof (char) + sizeof (int64_t) +
	    8 * sizeof (int32_t));
#else
	char data_header = AUT_SUBJECT32;

	token = get_token(sizeof (char) + 9 * sizeof (int32_t));
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&auid, 1);
	adr_int32(&adr, (int32_t *)&euid, 1);
	adr_int32(&adr, (int32_t *)&egid, 1);
	adr_int32(&adr, (int32_t *)&ruid, 1);
	adr_int32(&adr, (int32_t *)&rgid, 1);
	adr_int32(&adr, (int32_t *)&pid, 1);
	adr_int32(&adr, (int32_t *)&sid, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tid->port, 1);
#else
	adr_int32(&adr, (int32_t *)&tid->port, 1);
#endif
	adr_int32(&adr, (int32_t *)&tid->machine, 1);

	return (token);
}

/*
 * au_to_subject_ex
 * return s:
 *	pointer to a process token.
 */

token_t *
au_to_subject_ex(au_id_t auid, uid_t euid, gid_t egid, uid_t ruid, gid_t rgid,
    pid_t pid, au_asid_t sid, au_tid_addr_t *tid)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
#ifdef _LP64
	char data_header;		/* header for this token */

	if (tid->at_type == AU_IPv6) {
		data_header = AUT_SUBJECT64_EX;
		token = get_token(sizeof (char) + sizeof (int64_t) +
		    12 * sizeof (int32_t));
	} else {
		data_header = AUT_SUBJECT64;
		token = get_token(sizeof (char) + sizeof (int64_t) +
		    8 * sizeof (int32_t));
	}
#else
	char data_header;		/* header for this token */

	if (tid->at_type == AU_IPv6) {
		data_header = AUT_SUBJECT32_EX;
		token = get_token(sizeof (char) + 13 * sizeof (int32_t));
	} else {
		data_header = AUT_SUBJECT32;
		token = get_token(sizeof (char) + 9 * sizeof (int32_t));
	}
#endif

	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&auid, 1);
	adr_int32(&adr, (int32_t *)&euid, 1);
	adr_int32(&adr, (int32_t *)&egid, 1);
	adr_int32(&adr, (int32_t *)&ruid, 1);
	adr_int32(&adr, (int32_t *)&rgid, 1);
	adr_int32(&adr, (int32_t *)&pid, 1);
	adr_int32(&adr, (int32_t *)&sid, 1);
#ifdef _LP64
	adr_int64(&adr, (int64_t *)&tid->at_port, 1);
#else
	adr_int32(&adr, (int32_t *)&tid->at_port, 1);
#endif
	if (tid->at_type == AU_IPv6) {
		adr_int32(&adr, (int32_t *)&tid->at_type, 1);
		adr_char(&adr, (char *)tid->at_addr, 16);
	} else {
		adr_char(&adr, (char *)tid->at_addr, 4);
	}

	return (token);
}

/*
 * au_to_me
 * return s:
 *	pointer to a process token.
 */

token_t *
au_to_me(void)
{
	auditinfo_addr_t info;

	if (getaudit_addr(&info, sizeof (info)))
		return (NULL);
	return (au_to_subject_ex(info.ai_auid, geteuid(), getegid(), getuid(),
	    getgid(), getpid(), info.ai_asid, &info.ai_termid));
}
/*
 * au_to_text
 * return s:
 *	pointer to a text token.
 */
token_t *
au_to_text(char *text)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_TEXT;	/* header for this token */
	short bytes;			/* length of string */

	bytes = strlen(text) + 1;
	token = get_token((int)(sizeof (char) + sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, text, bytes);

	return (token);
}

/*
 * au_to_path
 * return s:
 *	pointer to a path token.
 */
token_t *
au_to_path(char *path)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_PATH;	/* header for this token */
	short bytes;			/* length of string */

	bytes = (short)strlen(path) + 1;

	token = get_token((int)(sizeof (char) +  sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, path, bytes);

	return (token);
}

/*
 * au_to_cmd
 * return s:
 *	pointer to an command line argument token
 */
token_t *
au_to_cmd(uint_t argc, char **argv, char **envp)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_CMD;	/* header for this token */
	short len = 0;
	short cnt = 0;
	short envc = 0;
	short largc = (short)argc;

	/*
	 * one char for the header, one short for argc,
	 * one short for # envp strings.
	 */
	len = sizeof (char) + sizeof (short) + sizeof (short);

	/* get sizes of strings */

	for (cnt = 0; cnt < argc; cnt++) {
		len += (short)sizeof (short) + (short)(strlen(argv[cnt]) + 1);
	}

	if (envp != NULL) {
		for (envc = 0; envp[envc] != NULL; envc++) {
			len += (short)sizeof (short) +
			    (short)(strlen(envp[envc]) + 1);
		}
	}

	token = get_token(len);
	if (token == NULL)
		return (NULL);

	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);

	adr_short(&adr, &largc, 1);

	for (cnt = 0; cnt < argc; cnt++) {
		len = (short)(strlen(argv[cnt]) + 1);
		adr_short(&adr, &len, 1);
		adr_char(&adr, argv[cnt], len);
	}

	adr_short(&adr, &envc, 1);

	for (cnt = 0; cnt < envc; cnt++) {
		len = (short)(strlen(envp[cnt]) + 1);
		adr_short(&adr, &len, 1);
		adr_char(&adr, envp[cnt], len);
	}

	return (token);
}

/*
 * au_to_exit
 * return s:
 *	pointer to a exit value token.
 */
token_t *
au_to_exit(int retval, int err)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_EXIT;	/* header for this token */

	token = get_token(sizeof (char) + (2 * sizeof (int32_t)));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&retval, 1);
	adr_int32(&adr, (int32_t *)&err, 1);

	return (token);
}

/*
 * au_to_return
 * return s:
 *	pointer to a return  value token.
 */
token_t *
au_to_return32(char number, uint32_t value)
{
	token_t *token;				/* local token */
	adr_t adr;				/* adr memory stream header */
	char data_header = AUT_RETURN32;	/* header for this token */

	token = get_token(2 * sizeof (char) + sizeof (int32_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &number, 1);
	adr_int32(&adr, (int32_t *)&value, 1);

	return (token);
}

/*
 * au_to_return
 * return s:
 *	pointer to a return  value token.
 */
token_t *
au_to_return64(char number, uint64_t value)
{
	token_t *token;				/* local token */
	adr_t adr;				/* adr memory stream header */
	char data_header = AUT_RETURN64;	/* header for this token */

	token = get_token(2 * sizeof (char) + sizeof (int64_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &number, 1);
	adr_int64(&adr, (int64_t *)&value, 1);

	return (token);
}


/*
 * au_to_opaque
 * return s:
 *	pointer to a opaque token.
 */
token_t *
au_to_opaque(char *opaque, short bytes)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_OPAQUE;	/* header for this token */

	if (bytes < 1)
		return (NULL);

	token = get_token((int)(sizeof (char) + sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, opaque, bytes);

	return (token);
}

/*
 * au_to_in_addr
 * return s:
 *	pointer to an internet address token
 */
token_t *
au_to_in_addr(struct in_addr *internet_addr)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IN_ADDR;	/* header for this token */

	token = get_token(sizeof (char) + sizeof (struct in_addr));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, (char *)internet_addr, sizeof (struct in_addr));

	return (token);
}

/*
 * au_to_in_addr_ex
 * return s:
 *	pointer to an internet extended token
 */
token_t *
au_to_in_addr_ex(struct in6_addr *addr)
{
	token_t *token;
	adr_t adr;

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		ipaddr_t in4;

		/*
		 * An IPv4-mapped IPv6 address is really an IPv4 address
		 * in IPv6 format.
		 */

		IN6_V4MAPPED_TO_IPADDR(addr, in4);
		return (au_to_in_addr((struct in_addr *)&in4));

	} else {
		char data_header = AUT_IN_ADDR_EX;
		int32_t	type = AU_IPv6;

		if ((token = get_token(sizeof (char) + sizeof (int32_t) +
		    sizeof (struct in6_addr))) == NULL) {
			return (NULL);
		}

		adr_start(&adr, token->tt_data);
		adr_char(&adr, &data_header, 1);
		adr_int32(&adr, &type, 1);
		adr_char(&adr, (char *)addr, sizeof (struct in6_addr));
	}

	return (token);
}

/*
 * au_to_iport
 * return s:
 *	pointer to token chain containing a ip port address token
 */
token_t *
au_to_iport(ushort_t iport)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IPORT;	/* header for this token */

	token = get_token(sizeof (char) + sizeof (short));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, (short *)&iport, 1);

	return (token);
}

token_t *
au_to_ipc(char type, int id)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_IPC;	/* header for this token */

	token = get_token((2 * sizeof (char)) + sizeof (int32_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &type, 1);
	adr_int32(&adr, (int32_t *)&id, 1);

	return (token);
}

/*
 * au_to_tid
 *
 * output format depends on type; at present only IP v4 and v6 addresses
 * are defined.
 *
 * IPv4 -- tid type, 16 bit remote port, 16 bit local port, ip type,
 *		32 bit IP address.
 * IPv6 -- tid type, 16 bit remote port, 16 bit local port, ip type,
 *		4 x 32 bit IP address.
 *
 */
token_t *
au_to_tid(au_generic_tid_t *tid)
{
	char		data_header = AUT_TID;	/* header for this token */
	adr_t		adr;			/* adr memory stream header */
	token_t		*token;			/* local token */
	au_ip_t		*ip;

	switch (tid->gt_type) {
	case AU_IPADR:
		ip = &(tid->gt_adr.at_ip);
		token = get_token((int)(2 * sizeof (char) + 2 * sizeof (short) +
		    sizeof (uint32_t) + ip->at_type));
		if (token == NULL)
			return (NULL);

		adr_start(&adr, token->tt_data);
		adr_char(&adr, &data_header, 1);
		adr_char(&adr, (char *)&(tid->gt_type), 1);
		adr_short(&adr, (short *)&(ip->at_r_port), 1);
		adr_short(&adr, (short *)&(ip->at_l_port), 1);
		adr_int32(&adr, (int32_t *)&(ip->at_type), 1);

		adr_char(&adr, (char *)ip->at_addr, ip->at_type);

		break;
	default:
		return (NULL);
	}
	return (token);
}

/*
 * The Modifier tokens
 */

/*
 * au_to_groups
 * return s:
 *	pointer to a group list token.
 *
 * This function is obsolete.  Please use au_to_newgroups.
 */
token_t *
au_to_groups(int *groups)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_GROUPS;	/* header for this token */

	token = get_token(sizeof (char) + NGROUPS * sizeof (int32_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)groups, NGROUPS);

	return (token);
}

/*
 * au_to_newgroups
 * return s:
 *	pointer to a group list token.
 */
token_t *
au_to_newgroups(int n, gid_t *groups)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_NEWGROUPS;	/* header for this token */
	short n_groups;

	if (n < 0 || n > SHRT_MAX || groups == NULL)
		return (NULL);
	token = get_token(sizeof (char) + sizeof (short) + n * sizeof (gid_t));
	if (token == NULL)
		return (NULL);
	n_groups = (short)n;
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &n_groups, 1);
	adr_int32(&adr, (int32_t *)groups, n_groups);

	return (token);
}

/*
 * au_to_exec_args
 * returns:
 *	pointer to an exec args token.
 */
token_t *
au_to_exec_args(char **argv)
{
	return (au_to_exec(argv, AUT_EXEC_ARGS));
}

/*
 * au_to_exec_env
 * returns:
 *	pointer to an exec args token.
 */
token_t *
au_to_exec_env(char **envp)
{
	return (au_to_exec(envp, AUT_EXEC_ENV));
}

/*
 * au_to_exec
 * returns:
 *	pointer to an exec args token.
 */
static token_t *
au_to_exec(char **v, char data_header)
{
	token_t *token;
	adr_t adr;
	char **p;
	int32_t n = 0;
	int len = 0;

	for (p = v; *p != NULL; p++) {
		len += strlen(*p) + 1;
		n++;
	}
	token = get_token(sizeof (char) + sizeof (int32_t) + len);
	if (token == (token_t *)NULL)
		return ((token_t *)NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, &n, 1);
	for (p = v; *p != NULL; p++) {
		adr_char(&adr, *p, strlen(*p) + 1);
	}
	return (token);
}

/*
 * au_to_uauth
 * return s:
 *	pointer to a uauth token.
 */
token_t *
au_to_uauth(char *text)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_UAUTH;	/* header for this token */
	short bytes;			/* length of string */

	bytes = strlen(text) + 1;

	token = get_token((int)(sizeof (char) + sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, text, bytes);

	return (token);
}

/*
 * au_to_upriv
 * return s:
 *	pointer to a use of privilege token.
 */
token_t *
au_to_upriv(char sorf, char *priv)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_UAUTH;	/* header for this token */
	short bytes;			/* length of string */

	bytes = strlen(priv) + 1;

	token = get_token(sizeof (char) + sizeof (char) + sizeof (short) +
	    bytes);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, &sorf, 1);	/* success/failure */
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, priv, bytes);

	return (token);
}

/*
 * au_to_user
 * return s:
 *	pointer to a user token.
 */
token_t *
au_to_user(uid_t uid,  char *username)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_USER;	/* header for this token */
	short  bytes;			/* length of string */

	bytes = (short)strlen(username) + 1;

	token = get_token(sizeof (char) + sizeof (uid_t) + sizeof (short) +
	    bytes);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_uid(&adr, &uid, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, username, bytes);

	return (token);
}

/*
 * au_to_xatom
 * return s:
 *	pointer to a xatom token.
 */
token_t *
au_to_xatom(char *atom)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_XATOM;	/* header for this token */
	short len;

	len = strlen(atom) + 1;

	token = get_token(sizeof (char) + sizeof (short) + len);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, (short *)&len, 1);
	adr_char(&adr, atom, len);

	return (token);
}

/*
 * au_to_xselect
 * return s:
 *	pointer to a X select token.
 */
token_t *
au_to_xselect(char *propname, char *proptype, char *windata)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_XSELECT;	/* header for this token */
	short proplen;
	short typelen;
	short datalen;

	proplen = strlen(propname) + 1;
	typelen = strlen(proptype) + 1;
	datalen = strlen(windata) + 1;

	token = get_token(sizeof (char) + (sizeof (short) * 3) +
	    proplen + typelen + datalen);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &proplen, 1);
	adr_char(&adr, propname, proplen);
	adr_short(&adr, &typelen, 1);
	adr_char(&adr, proptype, typelen);
	adr_short(&adr, &datalen, 1);
	adr_char(&adr, windata, datalen);

	return (token);
}

/*
 * x_common
 * return s:
 *	pointer to a common X token.
 */

static token_t *
x_common(char data_header, int32_t xid, uid_t cuid)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */

	token = get_token(sizeof (char) + sizeof (int32_t) + sizeof (uid_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, &xid, 1);
	adr_uid(&adr, &cuid, 1);

	return (token);
}

/*
 * au_to_xcolormap
 * return s:
 *	pointer to a X Colormap token.
 */

token_t *
au_to_xcolormap(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XCOLORMAP, xid, cuid));
}

/*
 * au_to_xcursor
 * return s:
 *	pointer to a X Cursor token.
 */

token_t *
au_to_xcursor(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XCURSOR, xid, cuid));
}

/*
 * au_to_xfont
 * return s:
 *	pointer to a X Font token.
 */

token_t *
au_to_xfont(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XFONT, xid, cuid));
}

/*
 * au_to_xgc
 * return s:
 *	pointer to a X Graphic Context token.
 */

token_t *
au_to_xgc(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XGC, xid, cuid));
}

/*
 * au_to_xpixmap
 * return s:
 *	pointer to a X Pixal Map token.
 */

token_t *
au_to_xpixmap(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XPIXMAP, xid, cuid));
}

/*
 * au_to_xwindow
 * return s:
 *	pointer to a X Window token.
 */

token_t *
au_to_xwindow(int32_t xid, uid_t cuid)
{
	return (x_common(AUT_XWINDOW, xid, cuid));
}

/*
 * au_to_xproperty
 * return s:
 *	pointer to a X Property token.
 */

token_t *
au_to_xproperty(int32_t xid, uid_t cuid, char *propname)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_XPROPERTY;	/* header for this token */
	short proplen;

	proplen = strlen(propname) + 1;

	token = get_token(sizeof (char) + sizeof (int32_t) + sizeof (uid_t) +
	    sizeof (short) + proplen);
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, &xid, 1);
	adr_uid(&adr, &cuid, 1);
	adr_short(&adr, &proplen, 1);
	adr_char(&adr, propname, proplen);

	return (token);
}

/*
 * au_to_xclient
 * return s:
 *	pointer to a X Client token
 */

token_t *
au_to_xclient(uint32_t client)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_XCLIENT;	/* header for this token */

	token = get_token(sizeof (char) + sizeof (uint32_t));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_int32(&adr, (int32_t *)&client, 1);

	return (token);
}

/*
 * au_to_label
 * return s:
 *	pointer to a label token.
 */
token_t *
au_to_label(m_label_t *label)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_LABEL;	/* header for this token */
	size32_t llen = blabel_size();

	token = get_token(sizeof (char) + llen);
	if (token == NULL) {
		return (NULL);
	} else if (label == NULL) {
		free(token);
		return (NULL);
	}
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_char(&adr, (char *)label, llen);

	return (token);
}

/*
 * au_to_mylabel
 * return s:
 *	pointer to a label token.
 */
token_t *
au_to_mylabel(void)
{
	ucred_t		*uc;
	token_t		*token;

	if ((uc = ucred_get(P_MYID)) == NULL) {
		return (NULL);
	}

	token = au_to_label(ucred_getlabel(uc));
	ucred_free(uc);
	return (token);
}

/*
 * au_to_zonename
 * return s:
 *	pointer to a zonename token.
 */
token_t *
au_to_zonename(char *name)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_ZONENAME;	/* header for this token */
	short bytes;			/* length of string */

	if (name == NULL)
		return (NULL);

	bytes = strlen(name) + 1;
	token = get_token((int)(sizeof (char) + sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, name, bytes);

	return (token);
}

/*
 * au_to_fmri
 * return s:
 *	pointer to a fmri token.
 */
token_t *
au_to_fmri(char *fmri)
{
	token_t *token;			/* local token */
	adr_t adr;			/* adr memory stream header */
	char data_header = AUT_FMRI;	/* header for this token */
	short bytes;			/* length of string */

	if (fmri == NULL)
		return (NULL);

	bytes = strlen(fmri) + 1;
	token = get_token((int)(sizeof (char) + sizeof (short) + bytes));
	if (token == NULL)
		return (NULL);
	adr_start(&adr, token->tt_data);
	adr_char(&adr, &data_header, 1);
	adr_short(&adr, &bytes, 1);
	adr_char(&adr, fmri, bytes);

	return (token);
}
