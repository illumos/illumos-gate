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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */


/*
 * Token processing for sysupd; each token function does one
 * or more operations.  All of them bump the buffer pointer
 * to the next token; some of them extract one or more data
 * from the token.
 */

#define	DEBUG	0
#if DEBUG
#define	DPRINT(x) { (void) fprintf x; }
#else
#define	DPRINT(x)
#endif

#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <bsm/libbsm.h>
#include <sys/tsol/label.h>
#include "toktable.h"	/* ../praudit */
#include "sysplugin.h"
#include "systoken.h"
#include <audit_plugin.h>

#if DEBUG
static FILE	*dbfp;			/* debug file */
#endif

static void	anchor_path(char *);
static size_t	collapse_path(char *, size_t);
static void	get_bytes_to_string(parse_context_t *, size_t *, char **,
		    size_t);
static void	skip_bytes(parse_context_t *);
static void	skip_string(parse_context_t *);
static int	xgeneric(parse_context_t *);

/*
 * Process a token in a record to (1) extract data of interest if any
 * and (2) point to the next token.
 *
 * returns 0 if ok.  + or - values are of debug value:
 *
 *	returns -1 if the parsing of the token failed.
 *
 *	returns +<previous id> if the token is not found.  This value
 *	is used to help determine where in the record the problem
 *	occurred.  The common failure case is that the parsing of
 *	token M is incorrect and the buffer pointer ends up pointing
 *	to garbage.  The positive error value of M *may* be the id of
 *	the incorrectly parsed token.
 */

int
parse_token(parse_context_t *ctx)
{
	char		tokenid;
	static char	prev_tokenid = -1;
	int		rc;

#if DEBUG
	static boolean_t	first = 1;

	if (first) {
		dbfp = __auditd_debug_file_open();
		first = 0;
	}
#endif

	adrm_char(&(ctx->adr), &tokenid, 1);

	if ((tokenid > 0) && (tokentable[tokenid].func != NOFUNC)) {
		rc = (*tokentable[tokenid].func)(ctx);
		prev_tokenid = tokenid;
		return (rc);
	}
	/* here if token id is not in table */
	return (prev_tokenid);
}

/* There should not be any file tokens in the middle of a record */

/* ARGSUSED */
int
file_token(parse_context_t *ctx)
{

	return (-1);
}

/* ARGSUSED */
int
file64_token(parse_context_t *ctx)
{
	return (-1);
}

static void
common_header(parse_context_t *ctx)
{
	adrm_u_int32(&(ctx->adr), &(ctx->out.sf_reclen), 1);
	ctx->adr.adr_now += sizeof (char);		/* version number */
	adrm_u_short(&(ctx->adr), &(ctx->out.sf_eventid), 1);
	ctx->adr.adr_now += sizeof (short);		/* modifier */
}

/*
 * 32bit header
 */
int
header_token(parse_context_t *ctx)
{
	common_header(ctx);
	ctx->adr.adr_now += 2 * sizeof (int32_t);	/* time */

	return (0);
}


int
header32_ex_token(parse_context_t *ctx)
{
	int32_t	type;

	common_header(ctx);

	adrm_int32(&(ctx->adr), &type, 1);		/* tid type */
	ctx->adr.adr_now += type * sizeof (char);	/* ip address */

	ctx->adr.adr_now += 2 * sizeof (int32_t);	/* time */

	return (0);
}


int
header64_ex_token(parse_context_t *ctx)
{
	int32_t	type;

	common_header(ctx);

	adrm_int32(&(ctx->adr), &type, 1);		/* tid type */
	ctx->adr.adr_now += type * sizeof (char);	/* ip address */

	ctx->adr.adr_now += 2 * sizeof (int64_t);	/* time */

	return (0);
}


int
header64_token(parse_context_t *ctx)
{
	common_header(ctx);

	ctx->adr.adr_now += 2 * sizeof (int64_t);	/* time */

	return (0);
}


/*
 * ======================================================
 *  The following token processing routines return
 *  0: if parsed ok
 * -1: can't parse and can't determine location of next token
 * ======================================================
 */

int
trailer_token(parse_context_t *ctx)
{
	short	magic_number;
	uint32_t bytes;

	adrm_u_short(&(ctx->adr), (ushort_t *)&magic_number, 1);
	if (magic_number != AUT_TRAILER_MAGIC)
		return (-1);

	adrm_u_int32(&(ctx->adr), &bytes, 1);

	return (0);
}


/*
 * Format of arbitrary data token:
 *	arbitrary data token id	&(ctx->adr) char
 * 	how to print		adr_char
 *	basic unit		adr_char
 *	unit count		adr_char, specifying number of units of
 *	data items		depends on basic unit
 *
 */
int
arbitrary_data_token(parse_context_t *ctx)
{
	char	basic_unit, unit_count;

	ctx->adr.adr_now += sizeof (char); /* how to print */

	adrm_char(&(ctx->adr), &basic_unit, 1);
	adrm_char(&(ctx->adr), &unit_count, 1);

	switch (basic_unit) {
	case AUR_CHAR: /* same as AUR_BYTE */
		ctx->adr.adr_now += unit_count * sizeof (char);
		break;
	case AUR_SHORT:
		ctx->adr.adr_now += unit_count * sizeof (short);
		break;
	case AUR_INT32:	/* same as AUR_INT */
		ctx->adr.adr_now += unit_count * sizeof (int32_t);
		break;
	case AUR_INT64:
		ctx->adr.adr_now += unit_count * sizeof (int64_t);
		break;
	default:
		return (-1);
	}
	return (0);
}


/*
 * Format of opaque token:
 *	opaque token id		adr_char
 *	size			adr_short
 *	data			adr_char, size times
 *
 */
int
opaque_token(parse_context_t *ctx)
{
	skip_bytes(ctx);
	return (0);
}


/*
 * Format of return32 value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_u_int32
 *
 */
int
return_value32_token(parse_context_t *ctx)
{
	char		errnum;

	adrm_char(&(ctx->adr), &errnum, 1);	/* pass / fail */
	ctx->adr.adr_now += sizeof (int32_t);	/* error code */

	ctx->out.sf_pass = (errnum == 0) ? 1 : -1;

	return (0);
}

/*
 * Format of return64 value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_u_int64
 *
 */
int
return_value64_token(parse_context_t *ctx)
{
	char		errnum;

	adrm_char(&(ctx->adr), &errnum, 1);	/* pass / fail */
	ctx->adr.adr_now += sizeof (int64_t);	/* error code */

	ctx->out.sf_pass = (errnum == 0) ? 1 : -1;

	return (0);
}


/*
 * Format of sequence token:
 *	sequence token id	adr_char
 *	audit_count		int32_t
 *
 */
int
sequence_token(parse_context_t *ctx)
{
	adrm_int32(&(ctx->adr), &(ctx->out.sf_sequence), 1);
	return (0);
}


/*
 * Format of text token:
 *	text token id		adr_char
 * 	text			adr_string
 */
int
text_token(parse_context_t *ctx)
{
	ushort_t	len;
	size_t		separator_sz = 0;
	char		*bp;	/* pointer to output string */

	adrm_u_short(&(ctx->adr), &len, 1);

	if (ctx->out.sf_textlen > 0)
		separator_sz = sizeof (AU_TEXT_NAME) - 1;

	DPRINT((dbfp, "text_token: start length=%d, add length=%d+%d\n",
	    ctx->out.sf_textlen, (size_t)len, separator_sz));

	ctx->out.sf_text = realloc(ctx->out.sf_text,
	    ctx->out.sf_textlen + (size_t)len + separator_sz);

	if (ctx->out.sf_text == NULL)
		return (-1);

	bp = ctx->out.sf_text;

	if (ctx->out.sf_textlen != 0) {	/* concatenation? */
		bp += ctx->out.sf_textlen;
		bp += strlcpy(bp, AU_TEXT_NAME, separator_sz + 1);
		ctx->out.sf_textlen += separator_sz;
		DPRINT((dbfp, "text_token: l is %d\n%s\n", ctx->out.sf_textlen,
		    ctx->out.sf_text));
	}
	adrm_char(&(ctx->adr), bp, len);
	len--;		/* includes EOS */
	*(bp + len) = '\0';

	ctx->out.sf_textlen += len;
	DPRINT((dbfp, "text_token: l=%d\n%s\n", ctx->out.sf_textlen,
	    ctx->out.sf_text));

	return (0);
}

/*
 * Format of tid token:
 *	ip token id	adr_char
 *	terminal type	adr_char
 *  terminal type = AU_IPADR:
 *	remote port:	ushort
 *	local port:	ushort
 *	IP type:	int32 -- AU_IPv4 or AU_IPv6
 *	address:	int32 if IPv4, else 4 * int32
 */
int
tid_token(parse_context_t *ctx)
{
	uchar_t		type;
	int32_t		ip_length;

	adrm_char(&(ctx->adr), (char *)&type, 1);

	switch (type) {
	default:
		return (-1);	/* other than IP type is not implemented */
	case AU_IPADR:
		ctx->adr.adr_now += 2 * sizeof (ushort_t);
		adrm_int32(&(ctx->adr), &ip_length, 1);
		ctx->adr.adr_now += ip_length;
		break;
	}
	return (0);
}

/*
 * Format of ip_addr token:
 *	ip token id	adr_char
 *	address		adr_int32
 *
 */
int
ip_addr_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (int32_t);

	return (0);
}

/*
 * Format of ip_addr_ex token:
 *	ip token id	adr_char
 *	ip type		adr_int32
 *	ip address	adr_u_char*type
 *
 */
int
ip_addr_ex_token(parse_context_t *ctx)
{
	int32_t	type;

	adrm_int32(&(ctx->adr), &type, 1);		/* ip type */
	ctx->adr.adr_now += type * sizeof (uchar_t);	/* ip address */

	return (0);
}

/*
 * Format of ip token:
 *	ip header token id	adr_char
 *	version			adr_char
 *	type of service		adr_char
 *	length			adr_short
 *	id			adr_u_short
 *	offset			adr_u_short
 *	ttl			adr_char
 *	protocol		adr_char
 *	checksum		adr_u_short
 *	source address		adr_int32
 *	destination address	adr_int32
 *
 */
int
ip_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += (2 * sizeof (char)) + (3 * sizeof (short)) +
	    (2 * sizeof (char)) + sizeof (short) + (2 * sizeof (int32_t));
	return (0);
}


/*
 * Format of iport token:
 *	ip port address token id	adr_char
 *	port address			adr_short
 *
 */
int
iport_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (short);

	return (0);
}


/*
 * Format of groups token:
 *	group token id		adr_char
 *	group list		adr_int32, 16 times
 *
 */
int
group_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += 16 * sizeof (int32_t);

	return (0);
}

/*
 * Format of newgroups token:
 *	group token id		adr_char
 *	number of groups	adr_short
 *	group list		adr_int32, "number" times
 *
 */
int
newgroup_token(parse_context_t *ctx)
{
	short int   number;

	adrm_short(&(ctx->adr), &number, 1);

	ctx->adr.adr_now += number * sizeof (int32_t);

	return (0);
}

/*
 * Format of argument32 token:
 *	argument token id	adr_char
 *	argument number		adr_char
 *	argument value		adr_int32
 *	argument description	adr_string
 *
 */
int
argument32_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (char) + sizeof (int32_t);
	skip_bytes(ctx);

	return (0);
}

/*
 * Format of argument64 token:
 *	argument token id	adr_char
 *	argument number		adr_char
 *	argument value		adr_int64
 *	argument description	adr_string
 *
 */
int
argument64_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (char) + sizeof (int64_t);
	skip_bytes(ctx);

	return (0);
}

/*
 * Format of acl token:
 * 	acl token id		adr_char
 *	type			adr_u_int32
 *	value			adr_u_int32
 *	mode			adr_u_int32
 */
int
acl_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += 3 * sizeof (uint32_t);

	return (0);
}

/*
 * Format of ace token:
 * 	ace token id		adr_char
 *	id			adr_u_int32
 *	access_mask		adr_u_int32
 *	flags			adr_u_short
 *	type			adr_u_short
 */
int
ace_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += 2 * sizeof (uint32_t) + 2 * sizeof (ushort_t);

	return (0);
}

/*
 * Format of attribute token: (old pre SunOS 5.7 format)
 *	attribute token id	adr_char
 * 	mode			adr_int32 (printed in octal)
 *	uid			adr_int32
 *	gid			adr_int32
 *	file system id		adr_int32
 *	node id			adr_int32
 *	device			adr_int32
 *
 */
int
attribute_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += 6 * sizeof (int32_t);

	return (0);
}

/*
 * Format of attribute32 token:
 *	attribute token id	adr_char
 * 	mode			adr_int32 (printed in octal)
 *	uid			adr_int32
 *	gid			adr_int32
 *	file system id		adr_int32
 *	node id			adr_int64
 *	device			adr_int32
 *
 */
int
attribute32_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += (5 * sizeof (int32_t)) + sizeof (int64_t);

	return (0);
}

/*
 * Format of attribute64 token:
 *	attribute token id	adr_char
 * 	mode			adr_int32 (printed in octal)
 *	uid			adr_int32
 *	gid			adr_int32
 *	file system id		adr_int32
 *	node id			adr_int64
 *	device			adr_int64
 *
 */
int
attribute64_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += (4 * sizeof (int32_t)) + (2 * sizeof (int64_t));

	return (0);
}


/*
 * Format of command token:
 *	attribute token id	adr_char
 *	argc			adr_short
 *	argv len		adr_short	variable amount of argv len
 *	argv text		argv len	and text
 *	.
 *	.
 *	.
 *	envp count		adr_short	variable amount of envp len
 *	envp len		adr_short	and text
 *	envp text		envp		len
 *	.
 *	.
 *	.
 *
 */
int
cmd_token(parse_context_t *ctx)
{
	short	cnt;
	short	i;

	adrm_short(&(ctx->adr), &cnt, 1);

	for (i = 0; i < cnt; i++)
		skip_bytes(ctx);

	adrm_short(&(ctx->adr), &cnt, 1);

	for (i = 0; i < cnt; i++)
		skip_bytes(ctx);

	return (0);
}


/*
 * Format of exit token:
 *	attribute token id	adr_char
 *	return value		adr_int32
 *	errno			adr_int32
 *
 */
int
exit_token(parse_context_t *ctx)
{
	int32_t	retval;

	adrm_int32(&(ctx->adr), &retval, 1);
	ctx->adr.adr_now += sizeof (int32_t);

	ctx->out.sf_pass = (retval == 0) ? 1 : -1;
	return (0);
}

/*
 * Format of exec_args token:
 *	attribute token id	adr_char
 *	count value		adr_int32
 *	strings			null terminated strings
 *
 */
int
exec_args_token(parse_context_t *ctx)
{
	int count, i;

	adrm_int32(&(ctx->adr), (int32_t *)&count, 1);
	for (i = 1; i <= count; i++) {
		skip_string(ctx);
	}

	return (0);
}

/*
 * Format of exec_env token:
 *	attribute token id	adr_char
 *	count value		adr_int32
 *	strings			null terminated strings
 *
 */
int
exec_env_token(parse_context_t *ctx)
{
	int count, i;

	adrm_int32(&(ctx->adr), (int32_t *)&count, 1);
	for (i = 1; i <= count; i++)
		skip_string(ctx);

	return (0);
}

/*
 * Format of liaison token:
 */
int
liaison_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (int32_t);

	return (0);
}


/*
 * Format of path token:
 *	path				adr_string
 */
int
path_token(parse_context_t *ctx)
{
	get_bytes_to_string(ctx, &(ctx->out.sf_pathlen), &(ctx->out.sf_path),
	    0);
	if (ctx->out.sf_path == NULL)
		return (-1);
	/*
	 * anchor the path because collapse_path needs it
	 */
	if (*(ctx->out.sf_path) != '/') {
		anchor_path(ctx->out.sf_path);
		ctx->out.sf_pathlen++;
	}
	ctx->out.sf_pathlen = collapse_path(ctx->out.sf_path,
	    ctx->out.sf_pathlen);

	return (0);
}

/*
 * path attr token / AUT_XATPATH
 *
 * Format of path attr token:
 *	token id		adr_char
 *	string count		adr_int32
 *	strings			adr_string
 *
 * the sequence of strings is converted to a single string with
 * a blank separator replacing the EOS for all but the last
 * string.
 */
int
path_attr_token(parse_context_t *ctx)
{
	int	count, i;
	int	last_len;
	size_t	offset;
	char	*p;

	adrm_int32(&(ctx->adr), &count, 1);

	offset = ctx->out.sf_atpathlen;
	p = ctx->adr.adr_now;
	for (i = 0; i <= count; i++) {
		last_len = strlen(p);
		ctx->out.sf_atpathlen += last_len + 1;
		p += last_len + 1;
	}
	ctx->out.sf_atpath = realloc(ctx->out.sf_atpath, ctx->out.sf_atpathlen);
	ctx->out.sf_atpath += offset;
	p = ctx->out.sf_atpath;		/* save for fix up, below */
	(void) memcpy(ctx->out.sf_atpath, ctx->adr.adr_now,
	    ctx->out.sf_atpathlen - offset);
	ctx->out.sf_atpathlen--;

	/* fix up: replace each eos except the last with ' ' */

	for (i = 0; i < count; i++) {
		while (*p++ != '\0')
			;
		*(p - 1) = ' ';
	}
	return (0);
}


/*
 * Format of System V IPC permission token:
 *	System V IPC permission token id	adr_char
 * 	uid					adr_int32
 *	gid					adr_int32
 *	cuid					adr_int32
 *	cgid					adr_int32
 *	mode					adr_int32
 *	seq					adr_int32
 *	key					adr_int32
 */
int
s5_IPC_perm_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += (7 * sizeof (int32_t));
	return (0);
}

static void
common_process(parse_context_t *ctx)
{
	int32_t	ruid, rgid, egid, pid;
	uint32_t asid;

	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_pauid), 1);
	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_peuid), 1);
	adrm_int32(&(ctx->adr), &egid, 1);
	adrm_int32(&(ctx->adr), &ruid, 1);
	adrm_int32(&(ctx->adr), &rgid, 1);
	adrm_int32(&(ctx->adr), &pid, 1);
	adrm_u_int32(&(ctx->adr), &asid, 1);
}

/*
 * Format of process32 token:
 *	process token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid			adr_int32*2
 *
 */
int
process32_token(parse_context_t *ctx)
{
	int32_t port, machine;

	common_process(ctx);

	adrm_int32(&(ctx->adr), &port, 1);
	adrm_int32(&(ctx->adr), &machine, 1);

	return (0);
}

/*
 * Format of process32_ex token:
 *	process token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid
 *		port		adr_int32
 *		type		adr_int32
 *		ip address	adr_u_char*type
 *
 */
int
process32_ex_token(parse_context_t *ctx)
{
	int32_t port, type;
	uchar_t addr[16];

	common_process(ctx);

	adrm_int32(&(ctx->adr), &port, 1);
	adrm_int32(&(ctx->adr), &type, 1);
	adrm_u_char(&(ctx->adr), addr, type);

	return (0);
}

/*
 * Format of process64 token:
 *	process token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid			adr_int64+adr_int32
 *
 */
int
process64_token(parse_context_t *ctx)
{
	int64_t port;
	int32_t machine;

	common_process(ctx);

	adrm_int64(&(ctx->adr), &port, 1);
	adrm_int32(&(ctx->adr), &machine, 1);

	return (0);
}

/*
 * Format of process64_ex token:
 *	process token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid
 *		port		adr_int64
 *		type		adr_int32
 *		ip address	adr_u_char*type
 *
 */
int
process64_ex_token(parse_context_t *ctx)
{
	int64_t port;
	int32_t type;
	uchar_t	addr[16];

	common_process(ctx);

	adrm_int64(&(ctx->adr), &port, 1);
	adrm_int32(&(ctx->adr), &type, 1);
	adrm_u_char(&(ctx->adr), addr, type);

	return (0);
}

/*
 * Format of System V IPC token:
 *	System V IPC token id	adr_char
 *	System V IPC type	adr_char
 *	object id		adr_int32
 *
 */
int
s5_IPC_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (char);
	ctx->adr.adr_now += sizeof (int32_t);

	return (0);
}


/*
 * Format of socket token:
 *	socket_type		adrm_short
 *	remote_port		adrm_short
 *	remote_inaddr		adrm_int32
 *
 */
int
socket_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += (2 * sizeof (short)) + sizeof (int32_t);

	return (0);
}


/*
 * Format of socket_ex token:
 *	socket_domain		adrm_short
 *	socket_type		adrm_short
 *	address_type		adrm_short
 *	local_port		adrm_short
 *	local_inaddr		adrm_u_char*address_type
 *	remote_port		adrm_short
 *	remote_inaddr		adrm_u_char*address_type
 *
 */
int
socket_ex_token(parse_context_t *ctx)
{
	short	ip_size;

	ctx->adr.adr_now += (2 * sizeof (short));
	adrm_short(&(ctx->adr), &ip_size, 1);

	ctx->adr.adr_now += sizeof (short) + (ip_size * sizeof (char)) +
	    sizeof (short) + (ip_size * sizeof (char));
	return (0);
}


static void
common_subject(parse_context_t *ctx)
{
	int32_t	ruid, rgid, pid;

	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_auid), 1);
	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_euid), 1);
	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_egid), 1);
	adrm_int32(&(ctx->adr), &ruid, 1);
	adrm_int32(&(ctx->adr), &rgid, 1);
	adrm_int32(&(ctx->adr), &pid, 1);
	adrm_u_int32(&(ctx->adr), (uint32_t *)&(ctx->out.sf_asid), 1);
}

/*
 * Format of subject32 token:
 *	subject token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid			adr_int32*2
 *
 */
int
subject32_token(parse_context_t *ctx)
{
	int32_t port;	/* not used in output */

	common_subject(ctx);

	adrm_int32(&(ctx->adr), &port, 1);
	ctx->out.sf_tid.at_type = AU_IPv4;
	adrm_u_char(&(ctx->adr), (uchar_t *)&(ctx->out.sf_tid.at_addr[0]), 4);

	return (0);
}

/*
 * Format of subject32_ex token:
 *	subject token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid
 *		port		adr_int32
 *		type		adr_int32
 *		ip address	adr_u_char*type
 *
 */
int
subject32_ex_token(parse_context_t *ctx)
{
	int32_t port;	/* not used in output */

	common_subject(ctx);

	adrm_int32(&(ctx->adr), &port, 1);
	adrm_u_int32(&(ctx->adr), &(ctx->out.sf_tid.at_type), 1);
	adrm_u_char(&(ctx->adr), (uchar_t *)&(ctx->out.sf_tid.at_addr[0]),
	    ctx->out.sf_tid.at_type);

	return (0);
}

/*
 * Format of subject64 token:
 *	subject token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid			adr_int64+adr_int32
 *
 */
int
subject64_token(parse_context_t *ctx)
{
	int64_t port;

	common_subject(ctx);

	adrm_int64(&(ctx->adr), &port, 1);
	ctx->out.sf_tid.at_type = AU_IPv4;
	adrm_u_char(&(ctx->adr), (uchar_t *)&(ctx->out.sf_tid.at_addr[0]), 4);

	return (0);
}

/*
 * Format of subject64_ex token:
 *	subject token id	adr_char
 *	auid			adr_int32
 *	euid			adr_int32
 *	egid 			adr_int32
 * 	ruid			adr_int32
 *	rgid			adr_int32
 * 	pid			adr_int32
 * 	sid			adr_int32
 * 	termid
 *		port		adr_int64
 *		type		adr_int32
 *		ip address	adr_u_char*type
 *
 */
int
subject64_ex_token(parse_context_t *ctx)
{
	int64_t port;

	common_subject(ctx);

	adrm_int64(&(ctx->adr), &port, 1);
	adrm_u_int32(&(ctx->adr), &(ctx->out.sf_tid.at_type), 1);
	adrm_u_char(&(ctx->adr), (uchar_t *)&(ctx->out.sf_tid.at_addr[0]),
	    ctx->out.sf_tid.at_type);

	return (0);
}


int
xatom_token(parse_context_t *ctx)
{
	skip_bytes(ctx);

	return (0);
}


int
xselect_token(parse_context_t *ctx)
{
	skip_bytes(ctx);
	skip_bytes(ctx);
	skip_bytes(ctx);

	return (0);
}

/*
 * anchor a path name with a slash
 * assume we have enough space
 */
static void
anchor_path(char *path)
{

	(void) memmove((void *)(path + 1), (void *)path, strlen(path) + 1);
	*path = '/';
}


/*
 * copy path to collapsed path.
 * collapsed path does not contain:
 *	successive slashes
 *	instances of dot-slash
 *	instances of dot-dot-slash
 * passed path must be anchored with a '/'
 */
static size_t
collapse_path(char *s, size_t ls)
{
	int	id;	/* index of where we are in destination string */
	int	is;	/* index of where we are in source string */
	int	slashseen;	/* have we seen a slash */

	ls++; /* source length including '\0' */

	slashseen = 0;
	for (is = 0, id = 0; is < ls; is++) {
		if (s[is] == '\0') {
			if (id > 1 && s[id-1] == '/') {
				--id;
			}
			s[id++] = '\0';
			break;
		}
		/* previous character was a / */
		if (slashseen) {
			if (s[is] == '/')
				continue;	/* another slash, ignore it */
		} else if (s[is] == '/') {
			/* we see a /, just copy it and try again */
			slashseen = 1;
			s[id++] = '/';
			continue;
		}
		/* /./ seen */
		if (s[is] == '.' && s[is+1] == '/') {
			is += 1;
			continue;
		}
		/* XXX/. seen */
		if (s[is] == '.' && s[is+1] == '\0') {
			if (id > 1)
				id--;
			continue;
		}
		/* XXX/.. seen */
		if (s[is] == '.' && s[is+1] == '.' && s[is+2] == '\0') {
			is += 1;
			if (id > 0)
				id--;
			while (id > 0 && s[--id] != '/')
				;
			id++;
			continue;
		}
		/* XXX/../ seen */
		if (s[is] == '.' && s[is+1] == '.' && s[is+2] == '/') {
			is += 2;
			if (id > 0)
				id--;
			while (id > 0 && s[--id] != '/')
				;
			id++;
			continue;
		}
		while (is < ls && (s[id++] = s[is++]) != '/')
			;
		is--;
	}
	return ((size_t)id - 1);
}

/*
 * for tokens with sub-fields that include a length, this
 * skips the sub-field.
 */

static void
skip_bytes(parse_context_t *ctx)
{
	ushort_t	c;

	adrm_u_short(&(ctx->adr), &c, 1);
	ctx->adr.adr_now += c;
}

static void
skip_string(parse_context_t *ctx)
{
	char	c;

	do {
		adrm_char(&(ctx->adr), &c, 1);
	} while (c != (char)0);
}

/*
 * add a byte to specified length so there can be a prefix of
 * '/' added (if needed for paths).  Another is added for '\0'
 *
 * if offset is zero, new data overwrites old, if any.  Otherwise
 * new data is appended to the end.
 */

static void
get_bytes_to_string(parse_context_t *ctx, size_t *l, char **p,
    size_t offset)
{
	ushort_t	len;
	char		*bp;

	adrm_u_short(&(ctx->adr), &len, 1);

	len++;	/* in case need to add '/' prefix */
	*p = realloc(*p, 1 + (size_t)len + offset);
	if (*p == NULL) {
		perror("audit_sysudp.so");
		return;
	}
	if (offset > 0)
		offset--;	/* overwrite end of string */

	*l = (size_t)len - 2 + offset;

	bp = *p + offset;
	adrm_char(&(ctx->adr), bp, len - 1);
	*(bp + len - 1) = '\0';
}


/*
 * Format of host token:
 *	host  		adr_uint32
 */
int
host_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (int32_t);

	return (0);
}

/*
 * Format of useofauth token:
 *	uauth token id		adr_char
 * 	uauth			adr_string
 *
 */
int
useofauth_token(parse_context_t *ctx)
{
	get_bytes_to_string(ctx, &(ctx->out.sf_uauthlen),
	    &(ctx->out.sf_uauth), 0);

	return (0);
}

/*
 * Format of user token:
 *	user token id		adr_char
 *	uid			adr_uid
 * 	username		adr_string
 *
 */
int
user_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (uid_t);
	skip_bytes(ctx);

	return (0);
}

/*
 * Format of zonename token:
 *	zonename token id		adr_char
 * 	zonename			adr_string
 *
 */
int
zonename_token(parse_context_t *ctx)
{
	get_bytes_to_string(ctx,
	    &(ctx->out.sf_zonelen),
	    &(ctx->out.sf_zonename),
	    0);

	return (0);
}

/*
 * Format of fmri token:
 *	fmri token id		adr_char
 *	fmri			adr_string
 */
int
fmri_token(parse_context_t *ctx)
{
	skip_bytes(ctx);

	return (0);
}

int
xcolormap_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}

int
xcursor_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}

int
xfont_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}

int
xgc_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}

int
xpixmap_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}

int
xwindow_token(parse_context_t *ctx)
{
	return (xgeneric(ctx));
}
/*
 * Format of xgeneric token:
 *	XID			adr_int32
 *	creator UID		adr_int32
 *
 * Includes:  xcolormap, xcursor, xfont, xgc, xpixmap, and xwindow
 */
static int
xgeneric(parse_context_t *ctx)
{
	ctx->adr.adr_now += 2 * sizeof (int32_t);

	return (0);
}
/*
 * Format of xproperty token:
 *	XID			adr_int32
 *	creator UID		adr_int32
 *	atom string		adr_string
 */
int
xproperty_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += 2 * sizeof (int32_t);

	return (0);
}
/*
 * Format of xclient token:
 * 	xclient id		adr_int32
 */
int
xclient_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (int32_t);

	return (0);
}

/*
 * -----------------------------------------------------------------------
 * privilege_token()	: Process privilege token and display contents
 *
 * Format of privilege token:
 *	privilege token id	adr_char
 *	privilege type		adr_string
 *	privilege		adr_string
 * -----------------------------------------------------------------------
 */

int
privilege_token(parse_context_t *ctx)
{
	skip_bytes(ctx);
	skip_bytes(ctx);

	return (0);
}

/*
 * -----------------------------------------------------------------------
 * secflags_token()	: Process secflags token and display contents
 *
 * Format of privilege token:
 *	secflags token id	adr_char
 *	secflag set name	adr_string
 *	secflags		adr_string
 * -----------------------------------------------------------------------
 */
int
secflags_token(parse_context_t *ctx)
{
	skip_bytes(ctx);
	skip_bytes(ctx);

	return (0);
}

/*
 * Format of label token:
 *	label ID                1 byte
 *	compartment length      1 byte
 *	classification          2 bytes
 *	compartment words       <compartment length> * 4 bytes
 */
int
label_token(parse_context_t *ctx)
{
	char	c;

	ctx->adr.adr_now += sizeof (char);	/* label ID */
	adrm_char(&(ctx->adr), &c, 1);

	ctx->adr.adr_now += sizeof (ushort_t);	/* classification */
	ctx->adr.adr_now += 4 * c;		/* compartments */

	return (0);
}

/*
 * Format of useofpriv token:
 *	priv_type			adr_char
 *	priv_set_t			adr_short
 *	priv_set			adr_char*(sizeof (priv_set_t))
 */
int
useofpriv_token(parse_context_t *ctx)
{
	ctx->adr.adr_now += sizeof (char); /* success / fail */
	skip_bytes(ctx);

	return (0);
}
