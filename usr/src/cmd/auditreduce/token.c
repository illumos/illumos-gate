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
 * Token processing for auditreduce.
 */

#include <locale.h>
#include <sys/zone.h>
#include "auditr.h"
#include "toktable.h"

extern int	re_exec2(char *);

static void	anchor_path(char *path);
static char	*collapse_path(char *s);
static void	get_string(adr_t *adr, char **p);
static int	ipc_type_match(int flag, char type);
static void	skip_string(adr_t *adr);
static int	xgeneric(adr_t *adr);

#if	AUDIT_REC
void
print_id(int id)
{
	char *suffix;

	if ((id < 0) || (id > MAXTOKEN) ||
	    (tokentable[id].func == NOFUNC)) {
		(void) fprintf(stderr,
		    "token_processing: token %d not found\n", id);
		return;
	}

	switch (id) {
	case AUT_NEWGROUPS:
		suffix = "_new";
		break;
	case AUT_ATTR32:
		suffix = "32";
		break;
	case AUT_ARG64:
	case AUT_RETURN64:
	case AUT_ATTR64:
	case AUT_HEADER64:
	case AUT_SUBJECT64:
	case AUT_PROCESS64:
	case AUT_OTHER_FILE64:
		suffix = "64";
		break;
	case AUT_SOCKET_EX:
	case AUT_IN_ADDR_EX:
		suffix = "_ex";
		break;
	case AUT_HEADER32_EX:
	case AUT_SUBJECT32_EX:
	case AUT_PROCESS32_EX:
		suffix = "32_ex";
		break;
	case AUT_HEADER64_EX:
	case AUT_SUBJECT64_EX:
	case AUT_PROCESS64_EX:
		suffix = "64_ex";
		break;
	default:
		suffix = "";
		break;
	}
	(void) fprintf(stderr, "token_processing: %s%s\n",
	    tokentable[id].t_name, suffix);
}
#endif	/* AUDIT_REC */

/*
 * Process a token in a record to determine whether the record is interesting.
 */

int
token_processing(adr_t *adr, int tokenid)
{
	if ((tokenid > 0) && (tokenid <= MAXTOKEN) &&
	    (tokentable[tokenid].func != NOFUNC)) {
#if	AUDIT_REC
		print_id(tokenid);
#endif	/* AUDIT_REC */
		return ((*tokentable[tokenid].func)(adr));
	}

	/* here if token id is not in table */
	return (-2);
}


/* There should not be any file or header tokens in the middle of a record */

/* ARGSUSED */
int
file_token(adr_t *adr)
{
	return (-2);
}

/* ARGSUSED */
int
file64_token(adr_t *adr)
{
	return (-2);
}

/* ARGSUSED */
int
header_token(adr_t *adr)
{
	return (-2);
}

/* ARGSUSED */
int
header32_ex_token(adr_t *adr)
{
	return (-2);
}

/* ARGSUSED */
int
header64_ex_token(adr_t *adr)
{
	return (-2);
}

/* ARGSUSED */
int
header64_token(adr_t *adr)
{
	return (-2);
}


/*
 * ======================================================
 *  The following token processing routines return
 *  -1: if the record is not interesting
 *  -2: if an error is found
 * ======================================================
 */

int
trailer_token(adr_t *adr)
{
	short	magic_number;
	uint32_t bytes;

	adrm_u_short(adr, (ushort_t *)&magic_number, 1);
	if (magic_number != AUT_TRAILER_MAGIC) {
		(void) fprintf(stderr, "%s\n",
		    gettext("auditreduce: Bad trailer token"));
		return (-2);
	}
	adrm_u_int32(adr, &bytes, 1);

	return (-1);
}


/*
 * Format of arbitrary data token:
 *	arbitrary data token id	adr char
 * 	how to print		adr_char
 *	basic unit		adr_char
 *	unit count		adr_char, specifying number of units of
 *	data items		depends on basic unit
 */
int
arbitrary_data_token(adr_t *adr)
{
	int	i;
	char	c1;
	short	c2;
	int32_t	c3;
	int64_t c4;
	char	how_to_print, basic_unit, unit_count;

	/* get how_to_print, basic_unit, and unit_count */
	adrm_char(adr, &how_to_print, 1);
	adrm_char(adr, &basic_unit, 1);
	adrm_char(adr, &unit_count, 1);
	for (i = 0; i < unit_count; i++) {
		switch (basic_unit) {
			/* case AUR_BYTE: has same value as AUR_CHAR */
		case AUR_CHAR:
			adrm_char(adr, &c1, 1);
			break;
		case AUR_SHORT:
			adrm_short(adr, &c2, 1);
			break;
		case AUR_INT32:
			adrm_int32(adr, (int32_t *)&c3, 1);
			break;
		case AUR_INT64:
			adrm_int64(adr, (int64_t *)&c4, 1);
			break;
		default:
			return (-2);
		}
	}
	return (-1);
}


/*
 * Format of opaque token:
 *	opaque token id		adr_char
 *	size			adr_short
 *	data			adr_char, size times
 */
int
opaque_token(adr_t *adr)
{
	skip_string(adr);
	return (-1);
}



/*
 * Format of return32 value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_u_int32
 */
int
return_value32_token(adr_t *adr)
{
	char		errnum;
	uint32_t	value;

	adrm_char(adr, &errnum, 1);
	adrm_u_int32(adr, &value, 1);
	if ((flags & M_SORF) &&
	    ((global_class & mask.am_success) && (errnum == 0)) ||
	    ((global_class & mask.am_failure) && (errnum != 0))) {
		checkflags |= M_SORF;
	}
	return (-1);
}

/*
 * Format of return64 value token:
 * 	return value token id	adr_char
 *	error number		adr_char
 *	return value		adr_u_int64
 */
int
return_value64_token(adr_t *adr)
{
	char		errnum;
	uint64_t	value;

	adrm_char(adr, &errnum, 1);
	adrm_u_int64(adr, &value, 1);
	if ((flags & M_SORF) &&
	    ((global_class & mask.am_success) && (errnum == 0)) ||
	    ((global_class & mask.am_failure) && (errnum != 0))) {
		checkflags |= M_SORF;
	}
	return (-1);
}


/*
 * Format of sequence token:
 *	sequence token id	adr_char
 *	audit_count		int32_t
 */
int
sequence_token(adr_t *adr)
{
	int32_t	audit_count;

	adrm_int32(adr, &audit_count, 1);
	return (-1);
}


/*
 * Format of text token:
 *	text token id		adr_char
 * 	text			adr_string
 */
int
text_token(adr_t *adr)
{
	skip_string(adr);
	return (-1);
}


/*
 * Format of ip_addr token:
 *	ip token id	adr_char
 *	address		adr_int32
 */
int
ip_addr_token(adr_t *adr)
{
	int32_t	address;

	adrm_char(adr, (char *)&address, 4);

	return (-1);
}

/*
 * Format of ip_addr_ex token:
 *	ip token id	adr_char
 *	ip type		adr_int32
 *	ip address	adr_u_char*type
 */
int
ip_addr_ex_token(adr_t *adr)
{
	int32_t type;
	uchar_t	address[16];

	adrm_int32(adr, (int32_t *)&type, 1);
	adrm_u_char(adr, address, type);

	return (-1);
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
 */
int
ip_token(adr_t *adr)
{
	char	version;
	char	type;
	short	len;
	unsigned short	id, offset, checksum;
	char	ttl, protocol;
	int32_t	src, dest;

	adrm_char(adr, &version, 1);
	adrm_char(adr, &type, 1);
	adrm_short(adr, &len, 1);
	adrm_u_short(adr, &id, 1);
	adrm_u_short(adr, &offset, 1);
	adrm_char(adr, &ttl, 1);
	adrm_char(adr, &protocol, 1);
	adrm_u_short(adr, &checksum, 1);
	adrm_char(adr, (char *)&src, 4);
	adrm_char(adr, (char *)&dest, 4);

	return (-1);
}


/*
 * Format of iport token:
 *	ip port address token id	adr_char
 *	port address			adr_short
 */
int
iport_token(adr_t *adr)
{
	short	address;

	adrm_short(adr, &address, 1);

	return (-1);
}


/*
 * Format of groups token:
 *	group token id		adr_char
 *	group list		adr_int32, 16 times
 */
int
group_token(adr_t *adr)
{
	int	gid[16];
	int	i;
	int	flag = 0;

	for (i = 0; i < 16; i++) {
		adrm_int32(adr, (int32_t *)&gid[i], 1);
		if (flags & M_GROUPR) {
			if ((unsigned short)m_groupr == gid[i])
				flag = 1;
		}
	}

	if (flags & M_GROUPR) {
		if (flag)
			checkflags |= M_GROUPR;
	}
	return (-1);
}

/*
 * Format of newgroups token:
 *	group token id		adr_char
 *	number of groups	adr_short
 *	group list		adr_int32, "number" times
 */
int
newgroup_token(adr_t *adr)
{
	gid_t	gid;
	int	i;
	short int   number;

	adrm_short(adr, &number, 1);

	for (i = 0; i < number; i++) {
		adrm_int32(adr, (int32_t *)&gid, 1);
		if (flags & M_GROUPR) {
			if (m_groupr == gid)
				checkflags |= M_GROUPR;
		}
	}

	return (-1);
}

/*
 * Format of argument32 token:
 *	argument token id	adr_char
 *	argument number		adr_char
 *	argument value		adr_int32
 *	argument description	adr_string
 */
int
argument32_token(adr_t *adr)
{
	char	arg_num;
	int32_t	arg_val;

	adrm_char(adr, &arg_num, 1);
	adrm_int32(adr, &arg_val, 1);
	skip_string(adr);

	return (-1);
}

/*
 * Format of argument64 token:
 *	argument token id	adr_char
 *	argument number		adr_char
 *	argument value		adr_int64
 *	argument description	adr_string
 */
int
argument64_token(adr_t *adr)
{
	char	arg_num;
	int64_t	arg_val;

	adrm_char(adr, &arg_num, 1);
	adrm_int64(adr, &arg_val, 1);
	skip_string(adr);

	return (-1);
}

/*
 * Format of acl token:
 *	acl token id		adr_char
 *	acl type		adr_u_int32
 *	acl value		adr_u_int32 (depends on type)
 *	file mode		adr_u_int (in octal)
 */
int
acl_token(adr_t *adr)
{

	int32_t	id;
	int32_t	mode;
	int32_t	type;

	adrm_int32(adr, &type, 1);
	adrm_int32(adr, &id, 1);
	adrm_int32(adr, &mode, 1);

	return (-1);
}

/*
 * Format of ace token:
 *	ace token id		adr_char
 *	ace who			adr_u_int32 (uid/gid)
 *	access mask		adr_u_int32
 *	ace flags		adr_u_int16
 *	ace type		adr_u_int16
 */
int
ace_token(adr_t *adr)
{
	uid_t		who;
	uint32_t	access_mask;
	uint16_t	flags, type;

	adrm_uid(adr, &who, 1);
	adrm_u_int32(adr, &access_mask, 1);
	adrm_u_short(adr, &flags, 1);
	adrm_u_short(adr, &type, 1);

	return (-1);
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
 */
int
attribute_token(adr_t *adr)
{
	int32_t	dev;
	int32_t	file_sysid;
	int32_t	gid;
	int32_t	mode;
	int32_t	nodeid;
	int32_t	uid;

	adrm_int32(adr, &mode, 1);
	adrm_int32(adr, &uid, 1);
	adrm_int32(adr, &gid, 1);
	adrm_int32(adr, &file_sysid, 1);
	adrm_int32(adr, &nodeid, 1);
	adrm_int32(adr, &dev, 1);

	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == uid)
			checkflags |= M_USERE;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == gid)
			checkflags |= M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_FGROUP) &&
		    (obj_group == gid))
			checkflags |= M_OBJECT;
		else if ((obj_flag & OBJ_FOWNER) &&
		    (obj_owner == uid))
			checkflags |= M_OBJECT;
	}
	return (-1);
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
 */
int
attribute32_token(adr_t *adr)
{
	int32_t	dev;
	int32_t	file_sysid;
	int32_t	gid;
	int32_t	mode;
	int64_t	nodeid;
	int32_t	uid;

	adrm_int32(adr, &mode, 1);
	adrm_int32(adr, &uid, 1);
	adrm_int32(adr, &gid, 1);
	adrm_int32(adr, &file_sysid, 1);
	adrm_int64(adr, &nodeid, 1);
	adrm_int32(adr, &dev, 1);

	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == uid)
			checkflags |= M_USERE;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == gid)
			checkflags |= M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_FGROUP) &&
		    (obj_group == gid))
			checkflags |= M_OBJECT;
		else if ((obj_flag & OBJ_FOWNER) &&
		    (obj_owner == uid))
			checkflags |= M_OBJECT;
	}
	return (-1);
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
 */
int
attribute64_token(adr_t *adr)
{
	int64_t	dev;
	int32_t	file_sysid;
	int32_t	gid;
	int32_t	mode;
	int64_t	nodeid;
	int32_t	uid;

	adrm_int32(adr, &mode, 1);
	adrm_int32(adr, &uid, 1);
	adrm_int32(adr, &gid, 1);
	adrm_int32(adr, &file_sysid, 1);
	adrm_int64(adr, &nodeid, 1);
	adrm_int64(adr, &dev, 1);

	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == uid)
			checkflags |= M_USERE;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == gid)
			checkflags |= M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_FGROUP) &&
		    (obj_group == gid))
			checkflags |= M_OBJECT;
		else if ((obj_flag & OBJ_FOWNER) &&
		    (obj_owner == uid))
			checkflags |= M_OBJECT;
	}
	return (-1);
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
 */
int
cmd_token(adr_t *adr)
{
	short	cnt;
	short	i;

	adrm_short(adr, &cnt, 1);

	for (i = 0; i < cnt; i++)
		skip_string(adr);

	adrm_short(adr, &cnt, 1);

	for (i = 0; i < cnt; i++)
		skip_string(adr);

	return (-1);
}


/*
 * Format of exit token:
 *	attribute token id	adr_char
 *	return value		adr_int32
 *	errno			adr_int32
 */
int
exit_token(adr_t *adr)
{
	int32_t	retval;
	int32_t	errno;

	adrm_int32(adr, &retval, 1);
	adrm_int32(adr, &errno, 1);
	return (-1);
}

/*
 * Format of strings array token:
 *	token id		adr_char
 *	count value		adr_int32
 *	strings			null terminated strings
 */
static int
strings_common_token(adr_t *adr)
{
	int count, i;
	char c;

	adrm_int32(adr, (int32_t *)&count, 1);
	for (i = 1; i <= count; i++) {
		adrm_char(adr, &c, 1);
		while (c != (char)0)
			adrm_char(adr, &c, 1);
	}
	/* no dump option here, since we will have variable length fields */
	return (-1);
}

int
path_attr_token(adr_t *adr)
{
	return (strings_common_token(adr));
}

int
exec_args_token(adr_t *adr)
{
	return (strings_common_token(adr));
}

int
exec_env_token(adr_t *adr)
{
	return (strings_common_token(adr));
}

/*
 * Format of liaison token:
 */
int
liaison_token(adr_t *adr)
{
	int32_t	li;

	adrm_int32(adr, &li, 1);
	return (-1);
}


/*
 * Format of path token:
 *	path				adr_string
 */
int
path_token(adr_t *adr)
{
	if ((flags & M_OBJECT) && (obj_flag == OBJ_PATH)) {
		char *path;

		get_string(adr, &path);
		if (path[0] != '/')
			/*
			 * anchor the path. user apps may not do it.
			 */
			anchor_path(path);
		/*
		 * match against the collapsed path. that is what user sees.
		 */
		if (re_exec2(collapse_path(path)) == 1)
			checkflags |= M_OBJECT;
		free(path);
	} else {
		skip_string(adr);
	}
	return (-1);
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
s5_IPC_perm_token(adr_t *adr)
{
	int32_t	uid, gid, cuid, cgid, mode, seq;
	int32_t	key;

	adrm_int32(adr, &uid, 1);
	adrm_int32(adr, &gid, 1);
	adrm_int32(adr, &cuid, 1);
	adrm_int32(adr, &cgid, 1);
	adrm_int32(adr, &mode, 1);
	adrm_int32(adr, &seq, 1);
	adrm_int32(adr, &key, 1);

	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == uid)
			checkflags |= M_USERE;
	}

	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == cuid)
			checkflags |= M_USERE;
	}

	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == gid)
			checkflags |= M_GROUPR;
	}

	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == cgid)
			checkflags |= M_GROUPR;
	}

	if ((flags & M_OBJECT) &&
	    ((obj_owner == uid) ||
	    (obj_owner == cuid) ||
	    (obj_group == gid) ||
	    (obj_group == cgid))) {

		switch (obj_flag) {
		case OBJ_MSGGROUP:
		case OBJ_MSGOWNER:
			if (ipc_type_match(OBJ_MSG, ipc_type))
				checkflags |= M_OBJECT;
			break;
		case OBJ_SEMGROUP:
		case OBJ_SEMOWNER:
			if (ipc_type_match(OBJ_SEM, ipc_type))
				checkflags |= M_OBJECT;
			break;
		case OBJ_SHMGROUP:
		case OBJ_SHMOWNER:
			if (ipc_type_match(OBJ_SHM, ipc_type))
				checkflags |= M_OBJECT;
			break;
		}
	}
	return (-1);
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
 */
int
process32_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int32_t port, machine;

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int32(adr, &port, 1);
	adrm_int32(adr, &machine, 1);

	if (!new_mode && (flags & M_USERA)) {
		if (m_usera == auid)
			checkflags |= M_USERA;
	}
	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == euid)
			checkflags |= M_USERE;
	}
	if (!new_mode && (flags & M_USERR)) {
		if (m_userr == ruid)
			checkflags |= M_USERR;
	}
	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == rgid)
			checkflags |= M_GROUPR;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == egid)
			checkflags |= M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_PROC) &&
		    (obj_id == pid)) {
			checkflags |= M_OBJECT;
		} else if ((obj_flag & OBJ_PGROUP) &&
		    ((obj_group == egid) ||
		    (obj_group == rgid))) {
			checkflags |= M_OBJECT;
		} else if ((obj_flag & OBJ_POWNER) &&
		    ((obj_owner == euid) ||
		    (obj_group == ruid))) {
			checkflags |= M_OBJECT;
		}
	}
	return (-1);
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
 */
int
process32_ex_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int32_t port, type;
	uchar_t addr[16];

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int32(adr, &port, 1);
	adrm_int32(adr, &type, 1);
	adrm_u_char(adr, addr, type);

	if (!new_mode && (flags & M_USERA)) {
		if (m_usera == auid)
			checkflags = checkflags | M_USERA;
	}
	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == euid)
			checkflags = checkflags | M_USERE;
	}
	if (!new_mode && (flags & M_USERR)) {
		if (m_userr == ruid)
			checkflags = checkflags | M_USERR;
	}
	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == egid)
			checkflags = checkflags | M_GROUPR;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == egid)
			checkflags = checkflags | M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_PROC) &&
		    (obj_id == pid)) {
			checkflags = checkflags | M_OBJECT;
		} else if ((obj_flag & OBJ_PGROUP) &&
		    ((obj_group == egid) ||
		    (obj_group == rgid))) {
			checkflags = checkflags | M_OBJECT;
		} else if ((obj_flag & OBJ_POWNER) &&
		    ((obj_owner == euid) ||
		    (obj_group == ruid))) {
			checkflags = checkflags | M_OBJECT;
		}
	}
	return (-1);
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
 */
int
process64_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int64_t port;
	int32_t machine;

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int64(adr, &port, 1);
	adrm_int32(adr, &machine, 1);

	if (!new_mode && (flags & M_USERA)) {
		if (m_usera == auid)
			checkflags |= M_USERA;
	}
	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == euid)
			checkflags |= M_USERE;
	}
	if (!new_mode && (flags & M_USERR)) {
		if (m_userr == ruid)
			checkflags |= M_USERR;
	}
	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == rgid)
			checkflags |= M_GROUPR;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == egid)
			checkflags |= M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_PROC) &&
		    (obj_id == pid)) {
			checkflags |= M_OBJECT;
		} else if ((obj_flag & OBJ_PGROUP) &&
		    ((obj_group == egid) ||
		    (obj_group == rgid))) {
			checkflags |= M_OBJECT;
		} else if ((obj_flag & OBJ_POWNER) &&
		    ((obj_owner == euid) ||
		    (obj_group == ruid))) {
			checkflags |= M_OBJECT;
		}
	}
	return (-1);
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
 * 		port		adr_int64
 * 		type		adr_int32
 * 		ip address	adr_u_char*type
 */
int
process64_ex_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int64_t port;
	int32_t type;
	uchar_t addr[16];

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int64(adr, &port, 1);
	adrm_int32(adr, &type, 1);
	adrm_u_char(adr, addr, type);

	if (!new_mode && (flags & M_USERA)) {
		if (m_usera == auid)
			checkflags = checkflags | M_USERA;
	}
	if (!new_mode && (flags & M_USERE)) {
		if (m_usere == euid)
			checkflags = checkflags | M_USERE;
	}
	if (!new_mode && (flags & M_USERR)) {
		if (m_userr == ruid)
			checkflags = checkflags | M_USERR;
	}
	if (!new_mode && (flags & M_GROUPR)) {
		if (m_groupr == egid)
			checkflags = checkflags | M_GROUPR;
	}
	if (!new_mode && (flags & M_GROUPE)) {
		if (m_groupe == egid)
			checkflags = checkflags | M_GROUPE;
	}

	if (flags & M_OBJECT) {
		if ((obj_flag & OBJ_PROC) &&
		    (obj_id == pid)) {
			checkflags = checkflags | M_OBJECT;
		} else if ((obj_flag & OBJ_PGROUP) &&
		    ((obj_group == egid) ||
		    (obj_group == rgid))) {
			checkflags = checkflags | M_OBJECT;
		} else if ((obj_flag & OBJ_POWNER) &&
		    ((obj_owner == euid) ||
		    (obj_group == ruid))) {
			checkflags = checkflags | M_OBJECT;
		}
	}
	return (-1);
}

/*
 * Format of System V IPC token:
 *	System V IPC token id	adr_char
 *	object id		adr_int32
 */
int
s5_IPC_token(adr_t *adr)
{
	int32_t	ipc_id;

	adrm_char(adr, &ipc_type, 1);	/* Global */
	adrm_int32(adr, &ipc_id, 1);

	if ((flags & M_OBJECT) &&
	    ipc_type_match(obj_flag, ipc_type) &&
	    (obj_id == ipc_id))
		checkflags |= M_OBJECT;

	return (-1);
}


/*
 * Format of socket token:
 *	socket_type		adrm_short
 *	remote_port		adrm_short
 *	remote_inaddr		adrm_int32
 */
int
socket_token(adr_t *adr)
{
	short	socket_type;
	short	remote_port;
	int32_t	remote_inaddr;

	adrm_short(adr, &socket_type, 1);
	adrm_short(adr, &remote_port, 1);
	adrm_char(adr, (char *)&remote_inaddr, 4);

	if ((flags & M_OBJECT) && (obj_flag == OBJ_SOCK)) {
		if (socket_flag == SOCKFLG_MACHINE) {
			if (remote_inaddr == obj_id)
				checkflags |= M_OBJECT;
		} else if (socket_flag == SOCKFLG_PORT) {
			if (remote_port == obj_id)
				checkflags |= M_OBJECT;
		}
	}
	return (-1);
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
 */
int
socket_ex_token(adr_t *adr)
{
	short	socket_domain;
	short	socket_type;
	short	ip_size;
	short	local_port;
	uchar_t	local_inaddr[16];
	short	remote_port;
	uchar_t	remote_inaddr[16];
	uchar_t	*caddr = (uchar_t *)&obj_id;

	adrm_short(adr, &socket_domain, 1);
	adrm_short(adr, &socket_type, 1);
	adrm_short(adr, &ip_size, 1);

	/* validate ip size */
	if ((ip_size != AU_IPv6) && (ip_size != AU_IPv4))
		return (0);

	adrm_short(adr, &local_port, 1);
	adrm_char(adr, (char *)local_inaddr, ip_size);

	adrm_short(adr, &remote_port, 1);
	adrm_char(adr, (char *)remote_inaddr, ip_size);

	/* if IP type mis-match, then nothing to do */
	if (ip_size != ip_type)
		return (-1);

	if ((flags & M_OBJECT) && (obj_flag == OBJ_SOCK)) {
		if (socket_flag == SOCKFLG_MACHINE) {
			if (ip_type == AU_IPv6) {
				caddr = (uchar_t *)ip_ipv6;
			}
			if ((memcmp(local_inaddr, caddr, ip_type) == 0) ||
			    (memcmp(remote_inaddr, caddr, ip_type) == 0)) {
				checkflags |= M_OBJECT;
			}
		} else if (socket_flag == SOCKFLG_PORT) {
			if ((local_port == obj_id) || (remote_port == obj_id)) {
				checkflags |= M_OBJECT;
			}
		}
	}
	return (-1);
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
 */
int
subject32_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int32_t port, machine;

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int32(adr, &port, 1);
	adrm_int32(adr, &machine, 1);

	if (flags & M_SUBJECT) {
		if (subj_id == pid)
			checkflags |= M_SUBJECT;
	}
	if (flags & M_USERA) {
		if (m_usera == auid)
			checkflags |= M_USERA;
	}
	if (flags & M_USERE) {
		if (m_usere == euid)
			checkflags |= M_USERE;
	}
	if (flags & M_USERR) {
		if (m_userr == ruid)
			checkflags |= M_USERR;
	}
	if (flags & M_GROUPR) {
		if (m_groupr == rgid)
			checkflags |= M_GROUPR;
	}
	if (flags & M_GROUPE) {
		if (m_groupe == egid)
			checkflags |= M_GROUPE;
	}
	if (flags & M_SID) {
		if (m_sid == (au_asid_t)sid)
			checkflags |= M_SID;
	}
	return (-1);
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
 * 		port		adr_int32
 * 		type		adr_int32
 * 		ip address	adr_u_char*type
 */
int
subject32_ex_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int32_t port, type;
	uchar_t addr[16];

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int32(adr, &port, 1);
	adrm_int32(adr, &type, 1);
	adrm_u_char(adr, addr, type);

	if (flags & M_SUBJECT) {
		if (subj_id == pid)
			checkflags = checkflags | M_SUBJECT;
	}
	if (flags & M_USERA) {
		if (m_usera == auid)
			checkflags = checkflags | M_USERA;
	}
	if (flags & M_USERE) {
		if (m_usere == euid)
			checkflags = checkflags | M_USERE;
	}
	if (flags & M_USERR) {
		if (m_userr == ruid)
			checkflags = checkflags | M_USERR;
	}
	if (flags & M_GROUPR) {
		if (m_groupr == egid)
			checkflags = checkflags | M_GROUPR;
	}
	if (flags & M_GROUPE) {
		if (m_groupe == egid)
			checkflags = checkflags | M_GROUPE;
	}
	if (flags & M_SID) {
		if (m_sid == (au_asid_t)sid)
			checkflags = checkflags | M_SID;
	}
	return (-1);
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
 */
int
subject64_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int64_t port;
	int32_t machine;

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int64(adr, &port, 1);
	adrm_int32(adr, &machine, 1);

	if (flags & M_SUBJECT) {
		if (subj_id == pid)
			checkflags |= M_SUBJECT;
	}
	if (flags & M_USERA) {
		if (m_usera == auid)
			checkflags |= M_USERA;
	}
	if (flags & M_USERE) {
		if (m_usere == euid)
			checkflags |= M_USERE;
	}
	if (flags & M_USERR) {
		if (m_userr == ruid)
			checkflags |= M_USERR;
	}
	if (flags & M_GROUPR) {
		if (m_groupr == rgid)
			checkflags |= M_GROUPR;
	}
	if (flags & M_GROUPE) {
		if (m_groupe == egid)
			checkflags |= M_GROUPE;
	}
	if (flags & M_SID) {
		if (m_sid == (au_asid_t)sid)
			checkflags |= M_SID;
	}
	return (-1);
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
 * 		port		adr_int64
 * 		type		adr_int32
 * 		ip address	adr_u_char*type
 */
int
subject64_ex_token(adr_t *adr)
{
	int32_t	auid, euid, egid, ruid, rgid, pid;
	int32_t	sid;
	int64_t port;
	int32_t type;
	uchar_t	addr[16];

	adrm_int32(adr, &auid, 1);
	adrm_int32(adr, &euid, 1);
	adrm_int32(adr, &egid, 1);
	adrm_int32(adr, &ruid, 1);
	adrm_int32(adr, &rgid, 1);
	adrm_int32(adr, &pid, 1);
	adrm_int32(adr, &sid, 1);
	adrm_int64(adr, &port, 1);
	adrm_int32(adr, &type, 1);
	adrm_u_char(adr, addr, type);

	if (flags & M_SUBJECT) {
		if (subj_id == pid)
			checkflags = checkflags | M_SUBJECT;
	}
	if (flags & M_USERA) {
		if (m_usera == auid)
			checkflags = checkflags | M_USERA;
	}
	if (flags & M_USERE) {
		if (m_usere == euid)
			checkflags = checkflags | M_USERE;
	}
	if (flags & M_USERR) {
		if (m_userr == ruid)
			checkflags = checkflags | M_USERR;
	}
	if (flags & M_GROUPR) {
		if (m_groupr == egid)
			checkflags = checkflags | M_GROUPR;
	}
	if (flags & M_GROUPE) {
		if (m_groupe == egid)
			checkflags = checkflags | M_GROUPE;
	}
	if (flags & M_SID) {
		if (m_sid == (au_asid_t)sid)
			checkflags = checkflags | M_SID;
	}
	return (-1);
}

/*
 * -----------------------------------------------------------------------
 * tid_token(): Process tid token and display contents
 *
 * Format of tid token:
 *	tid token id			adr_char
 * 	address type			adr_char
 *	For address type of AU_IPADR...
 *		remote port		adr_short
 *		local port		adr_short
 *		IP type			adr_int32
 *		IP addr			adr_int32 if IPv4
 *		IP addr			4 x adr_int32 if IPv6
 * address types other than AU_IPADR are not yet defined
 * -----------------------------------------------------------------------
 */
int
tid_token(adr_t *adr)
{
	int32_t	address[4];
	int32_t	ip_type;
	char	tid_type;
	short	rport;
	short	lport;

	adrm_char(adr, &tid_type, 1);
	switch (tid_type) {
	case AU_IPADR:
		adrm_short(adr, &rport, 1);
		adrm_short(adr, &lport, 1);
		adrm_int32(adr, &ip_type, 1);
		adrm_char(adr, (char *)&address, ip_type);
		break;
	default:
		return (0);
	}
	return (-1);
}

/*
 * -----------------------------------------------------------------------
 * zonename_token(): Process zonename token and display contents
 *
 * Format of zonename token:
 *	zonename token id		adr_char
 * 	zone name			adr_string
 * -----------------------------------------------------------------------
 */
int
zonename_token(adr_t *adr)
{
	char	*name;

	if (flags & M_ZONENAME) {
		get_string(adr, &name);
		if (strncmp(zonename, name, ZONENAME_MAX) == 0)
			checkflags |= M_ZONENAME;
		free(name);
	} else {
		skip_string(adr);
	}
	return (-1);
}

/*
 * fmri_token():
 *
 * Format of fmri token:
 * 	fmri				adr_string
 */
int
fmri_token(adr_t *adr)
{
	if ((flags & M_OBJECT) && (obj_flag == OBJ_FMRI)) {
		char	*fmri_name;

		get_string(adr, &fmri_name);

		/* match token against service instance */
		if (scf_cmp_pattern(fmri_name, &fmri) == 1) {
			checkflags |= M_OBJECT;
		}
		free(fmri_name);
	} else {
		skip_string(adr);
	}
	return (-1);
}

/*
 * Format of xatom token:
 */
int
xatom_token(adr_t *adr)
{
	skip_string(adr);

	return (-1);
}

/*
 * Format of xselect token:
 */
int
xselect_token(adr_t *adr)
{
	skip_string(adr);
	skip_string(adr);
	skip_string(adr);

	return (-1);
}

/*
 * anchor a path name with a slash
 * assume we have enough space
 */
void
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
char *
collapse_path(char *s)
{
	int	id;	/* index of where we are in destination string */
	int	is;	/* index of where we are in source string */
	int	slashseen;	/* have we seen a slash */
	int	ls;		/* length of source string */

	ls = strlen(s) + 1;

	slashseen = 0;
	for (is = 0, id = 0; is < ls; is++) {
		/* thats all folks, we've reached the end of input */
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
	return (s);
}


int
ipc_type_match(int flag, char type)
{
	if (flag == OBJ_SEM && type == AT_IPC_SEM)
		return (1);

	if (flag == OBJ_MSG && type == AT_IPC_MSG)
		return (1);

	if (flag == OBJ_SHM && type == AT_IPC_SHM)
		return (1);

	return (0);
}


void
skip_string(adr_t *adr)
{
	ushort_t	c;

	adrm_u_short(adr, &c, 1);
	adr->adr_now += c;
}


void
get_string(adr_t *adr, char **p)
{
	ushort_t	c;

	adrm_u_short(adr, &c, 1);
	*p = a_calloc(1, (size_t)c);
	adrm_char(adr, *p, c);
}


/*
 * Format of host token:
 *	host  		ard_uint32
 */
int
host_token(adr_t *adr)
{
	uint32_t host;

	adrm_u_int32(adr, &host, 1);

	return (-1);
}

/*
 * Format of useofauth token:
 *	uauth token id		adr_char
 * 	uauth			adr_string
 */
int
useofauth_token(adr_t *adr)
{
	skip_string(adr);
	return (-1);
}

/*
 * Format of user token:
 *	user token id		adr_char
 *	uid			adr_uid
 * 	username		adr_string
 */
int
user_token(adr_t *adr)
{
	uid_t	uid;

	adrm_uid(adr, &uid, 1);
	skip_string(adr);

	if ((flags & M_OBJECT) && (obj_flag == OBJ_USER) &&
	    (uid == obj_user)) {
		checkflags |= M_OBJECT;
	}

	return (-1);
}

int
xcolormap_token(adr_t *adr)
{
	return (xgeneric(adr));
}

int
xcursor_token(adr_t *adr)
{
	return (xgeneric(adr));
}

int
xfont_token(adr_t *adr)
{
	return (xgeneric(adr));
}

int
xgc_token(adr_t *adr)
{
	return (xgeneric(adr));
}

int
xpixmap_token(adr_t *adr)
{
	return (xgeneric(adr));
}

int
xwindow_token(adr_t *adr)
{
	return (xgeneric(adr));
}


/*
 * Format of xgeneric token:
 *	XID			adr_int32
 *	creator UID		adr_int32
 *
 * Includes:  xcolormap, xcursor, xfont, xgc, xpixmap, and xwindow
 */
int
xgeneric(adr_t *adr)
{
	int32_t xid;
	int32_t uid;

	adrm_int32(adr, &xid, 1);
	adrm_int32(adr, &uid, 1);

	if (flags & M_USERE) {
		if (m_usere == uid)
			checkflags = checkflags | M_USERE;
	}

	return (-1);
}


/*
 * Format of xproperty token:
 *	XID			adr_int32
 *	creator UID		adr_int32
 *	atom string		adr_string
 */
int
xproperty_token(adr_t *adr)
{
	int32_t	xid;
	int32_t uid;

	adrm_int32(adr, &xid, 1);
	adrm_int32(adr, &uid, 1);
	skip_string(adr);

	if (flags & M_USERE) {
		if (m_usere == uid)
			checkflags = checkflags | M_USERE;
	}

	return (-1);
}


/*
 * Format of xclient token:
 * 	xclient id		adr_int32
 */
int
xclient_token(adr_t *adr)
{
	int32_t	client_id;

	adrm_int32(adr, &client_id, 1);

	return (-1);
}

/*
 * Format of privilege set token:
 *	priv_set type		string
 *	priv_set		string
 */

int
privilege_token(adr_t *adr)
{
	skip_string(adr);	/* set type name */
	skip_string(adr);	/* privilege set */
	return (-1);
}

/*
 * Format of security flags token:
 *	security flag set		string
 *	security flags		string
 */

int
secflags_token(adr_t *adr)
{
	skip_string(adr);	/* set name */
	skip_string(adr);	/* security flags */
	return (-1);
}

/*
 * Format of label token:
 *      label ID                1 byte
 *      compartment length      1 byte
 *      classification          2 bytes
 *      compartment words       <compartment length> * 4 bytes
 */
int
label_token(adr_t *adr)
{
	static m_label_t *label = NULL;
	static size32_t l_size;
	int len;

	if (label == NULL) {
		label = m_label_alloc(MAC_LABEL);
		l_size = blabel_size() - 4;
	}

	if (label == NULL) {
		/* out of memory, should never happen; skip label */
		char	l;	/* length */

		adr->adr_now += sizeof (char);
		adrm_char(adr, (char *)&l, 1);
		adr->adr_now += sizeof (short) + (4 * l);
		return (-1);
	}

	adrm_char(adr, (char *)label, 4);
	len = (int)(((char *)label)[1] * 4);
	if (len > l_size) {
		return (-1);
	}
	adrm_char(adr, &((char *)label)[4], len);

	if (flags & M_LABEL) {
		if (blinrange(label, m_label))
			checkflags = checkflags | M_LABEL;
	}

	return (-1);
}


/*
 * Format of useofpriv token:
 *	success/failure		adr_char
 *	privilege(s)		adr_string
 */
/* ARGSUSED */
int
useofpriv_token(adr_t *adr)
{
	char	flag;

	adrm_char(adr, &flag, 1);
	skip_string(adr);
	return (-1);
}
