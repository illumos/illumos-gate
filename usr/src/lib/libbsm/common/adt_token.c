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
 * adt_token.c
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This file does not provide any user callable functions.  See adt.c
 */

#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <bsm/audit.h>

#include <adt_xlate.h>
#include <alloca.h>
#include <assert.h>
#include <netdb.h>
#include <priv.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/priv_names.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/vnode.h>

#include <tsol/label.h>

#ifdef	C2_DEBUG
#define	DPRINTF(x) { (void) printf x; }
#define	DFLUSH (void) fflush(stdout);

/* 0x + Classification + Compartments + end of string */
#define	HEX_SIZE 2 + 2*2 + 2*32 + 1

static char *
dprt_label(m_label_t *label)
{
	static char	hex[HEX_SIZE];
	char		*direct = NULL;

	if (label_to_str(label, &direct, M_INTERNAL, DEF_NAMES) != 0) {
		adt_write_syslog("label_to_str(M_INTERNAL)", errno);
		return ("hex label failed");
	}
	(void) strlcpy(hex, direct, sizeof (hex));
	free(direct);
	return (hex);
}
#else	/* !C2_DEBUG */
#define	DPRINTF(x)
#define	DFLUSH
#endif	/* C2_DEBUG */

static adt_token_func_t adt_getTokenFunction(char);

static char	*empty = "";

/*
 * call adt_token_open() first and adt_token_close() last.
 *
 * au_open is sort of broken; it returns a -1 when out of memory that
 * you're supposed to ignore; au_write and au_close return without
 * doing anything when a -1 is passed.  This code sort of follows the
 * au_open model except that it calls syslog to indicate underlying
 * brokenness.  Other than that, -1 is ignored.
 */

void
adt_token_open(struct adt_event_state *event)
{
	static int	have_syslogged = 0;

	event->ae_event_handle = au_open();
	if (event->ae_event_handle < 0) {
		if (!have_syslogged) {
			adt_write_syslog("au_open failed", ENOMEM);
			have_syslogged = 1;
		}
	} else {
		have_syslogged = 0;
	}
}

/*
 * call generate_token for each token in the order you want the tokens
 * generated.
 */

void
adt_generate_token(struct entry *p_entry, void *p_data,
    struct adt_event_state *event)
{
	adt_token_func_t	p_func;

	assert((p_entry != NULL) && (p_data != NULL) && (event != NULL));

	p_func = adt_getTokenFunction(p_entry->en_token_id);
	assert(p_func != NULL);

	DPRINTF(("p_entry=%p, p_data=%p, offset=%llu, msgFmt=%s\n",
	    (void *)p_entry, p_data, (long long)p_entry->en_offset,
	    p_entry->en_msg_format));
	DFLUSH

	(*p_func)(p_entry->en_type_def,
	    (char *)p_data + p_entry->en_offset, p_entry->en_required, event,
	    p_entry->en_msg_format);
}

/* call this last */

int
adt_token_close(struct adt_event_state *event)
{
	int	rc;

	rc = au_close(event->ae_event_handle, AU_TO_WRITE,
	    event->ae_internal_id);
	if (rc < 0)
		adt_write_syslog("au_close failed", errno);
	return (rc);
}

/*
 * one function per token -- see the jump table at the end of file
 */

/* ARGSUSED */
static void
adt_to_return(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{

#ifdef _LP64
	(void) au_write(event->ae_event_handle,
	    au_to_return64((int64_t)event->ae_rc, event->ae_type));
#else
	(void) au_write(event->ae_event_handle,
	    au_to_return32((int32_t)event->ae_rc, event->ae_type));
#endif
}

/*
 * AUT_CMD
 *
 * the command line is described with argc and argv and the environment
 * with envp.  The envp list is NULL terminated and has no separate
 * counter; envp will be a NULL list unless the AUDIT_ARGE policy is
 * set.
 */

/* ARGSUSED */
static void
adt_to_cmd(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	struct adt_internal_state	*sp = event->ae_session;
	int				argc;
	char				**argv;
	char				**envp = NULL;

	argc = ((union convert *)p_data)->tint;
	p_data = adt_adjust_address(p_data, sizeof (int), sizeof (char **));
	argv = ((union convert *)p_data)->tchar2star;
	p_data = adt_adjust_address(p_data, sizeof (char **), sizeof (char **));

	if (sp->as_kernel_audit_policy & AUDIT_ARGE)
		envp = ((union convert *)p_data)->tchar2star;

	(void) au_write(event->ae_event_handle,
	    au_to_cmd(argc, argv, envp));
}

/*
 * special case of AUT_CMD with 1 argument that is
 * a string showing the whole command and no envp
 */
/* ARGSUSED */
static void
adt_to_cmd1(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	char	*string;

	string = ((union convert *)p_data)->tcharstar;

	if (string == NULL) {
		if (required) {
			string = empty;
		} else {
			return;
		}
	}
	/* argc is hardcoded as 1 */
	(void) au_write(event->ae_event_handle, au_to_cmd(1, &string,
	    NULL));
}

/*
 * adt_to_tid	-- generic address (ip is only one defined at present)
 *	input:
 *		terminal type:  ADT_IPv4, ADT_IPv6...
 *		case: ADT_IPv4 or ADT_IPv6...
 *			ip type
 *			remote port
 *			local port
 *			address
 *		case: not defined...
 */
/* ARGSUSED */
static void
adt_to_tid(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	au_generic_tid_t	tid;
	uint32_t		type;
	au_ip_t			*ip;

	type = ((union convert *)p_data)->tuint32;

	switch (type) {
	case ADT_IPv4:
	case ADT_IPv6:
		p_data = adt_adjust_address(p_data, sizeof (uint32_t),
		    sizeof (uint32_t));

		tid.gt_type = AU_IPADR;
		ip = &(tid.gt_adr.at_ip);

		ip->at_type = (type == ADT_IPv4) ?
		    AU_IPv4 : AU_IPv6;

		ip->at_r_port = ((union convert *)p_data)->tuint16;
		p_data = adt_adjust_address(p_data, sizeof (uint16_t),
		    sizeof (uint16_t));

		ip->at_l_port = ((union convert *)p_data)->tuint16;

		/* arg3 is for the array element, not the array size */
		p_data = adt_adjust_address(p_data, sizeof (uint16_t),
		    sizeof (uint32_t));

		(void) memcpy(ip->at_addr, p_data, ip->at_type);
		break;
	default:
		adt_write_syslog("Invalid terminal id type", EINVAL);
		return;
	}
	(void) au_write(event->ae_event_handle, au_to_tid(&tid));
}

/*
 * au_to_frmi takes a char * that is the fmri.
 */
/* ARGSUSED */
static void
adt_to_frmi(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	char		*fmri;

	DPRINTF(("  adt_to_fmri dd_datatype=%d\n", def->dd_datatype));

	fmri = ((union convert *)p_data)->tcharstar;

	if (fmri == NULL) {
		if (required) {
			fmri = empty;
		} else {
			return;
		}
	}
	DPRINTF(("  fmri=%s\n", fmri));
	(void) au_write(event->ae_event_handle, au_to_fmri(fmri));
}

/*
 * au_to_label takes an m_label_t * that is the label.
 */
/* ARGSUSED */
static void
adt_to_label(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	m_label_t	*label;

	DPRINTF(("  adt_to_label dd_datatype=%d\n", def->dd_datatype));

	label = ((union convert *)p_data)->tm_label;

	if (label != NULL) {
		DPRINTF(("  label=%s\n", dprt_label(label)));
		DFLUSH
		(void) au_write(event->ae_event_handle, au_to_label(label));
	} else {
		DPRINTF(("  Null label\n"));
		if (required)
			adt_write_syslog("adt_to_label no required label", 0);
	}
}

/*
 * au_to_newgroups takes a length and an array of gids
 * as input.  The input to adt_to_newgroups is a length
 * and a pointer to an array of gids.
 */

/* ARGSUSED */
static void
adt_to_newgroups(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	int	n;
	gid_t	*groups;

	n = ((union convert *)p_data)->tint;
	if (n < 1) {
		if (required) {
			n = 0;  /* in case negative n was passed */
		} else {
			return;
		}
	}
	p_data = adt_adjust_address(p_data, sizeof (int), sizeof (int32_t *));

	groups = ((union convert *)p_data)->tgidstar;

	(void) au_write(event->ae_event_handle, au_to_newgroups(n, groups));
}

/* ARGSUSED */
static void
adt_to_path(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	char	*path;

	path = ((union convert *)p_data)->tcharstar;

	if (path != NULL) {
		DPRINTF(("  path=%s\n", path));
		(void) au_write(event->ae_event_handle, au_to_path(path));
	} else {
		DPRINTF(("  Null path\n"));
		if (required) {
			(void) au_write(event->ae_event_handle,
			    au_to_path(empty));
		}
	}
}

/*
 * dummy token id:  AUT_PATHLIST
 */

/* ARGSUSED */
static void
adt_to_pathlist(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	char	*path;
	char	*working_buf;
	char	*pathlist;
	char	*last_str;

	pathlist = ((union convert *)p_data)->tcharstar;

	if (pathlist != NULL) {
		working_buf = strdup(pathlist);
		if (working_buf == NULL) {
			adt_write_syslog("audit failure", errno);
			if (required) {
				(void) au_write(event->ae_event_handle,
				    au_to_path(empty));
			}
			return;
		}
		for (path = strtok_r(working_buf, " ", &last_str);
		    path; path = strtok_r(NULL, " ", &last_str)) {
			DPRINTF(("  path=%s\n", path));
			(void) au_write(event->ae_event_handle,
			    au_to_path(path));
		}
	} else {
		DPRINTF(("  Null path list\n"));
		if (required)
			(void) au_write(event->ae_event_handle,
			    au_to_path(empty));
	}
}

/*
 * AUT_PRIV
 */

/* ARGSUSED */
static void
adt_to_priv(datadef *def, void *p_data, int required,
    struct adt_event_state *event, const char *priv_type)
{
	priv_set_t	*privilege;

	privilege = ((union convert *)p_data)->tprivstar;

	if (privilege != NULL) {
		(void) au_write(event->ae_event_handle,
		    au_to_privset(priv_type, privilege));
	} else {
		if (required) {
			DPRINTF(("  Null privilege\n"));
			(void) au_write(event->ae_event_handle,
			    au_to_privset(empty, NULL));
		}
	}
}

/*
 * -AUT_PRIV_L	AUT_PRIV for a limit set
 */

/* ARGSUSED */
static void
adt_to_priv_limit(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	adt_to_priv(def, p_data, required, event, PRIV_LIMIT);
}

/*
 * -AUT_PRIV_I	AUT_PRIV for an inherit set
 */

/* ARGSUSED */
static void
adt_to_priv_inherit(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	adt_to_priv(def, p_data, required, event, PRIV_INHERITABLE);
}

/* ARGSUSED */
static void
adt_to_priv_effective(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	adt_to_priv(def, p_data, required, event, PRIV_EFFECTIVE);
}

static void
getCharacteristics(struct auditpinfo_addr *info, pid_t *pid)
{
	int	rc;

	if (*pid == 0) {		/* getpinfo for this pid */
		info->ap_pid = getpid();
	} else {
		info->ap_pid = *pid;
	}

	rc = auditon(A_GETPINFO_ADDR, (caddr_t)info,
	    sizeof (struct auditpinfo_addr));
	if (rc == -1) {
		info->ap_auid = AU_NOAUDITID;
		info->ap_asid = 0;
		(void) memset((void *)&(info->ap_termid), 0,
		    sizeof (au_tid_addr_t));
		info->ap_termid.at_type = AU_IPv4;
	}
}

/*
 * AUT_PROCESS
 *
 */

/* ARGSUSED */
static void
adt_to_process(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	au_id_t			auid;
	uid_t			euid;
	gid_t			egid;
	uid_t			ruid;
	gid_t			rgid;
	pid_t			pid;
	au_asid_t		sid;
	au_tid_addr_t		*tid;
	struct auditpinfo_addr	info;

	auid = ((union convert *)p_data)->tuid;
	p_data = adt_adjust_address(p_data, sizeof (uid_t), sizeof (uid_t));
	euid = ((union convert *)p_data)->tuid;
	p_data = adt_adjust_address(p_data, sizeof (uid_t), sizeof (gid_t));
	egid = ((union convert *)p_data)->tgid;
	p_data = adt_adjust_address(p_data, sizeof (gid_t), sizeof (uid_t));
	ruid = ((union convert *)p_data)->tuid;
	p_data = adt_adjust_address(p_data, sizeof (uid_t), sizeof (gid_t));
	rgid = ((union convert *)p_data)->tgid;
	p_data = adt_adjust_address(p_data, sizeof (gid_t), sizeof (pid_t));
	pid  = ((union convert *)p_data)->tpid;
	p_data = adt_adjust_address(p_data, sizeof (pid_t), sizeof (uint32_t));
	sid  = ((union convert *)p_data)->tuint32;
	p_data = adt_adjust_address(p_data, sizeof (uint32_t),
	    sizeof (au_tid_addr_t *));
	tid  = ((union convert *)p_data)->ttermid;

	getCharacteristics(&info, &pid);

	if (auid == AU_NOAUDITID)
		auid = info.ap_auid;

	if (euid == AU_NOAUDITID)
		euid = geteuid();

	if (egid == AU_NOAUDITID)
		egid = getegid();

	if (ruid == AU_NOAUDITID)
		ruid = getuid();

	if (rgid == AU_NOAUDITID)
		rgid = getgid();

	if (tid == NULL)
		tid = &(info.ap_termid);

	if (sid == 0)
		sid = info.ap_asid;

	if (pid == 0)
		pid = info.ap_pid;

	(void) au_write(event->ae_event_handle,
	    au_to_process_ex(auid, euid, egid, ruid, rgid, pid, sid, tid));
}

/*
 * Generate subject information.
 * If labels are present, generate the subject label token.
 * If the group audit policy is set, generate the subject group token.
 *
 * The required flag does not apply here.
 *
 * Non-attributable records are indicated by an auid of AU_NOAUDITID;
 * no subject token or group token is generated for a non-attributable
 * record.
 */

/* ARGSUSED */
static void
adt_to_subject(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	struct adt_internal_state	*sp = event->ae_session;

	if (sp->as_info.ai_auid == AU_NOAUDITID)
		return;

	assert(sp->as_have_user_data == ADT_HAVE_ALL);

	(void) au_write(event->ae_event_handle,
	    au_to_subject_ex(sp->as_info.ai_auid,
	    sp->as_euid, sp->as_egid, sp->as_ruid, sp->as_rgid,
	    sp->as_pid, sp->as_info.ai_asid,
	    &(sp->as_info.ai_termid)));
	if (is_system_labeled()) {
		(void) au_write(event->ae_event_handle,
		    au_to_label(sp->as_label));
	}
	/*
	 * Add optional tokens if in the process model.
	 * In a session model, the groups list is undefined and label
	 * is in the state.
	 */
	if (sp->as_session_model == ADT_PROCESS_MODEL) {
		if (sp->as_kernel_audit_policy & AUDIT_GROUP) {
			int group_count;
			int maxgrp = getgroups(0, NULL);
			gid_t *grouplist = alloca(maxgrp * sizeof (gid_t));

			if ((group_count = getgroups(maxgrp, grouplist)) > 0) {
				(void) au_write(event->ae_event_handle,
				    au_to_newgroups(group_count, grouplist));
			}
		}
	}
}

/*
 * adt_to_text()
 *
 * The format string, normally null, is sort of a wrapper around
 * the input.  adt_write_text() is a wrapper around au_write that
 * handles the format string
 *
 */
#define	TEXT_LENGTH 49

static void
adt_write_text(int handle, char *main_text, const char *format)
{
	char	buffer[TEXT_LENGTH * 2 + 1];

	if (format == NULL) {
		(void) au_write(handle, au_to_text(main_text));
	} else {
		(void) snprintf(buffer, TEXT_LENGTH * 2, format, main_text);
		(void) au_write(handle, au_to_text(buffer));
	}
}

static void
adt_to_text(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *format)
{
	static int	have_syslogged = 0;
	char		*string;
	char		**string_list;
	char		buffer[TEXT_LENGTH + 1];
	time_t		date;
	struct tm	tm;
	uint32_t	*int_list;
	int		written, available;
	int		i, arrayCount;
	struct msg_text *list;
	int		list_index;

	DPRINTF(("  adt_to_text dd_datatype=%d\n", def->dd_datatype));
	switch (def->dd_datatype) {
	case ADT_DATE:
		/*
		 * Consider creating a separate token type for dates
		 * -- store as longs and format them in praudit.
		 * For now, a date is input as a time_t and output as
		 * a text token.  If we do this, we need to consider
		 * carrying timezone info so that praudit can
		 * represent times in an unambiguous manner.
		 */
		date = ((union convert *)p_data)->tlong;
		if (strftime(buffer, sizeof (buffer), "%x",
		    localtime_r(&date, &tm)) > TEXT_LENGTH) {
			if (required) {
				(void) strncpy(buffer, "invalid date",
				    TEXT_LENGTH);
			} else {
				break;
			}
		}
		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
		/*
		 * The "input size" is overloaded to mean the list number
		 * and the msg_selector indexes the desired string in
		 * that list
		 */
	case ADT_MSG:
		list = &adt_msg_text[(enum adt_msg_list)def->dd_input_size];
		list_index = ((union convert *)p_data)->msg_selector;

		if ((list_index + list->ml_offset < list->ml_min_index) ||
		    (list_index + list->ml_offset > list->ml_max_index)) {
			string = "Invalid message index";
		} else {
			string = list->ml_msg_list[list_index +
			    list->ml_offset];
		}

		if (string == NULL) {	/* null is valid; means skip */
			if (required) {
				string = empty;
			} else {
				break;
			}
		}
		DPRINTF(("  text=%s\n", string));
		adt_write_text(event->ae_event_handle, string, format);
		break;
	case ADT_UID:
	case ADT_GID:
	case ADT_UINT:
	case ADT_UINT32:
		(void) snprintf(buffer, TEXT_LENGTH, "%u",
		    ((union convert *)p_data)->tuint);

		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_INT:
	case ADT_INT32:
		(void) snprintf(buffer, TEXT_LENGTH, "%d",
		    ((union convert *)p_data)->tint);

		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_LONG:
		(void) snprintf(buffer, TEXT_LENGTH, "%ld",
		    ((union convert *)p_data)->tlong);

		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_UIDSTAR:
	case ADT_GIDSTAR:
	case ADT_UINT32STAR:
		int_list = ((union convert *)p_data)->tuint32star;
		p_data = adt_adjust_address(p_data, sizeof (int *),
		    sizeof (int));
		arrayCount = ((union convert *)p_data)->tint;

		string = buffer;
		available = TEXT_LENGTH;	/* space available in buffer */

		if (arrayCount < 0)
			arrayCount = 0;

		if ((arrayCount > 0) && (int_list != NULL)) {
			for (; arrayCount > 0; arrayCount--) {
				written = snprintf(string, available,
				    "%d ", *int_list++);
				if (written < 1)
					break;
				string += written;
				available -= written;
			}
		} else if (required) {
			string = empty;
		} else {
			break;
		}

		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_ULONG:
		(void) snprintf(buffer, TEXT_LENGTH, "%lu",
		    ((union convert *)p_data)->tulong);

		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_UINT64:
		(void) snprintf(buffer, TEXT_LENGTH, "%llu",
		    ((union convert *)p_data)->tuint64);

		DPRINTF(("  text=%s\n", buffer));
		adt_write_text(event->ae_event_handle, buffer, format);
		break;
	case ADT_CHARSTAR:
		string = ((union convert *)p_data)->tcharstar;

		if (string == NULL) {
			if (required) {
				string = empty;
			} else {
				break;
			}
		}
		DPRINTF(("  text=%s\n", string));
		adt_write_text(event->ae_event_handle, string, format);
		break;
	case ADT_CHAR2STAR:
		string_list = ((union convert *)p_data)->tchar2star;
		p_data = adt_adjust_address(p_data, sizeof (char **),
		    sizeof (int));
		arrayCount = ((union convert *)p_data)->tint;

		if (arrayCount < 0)
			arrayCount = 0;

		if ((arrayCount > 0) && (string_list != NULL)) {
			for (i = 0; i < arrayCount; i++) {
				string = string_list[i];
				if (string != NULL)
					adt_write_text(event->ae_event_handle,
					    string, format);
			}
		} else if (required) {
			adt_write_text(event->ae_event_handle, empty, format);
		} else {
			break;
		}
		break;
	default:
		if (!have_syslogged) { /* don't flood the log */
			adt_write_syslog("unsupported data conversion",
			    ENOTSUP);
			have_syslogged = 1;
		}
		break;
	}
	DFLUSH
}

/*
 * AUT_UAUTH
 */

/* ARGSUSED */
static void
adt_to_uauth(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *format)
{
	char		*string;

	DPRINTF(("  adt_to_uauth dd_datatype=%d\n", def->dd_datatype));

	string = ((union convert *)p_data)->tcharstar;

	if (string == NULL) {
		if (required) {
			string = empty;
		} else {
			return;
		}
	}
	DPRINTF(("  text=%s\n", string));
	(void) au_write(event->ae_event_handle, au_to_uauth(string));
}

/*
 * AUT_USER
 */

/* ARGSUSED */
static void
adt_to_user(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *format)
{
	uid_t	uid;
	char	*username;

	DPRINTF(("  adt_to_user dd_datatype=%d\n", def->dd_datatype));

	uid = ((union convert *)p_data)->tuid;
	p_data = adt_adjust_address(p_data, sizeof (uid_t), sizeof (uid_t));

	username = ((union convert *)p_data)->tcharstar;

	if (username == NULL) {
		if (required) {
			username = empty;
		} else {
			return;
		}
	}
	DPRINTF(("  username=%s\n", username));
	(void) au_write(event->ae_event_handle, au_to_user(uid, username));
}

/*
 * AUT_ZONENAME
 */

/* ARGSUSED */
static void
adt_to_zonename(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	char	*name;

	name = ((union convert *)p_data)->tcharstar;

	if (name != NULL) {
		DPRINTF(("  name=%s\n", name));
		(void) au_write(event->ae_event_handle, au_to_zonename(name));
	} else {
		DPRINTF(("  Null name\n"));
		if (required) {
			(void) au_write(event->ae_event_handle,
			    au_to_zonename(empty));
		}
	}
}

/*
 * ADT_IN_PEER dummy token
 */

/* ARGSUSED */
static void
adt_to_in_peer(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	int	sock;
	struct sockaddr_in6 peer;
	int	peerlen = sizeof (peer);

	DPRINTF(("    adt_to_in_peer dd_datatype=%d\n", def->dd_datatype));

	sock = ((union convert *)p_data)->tfd;

	if (sock < 0) {
		DPRINTF(("  Socket fd %d\n", sock));
		if (required) {
			adt_write_syslog("adt_to_in_peer no required socket",
			    0);
		}
		return;
	}
	if (getpeername(sock, (struct sockaddr *)&peer, (socklen_t *)&peerlen)
	    < 0) {

		adt_write_syslog("adt_to_in_addr getpeername", errno);
		return;
	}
	if (peer.sin6_family == AF_INET6) {
		(void) au_write(event->ae_event_handle,
		    au_to_in_addr_ex(&(peer.sin6_addr)));
		(void) au_write(event->ae_event_handle,
		    au_to_iport((ushort_t)peer.sin6_port));
	} else {
		(void) au_write(event->ae_event_handle,
		    au_to_in_addr(&(((struct sockaddr_in *)&peer)->sin_addr)));
		(void) au_write(event->ae_event_handle,
		    au_to_iport(
		    (ushort_t)(((struct sockaddr_in *)&peer)->sin_port)));
	}
}

/*
 * ADT_IN_REMOTE dummy token
 *
 * Similar to ADT_IN_PEER except the input is
 * an IP address type (ADT_IPv4 | ADT_IPv6) and an address V4/V6
 */

/* ARGSUSED */
static void
adt_to_in_remote(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	int32_t	type;

	DPRINTF(("    adt_to_in_remote dd_datatype=%d\n", def->dd_datatype));

	type = ((union convert *)p_data)->tuint32;

	if (type ==  0) {
		if (required == 0) {
			return;
		}
		/* required and not specified */
		adt_write_syslog("adt_to_in_remote required address not "
		    "specified", 0);
		type = ADT_IPv4;
	}
	p_data = adt_adjust_address(p_data, sizeof (int32_t),
	    sizeof (uint32_t));

	switch (type) {
	case ADT_IPv4:
		(void) au_write(event->ae_event_handle, au_to_in_addr(
		    (struct in_addr *)&(((union convert *)p_data)->tuint32)));
		break;
	case ADT_IPv6:
		(void) au_write(event->ae_event_handle, au_to_in_addr_ex(
		    (struct in6_addr *)&(((union convert *)p_data)->tuint32)));
		break;
	default:
		adt_write_syslog("adt_to_in_remote invalid type", EINVAL);
		return;
	}
}

/*
 * adt_to_iport takes a uint16_t IP port.
 */

/* ARGSUSED */
static void
adt_to_iport(datadef *def, void *p_data, int required,
    struct adt_event_state *event, char *notUsed)
{
	ushort_t port;

	DPRINTF(("  adt_to_iport dd_datatype=%d\n", def->dd_datatype));

	port = ((union convert *)p_data)->tuint16;

	if (port == 0) {
		if (required == 0) {
			return;
		}
		/* required and not specified */
		adt_write_syslog("adt_to_iport no required port", 0);
	}
	(void) au_write(event->ae_event_handle, au_to_iport(port));

}


/*
 *	This is a compact table that defines only the tokens that are
 * actually generated in the adt.xml file.  It can't be a  pure
 * indexed table because the adt.xml language defines internal extension
 * tokens for some processing.  VIZ. ADT_CMD_ALT, ADT_AUT_PRIV_* (see
 * adt_xlate.h), and the -AUT_PATH value.
 */

#define	MAX_TOKEN_JMP 21

static struct token_jmp token_table[MAX_TOKEN_JMP] =
{
	{AUT_CMD, adt_to_cmd},
	{ADT_CMD_ALT, adt_to_cmd1},
	{AUT_FMRI, adt_to_frmi},
	{ADT_IN_PEER, adt_to_in_peer},
	{ADT_IN_REMOTE, adt_to_in_remote},
	{AUT_IPORT, adt_to_iport},
	{AUT_LABEL, adt_to_label},
	{AUT_NEWGROUPS, adt_to_newgroups},
	{AUT_PATH, adt_to_path},
	{-AUT_PATH, adt_to_pathlist},	/* private extension of token values */
	{ADT_AUT_PRIV_L, adt_to_priv_limit},
	{ADT_AUT_PRIV_I, adt_to_priv_inherit},
	{ADT_AUT_PRIV_E, adt_to_priv_effective},
	{AUT_PROCESS, adt_to_process},
	{AUT_RETURN, adt_to_return},
	{AUT_SUBJECT, adt_to_subject},
	{AUT_TEXT, adt_to_text},
	{AUT_TID, adt_to_tid},
	{AUT_UAUTH, adt_to_uauth},
	{AUT_USER, adt_to_user},
	{AUT_ZONENAME, adt_to_zonename}
};

/*
 *	{AUT_ACL, adt_to_acl},			not used
 *	{AUT_ARBITRARY, adt_to_arbitrary},	AUT_ARBITRARY is undefined
 *	{AUT_ARG, adt_to_arg},			not used
 *	{AUT_ATTR, adt_to_attr},		not used in mountd
 *	{AUT_XATOM, adt_to_atom},		not used
 *	{AUT_EXEC_ARGS, adt_to_exec_args},	not used
 *	{AUT_EXEC_ENV, adt_to_exec_env},	not used
 *	{AUT_EXIT, adt_to_exit},		obsolete
 *	{AUT_FILE, adt_to_file},		AUT_FILE is undefined
 *	{AUT_XCOLORMAP, adt_to_colormap},	not used
 *	{AUT_XCURSOR, adt_to_cursor},		not used
 *	{AUT_XFONT, adt_to_font},		not used
 *	{AUT_XGC, adt_to_gc},			not used
 *	{AUT_GROUPS, adt_to_groups},		obsolete
 *	{AUT_HEADER, adt_to_header},		generated by au_close
 *	{AUT_IP, adt_to_ip},			not used
 *	{AUT_IPC, adt_to_ipc},			not used
 *	{AUT_IPC_PERM, adt_to_ipc_perm},	not used
 *	{AUT_OPAQUE, adt_to_opaque},		not used
 *	{AUT_XPIXMAP, adt_to_pixmap},		not used
 *	{AUT_XPROPERTY, adt_to_property},	not used
 *	{AUT_SEQ, adt_to_seq},			not used
 *	{AUT_SOCKET, adt_to_socket},		not used
 *	{AUT_SOCKET_INET, adt_to_socket_inet},  AUT_SOCKET_INET is undefined
 *	{AUT_TRAILER, adt_to_trailer},		generated by au_close
 *	{AUT_XCLIENT, adt_to_xclient}		not used
 */

/* find function to generate token */

static adt_token_func_t
adt_getTokenFunction(char token_id)
{
	int	i;
	struct token_jmp	*p_jmp = token_table;

	for (i = 0; i < MAX_TOKEN_JMP; i++) {
		if (token_id == p_jmp->jmp_id) {
			return (p_jmp->jmp_to);
		}
		p_jmp++;
	}
	errno = EINVAL;
	return (NULL);
}

/*
 * adjustAddress -- given the address of data, its size, and the type of
 * the next data field, calculate the offset to the next piece of data.
 * Depending on the caller, "current" and "next" mean the current pointer
 * and the next pointer or the last pointer and the current pointer.
 */
void *
adt_adjust_address(void *current_address, size_t current_size,
    size_t next_size)
{
	ptrdiff_t adjustment;
	ptrdiff_t remainder;

	adjustment = (size_t)current_address + current_size;

	if (next_size) {
		remainder = adjustment % next_size;
		if (remainder != 0)
			adjustment += next_size - remainder;
	}
	return ((char *)adjustment);
}
