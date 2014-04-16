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

/*
 * Solaris Audit Token Table.
 */

#include <locale.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#include "praudit.h"
#include "toktable.h"

token_desc_t tokentable[MAXTAG + 1];

#define	table_init(i, n, f, t) \
	tokentable[(int)(i)].t_name = (n); \
	tokentable[(int)(i)].t_tagname = (n); \
	tokentable[(int)(i)].func = (f); \
	tokentable[(int)(i)].t_type = (t);

/* table_initx is for entries which need name different from tagname */
#define	table_initx(i, n, tn, f, t) \
	tokentable[(int)(i)].t_name = (n); \
	tokentable[(int)(i)].t_tagname = (tn); \
	tokentable[(int)(i)].func = (f); \
	tokentable[(int)(i)].t_type = (t);

/*
 * Initialize the table of tokens & other tags.
 */
void
init_tokens(void)
{
	/*
	 * TRANSLATION_NOTE
	 * These names refer to different type of audit tokens.
	 * To gain a better understanding of each token, read
	 * System Administration Guide: Security Services >> Solaris Auditing
	 * at http://docs.sun.com.
	 */

	(void) gettext("file");	/* to force out the translation note */

	/*
	 * Control token types
	 */

	table_init(AUT_INVALID, (char *)0, NOFUNC, T_UNKNOWN);
	table_init(AUT_OTHER_FILE32, "file", file_token, T_EXTENDED);
	table_init(AUT_OHEADER, "old_header", NOFUNC, T_EXTENDED);
	table_init(AUT_TRAILER, "trailer", trailer_token, T_UNKNOWN);
	table_initx(AUT_HEADER32, "header", "record",
	    header_token, T_EXTENDED);
	table_initx(AUT_HEADER32_EX, "header", "record",
	    header32_ex_token, T_EXTENDED);

	/*
	 * Data token types
	 */

	table_init(AUT_DATA, "arbitrary", arbitrary_data_token, T_EXTENDED);
	table_init(AUT_FMRI, "fmri", fmri_token, T_ELEMENT);
	table_init(AUT_IPC, "IPC", s5_IPC_token, T_ENCLOSED);
	table_init(AUT_PATH, "path", path_token, T_ELEMENT);
	table_init(AUT_XATPATH, "path_attr", path_attr_token, T_ELEMENT);
	table_init(AUT_SUBJECT32, "subject", subject32_token, T_ENCLOSED);
	table_init(AUT_PROCESS32, "process", process32_token, T_ENCLOSED);
	table_init(AUT_RETURN32, "return", return_value32_token, T_ENCLOSED);
	table_init(AUT_TEXT, "text", text_token, T_ELEMENT);
	table_init(AUT_OPAQUE, "opaque", opaque_token, T_ELEMENT);
	table_initx(AUT_IN_ADDR, "ip address", "ip_address",
	    ip_addr_token, T_ELEMENT);
	table_init(AUT_IP, "ip", ip_token, T_ENCLOSED);
	table_initx(AUT_IPORT, "ip port", "ip_port",
	    iport_token, T_ELEMENT);
	table_init(AUT_ARG32, "argument", argument32_token, T_ENCLOSED);
	table_initx(AUT_SOCKET, "socket", "old_socket",
	    socket_token, T_ENCLOSED);
	table_init(AUT_SEQ, "sequence", sequence_token, T_ENCLOSED);

	/*
	 * Modifier token types
	 */

	table_init(AUT_ACL, "acl", acl_token, T_ENCLOSED);
	table_init(AUT_ACE, "acl", ace_token, T_ENCLOSED);
	table_init(AUT_ATTR, "attribute", attribute_token, T_ENCLOSED);
	table_init(AUT_IPC_PERM, "IPC_perm", s5_IPC_perm_token, T_ENCLOSED);
	table_init(AUT_GROUPS, "group", group_token, T_ELEMENT);
	table_initx(AUT_LABEL, "sensitivity label", "sensitivity_label",
	    label_token, T_ELEMENT);
	table_init(AUT_PRIV, "privilege", privilege_token, T_EXTENDED);
	table_init(AUT_SECFLAGS, "secflags", secflags_token, T_EXTENDED);
	table_initx(AUT_UPRIV, "use of privilege", "use_of_privilege",
	    useofpriv_token, T_EXTENDED);
	table_init(AUT_LIAISON, "liaison", liaison_token, T_ELEMENT);
	table_init(AUT_NEWGROUPS, "group", newgroup_token, T_ELEMENT);
	table_init(AUT_EXEC_ARGS, "exec_args", exec_args_token, T_ELEMENT);
	table_init(AUT_EXEC_ENV, "exec_env", exec_env_token, T_ELEMENT);
	table_init(AUT_ATTR32, "attribute", attribute32_token, T_ENCLOSED);
	table_initx(AUT_UAUTH, "use of authorization",
	    "use_of_authorization", useofauth_token, T_ELEMENT);
	table_init(AUT_USER, "user", user_token, T_ENCLOSED);
	table_init(AUT_ZONENAME, "zone", zonename_token, T_ENCLOSED);

	/*
	 * X windows token types
	 */
	table_initx(AUT_XATOM, "X atom", "X_atom", xatom_token, T_ELEMENT);
	table_initx(AUT_XOBJ, "X object", "X_object", NOFUNC, T_UNKNOWN);
	table_initx(AUT_XPROTO, "X protocol", "X_protocol", NOFUNC, T_UNKNOWN);
	table_initx(AUT_XSELECT, "X selection", "X_selection",
	    xselect_token, T_ELEMENT);
	table_initx(AUT_XCOLORMAP, "X color map", "X_color_map",
	    xcolormap_token, T_ENCLOSED);
	table_initx(AUT_XCURSOR, "X cursor", "X_cursor",
	    xcursor_token, T_ENCLOSED);
	table_initx(AUT_XFONT, "X font", "X_font", xfont_token, T_ENCLOSED);
	table_initx(AUT_XGC, "X graphic context", "X_graphic_context",
	    xgc_token, T_ENCLOSED);
	table_initx(AUT_XPIXMAP, "X pixmap", "X_pixmap",
	    xpixmap_token, T_ENCLOSED);
	table_initx(AUT_XPROPERTY, "X property", "X_property",
	    xproperty_token, T_EXTENDED);
	table_initx(AUT_XWINDOW, "X window", "X_window",
	    xwindow_token, T_ENCLOSED);
	table_initx(AUT_XCLIENT, "X client", "X_client",
	    xclient_token, T_ELEMENT);

	/*
	 * Command token types
	 */

	table_init(AUT_CMD, "cmd", cmd_token, T_ELEMENT);
	table_init(AUT_EXIT, "exit", exit_token, T_ENCLOSED);

	/*
	 * Miscellaneous token types
	 */

	table_init(AUT_HOST, "host", host_token, T_ELEMENT);

	/*
	 * Solaris64 token types
	 */

	table_init(AUT_ARG64, "argument", argument64_token, T_ENCLOSED);
	table_init(AUT_RETURN64, "return", return_value64_token, T_ENCLOSED);
	table_init(AUT_ATTR64, "attribute", attribute64_token, T_ENCLOSED);
	table_initx(AUT_HEADER64, "header", "record",
	    header64_token, T_EXTENDED);
	table_init(AUT_SUBJECT64, "subject", subject64_token, T_ENCLOSED);
	table_init(AUT_PROCESS64, "process", process64_token, T_ENCLOSED);
	table_init(AUT_OTHER_FILE64, "file", file64_token, T_EXTENDED);

	/*
	 * Extended network address token types
	 */

	table_initx(AUT_HEADER64_EX, "header", "record",
	    header64_ex_token, T_EXTENDED);
	table_init(AUT_SUBJECT32_EX, "subject", subject32_ex_token, T_ENCLOSED);
	table_init(AUT_PROCESS32_EX, "process", process32_ex_token, T_ENCLOSED);
	table_init(AUT_SUBJECT64_EX, "subject", subject64_ex_token, T_ENCLOSED);
	table_init(AUT_PROCESS64_EX, "process", process64_ex_token, T_ENCLOSED);
	table_initx(AUT_IN_ADDR_EX, "ip address", "ip_address",
	    ip_addr_ex_token, T_ELEMENT);
	table_init(AUT_SOCKET_EX, "socket", socket_ex_token, T_ENCLOSED);
	table_init(AUT_TID, "tid", tid_token, T_EXTENDED);

#ifdef _PRAUDIT
	/*
	 * Done with tokens above here. Now do remaining tags.
	 */
	table_init(TAG_AUID, "audit-uid", pa_pw_uid, T_ATTRIBUTE);
	table_init(TAG_UID, "uid", pa_pw_uid, T_ATTRIBUTE);
	table_init(TAG_GID, "gid", pa_gr_uid, T_ATTRIBUTE);
	table_init(TAG_RUID, "ruid", pa_pw_uid, T_ATTRIBUTE);
	table_init(TAG_RGID, "rgid", pa_gr_uid, T_ATTRIBUTE);

	table_init(TAG_PID, "pid", pa_adr_u_int32, T_ATTRIBUTE);
	table_init(TAG_SID, "sid", pa_adr_u_int32, T_ATTRIBUTE);

	table_init(TAG_TID32, "tid", pa_tid32, T_ATTRIBUTE);
	table_init(TAG_TID64, "tid", pa_tid64, T_ATTRIBUTE);
	table_init(TAG_TID32_EX, "tid", pa_tid32_ex, T_ATTRIBUTE);
	table_init(TAG_TID64_EX, "tid", pa_tid64_ex, T_ATTRIBUTE);
	table_init(TAG_TID_TYPE, "type", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_IP, "ipadr", NOFUNC, T_ENCLOSED);
	table_init(TAG_IP_LOCAL, "local-port", pa_adr_u_short, T_ATTRIBUTE);
	table_init(TAG_IP_REMOTE, "remote-port", pa_adr_u_short, T_ATTRIBUTE);
	table_init(TAG_IP_ADR, "host", pa_ip_addr, T_ATTRIBUTE);

	table_initx(TAG_EVMOD, "event-modifier", "modifier",
	    pa_event_modifier, T_ATTRIBUTE);
	table_initx(TAG_EVTYPE, "event-type", "event",
	    pa_event_type, T_ATTRIBUTE);
	table_initx(TAG_TOKVERS, "token-version", "version",
	    pa_adr_byte, T_ATTRIBUTE);

	table_init(TAG_ISO, "iso8601", NOFUNC, T_ATTRIBUTE);

	table_init(TAG_ERRVAL, "errval", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_RETVAL, "retval", pa_adr_int32, T_ATTRIBUTE);

	table_init(TAG_SETTYPE, "set-type", pa_adr_string, T_ATTRIBUTE);
	/* Sub-element of groups & newgroups token: */
	table_init(TAG_GROUPID, "gid", pa_gr_uid, T_ELEMENT);

	table_init(TAG_XID, "xid", pa_xid, T_ATTRIBUTE);
	table_init(TAG_XCUID, "xcreator-uid", pa_pw_uid, T_ATTRIBUTE);

	table_init(TAG_XSELTEXT, "x_sel_text", pa_adr_string, T_ELEMENT);
	table_init(TAG_XSELTYPE, "x_sel_type", pa_adr_string, T_ELEMENT);
	table_init(TAG_XSELDATA, "x_sel_data", pa_adr_string, T_ELEMENT);

	table_init(TAG_ARGNUM, "arg-num", pa_adr_byte, T_ATTRIBUTE);
	table_init(TAG_ARGVAL32, "value", pa_adr_int32hex, T_ATTRIBUTE);
	table_init(TAG_ARGVAL64, "value", pa_adr_int64hex, T_ATTRIBUTE);
	table_init(TAG_ARGDESC, "desc", pa_adr_string, T_ATTRIBUTE);

	table_init(TAG_MODE, "mode", pa_mode, T_ATTRIBUTE);
	table_init(TAG_FSID, "fsid", pa_adr_int32, T_ATTRIBUTE);
	table_init(TAG_NODEID32, "nodeid", pa_adr_int32, T_ATTRIBUTE);
	table_init(TAG_NODEID64, "nodeid", pa_adr_int64, T_ATTRIBUTE);
	table_init(TAG_DEVICE32, "device", pa_adr_u_int32, T_ATTRIBUTE);
	table_init(TAG_DEVICE64, "device", pa_adr_u_int64, T_ATTRIBUTE);

	table_init(TAG_SEQNUM, "seq-num", pa_adr_u_int32, T_ATTRIBUTE);
	table_init(TAG_ZONENAME, "name", pa_adr_string, T_ATTRIBUTE);
	table_init(TAG_ARGV, "argv", pa_cmd, T_ELEMENT);
	table_init(TAG_ARGE, "arge", pa_cmd, T_ELEMENT);
	table_init(TAG_ARG, "arg", pa_string, T_ELEMENT);
	table_init(TAG_ENV, "env", pa_string, T_ELEMENT);
	table_init(TAG_XAT, "xattr", pa_string, T_ELEMENT);

	table_init(TAG_RESULT, "result", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_CUID, "creator-uid", pa_pw_uid, T_ATTRIBUTE);
	table_init(TAG_CGID, "creator-gid", pa_gr_uid, T_ATTRIBUTE);
	table_init(TAG_SEQ, "seq", pa_adr_u_int32, T_ATTRIBUTE);
	table_init(TAG_KEY, "key", pa_adr_int32hex, T_ATTRIBUTE);

	table_init(TAG_IPVERS, "version", pa_adr_charhex, T_ATTRIBUTE);
	table_init(TAG_IPSERV, "service_type", pa_adr_charhex, T_ATTRIBUTE);
	table_init(TAG_IPLEN, "len", pa_adr_short, T_ATTRIBUTE);
	table_init(TAG_IPID, "id", pa_adr_u_short, T_ATTRIBUTE);
	table_init(TAG_IPOFFS, "offset", pa_adr_u_short, T_ATTRIBUTE);
	table_init(TAG_IPTTL, "time_to_live", pa_adr_charhex, T_ATTRIBUTE);
	table_init(TAG_IPPROTO, "protocol", pa_adr_charhex, T_ATTRIBUTE);
	table_init(TAG_IPCKSUM, "cksum", pa_adr_u_short, T_ATTRIBUTE);
	table_init(TAG_IPSRC, "src_addr", pa_adr_int32hex, T_ATTRIBUTE);
	table_init(TAG_IPDEST, "dest_addr", pa_adr_int32hex, T_ATTRIBUTE);

	table_init(TAG_ACLTYPE, "type", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ACLVAL, "value", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ACEMASK, "access_mask", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ACEFLAGS, "flags", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ACETYPE, "type", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ACEID, "id", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_SOCKTYPE, "type", pa_adr_shorthex, T_ATTRIBUTE);
	table_init(TAG_SOCKPORT, "port", pa_adr_shorthex, T_ATTRIBUTE);
	table_init(TAG_SOCKADDR, "addr", NOFUNC, T_ATTRIBUTE);

	table_init(TAG_SOCKEXDOM, "sock_domain", pa_adr_shorthex, T_ATTRIBUTE);
	table_init(TAG_SOCKEXTYPE, "sock_type", pa_adr_shorthex, T_ATTRIBUTE);
	table_init(TAG_SOCKEXLPORT, "lport", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_SOCKEXLADDR, "laddr", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_SOCKEXFPORT, "fport", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_SOCKEXFADDR, "faddr", NOFUNC, T_ATTRIBUTE);

	table_init(TAG_IPCTYPE, "ipc-type", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_IPCID, "ipc-id", pa_adr_int32, T_ATTRIBUTE);

	table_init(TAG_ARBPRINT, "print", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ARBTYPE, "type", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_ARBCOUNT, "count", NOFUNC, T_ATTRIBUTE);

	table_init(TAG_HOSTID, "host", NOFUNC, T_ATTRIBUTE);
	table_init(TAG_USERNAME, "username", pa_adr_string, T_ATTRIBUTE);
#endif	/* _PRAUDIT */
}
