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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <libpq-fe.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uuid.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <procfs.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <netdb.h>
#include <sys/utsname.h>
#include <strings.h>
#include <ctype.h>
#include <sys/resource.h>
#include <syslog.h>
#include <msg_sub.h>
#include <host_ident.h>
#include <mms_cfg.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_sql.h"
#include "mm_commands.h"
#include "mm_util.h"

static char    *_SrcFile = __FILE__;

extern void uuid_clear(uuid_t uu);
extern void uuid_generate_random(uuid_t uu);
extern void uuid_generate(uuid_t uu); /* hits bug id 6397009 */
extern void uuid_unparse(uuid_t uu, char *out);


void
mm_clear_db(PGresult **results) {
	if (*results != NULL) {
		PQclear(*results);
		*results = NULL;
	}
}

void
mm_system_error(mm_command_t *cmd, char *fmt, ...) {
	va_list		args;
	char		*text;

	va_start(args, fmt);

	text = mms_vstrapp(NULL, fmt, args);

	va_end(args);

	mm_response_error(cmd,
	    ECLASS_INTERNAL, "ESYSTEM",
	    MM_5021_MSG,
	    "text",
	    text,
	    NULL);

	free(text);
}

int
mm_copy_cmd_buf(mm_command_t *cmd1, mm_command_t *cmd2) {
	SQL_CHK_LEN(&cmd1->cmd_buf, 0, &cmd1->cmd_bufsize,
	    strlen(cmd2->cmd_buf) + 1);
	strcpy(cmd1->cmd_buf, cmd2->cmd_buf);
no_mem:
	MM_ABORT_NO_MEM();
	return (1);
}

char *
mm_ret_loctext(mms_par_node_t *root) {
	mms_par_node_t	*loctext_clause;
	mms_par_node_t	*loctext_arg;
	mms_par_node_t	*work = 0;
	int		i = 0;

	if ((loctext_clause =  mms_pn_lookup(root, "loctext",
	    MMS_PN_CLAUSE, NULL)) == NULL) {
		mms_trace(MMS_DEVP,
		    "response does not have a loctext clause");
		return (NULL);
	}
	while (i < 2) {
		if ((loctext_arg =  mms_pn_lookup(loctext_clause, NULL,
		    MMS_PN_STRING, &work)) == NULL) {
			mms_trace(MMS_DEVP,
			    "response does not have an arg "
			    "in the loctext clause");
			return (NULL);
		}
		i ++;
	}
	return (loctext_arg->pn_string);
}

int
mm_ret_msg_id(mms_par_node_t *root) {

	/* This function looks up a message id */
	/* from the parse tree root */
	/* if there is no message id, */
	/* return -1 */

	mms_par_node_t	*id_clause;
	mms_par_node_t	*id_arg;
	mms_par_node_t	*work = 0;
	int		i = 0;
	int		message_id = -1;

	if ((id_clause =  mms_pn_lookup(root, "id",
	    MMS_PN_CLAUSE, 0)) == NULL) {
		mms_trace(MMS_DEVP,
		    "response does not have an id clause");
		return (-1);
	}
	while (i < 3) {
		if ((id_arg =  mms_pn_lookup_arg(id_clause, NULL,
		    MMS_PN_STRING, &work)) == NULL) {
			mms_trace(MMS_DEVP,
			    "response is missing an arg in the id clause");
			return (-1);
		}
		i ++;
	}
	if (id_arg->pn_string != NULL) {
		message_id = atoi(id_arg->pn_string);
		return (message_id);
	} else {
		mms_trace(MMS_ERR,
		    "bad id in message id arguement");
		return (-1);
	}


}

char *
mm_ret_response_msg(mm_command_t *cmd) {
	char		*msg_rsp = NULL;

	int		message_id = 0;
	char		*local_text = NULL;

	/*
	 * If there is a message,
	 * look up the id in the catalog,
	 * and create the loctext.
	 * If there is no matching id,
	 * use the id number and the
	 * loc text from the response
	 */

	if (cmd->cmd_response == NULL) {
		mms_trace(MMS_DEVP,
		    "cmd->cmd_response is NULL,"
		    "no response found");
		msg_rsp = mms_strapp(msg_rsp, "none");
		return (msg_rsp);
	}

	/* Get the id and loctext */
	if ((message_id = mm_ret_msg_id(cmd->cmd_response)) == -1) {
		mms_trace(MMS_DEVP,
		    "response does not have a message id");
	} else {
		mms_trace(MMS_DEVP,
		    "message id is %d",
		    message_id);
	}
	if ((local_text = mm_ret_loctext(cmd->cmd_response)) == NULL) {
		mms_trace(MMS_DEVP,
		    "response does not have a loctext");
	} else {
		mms_trace(MMS_DEVP,
		    "local text is %s",
		    local_text);
	}
	if ((message_id == -1) &&
	    (local_text == NULL)) {
		mms_trace(MMS_DEVP,
		    "there is no message in this response"
		    "msg_rsp == 'none'");
		msg_rsp = mms_strapp(msg_rsp, "none");
		return (msg_rsp);
	}
	/* Check if the id is in the catalog */
	if (mm_msg_exists(message_id) == 0) {
		/* no catalog message found */
		/* Use the id and/or loctext */
		msg_rsp = mms_strapp(msg_rsp,
		    "id: %d",
		    message_id);
		if (local_text != NULL) {
			msg_rsp = mms_strapp(msg_rsp,
			    " loctext: %s",
			    local_text);
		}
		return (msg_rsp);
	}


	if (mm_msg_parse(cmd, cmd->cmd_response)) {
		mms_trace(MMS_ERR,
		    "mm_ret_response_msg: "
		    "internal error parsing message");
	}
	if (cmd->cmd_msg.msg_localized) {
		msg_rsp = mms_strapp(msg_rsp, cmd->cmd_msg.msg_localized);
		return (msg_rsp);
	}
	mms_trace(MMS_ERR,
	    "error getting message from catalog");
	msg_rsp = mms_strapp(msg_rsp, "none");
	return (msg_rsp);

}



void
mm_set_cmd_err_buf(mm_command_t *cmd, char *class, char *token) {


	mms_trace(MMS_DEBUG, "mm_set_cmd_err_buf");

	/* If a child command had an error, */
	/* we should include the message in this error response */
	/* The error response should be in cmd->cmd_response */

	mms_trace(MMS_ERR, "    Class is %s, length %d",
	    class, strlen(class));
	mms_trace(MMS_ERR, "    Token is %s, length %d",
	    token, strlen(token));

	mm_response_error(cmd,
	    class, token, MM_5019_MSG,
	    NULL);
	return;


no_mem:
	MM_ABORT_NO_MEM();
}


mm_command_t *
mm_alloc_cmd(mm_wka_t *mm_wka) {
	/* Use this function to allocate mem space */
	/* for any MMS command */
	/* Sets up command for the given wka */

	mm_data_t	*mm_data = mm_wka->mm_data;
	mm_command_t	*mm_cmd;
	cci_t		*conn = &mm_wka->wka_conn;

	mm_cmd = (mm_command_t *)calloc(1, sizeof (mm_command_t));
	if (mm_cmd == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_command_t: %s",
		    strerror(errno));
		return (NULL);
	}
	/* set initial values */
	(void) snprintf(mm_cmd->wka_uuid, sizeof (mm_cmd->wka_uuid),
	    "%s", mm_wka->wka_conn.cci_uuid);
	mm_get_uuid(mm_cmd->cmd_uuid);
	MM_SET_FLAG(mm_cmd->cmd_flags, MM_CMD_DISPATCHABLE);
	MM_SET_FLAG(mm_cmd->cmd_flags, MM_CMD_NEED_ACCEPT);
	mm_cmd->wka_ptr = mm_wka;
	mm_cmd->cmd_mm_data = mm_data;

	/* Zero ints */
	mm_cmd->cmd_state = 0;
	mm_cmd->cmd_remove = 0;
	mm_cmd->cmd_mount_info.cmi_need_clear = 0;
	mm_cmd->cmd_notify_to = 0;
	mm_cmd->cmd_begin_has_end = 0;
	mm_cmd->cmd_bufsize = 0;
	mm_cmd->cmd_source_num = 0;
	mm_cmd->cmd_dest_num = 0;
	mm_cmd->cmd_const_num = 0;
	mm_cmd->cmd_begin_has_end = 0;
	mm_cmd->cmd_notify_to = 0;

	/* char ptrs */
	mm_cmd->cmd_buf = NULL;
	mm_cmd->cmd_begin_cmd = NULL;
	mm_cmd->cmd_eclass = NULL;
	mm_cmd->cmd_ecode = NULL;
	mm_cmd->cmd_name = NULL;
	mm_cmd->cmd_task = NULL;
	mm_cmd->cmd_textcmd = NULL;
	mm_cmd->cmd_report = NULL;

	/* mount command info */
	mm_cmd->cmd_mount_info.cmi_dm = NULL;
	mm_cmd->cmd_mount_info.cmi_drive = NULL;
	mm_cmd->cmd_mount_info.cmi_library = NULL;
	mm_cmd->cmd_mount_info.cmi_cartridge = NULL;
	mm_cmd->cmd_mount_info.cmi_pcl = NULL;
	mm_cmd->cmd_mount_info.cmi_side_name = NULL;
	mm_cmd->cmd_mount_info.cmi_capability = NULL;
	mm_cmd->cmd_mount_info.cmi_handle = NULL;
	mm_cmd->cmd_mount_info.cmi_where = NULL;
	mm_cmd->cmd_mount_info.cmi_filename = NULL;
	mm_cmd->cmd_mount_info.cmi_user = NULL;
	mm_cmd->cmd_mount_info.cmi_blocksize = NULL;
	mm_cmd->cmd_mount_info.cmi_filesequence = NULL;
	mm_cmd->cmd_mount_info.cmi_volumeid = NULL;
	mm_cmd->cmd_mount_info.cmi_retention = NULL;
	mm_cmd->cmd_mount_info.cmi_first_drive = NULL;
	mm_cmd->cmd_mount_info.cmi_first_lib = NULL;
	mm_cmd->cmd_mount_info.cmi_second_drive = NULL;
	mm_cmd->cmd_mount_info.cmi_second_lib = NULL;
	mm_cmd->cmd_mount_info.cui_signature_type = NULL;
	mm_cmd->cmd_mount_info.cui_signature = NULL;

	/* Create the source and dest lists */
	mm_cmd->cmd_has_list = 1;
	mms_list_create(&mm_cmd->cmd_source_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&mm_cmd->cmd_dest_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&mm_cmd->cmd_const_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&mm_cmd->cmd_resp_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));

	/* Initalize the access mode list */
	mms_list_create(&mm_cmd->cmd_mount_info.cmi_mode_list,
	    sizeof (cmi_mode_list_t),
	    offsetof(cmi_mode_list_t, cmi_mode_next));
	mm_cmd->cmd_mount_info.cmi_total_modes = 0;
	/* initialize the cart list */
	mms_list_create(&mm_cmd->cmd_mount_info.cmi_cart_list,
	    sizeof (cmi_cart_list_t),
	    offsetof(cmi_cart_list_t, cmi_cart_next));


	mms_list_create(&mm_cmd->cmd_depend_list, sizeof (mm_command_t),
	    offsetof(mm_command_t, cmd_depend_list_next));

	/* Create Begin-end list */
	mms_list_create(&mm_cmd->cmd_beginend_list, sizeof (mm_command_t),
	    offsetof(mm_command_t, cmd_next));


	if (mm_wka->wka_hello_needed == B_FALSE) {
		/* Set Cmd->language */
		if (strcmp(conn->cci_language, "MMP") == 0) {
			mm_cmd->cmd_language = MM_LANG_MMP;
		}
		if (strcmp(conn->cci_language, "DMP") == 0) {
			mm_cmd->cmd_language = MM_LANG_DMP;
		}
		if (strcmp(conn->cci_language, "LMP") == 0) {
			mm_cmd->cmd_language = MM_LANG_LMP;
		}
	} else {
		/* Havent revieved a hello yet */
		mm_cmd->cmd_language = MM_LANG_MMP;
	}
	return (mm_cmd);
}


void
mm_get_uuid(uuid_text_t uuid)
{
	uuid_t	  uu;

	uuid_clear(uu);
	/*
	 * Hit bugid 6397009 core dumped from get_ethernet_address() using
	 * uuid_generate(uu); so use uuid_generate_random(uu); instead.
	 */
	uuid_generate_random(uu);
	uuid_unparse(uu, uuid);
}

int
mm_is_fd_valid(int fd)
{
	if (fcntl(fd, F_GETFD, 0) == -1) {
		return (-1); /* failed, fd is invalid */
	}
	return (0); /* success, fd is valid */
}

int
mm_set_fd_limit(int fd_limit)
{
	struct rlimit rlp;
	char buf[20];

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0) {
		mms_trace(MMS_ERR, "fd limit query %d: %s",
		    errno, strerror(errno));
		return (1);
	}
	if (fd_limit == -1) {
		snprintf(buf, sizeof (buf), "\"default\"");
	} else {
		snprintf(buf, sizeof (buf), "%d", fd_limit);
	}
	mms_trace(MMS_DEVP, "mm fd limit is %s", buf);
	mms_trace(MMS_DEVP, "current fd limit is %d", rlp.rlim_cur);
	mms_trace(MMS_DEVP, "max fd limit is %d", rlp.rlim_max);

	/* wants to use system's open file descriptor max */
	if (fd_limit == -1) {
		return (0);
	}

	/* sanity check */
	if (fd_limit < MM_FD_LIMIT_MIN) {
		fd_limit = MM_FD_LIMIT_MIN;
	} else if (fd_limit > MM_FD_LIMIT_MAX) {
		fd_limit = MM_FD_LIMIT_MAX;
	}
	if (fd_limit > rlp.rlim_max) {
		fd_limit = rlp.rlim_max;
	}

	/* change the current limit */
	rlp.rlim_cur = fd_limit;

	if (setrlimit(RLIMIT_NOFILE, &rlp) != 0) {
		mms_trace(MMS_ERR, "fd limit set %d: %s", errno,
		    strerror(errno));
		/* don't exit. see that the limit is unchanged */
	}

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0) {
		mms_trace(MMS_ERR, "fd limit get %d: %s",
		    errno, strerror(errno));
		return (1);
	}
	mms_trace(MMS_INFO, "current fd limit is %d", rlp.rlim_cur);
	mms_trace(MMS_INFO, "max fd limit is %d", rlp.rlim_max);
	return (0);
}

void
mm_input_file(char *buf, int *result, void *callback_parm)
{
	mm_cb_file_t	*parm = (mm_cb_file_t *)callback_parm;

	if (parm->mm_cbf_index == parm->mm_cbf_len) {
		parm->mm_cbf_index = 0;
		parm->mm_cbf_len = 0;
		if (fgets(parm->mm_cbf_buf, parm->mm_cbf_size,
		    parm->mm_cbf_fp) == NULL) {
			buf[0] = EOF;
			*result = 0;
		} else {
			parm->mm_cbf_len = strlen(parm->mm_cbf_buf);
			buf[0] = parm->mm_cbf_buf[parm->mm_cbf_index++];
			*result = 1;
		}
	} else {
		buf[0] = parm->mm_cbf_buf[parm->mm_cbf_index++];
		*result = 1;
	}
}

char *
mm_parse_error(mms_list_t *err_list)
{
	mms_par_err_t	*err;
	char		*resp;

	if ((err = mms_list_head(err_list)) == NULL) {
		return (NULL);
	}
	resp = mms_strnew("response unacceptable "
	    "message [ id [ \"ieee\" \"1244\" \"5000\" ] "
	    "arguments [ "
	    "\"line\" \"%d\" "
	    "\"col\" \"%d\" "
	    "\"token\" \"%s\" "
	    "\"code\" \"%d\" "
	    "\"msg\" \"%s\" ] "
	    "loctext [ \"en\" \"line %d col %d "
	    "token %s code %d msg %s\" ] ]; ", err->pe_line,
	    err->pe_col, err->pe_token, err->pe_code,
	    err->pe_msg, err->pe_line, err->pe_col,
	    err->pe_token, err->pe_code, err->pe_msg);

	return (resp);
}

mms_par_node_t *
mm_text_to_par_node(char *buf, parser_func_t parse_func)
{
	mms_par_node_t	*cmd;
	mms_list_t		 err_list;
	int		 rc;
	mms_par_err_t	*err;

	rc = parse_func(&cmd, &err_list, buf);
	if (rc) {
		if (err = mms_list_head(&err_list)) {
			mms_trace(MMS_ERR, "parse error\n"
			    "line %d col %d token %s code %d msg %s\n%s",
			    err->pe_line, err->pe_col,
			    err->pe_token, err->pe_code,
			    err->pe_msg, buf);
		} else {
			mms_trace(MMS_ERR, "parse error");
		}
		mms_pe_destroy(&err_list);
		mms_pn_destroy(cmd);
		return (NULL);
	}
	mms_pe_destroy(&err_list);
	return (cmd);
}


void
mm_send_response(mms_t *conn, mm_command_t *cmd)
{

	/* Response list */
	mms_list_t		*resp_list = &cmd->cmd_resp_list;
	mm_char_list_t *cur_resp;
	mm_char_list_t *next_resp;

	int		sent_one = 0;
	int		sent_count = 0;

	mms_trace(MMS_DEVP, "mm_send_response");

	for (cur_resp = mms_list_head(resp_list);
	    cur_resp != NULL;
	    cur_resp = next_resp) {
		next_resp = mms_list_next(resp_list, cur_resp);
		if (cur_resp->text != NULL) {
			mm_send_text(conn, cur_resp->text);
			sent_count ++;
			sent_one = 1;
		}
	}
	mms_trace(MMS_DEVP, "sent %d responses from list",
	    sent_count);
	if (!sent_one) {
		/* If there was not a response in the list */
		/* check the cmd_buf and send */
		mms_trace(MMS_DEVP,
		    "no response in list");
		if (cmd->cmd_buf != NULL) {
			/* No response in the list */
			/* send the cmd_buf */
			mms_trace(MMS_DEVP,
			    "no resp in list, send cmd_buf");
			mm_send_text(conn, cmd->cmd_buf);
		}
	}

}


void
mm_send_text(mms_t *conn, char *buf)
{
	int		 rc;
	char		 ebuf[MMS_EBUF_LEN];
	int		 len;

	len = strlen(buf);
	rc = mms_writer(conn, buf);

	if (rc != len) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "send buf fd -> %d, count %d\n\n%s\n%s\n",
		    conn->mms_fd, len, buf, ebuf);
		mms_close(conn);
		return;
	} else {
		mms_trace(MMS_DEVP, "sent fd -> %d, count %d\n\n%s\n",
		    conn->mms_fd, len, buf);
	}
}

void
mm_send_text_si(mms_t *conn, char *buf)
{
	int		 rc;
	char		 ebuf[MMS_EBUF_LEN];
	int		 len;

	len = strlen(buf);
	rc = mms_writer(conn, buf);

	if (rc != len) {
		mms_get_error_string(&conn->mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "send buf fd -> %d, count %d\n\n%s\n%s\n",
		    conn->mms_fd, len, buf, ebuf);
		mms_close(conn);
		return;
	} else {
		mms_trace(MMS_DEVP, "sent fd -> %d, count %d\n\n",
		    conn->mms_fd, len);
	}
}

int
mm_parse_response(mms_par_node_t *root, mm_response_t *response)
{
	mms_par_node_t	*arg;
	mms_par_node_t	*value;
	mms_par_node_t	*work;
	char		*text;

	text = mms_pn_build_cmd_text(root);
	mms_trace(MMS_DEVP, "parse response\n%s", text);
	free(text);

	if (mms_pn_lookup(root, "response", MMS_PN_CMD, NULL) == NULL) {
		return (1);
	}

	if (arg = mms_pn_lookup(root, "accepted", MMS_PN_KEYWORD, NULL)) {
		response->response_type = MM_RESPONSE_ACCEPTED;
		response->response_string = arg->pn_string;
	} else if (arg = mms_pn_lookup(root, "unacceptable",
	    MMS_PN_KEYWORD, NULL)) {
		response->response_type = MM_RESPONSE_UNACCEPTABLE;
		response->response_string = arg->pn_string;
	} else if (arg = mms_pn_lookup(root, "success",
	    MMS_PN_KEYWORD, NULL)) {
		response->response_type = MM_RESPONSE_SUCCESS;
		response->response_string = arg->pn_string;
	} else if (arg = mms_pn_lookup(root, "cancelled",
	    MMS_PN_KEYWORD, NULL)) {
		response->response_type = MM_RESPONSE_CANCELLED;
		response->response_string = arg->pn_string;
	} else if (arg = mms_pn_lookup(root, "error",
	    MMS_PN_CLAUSE, NULL)) {
		response->response_type = MM_RESPONSE_ERROR;
		response->response_string = arg->pn_string;

		work = NULL;
		if (value = mms_pn_lookup(arg, NULL,
		    MMS_PN_KEYWORD, &work)) {
			response->error_class = value->pn_string;
		}

		if (value = mms_pn_lookup(arg, NULL,
		    MMS_PN_KEYWORD, &work)) {
			response->error_code = value->pn_string;
		}
	}

	/* TODO: response text and message clauses */

	return (0);
}

/* get client connection hostname and ip mms_address from IPv4 or IPv6 */
int
mm_connect_info(int fd, cci_t *conn)
{
	int		sa_len;
	union {
		struct sockaddr *sa;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
	} sa;
	const int	host_len = sizeof (mms_cli_host_t);
	mms_cli_host_t	host_str;


	sa.sa = (struct sockaddr *)calloc(sizeof (char), host_len);
	if (sa.sa == NULL) {
		return (1);
	}
	sa_len = host_len;

	if (getpeername(fd, sa.sa, &sa_len)) {
		free(sa.sa);
		return (1);
	} else if (sa.sa->sa_family == AF_INET) {
		if (inet_ntop(AF_INET, &sa.sin->sin_addr,
		    host_str, host_len) == NULL) {
			free(sa.sa);
			return (1);
		}
		conn->cci_port = sa.sin->sin_port;
	} else if (sa.sa->sa_family == AF_INET6) {
		if (inet_ntop(AF_INET6, &sa.sin6->sin6_addr,
		    host_str, host_len) == NULL) {
			free(sa.sa);
			return (1);
		}
		conn->cci_port = sa.sin6->sin6_port;
	} else {
		free(sa.sa);
		return (1);
	}
	free(sa.sa);

	if (mms_host_ident(host_str, conn->cci_host, conn->cci_ip) == NULL) {
		return (1);
	}

	return (0);
}

/* get host from mm data as represented internally by mm */
char *
mm_data_host_ident(mm_data_t *data)
{
	return (data->mm_host_ip);
}

/* get host from work area as represented internally by mm */
char *
mm_wka_host_ident(mm_wka_t *wka)
{
	return (wka->wka_conn.cci_ip);
}

/* get host from command as represented internally by mm */
char *
mm_cmd_host_ident(mm_command_t *cmd)
{
	return (cmd->wka_ptr->wka_conn.cci_ip);
}

/* get host from cci as represented internally by mm */
char *
mm_cci_host_ident(cci_t *conn)
{
	return (conn->cci_ip);
}

/* get host from string as represented internally by mm */
char *
mm_host_ident(char *host_str)
{
	mms_cli_host_t host;
	cci_ip_t ip;
	char *ident;

	if ((ident = mms_host_ident(host_str, host, ip)) == NULL) {
		return (NULL);
	}
	return (strdup(ident));
}

void
mm_write_trace_level(mms_trace_sev_t severity)
{
	char		*value;

	if ((value = mms_trace_sev2str(severity)) == NULL) {
		value = mms_trace_sev2str(MMS_SEV_ERROR);
	}
	(void) mms_cfg_setvar(MMS_CFG_MM_TRACE, value);
}

mms_trace_sev_t
mm_read_trace_level(void)
{
	char		*value;
	mms_trace_sev_t	severity;

	if ((value = mms_cfg_alloc_getvar(MMS_CFG_MM_TRACE, NULL)) == NULL) {
		severity = MMS_SEV_ERROR;
	} else {
		(void) mms_trace_str2sev(value, &severity);
	}
	if (value)
		free(value);
	return (severity);
}

void
mm_reconcile_trace_level(mm_db_t *db)
{
	char		*level;
	mms_trace_sev_t	db_severity;
	mms_trace_sev_t	file_severity;

	/*
	 * Reconcile file and database mms_trace level.
	 */
	if (mm_db_exec(HERE, db, "select \"TraceLevel\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		mm_clear_db(&db->mm_db_results);
		return;
	}
	if (PQntuples(db->mm_db_results) != 1) {
		mm_clear_db(&db->mm_db_results);
		return;
	}
	level = PQgetvalue(db->mm_db_results, 0, 0);
	(void) mms_trace_str2sev(level, &db_severity);
	mm_clear_db(&db->mm_db_results);
	file_severity = mm_read_trace_level();
	if (file_severity != db_severity) {
		if ((level = mms_trace_sev2str(file_severity)) == NULL) {
			mm_write_trace_level(db_severity);
			(void) mms_trace_filter(db_severity);
		} else if (mm_db_exec(HERE, db, "update \"SYSTEM\" set "
		    "\"TraceLevel\" = '%s';", level) != MM_DB_OK) {
			mm_clear_db(&db->mm_db_results);
		}
	}
}

int
mm_get_fd_limit(mm_db_t *db)
{
	int	limit;

	/*
	 * Get the allowed number of open sockets from the database
	 */
	if (mm_db_exec(HERE, db, "select \"SocketFdLimit\" from "
	    "\"SYSTEM\";") != MM_DB_DATA) {
		limit = -1;
	} else if (PQntuples(db->mm_db_results) != 1) {
		limit = -1;
	} else {
		limit = atoi(PQgetvalue(db->mm_db_results, 0, 0));
	}
	mm_clear_db(&db->mm_db_results);

	if (!(limit == -1 || (limit >= 1 && limit <= 65536))) {
		limit = -1;
	}
	mms_trace(MMS_DEVP, "socket fd limit %d", limit);
	return (limit);
}


char *
mm_return_char(mms_list_t *list, int index) {
	mm_char_list_t *node;
	mm_char_list_t *next;
	int count = 0;

	for (node = mms_list_head(list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(list, node);
		if (count == index) {
			return (node->text);
		}
		count ++;
	}
	return (NULL);
}



int
mm_add_char(char *str, mms_list_t *list) {
	mm_char_list_t *node;


	node =
	    (mm_char_list_t *)malloc(sizeof (mm_char_list_t));

	if (node == NULL) {
		mms_trace(MMS_ERR, "Error malloc source object");
		return (1);
	} else {
		memset(node, 0, sizeof (mm_char_list_t));
		node->text = NULL;
		node->text = mms_strapp(node->text, str);
		mms_list_insert_tail(list, node);
	}
	return (0);

}

void
mm_free_list(mms_list_t *list) {
	mm_char_list_t *cur;
	mm_char_list_t *next;

	for (cur = mms_list_head(list);
	    cur != NULL;
	    cur = next) {
		next = mms_list_next(list, cur);
		if (cur->text)
			free(cur->text);
		mms_list_remove(list,
		    cur);
		free(cur);
	}
}

int
mm_add_int(int number, mms_list_t *list) {
	mm_char_list_t *node;

	node =
	    (mm_char_list_t *)malloc(sizeof (mm_char_list_t));

	if (node == NULL) {
		mms_trace(MMS_ERR, "Error malloc source object");
		return (1);
	} else {
		memset(node, 0, sizeof (mm_char_list_t));
		node->number = number;
		mms_list_insert_tail(list, node);
	}
	return (0);

}


void
mm_print_char_list(mms_list_t *list) {
	mm_char_list_t *node;
	mm_char_list_t *next;

	for (node = mms_list_head(list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(list, node);
		mms_trace(MMS_DEVP, "    %s", node->text);
	}
}

int
mm_in_char_list(mms_list_t *list, char *str) {
	mm_char_list_t *node;
	mm_char_list_t *next;

	for (node = mms_list_head(list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(list, node);
		if (strcmp(node->text, str) == 0) {
			/* same */
			return (1);
		}
	}
	return (0);



}

int
mm_replace_char(mms_list_t *list, int index, char *str) {
	mm_char_list_t *node;
	mm_char_list_t *next;
	int count = 0;

	for (node = mms_list_head(list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(list, node);
		if (count == index) {
			free(node->text);
			node->text = strdup(str);
			return (0);
		}
	}
	return (1);
}


int
mm_add_obj_list(mms_list_t *list, char *obj) {
	mm_char_list_t	*mm_char_struct;

	mm_char_list_t	*cur_char;
	mm_char_list_t	*next;
	/* If the obj is already in the list, skip */
	for (cur_char = mms_list_head(list);
	    cur_char != NULL;
	    cur_char = next) {
		next = mms_list_next(list, cur_char);
		if (strcmp(cur_char->text, obj) == 0) {
			/* already have this obj */
			return (1);
		}
	}
	/* Don't have this obj yet */
	mm_char_struct = (mm_char_list_t *)
	    calloc(1, sizeof (mm_char_list_t));
	if (mm_char_struct == NULL) {
		mms_trace(MMS_ERR,
		    "Unable to malloc mm_char_list_t: %s",
		    strerror(errno));
		return (1);
	}
	mm_char_struct->text = strdup(obj);
	mms_list_insert_tail(list, mm_char_struct);
	return (0);

}

int
mm_add_to_source(mm_command_t *cmd, char *str) {

	mms_list_t *source_list = &cmd->cmd_source_list;

	if (mm_add_obj_list(source_list,
	    str) == 0) {
		cmd->cmd_source_num ++;
		return (0);
	}
	return (1);
}
int
mm_add_to_dest(mm_command_t *cmd, char *str) {

	mms_list_t *dest_list = &cmd->cmd_dest_list;

	if (mm_add_obj_list(dest_list,
	    str) == 0) {
		cmd->cmd_dest_num ++;
		return (0);
	}
	return (1);
}
int
mm_add_to_const(mm_command_t *cmd, char *str) {

	mms_list_t *const_list = &cmd->cmd_const_list;

	if (mm_add_obj_list(const_list,
	    str) == 0) {
		cmd->cmd_const_num ++;
		return (0);
	}
	return (1);
}
