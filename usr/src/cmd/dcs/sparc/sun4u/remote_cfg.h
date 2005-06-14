/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _REMOTE_CFG_H
#define	_REMOTE_CFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING: The contents of this file are shared by all projects
 * that  wish to  perform  remote  Dynamic Reconfiguration  (DR)
 * operations. Copies of this file can be found in the following
 * locations:
 *
 *	Project	    Location
 *	-------	    --------
 *	Solaris	    usr/src/cmd/dcs/sparc/sun4u/%M%
 *	SMS	    src/sms/lib/librdr/%M%
 *
 * In order for proper communication to occur,  the files in the
 * above locations must match exactly. Any changes that are made
 * to this file should  be made to all of the files in the list.
 */

/*
 * This file contains definitions for a transport layer interface socket
 * interface between a domain configuration server (DCS) and a domain
 * configuration agent (DCA). The domain configuration server resides
 * within Solaris on a domain. The domain configuration agent resides on
 * the system controller.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * The data_type field indicates whether the message is REQUEST
 * or REPLY.
 */
typedef enum {
	RDR_REQUEST = 1,
	RDR_REPLY
} rdr_msg_data_type_t;


/*
 * The error_msg_ctl field indicates whether error messages
 * should be generated or not. See the errstring argument in
 * the config_admin(3CFGADM) man page.
 */
typedef enum {
	RDR_GENERATE_ERR_MSGS = 1,
	RDR_DONT_GENERATE_ERR_MSGS
} rdr_error_msg_ctl_t;


/*
 * The list_msg_ctl field indicates whether a list should
 * be generated for all attachment points in the device tree or
 * only those attachment points specified in the message. See
 * the comment on the first two arguments for config_list_ext
 * in the config_admin(3CFGADM) man page.
 */
typedef enum {
	RDR_LIST_ONLY_PARAM_APS = 1,
	RDR_LIST_ALL_APS
} rdr_list_msg_control_t;


/*
 * The permissions field indicates if the list_ext command should
 * filter out attachment points that the remote user doesn't have
 * sufficient access permissions to view.
 */
typedef enum {
	RDR_NOT_PRIVILEGED = 0,
	RDR_PRIVILEGED
} rdr_list_permission_control_t;


/*
 * The message_opcode value of the message indicates the purpose
 * of the request. The defined values for message_opcode are:
 */
typedef enum {
	RDR_SES_REQ = 1,	   /* Session open.			   */
	RDR_SES_ESTBL,		   /* Session Establishment.		   */
	RDR_SES_END,		   /* Session end.			   */
	RDR_CONF_CHANGE_STATE,	   /* Change state of an attachment point. */
	RDR_CONF_PRIVATE_FUNC,	   /* Invoke h/w specific func.		   */
	RDR_CONF_TEST,		   /* Test the system board.		   */
	RDR_CONF_LIST_EXT,	   /* Listing interface.		   */
	RDR_CONF_HELP,		   /* Request output of localized help msg */
	RDR_CONF_AP_ID_CMP,	   /* Compare two attachment point ids.	   */
	RDR_CONF_ABORT_CMD,	   /* Abort the current config command.	   */
	RDR_CONF_CONFIRM_CALLBACK, /* Confirm call-back.		   */
	RDR_CONF_MSG_CALLBACK,	   /* Message call-back.		   */
	RDR_RSRC_INFO,		   /* System board resource info.	   */
	RDR_NUM_OPS
} rdr_msg_opcode_t;


/*
 * The status is valid only if the data_type is REPLY. The possible
 * values for status are, FAILED or SUCCESS.
 */
typedef enum {
	RDR_SUCCESS = 0,
	RDR_FAILED
} dr_msg_status_t;


/*
 * The following typedefs define message formats for use in the
 * rdr_msg_type_t union. The rdr_msg_type_t union contains the
 * majority of the information in the messages sent between the
 * DCS and DCA.
 *
 * Some types require variable length data to follow the fixed
 * length information in the struct. If this is required, a
 * comment is placed at the end of the struct that shows the
 * contents of that information along with the required number
 * of bytes.
 *
 * All *_size fields are the length of the string + 1 to account
 * for NULL termination.
 */


typedef struct {
	unsigned int		locale_size;
	/* locale string (locale_size bytes)	 */
} rdr_ses_req_t;


typedef struct {
	unsigned long		session_id;
} rdr_ses_req_reply_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	unsigned int		options_size;
	unsigned long		confirm_callback_id;
	unsigned long		confirm_appdata_ptr;
	unsigned long		msg_callback_id;
	unsigned long		msg_appdata_ptr;
	unsigned long		flags;
	unsigned long		timeval;
	unsigned short 		state_change_cmd;
	unsigned short		error_msg_ctl;
	char			retries;
	char			pad_byte1;
	/* ap id strings (ap_id_char_size bytes) */
	/* option string (options_size bytes)	 */
} rdr_change_state_t;


typedef struct {
	unsigned int		errstring_size;
	/* error string (errstring_size bytes)	 */
} rdr_change_state_reply_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	unsigned int		options_size;
	unsigned int		function_size;
	unsigned long		confirm_callback_id;
	unsigned long		confirm_appdata_ptr;
	unsigned long		msg_callback_id;
	unsigned long		msg_appdata_ptr;
	unsigned long		flags;
	unsigned short		error_msg_ctl;
	char			pad_byte1;
	char			pad_byte2;
	/* ap id strings (ap_id_char_size bytes) */
	/* option string (options_size bytes)	 */
	/* function string (function_size bytes) */
} rdr_private_func_t;


typedef struct {
	unsigned int		errstring_size;
	/* error string (errstring_size bytes)	 */
} rdr_private_func_reply_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	unsigned int		options_size;
	unsigned long		msg_callback_id;
	unsigned long		msg_appdata_ptr;
	unsigned long		flags;
	unsigned short		error_msg_ctl;
	char			pad_byte1;
	char			pad_byte2;
	/* ap id strings (ap_id_char_size bytes) */
	/* option string (options_size bytes)	 */
} rdr_test_t;


typedef struct {
	unsigned int		errstring_size;
	/* error string (errstring_size bytes)	 */
} rdr_test_reply_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	unsigned int		options_size;
	unsigned int		listopts_size;
	unsigned short		error_msg_ctl;
	unsigned short		list_msg_ctl;
	unsigned long		flags;
	unsigned int		permissions;
	/* ap id strings (ap_id_char_size bytes) */
	/* option string (options_size bytes)	 */
	/* list opt string (listopts_size bytes) */
} rdr_list_ext_t;


/*
 * The num_ap_ids is the total number of ap_ids in the sequence of
 * messages for the list_ext reply. The list data array is an
 * array of cfga_list_data_t (see config_admin (3CFGA)) structs
 * that has num_ap_ids elements.
 */
typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		errstring_size;
	/* list data array (num_ap_ids elements) */
	/* error string (errstring_size bytes)	 */
} rdr_list_ext_reply_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	unsigned long 		msg_callback_id;
	unsigned long		msg_appdata_ptr;
	unsigned int		options_size;
	unsigned long 		flags;
	/* ap id strings (ap_id_char_size bytes) */
	/* option string (options_size bytes)	 */
} rdr_help_t;


typedef struct {
	unsigned int		ap_id1_size;
	unsigned int		ap_id2_size;
	/* ap id 1 string (ap_id1_size bytes)	 */
	/* ap id 2 string (ap_id1_size bytes)	 */
} rdr_ap_id_cmp_t;


typedef struct {
	unsigned long		session_id;
} rdr_abort_cmd_t;


typedef struct {
	unsigned long		confirm_callback_id;
	unsigned long		appdata_ptr;
	unsigned int		message_size;
	/* prompt message (message_size bytes)	 */
} rdr_confirm_callback_t;


typedef struct {
	unsigned long		confirm_callback_id;
	unsigned long		appdata_ptr;
	int			response;
} rdr_confirm_callback_reply_t;


typedef struct {
	unsigned long		msg_callback_id;
	unsigned long		appdata_ptr;
	unsigned int		message_size;
	/* user message (message_size bytes)	 */
} rdr_msg_callback_t;


typedef struct {
	unsigned int		num_ap_ids;
	unsigned int		ap_id_char_size;
	int			flags;
	/* ap id strings (ap_id_char_size bytes) */
} rdr_rsrc_info_t;


typedef struct {
	unsigned long		packed_hdl_size;
	/* rsrc info buf (packed_hdl_size bytes) */
} rdr_rsrc_info_reply_t;


typedef union {
	rdr_ses_req_t			ses_req;
	rdr_ses_req_reply_t		ses_req_reply;
	rdr_change_state_t 		change_state;
	rdr_change_state_reply_t 	change_state_reply;
	rdr_private_func_t 		private_func;
	rdr_private_func_reply_t	private_func_reply;
	rdr_test_t			test;
	rdr_test_reply_t		test_reply;
	rdr_list_ext_t			list_ext;
	rdr_list_ext_reply_t		list_ext_reply;
	rdr_help_t			help;
	rdr_ap_id_cmp_t			ap_id_cmp;
	rdr_abort_cmd_t			abort;
	rdr_confirm_callback_t		confirm_callback;
	rdr_confirm_callback_reply_t	confirm_callback_reply;
	rdr_msg_callback_t		msg_callback;
	rdr_rsrc_info_t			rsrc_info;
	rdr_rsrc_info_reply_t		rsrc_info_reply;
} rdr_msg_type_t;


/*
 * The RDR message will contain the following members:
 */
typedef struct {
	unsigned long	data_length;

	/* Message Op, Type, and Status */
	unsigned char	message_opcode;		/* rdr_msg_opcode_t 	*/
	unsigned char	data_type;		/* rdr_msg_data_type_t	*/
	char		pad_byte1;
	char		pad_byte2;
	unsigned long	status;			/* rdr_msg_status_t	*/

	/* These are for security and version */
	unsigned long	random_req;
	unsigned long	random_resp;

	unsigned short	major_version;
	unsigned short	minor_version;
} rdr_msg_hdr_t;


/*
 * The RDR message body:
 */
typedef struct {
	rdr_msg_hdr_t 	app;
	rdr_msg_type_t	conf;
} rdr_msg_t;


#ifdef __cplusplus
}
#endif

#endif /* _REMOTE_CFG_H */
