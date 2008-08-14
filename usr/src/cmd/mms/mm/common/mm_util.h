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


#ifndef	_MM_UTIL_H
#define	_MM_UTIL_H

/*
 * Parser command xml text file line callback structure
 */
typedef struct mm_cb_file mm_cb_file_t;
struct mm_cb_file {		/* parser file callback */
	FILE		 *mm_cbf_fp;
	char		 *mm_cbf_buf;
	int		  mm_cbf_len;
	int		  mm_cbf_index;
	int		  mm_cbf_size;
	mms_par_node_t	**mm_cbf_node;
};

/*
 * Enumerated response string
 */
typedef enum mm_response_type mm_response_type_t;
enum mm_response_type {
	MM_RESPONSE_SUCCESS,
	MM_RESPONSE_ACCEPTED,
	MM_RESPONSE_UNACCEPTABLE,
	MM_RESPONSE_CANCELLED,
	MM_RESPONSE_ERROR
};

/*
 * Response parse tree pointers
 */
typedef struct mm_response mm_response_t;
struct mm_response {
	char			*response_string;
	mm_response_type_t	 response_type;
	char			*error_class;
	char			*error_code;
};


typedef struct mm_char_list mm_char_list_t;
struct mm_char_list {
	mms_list_node_t		mm_char_list_next;
	char			*text;
	int			number;
};

/*
 * MM, MMP, DMP, LMP routines
 */
extern void	 mm_get_uuid(uuid_text_t uuid);
extern int	 mm_is_fd_valid(int fd);
extern int	 mm_set_fd_limit(int fd_limit);
extern void	 mm_input(char *buf, int *result, int max, void *callback);
extern void	 mm_input_file(char *buf, int *result, void *callback);
extern char	*mm_parse_error(mms_list_t *err_list);
extern mms_par_node_t *mm_text_to_par_node(char *buf, parser_func_t parse_func);
extern void	 mm_send_text(mms_t *conn, char *buf);
extern void	 mm_send_text_si(mms_t *conn, char *buf);
extern void	 mm_send_response(mms_t *conn, mm_command_t *cmd);
extern int	 mm_parse_response(mms_par_node_t *cmd,
    mm_response_t *response);
extern int	 mm_connect_info(int fd, cci_t *conn);
/* get host from data type as represented internally by mm */
extern char	*mm_data_host_ident(mm_data_t *data);
extern char	*mm_wka_host_ident(mm_wka_t *wka);
extern char	*mm_cmd_host_ident(mm_command_t *cmd);
extern char	*mm_cci_host_ident(cci_t *conn);
extern char	*mm_host_ident(char *host_str);
extern mms_trace_sev_t	mm_read_trace_level(void);
extern void	mm_write_trace_level(mms_trace_sev_t sev);
extern void	mm_reconcile_trace_level(mm_db_t *db);
extern int	mm_get_fd_limit(mm_db_t *db);
extern int	mm_add_char(char *str, mms_list_t *list);
extern int	mm_add_int(int number, mms_list_t *list);
extern void	mm_print_char_list(mms_list_t *list);
extern int	mm_in_char_list(mms_list_t *list, char *str);
extern char	*mm_return_char(mms_list_t *list, int index);
extern void	mm_free_list(mms_list_t *list);
extern char	*mm_ret_response_msg(mm_command_t *cmd);
#endif /* _MM_UTIL_H */
