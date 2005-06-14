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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RDR_PARAM_TYPES_H
#define	_RDR_PARAM_TYPES_H

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
 * This file contains the structures that are exposed to the clients
 * of the Remote DR (RDR) module. They represent the data that is
 * required for the various RDR operations. They are passed into
 * the rdr_snd_msg() function and returned from the rdr_rcv_msg()
 * function.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <config_admin.h>
#include <time.h>

#ifdef SMSLIB_TARGET
#include <libscri/rsrc_info.h>
#else
#include "rsrc_info.h"
#endif /* SMSLIB_TARGET */


typedef time_t timeout_t;


typedef struct {
	char			*locale_str;
	unsigned long		session_id;
} ses_req_params_t;


typedef struct {
	unsigned int		error_code;
} ses_end_params_t;


typedef struct {
	cfga_cmd_t 		state_change;
	int			num_ap_ids;
	char *const 		*ap_ids;
	char  			*options;	/* const */
	struct cfga_confirm 	*confp;
	struct cfga_msg		*msgp;
	char			**errstring;
	cfga_flags_t 		flags;
	timeout_t 		timeval;
	int 			retries;
} change_state_params_t;


typedef struct {
	char			*function;	/* const */
	int			num_ap_ids;
	char *const		*ap_ids;
	char 			*options;	/* const */
	struct cfga_confirm 	*confp;
	struct cfga_msg		*msgp;
	char			**errstring;
	cfga_flags_t 		flags;
} private_func_params_t;


typedef struct {
	int			num_ap_ids;
	char *const		*ap_ids;
	char			*options;	/* const */
	struct cfga_msg		*msgp;
	char			**errstring;
	cfga_flags_t 		flags;
} test_params_t;


/*
 * A wrapper around the cfga_list_data_t
 * that allows sorting information to be
 * associated with each ap_id in an array.
 */
typedef struct {
	uint64_t		sort_order;
	cfga_list_data_t	ap_id_info;
} rdr_list_t;


typedef struct {
	int 			num_ap_ids;
	char			**ap_ids;
	rdr_list_t		**ap_id_list;
	int			*nlist;
	char			*options;
	char			*listopts;
	char			**errstring;
	int 			flags;
	unsigned int		permissions;
} list_ext_params_t;


typedef struct {
	int			num_ap_ids;
	char			**ap_ids;
	struct cfga_msg		*msgp;
	char 			*options;	/* const */
	cfga_flags_t 		flags;
} help_params_t;


typedef struct {
	char			*ap_log_id1;
	char			*ap_log_id2;
} ap_id_cmp_params_t;


typedef struct {
	unsigned long		session_id;
} abort_cmd_params_t;


typedef struct {
	struct cfga_confirm	*confp;
	char			*message;
	int 			response;
} confirm_callback_params_t;


typedef struct {
	struct cfga_msg		*msgp;
	char			*message;
} msg_callback_params_t;


typedef struct {
	int			num_ap_ids;
	char			**ap_ids;
	int			flags;
	ri_hdl_t		*hdl;
} rsrc_info_params_t;


typedef union {
	ses_req_params_t	req;
	ses_end_params_t	end;
	change_state_params_t	change;
	private_func_params_t	priv;
	test_params_t		test;
	list_ext_params_t	list_ext;
	help_params_t		help;
	ap_id_cmp_params_t	cmp;
	abort_cmd_params_t	abort;
	confirm_callback_params_t  conf_cb;
	msg_callback_params_t	msg_cb;
	rsrc_info_params_t	rsrc_info;
} cfga_params_t;


#ifdef __cplusplus
}
#endif

#endif	/* _RDR_PARAM_TYPES_H */
