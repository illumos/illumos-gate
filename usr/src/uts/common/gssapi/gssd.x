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
%/*
% * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%
%/*
% *  RPC protocol information for gssd, the usermode daemon that
% *  assists the kernel with gssapi. It is gssd that executes all
% *  gssapi calls except for some such as gss_sign(), and
% *  gss_verify(), which are executed in the kernel itself.
% *
% *  File generated from gssd.x
% */
%
%#define	NO 0
%#define	YES 1
%#define	FOREVER 1
%
%#include <sys/types.h>
%#include <sys/time.h>
%#include <rpc/auth_sys.h>
%#ifndef _KERNEL
%#include <locale.h>
%#endif /* not _KERNEL */
%

%#ifdef _KERNEL
%extern void killgssd_handle(CLIENT *);
%extern CLIENT *getgssd_handle(void);
%#endif /* _KERNEL */
%
/*
 * These are the definitions for the interface to GSSD.
 */

typedef unsigned int				OM_UINT32;

typedef opaque					GSS_CTX_ID_T<>;
typedef opaque					GSS_CRED_ID_T<>;
typedef opaque					GSS_OID<>;
typedef opaque					GSS_BUFFER_T<>;
typedef gid_t					GSSCRED_GIDS<>;

typedef GSS_OID					GSS_OID_SET<>;

struct GSS_CHANNEL_BINDINGS_STRUCT {
	int		present;
	OM_UINT32	initiator_addrtype;
	GSS_BUFFER_T	initiator_address;
	OM_UINT32	acceptor_addrtype;
	GSS_BUFFER_T    acceptor_address;
	GSS_BUFFER_T    application_data;
};

typedef	struct GSS_CHANNEL_BINDINGS_STRUCT	GSS_CHANNEL_BINDINGS;

struct gss_acquire_cred_arg {
	uid_t		uid;			/* client uid */
	GSS_BUFFER_T	desired_name;		/* name of cred */
	GSS_OID		name_type;		/* type of desired name */
	OM_UINT32	time_req;		/* context validity interval */
	GSS_OID_SET	desired_mechs;		/* cred mechanisms */
	int		cred_usage;		/* init/accept/both */
};

struct gss_acquire_cred_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_CRED_ID_T	output_cred_handle;	/* returned credential handle */
	OM_UINT32	gssd_cred_verifier; 	/* verifier for cred handle */
	GSS_OID_SET	actual_mechs;		/* found cred mechanisms */
	OM_UINT32	time_rec;		/* actual context validity */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_add_cred_arg {
	uid_t		uid;			/* client uid */
	GSS_CRED_ID_T	input_cred_handle;	/* input credential handle */
	OM_UINT32	gssd_cred_verifier; 	/* verifier for cred handle */
	GSS_BUFFER_T	desired_name;		/* name of cred */
	GSS_OID		name_type;		/* type of desired name */
	GSS_OID		desired_mech_type;	/* cred mechanisms */
	int		cred_usage;		/* init/accept/both */
	OM_UINT32	initiator_time_req;	/* context validity interval */
	OM_UINT32	acceptor_time_req;	/* context validity interval */
};
/* Note: For gss_add_cred we always update the underlying credentials of 
 * input_cred_handle. We always pass NULL as output_cred_handle when the call
 * to gss_add_cred is made 
*/
struct gss_add_cred_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_OID_SET	actual_mechs;		/* found cred mechanisms */
	OM_UINT32	initiator_time_rec;	/* cred validity interval */
	OM_UINT32	acceptor_time_rec;	/* cred validity interval */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_release_cred_arg {
	uid_t		uid;			/* client uid */
	OM_UINT32	gssd_cred_verifier; 	/* verifier for cred handles */
	GSS_CRED_ID_T	cred_handle;		/* credential handle */
};

struct gss_release_cred_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_init_sec_context_arg {
	uid_t		uid;			/* client uid */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CRED_ID_T	claimant_cred_handle;	/* must = GSS_C_NO_CREDENTIAL */
	OM_UINT32	gssd_cred_verifier;	/* verifier for cred handle */
	GSS_BUFFER_T	target_name;		/* name of server */
	GSS_OID		name_type;		/* type of principal name */
	GSS_OID		mech_type;		/* requested mechanism */
	int		req_flags;		/* requested context options */
	OM_UINT32	time_req;		/* context validity interval */
	GSS_CHANNEL_BINDINGS
			input_chan_bindings;	/* requested channel bindings */
	GSS_BUFFER_T	input_token;		/* token to send to peer */
};

struct gss_init_sec_context_res {
	GSS_CTX_ID_T	context_handle;		/* handle to created context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_OID		actual_mech_type;	/* actual mechanism used */
	GSS_BUFFER_T	output_token;		/* where peer token is put */
	OM_UINT32	ret_flags;		/* options of context */
	OM_UINT32	time_rec;		/* actual context validity */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_accept_sec_context_arg {
	uid_t		uid;			/* client uid */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CRED_ID_T	verifier_cred_handle;	/* must = GSS_C_NO_CREDENTIAL */
	OM_UINT32	gssd_cred_verifier;	/* verifier for cred handle */
	GSS_BUFFER_T	input_token_buffer;	/* token to send to peer */
	GSS_CHANNEL_BINDINGS
			input_chan_bindings;	/* requested channel bindings */
};

struct gss_accept_sec_context_res {
	GSS_CTX_ID_T	context_handle;		/* handle to created context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_BUFFER_T	src_name;		/* authenticated name of peer */
	GSS_OID		mech_type;		/* mechanism used */
	GSS_BUFFER_T	output_token;		/* where peer token is put */
	OM_UINT32	ret_flags;		/* options of context */
	OM_UINT32	time_rec;		/* actual context validity */
	GSS_CRED_ID_T	delegated_cred_handle;	/* always GSS_C_NO_CREDENTIAL */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_process_context_token_arg {
	uid_t		uid;			/* client uid */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	GSS_BUFFER_T	token_buffer;		/* token to process */
};

struct gss_process_context_token_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_delete_sec_context_arg {
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
};

struct gss_delete_sec_context_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_CTX_ID_T	context_handle;		/* handle to deleted context */
	GSS_BUFFER_T	output_token;		/* output token for peer */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_export_sec_context_arg {
        GSS_CTX_ID_T context_handle;		/* handle to existing context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
};

struct gss_export_sec_context_res {
        OM_UINT32	minor_status;		/* status from the mechanism */
        GSS_CTX_ID_T	context_handle;		/* handle to existing context */
        GSS_BUFFER_T	output_token;		/* input token for import_sec_context */
        OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_import_sec_context_arg {
        GSS_BUFFER_T	input_token;		/* input token for import_sec_context */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
};

struct gss_import_sec_context_res {
        OM_UINT32	minor_status;		/* status from the mechanism */
        GSS_CTX_ID_T	context_handle;		/* handle to created context */
        OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_context_time_arg {
	uid_t		uid;			/* client uid */
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
};

struct gss_context_time_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	OM_UINT32	time_rec;		/* actual context validity */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_sign_arg {
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	int		qop_req;		/* quality of protection */
	GSS_BUFFER_T	message_buffer;		/* message to sign */
};

struct gss_sign_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_BUFFER_T	msg_token;		/* msg_token */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_verify_arg {
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	GSS_BUFFER_T	message_buffer;		/* message to verify */
	GSS_BUFFER_T	token_buffer;		/* buffer containg token */
};

struct gss_verify_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	int		qop_state;		/* quality of protection */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_seal_arg {
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	int		conf_req_flag;		/* type of conf requested */
	int		qop_req;		/* quality of prot. requested */
	GSS_BUFFER_T	input_message_buffer;	/* message to protect */
};

struct gss_seal_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	int		conf_state;		/* type of conf. applied */
	GSS_BUFFER_T	output_message_buffer;	/* protected message */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_unseal_arg {
	OM_UINT32	gssd_context_verifier;	/* verifier for context handles */
	GSS_CTX_ID_T	context_handle;		/* handle to existing context */
	GSS_BUFFER_T	input_message_buffer;	/* message to protect */
};

struct gss_unseal_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_BUFFER_T	output_message_buffer;	/* protected message */
	int		conf_state;		/* type of conf. provided */
	int		qop_state;		/* quality of prot. provided */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_display_status_arg {
	uid_t		uid;			/* client uid */
	int		status_value;		/* status to be converted */
	int		status_type;		/* GSS or mech status */
	GSS_OID		mech_type;		/* mechanism */
	OM_UINT32	message_context;	/* recursion flag */
};

struct gss_display_status_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	int		message_context;	/* recursion flag */
	GSS_BUFFER_T	status_string;		/* text equiv of status */
	OM_UINT32	status;			/* status of GSSAPI call */
};

%/* gss_indicate_mechs_arg is void. This appears in the rpc call def */

struct gss_indicate_mechs_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_OID_SET	mech_set;		/* mechanism set supported */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_inquire_cred_arg {
	uid_t		uid;			/* client uid */
	OM_UINT32	gssd_cred_verifier;	/* verifier for cred handle */
	GSS_CRED_ID_T	cred_handle;		/* credential handle */
};

struct gss_inquire_cred_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	GSS_BUFFER_T	name;			/* name associated with cred */
	GSS_OID		name_type;		/* type of name */
	OM_UINT32	lifetime;		/* remaining validiy period */
	int		cred_usage;		/* how creds may be used */
	GSS_OID_SET	mechanisms;		/* mechs associated with cred */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gss_inquire_cred_by_mech_arg {
	uid_t		uid;			/* client uid */
	OM_UINT32	gssd_cred_verifier;	/* verifier for cred handle */
	GSS_CRED_ID_T	cred_handle;		/* credential handle */
	GSS_OID		mech_type;		/* cred mechanism */
};

struct gss_inquire_cred_by_mech_res {
	OM_UINT32	minor_status;		/* status from the mechanism */
	OM_UINT32	status;			/* status of GSSAPI call */
};

struct gsscred_name_to_unix_cred_arg {
	uid_t		uid;			/* client uid */
	GSS_BUFFER_T	pname;			/* principal name */
	GSS_OID		name_type;		/* oid of principal name */
	GSS_OID		mech_type;		/* for which mechanism to use */
};

struct gsscred_name_to_unix_cred_res {
	uid_t		uid;			/* principal's uid */
	gid_t		gid;			/* principal's gid */
	GSSCRED_GIDS	gids;			/* array of principal's gids */
	OM_UINT32	major;			/* status of the GSSAPI call */
};


struct
gsscred_expname_to_unix_cred_arg {
	uid_t		uid;			/* client uid */
	GSS_BUFFER_T	expname;		/* principal in export format */
};

struct
gsscred_expname_to_unix_cred_res {
	uid_t		uid;			/* principal's uid */
	gid_t		gid;			/* principal's gid */
	GSSCRED_GIDS	gids;			/* array of principal's gids */
	OM_UINT32	major;			/* major status code */
};


struct gss_get_group_info_arg {
	uid_t		uid;			/* client uid */
	uid_t		puid;			/* principal's uid */
};

struct gss_get_group_info_res {
	gid_t		gid;			/* principal's gid */
	GSSCRED_GIDS	gids;			/* array of principal's gids */
	OM_UINT32	major;			/* major status code */
};


struct gss_get_kmod_arg	{
	GSS_OID mech_oid;

};

union gss_get_kmod_res switch (bool module_follow) {
	case TRUE:
		string modname<>;
	case FALSE:
		void;
};


/*
 *  The server accepts requests only from the loopback address.
 *  Unix authentication is used, and the port must be in the reserved range.
 */

program GSSPROG {
    version GSSVERS {

	/*
	 *  Called by the client to acquire a credential.
	 */
	gss_acquire_cred_res
		GSS_ACQUIRE_CRED(gss_acquire_cred_arg)			= 1;

	/*
	 *  Called by the client to release a credential.
	 */
	gss_release_cred_res
		GSS_RELEASE_CRED(gss_release_cred_arg)			= 2;

	/*
	 *  Called by the client to initialize a security context.
	 */
	gss_init_sec_context_res
		GSS_INIT_SEC_CONTEXT(gss_init_sec_context_arg)		= 3;

	/*
	 *  Called by the server to initialize a security context.
	 */
	gss_accept_sec_context_res
		GSS_ACCEPT_SEC_CONTEXT(gss_accept_sec_context_arg) 	= 4;

	/*
	 *  Called to pass token to underlying mechanism.
	 */
	gss_process_context_token_res
		GSS_PROCESS_CONTEXT_TOKEN(gss_process_context_token_arg) = 5;

	/*
	 *  Called to delete a security context.
	 */
	gss_delete_sec_context_res
		GSS_DELETE_SEC_CONTEXT(gss_delete_sec_context_arg) 	= 6;

	/*
	 *  Called to get remaining time security context has to live.
	 */
	gss_context_time_res
		GSS_CONTEXT_TIME(gss_context_time_arg) 			= 7;

	/*
	 *  Called to sign a message.
	 */
	gss_sign_res	GSS_SIGN(gss_sign_arg)				= 8;

	/*
	 *  Called to verify a signed message.
	 */
	gss_verify_res	GSS_VERIFY(gss_verify_arg)			= 9;

	/*
	 *  Called to translate minor status into a string.
	 */
	gss_display_status_res
			GSS_DISPLAY_STATUS(gss_display_status_arg)	= 10;

	/*
	 *  Called to indicate which underlying mechanisms are supported
	 */
	gss_indicate_mechs_res
			GSS_INDICATE_MECHS(void)			= 11;

	/*
	 *  Called by the client to inquire about a credential.
	 */
	gss_inquire_cred_res
		GSS_INQUIRE_CRED(gss_inquire_cred_arg)			= 12;


	/*
	 *  Called to seal a message.
	 */
	gss_seal_res	GSS_SEAL(gss_seal_arg)				= 13;

	/*
	 *  Called to unseal a message.
	 */
	gss_unseal_res	GSS_UNSEAL(gss_unseal_arg)			= 14;

	/*
	 * gsscred interface functions to obtain principal uid and gids
	 */
	gsscred_expname_to_unix_cred_res
			GSSCRED_EXPNAME_TO_UNIX_CRED(
				gsscred_expname_to_unix_cred_arg)	= 15;

	gsscred_name_to_unix_cred_res
			GSSCRED_NAME_TO_UNIX_CRED(
				gsscred_name_to_unix_cred_arg)		= 16;

	gss_get_group_info_res
			GSS_GET_GROUP_INFO(gss_get_group_info_arg)	= 17;

	gss_get_kmod_res
			GSS_GET_KMOD(gss_get_kmod_arg)			= 18;

	gss_export_sec_context_res
			GSS_EXPORT_SEC_CONTEXT(gss_export_sec_context_arg) = 19;
	
	gss_import_sec_context_res
			GSS_IMPORT_SEC_CONTEXT(gss_import_sec_context_arg) = 20;
	/*
	 *  Called by the client to add to a credential.
	 */
	gss_add_cred_res
		GSS_ADD_CRED(gss_add_cred_arg)				= 21;
	gss_inquire_cred_by_mech_res
		GSS_INQUIRE_CRED_BY_MECH(gss_inquire_cred_by_mech_arg)
									= 22;

    } = 1;
} = 100234;
