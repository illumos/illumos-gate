#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3sip

MANFILES=	sip_add_branchid_to_via.3sip		\
		sip_add_from.3sip			\
		sip_add_header.3sip			\
		sip_add_param.3sip			\
		sip_add_request_line.3sip		\
		sip_branchid.3sip			\
		sip_clone_msg.3sip			\
		sip_copy_start_line.3sip		\
		sip_create_OKack.3sip			\
		sip_create_dialog_req.3sip		\
		sip_create_response.3sip		\
		sip_delete_dialog.3sip			\
		sip_delete_start_line.3sip		\
		sip_enable_counters.3sip		\
		sip_enable_trans_logging.3sip		\
		sip_get_contact_display_name.3sip	\
		sip_get_cseq.3sip			\
		sip_get_dialog_state.3sip		\
		sip_get_header.3sip			\
		sip_get_header_value.3sip		\
		sip_get_msg_len.3sip			\
		sip_get_num_via.3sip			\
		sip_get_param_value.3sip		\
		sip_get_request_method.3sip		\
		sip_get_request_uri_str.3sip		\
		sip_get_resp_desc.3sip			\
		sip_get_trans.3sip			\
		sip_get_trans_method.3sip		\
		sip_get_uri_parsed.3sip			\
		sip_guid.3sip				\
		sip_hold_dialog.3sip			\
		sip_hold_msg.3sip			\
		sip_hold_trans.3sip			\
		sip_init_conn_object.3sip		\
		sip_is_sip_uri.3sip			\
		sip_msg_is_request.3sip			\
		sip_msg_to_str.3sip			\
		sip_new_msg.3sip			\
		sip_parse_uri.3sip			\
		sip_process_new_packet.3sip		\
		sip_register_sent_by.3sip		\
		sip_sendmsg.3sip			\
		sip_stack_init.3sip

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
