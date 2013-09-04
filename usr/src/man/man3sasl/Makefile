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

MANSECT= 	3sasl

MANFILES=	sasl_authorize_t.3sasl			\
	 	sasl_auxprop.3sasl			\
	 	sasl_auxprop_add_plugin.3sasl		\
	 	sasl_auxprop_getctx.3sasl		\
	 	sasl_auxprop_request.3sasl		\
	 	sasl_canon_user_t.3sasl			\
	 	sasl_canonuser_add_plugin.3sasl		\
	 	sasl_chalprompt_t.3sasl			\
	 	sasl_checkapop.3sasl			\
	 	sasl_checkpass.3sasl			\
	 	sasl_client_add_plugin.3sasl		\
	 	sasl_client_init.3sasl			\
	 	sasl_client_new.3sasl			\
	 	sasl_client_plug_init_t.3sasl		\
	 	sasl_client_start.3sasl			\
	 	sasl_client_step.3sasl			\
	 	sasl_decode.3sasl			\
	 	sasl_decode64.3sasl			\
	 	sasl_dispose.3sasl			\
	 	sasl_done.3sasl				\
	 	sasl_encode.3sasl			\
	 	sasl_encode64.3sasl			\
	 	sasl_erasebuffer.3sasl			\
	 	sasl_errdetail.3sasl			\
	 	sasl_errors.3sasl			\
	 	sasl_errstring.3sasl			\
	 	sasl_getcallback_t.3sasl		\
	 	sasl_getopt_t.3sasl			\
	 	sasl_getpath_t.3sasl			\
	 	sasl_getprop.3sasl			\
	 	sasl_getrealm_t.3sasl			\
	 	sasl_getsecret_t.3sasl			\
	 	sasl_getsimple_t.3sasl			\
	 	sasl_global_listmech.3sasl		\
	 	sasl_idle.3sasl				\
	 	sasl_listmech.3sasl			\
	 	sasl_log_t.3sasl			\
	 	sasl_server_add_plugin.3sasl		\
	 	sasl_server_init.3sasl			\
	 	sasl_server_new.3sasl			\
	 	sasl_server_plug_init_t.3sasl		\
	 	sasl_server_start.3sasl			\
	 	sasl_server_step.3sasl			\
	 	sasl_server_userdb_checkpass_t.3sasl	\
	 	sasl_server_userdb_setpass_t.3sasl	\
	 	sasl_set_alloc.3sasl			\
	 	sasl_set_mutex.3sasl			\
	 	sasl_seterror.3sasl			\
	 	sasl_setpass.3sasl			\
	 	sasl_setprop.3sasl			\
	 	sasl_utf8verify.3sasl			\
	 	sasl_verifyfile_t.3sasl			\
	 	sasl_version.3sasl

MANLINKS=	prop_clear.3sasl	\
		prop_dispose.3sasl	\
		prop_dup.3sasl		\
		prop_erase.3sasl	\
		prop_format.3sasl	\
		prop_get.3sasl		\
		prop_getnames.3sasl	\
		prop_new.3sasl		\
		prop_request.3sasl	\
		prop_set.3sasl		\
		prop_setvals.3sasl	\
		sasl_encodev.3sasl

prop_clear.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_dispose.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_dup.3sasl		:= LINKSRC = sasl_auxprop.3sasl
prop_erase.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_format.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_get.3sasl		:= LINKSRC = sasl_auxprop.3sasl
prop_getnames.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_new.3sasl		:= LINKSRC = sasl_auxprop.3sasl
prop_request.3sasl	:= LINKSRC = sasl_auxprop.3sasl
prop_set.3sasl		:= LINKSRC = sasl_auxprop.3sasl
prop_setvals.3sasl	:= LINKSRC = sasl_auxprop.3sasl

sasl_encodev.3sasl	:= LINKSRC = sasl_encode.3sasl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
