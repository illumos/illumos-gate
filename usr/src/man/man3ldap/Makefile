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

MANSECT=	3ldap

MANFILES=	ber_decode.3ldap		\
		ber_encode.3ldap		\
		cldap_close.3ldap		\
		cldap_open.3ldap		\
		cldap_search_s.3ldap		\
		cldap_setretryinfo.3ldap	\
		ldap.3ldap			\
		ldap_abandon.3ldap		\
		ldap_add.3ldap			\
		ldap_ber_free.3ldap		\
		ldap_bind.3ldap			\
		ldap_charset.3ldap		\
		ldap_compare.3ldap		\
		ldap_control_free.3ldap		\
		ldap_delete.3ldap		\
		ldap_disptmpl.3ldap		\
		ldap_entry2text.3ldap		\
		ldap_error.3ldap		\
		ldap_first_attribute.3ldap	\
		ldap_first_entry.3ldap		\
		ldap_first_message.3ldap	\
		ldap_friendly.3ldap		\
		ldap_get_dn.3ldap		\
		ldap_get_entry_controls.3ldap	\
		ldap_get_lang_values.3ldap	\
		ldap_get_option.3ldap		\
		ldap_get_values.3ldap		\
		ldap_getfilter.3ldap		\
		ldap_memcache.3ldap		\
		ldap_memfree.3ldap		\
		ldap_modify.3ldap		\
		ldap_modrdn.3ldap		\
		ldap_open.3ldap			\
		ldap_parse_result.3ldap		\
		ldap_result.3ldap		\
		ldap_search.3ldap		\
		ldap_searchprefs.3ldap		\
		ldap_sort.3ldap			\
		ldap_ufn.3ldap			\
		ldap_url.3ldap			\
		ldap_version.3ldap

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
