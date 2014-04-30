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
# Copyright 2014 Andrew Stormont.
#

include		$(SRC)/Makefile.master

MANSECT= 	3uuid

MANFILES=	uuid_clear.3uuid

MANLINKS=	uuid_compare.3uuid		\
		uuid_copy.3uuid			\
		uuid_generate.3uuid		\
		uuid_generate_random.3uuid	\
		uuid_generate_time.3uuid	\
		uuid_is_null.3uuid		\
		uuid_parse.3uuid		\
		uuid_time.3uuid			\
		uuid_unparse.3uuid		\
		uuid_unparse_lower.3uuid	\
		uuid_unparse_upper.3uuid

uuid_compare.3uuid		:= LINKSRC = uuid_clear.3uuid
uuid_copy.3uuid			:= LINKSRC = uuid_clear.3uuid
uuid_generate.3uuid		:= LINKSRC = uuid_clear.3uuid
uuid_generate_random.3uuid	:= LINKSRC = uuid_clear.3uuid
uuid_generate_time.3uuid	:= LINKSRC = uuid_clear.3uuid
uuid_is_null.3uuid		:= LINKSRC = uuid_clear.3uuid
uuid_parse.3uuid		:= LINKSRC = uuid_clear.3uuid
uuid_time.3uuid			:= LINKSRC = uuid_clear.3uuid
uuid_unparse.3uuid		:= LINKSRC = uuid_clear.3uuid
uuid_unparse_lower.3uuid	:= LINKSRC = uuid_clear.3uuid
uuid_unparse_upper.3uuid	:= LINKSRC = uuid_clear.3uuid

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
