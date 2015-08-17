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
# Copyright (c) 2015, Joyent, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT =	3avl

MANFILES =					\
		avl_add.3avl			\
		avl_create.3avl			\
		avl_destroy.3avl		\
		avl_destroy_nodes.3avl		\
		avl_find.3avl			\
		avl_first.3avl			\
		avl_insert.3avl			\
		avl_is_empty.3avl		\
		avl_nearest.3avl		\
		avl_numnodes.3avl		\
		avl_swap.3avl

MANLINKS =				\
		AVL_NEXT.3avl		\
		AVL_PREV.3avl		\
		avl_insert_here.3avl	\
		avl_last.3avl		\
		avl_remove.3avl	

# avl_add.3avl
avl_remove.3avl		:= LINKSRC = avl_add.3avl

# avl_first.3avl
AVL_NEXT.3avl		:= LINKSRC = avl_first.3avl
AVL_PREV.3avl		:= LINKSRC = avl_first.3avl
avl_last.3avl		:= LINKSRC = avl_first.3avl

# avl_insert.3avl
avl_insert_here.3avl	:= LINKSRC = avl_insert.3avl

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
