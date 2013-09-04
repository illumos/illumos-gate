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

MANSECT= 	3rsm

MANFILES= 	rsm_create_localmemory_handle.3rsm	\
	 	rsm_get_controller.3rsm			\
	 	rsm_get_interconnect_topology.3rsm	\
	 	rsm_get_segmentid_range.3rsm		\
	 	rsm_intr_signal_post.3rsm		\
	 	rsm_intr_signal_wait_pollfd.3rsm	\
	 	rsm_memseg_export_create.3rsm		\
	 	rsm_memseg_export_publish.3rsm		\
	 	rsm_memseg_get_pollfd.3rsm		\
	 	rsm_memseg_import_connect.3rsm		\
	 	rsm_memseg_import_get.3rsm		\
	 	rsm_memseg_import_init_barrier.3rsm	\
	 	rsm_memseg_import_map.3rsm		\
	 	rsm_memseg_import_open_barrier.3rsm	\
	 	rsm_memseg_import_put.3rsm		\
	 	rsm_memseg_import_putv.3rsm		\
	 	rsm_memseg_import_set_mode.3rsm

MANLINKS=	rsm_free_interconnect_topology.3rsm	\
		rsm_free_localmemory_handle.3rsm	\
		rsm_get_controller_attr.3rsm		\
		rsm_intr_signal_wait.3rsm		\
		rsm_memseg_export_destroy.3rsm		\
		rsm_memseg_export_rebind.3rsm		\
		rsm_memseg_export_republish.3rsm	\
		rsm_memseg_export_unpublish.3rsm	\
		rsm_memseg_import_close_barrier.3rsm	\
		rsm_memseg_import_destroy_barrier.3rsm	\
		rsm_memseg_import_disconnect.3rsm	\
		rsm_memseg_import_get16.3rsm		\
		rsm_memseg_import_get32.3rsm		\
		rsm_memseg_import_get64.3rsm		\
		rsm_memseg_import_get8.3rsm		\
		rsm_memseg_import_get_mode.3rsm		\
		rsm_memseg_import_getv.3rsm		\
		rsm_memseg_import_order_barrier.3rsm	\
		rsm_memseg_import_put16.3rsm		\
		rsm_memseg_import_put32.3rsm		\
		rsm_memseg_import_put64.3rsm		\
		rsm_memseg_import_put8.3rsm		\
		rsm_memseg_import_unmap.3rsm		\
		rsm_memseg_release_pollfd.3rsm		\
		rsm_release_controller.3rsm

rsm_free_localmemory_handle.3rsm	:= LINKSRC = rsm_create_localmemory_handle.3rsm

rsm_get_controller_attr.3rsm		:= LINKSRC = rsm_get_controller.3rsm
rsm_release_controller.3rsm		:= LINKSRC = rsm_get_controller.3rsm

rsm_free_interconnect_topology.3rsm	:= LINKSRC = rsm_get_interconnect_topology.3rsm

rsm_intr_signal_wait.3rsm		:= LINKSRC = rsm_intr_signal_post.3rsm

rsm_memseg_export_destroy.3rsm		:= LINKSRC = rsm_memseg_export_create.3rsm
rsm_memseg_export_rebind.3rsm		:= LINKSRC = rsm_memseg_export_create.3rsm

rsm_memseg_export_republish.3rsm	:= LINKSRC = rsm_memseg_export_publish.3rsm
rsm_memseg_export_unpublish.3rsm	:= LINKSRC = rsm_memseg_export_publish.3rsm

rsm_memseg_release_pollfd.3rsm		:= LINKSRC = rsm_memseg_get_pollfd.3rsm

rsm_memseg_import_disconnect.3rsm	:= LINKSRC = rsm_memseg_import_connect.3rsm

rsm_memseg_import_get16.3rsm		:= LINKSRC = rsm_memseg_import_get.3rsm
rsm_memseg_import_get32.3rsm		:= LINKSRC = rsm_memseg_import_get.3rsm
rsm_memseg_import_get64.3rsm		:= LINKSRC = rsm_memseg_import_get.3rsm
rsm_memseg_import_get8.3rsm		:= LINKSRC = rsm_memseg_import_get.3rsm

rsm_memseg_import_destroy_barrier.3rsm	:= LINKSRC = rsm_memseg_import_init_barrier.3rsm

rsm_memseg_import_unmap.3rsm		:= LINKSRC = rsm_memseg_import_map.3rsm

rsm_memseg_import_close_barrier.3rsm	:= LINKSRC = rsm_memseg_import_open_barrier.3rsm
rsm_memseg_import_order_barrier.3rsm	:= LINKSRC = rsm_memseg_import_open_barrier.3rsm

rsm_memseg_import_put16.3rsm		:= LINKSRC = rsm_memseg_import_put.3rsm
rsm_memseg_import_put32.3rsm		:= LINKSRC = rsm_memseg_import_put.3rsm
rsm_memseg_import_put64.3rsm		:= LINKSRC = rsm_memseg_import_put.3rsm
rsm_memseg_import_put8.3rsm		:= LINKSRC = rsm_memseg_import_put.3rsm

rsm_memseg_import_getv.3rsm		:= LINKSRC = rsm_memseg_import_putv.3rsm

rsm_memseg_import_get_mode.3rsm		:= LINKSRC = rsm_memseg_import_set_mode.3rsm

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
