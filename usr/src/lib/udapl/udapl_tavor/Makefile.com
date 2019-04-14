#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright 2019, Joyent, Inc.

LIBRARY=	udapl_tavor.a
VERS=		.1

LOCOBJS =	\
	dapl_cno_create.o \
	dapl_cno_free.o \
	dapl_cno_modify_agent.o \
	dapl_cno_query.o \
	dapl_cno_util.o \
	dapl_cno_wait.o \
	dapl_cookie.o \
	dapl_cr_accept.o \
	dapl_cr_callback.o \
	dapl_cr_handoff.o \
	dapl_cr_query.o \
	dapl_cr_reject.o \
	dapl_cr_util.o \
	dapl_debug.o \
	dapl_ep_connect.o \
	dapl_ep_create.o \
	dapl_ep_create_with_srq.o \
	dapl_ep_disconnect.o \
	dapl_ep_dup_connect.o \
	dapl_ep_free.o \
	dapl_ep_get_status.o \
	dapl_ep_modify.o \
	dapl_ep_post_rdma_read.o \
	dapl_ep_post_rdma_write.o \
	dapl_ep_post_recv.o \
	dapl_ep_post_send.o \
	dapl_ep_query.o \
	dapl_ep_reset.o \
	dapl_ep_util.o \
	dapl_evd_clear_unwaitable.o \
	dapl_evd_connection_callb.o \
	dapl_evd_cq_async_error_callb.o \
	dapl_evd_create.o \
	dapl_evd_dequeue.o \
	dapl_evd_disable.o \
	dapl_evd_dto_callb.o \
	dapl_evd_enable.o \
	dapl_evd_free.o \
	dapl_evd_modify_cno.o \
	dapl_evd_post_se.o \
	dapl_evd_qp_async_error_callb.o \
	dapl_evd_query.o \
	dapl_evd_resize.o \
	dapl_evd_set_unwaitable.o \
	dapl_evd_un_async_error_callb.o \
	dapl_evd_util.o \
	dapl_evd_wait.o \
	dapl_get_consumer_context.o \
	dapl_get_handle_type.o \
	dapl_hash.o \
	dapl_hca_util.o \
	dapl_ia_close.o \
	dapl_ia_open.o \
	dapl_ia_query.o \
	dapl_ia_util.o \
	dapl_init.o \
	dapl_llist.o \
	dapl_lmr_create.o \
	dapl_lmr_free.o \
	dapl_lmr_query.o \
	dapl_lmr_sync_rdma.o \
	dapl_lmr_util.o \
	dapl_mr_util.o \
	dapl_name_service.o \
	dapl_osd.o \
	dapl_provider.o \
	dapl_psp_create.o \
	dapl_psp_create_any.o \
	dapl_psp_free.o \
	dapl_psp_query.o \
	dapl_pz_create.o \
	dapl_pz_free.o \
	dapl_pz_query.o \
	dapl_pz_util.o \
	dapl_ring_buffer_util.o \
	dapl_rmr_bind.o \
	dapl_rmr_create.o \
	dapl_rmr_free.o \
	dapl_rmr_query.o \
	dapl_rmr_util.o \
	dapl_rsp_create.o \
	dapl_rsp_free.o \
	dapl_rsp_query.o \
	dapl_set_consumer_context.o \
	dapl_sp_util.o \
	dapl_srq.o \
	dapl_srq_util.o

TAVOROBJS = \
	dapl_tavor_hca.o \
	dapl_tavor_hw.o \
	dapl_arbel_hw.o \
	dapl_hermon_hw.o \
	dapl_tavor_ibtf_cm.o \
	dapl_tavor_ibtf_dto.o \
	dapl_tavor_ibtf_mrsync.o \
	dapl_tavor_ibtf_qp.o \
	dapl_tavor_ibtf_util.o \
	dapl_tavor_wr.o

OBJECTS = $(LOCOBJS) $(TAVOROBJS)

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB)
LDLIBS +=	-ldevinfo -lsocket -lnsl -ldat -lc -ldladm

SRCDIR =	../common
TAVORSRCDIR =	../tavor

SRCS = $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(TAVOROBJS:%.o=$(TAVORSRCDIR)/%.c)

CPPFLAGS +=	-I$(SRC)/lib/udapl/udapl_tavor/include
CPPFLAGS +=	-I$(SRC)/lib/udapl/udapl_tavor/tavor
CPPFLAGS +=	-I$(SRC)/uts/common/sys/ib/clients/daplt
CPPFLAGS +=	-I$(SRC)/uts/common
CPPFLAGS +=	-I$(SRC)/uts/common/sys/ib/clients
CFLAGS +=	$(CCVERBOSE)
LINTFLAGS +=	-DDAPL_DBG
LINTFLAGS64 +=	-DDAPL_DBG

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-switch

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDAPL_DBG
$(RELEASE_BUILD)CERRWARN += -_gcc=-Wno-unused

# not linted
SMATCH=off

.KEEP_STATE:

all: $(LIBS)

debug: all

lint: lintcheck

pics/%.o: $(TAVORSRCDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
