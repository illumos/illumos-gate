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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY = libgss.a
VERS = .1

GSSOBJECTS	= g_acquire_cred.o \
	  g_acquire_cred_with_pw.o \
	  g_store_cred.o \
	  g_rel_cred.o \
	  g_init_sec_context.o \
	  g_accept_sec_context.o \
	  g_process_context.o \
	  g_delete_sec_context.o \
	  g_imp_sec_context.o \
	  g_exp_sec_context.o \
	  g_context_time.o \
	  g_sign.o \
	  g_verify.o \
	  g_seal.o \
	  g_unseal.o \
	  g_dsp_status.o \
	  g_compare_name.o \
	  g_dsp_name.o \
	  g_imp_name.o \
	  g_rel_name.o \
	  g_rel_buffer.o \
	  g_rel_oid_set.o \
	  g_oid_ops.o \
	  g_inquire_cred.o \
	  g_inquire_context.o \
	  g_inquire_names.o \
	  g_initialize.o \
	  g_glue.o \
	  gssd_pname_to_uid.o \
	  oid_ops.o \
	  g_canon_name.o \
	  g_dup_name.o \
	  g_export_name.o \
	  g_utils.o \
	  g_userok.o \
	  g_buffer_set.o \
	  g_inq_context_oid.o \


# defines the duplicate sources we share with gsscred
GSSCRED_DIR =	$(SRC)/cmd/gss/gsscred
GSSCREDOBJ =	gsscred_utils.o gsscred_file.o
# defines the duplicate sources we share with krb5 mech
KRB5DIR= $(SRC)/lib/gss_mechs/mech_krb5/mech
KRB5OBJ= rel_buffer.o util_buffer_set.o
# defines the duplicate sources we share with kernel module
UTSGSSDIR =	$(SRC)/uts/common/gssapi
UTSGSSOBJ =	gen_oids.o

SRCS +=		$(GSSCREDOBJ:%.o=$(GSSCRED_DIR)/%.c) \
		$(KRB5OBJ:%.o=$(KRB5DIR)/%.c) \
		$(UTSGSSOBJ:%.o=$(UTSGSSDIR)/%.c)
GSSLINTSRC =	$(GSSOBJECTS:%.o=$(SRCDIR)/%.c) \
		$(GSSCREDOBJ:%.o=$(GSSCRED_DIR)/%.c) \
	        $(KRB5OBJ:%.o=$(KRB5DIR)/%.c) \
		$(UTSGSSOBJ:%.o=$(UTSGSSDIR)/%.c)
OBJECTS =	$(GSSOBJECTS) $(GSSCREDOBJ) $(KRB5OBJ) $(UTSGSSOBJ)

# include library definitions
include ../../Makefile.lib

LIBS =	$(DYNLIB) $(LINTLIB)

$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS += 	-lc

CPPFLAGS += 	-I$(GSSCRED_DIR) -I$(SRC)/uts/common/gssapi/include \
		 -I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		 -I$(SRC)/uts/common/gssapi/ \
		 -I$(SRC)/lib/gss_mechs/mech_krb5/include/ \
		-DHAVE_STDLIB_H

$(EXPORT_RELEASE_BUILD)include $(CLOSED)/lib/libgss/Makefile.export

.KEEP_STATE:

all: $(LIBS)

lintcheck:=	SRCS= $(GSSLINTSRC)

lint:  lintcheck

$(GSSCREDOBJ:%.o=pics/%.o):
	$(COMPILE.c) -o $@ $(@:pics/%.o=$(GSSCRED_DIR)/%.c)
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/rel_buffer.o: $(SRC)/lib/gss_mechs/mech_krb5/mech/rel_buffer.c
	$(COMPILE.c) -o $@ $(SRC)/lib/gss_mechs/mech_krb5/mech/rel_buffer.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/util_buffer_set.o: $(SRC)/lib/gss_mechs/mech_krb5/mech/util_buffer_set.c
	$(COMPILE.c) -o $@ $(SRC)/lib/gss_mechs/mech_krb5/mech/util_buffer_set.c
	$(POST_PROCESS_O)

# gen_oids.c is kept in the kernel since the OIDs declared in them are
# used by rpcsec module
pics/gen_oids.o: $(SRC)/uts/common/gssapi/gen_oids.c
	$(COMPILE.c) -o $@ $(SRC)/uts/common/gssapi/gen_oids.c
	$(POST_PROCESS_O)	

# include library targets
include ../../Makefile.targ
