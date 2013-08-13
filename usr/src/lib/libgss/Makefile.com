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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
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
KRB5OBJ= rel_buffer.o util_buffer_set.o disp_com_err_status.o \
	      util_buffer.o  util_errmap.o
# defines the duplicate sources we share with krb5 mech error table
KRB5ETDIR= $(SRC)/lib/gss_mechs/mech_krb5/et
KRB5ETOBJ= error_message.o adb_err.o adm_err.o asn1_err.o \
	      chpass_util_strings.o \
	      gssapi_err_krb5.o gssapi_err_generic.o \
	      import_err.o \
	      kadm_err.o kdb5_err.o kdc5_err.o kpasswd_strings.o krb5_err.o \
	      kv5m_err.o prof_err.o pty_err.o ss_err.o
# defines the duplicate sources we share with kernel module
UTSGSSDIR =	$(SRC)/uts/common/gssapi
UTSGSSOBJ =	gen_oids.o

SRCS +=		$(GSSCREDOBJ:%.o=$(GSSCRED_DIR)/%.c) \
		$(KRB5OBJ:%.o=$(KRB5DIR)/%.c) \
		$(KRB5ETOBJ:%.o=$(KRB5ETDIR)/%.c) \
		$(UTSGSSOBJ:%.o=$(UTSGSSDIR)/%.c)
GSSLINTSRC =	$(GSSOBJECTS:%.o=$(SRCDIR)/%.c) \
		$(GSSCREDOBJ:%.o=$(GSSCRED_DIR)/%.c) \
		$(UTSGSSOBJ:%.o=$(UTSGSSDIR)/%.c)
OBJECTS =	$(GSSOBJECTS) $(GSSCREDOBJ) $(KRB5OBJ) $(UTSGSSOBJ) $(KRB5ETOBJ)

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

CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-empty-body

.KEEP_STATE:

all: $(LIBS)

lintcheck:=	SRCS= $(GSSLINTSRC)

lint:  lintcheck

$(GSSCREDOBJ:%.o=pics/%.o):
	$(COMPILE.c) -o $@ $(@:pics/%.o=$(GSSCRED_DIR)/%.c)
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/rel_buffer.o: $(KRB5DIR)/rel_buffer.c
	$(COMPILE.c) -o $@ $(KRB5DIR)/rel_buffer.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/util_buffer_set.o: $(KRB5DIR)/util_buffer_set.c
	$(COMPILE.c) -o $@ $(KRB5DIR)/util_buffer_set.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/disp_com_err_status.o: $(KRB5DIR)/disp_com_err_status.c
	$(COMPILE.c) -o $@ $(KRB5DIR)/disp_com_err_status.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/util_buffer.o: $(KRB5DIR)/util_buffer.c
	$(COMPILE.c) -o $@ $(KRB5DIR)/util_buffer.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/util_errmap.o: $(KRB5DIR)/util_errmap.c
	$(COMPILE.c) -o $@ $(KRB5DIR)/util_errmap.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/error_message.o: $(KRB5ETDIR)/error_message.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/error_message.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/adb_err.o: $(KRB5ETDIR)/adb_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/adb_err.c
	$(POST_PROCESS_O)

pics/adm_err.o: $(KRB5ETDIR)/adm_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/adm_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/asn1_err.o: $(KRB5ETDIR)/asn1_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/asn1_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/chpass_util_strings.o: $(KRB5ETDIR)/chpass_util_strings.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/chpass_util_strings.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/gssapi_err_generic.o: $(KRB5ETDIR)/gssapi_err_generic.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/gssapi_err_generic.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/gssapi_err_krb5.o: $(KRB5ETDIR)/gssapi_err_krb5.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/gssapi_err_krb5.c
	$(POST_PROCESS_O)


# we need this in libgss so we don't have to link against mech_krb5
pics/import_err.o: $(KRB5ETDIR)/import_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/import_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/kadm_err.o: $(KRB5ETDIR)/kadm_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/kadm_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/kdb5_err.o: $(KRB5ETDIR)/kdb5_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/kdb5_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/kdc5_err.o: $(KRB5ETDIR)/kdc5_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/kdc5_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/kpasswd_strings.o: $(KRB5ETDIR)/kpasswd_strings.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/kpasswd_strings.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/krb5_err.o: $(KRB5ETDIR)/krb5_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/krb5_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/kv5m_err.o: $(KRB5ETDIR)/kv5m_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/kv5m_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/prof_err.o: $(KRB5ETDIR)/prof_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/prof_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/pty_err.o: $(KRB5ETDIR)/pty_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/pty_err.c
	$(POST_PROCESS_O)

# we need this in libgss so we don't have to link against mech_krb5
pics/ss_err.o: $(KRB5ETDIR)/ss_err.c
	$(COMPILE.c) -o $@ $(KRB5ETDIR)/ss_err.c
	$(POST_PROCESS_O)

# gen_oids.c is kept in the kernel since the OIDs declared in them are
# used by rpcsec module
pics/gen_oids.o: $(SRC)/uts/common/gssapi/gen_oids.c
	$(COMPILE.c) -o $@ $(SRC)/uts/common/gssapi/gen_oids.c
	$(POST_PROCESS_O)	

# include library targets
include ../../Makefile.targ
