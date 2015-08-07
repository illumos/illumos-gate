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
# Copyright 2015 Gary Mills
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARY= libnisdb.a
VERS=	.2
PROTOCOL_DIR= $(ROOT)/include/rpcsvc
YPTOL_DIR= ./yptol

SED=	sed

OBJECTS = \
	db_entry.o db_entry_c_xdr.o \
	db_item.o db_item_c_xdr.o \
	db_vers.o db_vers_c_xdr.o \
	db_pickle.o \
	db_table.o db_table_c_xdr.o \
	db_index_entry.o db_index_entry_c.o \
	db_index.o db_index_c_xdr.o \
	db_scheme.o db_scheme_c_xdr.o \
	db_query.o db_query_c_xdr.o \
	db_mindex.o db_mindex2.o db_mindex3.o db_mindex_c_xdr.o \
	db_log_entry.o db_log_entry_c_xdr.o \
	db_log.o \
	db.o \
	xdr_nullptr.o \
	db_dictionary.o db_dictionary_c_xdr.o \
	db_dictxdr.o db_dictlog.o db_dictlog_c_xdr.o \
	nis_db.o \
	nisdb_mt.o nisdb_rw.o \
	nis_hashitem.o \
	ldap_attr.o ldap_cto.o ldap_glob.o ldap_ldap.o \
	ldap_map.o ldap_nisdbquery.o \
	ldap_op.o ldap_parse.o ldap_print.o ldap_ruleval.o \
	ldap_util.o ldap_val.o ldap_xdr.o ldap_scheme.o \
	nis_ldap.o \
	nis_parse_ldap_attr.o nis_parse_ldap_conf.o \
	nis_parse_ldap_map.o nis_parse_ldap_util.o \
	nis_parse_ldap_yp_util.o	\
	dit_access.o \
	dit_access_utils.o \
	lock_update.o \
	map_conv.o \
	map_ctrl.o \
	yptol_utils.o \
	shim.o \
	shim_ancil.o \
	shim_lockmap.o \
	ttl_utils.o \
	update.o \
	shim_changepasswd.o \
	stubs.o

X_FILES= \
    db_c.x             db_dictionary_c.x db_entry_c.x  db_index_c.x     \
    db_index_entry_c.x db_item_c.x       db_log_c.x    db_log_entry_c.x \
    db_mindex_c.x      db_query_c.x      db_scheme_c.x db_table_c.x     \
    db_vers_c.x	       db_dictlog_c.x

DERIVED_HEADERS= $(X_FILES:%_c.x=%_c.h) $(X_FILES:%_c.x=%.h)
DERIVED_SOURCES= $(X_FILES:%_c.x=%_c_xdr.c)
DERIVED_FILES= $(DERIVED_HEADERS) $(DERIVED_SOURCES)

# delete the derived files when cleaning up
CLEANFILES += $(DERIVED_FILES)

# include library definitions
include ../Makefile.lib

MAPFILES =	mapfile-vers

SRCS= db_dictionary_c_xdr.c db_dictlog_c_xdr.c db_dictxdr.c \
db_entry_c_xdr.c db_index_c_xdr.c db_index_entry_c_xdr.c db_item_c_xdr.c \
db_log_c_xdr.c db_log_entry_c_xdr.c db_mindex_c_xdr.c db_query_c_xdr.c \
db_scheme_c_xdr.c db_table_c_xdr.c db_vers_c_xdr.c \
$(YPTOL_DIR)/dit_access.c \
$(YPTOL_DIR)/dit_access_utils.c \
$(YPTOL_DIR)/lock_update.c \
$(YPTOL_DIR)/map_conv.c \
$(YPTOL_DIR)/map_ctrl.c \
$(YPTOL_DIR)/yptol_utils.c \
$(YPTOL_DIR)/shim.c \
$(YPTOL_DIR)/shim_ancil.c \
$(YPTOL_DIR)/shim_lockmap.c \
$(YPTOL_DIR)/ttl_utils.c \
$(YPTOL_DIR)/update.c \
$(YPTOL_DIR)/shim_changepasswd.c \
$(YPTOL_DIR)/stubs.c \
#db_c_xdr.c xdr_nullptr.c

# Libnisdb has grown large enough that there may be too many symbols
# wanting `small' PIC references. Hence, compile some files with
# `large' PIC references; the parser files are good candidates, since
# they're only used at startup, and performance isn't too important.
LARGESYMS=	nis_parse_ldap_conf.o \
		nis_parse_ldap_attr.o \
		nis_parse_ldap_yp_util.o \
		nis_parse_ldap_map.o \
		ldap_parse.o \
		dit_access.o \
		dit_access_utilis.o \
		map_conv.o \
		map_ctrl.o \
		shim.o \
		shim_ancil.o \
		shim_changepasswd.o \
		update.o \
		stubs.o \
		yptol_utils.o \
		nis_parse_ldap_util.o
LARGEPICS=	$(LARGESYMS:%=pics/%)
$(LARGEPICS) :=	sparc_C_PICFLAGS = $(C_BIGPICFLAGS)
$(LARGEPICS) :=	i386_C_PICFLAGS = $(C_BIGPICFLAGS)

# More and stricter semantic checks and lint-like checks
CFLAGS	+=	$(CCVERBOSE)

CPPFLAGS +=	-D_REENTRANT

# Have an unused variable that can't be removed
UVAR_PICS = \
pics/db_dictionary_c_xdr.o \
pics/db_dictlog_c_xdr.o \
pics/db_entry_c_xdr.o \
pics/db_index_c_xdr.o \
pics/db_item_c_xdr.o \
pics/db_log_entry_c_xdr.o \
pics/db_mindex_c_xdr.o \
pics/db_query_c_xdr.o \
pics/db_scheme_c_xdr.o \
pics/db_table_c_xdr.o \
pics/db_vers_c_xdr.o \
pics/ldap_xdr.o \
pics/dit_access.o \
pics/update.o \
pics/yptol_utils.o \
pics/map_ctrl.o

$(UVAR_PICS) := CERRWARN += -_gcc=-Wno-unused-variable

# Correcting these might alter logic
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-switch

# Extra includes, from yp, for yptol files.
CPPFLAGS += -I$(SRC)/cmd/ypcmd

# Need the path to nis_clnt.h
CLNT_PICS = pics/db_entry_c_xdr.o pics/ldap_xdr.o pics/db_mindex_c_xdr.o

$(CLNT_PICS) := CPPFLAGS += -I../libnsl/nis/gen

LIBS = $(DYNLIB)
ZDEFS=
LDLIBS += -lnsl -lldap -lc

# A number of interfaces are interposed by numerous applications, therefore
# prevent direct binding to anything in libnisdb.  Disable libnisdb from
# directly binding to itself, but allow libnisdb to directly bind to its
# dependencies (ie. map -Bdirect -> -zdirect).  Ensure lazy loading is
# established (which is enabled automatically with -Bdirect).  In addition,
# libnisdb interposes on socket(), so tag this library as an interposer.
# dependencies (lazyload).
BDIRECT =
DYNFLAGS +=	$(BNODIRECT) $(ZINTERPOSE) $(ZDIRECT) $(ZLAZYLOAD)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all:	$(DERIVED_FILES) $(LIBS)

install: all $(ROOTLIBS) $(ROOTLINKS)

lint: $(DERIVED_FILES) .WAIT lintcheck

pics/%.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: %.cc
	$(COMPILE.cc) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o profs/%.o: $(YPTOL_DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

#
# Pattern matching rules that define how to build the derived files.
#
%_c.h: %_c.x
	$(RM) $@
	$(RPCGEN) -DUSINGC -h -o $@ $<

%.h: %_c.x
	$(RM) $@
	$(RPCGEN) -h -o $@ $<

%_c_xdr.c: %_c.x
	$(RM) $@
	$(RPCGEN) -DUSINGC -c -o $@ $<

# rename the xdr_db_free_entry() in the db_table_c_xdr.c.  So the one
# in db_index_entry_c is used instead.
DB_TABLE=db_table_c

$(DB_TABLE)_xdr.c:	$(DB_TABLE).x
	$(RM) $@
	$(RPCGEN) -DUSINGC -c $(DB_TABLE).x |\
	$(SED) -e 's/^xdr_db_free_entry(/__OBSOLETED_xdr_db_free_entry(/' > $@

# include library targets
include ../Makefile.targ
