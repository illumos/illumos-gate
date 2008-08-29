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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:
.SUFFIXES:

PROG = mmsmm

SRCS = mm.c mm_cfg.c mm_sql.c mm_mmp_sql.c mm_dmp_sql.c mm_lmp_sql.c \
	mm_util.c mm_notify.c mm_db.c mm_task.c mm_path.c mm_types.c \
	mm_msg.c mm_mmp_mount.c mm_mmp_cp.c
OBJS = $(SRCS:%.c=%.o)
lint_SRCS = $(SRCS:%.c=%.ln)

include ../../../Makefile.cmd

ROOTCMDDIR=	$(ROOT)/lib/svc/method

CPPFLAGS += -DMMS_OPENSSL
CPPFLAGS += -I. -I../common -I$(SRC)/common/mms/mms
CPPFLAGS += -I$(SRC)/lib/mms/mms/common -I$(SRC)/lib/mms/mms/common
CPPFLAGS += -I/usr/include/libxml2 -I/usr/include/pgsql

CFLAGS +=  $(CTF_FLAGS) $(CC_VERBOSE)
LDLIBS += -lc -lsocket -lnsl -luuid $(ZIGNORE) -lpq
LDLIBS += -lxml2 -lscf
LDLIBS += -L$(SRC)/lib/mms/mms/$(MACH) -lmms -R/usr/lib

LDFLAGS += $(ZIGNORE)
DYNFLAGS += $(ZIGNORE)

C99MODE=	$(C99_ENABLE)

# The mm database schema with database versions
DBMODS = ../common/mms_db

# Generated mm database version header file
DBVER = ../common/mm_db_version.h

# Print last database version found in mms_db
DBMODS_VER = nawk '{ line[NR] = $$0 } END { \
	i = 1; \
	last = 0; \
	while (i <= NR) { \
		if (line[i] ~ /^[^\#]/) { \
			rec = rec line[i] " " \
		} \
		if ((i+1 == NR || line[i+1] ~ /^[0-9]/) && length(rec)) { \
			n = index(rec, " "); \
			if (n == 0) { \
				n = index(rec, "\t"); \
			} \
			n = n - 1; \
			if (n < 2) { \
				exit 1 \
			} \
			rev = substr(rec, 0, n); \
			ver = substr(rev, 0, n - 1) + 0; \
			mod = substr(rev, n, n); \
			cmd = substr(rec, n + 1, length(rec)); \
			if (mod ~ /u/) { \
				last = ver; \
			} \
			rec = "" \
		} \
		i = i + 1 \
	} \
	if (last == 0) { \
		exit 1 \
	} \
	print last \
	}'

# Check mm database version header file
DBVER_CHK = nawk '{ \
	if ($$0 ~ /\#define\tMM_DB_VERSION/) { \
		ver = $$3 \
	}} END { \
	if (length(ver) == 0 || ver < 1) { \
		exit 1 \
	}}'

CATMSGS = ../common/mm.msg
CATALOG = ../common/mm.cat

all: $(DBVER) .WAIT db_version_check .WAIT $(CATALOG) $(PROG) MKDIRS

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS)

lint: $(lint_SRCS)

%.ln: ../common/%.c
	$(LINT.c) -c $<

$(ROOTLIBSCSI)/%: %
	$(INS.file)

install_h:

MMPATHS  = $(ROOT)/etc/mms/config
MMTYPES = $(ROOT)/etc/mms/types
SSLCONF = $(ROOT)/var/mms/ssl/ca
MMCAT = $(ROOT)/usr/lib/mms
MMDB = $(ROOT)/etc/mms/db
SCBIN = $(ROOT)/usr/bin
LIBSVC = $(ROOT)/lib/svc/method

ETCPWD = $(ROOT)/etc/mms/passwd
VARHDL = $(ROOT)/var/mms/handle
LOGAPI = $(ROOT)/var/log/mms/api
LOGWCR = $(ROOT)/var/log/mms/wcr
SSLPUB = $(ROOT)/var/mms/ssl/pub
LOGDM = $(ROOT)/var/log/mms/dm
LOGLM = $(ROOT)/var/log/mms/lm
LOGMM = $(ROOT)/var/log/mms/mm
VARCORES = $(ROOT)/var/mms/cores

FILES += $(MMPATHS)/mm_paths.xml
FILES += $(MMTYPES)/mm_types.xml
FILES += $(SCBIN)/mmsssl.sh
FILES += $(MMCAT)/mm.cat
FILES += $(MMDB)/mms_db
FILES += $(SSLCONF)/mms_openssl.cnf

install: all $(ROOTCMD) $(FILES) 

include ../../../Makefile.targ

# Generate mm database version header file from mms_db file
$(DBVER): $(DBMODS)
	-rm -f hdrs/mm_db_version.h
	rm -f $(OBJ32)/mm.o $(OBJ32)/mm_db.o $(OBJ32)/mmsmm
	rm -f $(OBJ64)/mm.o $(OBJ64)/mm_db.o $(OBJ64)/mmsmm
	echo "#ifndef\t_MM_DB_VERSION_H" > $(DBVER)
	echo "#define\t_MM_DB_VERSION_H" >> $(DBVER)
	echo >> $(DBVER)
	echo "/* Generated Database Version */" >> $(DBVER)
	printf "#define\tMM_DB_VERSION " >> $(DBVER)
	$(DBMODS_VER) < $(DBMODS) >> $(DBVER)
	echo >> $(DBVER)
	echo "#endif\t\t/* _MM_DB_VERSION_H */" >> $(DBVER)

# Validate mm database version
db_version_check:
	$(DBVER_CHK) < $(DBVER)

$(CATALOG): $(CATMSGS)
	/bin/rm -f $(CATALOG)
	/usr/bin/gencat $(CATALOG) $(CATMSGS)

$(MMPATHS):
	$(INS.dir)

$(MMTYPES):
	$(INS.dir)

$(MMCAT):
	$(INS.dir)

$(MMDB):
	$(INS.dir)

$(SSLCONF):
	$(INS.dir)

$(MMPATHS)/% := FILEMODE = 0644

$(MMPATHS)/%:	$(MMPATHS) ../common/%
	$(INS.file)

$(MMTYPES)/% := FILEMODE = 0644

$(MMTYPES)/%:	$(MMTYPES) ../common/%
	$(INS.file)

$(SCBIN)/%:	../common/%
	$(INS.file)

$(SSLCONF)/% := FILEMODE = 0644

$(SSLCONF)/%:	$(SSLCONF) ../common/%
	$(INS.file)

$(MMCAT)/%:	$(MMCAT) ../common/%
	$(INS.file)

$(MMDB)/% := FILEMODE = 0644

$(MMDB)/%:	$(MMDB) ../common/%
	$(INS.file)

$(ETCPWD):
	$(INS.dir)

$(VARHDL):
	$(INS.dir)

$(LOGAPI):
	$(INS.dir)

$(LOGWCR):
	$(INS.dir)

$(SSLPUB):
	$(INS.dir)

$(LOGDM):
	$(INS.dir)

$(LOGLM):
	$(INS.dir)

$(LOGMM):
	$(INS.dir)

$(VARCORES):
	$(INS.dir)


MKDIRS: $(ETCPWD) $(VARHDL) $(LOGAPI) $(LOGWCR) $(SSLPUB) $(LOGDM) \
	$(LOGLM) $(LOGMM) $(VARCORES)
