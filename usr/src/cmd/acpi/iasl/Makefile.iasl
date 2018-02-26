#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright (c) 2018, Joyent, Inc.
#
# Adapted from acpica/generate/unix/iasl/Makefile, which lacked a copyright
# notice.
#

# This makefile is also used by $SRC/tools/iasl/Makefile

OBJS =	aslanalyze.o aslascii.o aslbtypes.o aslcodegen.o aslcompile.o \
	asldebug.o aslerror.o aslexternal.o aslfileio.o \
	aslfiles.o aslfold.o aslhex.o asllength.o asllisting.o asllistsup.o \
	aslload.o asllookup.o aslmain.o aslmap.o aslmapenter.o aslmapoutput.o \
	aslmaputils.o aslmessages.o aslmethod.o aslnamesp.o asloffset.o \
	aslopcodes.o asloperands.o aslopt.o asloptions.o aslpld.o aslpredef.o \
	aslprepkg.o aslprintf.o aslprune.o aslresource.o aslrestype1.o \
	aslrestype1i.o aslrestype2.o aslrestype2d.o aslrestype2e.o \
	aslrestype2q.o aslrestype2s.o aslrestype2w.o aslstartup.o aslstubs.o \
	asltransform.o asltree.o aslutils.o asluuid.o aslwalks.o aslxref.o \
	aslxrefout.o dtcompile.o dtexpress.o dtfield.o dtio.o \
	dtsubtable.o dttable.o dttable1.o dttable2.o dttemplate.o dtutils.o \
	prexpress.o prmacros.o prscan.o prutils.o
# ../common
OBJS +=	adfile.o acfileio.o adisasm.o adwalk.o ahids.o ahtable.o ahpredef.o \
	ahuuids.o dmextern.o dmrestag.o dmtbinfo.o dmtable.o dmtbdump.o \
	getopt.o osl.o osunixxf.o
# usr/src/common/acpica/disassembler
OBJS += dmbuffer.o dmcstyle.o dmdeferred.o dmnames.o dmopcode.o dmresrc.o \
	dmresrcl.o dmresrcl2.o dmresrcs.o dmtables.o dmutils.o dmwalk.o
# usr/src/common/acpica/dispatcher
OBJS += dsargs.o dscontrol.o dsfield.o dsobject.o dsopcode.o dsutils.o \
	dswload.o dswload2.o dswexec.o dswscope.o dswstate.o
# usr/src/common/acpica/executer
OBJS += exconcat.o exconvrt.o excreate.o exdump.o exmisc.o exmutex.o exnames.o \
	exoparg1.o exoparg2.o exoparg3.o exoparg6.o exprep.o exresolv.o \
	exresop.o exresnte.o exstore.o exstoren.o exstorob.o exsystem.o \
	exutils.o
# usr/src/common/acpica/namespace
OBJS += nsaccess.o nsalloc.o nsdump.o nsnames.o nsobject.o nsparse.o \
	nssearch.o nsutils.o nswalk.o
# usr/src/common/acpica/parser
OBJS += psargs.o psloop.o psobject.o psopcode.o psopinfo.o psparse.o psscope.o pstree.o \
	psutils.o pswalk.o
# usr/src/common/acpica/tables
OBJS +=	tbdata.o tbfadt.o tbinstal.o tbprint.o tbutils.o tbxface.o
# usr/src/common/acpica/utilities
OBJS += utaddress.o utalloc.o utascii.o utbuffer.o utcache.o utcopy.o \
	utdebug.o utdecode.o utdelete.o uterror.o utexcep.o utglobal.o uthex.o \
	utinit.o utlock.o utmath.o utmisc.o utmutex.o utnonansi.o utobject.o \
	utownerid.o utpredef.o utprint.o utresrc.o utstate.o utstring.o \
	utuuid.o utxface.o utxferror.o

SRCS = $(OBJS:.o=.c)

ACPI_CMN_SRC		= $(SRC)/common/acpica

# Source used only by iasl
ASL_COMPILER		= compiler
ACPICA_DEBUGGER		= debugger
# Source used by kernel module and iasl
ACPICA_DISASSEMBLER	= $(ACPI_CMN_SRC)/disassembler
ACPICA_DISPATCHER	= $(ACPI_CMN_SRC)/dispatcher
ACPICA_EXECUTER		= $(ACPI_CMN_SRC)/executer
ACPICA_NAMESPACE	= $(ACPI_CMN_SRC)/namespace
ACPICA_PARSER		= $(ACPI_CMN_SRC)/parser
ACPICA_TABLES		= $(ACPI_CMN_SRC)/tables
ACPICA_UTILITIES	= $(ACPI_CMN_SRC)/utilities
# Source used by other programs and iasl
ACPICA_COMMON		= $(IASL_SRC_DIR)/../common

VPATH = $(ACPICA_DEBUGGER):$(ACPICA_DISASSEMBLER):\
	$(ACPICA_DISPATCHER):$(ACPICA_EXECUTER):$(ACPICA_NAMESPACE):\
	$(ACPICA_PARSER):$(ACPICA_TABLES):$(ACPICA_UTILITIES):\
	$(ACPICA_COMMON):$(ACPICA_OSL)

INTERMEDIATES = \
	aslcompiler.y \
	aslcompilerlex.c \
	aslcompilerparse.c \
	dtparserlex.c \
	dtparserparse.c \
	prparserlex.c \
	prparserparse.c \
	aslcompiler.y.h \
	dtparser.y.h \
	prparser.y.h

CERRWARN += -_gcc=-Wno-unused-function

CPPFLAGS += -I$(SRC)/uts/intel/sys/acpi -DACPI_ASL_COMPILER -I.

LEX_C_FILES = aslcompilerlex.c dtparserlex.c prparserlex.c
YACC_C_FILES = aslcompilerparse.c dtparserparse.c prparserparse.c
YACC_H_FILES = aslcompiler.y.h dtparser.y.h prparser.y.h
YACC_FILES = $(YACC_C_FILES) $(YACC_H_FILES)

aslcompilerlex.c aslcompilerparse.c aslcompiler.y.h := PARSER = AslCompiler
aslcompilerlex.c aslcompilerparse.c aslcompiler.y.h := LY_BASE = aslcompiler

dtparserlex.c dtparserparse.c dtparser.y.h := PARSER = DtParser
dtparserlex.c dtparserparse.c dtparser.y.h := LY_BASE = dtparser

prparserlex.c prparserparse.c prparser.y.h := PARSER = PrParser
prparserlex.c prparserparse.c prparser.y.h := LY_BASE = prparser

$(LEX_C_FILES) := LEXFILE = $(LY_BASE).l
$(LEX_C_FILES) := LEXFILE = $(LY_BASE).l
$(YACC_FILES) := YTABC = $(LY_BASE)parse.c

OBJS += $(LEX_C_FILES:.c=.o) $(YACC_C_FILES:.c=.o)

GM4FLAGS = -P
LFLAGS = -i -s

.KEEP_STATE:

.PARALLEL: $(OBJS) $(INTERMEDIATES)

all: $(YACC_FILES) .WAIT $(PROG)

$(IASL_OBJ_DIR)/aslcompiler.y: $(IASL_SRC_DIR)/aslparser.y
	$(GM4) $(GM4FLAGS) $(IASL_SRC_DIR)/aslparser.y > $@.tmp
	mv $@.tmp $@

$(LEX_C_FILES):
	$(FLEX) $(LFLAGS) -P$(PARSER) -o $@ $(IASL_SRC_DIR)/$(LEXFILE)

%parse.h: %parse.c

#
# This rule builds .c and .h files from .y files that are in the source
# directory.  When building under $(SRC)/cmd/acpi/iasl, this rule handles all
# invocations of $(BISON) because $(IASL_SRC_DIR) and $(IASL_OBJ_DIR) are the
# same.
#
# Keep this rule in sync with the one below it.  Only the dependency should be
# different.
#
%parse.c %.y.h: $(IASL_SRC_DIR)/%.y
	_suffix=`echo $@ | awk -F. '{print $$NF}'` && \
	_d=`mktemp -d $(PARSER).XXXXXX` && \
	(cd $$_d && $(BISON) -y -v -d -p$(PARSER) $<) && \
	mv $$_d/y.tab.$$_suffix $@; \
	_ret=$$?; \
	rm -rf $$_d; \
	exit $$_ret

#
# This rule builds .c and .h files from dynamically generated .y files, but only
# when $(IASL_SRC_DIR) and $(IASL_OBJ_DIR) are different.  When building under
# $(SRC)/cmd/acpi/iasl, this rule is not used.  When building under
# $(SRC)/tools/iasl, it creates .c and .h files from dynamically generated .y
# files (e.g. aslcompiler.y).
#
# Keep this rule in sync with the one above it.  Only the dependency should be
# different.
#
%parse.c %.y.h: $(IASL_OBJ_DIR)/%.y
	_suffix=`echo $@ | awk -F. '{print $$NF}'` && \
	_d=`mktemp -d $(PARSER).XXXXXX` && \
	(cd $$_d && $(BISON) -y -v -d -p$(PARSER) $<) && \
	mv $$_d/y.tab.$$_suffix $@; \
	_ret=$$?; \
	rm -rf $$_d; \
	exit $$_ret

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(INTERMEDIATES) $(PROG) *.tmp
	$(RM) -r AslCompiler.?????? DtParser.?????? PrParser.??????

lint:	lint_SRCS
