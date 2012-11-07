#
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# BSD 3 Clause License
#
# Copyright (c) 2007, The Storage Networking Industry Association.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 	- Redistributions of source code must retain the above copyright
#	  notice, this list of conditions and the following disclaimer.
#
# 	- Redistributions in binary form must reproduce the above copyright
#	  notice, this list of conditions and the following disclaimer in
#	  the documentation and/or other materials provided with the
#	  distribution.
#
#	- Neither the name of The Storage Networking Industry Association (SNIA)
#	  nor the names of its contributors may be used to endorse or promote
#	  products derived from this software without specific prior written
#	  permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
PROG = ndmpd

include $(SRC)/cmd/Makefile.cmd

NDMP_DIR = ndmp
TLM_DIR = tlm

include $(NDMP_DIR)/Makefile.rpcgen

CFLAGS += $(CCVERBOSE)

CPPFLAGS += $(LFLAGS64)

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -DDEBUG
CPPFLAGS += -I. -Iinclude

C99MODE = $(C99_ENABLE)

# lint does not like unused _umem_*_init
LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2 

# function argument declared inconsistently
LINTFLAGS += -xerroff=E_INCONS_ARG_DECL2
# value type used inconsistently
LINTFLAGS += -xerroff=E_INCONS_VAL_TYPE_USED2
# value type declared inconsistently
LINTFLAGS += -xerroff=E_INCONS_VAL_TYPE_DECL2
# argument used inconsistently
LINTFLAGS += -xerroff=E_INCONS_ARG_USED2 

CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-address

LDLIBS   += -lsocket -lnsl -lzfs -lsec -lndmp -lmd5 -lnvpair -lumem -lbsm -lgen -lcmdutils -linetutil

OBJS= \
	$(NDMP_DIR)/ndmp_xdr.o \
	$(NDMP_OBJ:%.o=$(NDMP_DIR)/%.o) $(TLM_OBJ:%.o=$(TLM_DIR)/%.o)

NDMP_OBJ = \
	ndmpd_callbacks.o \
	ndmpd_chkpnt.o \
	ndmpd_comm.o \
	ndmpd_config.o \
	ndmpd_connect.o \
	ndmpd_data.o \
	ndmpd_door.o \
	ndmpd_dtime.o \
	ndmpd_fhistory.o \
	ndmpd_handler.o \
	ndmpd_log.o \
	ndmpd_main.o \
	ndmpd_mark.o \
	ndmpd_mover.o \
	ndmpd_prop.o \
	ndmpd_scsi.o \
	ndmpd_tape.o \
	ndmpd_tar.o \
	ndmpd_tar3.o \
	ndmpd_util.o \
	ndmpd_zfs.o

TLM_OBJ = \
	tlm_backup_reader.o \
	tlm_bitmap.o \
	tlm_buffers.o \
	tlm_info.o \
	tlm_init.o \
	tlm_lib.o \
	tlm_restore_writer.o \
	tlm_traverse.o \
	tlm_util.o \
	tlm_hardlink.o

SRCS= $(NDMP_OBJ:%.o=$(NDMP_DIR)/%.c) $(TLM_OBJ:%.o=$(TLM_DIR)/%.c)

SVCMETHOD = svc-ndmp
$(ROOTSVCMETHOD) := FILEMODE = 0555

MANIFEST = ndmp.xml
ROOTMANIFESTDIR= $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE = 444

ROOTNDMPDDIR=	$(ROOTLIB)/ndmp
ROOTNDMPDFILE = $(PROG:%=$(ROOTNDMPDDIR)/%)

FILEMODE = 0444
$(ROOTNDMPDFILE):= FILEMODE = 0555

$(ROOTNDMPDDIR):
	$(INS.dir)

$(ROOTNDMPDDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTNDMPDDIR)  $(ROOTNDMPDFILE) $(ROOTSVCMETHOD) $(ROOTMANIFEST) 

check:	$(CHKMANIFEST)

clobber:

$(PROG) : $(OBJS)
	$(LINK.c) -o $@  $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(NDMP_DIR)/%.o : $(NDMP_DIR)/%.c
	$(COMPILE.c) -o $@ $<

$(TLM_DIR)/%.o : $(TLM_DIR)/%.c
	$(COMPILE.c) -o $@ $<

lint:	lint_SRCS

clean:  rpcclean
	rm -f $(NDMP_DIR)/*.o $(TLM_DIR)/*.o

include $(SRC)/cmd/Makefile.targ
