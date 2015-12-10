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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 RackTop Systems.
#

FSTYPE=		autofs
AUTO=		automount
MOUNT=		mount
VERS=		.2
DFSHARES=	dfshares
SHARE=		share
UNSHARE=	unshare
LIBPROG=	$(AUTO) $(MOUNT) $(DFSHARES) $(SHARE) $(UNSHARE)
TYPEPROG=	automountd

LINKINSTALL=	$(ROOTUSRSBIN)/$(AUTO)
LINKVALUE=	../lib/fs/$(FSTYPE)/$(AUTO)
MAPS=		auto_master auto_home
MAPINSTALL=	$(MAPS:%=$(ROOTETC)/%)
AUTOFS=		autofs
DEFAULTFILES=	autofs.dfl
SMFMANIFEST=	autofs.xml
SMFMETHOD=	svc-autofs
MFSTINSTALL=	$(SMFMANIFEST:%=$(ROOTSVCSYSTEM)/filesystem/%)
METHODINSTALL=	$(SMFMETHOD:%=$(ROOTLIBSVCMETHOD)/%)

OTHERINSTALL=	$(MAPINSTALL) $(LINKINSTALL) $(ROOTETCDEFAULTFILES) \
		$(MFSTINSTALL) $(METHODINSTALL)

UNCHECKED_HDRS=	webnfs.h

MANIFEST=	autofs.xml
SVCMETHOD=	svc-autofs

include		../Makefile.fstype

$(MAPINSTALL)	:= FILEMODE= 0644

$(MFSTINSTALL)	:= FILEMODE = 0444

REAL_COMMON=	debug_alloc.o
COMMON=		ns_generic.o ns_files.o ns_nis.o \
		ns_ldap.o auto_mnttab.o auto_subr.o $(REAL_COMMON)

AUTOOBJS=	automount.o $(COMMON) $(FSLIB) smfcfg.o

MOUNTOBJS=	mount.o $(FSLIB) $(REAL_COMMON)

LOCAL=		autod_main.o \
		autod_parse.o autod_mount.o autod_nfs.o nfs_cast.o \
		autod_autofs.o autod_xdr.o autod_readdir.o autod_lookup.o \
		smfcfg.o

TYPEOBJS=	$(LOCAL) $(COMMON) replica.o nfs_sec.o nfs_resolve.o nfs_subr.o \
		$(FSLIB) webnfs_xdr.o webnfs_client.o selfcheck.o

SHAREOBJS=	$(SHARESRCS:%.c=%.o)

UNSHAREOBJS=	$(UNSHARESRCS:%.c=%.o)

POFILE= autofs.po
GREP= egrep
SED= sed

$(AUTO) := 	LDLIBS += -lnsl -lsldap -lscf
$(MOUNT):=	LDLIBS += -lscf
$(TYPEPROG) :=	LDLIBS += -lrpcsvc -lsocket -lnsl -lsldap -lkstat -lscf

CFLAGS +=	$(CCVERBOSE) -D_FILE_OFFSET_BITS=64
CPPFLAGS=	-I. -I.. -I../nfs/lib $(CPPFLAGS.master) -D_REENTRANT  \
			$(MALLOC_DEBUG)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-function

OBJS=		$(AUTOOBJS) $(MOUNTOBJS) $(TYPEOBJS) \
		$(SHAREOBJS) $(UNSHAREOBJS)

AUTOSRCS=	automount.c $(COMMON:%.o=%.c) $(FSLIBSRC)
MOUNTSRCS=	mount.c $(FSLIBSRC)
TYPESRCS=	$(LOCAL:%.o=%.c) $(COMMON:%.o=%.c) \
		../nfs/lib/replica.c ../nfs/lib/nfs_sec.c \
		../nfs/lib/nfs_subr.c $(FSLIBSRC) ../nfs/lib/selfcheck.c \
		../nfs/lib/nfs_resolve.c ../nfs/lib/smfcfg.c
SHARESRCS=	$(SHARE:%=%.c)
UNSHARESRCS=	$(UNSHARE:%=%.c)
DFSHARESSRCS=	$(DFSHARES:%=%.sh)
SRCS=		$(OBJS:%.o=%.c)

nfs_sec.o :=	CPPFLAGS += -DWNFS_SEC_NEGO

$(AUTO):	$(AUTOOBJS)
		$(LINK.c) -o $@ $(AUTOOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(MOUNT):	$(MOUNTOBJS)
		$(LINK.c) -o $@ $(MOUNTOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(TYPEPROG):	webnfs.h $(TYPEOBJS)
		$(LINK.c) -o $@ $(TYPEOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(SHARE):	$(SHAREOBJS)
		$(LINK.c) -o $@ $(SHAREOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(UNSHARE):	$(UNSHAREOBJS)
		$(LINK.c) -o $@ $(UNSHAREOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(ROOTSVCSYSTEM)/filesystem/%: %
		$(INS.file)

DUMP_PROG=malloc_dump
BUILDDIR=tmp
DUMP_PROTO=$(BUILDDIR)/$(DUMP_PROG)_client
XFILE=$(BUILDDIR)/malloc_dump.x
XLINE= "program DUMP { version VERS \
	{ void DUMP_IT(void) = 1000000; } = 2; } = 100099;"

$(XFILE):	$(BUILDDIR)
		$(RM) $(XFILE)
		echo $(XLINE) > $(XFILE)

$(BUILDDIR):
		$(RM) -r $(BUILDDIR)
		mkdir $(BUILDDIR)

$(DUMP_PROTO):	$(BUILDDIR) $(XFILE)
		cd $(BUILDDIR); $(RM) *.[ch] makefile.malloc_dump ; rpcgen -a `basename $(XFILE)
		cd $(BUILDDIR); $(MAKE) -f makefile.malloc_dump `basename $@`

$(DUMP_PROG):	$(DUMP_PROTO)
		$(RM) $@
		cp $(DUMP_PROTO) $@

clean_dump:
		$(RM) -r $(BUILDDIR)
		$(RM) $(DUMP_PROG)
$(ROOTUSRSBIN)/$(AUTO):
		$(RM) $@; $(SYMLINK) $(LINKVALUE) $@

replica.o:	../nfs/lib/replica.c
		$(COMPILE.c) ../nfs/lib/replica.c

nfs_sec.o:	../nfs/lib/nfs_sec.c
		$(COMPILE.c) ../nfs/lib/nfs_sec.c

nfs_subr.o:	../nfs/lib/nfs_subr.c
		$(COMPILE.c) ../nfs/lib/nfs_subr.c

selfcheck.o:	../nfs/lib/selfcheck.c
		$(COMPILE.c) ../nfs/lib/selfcheck.c

smfcfg.o: ../nfs/lib/smfcfg.c
		$(COMPILE.c) ../nfs/lib/smfcfg.c

nfs_resolve.o:	../nfs/lib/nfs_resolve.c
		$(COMPILE.c) ../nfs/lib/nfs_resolve.c

webnfs_xdr.c:	webnfs.x
	$(RPCGEN) -M -C -c -o $@ webnfs.x

webnfs_client.c:	webnfs.x
	$(RPCGEN) -M -C -l -o $@ webnfs.x

webnfs.h:	webnfs.x
	$(RPCGEN) -M -C -h -o $@ webnfs.x

webnfs.x:	../nfs/lib/webnfs.x
	$(RM) webnfs.x
	cp ../nfs/lib/webnfs.x .

catalog: $(POFILE)

$(POFILE):
	$(RM) messages.po
	$(SED) -e 's/pr_msg/gettext/' `$(GREP) -l "pr_msg|gettext" *.[ch]` | \
	$(XGETTEXT) $(XGETFLAGS) -
	$(SED) -e '/^# msg/d' -e '/^domain/d' < messages.po > $@
	$(RM) messages.po

lint:
	$(LINT.c) $(AUTOSRCS)
	$(LINT.c) $(MOUNTSRCS)
	$(LINT.c) $(TYPESRCS)

clean:	clean_dump
	$(RM) $(OBJS) webnfs_xdr.c webnfs_client.c webnfs.h webnfs.x

check:	$(CHKMANIFEST)
