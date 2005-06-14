#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Makefile for system source
#
# include global definitions
include Makefile.master
#
# the Targetdirs file is the AT&T target.dirs file in a makefile format.
# it defines TARGETDIRS and ROOTDIRS.
include Targetdirs

COMMON_SUBDIRS=	uts lib cmd ucblib ucbcmd

#
# sparc needs to build both stand and psm, in that order
# x86 needs to build psm and GRUB
#
sparc_SUBDIRS= stand psm
i386_SUBDIRS= psm grub

SUBDIRS= $(COMMON_SUBDIRS) $($(MACH)_SUBDIRS)

HDRSUBDIRS=	uts head lib cmd ucbhead

# UCB headers are bug-for-bug compatible and not checkable against the header
# standards.
#
CHKHDRSUBDIRS=	head uts lib

# The check target also causes smf(5) service manifests to be validated.
CHKMFSTSUBDIRS=	cmd

MSGSUBDIRS=	cmd ucbcmd lib
DOMAINS= \
	SUNW_OST_ADMIN \
	SUNW_OST_NETRPC \
	SUNW_OST_OSCMD \
	SUNW_OST_OSLIB \
	SUNW_OST_UCBCMD \
	SUNW_OST_ZONEINFO

MSGDDIRS=       $(DOMAINS:%=$(MSGROOT)/%)
MSGDIRS=        $(MSGROOT) $(MSGDDIRS) $(MSGROOT)/LC_TIME

all all_xmod :=		TARGET= all
install install_xmod :=	TARGET= install
install_h :=		TARGET= install_h
clean :=		TARGET= clean
clobber :=		TARGET= clobber
check :=		TARGET= check
_msg :=			TARGET= _msg


.KEEP_STATE:

#
# Note: install only builds the all target for the pkgdefs
#       directory.  We are not yet ready to have an install
#	build create 'packages' also.  To build packages
#	cd pkgdefs and do a 'make install'
#
all: sgs .WAIT $(SUBDIRS) pkg_all
install: sgs .WAIT $(SUBDIRS) pkg_all .WAIT _msg
	@cd pkgdefs/SUNW0on; pwd; $(MAKE) _msg
	@rm -rf "$(ROOT)/catalog"

clean clobber: $(SUBDIRS) head pkgdefs
_msg: _msgdirs rootdirs $(MSGSUBDIRS)

# for a complete build from scratch
crankturn: sgs uts pkg_all
	@cd lib; pwd; $(MAKE) install
	@cd cmd; pwd; $(MAKE) all
	@cd ucblib; pwd; $(MAKE) install
	@cd ucbcmd; pwd; $(MAKE) all

pkg_all:
	@cd pkgdefs; pwd; $(MAKE) all

#
# target for building a proto area for reference via the ROOT macro
#
protolibs: rootlibs ucblibs

# build all ucb libraries
#
ucblibs:
	@cd ucblib; pwd; $(MAKE) install

# Base subset of rootproto, excluding ucb libraries
#
rootlibs: sgs
	@cd lib; pwd; $(MAKE) install

$(SUBDIRS) head ucbhead pkgdefs: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

.PARALLEL:	sysheaders userheaders libheaders ucbheaders cmdheaders

# librpcsvc has a dependency on headers installed by
# userheaders, hence the .WAIT before libheaders.
sgs: rootdirs .WAIT sysheaders userheaders .WAIT \
	libheaders ucbheaders cmdheaders

#
# top-level setup target (headers/tools)
setup: sgs
	@cd tools; pwd; $(MAKE) install

# /var/mail/:saved is a special case because of the colon in the name.
#
rootdirs: $(ROOTDIRS)
	$(INS) -d -m 775 $(ROOT)/var/mail/:saved
	$(CH)$(CHOWN) root $(ROOT)/var/mail/:saved
	$(CH)$(CHGRP) mail $(ROOT)/var/mail/:saved

lint: FRC
	$(MAKE) -f Makefile.lint

_msgdirs:       $(MSGDIRS)

$(ROOTDIRS) $(MSGDIRS):
	$(INS.dir)

userheaders: FRC
	@cd head; pwd; $(MAKE) install_h

libheaders: FRC
	@cd lib; pwd; $(MAKE) install_h

sysheaders: FRC
	@cd uts; pwd; $(MAKE) install_h

ucbheaders: FRC
	@cd ucbhead; pwd; $(MAKE) install_h

cmdheaders: FRC
	@cd cmd/fm; pwd; $(MAKE) install_h
	@cd cmd/mdb; pwd; $(MAKE) install_h

# each xmod target depends on a corresponding MACH-specific pseudotarget
# before doing common xmod work
#
all_xmod install_xmod: $$@_$(MACH)
	@cd uts/common/sys; pwd; $(MAKE) svvs_h

all_xmod_sparc install_xmod_sparc: FRC
	@cd uts/sparc; pwd; \
	  $(MAKE) TARGET=$(TARGET) svvs pm wsdrv

all_xmod_i386 install_xmod_i386: FRC
	@cd uts/i86; pwd; $(MAKE) TARGET=$(TARGET) svvs

check:	$(CHKHDRSUBDIRS) $(CHKMFSTSUBDIRS)

#
# Cross-reference customization: skip all of the subdirectories that
# don't contain actual source code.
#
XRPRUNE = spec pkgdefs prototypes xmod
XRINCDIRS = uts/common head ucbhead

cscope.out tags: FRC
	$(XREF) -f -x $@

FRC:

# EXPORT DELETE START

XMOD_DELETE_FILES:sh = cat xmod/xmod_files

EXPORT_SRC:
	@cd cmd/cmd-inet/usr.lib/in.iked;  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/cmd-inet/usr.lib/ike-certutils;  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/cmd-inet/usr.sbin; pwd; $(MAKE) EXPORT_SRC
	@cd cmd/cmd-crypto/etc; pwd; $(MAKE) EXPORT_SRC
	@cd cmd/crypt;	  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/gss/gssd;         pwd; $(MAKE) EXPORT_SRC
	@cd cmd/krb5/kadmin;  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/sendmail/src; pwd; $(MAKE) EXPORT_SRC
	@cd cmd/xntpd;	  pwd; $(MAKE) EXPORT_SRC
	@cd common/crypto/aes;	  pwd; $(MAKE) EXPORT_SRC
	@cd common/crypto/arcfour; pwd; $(MAKE) EXPORT_SRC
	@cd common/crypto/blowfish;	  pwd; $(MAKE) EXPORT_SRC
	@cd common/crypto/des;	  pwd; $(MAKE) EXPORT_SRC
	@cd common/crypto/rsa;	  pwd; $(MAKE) EXPORT_SRC
	@cd lib/crypt_modules/bsdbf; pwd ; $(MAKE) EXPORT_SRC
	@cd lib/gss_mechs/mech_dummy;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/gss_mechs/mech_dh/backend;	pwd; $(MAKE) EXPORT_SRC
	@cd lib/gss_mechs/mech_krb5;		pwd; $(MAKE) EXPORT_SRC
	@cd lib/gss_mechs/mech_spnego;		pwd; $(MAKE) EXPORT_SRC
	@cd lib/libcrypt; pwd; $(MAKE) EXPORT_SRC
	@cd lib/libelfsign;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/libgss;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/libike;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/libnsl;	  pwd; $(MAKE) EXPORT_SRC
	@cd lib/openssl; pwd; $(MAKE) EXPORT_SRC
	@cd lib/pkcs11/pkcs11_softtoken/common;  pwd; $(MAKE) EXPORT_SRC
	@cd lib/pkcs11/libpkcs11;  pwd; $(MAKE) EXPORT_SRC
	@cd lib/pkcs11;  pwd; $(MAKE) EXPORT_SRC
	@cd lib/libsldap; pwd; $(MAKE) EXPORT_SRC
	@cd lib/libsasl; pwd; $(MAKE) EXPORT_SRC
	@cd lib/sasl_plugins; pwd; $(MAKE) EXPORT_SRC
	@cd lib/smartcard;	  pwd; $(MAKE) EXPORT_SRC
	@cd lib/pam_modules/krb5;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/udapl; pwd; $(MAKE) EXPORT_SRC
	@cd lib/libresolv2; pwd; $(MAKE) EXPORT_SRC
	@cd tools/elfsign; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/crypto/io; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/des; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/inet; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/inet/ip; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/rpc; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/sys; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/include;		pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi;			pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/mechs/dummy;	pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/mechs/krb5;	pwd; $(MAKE) EXPORT_SRC
	@cd uts/common; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sparc; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sun4u/forthdebug; pwd; $(MAKE) EXPORT_SRC
	@cd uts/intel; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sun4u; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sun4u/chalupa;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/cherrystone;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/daktari;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/enchilada;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/ents;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/excalibur;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/chicago;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/littleneck;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/lw2plus;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/lw8;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/mpxu;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/serengeti;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/starcat;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4u/taco;	pwd;	$(MAKE) EXPORT_SRC
	@cd uts/sun4v/io/ncp;	pwd;	$(MAKE) EXPORT_SRC
	@cd pkgdefs;	pwd; $(MAKE) EXPORT_SRC
	$(RM) -r $(XMOD_DELETE_FILES)
	$(RM) Targetdirs+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
			< Targetdirs > Targetdirs+
	$(MV) Targetdirs+ Targetdirs
	$(CHMOD) 444 Targetdirs
	$(RM) Makefile+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
			< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
	$(RM) Makefile.master+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
			< Makefile.master > Makefile.master+
	$(MV) Makefile.master+ Makefile.master
	$(CHMOD) 444 Makefile.master

CRYPT_SRC:
	@cd cmd/cmd-inet/usr.lib/in.iked;  pwd; $(MAKE) CRYPT_SRC
	@cd cmd/cmd-inet/usr.lib/ike-certutils;  pwd; $(MAKE) CRYPT_SRC
	@cd lib/crypt_modules/bsdbf; pwd ; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_dummy;   pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_dh/backend; pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_krb5; pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_spnego; pwd; $(MAKE) CRYPT_SRC
	@cd lib/libelfsign;   pwd; $(MAKE) CRYPT_SRC
	@cd lib/libike;   pwd; $(MAKE) CRYPT_SRC
	@cd lib/libnsl;	 pwd; $(MAKE) CRYPT_SRC
	@cd lib/libsasl;	 pwd; $(MAKE) CRYPT_SRC
	@cd lib/libresolv2;	 pwd; $(MAKE) CRYPT_SRC
	@cd lib/sasl_plugins; pwd; $(MAKE) CRYPT_SRC
	@cd lib/pam_modules/krb5;   pwd; $(MAKE) CRYPT_SRC
	@cd tools/elfsign; pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/inet;    pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/inet/ip;    pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/gssapi;    pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/gssapi/include;    pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/gssapi/mechs/dummy;        pwd; $(MAKE) CRYPT_SRC
	@cd uts/common/gssapi/mechs/krb5; pwd; $(MAKE) CRYPT_SRC
	$(RM) Makefile+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
			< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
	$(RM) Makefile.master+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
			< Makefile.master > Makefile.master+
	$(MV) Makefile.master+ Makefile.master
	$(CHMOD) 444 Makefile.master

# EXPORT DELETE END

ONC_PLUS:
	@cd cmd/login; pwd; $(MAKE) ONC_PLUS
	@cd uts; pwd; $(MAKE) ONC_PLUS

#
# Targets for reporting compiler versions; nightly uses these.
#

cc-version:
	@if [ -x "$($(MACH)_CC)" ]; then		\
		$(ECHO) $($(MACH)_CC);			\
		$($(MACH)_CC) -V 2>&1 | head -1;	\
	elif [ -x "$(SPRO_VROOT)/bin/cc" ]; then	\
		$(ECHO) $(SPRO_VROOT)/bin/cc;		\
		$(SPRO_VROOT)/bin/cc -V 2>&1 | head -1;	\
	else						\
		$(ECHO) No compiler found;		\
		exit 1;					\
	fi

cc64-version:
	@if [ -x "$($(MACH64)_CC)" ]; then		\
		$(ECHO) 64-bit compiler;		\
		$(ECHO) $($(MACH64)_CC);		\
		$($(MACH64)_CC) -V 2>&1 | head -1;	\
	elif [ -x "$(GNU_ROOT)/bin/gcc" ]; then		\
		$(ECHO) 64-bit compiler;		\
		$(ECHO) $(GNU_ROOT)/bin/gcc;		\
		$(GNU_ROOT)/bin/gcc --version 2>&1 | head -1;	\
	else						\
		$(ECHO) No 64-bit compiler found;	\
	fi

java-version:
	@if [ -x "$(JAVAC)" ]; then			\
		$(ECHO) $(JAVAC);			\
		$(JAVA_ROOT)/bin/java -fullversion 2>&1 | head -1;	\
	else						\
		$(ECHO) No Java compiler found;		\
		exit 1;					\
	fi
