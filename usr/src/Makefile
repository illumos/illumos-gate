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
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
#
#
# Makefile for system source
#
# include global definitions
include Makefile.master
#
# the Targetdirs file is the AT&T target.dirs file in a makefile format.
# it defines TARGETDIRS and ROOTDIRS.
include Targetdirs

COMMON_SUBDIRS=	uts lib cmd ucblib ucbcmd psm man
sparc_SUBDIRS= stand
i386_SUBDIRS= grub

#
# sparc needs to build stand before psm
#
$(SPARC_BLD)psm: stand

SUBDIRS= $(COMMON_SUBDIRS) $($(MACH)_SUBDIRS)

HDRSUBDIRS=	uts head lib cmd ucbhead

# UCB headers are bug-for-bug compatible and not checkable against the header
# standards.
#
CHKHDRSUBDIRS=	head uts lib

#
# Headers that can be built in parallel
#
PARALLEL_HEADERS = sysheaders userheaders libheaders ucbheaders cmdheaders

#
# Directories that can be built in parallel
#
PARALLEL_DIRS = uts lib man

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
install1 :=		TARGET= install
install2 :=		TARGET= install
install_h :=		TARGET= install_h
clean :=		TARGET= clean
clobber :=		TARGET= clobber
check :=		TARGET= check

.KEEP_STATE:

#
# Note: install does not cause a build in pkg.  To build packages,
#	cd pkg and do a 'make install'
#

all: mapfiles closedbins sgs .WAIT $(SUBDIRS) pkg

#
# The _msg build is a two-step process.  First, the _msg dependency
# causes recursive makes in $(MSGSUBDIRS), which stages raw message
# files in $(ROOT)/catalog.  Second, the action from the install
# target rule causes those messages to be post-processed from where
# they were staged in $(ROOT)/catalog, and the results placed into the
# proto area.
#
# The stage-licenses target causes the license files needed for
# packaging to be pulled from $(SRC) and $(CLOSED) and staged in
# $(ROOT)/licenses.
#
install: install1 install2 _msg stage-licenses
	@cd msg; pwd; $(MAKE) _msg
	@rm -rf "$(ROOT)/catalog"

stage-licenses: install2
	@cd pkg; pwd; $(MAKE) stage-licenses

install1: mapfiles closedbins sgs

install2: install1 $(SUBDIRS)

_msg: _msgdirs rootdirs install2 FRC
	@for m in $(MSGSUBDIRS); do \
		cd $$m; pwd; $(MAKE) _msg; cd ..; \
	done

mapfiles: bldtools
	@cd common/mapfiles; pwd; $(MAKE) install

clean clobber: $(SUBDIRS) head pkg

closedbins: bldtools $(ROOTDIRS) FRC
	@CLOSED_ROOT="$$ON_CLOSED_BINS/root_$(MACH)$${RELEASE_BUILD+-nd}"; \
	if [ "$$CLOSED_IS_PRESENT" = no ]; then \
		if [ ! -d "$$CLOSED_ROOT" ]; then \
			$(ECHO) "Error: if closed sources are not present," \
			    "ON_CLOSED_BINS must point to closed binaries."; \
			$(ECHO) "root_$(MACH)$${RELEASE_BUILD+-nd} is not" \
			    "present in $$ON_CLOSED_BINS."; \
			exit 1; \
		fi; \
		$(ECHO) "Copying closed binaries from $$CLOSED_ROOT"; \
		(cd $$CLOSED_ROOT; \
		    $(TAR) cfX - $(CODEMGR_WS)/exception_lists/closed-bins .) | \
		    (cd $(ROOT); $(TAR) xBpf -); \
		( cd $(ROOT); $(CTFSTRIP) $$(cd $$CLOSED_ROOT; $(FIND) \
		    ./kernel ./usr/kernel ./platform/*/kernel -type f -a -perm -u+x | \
		    $(EGREP) -vf $(CODEMGR_WS)/exception_lists/closed-bins) ); \
	fi

#
# Declare what parts can be built in parallel
# DUMMY at the end is used in case macro expansion produces an empty string to
# prevent everything going in parallel
#
.PARALLEL: $(PARALLEL_HEADERS) DUMMY
.PARALLEL: $(PARALLEL_DIRS) DUMMY

$(SUBDIRS) head ucbhead pkg: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

# librpcsvc has a dependency on headers installed by
# userheaders, hence the .WAIT before libheaders.
sgs: rootdirs .WAIT sysheaders userheaders .WAIT \
	libheaders ucbheaders cmdheaders

#
# Top-level setup target to setup the development environment that includes
# headers, tools and generated mapfiles.  For open-only builds (i.e.: source
# trees w/o usr/closed), this also depends on the closedbins target (above)
# in order to properly seed the proto area.  Note, although the tools are
# dependent on a number of constant mapfiles, the tools themselves are
# required to build the generated mapfiles.
#
setup: closedbins bldtools sgs mapfiles

bldtools:
	@cd tools; pwd; $(MAKE) install

# /var/mail/:saved is a special case because of the colon in the name.
#
rootdirs: $(ROOTDIRS)
	$(INS) -d -m 775 $(ROOT)/var/mail/:saved

lint: FRC
	$(MAKE) -f Makefile.lint

_msgdirs:       $(MSGDIRS)

$(ROOTDIRS) $(MSGDIRS):
	$(INS.dir)

userheaders: FRC
	@cd head; pwd; $(MAKE) install_h

libheaders: bldtools
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
$(CLOSED_BUILD)XRDIRS += ../closed
XRPRUNE = pkg prototypes xmod
XRINCDIRS = uts/common head ucbhead
$(CLOSED_BUILD)XRINCDIRS = uts/common ../closed/uts/common head ucbhead

cscope.out tags: FRC
	$(XREF) -f -x $@

FRC:

# EXPORT DELETE START

XMOD_DELETE_FILES:sh = cat xmod/xmod_files

EXPORT_SRC:
	@cd $(CLOSED)/cmd/cmd-inet/usr.lib/in.iked;  pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/cmd/cmd-inet/usr.lib/ike-certutils;  pwd; \
	    $(MAKE) EXPORT_SRC
	@cd cmd/cmd-inet/usr.sbin; pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/cmd/cmd-crypto/etc; pwd; $(MAKE) EXPORT_SRC
	@cd cmd/crypt;	  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/gss/gssd;         pwd; $(MAKE) EXPORT_SRC
	@cd cmd/krb5/kadmin;  pwd; $(MAKE) EXPORT_SRC
	@cd cmd/sendmail/src; pwd; $(MAKE) EXPORT_SRC
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
	@cd lib/libgss;   pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/lib/libike;   pwd; $(MAKE) EXPORT_SRC
	@cd lib/libnsl;	  pwd; $(MAKE) EXPORT_SRC
	@cd lib/pkcs11/pkcs11_softtoken/common;  pwd; $(MAKE) EXPORT_SRC
	@cd lib/libsldap; pwd; $(MAKE) EXPORT_SRC
	@cd lib/libsasl; pwd; $(MAKE) EXPORT_SRC
	@cd lib/sasl_plugins; pwd; $(MAKE) EXPORT_SRC
	@cd lib/pam_modules/krb5;   pwd; $(MAKE) EXPORT_SRC
	@cd psm/stand/boot; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/crypto/io; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/des; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/rpc; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/sys; pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/include;		pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi;			pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/mechs/dummy;	pwd; $(MAKE) EXPORT_SRC
	@cd uts/common/gssapi/mechs/krb5;	pwd; $(MAKE) EXPORT_SRC
	@cd uts/common; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sparc; pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/uts/sun4u/forthdebug; pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/uts/sun4v/forthdebug; pwd; $(MAKE) EXPORT_SRC
	@cd uts/intel; pwd; $(MAKE) EXPORT_SRC
	@cd uts/sun4u; pwd; $(MAKE) EXPORT_SRC
	@cd $(CLOSED)/uts/sun4v/io/ncp;	pwd;	$(MAKE) EXPORT_SRC
	@cd $(CLOSED)/uts/sun4v/io/n2cp; pwd;	$(MAKE) EXPORT_SRC
	@cd pkg; pwd;	$(MAKE) EXPORT_SRC
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
	@cd $(CLOSED)/cmd/cmd-crypto/etc;  pwd; $(MAKE) CRYPT_SRC
	@cd $(CLOSED)/cmd/cmd-inet/usr.lib/in.iked;  pwd; $(MAKE) CRYPT_SRC
	@cd $(CLOSED)/cmd/cmd-inet/usr.lib/ike-certutils;  pwd; \
	    $(MAKE) CRYPT_SRC
	@cd lib/crypt_modules/bsdbf; pwd ; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_dummy;   pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_dh/backend; pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_krb5; pwd; $(MAKE) CRYPT_SRC
	@cd lib/gss_mechs/mech_spnego; pwd; $(MAKE) CRYPT_SRC
	@cd $(CLOSED)/lib/libike;   pwd; $(MAKE) CRYPT_SRC
	@cd lib/libnsl;	 pwd; $(MAKE) CRYPT_SRC
	@cd lib/libsasl;	 pwd; $(MAKE) CRYPT_SRC
	@cd lib/sasl_plugins; pwd; $(MAKE) CRYPT_SRC
	@cd lib/pam_modules/krb5;   pwd; $(MAKE) CRYPT_SRC
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
	@if $($(MACH)_CC) -_versions >/dev/null 2>/dev/null; then \
		$(ECHO) 32-bit compiler;			\
		$(ECHO) $($(MACH)_CC);				\
		$($(MACH)_CC) -_versions 2>&1 |			\
		    $(EGREP) '^(cw|cc|gcc|primary|shadow)';	\
	else							\
		__COMPILER=`$($(MACH)_CC) -_compiler 2>/dev/null || $(TRUE)`;\
		if [ -z "$$__COMPILER" ]; then			\
			$(ECHO) No 32-bit compiler found;	\
			exit 1;					\
		else						\
			$(ECHO) 32-bit compiler;		\
			$(ECHO) $($(MACH)_CC);			\
			$(ECHO) $$__COMPILER;			\
			$($(MACH)_CC) -V 2>&1 | head -1;	\
		fi;						\
	fi

cc64-version:
	@if $($(MACH64)_CC) -_versions >/dev/null 2>/dev/null; then \
		$(ECHO) 64-bit compiler;			\
		$(ECHO) $($(MACH64)_CC);			\
		$($(MACH64)_CC) -_versions 2>&1 |		\
		    $(EGREP) '^(cw|cc|gcc|primary|shadow)';	\
	else							\
		__COMPILER=`$($(MACH64)_CC) -_compiler 2>/dev/null || $(TRUE)`;\
		if [ -z "$$__COMPILER" ]; then			\
			$(ECHO) No 64-bit compiler found;	\
			exit 1;					\
		else						\
			$(ECHO) 64-bit compiler;		\
			$(ECHO) $($(MACH64)_CC);		\
			$(ECHO) $$__COMPILER;			\
			$($(MACH64)_CC) -V 2>&1 | head -1;	\
		fi;						\
	fi

java-version:
	@if [ -x "$(JAVAC)" ]; then			\
		$(ECHO) $(JAVAC);			\
		$(JAVA_ROOT)/bin/java -fullversion 2>&1 | head -1;	\
	else						\
		$(ECHO) No Java compiler found;		\
		exit 1;					\
	fi
