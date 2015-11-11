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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#

include		$(SRC)/Makefile.master

FILES=	\
		$(MACH)_cc_map.noexeglobs \
		$(MACH)_gcc_map.noexeglobs

$(BUILD64)FILES += \
		$(MACH64)_cc_map.noexeglobs \
		$(MACH64)_gcc_map.noexeglobs

SYMS1=		syms.1
SYMS2=		syms.2
MAIN1=		main.1
MAIN2=		main.2

TEMPLATE1=	map.noexeglobs.1.template
TEMPLATE2=	map.noexeglobs.2.template

all install:	$(FILES)

lint:

clean:
		$(RM) $(SYMS1) $(SYMS2) $(MAIN1) $(MAIN2)

clobber:	clean
		$(RM) $(FILES)

# A number of dynamic executables have their own definitions of interfaces that
# exist in system libraries.  To prevent name-space pollution it is desirable
# to demote the interfaces within these executable to locals.  However, various
# symbols defined by the compiler drivers crt/values files need to remain
# global in any dynamic object that includes these files.  These symbols
# interpose on symbols in libc, or provide call backs for other system
# libraries.  The various compiler drivers (cc and gcc), and the crt/values
# files that these drivers are configured to include, differ between the
# various compilations environments (platform, 32/64-bit).  Therefore, the
# only means of creating a mapfile to demote symbols is to dynamically generate
# the mapfile for a specific compilation environment.
#
# Here, template mapfiles are used to generate a number of compilation specific
# mapfiles.  These mapfiles are referenced by components of the build through
# the MAPFILE.NGB macro defined in Makefile.master.  These dynamically created
# mapfiles are not delivered into the $ROOT area, and therefore are not
# delivered as packaged components of the OSNet.

$(MACH)_cc_map.noexeglobs :=	LINK =	$(LINK.c)
$(MACH64)_cc_map.noexeglobs :=	LINK =	$(LINK64.c)

$(MACH)_gcc_map.noexeglobs :=	CC =	$(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc
$(MACH)_gcc_map.noexeglobs :=	LINK =	$(LINK.c)
$(MACH64)_gcc_map.noexeglobs :=	CC =	$(ONBLD_TOOLS)/bin/$(MACH)/cw -_gcc
$(MACH64)_gcc_map.noexeglobs :=	LINK =	$(LINK64.c)
 
# This generic target creates two dynamic executables from an empty "main"
# program.  These objects are not executed, but are analyzed to determine the
# global symbols each provides.
#
# The first executable demotes a family of known interfaces to local and allows
# all other symbol definitions to remain global.  This executables provides the
# base for discovering all symbol definitions provided by the various
# compilation environments.  The second executable demotes all symbols to
# locals.  Within both executables, some symbols remain globals (_end, _etext,
# etc.) as the link-editor has special knowledge of these symbols and their
# expected visibility requirements.  By inspecting the deferences between the
# global symbols within the two executables, a mapfile can be generated to
# ensure the symbols defined by the compilation environments files remain
# global.

%map.noexeglobs:main.c $(TEMPLATE1) $(TEMPLATE2)
	$(LINK) -o $(MAIN1) -M$(TEMPLATE1) main.c
	$(ELFDUMP) -s -N.dynsym $(MAIN1) | $(EGREP) "WEAK|GLOB" | \
	    $(GREP) -v UNDEF | $(AWK) '{print $$9 }' | $(SORT) > $(SYMS1)
	$(LINK) -o $(MAIN2) -M$(TEMPLATE2) main.c
	$(ELFDUMP) -s -N.dynsym $(MAIN2) | $(EGREP) "WEAK|GLOB" | \
	    $(GREP) -v UNDEF | $(AWK) '{print $$9 }' | $(SORT) > $(SYMS2)
	$(ECHO) "# GENERATED FILE - DO NOT EDIT"	>  $@
	$(GREP) MAP-HEAD $(TEMPLATE2) | \
	    $(SED) -e "s/	*# MAP-HEAD//"		>> $@
	$(DIFF) $(SYMS1) $(SYMS2) | $(GREP) "^<" | \
	    $(SED) -e "s/^< \(.*\)/        \1;/"	>> $@
	$(GREP) MAP-TAIL $(TEMPLATE2) | \
	    $(SED) -e "s/	*# MAP-TAIL//"		>> $@
	$(RM) $(SYMS1) $(SYMS2) $(MAIN1) $(MAIN2)
