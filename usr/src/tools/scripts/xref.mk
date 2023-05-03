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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This Makefile is used exclusively by `xref' to generate and maintain
# cross-reference databases (right now: cscope, ctags, and etags).
#
# By default, the cross-reference is built for all files underneath the
# currrent working directory that match the criteria specified in the
# xref.files rule below, and any files that would also be hauled over as
# part of a `bringover' of the working directory (though this can be
# turned off via the -f flag to `xref').
#
# However, this behavior can be customized in each directory of the build
# tree through the following Makefile macros, if necessary:
#
#   XRDIRS:	The list of directories to include; defaults to `.'.
#		The more interesting directories should be listed earlier.
#   XRPRUNE:	The list of directories to prune out.
#   XRADD:	The list of additional filename globs to include.
#   XRDEL:	The list of additional filename globs to exclude.
#   XRINCDIRS:	The list of additional include paths, in "foo bar" format.
#   XRINCS:	The list of additional include paths, in "-Ifoo -Ibar" format.
#
# Note that XRINCDIRS and XRINCS are for specifying header paths that are
# not already included in CPPFLAGS and HDRDIR.
#
# These macros are assumed to be set in a file named `Makefile', but this
# too can be overridden via the -m option to `xref'.
#
# This Makefile should *never* be included by other Makefiles.
#

XRMAKEFILE=Makefile
include $(SRC)/Makefile.master

#
# Default values for the cross-reference tools; these can be overridden
# either in the environment or in XRMAKEFILE.  To use regular cscope, set
# CSCOPE to cscope and CSFLAGS to -b.
#
CSCOPE	= $(BUILD_TOOLS)/onbld/bin/$(MACH)/cscope-fast
CSFLAGS	= -bq
CTAGS	= /usr/bin/ctags
CTFLAGS	= -wt

# etags was historically part of the Sun compiler distribution and is now
# distributed in various ways for illumos, we do a path search lacking better
# options.
ETAGS	= etags
ETFLAGS	=

FLGFLP	= $(BUILD_TOOLS)/onbld/bin/flg.flp

XRDIRS	= .
XRINCS	= $(XRINCDIRS:%=-I%) $(HDRDIR:%=-I%) $(CPPFLAGS)

include $(XRMAKEFILE)

XRADDLIST	= $(XRADD) *.[CcdSshlxy] Makefile* *.cc *.xml \
		  *.dtd.* *.ndl
XRDELLIST	= $(XRDEL)
XRPRUNELIST	= $(XRPRUNE) .hg .git
XRFINDADD	= $(XRADDLIST:%=-o -name '%')
XRFINDDEL	= $(XRDELLIST:%=-a ! -name '%')
XRFINDPRUNE	= $(XRPRUNELIST:%=-o -name '%')
XRSEDPRUNE	= $(XRPRUNELIST:%=/\/%\//d; /^%\//d;)

.KEEP_STATE:
.PRECIOUS: cscope.out cscope.in.out cscope.po.out tags TAGS

#
# Build the list of files to be included in the cross-reference database.
#
# Please note that:
#
#	* Any additional FLG-related source files are in xref.flg.
#
#	* We use relative pathnames for the file list; this makes it easier
#	  to share the resulting cross-reference across machines.  We also
#	  strip the leading './' off of pathnames (if necessary) so that we
#	  don't trip up vi (since it thinks foo.c and ./foo.c are different
#	  files).
#
#	* We strip out any duplicate file names, being careful not to
#	  disturb the order of the file list.
#
#	* We put all the Makefiles at the end of the file list, since they're
#	  not really source files and thus can cause problems.
#
#	* We otherwise do not sort the file list, since we assume that if
#	  the order matters, then XRDIRS would've been set so that the more
#	  important directories are first.
#
xref.files:
	$(TOUCH) xref.flg
	$(FIND) $(XRDIRS) `$(CAT) xref.flg`			\
	    -type d \( -name SCCS $(XRFINDPRUNE) \) -prune -o	\
	    -type f \( \( -name '' $(XRFINDADD) \) $(XRFINDDEL) \) -print |\
	    $(PERL) -ne 's:^\./::; next if ($$seen{$$_}++); print' > xref.tmp
	> xref.files
	-$(GREP) -v Makefile xref.tmp >> xref.files
	-$(GREP) Makefile xref.tmp >> xref.files
	$(RM) xref.tmp

#
# Use the .flg files to assemble a list of other source files that are
# important for building the sources in XRDIRS.  So that the list can be
# fed to the $(FIND) in xref.files, we tell $(FLGFLP) to generate relative
# pathnames.  We filter out any files that are along paths that are being
# pruned.
#
xref.flg:
	> xref.tmp
	for dir in $(XRDIRS); do					\
		$(FLGFLP) -r $$dir >> xref.tmp;				\
	done
	$(SED) '$(XRSEDPRUNE)' < xref.tmp | $(SORT) -u > xref.flg
	$(RM) xref.tmp

#
# Note that we don't remove the old cscope.out since cscope is smart enough
# to rebuild only what has changed.  It can become confused, however, if files
# are renamed or removed, so it may be necessary to do an `xref -c' if
# a lot of reorganization has occured.
#
xref.cscope: xref.files
	-$(ECHO) $(XRINCS) | $(XARGS) -n1 | $(GREP) '^-I' |		\
	    $(CAT) - xref.files > cscope.files
	$(CSCOPE) $(CSFLAGS)

xref.cscope.clobber: xref.clean
	-$(RM) cscope.out cscope.in.out cscope.po.out cscope.files

#
# Create tags databases, similar to above.
#
# Since assembler files contain C fragments for lint, the lint fragments will
# allow tags to "work" on assembler.  Please note that:
#
#	* We order the tags file such that source files that tags seems to
#	  get along with best are earlier in the list, and so that structure
#	  definitions are ordered before their uses.
#
#	* We *don't* sort the file list within a given suffix, since we
#	  assume that if someone cared about ordering, they would've already
#	  set XRDIRS so that the more important directories are first.
#
#	* We include "/dev/null" in the xref.ctags rule to prevent ctags
#	  from barfing if "xref.tfiles" ends up empty (alas, ctags is
#	  too lame to read its file list from stdin like etags does).
#

xref.ctags: xref.tfiles
	$(CTAGS) $(CTFLAGS) /dev/null `$(CAT) xref.tfiles`

xref.ctags.clobber: xref.clean
	-$(RM) tags

xref.etags: xref.tfiles
	$(CAT) xref.tfiles | $(ETAGS) $(ETFLAGS) -

xref.etags.check:
	@$(CAT) /dev/null | $(ETAGS) -

xref.etags.clobber: xref.clean
	-$(RM) TAGS

xref.tfiles: xref.files
	> xref.tfiles
	-for suffix in h c C cc l y s; do				\
		$(GREP) "\.$${suffix}$$" xref.files >> xref.tfiles;	\
	done

#
# Note that we put `cscope.files' in clobber rather than clean because
# cscope will whine if it doesn't exist (unless it's passed -d).
#
xref.clean:
	-$(RM) xref.tfiles xref.files xref.tmp xref.flg ncscope.*
