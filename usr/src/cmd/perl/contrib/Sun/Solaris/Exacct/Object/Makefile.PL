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
# Makefile.PL for ::Exacct::Object
#

# See ../Makefile.PL for an explanation of the linker flag manipulations.

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

#
# Some later versions of ExtUtils::MakeMaker are broken,
# and complain about function redefinitions in the child Makefile.PLs.
# Stop the warnings.
#
no warnings qw(redefine);

our (@defines, @man3pods);

#
# MakeMaker overrides.
#
package MY;
no warnings qw(once);

#
# Overrides that are common to both the ON and non-ON build environments.
#

#
# Suppress the setting of LD_RUN_PATH, as it isn't necessary.
#

sub const_loadlibs
{
	my $self = shift(@_);
	delete($self->{LD_RUN_PATH});
	return($self->SUPER::const_loadlibs(@_));
}

sub dynamic_lib
{
	my $self = shift(@_);
	my $txt = $self->SUPER::dynamic_lib(@_);
	$txt =~ s/LD_RUN_PATH=\S*\s*//;
	return($txt);
}

#
# ON-specific overrides.
#
if (exists($ENV{CODEMGR_WS}) && exists($ENV{ENVCPPFLAGS1})) {
	#
	# Override postamble and replace it with one that explicitly records
	# the dependency between Object.c (generated from Object.xs by xsubpp)
	# and the ObjectDefs.xi file (generated from sys/exacct.h by
	# extract_defines).  Note we have to mimic the -I processing done by cc
	# to find the correct version of the file, as we want the copy from the
	# proto area rather than /usr/include.  This ensures that the constant
	# values exported by the perl module stay up-to date with the
	# corresponding #defines.
	#
	*postamble = sub {
		return <<'EOF';
EXACCT_H:sh= \
	for dir in $ENVCPPFLAGS1 $ENVCPPFLAGS2 $ENVCPPFLAGS3 $ENVCPPFLAGS4 \
	    /usr/include; do \
		dir=`expr $dir : '^-I\(.*\)$' \| $dir`; \
		file="$dir/sys/exacct.h"; \
		test -f $file && echo $file && break; \
	done;

Object.c:	ObjectDefs.xi

ObjectDefs.xi:	../extract_defines $(EXACCT_H)
	$(PERL) ../extract_defines Object $@ $(EXACCT_H)
EOF
	};

	# Enable/disable debugging as required.
	@main::defines = ( DEFINE => '-DEXACCT_DEBUG' )
	    if (! exists($ENV{RELEASE_BUILD}));

	# Don't install POD pages for ON.
	@main::man3pods = ( MAN3PODS => {} );

#
# Non-ON overrides.
#
} else {
	#
	# Override postamble and replace it with one that explicitly records
	# the dependency between Object.c (generated from Object.xs by xsubpp)
	# and the ObjectDefs.xi file (generated from /usr/include/sys/exacct.h
	# by # extract_defines).  This ensures # that the constant values
	# exported by the perl module stay up-to date with the corresponding
	# #defines.
	#
	*postamble = sub {
		return <<'EOF';
EXACCT_H = /usr/include/sys/exacct.h

Object.c:	ObjectDefs.xi

ObjectDefs.xi:	../extract_defines $(EXACCT_H)
	$(PERL) ../extract_defines Object $@ $(EXACCT_H)
EOF
	};

	# Install the POD documentation for non-ON builds.
	my $man3pfx = '$(INST_MAN3DIR)/Sun::Solaris::Exacct';
	@main::man3pods = ( MAN3PODS => {
	    '../pod/Object.pod' => $man3pfx . '::Object.$(MAN3EXT)',
	    '../pod/Item.pod' => $man3pfx . '::Object::Item.$(MAN3EXT)',
	    '../pod/Group.pod' => $man3pfx . '::Object::Group.$(MAN3EXT)'
	});
}

#
# Having set everything up, write the Makefile.
#
package main;

WriteMakefile(
    NAME         => 'Sun::Solaris::Exacct::Object',
    VERSION_FROM => 'Object.pm',
    H            => [ '../exacct_common.xh' ],
    TYPEMAPS     => [ '../typemap' ],
    @defines,
    @man3pods,
    dynamic_lib  => { OTHERLDFLAGS =>
        '-h $(DLBASE).$(DLEXT) ' .
        '-R\$$ORIGIN/.. $(INST_ARCHAUTODIR)/../Exacct.so'
	},
    realclean    => { FILES => 'ObjectDefs.xi' },
);
