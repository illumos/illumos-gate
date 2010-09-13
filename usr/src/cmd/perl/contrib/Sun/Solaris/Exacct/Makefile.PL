#
# Copyright (c) 2002, 2008, Oracle and/or its affiliates. All rights reserved.
#

#
# Makefile.PL for ::Exacct
#

#
# Linker flags note:
# The various .so files that comprise the ::Exacct module need to be able to
# cross-call each other, and therefore to prevent runtime linker errors it is
# necessary to establish linker dependencies between the various .so files.
#
# This causes several problems.  The first of these is that perl .so files are
# built in one directory (under ../blib in this case) and installed into
# another, so it is necessary to record the dependency using a path relative to
# the dependent. This can be done with the $ORIGIN linker mechanism.

# The second problem is that it is necessary to specify the name of the
# dependee at link edit time in a manner that doesn't result in the build-time
# path of the dependee being hard coded in to the dependent, as this would
# stop ld.so.1 performing its normal search process for the files.  This can't
# be done with the normal '--L/my/lib/path -lmylib' mechanism, because the XSUB
# .so files aren't prefixed with 'lib'.  To do this the -h linker flag is used
# to explicitly set the SONAME in the dependee.  This is then used as the name
# of the dependent in the dependee rather than the full path by which it was
# found at link edit time.
#
# For more details, refer to the Linker and Libraries Guide.
#

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

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
# Force the parent directory to be built first, because the sub-modules all
# have a linker dependency against Exacct.so.
#
sub top_targets
{
	my $self = shift(@_);
	my $txt = $self->SUPER::top_targets(@_);
	$txt =~ s/pm_to_blib subdirs/pm_to_blib \$(LINKTYPE) .WAIT subdirs/;
	return($txt);
}

#
# Make 'install' wait for 'all' to complete.
#
sub install
{
	my $self = shift(@_);
	my $txt = $self->SUPER::install(@_);
	$txt =~ s/ all / all .WAIT /g;
	return($txt);
}

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
	# the dependency between Exacct.c (generated from Exacct.xs by xsubpp)
	# and the ExacctDefs.xi file (generated from sys/exacct.h by
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

Exacct.c:	ExacctDefs.xi

ExacctDefs.xi:	extract_defines $(EXACCT_H)
	$(PERL) extract_defines Exacct $@ $(EXACCT_H)
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
	# the dependency between Exacct.c (generated from Exacct.xs by xsubpp)
	# and the ExacctDefs.xi file (generated from /usr/include/sys/exacct.h
	# by extract_defines).  This ensures that the constant values exported
	# by the perl module stay up-to date with the corresponding #defines.
	#
	*postamble = sub {
		return <<'EOF';
EXACCT_H = /usr/include/sys/exacct.h

Exacct.c:	ExacctDefs.xi

ExacctDefs.xi:	extract_defines $(EXACCT_H)
	$(PERL) extract_defines Exacct $@ $(EXACCT_H)
EOF
	};

	# Install the POD documentation for non-ON builds.
	my $man3pfx = '$(INST_MAN3DIR)/Sun::Solaris::Exacct';
	@main::man3pods = (
	    MAN3PODS => { 'pod/Exacct.pod' => $man3pfx . '.$(MAN3EXT)' }
	);
}

#
# Having set everything up, write the Makefile.
#
package main;

WriteMakefile(
    NAME         => 'Sun::Solaris::Exacct',
    VERSION_FROM => 'Exacct.pm',
    DIR          => [ qw(Catalog File Object) ],
    H            => [ 'exacct_common.xh' ],
    LIBS         => [ '-lexacct' ],
    @defines,
    @man3pods,
    dynamic_lib  => { OTHERLDFLAGS => '-h $(DLBASE).$(DLEXT)' },
    realclean    => { FILES => 'ExacctDefs.xi' },
);
