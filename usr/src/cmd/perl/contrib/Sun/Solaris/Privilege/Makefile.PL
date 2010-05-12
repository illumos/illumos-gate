#
# Copyright (c) 2004, 2008, Oracle and/or its affiliates. All rights reserved.
#

#
# Makefile.PL for ::Privilege
#

require 5.8.4;
use strict;
use warnings;
use ExtUtils::MakeMaker;

# #defines.
my @defines = ( DEFINE => exists($ENV{RELEASE_BUILD}) ? '-DNDEBUG' : '' );

# List of POD pages to install.
my @man3pods = ( MAN3PODS => {} );

#
# If not building as part of ON.
#
if (! exists($ENV{ENVCPPFLAGS1})) {

	#
	# Suppress the setting of LD_RUN_PATH.  The ON build environment
	# contains a modified MakeMaker that does this automatically, so we
	# only need to do this if we are building outside of ON.
	#
	package MY;
	no warnings qw(once);

	# Override const_loadlibs to remove LD_RUN_PATH cruft.
	*const_loadlibs = sub
	{
		my $self = shift(@_);
		delete($self->{LD_RUN_PATH});
		return($self->SUPER::const_loadlibs(@_));
	};

	# Override dynamic_lib to get rid of LD_RUN_PATH cruft.
	*dynamic_lib = sub
	{
		my $self = shift(@_);
		my $txt = $self->SUPER::dynamic_lib(@_);
		$txt =~ s/LD_RUN_PATH=\S*\s*//;
		return($txt);
	};

	# Turn off debugging.
	@defines = ();

	#
	# Install the POD documentation for non-ON builds.
	#
	my $man3pfx = '$(INST_MAN3DIR)/Sun::Solaris::Privilege';
	@man3pods = (
	    MAN3PODS => { 'pod/Privilege.pod' => $man3pfx . '.$(MAN3EXT)' }
	);
}

WriteMakefile(
    NAME         => 'Sun::Solaris::Privilege',
    VERSION_FROM => 'Privilege.pm',
    @defines,
    @man3pods,
);
