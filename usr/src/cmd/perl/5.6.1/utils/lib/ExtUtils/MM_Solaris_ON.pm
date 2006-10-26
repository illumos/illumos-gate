#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# MM_Solaris_ON.pm overrides various parts of MakeMaker so that perl modules
# build correctly as part of Solaris/ON.  The changes are:
#    1.  pasthru() is overriden to pass down values of INC and DEFINES to child
#        Makefile.PLs, otherwise only top-level module Makefile.PLs will be
#        affected by such flags.  This could be construed as a bug in perl,
#        but fixing it causes breakage in commonly used perl modules (e.g. Tk).
#    2.  constants() is overriden to add the incluide paths specified in the
#        ENVCPPFLAGS[1-n] environment variables to the compiler command-line so
#        that the compiler looks in the proto area for include files.
#    3.  ext() is overriden to add the library paths specified in the
#        ENVLDLIBS[1-n] environment variables to the linker command-line so
#        that the linker looks in the proto area for libraries.
#

# Magic needed to plug into Makemaker - see ExtUtils::MM*.pm
package ExtUtils::MM_Solaris_ON;
require Exporter;
Exporter::import(qw(ExtUtils::MakeMaker $Verbose &neatvalue));
unshift(@MM::ISA, qw(ExtUtils::MM_Solaris_ON));

#
# The pasthru() method works out which macros need to be passed to child makes.
# In addition to the default list of values, pass through DEFINE and INC as
# well.  See ExtUtils::MM_Unix for details of the pasthru() method.
#
sub pasthru
{
	my ($self) = shift;
	my (@pasthru);

	foreach (qw(LIB LIBPERL_A LINKTYPE PREFIX OPTIMIZE DEFINE INC)) {
		push(@pasthru, "$_=\"\$($_)\"");
	}
	return ("\nPASTHRU = " . join ("\\\n    ", @pasthru) . "\n");
}

#
# The constants() method works out the compiler flags needed to build a module.
# Override it to take into account the current settings of the ENVCPPFLAGS[1-n]
# environment variables when building as part of Solaris/ON.  See
# ExtUtils::MM_Unix for details of the constants() method.
#
sub constants
{
	my ($self) = @_;

	# Find all the ENVCPPFLAGS[1-n] environment variables
	my (%inc_seen, @newincs, %proto_seen, @protos);

	# Prepopulate @protos with $ENV{ROOT} if it is set
	if (defined ($ENV{ROOT})) {
		push(@protos, $ENV{ROOT});
	}

	foreach my $ip (map({ /^ENVCPPFLAGS\d+$/ ? split(' ', $ENV{$_}) : () }
	    keys(%ENV))) {
		# Ignore everything except '-I' flags
		next unless ($ip =~ s!^-I(.*)$!$1!);

		# Add to newincs if not seen before
		push(@newincs, "-I$ip") unless ($inc_seen{$ip}++);

		#
		# If the path points to somewhere under a proto area,
		# figure out the top of the proto area & save for later
		#
		next unless ($ip =~ s!^(.*/proto/root_[^/]+)/.*$!$1!);
		push(@protos, $ip) unless ($proto_seen{$ip}++);
	}

	# Search INC string, prepending the proto areas to any absolute paths
	foreach (split(' ', $self->{INC})) {
		# Deal with -I flags
		if (my ($p) = $_ =~ /^-I(.*)$/) {
			# Only prepend to absolute paths
			if ($self->file_name_is_absolute($p)) {
				foreach my $pp (@protos) {
					my $ppp = "$pp$p";
					push(@newincs, "-I$ppp")
					    unless ($inc_seen{$ppp}++);
				}
			# Pass relative paths through
			} else {
				push(@newincs, "-I$p") unless ($inc_seen{$p}++);
			}

		# Pass anything else through
		} else {
			push(@newincs, $_);
		}
	}

	# Call the default Unix constants() method (see MM_Unix.pm)
	$self->{INC} = join(' ', @newincs);
	return ($self->ExtUtils::MM_Unix::constants());
}

#
# The ext() method works out the linker flags required to build a module.
# Override it to take into account the current settings of the ENVLDLIBS[1-n]
# environment variables when building as part of Solaris/ON.  Also remove the
# LD_RUN_PATH that is returned by the default implementation, as it is not
# correct when building as part of Solaris/ON.  See ExtUtils::Liblist for
# details of the ext() method.
#
sub ext
{
	my ($self, $libs, $verbose, $need_names) = @_;

	# Find all the ENVLDLIBS[1-n] environment variables
	my (%lib_seen, @lib_prefix, @newlibs, %proto_seen, @protos);
	foreach my $lp (map({ /^ENVLDLIBS\d+$/ ? split(' ', $ENV{$_}) : () }
	    keys(%ENV))) {
		# Ignore everything except '-L' flags
		next unless ($lp =~ s!^-L(.*)$!$1!);

		# Add to lib_prefix if not seen before
		push(@lib_prefix, "-L$lp") unless ($lib_seen{$lp}++);

		#
		# If the path points to somewhere under a proto area,
		# figure out the top of the proto area & save for later
		#
		next unless ($lp =~ s!^(.*/proto/root_[^/]+)/.*$!$1!);
		push(@protos, $lp) unless ($proto_seen{$lp}++);
	}

	# Search libs string, prepending the proto areas to any absolute paths
	%lib_seen = ();
	foreach (split(' ', $libs)) {
		# Deal with -L flags
		if (my ($p) = $_ =~ /^-L(.*)$/) {
			# Only prepend to absolute paths
			if ($self->file_name_is_absolute($p)) {
				foreach my $pp (@protos) {
					my $ppp = "$pp$p";
					push(@newlibs, "-L$ppp")
					    unless ($lib_seen{$ppp}++);
				}
			# Pass relative paths through
			} else {
				push(@newlibs, "-L$p") unless ($lib_seen{$p}++);
			}

		# Pass anything else through
		} else {
			push(@newlibs, $_);
		}
	}
	
	# Call the default Unix ext() method (see Liblist.pm)
	require ExtUtils::Liblist;
	my @retval = $self->ExtUtils::Liblist::Kid::ext(join(' ', @newlibs),
	    $verbose, $need_names);

	#
	# Prepend any missing members of @lib_prefix onto LDLOADLIBS.
	# Do this after calling ext() as ext() will strip out all the -L flags
	# if passed an empty library list.  Note we don't touch EXTRALIBS as
	# it is only used to create the extralibs.ld file, and we don't want
	# the ON environment leaking out into shipped files.
	#
	my $prefix = join(' ', grep({ ! $lib_seen{$_}++ } @lib_prefix));
	$prefix .= ' ';
	$retval[2] = $prefix . $retval[2];

	# By default any directories containing libraries are returned as part
	# LD_RUN_PATH.  When building Solaris/ON, we don't want this behaviour
	# as it results in the proto area being stored in RPATH in the resulting
	# perl module.so files, so we null it out here.
	#
	$retval[3] = '';
	return (@retval);
}
