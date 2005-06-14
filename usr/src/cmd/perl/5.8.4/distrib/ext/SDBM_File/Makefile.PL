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
use ExtUtils::MakeMaker;
use Config;

# The existence of the ./sdbm/Makefile.PL file causes MakeMaker
# to automatically include Makefile code for the targets
#	config, all, clean, realclean and sdbm/Makefile
# which perform the corresponding actions in the subdirectory.

$define = ($^O eq 'MSWin32') ? '-DMSDOS' : '';
if ($^O eq 'MSWin32') { $myextlib = 'sdbm\\libsdbm$(LIB_EXT)'; }
else                  { $myextlib = 'sdbm/libsdbm$(LIB_EXT)';  }

WriteMakefile(
              NAME	=> 'SDBM_File',
              MYEXTLIB => $myextlib,
              MAN3PODS 	=> {}, 	# Pods will be built by installman.
              XSPROTOARG => '-noprototypes', 		# XXX remove later?
              VERSION_FROM => 'SDBM_File.pm',
              DEFINE => $define,
	      PERL_MALLOC_OK => 1,
             );

sub MY::postamble {
  if ($^O =~ /MSWin32/ && Win32::IsWin95()) {
	if ($Config{'make'} =~ /dmake/i) {
	    # dmake-specific
	    return <<'EOT';
$(MYEXTLIB): sdbm/Makefile
@[
	cd sdbm
	$(MAKE) all
	cd ..
]
EOT
	} elsif ($Config{'make'} =~ /nmake/i) {
	    #
	    return <<'EOT';
$(MYEXTLIB): sdbm/Makefile
	cd sdbm
	$(MAKE) all
	cd ..
EOT
	} 
} elsif ($^O ne 'VMS') {
    '
$(MYEXTLIB): sdbm/Makefile
	cd sdbm && $(MAKE) all
';
  }
  else {
    '   
$(MYEXTLIB) : [.sdbm]descrip.mms
	set def [.sdbm]
    $(MMS) all
    set def [-]
';  
  }
}
