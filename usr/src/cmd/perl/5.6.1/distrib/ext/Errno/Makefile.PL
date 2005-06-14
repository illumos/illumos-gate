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

@VMS = ($^O eq 'VMS') ? (MAN3PODS => {}) : ();

WriteMakefile(
    NAME	 => 'Errno',
    VERSION_FROM => 'Errno_pm.PL',
    MAN3PODS     => {}, 	# Pods will be built by installman.
    PL_FILES	 => {'Errno_pm.PL'=>'Errno.pm'},
    PM		 => {'Errno.pm' => '$(INST_LIBDIR)/Errno.pm'},
    'clean'	 => {FILES => 'Errno.pm'},
    'dist'	 => {
	COMPRESS => 'gzip -9f',
	SUFFIX   => '.gz', 
	DIST_DEFAULT => 'd/Errno.pm tardist',
    },
    @VMS,
);

sub MY::postamble {
    my $TARG = MM->catfile('d','Errno.pm');
qq!$TARG : Makefile
	echo '#This is a dummy file so CPAN will find a VERSION' > $TARG
	echo 'package Errno;' >> $TARG
	echo '\$\$VERSION = "\$(VERSION)";' >>$TARG
	echo '#This is to make sure require will return an error' >>$TARG
	echo '0;' >>$TARG

!
}
