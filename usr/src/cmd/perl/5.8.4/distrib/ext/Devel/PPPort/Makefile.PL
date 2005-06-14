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

unless($ENV{PERL_CORE}) {
    $ENV{PERL_CORE} = 1 if grep { $_ eq 'PERL_CORE=1' } @ARGV;
}
if ($ENV{PERL_CORE}) {
    # Pods will be built by installman.
    @coreopts = ( MAN3PODS => {} );
}
else {
    @coreopts = ();
}

WriteMakefile(
    NAME	=> "Devel::PPPort",
    DISTNAME	=> "Devel-PPPort",
    VERSION_FROM=> 'PPPort.pm',

    PL_FILES	=> { 'ppport_h.PL' => 'ppport.h' },
    'depend'	=> { '$(OBJECT)' => '$(H_FILES)' },
    C		=> [qw(module2.c module3.c)],
    H		=> [qw(ppport.h)],
    OBJECT	=> '$(BASEEXT)$(OBJ_EXT) $(O_FILES)',
    XSPROTOARG	=> '-noprototypes',
    'dist'	=> { COMPRESS=>"gzip", SUFFIX=>"gz" },
    'clean'	=> { FILES => qw($(H_FILES))},
    @coreopts,
);
