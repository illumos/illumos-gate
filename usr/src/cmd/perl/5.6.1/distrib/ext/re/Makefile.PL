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
use File::Spec;

WriteMakefile(
    NAME		=> 're',
    VERSION_FROM	=> 're.pm',
    MAN3PODS		=> {}, 	# Pods will be built by installman.
    XSPROTOARG		=> '-noprototypes',
    OBJECT		=> 're_exec$(OBJ_EXT) re_comp$(OBJ_EXT) re$(OBJ_EXT)',
    DEFINE		=> '-DPERL_EXT_RE_BUILD -DPERL_EXT_RE_DEBUG',
    clean		=> { FILES => '*$(OBJ_EXT) *.c ../../lib/re.pm' },
);

package MY;

sub upupfile {
    File::Spec->catfile(File::Spec->updir, File::Spec->updir, $_[0]);
}

sub postamble {
    my $regcomp_c = upupfile('regcomp.c');
    my $regexec_c = upupfile('regexec.c');

    <<EOF;
re_comp.c : $regcomp_c
	- \$(RM_F) re_comp.c
	\$(CP) $regcomp_c re_comp.c

re_comp\$(OBJ_EXT) : re_comp.c

re_exec.c : $regexec_c
	- \$(RM_F) re_exec.c
	\$(CP) $regexec_c re_exec.c

re_exec\$(OBJ_EXT) : re_exec.c

EOF
}
