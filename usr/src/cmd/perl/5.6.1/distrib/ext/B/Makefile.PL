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
use File::Spec;

my $e = $Config{'exe_ext'};
my $o = $Config{'obj_ext'};
my $exeout_flag = '-o ';
if ($^O eq 'MSWin32') {
    if ($Config{'cc'} =~ /^cl/i) {
	$exeout_flag = '-Fe';
    }
    elsif ($Config{'cc'} =~ /^bcc/i) {
	$exeout_flag = '-e';
    }
}

WriteMakefile(
    NAME	=> "B",
    VERSION	=> "a5",
    PL_FILES	=> { 'defsubs_h.PL' => 'defsubs.h' },
    MAN3PODS	=> {},
    clean	=> {
	FILES		=> "perl$e *$o B.c defsubs.h *~"
    }
);   

package MY;

sub post_constants {
    "\nLIBS = $Config::Config{libs}\n"
}    

sub upupfile {
    File::Spec->catfile(File::Spec->updir,
			File::Spec->updir, $_[0]);
}

sub MY::postamble {
    my $op_h   = upupfile('op.h');
    my $cop_h  = upupfile('cop.h');
    my $noecho = shift->{NOECHO};
"
B\$(OBJ_EXT) : defsubs.h              

defsubs.h :: $op_h $cop_h                     
	\$(PERL) -I\$(INST_ARCHLIB) -I\$(INST_LIB) -I\$(PERL_ARCHLIB) -I\$(PERL_LIB) defsubs_h.PL defsubs.h
" 
}
