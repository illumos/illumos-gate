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

$define = '-DSDBM -DDUFF';
$define .= ' -DWIN32 -DPERL_STATIC_SYMS' if ($^O eq 'MSWin32');

if ($^O eq 'VMS') {  # Old VAXC compiler can't handle Duff's device
    require Config;
    $define =~ s/\s+-DDUFF// if $Config::Config{'vms_cc_type'} eq 'vaxc';
}

WriteMakefile(
    NAME      => 'sdbm', # (doesn't matter what the name is here) oh yes it does
#    LINKTYPE  => 'static',
    DEFINE    => $define,
    INC       => '-I$(PERL_INC)', # force PERL_INC dir ahead of system -I's
    INST_ARCHLIB => '.',
    SKIP      => [qw(dynamic dynamic_lib dlsyms)],
    OBJECT    => '$(O_FILES)',
    clean     => {'FILES' => 'dbu libsdbm.a dbd dba dbe x-dbu *.dir *.pag'},
    H         => [qw(tune.h sdbm.h pair.h $(PERL_INC)/config.h)],
    C         => [qw(sdbm.c pair.c hash.c)]
);

sub MY::constants {
  package MY;
  my $r = shift->SUPER::constants();
  if ($^O eq 'VMS') {
    $r =~ s/^INST_STATIC =.*$/INST_STATIC = libsdbm\$(LIB_EXT)/m
  }
  return $r;
}

sub MY::post_constants {
  package MY;
  if ($^O eq 'VMS') {
    shift->SUPER::post_constants();
  } else {
'
INST_STATIC = libsdbm$(LIB_EXT)
'
  }
}

sub MY::top_targets {
    my $noecho = shift->{NOECHO};
    
    my $r = '
all :: static
	' . $noecho . '$(NOOP)

config ::
	' . $noecho . '$(NOOP)

lint:
	lint -abchx $(LIBSRCS)

';
    $r .= '
# This is a workaround, the problem is that our old GNU make exports
# variables into the environment so $(MYEXTLIB) is set in here to this
# value which can not be built.
sdbm/libsdbm.a:
	' . $noecho . '$(NOOP)
' unless $^O eq 'VMS';

    return $r;
}
