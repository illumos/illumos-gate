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

WriteMakefile(
    NAME => 'DynaLoader',
    LINKTYPE	=> 'static',
    DEFINE	=> '-DPERL_CORE -DLIBC="$(LIBC)"',
    MAN3PODS 	=> {}, 	# Pods will be built by installman.
    SKIP	=> [qw(dynamic dynamic_lib dynamic_bs)],
    XSPROTOARG => '-noprototypes', 		# XXX remove later?
    VERSION_FROM => 'DynaLoader_pm.PL',
    PL_FILES	=> {'DynaLoader_pm.PL'=>'DynaLoader.pm',
		    'XSLoader_pm.PL'=>'XSLoader.pm'},
    PM		=> {'DynaLoader.pm' => '$(INST_LIBDIR)/DynaLoader.pm',
		    'XSLoader.pm' => '$(INST_LIBDIR)/XSLoader.pm'},
    depend      => {'DynaLoader.o' => 'dlutils.c'},
    clean	=> {FILES => 'DynaLoader.c DynaLoader.xs DynaLoader.pm ' .
			     'XSLoader.pm'},
);

sub MY::postamble {
	'
DynaLoader.xs: $(DLSRC)
	$(RM_F) $@
	$(CP) $? $@

# Perform very simple tests just to check for major gaffs.
# We can\'t do much more for platforms we are not executing on.
test-xs:
	for i in dl_*xs; \
	    do $(PERL) -I$(PERL_ARCHLIB) -I$(PERL_LIB) $(XSUBPP) $(XSUBPPARGS) $$i > /dev/null; \
	done
';
}

