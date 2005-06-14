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
    VERSION_FROM    => "lib/List/Util.pm",
    MAN3PODS        => {},  # Pods will be built by installman.
    NAME            => "List::Util",
    DEFINE          => "-DPERL_EXT",
);

package MY;

# We go through the ListUtil.c trickery to foil platforms
# that have the feature combination of
# (1) static builds
# (2) allowing only one object by the same name in the static library
# (3) the object name matching being case-blind
# This means that we can't have the top-level util.o
# and the extension-level Util.o in the same build.
# One such platform is the POSIX-BC BS2000 EBCDIC mainframe platform.

BEGIN {
    use Config;
    unless (defined $Config{usedl}) {
	eval <<'__EOMM__';
sub xs_c {
    my($self) = shift;
    return '' unless $self->needs_linking();
'
ListUtil.c:	Util.xs
	$(PERL) -I$(PERL_ARCHLIB) -I$(PERL_LIB) $(XSUBPP) $(XSPROTOARG) $(XSUBPPARGS) Util.xs > ListUtil.xsc && $(MV) ListUtil.xsc ListUtil.c
';
}

sub xs_o {
    my($self) = shift;
    return '' unless $self->needs_linking();
'

Util$(OBJ_EXT):	ListUtil.c
	$(CCCMD) $(CCCDLFLAGS) -I$(PERL_INC) $(DEFINE) ListUtil.c
	$(MV) ListUtil$(OBJ_EXT) Util$(OBJ_EXT)
';
}

__EOMM__
    }
}
