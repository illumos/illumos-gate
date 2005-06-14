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
use ExtUtils::MakeMaker 5.16 ;
use Config ;

# OS2 is a special case, so check for it now.
my $OS2 = "-DOS2" if $Config{'osname'} eq 'os2' ;

my $LIB = "-ldb" ;
# so is win32
$LIB = "-llibdb" if $^O eq 'MSWin32' ;

WriteMakefile(
	NAME 		=> 'DB_File',
	LIBS 		=> ["-L/usr/local/lib $LIB"],
        MAN3PODS        => {},         # Pods will be built by installman.
	#INC		=> '-I/usr/local/include',
	VERSION_FROM	=> 'DB_File.pm',
	OBJECT		=> 'version$(OBJ_EXT) DB_File$(OBJ_EXT)',
	XSPROTOARG	=> '-noprototypes',
	DEFINE		=> $OS2 || "",
	INC => ($^O eq "MacOS" ? "-i ::::db:include" : "")
	);

sub MY::postamble {
      '
version$(OBJ_EXT):	version.c

' ;
}

