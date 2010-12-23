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
BEGIN {
	require 5.006;
}

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME		=> 'Devel::DProf',
	DISTNAME	=> 'DProf',
	VERSION_FROM	=> 'DProf.pm',
	clean		=> { 'FILES' => 'tmon.out t/tmon.out t/err'},
	XSPROTOARG	=> '-noprototypes',
	DEFINE		=> '-DPERLDBf_NONAME=0x40 -DPERLDBf_GOTO=0x80 '
			  .'-DG_NODEBUG=32 -DPL_NEEDED',
	dist		=> {
			     COMPRESS => 'gzip -9f',
			     SUFFIX => 'gz',
			     DIST_DEFAULT => 'all tardist',
			   },
	MAN3PODS	=> {},
);
