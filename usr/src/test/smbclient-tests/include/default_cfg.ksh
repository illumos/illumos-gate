#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

# testdir base
export TESTDS=smbclnt
export TBASEDIR=/var/tmp/$TESTDS
export TMNT=$TBASEDIR/mnt
export TMNT2=$TBASEDIR/mnt2
export TDIR=$TBASEDIR/test

# Users for SMB client authentication testing
# Share names (public, a_share, b_share) are hard-coded in the tests.
export AUSER=smbusera
export AUSERUID=20100
export APASS=A_nex_123
export BUSER=smbuserb
export BUSERUID=20101
export BPASS=B_nex_123
export TUSER=smbuserc
export TUSERUID=20102
export TPASS=C_nex_123

# Should replace this in the few tests that use $TUSER1
export TUSER1=$BUSER

# User groups
export SMBGRP=smbgrp
export SMBGRPGID=2000
export SMBGRP1=smbgrp1
export SMBGRP1GID=2001

# Share group name
export SHAREGRP=smbclient

# expect tools
export EXPECT=${EXPECT:-"/usr/bin/expect"}

# utility for set password for cifs user on the server side
export PASSWDEXP=${PASSWDEXP:-"${STF_SUITE}/bin/passwd.exp"}

# utility for create the keychain for the cifs user
export SMBUTILEXP=${STF_SUITE}/bin/smbutil.exp

# utility to truncate the file
export FILETRUNC=${STF_SUITE}/bin/file_trunc

# large data file (read-only) used for copy tests, etc.
export REFFILE=/usr/lib/libc.so.1

# avoid testruner timeouts (set by smbclienttest -f)
# export STC_QUICK=1
