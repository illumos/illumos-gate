#!/bin/ksh -p
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
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

usage()
{
	echo "Usage: $0 -p <prodver> -m <mach> -o <awk_script>"
	exit 1
}

#
# Awk strings
#
# Two VERSION patterns: one for Dewey decimal, one for Dewey plus ",REV=n".
# The first has one '=' character and the second has two or more '=' characters.
#
VERSION1="VERSION=[^=]*$"
VERSION2="VERSION=[^=]*=.*$"
PRODVERS="^SUNW_PRODVERS="
ARCH='ARCH=\"ISA\"'

rev=$(date "+%Y.%m.%d.%H.%M")
unset mach prodver awk_script

while getopts o:p:m: c; do
	case $c in
	o) awk_script=$OPTARG ;;
	m) mach=$OPTARG ;;
	p) prodver=$OPTARG ;;
	\?) usage ;;
	esac
done

[[ -z "$prodver" || -z "$mach" || -z "$awk_script" ]] && usage
[[ -f $awk_script ]] && rm -f $awk_script

#
# Build awk script which will process all the pkginfo.tmpl files.
# The first VERSION pattern is replaced with a leading quotation mark.
#
cat << EOF > $awk_script
/$VERSION1/ {
      sub(/\=[^=]*$/,"=\"$rev\"")
      print
      next
   }
/$VERSION2/ {
      sub(/\=[^=]*$/,"=$rev\"")
      print
      next
   }
/$PRODVERS/ { 
      printf "SUNW_PRODVERS=\"%s\"\n", "$prodver" 
      next
   }
/$ARCH/ {
      printf "ARCH=\"%s\"\n", "$mach"
      next
   }
{ print }
EOF
