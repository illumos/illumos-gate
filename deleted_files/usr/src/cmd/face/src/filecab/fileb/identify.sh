#!/sbin/sh
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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
#
# This file contains a script in a simple language to identify terminals
# automatically.
#
# Note that special characters in "case" strings must be backslashed twice,
# since first the escape character handler processes them , then regcmp(3X).
# For more info on how to modify this file, see "Termtest: A Tool for the
# Automatic Identification of Terminals" by M. P. Lindner
#

# ANSI and ANSI-like terminals
query \E[c
case \E\\[?8;7;[2-5]*c
	print TERM=5620
	exit
case \E\\[?8;8;[0-9]*c
        # AT&T 630 terminal
        print TERM=att630
        query \E[?10n
        case \E\\[?24;.*R
                print TERM=$TERM-24
        end
        exit
case \E\\[?[78];[450];[0-9]*c
	# AT&T 600 series terminal
	query \E[c
	case \E\\[?7;5;.*
		print TERM=att605
		break
	case \E\\[?7;4;.*
		print TERM=att610
		break
	case \E\\[?8;0;.*
		print TERM=att620
		break
	case \E\\[?8;4;.*
		print TERM=att615
		break
	end
	query \E[>0c
	case \E\\[>1;.*c
		print TERM=$TERM-103k
	end
	query \E[s
	case \E\\[[0-9]{10}2.*
		print COLUMNS=132
	end
	exit
case \E\\[?;[0-9]*;30;[0-9]*c
	print TERM=gs5430
	exit
# AT&T 4400 series terminals
case \E\\[?1;2;([0-9][0-9])$0;[0-9]*c
	print TERM=att44$0
	exit
case \E\\[?6c
	print TERM=510a
	exit
case \E\\[?;[0-9]*;5101;[0-9]*c\r
	print TERM=gs510A
	exit
case \E\\[?;[0-9]*;510;[0-9]*c
	print TERM=gs510D
	exit
case \E\\[?;[0-9]*;251;[0-9]*c
	print TERM=gs5425
	exit
# 6300 with AT&T emots color terminal emulator
case \E\\[?[0-9]*;[0-9]*;630[12];[0-9]*c
	print TERM=emots
	exit
case \E\\[?8c
	print TERM=tvi970
	exit
case \E\\[?1;[0-9]*c
	print TERM=vt100
	exit
case \E\\[=1;[12]c
	print TERM=avt
	exit
end
