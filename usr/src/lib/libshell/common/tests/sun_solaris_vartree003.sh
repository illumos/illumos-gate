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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# variable tree test #003
# Propose of this test is whether ksh93 handles global variable trees
# and function-local variable trees the same way, including "nameref"
# and "unset" handling.
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

# the test cannot use "nounset"
Command=${0##*/}
integer Errors=0

function example_tree
{
cat <<EOF
(
	typeset -A l1=(
		[adobe]=(
			typeset -A l2=(
				[avantgarde]=(
					typeset -A l3=(
						[demi]=(
							typeset -A entries=(
								[182c069a485316b1bc7ae001c04c7835]=(
									typeset -a comments=(
										FONT
										-adobe-avantgarde-demi-r-normal--199-120-1200-1200-p-1130-iso8859-1
										COPYRIGHT
										'Copyright Notice not available'
										RAW_PIXELSIZE
										RAW_POINTSIZE
										--
										section
										diaeresis
										copyright
										ordfeminine
										guillemotleft
									)
									typeset -a filenames=(
										X11Rx/R6.4/xc/programs/Xserver/XpConfig/C/print/models/SPSPARC2/fonts/AvantGarde-Demi.pmf
									)
									md5sum=182c069a485316b1bc7ae001c04c7835
									typeset -a xlfd=(
										-adobe-avantgarde-demi-r-normal--199-120-1200-1200-p-1130-iso8859-1
									)
								)
								[7db15b51965d8fe1f1c55fcb101d7616]=(
									typeset -a comments=(
										FONT
										-adobe-avantgarde-demi-i-normal--199-120-1200-1200-p-1130-iso8859-1
										COPYRIGHT
										'Copyright Notice not available'
										RAW_PIXELSIZE
										RAW_POINTSIZE
										--
										section
										diaeresis
										copyright
										ordfeminine
										guillemotleft
									)
									typeset -a filenames=(
										X11Rx/R6.4/xc/programs/Xserver/XpConfig/C/print/models/SPSPARC2/fonts/AvantGarde-DemiOblique.pmf
									)
									md5sum=7db15b51965d8fe1f1c55fcb101d7616
									typeset -a xlfd=(
										-adobe-avantgarde-demi-i-normal--199-120-1200-1200-p-1130-iso8859-1
									)
								)
								[a37e4a4a5035abf6f294d830fbd9e775]=(
									typeset -a comments=(
										FONT
										-adobe-avantgarde-demi-r-normal--422-120-2540-2540-p-2395-iso8859-1
										COPYRIGHT
										'Copyright (c) 1985, 1987, 1989, 1990, 1991 Adobe Systems Incorporated.  All Rights Reserved.ITC Avant Garde Gothic is a registered trademark of International Typeface Corporation.'
										RAW_PIXELSIZE
										RAW_POINTSIZE
										--
										section
										diaeresis
										copyright
										ordfeminine
										guillemotleft
									)
									typeset -a filenames=(
										fox-gate/XW_NV/open-src/tarballs/xorg-server-1.3.0.0/hw/xprint/config/C/print/models/PSdefault/fonts/AvantGarde-Demi.pmf
									)
									md5sum=a37e4a4a5035abf6f294d830fbd9e775
									typeset -a xlfd=(
										-adobe-avantgarde-demi-r-normal--422-120-2540-2540-p-2395-iso8859-1
									)
								)
								[da3d6d94fcf759b95c7f829ce5619374]=(
									typeset -a comments=(
										FONT
										-adobe-avantgarde-demi-i-normal--422-120-2540-2540-p-2395-iso8859-1
										COPYRIGHT
										'Copyright (c) 1985, 1987, 1989, 1990, 1991 Adobe Systems Incorporated.  All Rights Reserved.ITC Avant Garde Gothic is a registered trademark of International Typeface Corporation.'
										RAW_PIXELSIZE
										RAW_POINTSIZE
										--
										section
										diaeresis
										copyright
										ordfeminine
										guillemotleft
									)
									typeset -a filenames=(
										fox-gate/XW_NV/open-src/tarballs/xorg-server-1.3.0.0/hw/xprint/config/C/print/models/PSdefault/fonts/AvantGarde-DemiOblique.pmf
									)
									md5sum=da3d6d94fcf759b95c7f829ce5619374
									typeset -a xlfd=(
										-adobe-avantgarde-demi-i-normal--422-120-2540-2540-p-2395-iso8859-1
									)
								)
							)
						)
					)
				)
			)
		)
	)
)
EOF
}

function main
{
	set -o errexit
	
	typeset xlfd_tree=()
	typeset -A xlfd_tree.l1
	
	eval "xlfd_tree=$( example_tree )"
	
	typeset i j k l fn

        # filter chain begin
        for i in "${!xlfd_tree.l1[@]}" ; do
              for j in "${!xlfd_tree.l1["$i"].l2[@]}" ; do
        	     for k in "${!xlfd_tree.l1["$i"].l2["$j"].l3[@]}" ; do
        		     nameref vndnode=xlfd_tree.l1["$i"].l2["$j"].l3["$k"]
        		     
        		     for l in "${!vndnode.entries[@]}" ; do
        			     nameref node=vndnode.entries["$l"]
        			     
        			     for fn in "${node.filenames[@]}" ; do
        				     if [[ "${fn}" != ~(E)x-re_gate_XW_NV_MWS ]] ; then
        					     unset "${!node}"
        					     break
        				     fi
        			     done
        		     done
        	     done
              done
	done

	# filter chain end

	return 0
}

main || ((Errors++))

# tests done
exit $((Errors))
