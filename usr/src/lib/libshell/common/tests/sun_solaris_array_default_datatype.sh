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
# This test module checks whether indexed+associative arrays
# set the default datatype correctly if someone uses the "+="
# operator to add a value to an array element which does not
# exist yet.
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

compound bracketstat=(
	integer bopen=0
	integer bclose=0
)

function count_brackets
{
	typeset x="$1"
	typeset c

	integer i
	(( bracketstat.bopen=0 , bracketstat.bclose=0 ))

	for (( i=0 ; i < ${#x} ; i++ )) ; do
	        c="${x:i:1}"
		[[ "$c" == "(" ]] && (( bracketstat.bopen++ ))
		[[ "$c" == ")" ]] && (( bracketstat.bclose++ ))
	done
	
	(( bracketstat.bopen != bracketstat.bclose )) && return 1
	
	return 0
}

# function to add the floating-point value 1.1 to array element "34"
# floating-point datatypes should increment by 1.1, integers by 1
function add_float
{
	nameref arr=$1
	
	arr[34]+=1.1
	
	return 0
}

# function to add a compound variable called "val" to array element arr[34]
function add_compound
{
	nameref arr=$1
	
	arr[34]+=( float val=1.1 )
	
	return 0
}

# We run the tests in multiple cyles:
# First cycle uses a normal compound variable as basis
# Second cycle uses a nameref to a compound variable as basis
# Third cycle uses a nameref to a nameref to a compound variable as basis
for cycle in \
	c1 c2 c3 c4 \
	c2_sub c3_sub c4_sub \
	c2_indexed_array c3_indexed_array c4_indexed_array \
	c2_associative_array c3_associative_array c4_associative_array; do
	case ${cycle} in
		c1)
			compound mycpv
			;;
		c2)
			compound rootcpv
			nameref mycpv=rootcpv
			;;
		c3)
			compound rootcpv
			nameref namereftoroot=rootcpv
			nameref mycpv=namereftoroot
			;;
		c4)
			compound rootcpv
			nameref namereftoroot0=rootcpv
			nameref namereftoroot1=namereftoroot0
			nameref mycpv=namereftoroot1
			;;
		# same as cX but uses a subvariable of rootcpv
		c2_sub)
			compound rootcpv
			compound rootcpv.sub
			nameref mycpv=rootcpv.sub
			;;
		c3_sub)
			compound rootcpv
			compound rootcpv.sub
			nameref namereftoroot=rootcpv.sub
			nameref mycpv=namereftoroot
			;;
		c4_sub)
			compound rootcpv
			compound rootcpv.sub
			nameref namereftoroot0=rootcpv.sub
			nameref namereftoroot1=namereftoroot0
			nameref mycpv=namereftoroot1
			;;
		# same as cX but uses a subvariable of an indexed array
		c2_indexed_array)
			compound -a rootcpv
			nameref mycpv=rootcpv[4]
			;;
		c3_indexed_array)
			compound -a rootcpv
			nameref namereftoroot=rootcpv[4]
			nameref mycpv=namereftoroot
			;;
		c4_indexed_array)
			compound -a rootcpv
			nameref namereftoroot0=rootcpv[4]
			nameref namereftoroot1=namereftoroot0
			nameref mycpv=namereftoroot1
			;;
		# same as cX but uses a subvariable of an indexed array
		c2_associative_array)
			compound -A rootcpv
			nameref mycpv=rootcpv["hello world"]
			;;
		c3_associative_array)
			compound -A rootcpv
			nameref namereftoroot=rootcpv["hello world"]
			nameref mycpv=namereftoroot
			;;
		c4_associative_array)
			compound -A rootcpv
			nameref namereftoroot0=rootcpv["hello world"]
			nameref namereftoroot1=namereftoroot0
			nameref mycpv=namereftoroot1
			;;
		*)
			err_exit "${cycle}: Should not happen."
			;;
	esac


	# Test 001: Test indexed floating-point array
	float -a mycpv.myindexedfloatarray

	add_float mycpv.myindexedfloatarray
	(( mycpv.myindexedfloatarray[34] == 1.1 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 1.1"
	add_float mycpv.myindexedfloatarray
	(( mycpv.myindexedfloatarray[34] == 2.2 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 2.2"
	unset mycpv.myindexedfloatarray[34]
	(( mycpv.myindexedfloatarray[34] == 0.0 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 0.0"

	# 2nd try (we do this to check whether "unset" works properly)
	add_float mycpv.myindexedfloatarray
	(( mycpv.myindexedfloatarray[34] == 1.1 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 1.1"
	add_float mycpv.myindexedfloatarray
	(( mycpv.myindexedfloatarray[34] == 2.2 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 2.2"
	unset mycpv.myindexedfloatarray[34]
	(( mycpv.myindexedfloatarray[34] == 0.0 )) || err_exit "${cycle}: mycpv.myindexedfloatarray[34] == ${mycpv.myindexedfloatarray[34]}, expected 0.0"



	# Test 002: Test associative floating-point array
	float -A mycpv.myassociativefloatarray
	add_float mycpv.myassociativefloatarray
	(( mycpv.myassociativefloatarray[34] == 1.1 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 1.1"
	add_float mycpv.myassociativefloatarray
	(( mycpv.myassociativefloatarray[34] == 2.2 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 2.2"
	unset mycpv.myassociativefloatarray[34]
	(( mycpv.myassociativefloatarray[34] == 0.0 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 0.0"

	# 2nd try (we do this to check whether "unset" works properly)
	add_float mycpv.myassociativefloatarray
	(( mycpv.myassociativefloatarray[34] == 1.1 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 1.1"
	add_float mycpv.myassociativefloatarray
	(( mycpv.myassociativefloatarray[34] == 2.2 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 2.2"
	unset mycpv.myassociativefloatarray[34]
	(( mycpv.myassociativefloatarray[34] == 0.0 )) || err_exit "${cycle}: mycpv.myassociativefloatarray[34] == ${mycpv.myassociativefloatarray[34]}, expected 0.0"



	# Test 003: Test indexed integer array
	integer -a mycpv.myindexedintegerarray

	add_float mycpv.myindexedintegerarray
	(( mycpv.myindexedintegerarray[34] == 1 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 1"
	add_float mycpv.myindexedintegerarray
	(( mycpv.myindexedintegerarray[34] == 2 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 2"
	unset mycpv.myindexedintegerarray[34]
	(( mycpv.myindexedintegerarray[34] == 0 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 0"

	# 2nd try (we do this to check whether "unset" works properly)
	add_float mycpv.myindexedintegerarray
	(( mycpv.myindexedintegerarray[34] == 1 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 1"
	add_float mycpv.myindexedintegerarray
	(( mycpv.myindexedintegerarray[34] == 2 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 2"
	unset mycpv.myindexedintegerarray[34]
	(( mycpv.myindexedintegerarray[34] == 0 )) || err_exit "${cycle}: mycpv.myindexedintegerarray[34] == ${mycpv.myindexedintegerarray[34]}, expected 0"



	# Test 004: Test associative integer array
	integer -A mycpv.myassociativeintegerarray

	add_float mycpv.myassociativeintegerarray
	(( mycpv.myassociativeintegerarray[34] == 1 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 1"
	add_float mycpv.myassociativeintegerarray
	(( mycpv.myassociativeintegerarray[34] == 2 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 2"
	unset mycpv.myassociativeintegerarray[34]
	(( mycpv.myassociativeintegerarray[34] == 0 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 0"

	# 2nd try (we do this to check whether "unset" works properly)
	add_float mycpv.myassociativeintegerarray
	(( mycpv.myassociativeintegerarray[34] == 1 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 1"
	add_float mycpv.myassociativeintegerarray
	(( mycpv.myassociativeintegerarray[34] == 2 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 2"
	unset mycpv.myassociativeintegerarray[34]
	(( mycpv.myassociativeintegerarray[34] == 0 )) || err_exit "${cycle}: mycpv.myassociativeintegerarray[34] == ${mycpv.myassociativeintegerarray[34]}, expected 0"



	# Test 005: Tested indexed compound variable array
	compound -a mycpv.myindexedcompoundarray
	add_compound mycpv.myindexedcompoundarray
	(( mycpv.myindexedcompoundarray[34].val == 1.1 )) || err_exit "${cycle}: mycpv.myindexedcompoundarray[34].val == ${mycpv.myindexedcompoundarray[34].val}, expected 1.1"
	# try to add it a 2nd time - since the new element will replace the old
	# one the value will _not_ be incremented (or better: The compound
	# variable value "val" will be added, not the value of the "val"
	# variable)
	add_compound mycpv.myindexedcompoundarray
	(( mycpv.myindexedcompoundarray[34].val == 1.1 )) || err_exit "${cycle}: mycpv.myindexedcompoundarray[34].val == ${mycpv.myindexedcompoundarray[34].val}, expected 1.1"
	unset mycpv.myindexedcompoundarray[34]
	[[ ! -v mycpv.myindexedcompoundarray[34].val ]] || err_exit "${cycle}: [[ ! -v mycpv.myindexedcompoundarray[34].val ]] should return failure, got $?"
	(( mycpv.myindexedcompoundarray[34].val == 0.0 )) || err_exit "${cycle}: mycpv.myindexedcompoundarray[34].val == ${mycpv.myindexedcompoundarray[34].val}, expected 0.0"
	[[ "${mycpv.myindexedcompoundarray[34]}" == "" ]] || err_exit "${cycle}: mycpv.myindexedcompoundarray[34] expected to be equal to an empty string but contains |${mycpv.myindexedcompoundarray[34]}|"



	# Test 006: Tested associative compound variable array
	compound -A mycpv.myassociativecompoundarray
	add_compound mycpv.myassociativecompoundarray
	(( mycpv.myassociativecompoundarray[34].val == 1.1 )) || err_exit "${cycle}: mycpv.myassociativecompoundarray[34].val == ${mycpv.myassociativecompoundarray[34].val}, expected 1.1"
	# try to add it a 2nd time - since the new element will replace the old
	# one the value will _not_ be incremented (or better: The compound
	# variable value "val" will be added, not the value of the "val"
	# variable)
	add_compound mycpv.myassociativecompoundarray
	(( mycpv.myassociativecompoundarray[34].val == 1.1 )) || err_exit "${cycle}: mycpv.myassociativecompoundarray[34].val == ${mycpv.myassociativecompoundarray[34].val}, expected 1.1"
	unset mycpv.myassociativecompoundarray[34]
	[[ ! -v mycpv.myassociativecompoundarray[34].val ]] || err_exit "${cycle}: [[ ! -v mycpv.myassociativecompoundarray[34].val ]] should return failure, got $?"
	(( mycpv.myassociativecompoundarray[34].val == 0.0 )) || err_exit "${cycle}: mycpv.myassociativecompoundarray[34].val == ${mycpv.myassociativecompoundarray[34].val}, expected 0.0"
	[[ "${mycpv.myassociativecompoundarray[34]}" == "" ]] || err_exit "${cycle}: mycpv.myassociativecompoundarray[34] expected to be equal to an empty string but contains |${mycpv.myassociativecompoundarray[34]}|"


	# check whether the compound variable output is still Ok
	count_brackets "${mycpv}" || err_exit "${cycle}: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
	count_brackets "$(print -v mycpv)" || err_exit "${cycle}: print -v mycpy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
	count_brackets "$(print -C mycpv)" || err_exit "${cycle}: print -C mycpy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"


	# reset
	unset mycpv
	[[ ! -v mycpv ]] || err_exit "${cycle}: mycpy should not exist"
	[[ "${mycpv}" == "" ]] || err_exit "${cycle}: mycpv expected to be empty"
done


# tests done
exit $((Errors))
