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
# variable tree test #001
# Propose of this test is whether ksh93 crashes or not - ast-ksh.2008-05-14
# crashes like this when running this test:
# 
# program terminated by signal ILL (illegal opcode)
# 0xffffffffffffffff:     <bad address 0xffffffffffffffff>
# Current function is nv_diropen
#   123                   dp->hp = (Namval_t*)dtprev(dp->root,&fake);
# (dbx) where
#   [1] 0x100381e80(0x100381e80, 0xffffffff7fffe690, 0x10, 0x61, 0x0, 0x100381ec9), at 0x100381e80 
# =>[2] nv_diropen(np = (nil), name = 0x100381ebc "mysrcdata"), line 123 in "nvtree.c"
#   [3] walk_tree(np = 0x1003809e0, dlete = 524289), line 743 in "nvtree.c"
#   [4] put_tree(np = 0x1003809e0, val = (nil), flags = 524289, fp = 0x100381db0), line 814 in "nvtree.c"
#   [5] nv_putv(np = 0x1003809e0, value = (nil), flags = 524289, nfp = 0x100381db0), line 141 in "nvdisc.c"
#   [6] _nv_unset(np = 0x1003809e0, flags = 524289), line 1976 in "name.c"
#   [7] table_unset(shp = 0x10033e900, root = 0x100380900, flags = 524289, oroot = 0x100360980), line 1902 in "name.c"
#   [8] sh_unscope(shp = 0x10033e900), line 2711 in "name.c"
#   [9] sh_funscope(argn = 1, argv = 0x10035e680, fun = (nil), arg = 0xffffffff7ffff118, execflg = 4), line 2470 in "xec.c"
#   [10] sh_funct(np = 0x100380860, argn = 1, argv = 0x10035e680, envlist = (nil), execflg = 4), line 2528 in "xec.c"
#   [11] sh_exec(t = 0x10035e620, flags = 4), line 1032 in "xec.c"
#   [12] exfile(shp = 0x10033e900, iop = 0x100379a20, fno = 10), line 589 in "main.c"
#   [13] sh_main(ac = 2, av = 0xffffffff7ffffa08, userinit = (nil)), line 364 in "main.c"
#   [14] main(argc = 2, argv = 0xffffffff7ffffa08), line 46 in "pmain.c"
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


function build_tree
{
#set -o errexit -o xtrace
	typeset index
	typeset s
	typeset i
	typeset dummy
	typeset a b c d e f
	
	nameref dest_tree="$1" # destination tree
	nameref srcdata="$2"   # source data
	typeset tree_mode="$3" # mode to define the type of leads

	typeset -A dest_tree.l1

	for index in "${!srcdata.hashnodes[@]}" ; do
		nameref node=srcdata.hashnodes["${index}"]

		for i in "${node.xlfd[@]}" ; do
			IFS='-' read dummy a b c d e f <<<"$i"
			
			if [[ "$a" == "" ]] ; then
				a="$dummy"
			fi
			
			[[ "$a" == "" ]] && a='-'
			[[ "$b" == "" ]] && b='-'
			[[ "$c" == "" ]] && c='-'
						
			if [[ "${dest_tree.l1["$a"]}" == "" ]] ; then
			#if ! (unset dest_tree.l1["$a"]) ; then
				typeset -A dest_tree.l1["$a"].l2
			fi

			if [[ "${dest_tree.l1["$a"].l2["$b"]}" == "" ]] ; then
			#if ! (unset dest_tree.l1["$a"].l2["$b"]) ; then
				typeset -A dest_tree.l1["$a"].l2["$b"].l3
			fi

			if [[ "${!dest_tree.l1["$a"].l2["$b"].l3["$c"].entries[*]}" == "" ]] ; then
				typeset -A dest_tree.l1["$a"].l2["$b"].l3["$c"].entries
			fi
					
			#dest_tree.l1["$a"].l2["$b"].l3["$c"].entries+=( "$index" )
			typeset new_index
			if [[ "${tree_mode}" == "leaf_name" ]] ; then
				new_index=$(( ${#dest_tree.l1["$a"].l2["$b"].l3["$c"].entries[@]}+1 ))
			else
				new_index="${node.name}"

				# skip if the leaf node already exists
				if [[ "${dest_tree.l1["$a"].l2["$b"].l3["$c"].entries[${new_index}]}" != "" ]] ; then
					continue
				fi
			fi
			
			add_tree_leaf dest_tree.l1["$a"].l2["$b"].l3["$c"].entries[${new_index}] "${index}" "${tree_mode}"
		done
	done
	
	return 0	
}

function add_tree_leaf
{
	nameref tree_leafnode="$1"
	nameref data_node=srcdata.hashnodes["$2"]
	typeset add_mode="$3"
	
	case "${add_mode}" in
		"leaf_name")
			tree_leafnode="${data_node.name}"
			return 0
			;;
		"leaf_compound")
			tree_leafnode=(
				typeset name="${data_node.name}"
				typeset -a filenames=( "${data_node.filenames[@]}" )
				typeset -a comments=( "${data_node.comments[@]}" )
				typeset -a xlfd=( "${data_node.xlfd[@]}" )
			)
			return 0
			;;
		*)
			print -u2 -f "ERROR: Unknown mode %s in add_tree_leaf\n" "${add_mode}"
			return 1
			;;
	esac
	
	# not reached
	return 1
}

function main
{
	typeset mysrcdata=(
		typeset -A hashnodes=(
			[abcd]=(
				name='abcd'
				typeset -a xlfd=(
					'-urw-itc zapfchancery-medium-i-normal--0-0-0-0-p-0-iso8859-1'
					'-urw-itc zapfdingbats-medium-r-normal--0-0-0-0-p-0-adobe-fontspecific'
					'-urw-itc zapfdingbats-medium-r-normal--0-0-0-0-p-0-sun-fontspecific'
				)
				typeset -a comments=(
					'comment 1'
					'comment 2'
					'comment 3'
				)
				typeset -a filenames=(
					'/home/foo/abcd_1'
					'/home/foo/abcd_2'
					'/home/foo/abcd_3'
				)
			)
		)
	)

	mytree=()
	build_tree mytree mysrcdata leaf_compound
#	(( $(print -r -- "$mytree" | wc -l) > 10 )) || err_exit "Compound tree too small."
}

main

# tests done
exit $((Errors))
