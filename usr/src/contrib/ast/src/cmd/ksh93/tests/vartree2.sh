########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
#
# variable tree test #002
# Propose of this test is whether ksh93 handles global variable trees
# and function-local variable trees the same way, including "nameref"
# and "unset" handling.
#

function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}

alias err_exit='err_exit $LINENO'

# "built_tree1" and "built_tree2" are identical except the way how they test
# whether a variable exists:
# - "built_tree1" uses "${varname}" != "", e.g. looking whether the variable
#    as non-zero length content
# - "built_tree2" uses "! (unset varname)", e.g. "unset" in a subshell
function build_tree1
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

# "built_tree1" and "built_tree2" are identical except the way how they test
# whether a variable exists:
# - "built_tree1" uses "${varname}" != "", e.g. looking whether the variable
#    as non-zero length content
# - "built_tree2" uses "! (unset varname)", e.g. "unset" in a subshell
function build_tree2
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

			#if [[ "${dest_tree.l1["$a"]}" == "" ]] ; then
			if ! (unset dest_tree.l1["$a"]) ; then
				typeset -A dest_tree.l1["$a"].l2
			fi

			#if [[ "${dest_tree.l1["$a"].l2["$b"]}" == "" ]] ; then
			if ! (unset dest_tree.l1["$a"].l2["$b"]) ; then
				typeset -A dest_tree.l1["$a"].l2["$b"].l3
			fi

			if [[ "${!dest_tree.l1["$a"].l2["$b"].l3["$c"].entries[*]}" == "" ]] ; then
				typeset -A dest_tree.l1["$a"].l2["$b"].l3["$c"].entries
			fi

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

# "mysrcdata_local" and "mysrcdata_global" must be identical
typeset mysrcdata_global=(
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

mytree_global1=()
mytree_global2=()

function main
{
	# "mysrcdata_local" and "mysrcdata_global" must be identical
	typeset mysrcdata_local=(
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

	#### Build tree using global tree variables
	build_tree1 mytree_global1 mysrcdata_global leaf_compound || \
		err_exit 'build_tree1 mytree_global1 mysrcdata_global leaf_compound returned an error'
	(( $(print -r -- "${mytree_global1}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_global1' too small"

	build_tree2 mytree_global2 mysrcdata_global leaf_compound || \
		err_exit 'build_tree2 mytree_global2 mysrcdata_global leaf_compound returned an error'
	(( $(print -r -- "${mytree_global2}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_global2' too small"


	#### build tree using local tree variables
	mytree_local1=()
	mytree_local2=()

	build_tree1 mytree_local1 mysrcdata_local leaf_compound || \
		err_exit 'build_tree1 mytree_local1 mysrcdata_local leaf_compound returned an error'
	(( $(print -r -- "${mytree_local1}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_local1' too small"

	build_tree2 mytree_local2 mysrcdata_local leaf_compound || \
		err_exit 'build_tree2 mytree_local2 mysrcdata_local leaf_compound returned an error'
	(( $(print -r -- "${mytree_local2}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_local2' too small"


	#### Compare treess
	if [[ "${mytree_global1}" != "${mytree_local1}" ]] ; then
		err_exit "compound trees 'mytree_global1' and 'mytree_local1' not identical"
	fi

	if [[ "${mytree_global1}" != "${mytree_global2}" ]] ; then
		err_exit "compound trees 'mytree_global1' and 'mytree_global2' not identical"
	fi

	if [[ "${mytree_local1}" != "${mytree_local2}" ]] ; then
		err_exit "compound trees 'mytree_local1' and 'mytree_local2' not identical"
	fi


	#### test "unset" in a subshell
	(  unset 'mytree_global1.l1[urw].l2[itc zapfdingbats]'  ) || \
		err_exit "try 1: variable 'mytree_global1.l1[urw].l2[itc zapfdingbats]' not found"
	(  unset 'mytree_global1.l1[urw].l2[itc zapfdingbats]'  ) || \
		err_exit "try 2: variable 'mytree_global1.l1[urw].l2[itc zapfdingbats]' not found"

	# remove parent node (array element) and then check whether the child is gone, too:
	(
		unset 'mytree_global1.l1[urw].l2[itc zapfdingbats]'
		[[ -v 'mytree_global1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]'} ]]
	) && err_exit "global: parent node removed (array element), child still exists"
	(
		unset 'mytree_local1.l1[urw].l2[itc zapfdingbats]'
		[[ -v 'mytree_local1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ]]
	) && err_exit "local: parent node removed (array element), child still exists"

	# remove parent node  (array variable) and then check whether the child is gone, too:
	(
		unset 'mytree_local1.l1[urw].l2'
		[[ -v 'mytree_local1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ]]
	) && err_exit "global: parent node removed (array variable), child still exists"
	(
		unset 'mytree_local1.l1[urw].l2'
		[[ -v 'mytree_local1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ]]
	) && err_exit "local: parent node removed (array variable), child still exists"


	#### test "unset" and compare trees
	unset 'mytree_global1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ||
		err_exit "variable 'mytree_global1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' not found"

	[[ "${mytree_global1}" != "${mytree_local1}" ]] || err_exit "mytree_global1 and mytree_local1 should differ"

	unset 'mytree_local1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ||
		err_exit "variable 'mytree_local1.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' not found"

	# Compare trees (after "unset")
	if [[ "${mytree_global1}" != "${mytree_local1}" ]] ; then
		err_exit "compound trees 'mytree_local1' and 'mytree_global1' not identical after unset"
	fi
}

main

exit $((Errors<125?Errors:125))
