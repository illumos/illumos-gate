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
# variable tree test #001
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

mytree_global=()

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

	# build tree using global tree variables
	build_tree mytree_global mysrcdata_global leaf_compound || \
		err_exit 'build_tree mytree_global mysrcdata_global leaf_compound returned an error'

	(( $(print -r -- "${mytree_global}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_global' too small"

	# build tree using local tree variables
	mytree_local=()
	build_tree mytree_local mysrcdata_local leaf_compound || \
		err_exit 'build_tree mytree_local mysrcdata_local leaf_compound returned an error'

	(( $(print -r -- "${mytree_local}" | wc -l) > 10 )) || err_exit "compound tree 'mytree_local' too small"

	# Compare trees
	if [[ "${mytree_global}" != "${mytree_local}" ]] ; then
		err_exit "compound trees 'mytree_local' and 'mytree_global' not identical"
	fi

	unset 'mytree_global.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ||
		err_exit "variable 'mytree_global.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' not found"

	[[ "${mytree_global}" != "${mytree_local}" ]] || err_exit "mytree_global and mytree_local should differ"

	unset 'mytree_local.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' ||
		err_exit "variable 'mytree_local.l1[urw].l2[itc zapfdingbats].l3[medium].entries[abcd].filenames[0]' not found"

	# Compare trees (after "unset")
	if [[ "${mytree_global}" != "${mytree_local}" ]] ; then
		err_exit "compound trees 'mytree_local' and 'mytree_global' not identical after unset"
	fi
}

main

exit $((Errors<125?Errors:125))
