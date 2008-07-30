#! /usr/bin/ksh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Convert a wx-based workspace to Mercurial.
#

usage="wx2hg [-u] [-r hg_rev] [-t hg_ws] codemgr_ws"

#
# If "yes", then give some hints about cleanup and rerunning after a
# failure.
#
can_retry=no
tail=/usr/xpg4/bin/tail

function has_hg_twin {
	[[ -n "$primary_twin" ]]
}

function warn {
	print -u2 wx2hg: warning: "$@"
}

function note {
	print -u2 wx2hg: note: "$@"
}

function fail {
	print -u2 wx2hg: "$@"
	if [[ "$can_retry" = yes ]]; then
		print -u2 "Please run"
		print -u2 "  hg --cwd $hg_ws update -C"
		print -u2 "before retrying."
	fi
	exit 1
}

function clone_twins {
	ws="$1"
	rev="$2"

	echo "Cloning $primary_twin"
	echo "to $ws"
	set -x
	hg clone -r $rev "$primary_twin" "$ws"
	set +x

	rev_warning=n
	for dir in $nested_twins; do
		(cd "$primary_twin"/$dir ; \
		    hg log -l 1 -r $hg_rev > /dev/null 2>1)
		if  (( $? != 0 )); then
			warn "Unable to clone $primary_twin/$dir"
			rev_warning=y
			continue
		fi
		echo "Cloning from $primary_twin/$dir"
		echo "to $ws/$dir"
		mkdir -p $ws/$dir
		set -x
		hg init $ws/$dir
	    	( cd $ws/$dir; hg pull -u "$primary_twin"/$dir )
		set +x
	done

	[[ $rev_warning = "n" ]] || fail \
"revision $hgrev was not present in all workspaces.\n" \
"When using -r with nested repositories, you should specify a tag\n" \
"name that is valid in each workspace."
}

#
# Command-line processing, sanity checks, and setup.
#

[[ -n $(whence workspace) ]] || 
    fail "workspace command not found; please check PATH."

# do a wx update?
do_update=yes

#
# Mercurial workspace to populate.  Default is to create, in the same
# directory as the Teamware workspace, a new Mercurial workspace cloned
# from the hg_twin of the Teamware parent.
#
hg_ws=""

#
# Revision in the Mercurial workspace to apply the changes to.
# Default is to get the most recent revision (tip), thus avoiding
# the need for a merge unless overridden by the caller using -r.
#
hg_rev="tip"

while getopts r:t:u opt; do
	case $opt in
	r)	hg_rev="$OPTARG";;
	t)	hg_ws="$OPTARG";;
	u)	do_update=no;;
	?)	print -u2 "usage: $usage"; exit 1;;
	esac
done
shift $(($OPTIND - 1))

if [[ $# -ne 1 ]]; then
	print -u2 "usage: $usage"
	exit 1
fi

CODEMGR_WS="$1"
[[ "$CODEMGR_WS" = /* ]] || CODEMGR_WS="$(pwd)/$CODEMGR_WS"
export CODEMGR_WS

if [[ -n "$hg_ws" ]]; then
	if [[ ! -d "$hg_ws" || ! -d "$hg_ws/.hg" ]]; then
		fail "$hg_ws is not a Mercurial workspace."
	fi
	[[ "$hg_ws" = /* ]] || hg_ws="$(pwd)/$hg_ws"
fi

[[ -d "$CODEMGR_WS" ]] || fail "$CODEMGR_WS does not exist."
cd "$CODEMGR_WS"

codemgr_parent=$(workspace parent)
[[ -n "$codemgr_parent" ]] || \
    fail "$CODEMGR_WS is not a Teamware workspace or does not have a parent."
[[ -d "$codemgr_parent" ]] || fail "parent ($codemgr_parent) doesn't exist."

primary_twin=""
nested_twins=""
twinfile="$codemgr_parent"/Codemgr_wsdata/hg_twin
if [[ -f $twinfile ]]; then
	primary_twin=$(head -1 $twinfile)
	nested_twins=$($tail -n +2 $twinfile | sort -r)
fi

if has_hg_twin; then
	echo "Teamware parent $codemgr_parent has twin $primary_twin"
	[[ -n "$nested_twins" ]] &&
	    echo "and nested twins $nested_twins"
fi

#
# Do this check before time-consuming operations like creating
# the target repo.
#
his=$(find Codemgr_wsdata -name history -mtime -1)
if [[ -z "$his" ]]; then
	warn "history file is more than one day old; do you need to" \
	    "bringover from $codemgr_parent?"
fi

# Less time-consuming than cloning

if [[ ! -d wx ]]; then
	print "Initializing wx..."
	wx init -ft
else
	if [[ "$do_update" = yes ]]; then
		print "Updating wx state..."
		wx update
	fi
fi

wx outchk

out_files=$(wx out)
active_files=$(wx list)

if [[ ! -z "$out_files" ]]; then
    	fail "wx2hg will only migrate checked-in files;" \
	    "please check in these files with wx ci and try again"
fi

# more time-consuming than wx update and wx outchk

if [[ -z "$hg_ws" ]]; then
	ws=$(basename $(pwd))
	hg_ws=$(dirname $(pwd))/"$ws-hg"
fi

if [[ -d "$hg_ws" ]]; then
    	echo "Updating preexisting Mercurial workspace $hg_ws to $hg_rev\n"
    	(cd "$hg_ws"; hg update -C $hg_rev) ||
	    fail "hg update $hg_rev failed for $hg_ws"
	if [[ -n "$nested_twins" ]]; then
		update_warning=n
		for dir in $nested_twins; do
			if [[ ! -d "$hg_ws/$dir" ]]; then
				warn "$hw_ws/$dir does not exist"
				update_warning=y
			fi
			echo "Updating preexisting nested workspace " \
			    "$hg_ws/$dir to $hg_rev\n"
			(cd "$hg_ws"/$dir ; hg update -C $hg_rev)
			if (( $? != 0 )); then
				warn "hg update $hg_rev failed for $hg_ws/$dir"
				update_warning=y
				continue
			fi
		done

		[[ $update_warning = "n" ]] ||
		    fail "When using an existing Mercurial workspace with\n" \
			"nested repositories, all nested repositories must\n" \
			"already exist in the existing workspace.  If also\n" \
			"specifying -r, then the specified hg_rev must be\n" \
			"valid in all nested repositories."
	fi
else
    	if has_hg_twin; then
    	    	clone_twins "$hg_ws" $hg_rev
	else
		fail "$codemgr_parent is not recognized as a gate;" \
		    "please provide a Mercurial workspace (-t hg_ws)" \
		    "that matches it."
	fi
fi

can_retry=yes

# Make sure hg_ws is an absolute path
[[ "$hg_ws" = /* ]] || hg_ws="$(pwd)/$hg_ws"


# usage: which_repo filename
function which_repo {
	typeset f=$1

	for r in $nested_twins; do
		if [ ${f##$r/} != $f ]; then
			echo ${f##$r/} $r
			return
		fi
	done

	echo $f "."
}

#
# Do renames first, because they'll be listed with the new name by "wx
# list".  There's a conflict if the new name already exists or if the
# old name does not exist.  We can theoretically recover from the
# former (move the existing file out of the way, or pick a different
# new name), but not the latter.  For now, just error out and let the
# user fix up the workspace so that there isn't a conflict.
#

renamelist=/tmp/wxrename$$
wx renamed > "$renamelist"

# usage: do_rename oldname newname
function do_rename {
	typeset old_file old_repo new_file new_repo

	which_repo $1 | read old_file old_repo
	which_repo $2 | read new_file new_repo

	typeset old=$old_repo/$old_file
	typeset new=$new_repo/$new_file

	[[ -f "$old" ]] || fail "can't rename: $old doesn't exist."
	[[ ! -f "$new" ]] || fail "can't rename: $new already exists."

	dir=$(dirname "$new")
	base=$(basename "$new")
	[[ -d "$dir" ]] || mkdir -p "$dir" || fail "mkdir failed"

	if [ $old_repo = $new_repo ]; then
		print "rename $old -> $new"
		set -x
		( cd $old_repo; hg mv $old_file $new_file ) || \
		    fail "rename failed."
		set +x
	else
		print "moving $old_file from repository $old_repo"
		print "to $new_file in repository $new_repo"
		cp $old $new
		set -x
		( cd $old_repo; hg rm $old_file ) || fail "hg rm failed"
		( cd $new_repo; hg add $new_file ) || fail "hg add failed"
		set +x
	fi
}

if [[ -s "$renamelist" ]]; then
	cat "$renamelist" | (
		cd "$hg_ws"
		while :; do
			read newname oldname
			[[ -n "$newname" ]] || break
			do_rename "$oldname" "$newname"
		done
	) || exit 1
fi

#
# usage: name_in_parent fname
# If fname had been renamed, echo the old name.  Otherwise echo the
# given name.
#
function name_in_parent {
	typeset new old

	if [[ -s "$renamelist" ]]; then
		cat "$renamelist" | while :; do
			read new old
			[[ -n "$new" ]] || break
			if [[ "$1" = "$new" ]]; then
				print "$old"
				return
			fi
		done
	fi
	print "$1"
}

#
# Now do content changes.  There's a likely conflict if the file in
# Mercurial is different from the file in the Teamware parent.
#

parentfile=/tmp/parent$$
patchfile=/tmp/patch$$
childfile=/tmp/child$$

[[ -n "$active_files" ]] || warn "no files in active list."

for f in $active_files; do
	#
	# Get the name that the file appears in the parent as.
	#
	oldname=$(name_in_parent "$f")

	# We need unexpanded SCCS keywords for both parent and child
	sccs get -skp "$f" > "$childfile"

	if [[ -f "$codemgr_parent/$oldname" ]]; then
	    	(cd $codemgr_parent; sccs get -skp "$oldname" > "$parentfile")
	else
	    	rm -f $parentfile
	fi

	if [[ ! -r "$parentfile" ]]; then
		print "new file: $f"
		[[ ! -f "$hg_ws/$f" ]] || fail "$f already exists in $hg_ws."
		dir=$(dirname "$hg_ws/$f")
		base=$(basename "$hg_ws/$f")
		[[ -d "$dir" ]] || mkdir -p "$dir" || fail "mkdir failed"
		cp "$childfile" "$hg_ws/$f" || fail "copy failed"
		set -x
		(cd "$dir" && hg add "$base") || fail "hg add failed."
		set +x
	elif diff "$parentfile" "$hg_ws/$f" > /dev/null 2>&1; then
		if diff -u "$parentfile" "$childfile" > "$patchfile"; then
			print "skipping $f (unchanged)."
			continue
		fi
		(cd "$hg_ws"; gpatch -F0 $f < "$patchfile")
		[[ $? -eq 0 ]] || fail "$f: patch failed."
	else
	    	diff -u "$parentfile" "$hg_ws/$f"
		echo ""

		fail "For file:\n\n\t$f\n\nthe teamware parent:" \
		    "\n\n\t$codemgr_parent" \
		    "\n\ndoesn't match its mercurial twin;" \
			"specify the matching revision in mercurial\nwith" \
		    	"-r hg_rev, or resynchronize them.\n"
	fi
done

note "remember to commit your changes:"
echo "in primary repository ${hg_ws}:"
( cd $hg_ws ; hg status -mard )
for n in $nested_twins; do
	echo "in nested repository ${n}:"
	( cd $hg_ws/$n ; hg status -mard )
done

if [[ "$hg_rev" != "tip" ]]; then
    	note "before you integrate your changes, $hg_ws must be merged to tip"
fi

rm -f "$parentfile" "$patchfile" "$renamelist" "$childfile"

exit 0
