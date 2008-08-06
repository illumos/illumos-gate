#!/bin/ksh -p
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

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 

# wx -- workspace extensions.  Jeff Bonwick, December 1992.

# The bugster cat/subcat = consolidation/os-net-tools

version() {
	if [[ $(whence $0) = "/opt/onbld/bin/wx" ]] && \
	    pkginfo SUNWonbld > /dev/null 2>&1; then
		pkginfo -l SUNWonbld | egrep "PKGINST:|VERSION:|PSTAMP:"
	else
		ls -l $(whence $0)
	fi    
}

ring_bell() {
	# Sound bell to stderr, no newline 
	print -u2 "\007\c"
}

fail() {
	ring_bell
	# output error message to stderr
	print -u2 "$@ Aborting $command."
	exit 1
}

ask() {
	typeset question=$1 default_answer=$2
	if [ -z "$default_answer" ]; then
		echo "$question \c"
	else
		echo "$question [$default_answer]: \c"
	fi
	read answer
	[ -z "$answer" ] && answer="$default_answer"
}

yesno() {
	typeset question="$1"
	answer=
	while [ -z "$answer" ]; do
		ask "$question" y/n
		case $answer in
			y|yes)	answer=yes;;
			n|no)	answer=no;;
			*)	answer=;;
		esac
	done
}

ok_to_proceed() {
	yesno "$*"
	if [[ "$answer" == no ]]; then
		echo "Exiting, no action performed"
		exit 1
	fi
}

escape_re() {
	# Escape the . so they are treated as literals in greps.
	echo "$1"|sed 's{\.{\\.{g'
}

remove_local_nt_entry() {
	# remove entries in local nt cache
	grep -v "^$(escape_re $1) " $wxdir/local_nametable > \
		$wxtmp/local_nametable
	[[ ! -f $wxtmp/local_nametable ]] && \
		fail "Error: cannot create $wxtmp/local_nametable"
	mv -f $wxtmp/local_nametable $wxdir/local_nametable ||
		fail "Error: cannot create $wxdir/local_nametable."
}

remove_renamed_entry() {
	# remove entries in renamed list
	# assuming arg is the new filename to remove
	grep -v "^$(escape_re $1) " $wxdir/renamed > \
		$wxtmp/renamed
	[[ ! -f $wxtmp/renamed ]] && fail "Error: cannot create $wxtmp/renamed"
	mv -f $wxtmp/renamed $wxdir/renamed ||
		fail "Error: mv -f $wxtmp/renamed $wxdir/renamed failed"
}

add_local_nt_entry() {
	# Add workspace nametable entry to local nt cache for better perf.
	[[ -r $wsdata/nametable ]] || return 0
	if ! grep -q "^$(escape_re $1) " $wxdir/local_nametable; then
		# add entries from workspace nt to local nt cache
		grep "^$(escape_re $1) " $wsdata/nametable >> \
			$wxdir/local_nametable
		[[ ! -f $wxdir/local_nametable ]] && \
			fail "Error: cannot create $wxdir/local_nametable"
	fi
	return 0
}

remove_active_entry() {
	# Remove entry from active list 
	# $1 is the filepath to remove

	nawk '
	$1 == target {
		# Get past filepath line
		while(NF > 0)
			getline;
		# Get past blank lines
		while(NF == 0)
			getline;
		# Get past comments
		while(NF > 0)
			getline;
		# Get past ending blank lines
		while(NF == 0) {
			if (getline) {
				continue;
			} else {
				next;
			}
		}
	}
	# print the other active list entries
	{ print $0; } ' target=$1 $wxdir/active >$wxtmp/tmp_active ||
		fail "Error: cannot create $wxtmp/tmp_active."
	if mv -f $wxtmp/tmp_active $wxdir/active; then
		echo "$1 removed from active list."
		remove_local_nt_entry $1
	else
		cat >&2 <<-EOF
An error occured trying to remove $1 from the active list.
The active list may be corrupt.  You should check it out and 
possibly run '$ME update' to fix.
		EOF
		fail 
	fi
}

rename_active_entry() {
	# renamed $1 to $2 filepath in active list
	sed "s|^$(escape_re $1)$|$2|" $wxdir/active >\
		$wxtmp/active || fail "Error: cannot create $wxtmp/active."
	mv -f $wxtmp/active $wxdir/active || \
		fail "Error: mv $wxtmp/active $wxdir/active failed."
}

is_active() {
	# Return 0 if filepath arg is found in active list.
	wx_active|grep -q "^$(escape_re $1)$"
}

#
# ask user if s/he wants to remove an entry from the active list.
# Will not remove entries that differ from parent or are new.
#
ask_remove_active_entry() {
	# if an arg is passed in then this is assumed to be the filepath
	# otherwise we assume the variables were set properly by the caller
	if [[ $# -eq 1 ]]; then
		dir=$(dirname $1)
		file=$(basename $1)
		filepath=$1

		if [[ ! -f $file ]]; then
			echo "Cannot find $file"
			return 1
		fi
	fi

	if is_active $filepath; then
		if wx_pnt_filepath $filepath; then
			if ! cmp -s $file $parentfilepath; then
				cat <<-EOF

The file $filepath
differs from parent file:
$parentfilepath
and will remain in the active list.
				EOF
				return
			fi
		else
			# New file, leave in active list.
			cat <<-EOF
$filepath
is new and will remain in active list.  Use:
'$ME uncreate $filepath'
to remove from active list.
			EOF
			return
		fi
		# Remove entry from active list because it is the same as 
		# the parent.
		echo "There is no difference between $filepath and the parent"
		echo "$parentfilepath"
		yesno "Okay to remove $filepath from active list?"
		if [[ "$answer" == 'yes' ]]; then
			remove_active_entry $filepath
		fi
	fi
}

refresh_pnt_nt_cache() {
	# Refresh the parent nametable cache if necessary.
	# Note, this is a cache for the parent nametable entries that
	# have the same hash as the local active and renamed files.

	# no parent so nothing to update.
	[[ -z $parent ]] && return 0

	if [[ ! -r $parent/Codemgr_wsdata/nametable ]]; then
		fail "Error: cannot read $parent/Codemgr_wsdata/nametable"
	fi

	if [[ ! -f $wxtmp/parent_nametable ||
	    $parent/Codemgr_wsdata/nametable -nt $wxtmp/parent_nametable ||
	    $wsdata/parent -nt $wxtmp/parent_nametable ||
	    $wxdir/local_nametable -nt $wxtmp/parent_nametable ]]; then
		cut -f2- -d' ' $wxdir/local_nametable > $wxtmp/hash_list

		if [[ ! -f $wxtmp/hash_list ]]; then
			fail "Error: cannot create $wxtmp/hash_list."
		fi

		if [[ -s $wxtmp/hash_list ]]; then
			# Use hash list to get only the parent files
			# we're interested in.
			fgrep -f $wxtmp/hash_list \
			    $parent/Codemgr_wsdata/nametable \
				 > $wxtmp/parent_nametable 
			[[ ! -f $wxtmp/parent_nametable ]] && \
				fail "Error: cannot create $wxtmp/parent_nametable"
		else

			# There aren't any files to search for so just
			# update the timestamp.

			touch $wxtmp/parent_nametable
		fi
	fi
}

# add an active file to the new list
add_new() {
	typeset efp=$(escape_re $1)
	# update new file list
	if [[ ! -f $wxdir/new ]]; then
		touch $wxdir/new || fail "Error: cannot create $wxdir/new."
	fi
	if is_active $1 && ! grep -q "^$efp$" $wxdir/new; then
		echo "$1" >> $wxdir/new || fail "Error: cannot update $wxdir/new."
	fi
}

# remove a file from the new list
remove_new() {
	# remove entries in new list
	typeset efp=$(escape_re $1)
	if [[ -f $wxdir/new ]] && grep -q "^$efp$" $wxdir/new; then
		grep -v "^$efp$" $wxdir/new > $wxtmp/new
		[[ ! -f $wxtmp/new ]] && fail "Error: cannot create $wxtmp/new"
		mv -f $wxtmp/new $wxdir/new || fail "Error: cannot create $wxdir/new." 
	fi
}

update_active() {
	# Try to add an entry to the active list
	typeset efp=$(escape_re $1)

	if ! is_active $1; then
		if [[ -n "$comment_file" ]]; then
			# Use sed to remove any empty lines from comment file.
			(echo $1; echo; sed '/^[ 	]*$/d' $comment_file;\
				echo) >>$wxdir/active ||
				fail "Could not update active list."
		else
			(echo $1; echo; wx_show_comment; echo) \
			    >> $wxdir/active ||
				fail "Could not update active list."
			echo "Remember to edit the comment in the active list "\
				 "(use '$ME ea')."
		fi
		add_local_nt_entry $1
	fi  # End if not in active list
}

sort_active() {
	typeset origfp=$filepath

	# Note must use filepath for wx_show_comment
	wx_active | sort | while read filepath; do
		(print "$filepath"; print; wx_show_comment; print)
	done > $wxtmp/active_sort || \
		fail "Error: cannot create $wxtmp/active_sort"
	mv -f $wxtmp/active_sort $wxdir/active || \
		fail "Error: cannot create $wxdir/active"

	filepath=$origfp
}

sort_renamed() {
	sort $wxdir/renamed > $wxtmp/renamed_sort || \
		fail "Error: cannot create $wxtmp/renamed_sort"
	mv -f $wxtmp/renamed_sort $wxdir/renamed || \
		fail "Error: cannot create $wxdir/active"
}

update_active_comment() {
	# replace comment in active list entry with contents of $comment_file
	nawk '
	# find active list entry to modify
	$1 == filepath {
		# print filepath line
		while(NF > 0){
			print $1;
			getline;
		}
		#print 1 blank (delimit)
		print "";
		# Get past blank lines
		while(NF == 0){
			getline;
		}
		# Get past active entry comments
		# append to or replace comment
		if (comment_mode == "append"){
			while(NF > 0) {
				# output existing comments
				print $0;
				getline;
			}
		} else {
			# get past existing comments
			while(NF > 0) getline;
		}

		# output new comments
		while (getline < comments){
			# do not print blank lines
			if (NF > 0)
				print $0
		}
		close comments
		# print delimiting blank line
		printf "\n"

		# Get past ending blank lines in active entry
		NF=0
		while(NF == 0) {
			if (getline) {
				continue;
			} else {
				next;
			}
		}
	}
	# print the other active list entries
	{ print $0; } ' filepath=$1 comment_mode=$comment_mode \
		comments=$comment_file $wxdir/active >$wxtmp/tmp_active && \
		mv $wxtmp/tmp_active $wxdir/active 
	if [[ $? -eq 0 ]]; then
		echo "$1 comment(s) updated in active list."
	else
		cat <<-EOF

An error occured trying to update comments for $1 in the active list.
The active list ($wxdir/active) may be corrupt.  You should check it out
and possilbly run '$ME ea' to fix.

		EOF
		fail
	fi
}

lookup_parent() {
	# Find a local file's parent filepath.
	# Returns 1 if not found (local file is new)
	# Sets env var. parentfilepath and parenthash if found
	# Requires a file arg.
	# Updates local and parent nt caches.

	typeset efp parententry localfile hash1 hash2 hash3 hash4 \
		local_nt pnt_nt

	parentfile=
	parenthash=

	if [[ -z $parent ]]; then
		cat >&2 <<-EOF

Warning: there is no parent for the current workspace so local file:
$1
is assumed to be new.
		EOF
		return 1
	fi
	if [[ ! -f $wsdata/nametable ]]; then
		# Nothing has been brought over so assuming new file.
		cat >&2 <<-EOF

Warning: the $wsdata/nametable
doesn't exist so
$1
is assumed to be new.
		EOF
		return 1
	fi

	if [[ ! -r $parent/Codemgr_wsdata/nametable ]]; then
		fail "Error: cannot read $parent/Codemgr_wsdata/nametable."
	fi
	if [[ ! -f $wxtmp/parent_nametable ]] || $need_pnt_refresh; then
		refresh_pnt_nt_cache
		need_pnt_refresh=false
	fi
	if [[ ! -f $wxdir/local_nametable ]]; then
		touch $wxdir/local_nametable ||
			fail "Error: cannot create $wxdir/local_nametable."
	fi

	efp=$(escape_re $1)

	for local_nt in $wxdir/local_nametable $wsdata/nametable; do

		# May be multiple entries in nametable, see if one
		# matches parent.

		grep "^$efp " $local_nt |\
		while read localfile hash1 hash2 hash3 hash4; do
			for pnt_nt in $wxtmp/parent_nametable \
			    $parent/Codemgr_wsdata/nametable; do
				# get current parent nt entry
				parententry=$(grep \
				    " $hash1 $hash2 $hash3 $hash4$" $pnt_nt)
				if [[ -n "$parententry" ]]; then
					# found parent entry
					parentfile=$(echo "$parententry" |\
						cut -f1 -d' ')
					parenthash="$(echo "$parententry" |\
						cut -f2- -d' ')"
					if [[ "$local_nt" == \
						"$wsdata/nametable" ]]; then

						# Update the local nt
						# hash cache if parent
						# found and local
						# workspace nt used.

						add_local_nt_entry $localfile
					fi
					if [[ $pnt_nt == \
					    $parent/Codemgr_wsdata/nametable ]]
					then

						# Update the parent nt
						# hash cache if actual
						# parent nt used.

						echo $parententry >>\
						    $wxtmp/parent_nametable
					fi

					# break out of all the loops if
					# parent found

					break 3
				fi
			done # for pnt_nt
		done # while read active file
	done # for local_nt

	if [[ -z "$parentfile" ]]; then
		# parent filepath not found.
		return 1
	else
		# parent filepath found.
		return 0
	fi
}

#
# Detect if a file was locally renamed
#
renamed() {
	# Return 0 if renamed, 1 if not locally renamed
	# parentfile and parenthash set as side effect
	# Must be used by commands that set filepath (like wx_eval)

	if [[ ! -f $wxdir/renamed ]]; then
		update_renamed_dir
	fi

	# new is the new filename in the current ws, old is the previous
	# filename that should exist in parent ws.

	if grep -q "^$(escape_re $filepath) " $wxdir/renamed; then
		if lookup_parent $filepath; then
			return 0
		else

			# New files aren't in $wxdir/renamed so no
			# parent is a problem

			fail "Error: renamed $filepath but no matching parent"\
				"file in $parent"
		fi
	else
		# not locally renamed
		return 1
	fi
}

wx_pnt_filepath() {
	# return 0 if parent file found. Side effect: sets parentfilepath
	# and parentsdot.  parentfile and parenthash are set via lookup_parent.

	# if an arg is passed in then this is assumed to be the filepath
	# otherwise we assume the variables were set properly by the caller
	if [[ $# -eq 1 ]]; then
		dir=$(dirname $1)
		file=$(basename $1)
		filepath=$1
	fi

	# Find the parent filename
	if lookup_parent $filepath; then
		parentfilepath=$parent/$parentfile
		parentsdot=$parent/$(dirname $parentfile)/SCCS/s.$(basename \
		    $parentfile)
		if [[ -f $parentfilepath && -s $parentsdot ]]; then
			# found
			return 0
		else
			fail "Error: located parent filepath $parentfilepath"\
				"but file does not exist or SCCS file is empty."
		fi
	fi

	# wasn't found
	return 1
}

get_pb_output() {
	# Get output of putback -n (useful for parsing to find diffs between
	# workspaces).  Creates $wxtmp/putback.err and $wxtmp/putback.out
	typeset -i rc=0
	typeset origdir=$(pwd)
	# clean up if interrupted.
	trap "rm $wxtmp/putback.out;exit 1" HUP INT QUIT TERM

	cat <<-EOF
Doing a '$PUTBACK -n $*' to find diffs between workspaces.
Please be patient as this can take several minutes.
	EOF

        cd $workspace

	$PUTBACK -n $* 2>$wxtmp/putback.err >$wxtmp/putback.out
	rc=$?
	# Note a blocked putback returns a 2 but is not a problem.
	if [[ $rc -ne 0 && $rc -ne 2 ]]; then
		rm $wxtmp/putback.out
		fail "Error, $PUTBACK -n $* failed. See $wxtmp/putback.err"\
			"for details."
	fi
	trap - HUP INT QUIT TERM
        cd $origdir
	return 0
}

wx_usage() {
	version

	cat << EOF

See <http://www.opensolaris.org/os/community/on/wx/> for usage tips.

Usage:  $ME command [-D] [args]

        -D turn on debugging for any command (output to stderr)

===================== Initialization and Update Commands ====================
        $ME init [-f(t|q|n) [-s]] [src-root-dir]     
                        initialize workspace for $ME usage
                        -f(t|q|n): non-interactive mode of update.  Use this
                                   to keep init from asking questions.
                            -ft: thorough update (update both active and 
                                 renamed lists with all diffs between parent
                                 and current workspace).
                            -fq: quick update (update active list with files
                                 currently checked out in current workspace).
                            -fn: no update (just create empty active and 
                                 renamed lists if they don't exist already).
                            -s:  keep active list sorted by default.  Must
                                 follow a -f(t|q|n) flag.
                        src-root-dir: optional path relative to top of 
                                      workspace where wx will search for files.
                                      Use "." to set src-root to top of
                                      workspace.  Default is usr.
        $ME update [-q|-r] [-s]
                        Update the active and renamed file lists by
                        appending names of all files that have been
                        checked out, changed, created or renamed as
                        compared to the parent workspace.  This is the
                        most accurate way of updating but it is slow.
                        All files in the workspace must be under SCCS
                        control in order for update to find them.  Note,
                        this operation can be sped up in some cases by
                        setting the PUTBACK env. variable to use 
                        "cm_env -g -o putback". (See
                        http://webhome.holland.sun.com/casper/ for more
                        info about the turbo def.dir.flp tool).

                        -q: quick update (only updates active list with
                            files currently checked out in workspace).  This
                            is faster but will not find renames or files that
                            have been checked-in/delget'ed.
                        -r: only update the renamed list.  Does not update
                            the active list.
                        -s: sort the active list.

======================== Information Commands ===========================
        $ME list [-r|-p|-w] list active files (the ones you are working on)
                        -r: list only renamed active files.
                        -p: output list of both active and renamed files 
                            suitable for input to putback. 
                        -w: output list of both active and renamed files
                            suitable for input to webrev (see $ME webrev 
                            subcommand below).
        $ME active          alias for list 
        $ME pblist          alias for list -p (see above).

        $ME renamed [-a|-d|-p]
                         list locally renamed files. The output format is:
                         "new_name previous_name". Note, deleted files are
                         a special case of rename. 
                        -a: list only renamed active files (same as list -r)
                        -d: list only deleted files
                        -p: show "new_name parent_name" (Note, parent_name 
                            may not be the same as previous_name)
        $ME new [-t]    List new active files (files that exist in child only)
                        Note, should be run before reedit (see reedit below).
                        -t: thorough, does not use new cache (slower but more
                            accurate if new cache isn't current).
        $ME out         find all checked-out files in workspace
        $ME info        [file ...] show all info about active files

        $ME diffs [file ...]
                        show sccs diffs for files (current vs previous
                        local version).  Will show diffs for all active
                        files if no files given on command line.  Will
                        use WXDIFFCMD environment variable if set.  Hint,
                        try: export WXDIFFCMD="diff -bwU5"

        $ME tdiffs [file ...]
                        Similar to diffs but new files are also displayed.
                        New files are those listed by '$ME new'.

        $ME pdiffs [file ...]   show diffs against parent files
                        Will show diffs between local file and it's
                        parent for all active files if no files given on
                        command line.  Will use WXDIFFCMD environment
                        variable if set. 

        $ME tpdiffs [file ...]   show diffs against parent files
                        Similar to pdiffs but new files are also displayed.
                        A file is considered new if it does not exist in
                        the parent.

        $ME prt [-y]    show sccs history for all active files

        $ME comments    display check-in comments for active files
        $ME bugs [-u]   display all bugids in check-in comments
        $ME arcs [-u]   display all ARC cases in check-in comments
        $ME pbcom [-v] [-u] [-N]  display summarized comments suitable for putback
                        Default is to display only bugs and arc cases. Will
                        display warnings about non-bug comments to stderr.
                        -v: display all comments verbatim including non-bug/arc 
                        -u: prevent sorting, order determined by active list
                        -N: don't check bug synopsis against bug database

======================== File Manipulation Commands ======================
        $ME edit [-s] [file ...]        
                        check out either file(s) on command line or
                        all active files if no file args.
                        (Updates the active list.)
                        -s: silent, less sccs diagnostic output.  This is 
                            true for the other commands that accept the 
                            -s flag.
        $ME checkout    Alias for edit command.
        $ME co          Alias for edit command.

        $ME unedit [-s][-f] [file ...] 
                        Returns file(s) to state prior to edit/checkout
                        Note, files will be unlocked and any changes made
                        when file was last checked out will be lost.
                        Unedit all active files if no files listed on
                        command line.  Removes active list entry if there
                        are no diffs between local and parent file.
                        (Updates active list)
                        -f: force unedit, non-interactive. Will backup
                            if wx files newer than last backup.
        $ME uncheckout  Alias for unedit command.
        $ME unco        Alias for unedit command.

        $ME delget [-(c|C) comment_file][-s][-f] [file ...] 
                        Check in all active files or files on command
                        line. Check in comments will be those in active
                        file.  See '$ME comments' for more info.
                        -c comment_file: use comment(s) in specified comment
                                         file when checking in file(s). Note,
                                         each comment should be on new line,
                                         blank lines not allowed.  Existing
                                         comments in active list will be 
                                         replaced by contents of comment_file.
                        -C comment_file: Similar to -c but comments are 
                                         appended to current active list 
                                         comments.
                        -f: force checkin, no checks, non-interactive.
                            Use this if your sure the files okay to checkin
                            otherwise this command will check for
                            keyword problems. Will backup if wx files
                            newer than last backup.

                        NOTE: use redelget to reset new file's version to 1.1.

        $ME checkin     Alias for delget command.
        $ME ci          Alias for delget command.

        $ME create [-(c|C) comment_file] [-f] [-o] file [file ...]
                        Creates one or more files in the workspace.
                        (Updates active list)
                        -(c|C) comment_file: see delget
                        -f: force create regardless of warnings,
                            (non-interactive).
                        -o: also check out file for further editing.

        $ME uncreate [-f] [file ...]
                        Undoes the create of a new file.  The file's
                        active list entry, its SCCS history and the
                        entry in the workspace nametable will be removed
                        but the file will stay in the workspace.
                        Will uncreate all new files in active list if
                        no file argument is specified.
                        -f: force uncreate, non-interactive. Will backup
                            if wx files newer than last backup.

        $ME get [-k][-r #][-p] [file ...]
                        Get a copy of all active files or files on command
                        line.  By default this is a read only version of
                        the file.
                        -r #: get specified version #
                        -p: output to stdout
                        -k: don't expand the sccs ID string
        $ME extract     Alias for get command.

        $ME reedit [-m] [-s] [file ...]
                        Collapse the sccs delta (file history) such that
                        all changes made to the file in the current
                        workspace are now in one delta.  If no files are
                        given on command line then all the active files
                        are processed.  The files are left in a checked
                        out state so you can make further changes if a
                        resolve to make all your changes look like a
                        single delta.  This eliminates the uninteresting
                        leaf deltas that arise from resolving conflicts,
                        so your putbacks do not contain a bunch of noise
                        about every bringover/resolve you did in the
                        interim.  Accepts the same compression flags as
                        $ME backup.  If [file ...] given, wx only
                        reedits files passed on command line.  This adds
                        files to active list if not already there.
                        
                        NOTE: reedit is appropriate for leaf workspaces
                        ONLY -- applying reedit to an interior-node
                        workspace would delete all childrens comments
                        and confuse Teamware tools in general.
                        
                        NOTE: if files are listed as new that are not
                        then DO NOT use the reedit as it will destroy
                        the file history.

                        NOTE: if a file is new reedit will leave the
                        file checked out so in order to keep the delta
                        version at 1.1 redelget must be used for
                        checkin.

                        -m: only reedit files that have more that one
                            delta as compared to parent file.  New files
                            will be recreated with comment found in
                            active list.
                        -s: silent checkin

        $ME recheckout  Alias for reedit command.
        $ME reco        Alias for reedit command.

        $ME redelget [-m][-s] [file ...]
                        Similar to reedit but the file is checked in
                        when the command is done. This is the command to
                        use to collapse new files to their initial
                        1.1 delta (will assign comment in active list).
        $ME recheckin   Alias for redelget command.
        $ME reci        Alias for redelget command.

        $ME delete [-f] [file ...]
                        Delete one or more files from the workspace.
                        Will delete all files in active list if no file
                        args.  Note, for files brought over from parent,
                        this command actually moves the file under the
                        deleted_files/ subdir so it can be recovered.
                        For new files this command can remove the file
                        and file history completely.
                        (Updates active list if file is in there.)
                        -f : force delete regardless of warnings 
                             (non-interactive)

                             Warning, this will completely remove new
                             files from the workspace.  Will backup
                             if wx files newer than last backup.
        $ME rm          Alias for delete command.

        $ME mv file newfile     
                        Rename file to newfile
                        (Updates active list with new file name)
        $ME mv file newdir      
        $ME mv dir newdir       
                        Renames dir or file to newdir.  If newdir exists
                        then dir will be subdir under newdir.  Note,
                        this renames all files in dir and can take a
                        while if there are a lot of files affected by
                        the rename.  (Updates active list)

        $ME reset [-f] [file ...]
                        Resets file contents and history to that of
                        parent file.  If the file was renamed locally it
                        will be renamed to that of the parent.  It does not
                        work on new files (see uncreate or delete).

                        NOTE: use with care.  If something goes wrong,
                        do a wx restore from the last backup and copy
                        wx/tmp/nametable.orig to Codemgr_wsdata/nametable.

======================== Teamware Commands ======================
        $ME putback [-v][-f][-N][Teamware putback flags, see below][file ...]
                        Use Teamware putback command to putback either
                        file(s) specified or *all* active and renamed
                        files if no file(s) specified.  Will use pbcom
                        output as the putback comments. 
                        -f: force non-interactive mode (will not prompt)
                        -v: pass comments verbatim to putback(see pbcom)
                        -N: don't check bug synopsis against bug database
                        Accepts -n, -p pws, -q putback flags ('man putback' 
                        for more info).
        $ME pb          alias for putback.

        $ME resolve [Teamware resolve args]
                        resolve bringover conflicts and reedit merged 
                        files.  See 'man resolve' for args.

======================== ON Rules checking Commands ======================
        $ME cstyle      run cstyle over all active .c and .h files
                        skips files in wx/cstyle.NOT
        $ME jstyle      run jstyle over all active .java files
                        skips files in wx/jstyle.NOT
        $ME hdrchk      run 'hdrchk -a' over all active .h files
                        skips files in wx/hdrchk.NOT
        $ME makestyle   run makestyle over all active Makefiles
        $ME keywords    run keywords over all active files
                        skips files in wx/keywords.NOT
        $ME copyright   make sure there is a correct copyright message
                        that contains the current year
                        skips files in wx/copyright.NOT
        $ME cddlchk     make sure there is a current CDDL block in
                        active files
                        skips files in wx/cddlchk.NOT
        $ME rmdelchk    make sure sccs rmdel was not run on active files
                        (This causes Teamware problems.)
        $ME deltachk    make sure only 1 sccs delta in active files
                        (more than 1 breaks gate putback rules unless > 1
                        bug in putback.)
        $ME comchk      make sure comments are okay
        $ME rtichk      make sure RTI is approved for bugs/rfe's listed
                        in active list comments.  Will skip rtichk if
                        wx/rtichk.NOT exists.
        $ME outchk      warn if there are files checked out that aren't in
                        active list.
        $ME nits [file ...]
                        nits checking.  Run cstyle, jstyle, hdrchk, copyright,
                        cddlchk, and keywords over files to which they are
                        applicable (makestyle is not currently run
                        because it seems to be quite broken -- more
                        noise than data).  This is a subset of pbchk checks
                        suitable for checking files during development.
                        Use pbchk before doing the final putback.
                        Will run checks on all active files if no file args.
                        Will skip checks for files listed in wx/nits.NOT.
        $ME pbchk [file ...]
                        putback check.  Run cstyle, jstyle, hdrchk, copyright,
                        cddlchk, keywords, rmdelchk, deltachk, comchk, rtichk
                        and outchk over files to which they are
                        applicable (makestyle is not currently run
                        because it seems to be quite broken -- more
                        noise than data).  Good command to run before
                        doing a putback.  
                        Will run checks on all active files if no file args.
                        Will skip checks for files listed in wx/pbchk.NOT.

======================== Code Review Commands ======================
        $ME webrev [webrev-args]
                        generate webrev for active and renamed/deleted files.
                        Note, uses comments in the active list.  This is the
                        preferred way of reviewing code.  Arguments to webrev
                        may also be specified.
                        Will skip files listed in wx/webrev.NOT

        $ME codereview [-N] [codereview options]
                        generate environmentally friendly codereview diffs
                        for all active files.  -N indicates that delta
                        comments should not be included.

        $ME fullreview [-N] [codereview options]
                        generate full codereview diffs for all active files.
                        -N indicates that delta comments should not be
                        included.

======================== Backup and Restore Commands ======================
        $ME backup [-i|-n|-z|-b|-t]
                        make backup copies of all active and renamed files.
                        -i: info about backups (backup dir and contents)
                        -n: no compression 
                        -z: use gzip, faster than bzip2 but less compression.
                        -b: use bzip2, slower but better compression.
                        -t: backup if wx files are newer than last backup.
                        Defaults to the compression of the previous backup.
        $ME bu          Alias for backup command.

        $ME restore [-f] [backup_dir]   
                        restore a backup in a workspace (restores both
                        active files and performs file renames).  A path
                        to the directory containing the backup to
                        restore from can be optionally specified.
                        -f: non-interactive.  Will restore from last backup.

======================== Misc Commands ============================
        $ME apply <cmd> apply cmd to all active files; for example,
                        "$ME apply cat" cats every file
        $ME eval <cmd>  like apply, but more general.  In fact,
                        "$ME apply cmd" is implemented internally as
                        "$ME eval 'cmd \$file'".  When using eval,
                        you can refer to \$dir, \$file, \$filepath,
                        \$parent, and \$workspace.  For example:
                        $ME eval 'echo \$dir; sccs prt \$file | more'
                        will show the sccs history for each active file,
                        preceded by its directory.
        $ME grep        search all active files for pattern; equivalent to
                        "$ME eval 'echo \$filepath; grep pattern \$file'"
        $ME egrep       see $ME grep
        $ME sed         see $ME grep
        $ME nawk        see $ME grep

        $ME dir         echo the $ME directory path (\$workspace/$ME)
        $ME e <file>    edit the named $ME control file, e.g. "$ME e active".
                        The editor is \$EDITOR if set, else vi.

        $ME ea          shorthand for "$ME e active" (edit active list).  
                        Note, the format for each entry in the active
                        list is:

                        filepath
                        <empty line> # no spaces allowed
                        one or more comment lines # no blank lines between.
                        <empty line> # no spaces allowed, ends the entry.

                        In general, it is best to only edit the active
                        list to update comments.  Use the other $ME
                        commands like edit or create to update the
                        active list when possible.

        $ME ws <file>   cat the named workspace control file, i.e.
                        \$workspace/Codemgr_wsdata/file
        $ME args        shorthand for "$ME ws args"
        $ME access      shorthand for "$ME ws access_control"

        $ME help        print this usage message
        $ME version     print current version of this program
EOF
	exit 1
}

list_putback() {
	(wx_active; list_renamed -n)|nawk '!seen[$0]++'
}

list_new() {
	# list new files (not found in parent ws)
	typeset new

	if [[ $1 == '-t' ]]; then
		wx_active|
		while read new; do
			# thorough, skip new cache
			if ! lookup_parent $new; then
				# no parent, new file
				echo "$new"
			fi
		done
	else
		while read new; do
			# use new cache
			if ! lookup_parent $new; then
				# no parent, new file
				echo "$new"
			fi
		done < $wxdir/new
	fi
}

list_renamed() {
	typeset active current old

	if [[ $# -eq 0 ]]; then
		cat $wxdir/renamed
	elif [[ $1 == '-d' ]]; then
		# Only list only deleted file renames
		grep '^deleted_files/' $wxdir/renamed
	elif [[ $1 == '-n' ]]; then
		# Only list only current filenames
		cut -f1 -d' ' $wxdir/renamed
	elif [[ $1 == '-p' ]]; then
		# list parent for current instead of local previous name
		while read current old; do
			if lookup_parent $current; then
				print "$current $parentfile"
			else
				ring_bell
				print -u2 "Warning: cannot find parent file"\
					"for $current"
			fi
		done < $wxdir/renamed
	elif [[ $1 == '-a' ]]; then
		# Just list active renamed files
		for active in $(wx_active); do
			grep "^$(escape_re $active) " $wxdir/renamed
		done
	elif [[ $1 == '-r' ]]; then
		wx_active > $wxtmp/alist || fail "Error: cannot create $wxtmp/alist"
		# Just list non-active renamed files (just current name)
		while read current old; do
			grep -q "^$(escape_re $current)$" $wxtmp/alist || 
				echo $current
		done < $wxdir/renamed
		rm -f $wxtmp/alist
	else
		fail "Invalid flag $i. Run 'wx help' for info."
	fi
}

list_webrev() {
	# Output a list of active and renamed files suitable for webrev
	for filepath in $( (wx_active; list_renamed -n)|nawk '!seen[$0]++'); do
		if renamed; then
			echo "$filepath $parentfile"
		else
			echo "$filepath"
		fi
	done
}

wx_webrev() {
	typeset origdir=$PWD

	cd $workspace
	# skip files listed in .NOT files
	cat -s $wxdir/$command.NOT >$wxtmp/NOT
	
	( # do the loops in a subshell so there is only one file open
	for filepath in $(wx_active); do
		if grep -q "^$(escape_re $filepath)$" $wxtmp/NOT; then
			print -u2 "$filepath (skipping)"
			continue
		fi
		if renamed; then
			echo "$filepath $parentfile"
		else
			echo "$filepath"
		fi
		echo "\n$(wx_show_comment)\n"
	done 

	# Do non-active renamed files
	for filepath in $(list_renamed -r); do
		if grep -q "^$(escape_re $filepath)$" $wxtmp/NOT; then
			print -u2 "renamed $filepath (skipping)"
			continue
		fi
		lookup_parent $filepath ||
			fail "Error: cannot find parent for $filepath."
		if [[ $filepath != $parentfile ]]; then
			echo "$filepath $parentfile"
			# output empty line, comment, empty line
			echo "\nRenamed only (webrev comment generated by "\
			    "$ME, not an sccs comment)\n"
		else
			echo "$filepath"
			echo "\nWarning, file in renamed list but has same "\
			    "name as parent (not an sccs comment)\n"
		fi
	done
	# End of subshell
	) > $wxtmp/webrev.list
	
	# Note that the file list must come last.
	${WXWEBREV:-webrev} -w "$@" $wxtmp/webrev.list

	cd $origdir
}

#
# list all active files
#
wx_active() {
	# do not print hash by default
	typeset rc hash=0
	
	case $1 in
		# list only renamed active files
		-r) list_renamed -a; return 0;;
		# list suitable for putback (both active and renamed)
		-p) list_putback; return 0;;
		# list suitable for webrev (both active and renamed)
		-w) list_webrev; return 0;;
		-*) fail "Invalid flag $1. See 'wx help' for more info.";;
	esac

        if [[ ! -r $wxdir/active ]]; then
                fail "Error: cannot read $wxdir/active"
        fi

	nawk '
	{
	    # skip blank lines
	    while (NF == 0) { 
		    if (getline == 0)
			    next;
	    }
	    if (NF > 0){
		    # print the active filepath
		    print $1;
		    getline;
	    }
	    # skip blank lines
	    while (NF == 0) { 
		    if (getline == 0){
			    # Error, corrupt active list (missing comment)
			    exit 1
		    }
	    }
	    # skip comment
	    while (NF > 0) {
		    if (getline == 0){
			    # Error, blank line after comment missing
			    exit 2
		    }
	    }
	}' $wxdir/active

	rc=$?
	if [[ $rc -eq 1 ]];then
		fail "Corrupt active list (missing comment)."
	elif [[ $rc -eq 2 ]];then
		fail "Corrupt active list (blank line needed after comment)."
	fi
}

#
# show the comment for $filepath
#
wx_show_comment() {
	if [[ -f $wxdir/active ]]; then
		nawk '
		{
			filename=$1
			getline
			while (getline) {
				if (length == 0)
					next
				if (filename == target) {
					if ($0 == "NO_COMMENT") {
							found = 0
							exit 1
					}
					found = 1
					print
				}
			}
		}
		END {
			if (found == 0)
				print "NO_COMMENT"
			exit 1 - found
		}' target=$filepath $wxdir/active
		return $?
	else
		echo "NO_COMMENT"
	fi
}

bugdb_lookup_monaco() {
	typeset buglist=$1
	typeset monaco=/net/monaco.sfbay/export/bin/monaco 

	if [[ ! -x $monaco ]]; then
		return 1
	fi

	$monaco -text <<-EOF
	set What =
	substr(cr.cr_number, 1, 7), synopsis

	set Which =
	cr.cr_number in ($buglist)

	set FinalClauses =
	order by cr.cr_number

	do query/CR
	EOF
}

bugdb_compare() {
	nawk -v bugdb=$1 -v active=$2 -f - <<-"EOF"
	BEGIN {
		file = bugdb
		while (getline < file) {
			synbugdb[$1] = substr($0, length($1) + 1)
		}
		
		file = active
		while (getline < file) {
			synactive = substr($0, length($1) + 1)
			# If the synopsis doesn't match the bug database
			# and the synopsis isn't what's in the database
			# with " (something)" appended, spew a warning.
			if (!($1 in synbugdb)) {
				print "Bug " $1 " is not in the database"
			} else if (synbugdb[$1] != synactive &&
				!(index(synactive, synbugdb[$1]) == 1 &&
				  substr(synactive, length(synbugdb[$1])) ~ \
					/ \([^)]*\)$/)) {
				print "Synopsis of " $1 " is wrong:"
				print "  should be:" synbugdb[$1]
				print "         is:" synactive
			}
		}
	}
	EOF
}

#
# Summarize all comments listing, in order:
#	 - free-form comments
#	 - ARC case comments
#	 - Bug comments
#
# -a will suppress ARC case comments
# -b will suppress bug comments
# -n will do pbchk processing (give all warnings, no error exit)
# -o will suppress free-form (other) comments
# -p will do pbcom checking and exit if it finds problems unless -v is given
# -u will prevent sorting of the ARC case comments and bug comments
# -v will output all comments verbatim (no sorting)
# -N will prevent bug lookup, which may take a while.
#
# Note, be careful when modifying this function as sometimes the output
# should go to stdout, as in the case of being called via pbchk and
# sometimes the output should go to stderr.  Think about this when
# making changes in here.
#

wx_summary() {
	typeset i comment arc arcerr bug bugnospc bugid buglist synopsis \
		show_arcs=true \
		show_bugs=true \
		show_others=true \
		verbatim=false \
		pbchk=false \
		pbcom=false \
		cmd=sort \
		nolookup=false

	while getopts :abnopuvN i; do
		  case $i in
		  a)	show_arcs=false;;
		  b)	show_bugs=false;;
		  n)	pbchk=true;;
		  o)	show_others=false;;
		  p)	pbcom=true;;
		  v)	verbatim=true;;
		  u)	cmd=cat;;
		  N)	nolookup=true;;
		  *)	fail "Invalid flag -$OPTARG. See 'wx help' for more"\
		  		"info.";;
		  esac
	done

	# Store all the comments in a tmp file
	for filepath in $file_list; do
		wx_show_comment
	done | nawk '!seen[$0]++' > $wxtmp/comments

	if grep -q "^NO_COMMENT$" $wxtmp/comments; then
		print -u2 "Warning, found NO_COMMENT. Run '$ME ea' to edit the "\
			  "comments."
		if $pbcom; then
			# Don't want to output anything to stdout for a pbcom
			# if there is an error.
			return 1
		fi
	fi
	if $pbcom && $verbatim; then
		# All comments output verbatim.  Note, is hacky because
		# of the wx_summary interface.  pbcom calls wx_summary
		# with -po assuming other comments shouldn't be output.
		show_others=true
	fi

	# Note, hard tab in the arc regex.  This only recognizes FWARC,
	# LSARC and PSARC.  Also, regex must be compat with both egrep
	# and nawk.
	arc='(FW|LS|PS)ARC[\/ 	][12][0-9][0-9][0-9]\/[0-9][0-9][0-9][^0-9]'
	# bug ID must followed by single space
	bug='[0-9][0-9][0-9][0-9][0-9][0-9][0-9] '
	bugnospc='[0-9][0-9][0-9][0-9][0-9][0-9][0-9][^ ]'

	if $show_arcs; then
		# Note must use /usr/bin/sort.
		if ! egrep "^$arc" $wxtmp/comments |
			 sed 's#\([A-Z][A-Z]*ARC\)[/ 	]#\1 #' | sort |
			 /usr/bin/sort -cu -k 1,2 2>$wxtmp/error >/dev/null
		then
			arcerr=$(nawk '{match($0, '"/$arc/"'); \
				print substr($0, RSTART, RLENGTH);}' \
				$wxtmp/error)

			if $pbchk; then
				# if pbchk print to stdout
				print "Inconsistent ARC summaries for: $arcerr"
			else
				# else print to stderr
				print -u2 \
				"Inconsistent ARC summaries for: $arcerr"
			fi
			if $pbcom && ! $verbatim; then

				# Don't want to output anything to
				# stdout for a pbcom if there is an
				# error.

				return 1
			fi
		fi
	fi

	if $show_bugs; then
		# Treating bug comments with "(nit comment)" at the end as the
		# same as the original bug hence the sed and nawk below
		# Note hard tabs in sed arg.
		# Must use /usr/bin/sort.
		if ! grep "^$bug" $wxtmp/comments |sort|
			 sed 's/[ 	][ 	]*([^)]*) *$//' |
			 nawk '!seen[$0]++'|
			 /usr/bin/sort -cnu 2>$wxtmp/error >/dev/null; then
			if $pbchk; then
				print -n "Inconsistent bug summaries for: "
				sed 's#^[^0-9]*\('"${bug}"'\).*#\1#' \
				    $wxtmp/error
			else
				print -nu2 "Inconsistent bug summaries for: "
				sed 's#^[^0-9]*\('"${bug}"'\).*#\1#' \
				    $wxtmp/error >&2
			fi
			if $pbcom && ! $verbatim; then
				# Don't want to output anything to
				# stdout for a pbcom if there is an
				# error.
				return 1
			fi
		fi

		# Compare bug synopsis in active comments with the bug database.
		# If we've been passed -N, then we just never set buglist, thus
		# skipping the lookup.
		if ! $nolookup; then
			grep "^$bug" $wxtmp/comments | sort > $wxtmp/buglist.active
			cat $wxtmp/buglist.active | while read bugid synopsis; do
				buglist=$buglist,$bugid
			done
			buglist=${buglist#,}
		else
			if $pbchk; then
				print "Not performing bug synopsis check (be careful)"
			else
				print -u2 "Not performing bug synopsis check (be careful)"
			fi
		fi
		if [[ -n $buglist ]]; then
			bugdb_lookup_monaco $buglist > $wxtmp/buglist.bugdb
			if [[ -s $wxtmp/buglist.bugdb && $? -eq 0 ]]; then
				bugdb_compare $wxtmp/buglist.bugdb \
					$wxtmp/buglist.active > $wxtmp/error
				if [[ -s $wxtmp/error ]]; then
					if $pbchk; then
						cat $wxtmp/error
					else
						cat $wxtmp/error >&2
					fi
					if $pbcom && ! $verbatim; then
						# Don't want to output anything
						# to stdout for a pbcom if there
						# is an error.
						return 1
					fi
				fi
			else
				if $pbchk; then
					print "Could not perform bug synopsis check"
				else
					print -u2 "Could not perform bug synopsis check"
					if $pbcom; then
						print -u2 "Use -N to skip bug synopsis check (be careful)"
					fi
				fi
				if $pbcom && ! $verbatim; then
					# Don't want to output anything
					# to stdout for a pbcom if there
					# is an error.
					return 1
				fi
			fi
		fi

		if egrep "^$bugnospc" $wxtmp/comments >$wxtmp/error; then
			# must have single space following bug ID
			if $pbchk; then
				print "\nThese bugs are missing single space following the bug ID"
				print "(output prefaced by active file line number ':'):"
				while read comment
				do
					grep -n "^$comment" $wxdir/active
				done < $wxtmp/error
			else
				print -u2 "\nThese bugs are missing single space following the bug ID"
				print -u2 "(output prefaced by active file line number ':'):"
				while read comment
				do
					grep -n "^$comment" $wxdir/active >&2
				done < $wxtmp/error
			fi
			if $pbcom && ! $verbatim; then
				# Don't want to output anything to
				# stdout for a pbcom if there is an
				# error.
				return 1
			fi
		fi
	fi

	# Create warning for pbchk or pbcom.
	if $pbchk || ($pbcom && ! $verbatim) &&
		egrep -v "^($bug|$bugnospc|$arc|NO_COMMENT$)" $wxtmp/comments\
				> $wxtmp/other_comments; then
		cat <<-EOF
Warning, the following comments are found in your active list
that are neither bug or arc cases: 

		EOF
		cat $wxtmp/other_comments
		print -- "\n---- End of active list comment warnings ----"
	fi > $wxtmp/comment_warning

	if [[ -s $wxtmp/comment_warning ]]; then
		if $pbchk; then
			# output to stdout, don't exist in case there are more
			# warnings.
			cat $wxtmp/comment_warning
		elif $pbcom && ! $verbatim ; then
			# Don't want to output anything to stdout for a pbcom
			# if there is an error.
			cat $wxtmp/comment_warning >&2
			return 1
		fi
	fi

	if $pbchk; then
		cd $workspace
		# See if sccs delta comment is the same as active list comment
		for filepath in $file_list; do
			# extract most recent delta comment
			sccs prs -d ':C:' $filepath | sort > $wxtmp/com1 ||
				fail "sccs prs -d ':C:' $filepath failed."

			# Add blank line to active comments so following cmp will
			# work properly.
			(wx_show_comment; print) | sort > $wxtmp/com2

			if ! cmp -s $wxtmp/com1 $wxtmp/com2; then
				print "\n$filepath"
				print "Warning: current sccs comment does not"\
					"match active list comment"
				print "(< sccs comment, > active list comment):"
				diff $wxtmp/com1 $wxtmp/com2 
			fi
		done 
		# Just output warnings for pbchk
		return 0
	fi

	if $show_others; then
		  if ! $verbatim; then
			  # The non-verbatim check should have produced the
			  # other_comments file.
			  cat $wxtmp/other_comments| $cmd
		  else
			  # just output comments verbatim then return
			  cat $wxtmp/comments
			  return 0
		  fi
	fi

	if $show_arcs; then
		  egrep "^$arc" $wxtmp/comments | $cmd
	fi

	if $show_bugs; then
		  egrep "^$bug" $wxtmp/comments | $cmd
	fi
	return 0
}

update_renamed_file() {
	# Try to add a entry to the renamed list.  Note, this stores the new
	# name and previous name, not the  parent name as this is more useful in
	# detecting cyclic renames.

	# ofp: old filepath, nfp: new filepath
	typeset ofp=$1 nfp=$2

	# remove old and new entries from renamed
	egrep -v "^($(escape_re $ofp)|$(escape_re $nfp)) " $wxdir/renamed \
		>$wxtmp/renamed
	[[ ! -f $wxtmp/renamed ]] && fail "Error: cannot create $wxtmp/renamed"
	mv -f $wxtmp/renamed $wxdir/renamed || \
		fail "Error: cannot create $wxdir/renamed."

	# remove old entries from local nt cache
	remove_local_nt_entry $ofp

	# Do not update renamed list if the filepath is the same as
	# the parent or the file is new.
	if lookup_parent $nfp; then
		if [[ $parentfile != $nfp ]]; then
			print "$nfp $ofp" >> $wxdir/renamed || \
				fail "Error: cannot append $wxdir/renamed."
			
			[[ $ACTSORT == sort ]] && do_renamed_sort=true
		fi
	fi
	return 0
}

update_renamed_dir() {
	typeset append pb_files new orig
	typeset -i rc

	if [[ $# -eq 0 ]]; then
		# No args so we need to create the renamed list from
		# the source root.
		append=false
		if [ -r $wxdir/srcroot_dir ]; then
			pb_files=$(cat $wxdir/srcroot_dir)
		else
			pb_files=$DEFAULT_SRCDIR
		fi
	else
		# Assuming one or more filepaths as args
		append=true
		pb_files="$*"
	fi
	echo "Updating $ME renamed list... this may take several minutes."

	# Get output of putback -n to detect renames elsewhere in
	# this script. 

	get_pb_output $pb_files

	nawk '
		/^rename from:/{orig_file=$3}
		$1 == "to:" {print $2 " " orig_file}' \
		$wxtmp/putback.out  >$wxtmp/pb_renames || \
			fail "Error, creation of $wxtmp/pb_renames failed."

	cp $wxdir/renamed $wxdir/renamed.old || 
		fail "Error: cannot create $wxdir/renamed.old."

	if $append; then
		nawk '!seen[$0]++' $wxtmp/pb_renames $wxdir/renamed \
			> $wxtmp/renamed || \
			fail "Error: cannot create $wxtmp/renamed."
		mv -f $wxtmp/renamed $wxdir/renamed || \
			fail "Error: cannot create $wxdir/renamed."
	else
		mv -f $wxtmp/pb_renames $wxdir/renamed ||
			fail "Error: cannot create $wxdir/renamed."
	fi

	[[ $ACTSORT == sort ]] && do_renamed_sort=true
}

# returns 0 if a pattern in patternfile matches input path arg
pathcheck() {
	typeset pattern path=$1 patternfile=$2

	while read pattern; do
		if [[ $path == $pattern ]]; then
			return 0 # pattern matched path
		fi
	done < $patternfile
	return 1 # file path not matched by pattern
}

#
# Evaluate a command for all listed files.  This is the basic building
# block for most wx functionality.
#

wx_eval() {
	typeset -i changedir=1

	if [[ $# -gt 1 && "$1" == "-r" ]]; then
		changedir=0
		shift
	fi

	pre_eval=$*
	# skip files listed in .NOT files
	cat -s $wxdir/$command.NOT >$wxtmp/NOT
	for filepath in $file_list; do
		if pathcheck $filepath $wxtmp/NOT; then
			print "$filepath (skipping)"
		else
			cd $workspace
			dir=`dirname $filepath`
			file=`basename $filepath`
			[[ $changedir -eq 1 ]] && cd $dir
			eval $pre_eval
		fi
	done
}

#
# Initialize a workspace for wx.
#

wx_init() {
	typeset srcroot_dir force=false

	# check that srcroot is relative to top of workspace
	if cd $workspace/$1; then
		# normalize the srcroot dir for test below
		srcroot_dir=$(/bin/pwd)
		srcroot_dir="${srcroot_dir#$workspace/}"
		if [[ $srcroot_dir == $workspace ]]; then
			# Special case need to set srcroot_dir to
			# a relative path but we're at the top of the
			# workspace.
			srcroot_dir="."
		fi
	else
		fail "Source root '$1' does not exist in workspace"\
			"($workspace)."
	fi

	if [ -d $wxtmp ]; then
                if [[ $2 != -f[nqt] ]]; then
                        echo "This workspace has already been initialized."
                        ok_to_proceed 'Do you really want to re-initialize?'
                fi
	else
		mkdir -p $wxtmp
	fi

	#
	# Make sure to save $srcroot_dir as a path relative to the workspace
	# root; an absolute path would break if the workspace name changed.
	#
	rm -f $wxdir/srcroot_dir
	echo $srcroot_dir >$wxdir/srcroot_dir

	backup_dir=$HOME/$ME.backup/$workspace_basename
	[[ -d $backup_dir ]] || mkdir -p $backup_dir ||
		fail "mkdir -p $backup_dir failed."
	cd $backup_dir
	rm -f $wxdir/backup_dir
	pwd >$wxdir/backup_dir || fail "Creation of  $wxdir/backup_dir failed." 

	touch $wxdir/renamed
	touch $wxdir/active
	touch $wxdir/new
	touch $wxdir/local_nametable 

	if [[ -z "$2" ]]; then
		# Interactive mode
		cat << EOF
    Pick one of the following update methods:

    1) Thorough: Detect any differences between the current workspace
       and its parent and update the active, new and renamed lists.  Use
       this in workspaces where files have been renamed or deleted or
       there are files that are different from the parent that are not
       checked out.  Note, files must be under SCCS control in order for
       this method to compare them to the parent workspace.

    2) Quick: Only update the active list with files that are currently
       checked out.  Will not update the renamed list.

    3) None: Use this on workspaces where there are no changes between
       the workspace and its parent.  This is very quick but will not
       update the active, new or renamed lists.

EOF
		read answer?"Which update method? [1|2|3]: "
		case $answer in
			1) wx_update;;
			2) wx_update -q;;
			3) ;;
			*) fail "Bad answer: ${answer}. Rerun init command"\
				"again";;
		esac
		yesno "Keep active list sorted by default?"
		if [[ "$answer" == 'yes' ]]; then
			print "true" > $wxdir/sort_active
		else
			print "false" > $wxdir/sort_active
		fi
	else
		# non-interactive mode
		case $2 in
			# forced thorough update
			-ft) wx_update; force=true;;
			# forced quick update
			-fq) wx_update -q; force=true;;
			# forced no update
			-fn) force=true;;
			# invalid arg
			-*) fail "$ME $command: unrecognized argument";;
		esac
		if [[ $3 == -s ]]; then
			print "true" > $wxdir/sort_active
		else
			print "false" > $wxdir/sort_active
		fi
	fi
	print

	if [ -s $wxdir/active ]; then
		basedir=$workspace
		file_list=`wx_active`
		if $force; then
			# only backup if necessary
			print "Will backup wx and active files if necessary"
			wx_backup -t
		else
			print "Making backup copies of all wx and active files"
			wx_backup
		fi
	else
		echo "Active list empty, not doing backup."
		echo
	fi

	echo "$ME initialization complete"
}

#
# Find all checked out files
#

wx_checked_out() {
	typeset origdir=$(pwd)
	cd $workspace
	x=$(ls -t $wsdata/nametable $wxdir/sccs_dirs 2>/dev/null)
	if [[ -z $x || "`basename $x`" == nametable ]]; then
		if [ -f $wxdir/srcroot_dir ]; then
			srcroot_dir=`cat $wxdir/srcroot_dir`
		else
			srcroot_dir=$DEFAULT_SRCDIR
		fi
		print -u2 "Workspace nametable changed: sccs_dirs out of date"
		print -u2 "Updating $wxdir/sccs_dirs...this may take a few minutes.\n"
		rm -f $wxdir/sccs_dirs
		find $srcroot_dir -name SCCS -print | sort >$wxdir/sccs_dirs
	fi
	cd $workspace
	rm -f $wxtmp/checked_out
	# Note if srcroot_dir = . this must be removed from the front of the
	# filepaths.
	echo $(sed -e 's,$,/p.*,' $wxdir/sccs_dirs) | \
		tr \\040 \\012 | \
		grep -v '*' | \
		sed -e 's,SCCS/p.,,' |sed -e 's,^\./,,' >$wxtmp/checked_out
	cd $origdir
}

deal_ws_renames() {
	# See if any active/renamed files were renamed externally
	# (perhaps by bringover?) and try to rename the active entry
	# filepath.
	typeset fp newfp renamed localfile hash1 hash2 hash3 hash4 \
		notrenamed_list origdir=$(pwd)
	cd $workspace
	list_putback |\
	while read fp; do
		if [[ ! -f $fp ]]; then
			# file not found, suspect rename.
			# using renamed for error checking.
			renamed=false
			# search cached local nt to find old hash info
			grep "^$(escape_re $fp) " $wxdir/local_nametable |\
			while read localfile hash1 hash2 hash3 hash4; do
				# find new filepath
				newfp=$(fgrep " $hash1 $hash2 $hash3 $hash4"\
					$wsdata/nametable|cut -f1 -d' ')

				[[ -z $newfp ]] && continue

				if [[ $newfp != $fp ]]; then
					update_renamed_file $fp $newfp 
					rename_active_entry $fp $newfp
					echo "\nRenamed active file"\
						"$fp to $newfp"
					renamed=true
					break
				fi
			done
			if ! $renamed; then
				if [[ -z $notrenamed_list ]]; then
					notrenamed_list="$fp"
				else
					notrenamed_list="$notrenamed_list\n$fp"
				fi
			fi
		fi
	done
	if [[ -n $notrenamed_list ]]; then
		ring_bell
		cat <<-EOF
Warning, active file(s):
   $(echo $notrenamed_list)
not found and cannot be renamed.  Use "$ME ea" to edit the active list to
remove these entries if they do not exist in this workspace.
		EOF
	fi
	cd $origdir
}

#
# Old style update the active file list (by appending all checked out files).
# This is what the original wx update did.
#
wx_update_quick() {

	# Sort active if requested.
	[[ "$1" == "-s" ]] && ACTSORT=sort

	wx_checked_out
	cd $wxdir
	rm -f tmp/files.old tmp/files.new active.new
	wx_active >tmp/files.old || fail "Error: cannot create $wxtmp/files.old"
	# sed has a hard tab, used to delete lines containing only whitespace
	sed '/^[	 ]*$/d' tmp/files.old tmp/checked_out|
		nawk '!seen[$0]++' | $ACTSORT > tmp/files.new ||
			fail "Error: cannot create $wxtmp/files.new"
	cp -f new new.old || fail "Error: cannot create new.old."
	while read filepath ; do
		add_local_nt_entry $filepath
		(echo "$filepath"; echo; wx_show_comment; echo) 
	done < tmp/files.new > active.new || 
		fail "Error: cannot create $wxdir/active.new"

	mv -f active active.old
	mv -f active.new active

	echo
	echo "New active file list:"
	echo
	cat tmp/files.new
	echo
	echo "Diffs from previous active file list:"
	echo
	${WXDIFFCMD:-diff} tmp/files.old tmp/files.new
	echo "End active diffs =========================="

	# Do new file processing after active list is updated.

	# Note, the parent nt read check below is hackish because we are
	# assuming that lookup_parent needs to read the parent nt and if it
	# can't then we want to just issue the warning.
	if [[ -n $parent && ! -r $parent/Codemgr_wsdata/nametable ]]; then
		echo "\nWarning: cannot read parent nametable, new file list"\
			"not output." >&2
	else
		while read filepath; do
			# lookup_parent populates local nt cache
			if lookup_parent $filepath; then
				remove_new $filepath
			else
				add_new $filepath
			fi
		done < tmp/files.new

		echo
		echo "New new-file list:"
		echo
		cat new
		echo
		echo "Diffs from previous new-file list:" 
		echo
		${WXDIFFCMD:-diff} new.old new
		echo "End new diffs =========================="
	fi
}

#
# Update various lists (active, renamed, new)
#

wx_update() {
	typeset i efp sortarg do_quick=false
	typeset -i rc found
	# default, update all lists
	typeset update_active=true update_renamed=true update_new=true

	while getopts :qrs i; do
		  case $i in
		  q)	do_quick=true;;
		  r)	update_active=false
			update_new=false;;
		  s)	ACTSORT=sort; sortarg="-s";;
		  *)	fail "Invalid flag -$OPTARG. See 'wx help' for more"\
		  		"info.";;
		  esac
	done

	deal_ws_renames

	if $do_quick; then
		# Do old school wx update (only for checked out files)
		# This is faster but not as thorough.
		wx_update_quick $sortarg
		return
	fi

	if [[ -z $parent ]]; then
		fail "Error: cannot do thorough update, no parent.  Use 'update -q'"\
			"instead."
	fi
	if [[ ! -r $parent/Codemgr_wsdata/nametable ]]; then
		fail "Error: cannot read $parent/Codemgr_wsdata/nametable"
	fi

	# create tmp/checked_out file which putback -n may not list.
	# Do this before putback so it doesn't unnecessarily update the
	# sccs dirs cache.
	wx_checked_out 

	# Get output of putback -n to detect renames and active files.
	if [ -f $wxdir/srcroot_dir ]; then
		get_pb_output $(cat $wxdir/srcroot_dir)
	else
		get_pb_output $DEFAULT_SRCDIR
	fi

	cd $wxdir

	if $update_renamed; then
		if [[ -f renamed ]]; then
			mv renamed renamed.old ||
			    fail "Error: cannot create $wxdir/renamed.old."
		else
			touch renamed.old ||
			    fail "Error: cannot create $wxdir/renamed.old."
		fi

		nawk '  /^rename from:/{orig_file=$3}
			$1 == "to:" {print $2 " " orig_file}' \
			tmp/putback.out |$ACTSORT > tmp/renamed ||\
				fail "Error, creation of $wxdir/tmp/renamed failed."
			mv -f tmp/renamed renamed || \
				fail "Error: cannot create $wxdir/renamed"

		for filepath in $(cut -f1 -d' ' renamed); do
			add_local_nt_entry $filepath
		done

		echo "New renamed file list:"
		echo
		cat renamed
		echo
		echo "Diffs from previous renamed file list:"
		echo
		${WXDIFFCMD:-diff} renamed.old renamed
		echo "End renamed diffs =========================="
	fi

	if $update_active; then
		# Create active list from putback output.
		nawk '/^(update|create): / {print $2};
		     /^The following files are currently checked out/ \
			{p=1; continue};
		     /^"/ {continue};
		     NF == 0 {p=0; continue};
		     {if (p==1)
		     	print $1}' tmp/putback.out |
		     sort -u > tmp/active_nawk_out ||
		     fail "Error: cannot create $wxtmp/active_nawk_out"

		# list files in conflict also
		nawk '/^(conflict): / {print $2}' tmp/putback.out |
		    sort -u > tmp/conflict_nawk_out ||
		    fail "Error: cannot create $wxtmp/conflict_nawk_out"

		# Need to read $wsdata/nametable if there are conflicts
		if [[ -s tmp/conflict_nawk_out && ! -r $wsdata/nametable ]]
		then
			fail "Error: cannot read $wsdata/nametable."
		fi

		# clear the tmp active file
		print -n > tmp/active.new || fail "Error: cannot create tmp/active.new."

		# store current active list
		wx_active > tmp/files.old ||
			fail "Error: cannot create $wxtmp/files.old"

		# go through all the possible active files (keeping the existing
		# ones as well). Note hard tab in sed arg.
		for filepath in $(sed '/^[	 ]*$/d' tmp/files.old \
			tmp/checked_out tmp/conflict_nawk_out \
			tmp/active_nawk_out | nawk '!seen[$0]++' | $ACTSORT); do

			efp=$(escape_re $filepath)

			if grep -q "^$efp$" tmp/conflict_nawk_out; then

				# conflict files have a parent but the
				# putback output only shows the parent's
				# filename, need to find local name in
				# case of rename

				grep "^$efp " $parent/Codemgr_wsdata/nametable|\
					read localfile hash1 hash2 hash3 hash4
				local_file="$(\
				    fgrep " $hash1 $hash2 $hash3 $hash4" \
					$wsdata/nametable | cut -f1 -d' ')"

				# continue if empty string
				[[ -z "$local_file" ]] && continue

				if ! grep -q "^$local_file" tmp/active.new; then
					filepath=$local_file
				else
					continue
				fi
			fi
			add_local_nt_entry $filepath
			(echo $filepath; echo; wx_show_comment; echo)\
			    >> tmp/active.new
		done

		rm -f tmp/active_nawk_out

		mv -f active active.old
		mv -f tmp/active.new active
		wx_active > tmp/files.new

		echo
		echo "New active file list:"
		echo
		cat tmp/files.new
		echo
		echo "Diffs from previous active file list:" 
		echo
		${WXDIFFCMD:-diff} tmp/files.old tmp/files.new
		echo "End active diffs =========================="
		rm -f tmp/files.old tmp/files.new

	fi

	# The new list is for caching names of new files to speed up commands
	# that list the new files.
	if $update_new; then
		if [ -f new ]; then
			cp -f new new.old || fail "Error: cannot create file new.old."
		elif [ ! -f new.old ]; then
			touch new.old || fail "Error: cannot create file new.old."
		fi
		# Create new list from putback output.
		nawk '/^create: / {print $2};' tmp/putback.out |
			sort -u > tmp/new || fail "Error: cannot create $wxtmp/new."
		mv -f tmp/new new
		echo
		echo "New new-file list:"
		echo
		cat new
		echo
		echo "Diffs from previous new-file list:" 
		echo
		${WXDIFFCMD:-diff} new.old new
		echo "End new diffs =========================="
	fi
}

wx_edit() {
	# Must be called via wx_eval
	if [ -f SCCS/p.$file ]; then
		echo "$filepath already checked out"
		update_active $filepath
	elif [ -f $file ]; then
		echo $filepath
		if sccs edit $silent $file; then
			update_active $filepath
		else
			fail "sccs edit $filepath failed."
		fi
	else
		ring_bell
		echo "Warning. file $filepath not found."
	fi

	[[ $ACTSORT == sort ]] && do_active_sort=true
}

wx_unedit() {
	# Must be called via wx_eval
	typeset -i force=0
	typeset arg msg

	# set positional args to contents of global $args
	set -- $args

	while getopts :f arg; do
		case $arg in
			 f) force=1;;
			 *) fail "Invalid flag -$OPTARG. See 'wx help' for"\
			 	"more info.";;
		esac
	done

	msg="differs from parent file, will remain in active list."

	if [[ ! -f SCCS/p.$file ]]; then
		echo "$filepath not checked out"
	else
		if [[ $backup_done -eq 0 ]]; then
			if [[ $force -eq 0 ]]; then
				yesno "Do you want to backup files first?"
				if [[ "$answer" == "yes" ]]; then
					wx_backup || fail "Backup failed."
				fi
			else
				# only backup if necessary
				print "Will backup wx and active files if necessary"
				wx_backup -t || fail "Backup failed."
			fi
			backup_done=1;

			# cd to the dir where the file is in case
			# wx_backup took us somewhere else.

			cd ${workspace}/$dir
		fi

		echo $filepath
		if sccs unedit $silent $file; then
			if [[ $force -eq 1 ]]; then
				if is_active $filepath; then
					if wx_pnt_filepath $filepath; then
						if cmp -s $file $parentfilepath; then
							remove_active_entry $filepath
						else
							print "$filepath $msg"
						fi
					fi
				fi
			else
				ask_remove_active_entry
			fi
		fi
	fi
}

wx_create() {
	# Must be called via wx_eval
	typeset -i checkout=0 force=0
	typeset arg

	while getopts :fo arg; do
		case $arg in
			 o) checkout=1;;
			 f) force=1;;
			 *) fail "Invalid flag -$OPTARG. See 'wx help' for"\
			 	"more info.";;
		esac
	done

	if [ ! -f $file ]; then
		ring_bell
		echo "Error! $filepath is not a file."
		return 1
	elif [ -f $workspace/deleted_files/$filepath ]; then
		ring_bell
		cat >&2 <<-EOF
Error: a deleted version of $filepath exists.
You must undelete the file and edit that version.
Run:
'cd $workspace'
'$ME mv deleted_files/$filepath $filepath'
'$ME edit $filepath'
		EOF
		return 1
	elif [[ -n $parent && -f $parent/$filepath ]]; then
		ring_bell
		cat >&2 <<-EOF
Error! $filepath exists in the parent workspace $parent.
Choose a different name.
		EOF
		return 1
	elif [[ -n $parent && -f $parent/deleted_files/$filepath ]]; then
		ring_bell
		cat >&2 <<-EOF
Error! a deleted version of $filepath exists in the parent workspace
You must undelete the file and edit that version.
Run:
'cd $workspace'
'bringover deleted_files/$filepath'
'$ME mv deleted_files/$filepath $filepath'
'$ME edit $filepath'
		EOF
		return 1
	elif [ -f SCCS/s.$file ]; then
			echo "$filepath already created, active list not"\
				"updated." >&2
	else
		# XXX it would be nice if keyword would work on new files
		if ! egrep "$SCCSKEYWORD" $file >/dev/null; then
			ring_bell
			cat >&2 <<-EOF

Warning!!!
$filepath 
is missing SCCS keywords.  See
/net/wizard.eng/export/misc/general_docs/keyword_info.txt
for more info.  Note, pay attention to the tabs.
			EOF
			if [[ $force -ne 1 ]]; then
				yesno "Continue with create?" 
				if [[ "$answer" != 'yes' ]]; then
					echo "Aborting create $filepath"
					return 1
				fi
			fi
		fi

		if ! copyrightchk $file; then
			# Sound bell
			ring_bell
			cat >&2 <<-EOF

Warning!!!
$filepath 
has copyright problems.  See
/net/wizard.eng/export/misc/general_docs/golden_rules.txt
for more info.
			EOF
			if [[ $force -ne 1 ]]; then
				yesno "Continue with create?" 
				if [[ "$answer" != 'yes' ]]; then
					echo "Aborting create $filepath"
					return 1
				fi
			fi
		fi

		if ! cddlchk -a $file; then
			# Sound bell
			ring_bell
			cat >&2 <<-EOF

Warning!!!
$filepath 
has CDDL block problems.  See
http://www.opensolaris.org/os/community/onnv/devref_toc/devref_7/#7_2_3_nonformatting_considerations
for more info.
			EOF
			if [[ $force -ne 1 ]]; then
				yesno "Continue with create?" 
				if [[ "$answer" != 'yes' ]]; then
					echo "Aborting create $filepath"
					return 1
				fi
			fi
		fi

		if [[ ! -d SCCS ]]; then
			mkdir SCCS || fail "Error: cannot create SCCS dir."
		fi

		if [[ -n "$comment_file" ]]; then
			sccs create $silent -y"$(\
			    sed '/^[ 	]*$/d' $comment_file)" $file ||
				    fail "sccs create $filepath failed."
		else
			sccs create $silent $file ||
				fail "sccs create $filepath failed."
		fi
		rm -f ,$file
		update_active $filepath
		add_new $filepath
		if [[ $checkout -eq 1 ]]; then
			sccs edit $silent $file ||
				fail "sccs edit $filepath failed."
		fi
		[[ $ACTSORT == sort ]] && do_active_sort=true
	fi
}

wx_uncreate() {
	# Must be called via wx_eval
	# undoes a 'wx create'

	typeset efp
	typeset -i force=0

	case $1 in
		-f) force=1;;
		-*) fail "$ME $command: unrecognized argument";;
	esac

	if [[ $backup_done -eq 0 ]]; then
		if [[ $force -eq 0 ]]; then
			yesno "Do you want to backup files first?"
			if [[ "$answer" == 'yes' ]]; then
				wx_backup || fail "Backup failed."
			fi
		else
			# only backup if necessary
			print "Will backup wx and active files if necessary"
			wx_backup -t || fail "Backup failed."
		fi
		backup_done=1;
		cd $workspace/$dir
	fi

	if [[ ! -f $file ]]; then
		echo "$filepath not found, skipping"
		return 1
	fi

	efp=$(escape_re $filepath)

	if ! wx_pnt_filepath; then
		# This is a new file so let's uncreate it.
		answer='no'
		if [[ $force -ne 1 ]]; then
			cat <<-EOF

$filepath appears to be a new file.  
Note, $command will remove its SCCS info from your
workspace and entry in the active list but will leave
the file in your workspace.  

			EOF
			# yesno sets answer
			yesno "Continue $command $filepath?"
		else
			# forced to yes
			answer='yes'
		fi

		if [[ "$answer" == 'yes' ]]; then
			if [[ ! -f SCCS/p.$file ]]; then
				sccs edit $file ||
				    fail "sccs edit $filepath failed."
			fi
			rm -f SCCS/s.$file SCCS/p.$file
			# For later cleanup on exit
			if grep -q "^$efp " $wsdata/nametable 2>/dev/null; then
				NEED_WS_CLEAN='y'
			fi
		
			if is_active $filepath; then
				remove_active_entry $filepath
			fi
			remove_new $filepath
		else
			echo "skipping $filepath"
		fi
	else
		echo "Not new, skipping $filepath"
	fi # if ! wx_pnt_filepath
}

wx_reset() {
	# Must be called via wx_eval
	# resets a local file to the parent version

	typeset efp
	typeset -i force=0

	case $1 in
		-f) force=1;;
		-*) fail "$ME $command: unrecognized argument";;
	esac

	if [[ $backup_done -eq 0 ]]; then
		if [[ $force -eq 0 ]]; then
			yesno "Do you want to backup files first?"
			if [[ "$answer" == 'yes' ]]; then
				wx_backup || fail "Backup failed."
			fi
		else
			# only backup if necessary
			print "Will backup wx and active files if necessary"
			wx_backup -t || fail "Backup failed."
		fi
		backup_done=1;
	fi

	if [[ ! -f $file ]]; then
		print "$filepath not found, skipping"
		return 1
	fi

	efp=$(escape_re $filepath)

	if wx_pnt_filepath; then
		if [[ $force -ne 1 ]]; then
			answer='no' # safe default
			cat <<-EOF

Regarding: $filepath
$command will reset the file contents and sccs history to that of the parent:
$parentfilepath
and remove the entry from the active and renamed lists.

			EOF
			if [[ $filepath != $parentfile ]]; then
				print "Note: local file will be reset to parent filepath."
			fi
			# yesno sets answer
			yesno "Continue $command $filepath?"
		else
			# forced to yes
			answer='yes'
		fi

		if [[ "$answer" == 'yes' ]]; then
			if is_active $filepath; then
				remove_active_entry $filepath
			fi
			if renamed; then
				remove_renamed_entry $filepath
			fi
			rm -f $file SCCS/[ps].$file
			grep -v "^$efp " $wsdata/nametable > $wxtmp/nametable.new || \
				fail "Error: cannot create $wxtmp/nametable.new ."
			mv -f $wxtmp/nametable.new $wsdata/nametable || \
				fail "Error: mv -f $wxtmp/nametable.new $wsdata/nametable failed."

			# add to bringover list for more efficient bringover
			bofilelist="$bofilelist $parentfile"
		else
			print -u2 "Skipping $filepath"
		fi
	else
		cat >&2 <<-EOF

Warning: skipping $filepath 
as it appears to be new. Use 'uncreate' to remove this new file from the
workspace.
		EOF
	fi # if ! wx_pnt_filepath
}


cyclic_rename() {
	# Detect the cyclic rename that causes Teamware problems.
	# See 'man workspace' for more info
	typeset new_filepath=$1 old_filepath=$2\
		found_new=false found_old=false
	typeset prev_new prev_old

	while read prev_new prev_old; do
		if [[ "deleted_files/$new_filepath" == $prev_new &&
			  $old_filepath != $prev_new ]]; then

			# Cyclic rename
			return 0
		fi

		if [[ $new_filepath == $prev_old && $prev_new != $old_filepath ]]
		then
			# The new file was the old file of a previous rename
			found_new=true
			if $found_old; then
				# Cyclic rename
				return 0
			fi
		elif [[ $old_filepath == $prev_new && 
		    $new_filepath != $prev_old ]]; then

			# The old filepath was the new filepath of a
			# previous rename and this rename is not an undo
			# (new filepath is diff from previous old
			# filepath)

			found_old=true
			if $found_new; then
				# Cyclic rename
				return 0
			fi
		fi
	done < $wxdir/renamed

	# Not a cyclic rename
	return 1
}

wx_delete() {
	# Must be called via wx_eval
	typeset efp
	typeset -i force=0

	case $1 in
		-f) force=1;;
		-*) fail "$ME $command: unrecognized argument";;
	esac

	if [[ $backup_done -eq 0 ]]; then
		if [[ $force -eq 0 ]]; then
			yesno "Do you want to backup files first?"
			if [[ "$answer" == 'yes' ]]; then
				wx_backup || fail "Backup failed."
			fi
		else
			# only backup if necessary
			print "Will backup wx and active files if necessary"
			wx_backup -t || fail "Backup failed."
		fi
		backup_done=1;
		cd $workspace/$dir
	fi

	if [[ ! -f $file ]]; then
		fail "$filepath isn't a file."
	fi

	# this is used a couple times so save escape_re value
	efp=$(escape_re $filepath)

	if wx_pnt_filepath; then
		# Not a new file (has a parent)
		if is_active $filepath; then
			ring_bell
			cat >&2 <<-EOF

Warning! $filepath 
is in active list. You should run
"$ME reedit $filepath" 
"$ME unedit $filepath" 
which should remove it from the active list then run 
"$ME $command $filepath".
Note, if you have made changes to this file that you want to keep, back
it up first.

$filepath not deleted.

			EOF
			return 1
		fi
		# See if this is already in the renamed list
		if grep -q "^deleted_files/$efp " $wxdir/renamed; then
			ring_bell
			if [[ -f $workspace/deleted_files/$filepath ]]; then
				cat >&2  <<-EOF
Warning: $filepath
has already been deleted.
Check for deleted_files/$filepath
in $wxdir/renamed .
				EOF
			else
				cat >&2 <<-EOF
Warning! the $ME renamed list appears to be corrupt.
				EOF
				fail "Please run '$ME update -r' and try this"\
					"command again."
			fi
		fi
		if workspace filerm $file; then
			# we know filerm renames files under deleted_files/
			update_renamed_file $filepath deleted_files/$filepath

			print "$filepath deleted"
			print
			print "To recover $filepath do:"
			print "'cd $workspace'"
			print "'$ME mv deleted_files/$filepath $filepath'"
		else
			print "There was an error while trying to delete $filepath"
		fi
	else
		# This is a new file so let's remove it.
		if is_active $filepath; then
			ring_bell
			cat >&2 <<-EOF

Warning: $filepath 
is in active list. You should run
"$ME uncreate $filepath" 
which should remove it from the active list
then run "$ME $command $filepath". 

$filepath not deleted.

			EOF
			return 1
		fi

		answer='no'
		if [[ $force -ne 1 ]]; then
			cat <<-EOF

Warning: $filepath 
appears to be a new file.

Do you want to completely remove the file and SCCS info from 
your workspace?  (If you answer no, the file will just be 
removed from the active list if it's in there.  If you answer 
yes, the file and associated SCCS history files will removed 
from the active list and also removed entirely from the 
workspace.)

			EOF
			# yesno sets answer
			yesno "Completely remove $filepath?"
		else
			# forced to yes
			answer='yes'
		fi

		if [[ "$answer" == 'yes' ]]; then
			rm -f $file SCCS/s.$file 
			[[ -f SCCS/p.$file ]] && rm -f SCCS/p.$file
			echo "$filepath removed from workspace."
			# For later cleanup, optional
			if grep -q "^$efp " $wsdata/nametable 2>/dev/null; then
				NEED_WS_CLEAN='y'
			fi
		fi
		remove_new $filepath
	fi
}

wx_mv() {
	# create some local variables to avoid side effects
	typeset efp old_filepath new_filepath

	cd $workspace

	old_filepath=$1
	new_filepath=$2

	if [[ -d $old_filepath && ( -d $new_filepath || ! -f $new_filepath ) ]]
	then

		if [[ $(basename $old_filepath) == "SCCS" ]]; then
			return
		fi

		echo "Doing a $command between two directories can take a "\
		    "while, please be patient."
		# deal with directory to directory move
		if [[ -d $new_filepath ]]; then
			base="$(basename $old_filepath)/"
		else
			base=
		fi

		sccsmv $old_filepath $new_filepath ||
		    fail "sccsmv $old_filepath $new_filepath failed."

		# remove previous renamed entry
		remove_renamed_entry $old_filepath
		
		update_renamed_dir $new_filepath/$base

		if grep -q "^$efp/" $wsdata/nametable 2>/dev/null; then
			# Old entries in workspace nametable so set this
			# to clean up on exit
			NEED_WS_CLEAN='y'
		fi

		# rename path of active entry
		sed "s|^$efp/|$new_filepath/$base|" $wxdir/active \
			   > $wxtmp/active || fail "Error: cannot create $wxtmp/active."
		mv $wxtmp/active $wxdir/active ||
			fail "Error: cannot create $wxdir/active."
		sed "s|^$efp/|$new_filepath/$base|" $wxdir/new \
			   > $wxtmp/new || fail "Error: cannot create $wxtmp/new."
		mv $wxtmp/new $wxdir/new || fail "Error: cannot create $wxdir/new."
		
	elif [[ -f $old_filepath && -d $new_filepath ]]; then
		wx_mv_file $old_filepath $new_filepath/$(basename $old_filepath)
	elif [[ -f $old_filepath && ! -f $new_filepath ]]; then
		wx_mv_file $old_filepath $new_filepath
	elif [[ ! -f $old_filepath ]]; then
		fail "Error! $old_filepath not found."
	elif [[ -f $new_filepath ]]; then
		fail "Error! $new_filepath exists."
	fi
}

wx_mv_file() {
	# store literal filepath in local var. to avoid side effects
	typeset efp old_filepath new_filepath

	cd $workspace

	old_filepath=$1
	new_filepath=$2

	if [[ ! -f $old_filepath ]]; then
		fail "Error! $old_filepath does not exist."

	elif [[ -f $new_filepath ]]; then
		fail "Error! $new_filepath already exists."

	else
		if cyclic_rename $new_filepath $old_filepath; then
			fail "Cyclic renamed detected. See 'man workspace'"\
				"for more info."
		fi

		if workspace filemv $old_filepath $new_filepath; then
			update_renamed_file $old_filepath $new_filepath 
			efp=$(escape_re $old_filepath)
			if is_active $old_filepath; then
				# In active list so update list with new
				# file name
				rename_active_entry $old_filepath $new_filepath
			fi
			if grep -q "^$efp$" $wxdir/new; then
				remove_new $old_filepath
				add_new $new_filepath
			fi
			if grep -q "^$efp " $wsdata/nametable 2>/dev/null; then
				NEED_WS_CLEAN=y
			fi
		else
			echo "There was an error renaming $old_filepath to "\
			    "$new_filepath"
		fi
	fi
}

sccs_rmdel_done() {
	# Note there are literal tabs in the []'s below so be careful when
	# editing.

	# file not in SCCS so return false (1)
	[[ ! -f SCCS/s.$file ]] && return 1

	if wx_pnt_filepath; then
		sccs prt -a $parentfilepath > $wxtmp/parenthist
		sccs prt -a $file > $wxtmp/filehist
		diff $wxtmp/parenthist $wxtmp/filehist |
			grep '^> R [0-9]\.[0-9]'|
			egrep -v ' (Codemgr|Fake)[ 	]' |
			sed 's/^> //' > $wxtmp/newrmdels
		[[ ! -f $wxtmp/newrmdels ]] && fail "Error: cannot create $wxtmp/newrmdels"
		rm -f $wxtmp/parenthist $wxtmp/filehist
	else
		# New file, no parent
		sccs prt -a $file |
		    egrep -v \
			'^R [0-9]+(\.[0-9]+)+[ 	].* (Codemgr|Fake)[ 	]' |
		    egrep '^R [0-9]+(\.[0-9]+)+[ 	]' > $wxtmp/newrmdels
		[[ ! -f $wxtmp/newrmdels ]] && fail "Error: cannot create $wxtmp/newrmdels"
	fi

	if [[ -s $wxtmp/newrmdels ]]; then
		cat $wxtmp/newrmdels
		rm -f $wxtmp/newrmdels
		# an rmdel was done so return true
		return 0
	else
		rm -f $wxtmp/newrmdels
		# no rmdel was done so return false
		return 1
	fi
}

rmdelchk() {
	# returns 0 (success) if an rmdel was done.
	# Should be called via wx_eval().
	if sccs_rmdel_done ; then
		ring_bell
		cat <<-EOF

Warning, it looks like 'sccs rmdel' was run on $filepath
This will cause a problem for Teamware.  Please fix this.
Note, this can be fixed by doing '$ME reedit $filepath'
		EOF
		return 0
	else
		return 1
	fi
}

wx_delget() {
	typeset -i force=0
	typeset arg comment_found=false

	while getopts :f arg; do
		case $arg in
			 f) force=1;;
			 *) fail "Invalid flag -$OPTARG. See 'wx help' for"\
			 	"more info.";;
		esac
	done

	if [[ (! -f SCCS/s.$file && ! -f SCCS/p.$file) || 
		(-f SCCS/s.$file &&  -f SCCS/p.$file) ]]; then

		# Check for keywords unless force is set or file is in
		# keywords.NOT
		if [[ $force -ne 1 ]] && [ -f SCCS/p.$file ] && 
			! grep -q "^$(escape_re $filepath)$" \
				$wxdir/keywords.NOT 2>/dev/null &&
			! keywords -p $file; then

			ring_bell
			cat <<-EOF

The keywords check has detected a problem with $filepath
If this check should be skipped for this file, put the filepath in
${wxdir}/keywords.NOT.
See /net/wizard.eng/export/misc/general_docs/keyword_info.txt
for more info about keywords.  Note, pay attention to the tabs.

			EOF
			yesno "Continue with $command for $filepath?" 
			if [[ "$answer" != 'yes' ]]; then
				echo "Aborting $command $filepath\n"
				return
			fi
		fi

		[[ -f $wxtmp/comment ]] && rm $wxtmp/comment
		if [[ -n "$comment_file" ]]; then
			# note hard tab in sed r.e.
			sed '/^[ 	]*$/d' $comment_file > $wxtmp/comment &&
			    comment_found=true
		else
			wx_show_comment >$wxtmp/comment && comment_found=true
		fi
		if $comment_found; then
			echo $filepath
			cat $wxtmp/comment
			if [[ -f SCCS/s.$file ]]; then
				# file history so check in file
				sccs delget $silent -y"`cat $wxtmp/comment`" \
					$file ||
					fail "sccs delget failed $filepath."
			else
				# no file history so create file
				sccs create $silent -y"`cat $wxtmp/comment`" \
					$file ||
					fail "sccs create $filepath failed."
				rm -f ,$file
			fi
			[[ -n "$comment_file" ]] && 
			    update_active_comment $filepath
		else
			ring_bell
			print "\nError: no comments (NO_COMMENT) registered for $filepath"
			if [[ $force -ne 1 ]] ; then
				yesno "Invoke ${EDITOR:-vi} to edit"\
					"$wxdir/active"'?'
				if [ "$answer" == 'yes' ]; then
					${EDITOR:-vi} $wxdir/active
					wx_delget
				else
					fail "Edit $wxdir/active and try again."
				fi
			else
				fail "Edit $wxdir/active and try again."
			fi
		fi
	elif [[ -f SCCS/s.$file && ! -f SCCS/p.$file ]]; then
		echo "$filepath already checked in"
	elif [[ ! -f SCCS/s.$file && -f SCCS/p.$file ]]; then
		fail "Error, $filepath is missing SCCS/s.$file ."
	fi
}

wx_get() {
	if [[ -f SCCS/s.$file ]]; then
		sccs get $args -s $file || fail "sccs get $file failed."
	else
		ring_bell
		echo "$filepath not in SCCS"
	fi
}

wx_info() {
	if [ -f SCCS/p.$file ]; then
		if [[ -w $file ]]; then
			echo "$filepath (checked out)"
		else
			ring_bell
			echo "$filepath (Warning, inconsistent state."
			echo "   SCCS/p.$file exists but $file is readonly.)"
		fi
	elif [[ ! -f $file ]]; then
		ring_bell
		echo "$filepath (Warning, not found in $workspace)"
	elif [[ ! -f SCCS/s.$file ]]; then
		ring_bell
		echo "$filepath (Warning, not in SCCS)"
	else
		echo "$filepath (checked in)"
	fi
	echo "Check-in comment:"
	wx_show_comment
	if [ -f SCCS/s.$file ]; then
		echo "Most recent delta: \c"
		sccs prt -y $file
	fi
	echo "File name status:"
	if renamed; then
		# old is set by renamed
		echo "Locally renamed, parent file = $parentfile"
	elif lookup_parent $filepath; then
		# parentfile is set by lookup_parent
		if [[ "$filepath" != "$parentfile" ]]; then
			echo "In parent ws, file renamed to: $parentfile"
		else
			echo "Same as parent."
		fi
	else
		echo "New file (does not exist in parent ws)."
	fi
	echo
}

get_multi_deltas() {
	# Get list of files with more that one delta when putback.
	# set global multi_delta_list.
	if ! deltachk >/dev/null 2>&1; then
		multi_delta_list="$multi_delta_list $filepath"
	fi
}

wx_reedit() {
	typeset -i numkids=`workspace children | wc -l`
	typeset i newfiles only_multideltas=false

	case $1 in
		-m)	only_multideltas=true;;
		-*)	fail "Invalid flag $1. See 'wx help' for more"\
		  		"info.";;
	esac

	if [[ ! -f $wsdata/nametable ]]; then
		echo "$wsdata/nametable not found, all files assumed new."
		ok_to_proceed "Okay to continue with $command?"
	elif [[ ! -r $wsdata/nametable ]]; then
		fail "Error: cannot read $wsdata/nametable."
	fi

	if $only_multideltas; then
		# get_multi_deltas sets multi_delta_list
		wx_eval get_multi_deltas
		# set file_list for wx_eval wx_reedit_file below
		file_list=$multi_delta_list
	fi

	cd $workspace

	for i in $file_list; do
		if [[ ! -f $i ]]; then
			fail "$i does not exist."
		fi
		if ! lookup_parent $i; then
			if [[ -z $newfiles ]]; then
				newfiles="$i"
			else
				newfiles="$newfiles\n$i"
			fi
		fi
	done
	
	if [[ -n $newfiles ]]; then
		# If there are some new files, give user a warning
		cat <<-EOF | ${PAGER:-more}

$ME thinks following files are new (not in parent workspace) and will
reset their file histories to version 1.1 (exit if this list isn't correct):
$(echo $newfiles)

		EOF
		ok_to_proceed "Okay to continue with $command?"
		if ! $CHECKIN; then
			cat <<-EOF

Hint, use '$ME redelget' to collapse/reset new file histories to version
1.1 since '$ME $command' will check out the file and '$ME delget' always
increments the file version doing the check in.

			EOF
		fi
	fi

	if [ $numkids -gt 0 ]; then
		echo "WARNING: This workspace has the following children:"
		echo
		workspace children
		echo
		echo "The reedit command will coalesce all children's deltas"
		echo "into one, losing all delta comments in the process."
		ok_to_proceed 'Are you sure you want to proceed?'
	fi
	echo
	yesno "Do you want to backup files first?"
	if [[ "$answer" == 'yes' ]]; then
		wx_backup || fail "Backup failed."
	fi

	echo "$command beginning..."
	echo
	wx_eval wx_reedit_file
	echo
	echo "$command complete"
	echo
	[[ $ACTSORT == sort ]] && do_active_sort=true
}

wx_reedit_file() {
	# Must be called via wx_eval
	typeset comment_found=false

	if [[ ! -f $file ]]; then
		echo "$file does not exist.  Can not reedit $file"
		return
	fi

	echo $filepath
	# Is there a parent file?
	if wx_pnt_filepath; then
		rm -f $wxtmp/s.$file
		cp -p $parentsdot $wxtmp/s.$file ||
			fail "Error: cannot cp $parentsdot $wxtmp/s.$file ."

		# get the latest parent delta and comment and filter out
		# certain fields removing trailing spaces

		p_delta="$(sccs prt -y $parentsdot|expand -1|grep 'SCCS'|\
				   cut -f'4,5,6,9-' -d' '|sed 's/  *$//')" 

		if [[ -z "$p_delta" ]]; then
			ring_bell
			echo "Warning ${command}: skipping $filepath,"
			echo "cannot get parent delta info"
			echo
			return 1
		fi

		# create a list of local deltas in the same format
		# also removing trailing spaces
		sccs prt $file|expand -1|
			nawk '
			/^D [0-9]+(\.[0-9]+)+ +[0-9][0-9]\/[0-9][0-9]/ {
				if (delta != "") {
					# print previous delta info
					print delta comment;
				}
				delta=sprintf("%s %s %s %s ",$3, $4, $5, $8);
				comment = "";
			}
			! /^D [0-9]+(\.[0-9]+)+ +[0-9][0-9]\/[0-9][0-9]/ {
				# Add comment lines to comment variable
				if (comment == "") {
					if (NF > 0) {
						comment = $0;
					} else {
						# empty lines require a space
						# in comment.
						comment = " ";
					}
				} else {
					if (NF > 0) {
						comment = comment " " $0;
					} else {
						comment = comment " ";
					}
				}
			}
			END {
				if (delta != "") {
					# print last delta info
					print delta comment;
				}
			}' | sed 's/  *$//' > $wxtmp/l_deltas ||
			    	fail "Error: cannot create $wxtmp/l_deltas."

		# If the latest parent delta doesn't appear in the local file
		# then a bringover is required.  Use fgrep because comment may
		# have RE chars in it.
		if ! fgrep "$p_delta" $wxtmp/l_deltas >/dev/null; then
			ring_bell
			echo "\nWarning ${command}: skipping $filepath because:"
			echo "parent's version of $filepath"
			echo "is newer than child's -- bringover required."
			echo
			return 1
		fi

		if [ ! -f SCCS/p.$file ]; then
			if sccs edit $silent $file; then
				update_active $filepath
			else
				fail "sccs edit $file failed."
			fi
		fi

		# make copy of local file and copy parent's SCCS s. file over
		# local.
		mv -f $file ${file}.wx_reedit ||
			fail "mv -f $file ${file}.wx_reedit failed."
		rm -f SCCS/s.$file SCCS/p.$file
		cp $wxtmp/s.$file SCCS/s.$file ||
			fail "cp $wxtmp/s.$file SCCS/s.$file failed."

		if sccs edit $silent $file; then
			update_active $filepath
		else
			fail "sccs edit $file failed."
		fi

		mv -f ${file}.wx_reedit $file ||
			fail "mv -f ${file}.wx_reedit $file failed."

		if $CHECKIN; then
			wx_delget
		fi
		touch $file
	else
		# reediting a new file.
		if [[ -f SCCS/s.$file ]]; then
			if [[ ! -f SCCS/p.$file ]]; then
				# File needs to be checked out
				sccs edit $silent $file ||
				    fail "sccs edit $file failed."
			fi
			# clean up SCCS since we are going to create again.
			rm -f SCCS/s.$file
		fi
		# clean up SCCS since we are going to create again.
		[[ -f SCCS/p.$file ]] && rm -f SCCS/p.$file

		[[ -f $wxtmp/comment ]] && rm $wxtmp/comment
		wx_show_comment >$wxtmp/comment && comment_found=true
		if $comment_found; then
			echo $filepath
			cat $wxtmp/comment
			rm -f SCCS/s.$file SCCS/p.$file
			sccs create $silent -y"`cat $wxtmp/comment`" $file ||
			    fail "sccs create $filepath failed."
			rm -f ,$file
			[[ -n "$comment_file" ]] && 
			    update_active_comment $filepath
		else
			ring_bell
			echo "\nError, no comments registered for $filepath"
			if [[ $force -ne 1 ]] ; then
				yesno "Invoke ${EDITOR:-vi} to edit"\
					"$wxdir/active"'?'
				if [[ "$answer" == 'yes' ]]; then
					${EDITOR:-vi} $wxdir/active
					wx_reedit_file
				else
					fail "Edit $wxdir/active and try again."
				fi
			else
				fail "Edit $wxdir/active and try again."
			fi
		fi

		if $CHECKIN; then
			# No need to check out file.
			return
		fi

		if sccs edit $silent $file; then
			update_active $filepath
			add_new $filepath
		else
			fail "sccs edit $file failed."
		fi
	fi
}

#
# Warn if there are sccs delta issues
#
deltachk() {
	# must be run via wx_eval
	typeset -i numdeltas
	typeset newfile checkedout=false

	if wx_pnt_filepath; then
		# find number of deltas by subtracting the number in the parent
		# from the local file (note the literal Control-A in the grep
		# R.E.s below).
		(( numdeltas = $(grep '^d D' SCCS/s.$file|wc -l) - \
				    $(grep '^d D' $parentsdot|wc -l) ))
		newfile=false
	else
		# checking a new file (note the literal Control-A in the grep
		# R.E.)
		numdeltas=$(grep '^d D' SCCS/s.$file|wc -l)
		newfile=true
	fi

	if [[ -z $numdeltas ]]; then
		cat <<-EOF

Warning: the local file:
$filepath
does not appear to have a sccs delta history file or the sccs delta
history file is corrupt.  If the local file is new try using:
"cd $dir"
"$ME create $file"

If the file is not new (exists in parent):
"cd $dir"
Save a copy of the local file
Remove the SCCS/[ps].$file history files
"bringover $filepath"
"$ME edit $file"
Then carefuly merge the saved copy of local file with the
file brought over from parent.  Hint: twmerge is a good merge 
tool.
		EOF
		return 1
	fi

	[[ -f SCCS/p.$file ]] && checkedout=true

	# Note the use of hard tabs in the messages
	case $numdeltas in
		0)	if $checkedout; then
                                # file is checked out so assume there
                                # will be 1 delta when checked in.
				return 0 
			else
				if [[ -n $parentfilepath ]];  then
					if cmp -s $file $parentfilepath; then
						cat <<-EOF

Warning: the local file:
$filepath
and the parent file:
$parentfilepath
content are identical.  There are no new deltas in the local file.
If this file is no longer required in the active list use:
"cd $dir"
"$ME reset $file"
to remove file from the wx state files (active list, etc...)
						EOF
					else
						cat <<-EOF

Warning: the local file:
$filepath
and the parent file:
$parentfilepath
have the same number of deltas but contents differ.  A bringover may be
required before putback.
						EOF
					fi
				else
					cat <<-EOF

Warning: the local file:
$filepath
is new but doesn't appear to contain any deltas.  The SCCS delta history file
may need to be recreated.  If so: 
"cd $dir"
"rm SCCS/s.$file"
"$ME create $file"
					EOF
				fi
				return 1 
			fi ;;

		1)	if $checkedout; then
				cat <<-EOF

Regarding $filepath
Warning! There may be more than 1 delta when you check this file in
(currently checked out).  Run '$ME redelget' on this file to collapse
the deltas and check in with 1 delta unless putting back > 1 bug.
				EOF
				return 1 
			else
				return 0 
			fi ;;

		-*) # a negative number means the parent has more deltas
			
			cat <<-EOF

Regarding $filepath
Warning! The parent file has more deltas than the local file.
You should bringover the local file to fix this.
			EOF
			;;

		*)	if $newfile && $checkedout; then
				cat <<-EOF

Regarding $filepath
Warning! There may be more than 1 delta when you check this file in
(currently checked out).  Run '$ME redelget' on this file to collapse
the deltas and check in with 1 delta unless putting back > 1 bug.
				EOF
			else
				cat <<-EOF

Regarding $filepath
Warning! There is more than 1 delta.  Run:
'cd $dir; $ME redelget $file' 
to collapse the deltas on this file and check in with 1 delta unless
putting back > 1 bug.
				EOF
			fi
			return 1;;
	esac
}

wx_cstyle() {
	case $file in
		*.[ch])	;;
		*)	return;;
	esac
	((CSTYLE_INDEX = CSTYLE_INDEX + 1))
	(cd $workspace;
	 cstyle ${CSTYLE_FLAGS} $args $filepath >\
	    $wxtmp/wx.cstyle.$CSTYLE_INDEX) &
}

wx_jstyle() {
	case $file in
		*.java)	;;
		*)	return;;
	esac
	((JSTYLE_INDEX = JSTYLE_INDEX + 1))
	(cd $workspace;
	 jstyle ${JSTYLE_FLAGS} $args $filepath >\
	    $wxtmp/wx.jstyle.$JSTYLE_INDEX) &
}

wx_find_compression_progs() {
	gzip=/usr/bin/gzip
	if [[ ! -x $gzip && -n "$GZIPBIN" ]]; then
		gzip=$GZIPBIN
	fi

	bzip2=/usr/bin/bzip2
	if [[ ! -x $bzip2 && -n "$BZIP2BIN" ]]; then
		bzip2=$BZIP2BIN
	fi
}

wx_get_backup_dir() {
	typeset backup_dir_file
	# if backup_dir hasn't been set already...
	if [[ -z "$backup_dir" ]]; then
		# use the backup dir specifier in the wx/
		backup_dir_file=$wxdir/backup_dir
		if [[ ! ( -f $backup_dir_file && -r $backup_dir_file && 
			-s $backup_dir_file ) ]]; then
			fail "$backup_dir_file: missing, empty, or not readable"
		fi
		backup_dir=`cat $backup_dir_file`
	fi
	if [[ ! ( -d $backup_dir && -x $backup_dir && -r $backup_dir ) ]]; then
		fail "$backup_dir: missing, not a directory, or bad permissions"
	fi
}

#
# This code requires that the files (n.sdot, n.pdot and n.clear) for a given
# backup have the same extension (.tar, .tar.gz, or .tar.bz2).  It also
# disallows the existance of two incarnations of the same file (i.e.
# n.clear.tar and n.clear.tar.gz)
#
# It's up to the user to straighten things out if the above conditions are
# violated.  The only time that is a problem is if they are trying to
# restore a version which violates the above rules.
#
#  Takes one argument, the version number.
#
#  Returns:
#	(return code)	0 if exists and consistent,
#			1 if not found,
#			2 if inconsistent
#	b_clear, b_sdot, b_pdot	On success, the full path to the clear, sdot
#	and pdot files comp, ext	The compression program for and
#	extension of said files
#
wx_check_backup() {
	typeset _new _b_new _renamed _b_renamed _active _b_active \
		_local_nt _b_local_nt found bad

	_version=$1
	clear=$_version.clear.tar
	sdot=$_version.sdot.tar
	pdot=$_version.pdot.tar
	not=$_version.not.tar
	_renamed=$_version.renamed
	_b_renamed=$backup_dir/$_renamed
	_new=$_version.new
	_b_new=$backup_dir/$_new
	_active=$_version.active
	_b_active=$backup_dir/$_active
	_local_nt=$_version.local_nametable
	_b_local_nt=$backup_dir/$_local_nt
	_sort=$_version.sort_active
	_b_sort=$backup_dir/$_sort
	found=false
	bad=false
	#
	# these arrays must be in sync with:
	# 1. the immediately following _count variable
	# 2. wx_find_last_backup's egrep expression
	# 3. wx_backup's "$args" handling.
	# 4. wx_find_compression_progs's programs
	#
	set -A _comps	""  "$gzip" "$bzip2"
	set -A _extns	""  ".gz"   ".bz2"
	_count=3

	idx=0
	while [[ $idx -lt $_count ]] ; do
		_ext=${_extns[$idx]}
		_comp=${_comps[$idx]}
		_clear=$clear$_ext
		_sdot=$sdot$_ext
		_pdot=$pdot$_ext
		_b_clear=$backup_dir/$_clear
		_b_sdot=$backup_dir/$_sdot
		_b_pdot=$backup_dir/$_pdot

		if [[ -f $_b_clear || -f $_b_sdot ]]; then
			if $found; then
				echo "$backup_dir: both $_version.*.tar$ext "\
					 "and $_version.*.tar$_ext exist"
				bad=true
			else
				ext=$_ext
				comp=$_comp
				found=true
			fi
		fi

		if [[ -f $_b_clear && ! -f $_b_sdot ]]; then
			echo "$backup_dir: $_clear exists; $_sdot does not"
			bad=true
		elif [[ ! -f $_b_clear && -f $_b_sdot ]]; then
			echo "$backup_dir: $_sdot exists; $_clear does not"
			bad=true
		elif [[ ! -f $_b_sdot && -f $_b_pdot ]]; then
			echo "$backup_dir: $_pdot exists; $_sdot does not"
			bad=true
		fi
		idx=`expr $idx + 1`
	done

	if [[ ! -f $_b_renamed && -f $_b_active ]]; then
		# Can determine compression only
		return 1
	fi
	
	if [[ -f $_b_renamed && -f $_b_active && -f $_b_new &&
		-f $_b_local_nt ]]; then
		found=true
	else
		bad=true
	fi

	$bad && return 2
	$found || return 1

	b_renamed=$_b_renamed
	b_new=$_b_new
	b_active=$_b_active
	b_local_nt=$_b_local_nt

	if [[ -f $backup_dir/$clear$ext && -f $backup_dir/$sdot$ext ]]; then
		b_clear=$backup_dir/$clear$ext
		b_sdot=$backup_dir/$sdot$ext
	else
		b_clear=
		b_sdot=
	fi

	# It's not an error if this doesn't exist.
	if [[ -f $backup_dir/$pdot$ext ]]; then
		b_pdot=$backup_dir/$pdot$ext
	else
		b_pdot=
	fi
	# It's not an error if this doesn't exist.
	if [[ -f $backup_dir/$not ]]; then
		b_not_files=$backup_dir/$not
	else
		b_not_files=
	fi
	# It's not an error if this doesn't exist.
	if [[ -f $_b_sort ]]; then
		b_sort=$_b_sort
	else
		b_sort=
	fi

	return 0
}

#
# finds the number of the last backup.
#
# Returned in $result, which is -1 if no backups are found
#
wx_find_last_backup() {
	#
	# The list of extensions in the egrep expression must be in sync
	# with wx_check_backup's arrays
	#
	result=`ls -1 $backup_dir | egrep \
	    '^[0-9][0-9]*\.((pdot|sdot|clear)\.tar($|\.gz$|\.bz2$)|active|renamed|new|local_nametable$)'| \
	    sed 's/^\([0-9][0-9]*\)\..*$/\1/'| sort -rn | head -1`

	[[ -n "$result" ]] # fail if result is empty
}

#
# wx_do_backup
# Returns 0 on successful backup, 1 if nothing to backup, 2 any other
# error.
#

wx_do_backup() {
	_type=$1	# type of files (for user)
	_out=$2		# file to write to
	_comp="$3"	# compression program, or empty for no compression
	_evalarg=$4	# arg to wx_eval to get the correct file list
	typeset backupfiles=$(wx_eval "$_evalarg")

	echo
	echo "Saving $_type files to $_out"
	echo

	if [[ -z $backupfiles ]]; then
		echo "Note, nothing to backup."
		return 1
	fi

	if [[ -n "$_comp" ]]; then
		( tar cvf - $backupfiles 2>$BACKUP_ERRORS || \
		    rm -f $_out ) | $_comp -9 -c > $_out || rm -f $_out
	else
		tar cvf $_out $backupfiles 2>$BACKUP_ERRORS || 
		    rm -f $_out
	fi

	[[ -f "$_out" ]] || return 2	# $_out is removed on any error

	return 0
}

wx_do_restore() {
	_type=$1		# type of files (for user)
	_in=$2		  # file to read from
	_comp="$3"	  # uncompressing program
	echo
	echo "Restoring $_type files from $_in"
	echo

	if [[ -n "$_comp" ]]; then
		#
		# if decompression fails, echo a bad value to make tar fail
		#
		($_comp -dc < $_in || echo "fail") | tar xvpf - || return 1
	else
		tar xvpf $_in || return 1
	fi
	return 0
}

#
# do renames in a workspace from a backup set
#

wx_do_renames() {
	typeset _in=$1 # file to read from

	if [[ ! -f $wsdata/nametable ]]; then
		echo "$wsdata/nametable not found, not doing renames."
		return 0
	fi

	echo
	echo "Restoring renamed files from $_in"
	echo

	# Note this assumes we're staring in $workspace

	while read new hash1 hash2 hash3 hash4; do
		# get current local file name
		current=$(grep " $hash1 $hash2 $hash3 $hash4$" \
				$wsdata/nametable | cut -f1 -d' ')

		if [[ -z $current ]]; then
			# nothing to rename
			continue
		fi

		if [[ "$new" == "$current" ]]; then
			# rename not needed
			continue
		fi

		if [[ ! -f $new ]]; then
			if [[ ! -d $(dirname $new) ]]; then
				mkdir -p $(dirname $new) ||
					fail "Error: cannot create dir $(dirname $new)"
			fi
			echo "Renaming current workspace file $current to $new"
			workspace filemv $current $new
		else
			if [[ -f $current ]]; then
				ring_bell
				cat >&2 <<-EOF

Warning: $current 
and $new 
files both exist in current workspace with the
same hash.  The restored renamed list should be recreated by running:
'$ME update -r'
Skipping rename of $current 
to $new
				EOF
				
			fi
		fi 
	done < $_in

	return 0 
}

wx_backup() {
	typeset orig_file_list ws_file back_file
	typeset newer=false
	typeset origdir=$PWD

	case $1 in
		-i)	wx_get_backup_dir
			echo "Backup dir is $backup_dir"
			ls -ltr $backup_dir
			echo "Backup dir is $backup_dir"
			cd $origdir
			return ;;
		-t) 	newer=true
                        # backup if wx files are newer than last backup.
                        # Implies use of default compression and no
                        # interaction.  Doing shift so case further down
                        # won't see -t.
			shift;; 
	esac
	# save state in case wx_backup called from another command.
	orig_file_list=$file_list

	# we always backup the active files.
	file_list=$(wx_active)

	if [[ ! -s $wxdir/renamed && -z $file_list ]]; then
		echo "There isn't anything to backup."
                file_list=$orig_file_list
		return 0
	fi

	# must be in workspace to do backup
	cd $workspace || fail "Error: cannot cd $workspace"

	if $newer; then
		# get latest wx state files and active files but skip
		# wx/tmp and wx/*.old files.
		ws_file=$(ls -1t $wxdir/!(tmp|*.old) $file_list|head -1)
		# get latest backup.
		wx_get_backup_dir
		back_file=$(ls -1t $backup_dir/*|head -1)
		if [[ ( -z "$back_file" && -n "$ws_file" ) || \
			(( -n "$back_file" && -n "$ws_file" ) && \
			$ws_file -nt $back_file ) ]]
		then
			: # continue with backup
		else
			print "Skipping backup, last backup newer than wx"\
				"files."
                        file_list=$orig_file_list
			cd $origdir
			return 0
		fi
	fi

	wx_find_compression_progs
	wx_get_backup_dir

	if [[ ! -w $backup_dir ]]; then
		fail "$backup_dir: not writable"
	fi

	if wx_find_last_backup; then
		prev_backup=$result
		version=`expr $result + 1`
	else
		prev_backup=
		version=0
	fi

	#
	# This must be in sync with wx_check_backup's arrays
	#
	case $1 in
		-n) ext=;	comp=;;
		-z) ext=.gz;	comp=$gzip;;
		-b) ext=.bz2; comp=$bzip2;;
		"-") shift;; # treat this as use default compression
		"") ;; # treat this as use default compression
		-??*) fail "$ME $command: only accepts a single argument";;
		*)  fail "$ME $command: unrecognized argument";;
	esac

	if [[ -z "$1" ]]; then
		#
		# default to the compression of the previous backup
		#
		if [[ -z "$prev_backup" ]]; then
			ext=
			comp=
		else 
			wx_check_backup $prev_backup
			# A return of 1 is okay
			if [ $? -gt 1 ]; then
				echo "$backup_dir/$prev_backup.*: "\
					"cannot determine previous "\
					"compression."
				if $newer; then
                                        # Assume we want backup.
					answer="yes"
				else
					yesno "Proceed with no "\
						"compression?"
				fi
				if [[ $answer == "no" ]]; then
					echo "No backup done."
                                        file_list=$orig_file_list
					cd $origdir
					return
				fi
				ext=
				comp=
			fi
		fi
	fi

	if [[ -n "$comp" && ! -x "$comp" ]]; then
		echo "${comp}: missing.  defaulting to no compression"
		ext=
		comp=
	fi

	b_clear=$backup_dir/$version.clear.tar$ext
	b_sdot=$backup_dir/$version.sdot.tar$ext
	b_pdot=$backup_dir/$version.pdot.tar$ext
	b_local_nt=$backup_dir/$version.local_nametable
	b_active=$backup_dir/$version.active
	b_renamed=$backup_dir/$version.renamed
	b_new=$backup_dir/$version.new
	b_not_files=$backup_dir/$version.not.tar
	b_sort=$backup_dir/$version.sort_active

	#
	# If anything goes wrong, clean up after ourselves
	#
	trap "/usr/bin/rm -f $b_clear $b_sdot $b_pdot $b_active $b_renamed $b_new $b_local_nt $b_not_files $b_sort; exit 1" 0 1 2 3 15

	fail_msg='failed.  Cleaning up. '

	#
	# It is not a hard error for the SCCS/s.file to be missing.  We just
	# let the user know what's going on.
	#
	sdot_cmd='
_sdot="SCCS/s.$file";
_file="$dir/$_sdot";
if [[ -f $_sdot ]]; then
	echo "$_file";
else
	echo "$_file: not found" >&2;
fi
'
	pdot_cmd='
_pdot="SCCS/p.$file";
_sdot="SCCS/s.$file";
_file="$dir/$_pdot";
if [[ -f $_pdot ]]; then
	echo "$_file";
elif [[ ! -f $_sdot ]]; then
	echo "$_file: not checked in" >&2;
elif [[ -w $file ]]; then
	echo "$_file: not found but $file is writable!" >&2;
fi
'
	# Do this first in case there are no active files
	echo
	echo "Saving renamed file list to $b_renamed"
	echo
	cp $wxdir/renamed $b_renamed || fail "$b_renamed: $fail_msg"

	if [[ -f $wxdir/local_nametable ]]; then
		echo
		echo "Saving local_nametable to $b_local_nt"
		echo
		cp $wxdir/local_nametable $b_local_nt || \
			fail "$b_local_nt: $fail_msg"
	fi

	if [[ -f $wxdir/sort_active ]]; then
		print
		print "Saving sort_active to $b_active"
		print
		cp $wxdir/sort_active $b_sort || fail "$b_sort: $fail_msg"
	fi

	if ls wx/*.NOT >/dev/null 2>&1; then
		echo
		echo "Saving .NOT files to $b_not_files"
		echo
		tar -cf $b_not_files wx/*.NOT || fail "$b_not_files: $fail_msg"
	fi

	# Are there any active files to backup?
	if [[ -n $file_list ]]; then
		wx_do_backup 'clear' $b_clear "$comp" 'echo $filepath' ||
			fail "$b_clear: $fail_msg"

		wx_do_backup 'sdot' $b_sdot "$comp" "$sdot_cmd" ||
			fail "$b_sdot: $fail_msg"

		echo
		echo "Saving new list to $b_new"
		echo
		cp $wxdir/new $b_new || fail "$b_new: $fail_msg"

		# It's not fatal if the backup error for pdot files is
		# 'no files to backup'.  This is because it's possible
		# that the active files aren't checked out so there
		# won't be any pdot files.
		wx_do_backup 'pdot (if any)' $b_pdot "$comp" "$pdot_cmd" 
		if [[ $? -gt 1 ]]; then
			fail "$b_pdot: $fail_msg $(cat $BACKUP_ERRORS)"
		fi
	fi
	
	echo
	echo "Saving active file list to $b_active"
	echo
	cp $wxdir/active $b_active || fail "$b_active: $fail_msg"

	trap - 0 1 2 3 15

	rm -f $BACKUP_ERRORS

	# restore file_list state.
	file_list=$orig_file_list

	cd $origdir
	return 0
}

wx_restore() {
	typeset force=0

	case $1 in
		-f) force=1;;
		-*) fail "Invalid flag $1. See 'wx help' for more  info.";;
	esac

	if [[ $force -eq 0 ]]; then
		cat <<-EOF

Warning, the restore command will overwrite several files including the
active and renamed lists.  This could be a problem if you have made
changes to your workspace and $ME related files following the last
backup.  It may be a good idea to run:

$ME update

after the restore so that the active and renamed lists are updated with
the new changes in the workspace.

Also, restore may perform workspace renames in this workspace if it
finds that the existing file has a pathname that differs from that in
the backup being restored.

		EOF
		ok_to_proceed "Do you really want to do the restore?"
	fi

	wx_find_compression_progs
	wx_get_backup_dir

	if wx_find_last_backup; then
		version=$result
	else
		fail "$backup_dir: no backups found"
	fi

	if [[ $force -eq 0 ]]; then
		ask 'Version to restore from' $version
		version=$answer
	fi

	#
	# wx_check_backup sets $comp, $b_clear, and $b_sdot when successful
	#
	if wx_check_backup $version; then
		:
	else
		if [[ $? -eq 2 ]]; then
			fail "$backup_dir/$version.*: unable to restore"\
				"inconsistent version"
		else
			fail "$backup_dir: Unable to find version $version"
		fi
	fi

	b_active=$backup_dir/$version.active

	if [[ -n "$comp" && ! -x "$comp" ]]; then
		fail "${comp}: missing -- cannot decompress $b_clear"
	fi

	# must be in workspace to do restore
	cd $workspace || fail "Error: cannot cd $workspace" 

	[[ -f $b_renamed ]] || fail "$b_renamed: missing"
	[[ -f $b_new     ]] || fail "$b_new: missing"
	[[ -f $b_active  ]] || fail "$b_active: missing"

	[[ -r $b_renamed ]] || fail "$b_renamed: not readable"
	[[ -r $b_new     ]] || fail "$b_new: not readable"
	[[ -r $b_active  ]] || fail "$b_active: not readable"

	if [[ -f $b_clear ]]; then
		[[ -r $b_clear ]] || fail "$b_clear: not readable"
	fi
	if [[ -f $b_sdot ]]; then
		[[ -r $b_sdot ]] || fail "$b_sdot: not readable"
	fi
	if [[ -f $b_pdot ]]; then
		[[ -r $b_pdot ]] || fail "$b_pdot: not readable"
	fi
	if [[ -f $b_local_nt ]]; then
		[[ -r $b_local_nt ]] || fail "$b_local_nt: not readable"
	fi
	if [[ -f $b_not_files ]]; then
		[[ -r $b_not_files ]] || fail "$b_not_files: not readable"
	fi
	if [[ -f $b_sort ]]; then
		[[ -r $b_sort ]] || fail "$b_sort: not readable"
	fi

	#
	# If something goes wrong, we need to make sure they notice, so
	# we make the message quite visible, and echo a BELL.
	#
	fail_msg='Extraction failed.

	*DANGER* *DANGER* workspace could be corrupted *DANGER* *DANGER*'

	cp $b_renamed $wxdir/renamed || fail "$wxdir/renamed: $fail_msg"
	cp $b_new $wxdir/new || fail "$wxdir/new: $fail_msg"
	cp $b_active $wxdir/active || fail "$wxdir/active: $fail_msg"
	cp $b_local_nt $wxdir/local_nametable ||
		fail "$wxdir/local_nametable: $fail_msg"
	if [[ -n $b_sort ]]; then
		cp $b_sort $wxdir/sort_active || \
			fail "$wxdir/sort_active: $fail_msg"
	fi

	# Need to move active files that are renamed in current ws back to
	# their name in the active list to avoid two copies of the file
	# occuring when the clear files are restored below.
	wx_do_renames $wxdir/local_nametable ||
		fail "$wxdir/local_nametable: $fail_msg"

	if [[ -n $b_not_files ]]; then
		tar -xf $b_not_files || fail "$wx/*.NOT: $fail_msg"
	fi
	# It's not an error if there is no clear backup.
	if [[ -f $b_clear ]]; then
		wx_do_restore "clear" $b_clear "$comp" ||
		    fail "$b_clear: $fail_msg"
	fi
	# It's not an error if there is no sdot backup.
	if [[ -f $b_sdot ]]; then
		wx_do_restore "sdot" $b_sdot "$comp" ||
			fail "$b_sdot: $fail_msg"
	fi
	# It's not an error if there is no pdot backup.
	if [[ -f $b_pdot ]]; then
		wx_do_restore "pdot" $b_pdot "$comp" ||
			fail "$b_pdot: $fail_msg"
	fi

	# Do some integrity checking
	for filepath in $(wx_active); do
		if cd ${workspace}/$(dirname $filepath); then
			file=$(basename $filepath)

			# If file is not writable then assume the
			# SCCS/p.file is bogus.  This can happen if a
			# file is checked out and a wx restore is done
			# and the restored file was not checked out when
			# it was backed up.

			if [[ ! -w $file && -f SCCS/p.$file ]]; then
				ring_bell
				cat <<-EOF

Warning! $filepath is in inconsistent state.
$filepath is not writable and SCCS/p.$file exists.
Removing SCCS/p.$file 
To edit the file run '$ME edit $filepath'
				EOF
				rm -f SCCS/p.$file
			elif [[ -w $file && ! -f SCCS/p.$file ]]; then
				ring_bell
				cat <<-EOF

Warning! $filepath is in inconsistent state.
$filepath is writable 
but there is no SCCS/p.$file

				EOF
				yesno "Should this file be checked out?"
				if [[ "$answer" == 'yes' ]]; then
					if mv $file $wxtmp; then
						if sccs edit $file; then
							update_active $filepath
						fi
						mv -f $wxtmp/$file $file
					fi
				else
					ask_remove_active_entry 
					echo "Setting $filepath read only"
					chmod ugo-w $file
				fi
			fi
		else
			ring_bell
			echo "\nWarning! Could not check sccs state of "\
			    "$filepath"
		fi
	done
}

wx_fullreview() {
	if wx_pnt_filepath; then
		:
	else
		parentfilepath=/dev/null
	fi
	if $show_comments && wx_show_comment > $wxdir/comment; then
		comm=-y"`cat $wxdir/comment`"
		codereview "$comm" $args $parentfilepath $workspace/$filepath
	else
		codereview $args $parentfilepath $workspace/$filepath
	fi
}

#
# Check on RTI status for bug ID's found in active list comments.
#

wx_rtichk() {
	typeset bugs[]
	# gate contains the gate dir, not full path
	typeset gate=${parent##*/}
	typeset -i rc=0
	typeset nolookup opt

	if [[ -f $wxdir/rtichk.NOT ]]; then
		print "\nSkipping RTI check:"
		return
	else
		print "\nDoing RTI check:"
	fi

	while getopts :N opt; do
		case $opt in
			N) nolookup='-N' ;;
			*) fail "Invalid flag -$OPTARG." ;;
		esac
	done

	# Note, rtichk needs a gate arg to correctly determine status.
	if [[ -z $gate ]]; then
		cat >&2 <<-EOF
Warning: cannot find a parent gate, skipping RTI checking.
		EOF
	fi

	# Use wx_summary to output bug ID's in active list comments,
	# redirecting warnings about non-bug ID's to file for later use.
	set -A bugs $(wx_summary -ao $nolookup 2>$wxtmp/bugwarnings|cut -f1 -d' ')
	rtichk -g $gate ${bugs[@]}
	rc=$?

	if [[ -s $wxtmp/bugwarnings ]]; then
		cat <<-EOF

There are issues with the bug ID format in the 
$wxdir/active file.
Please fix the following and run rtichk again:

		EOF
		cat $wxtmp/bugwarnings
		((rc = 1))
	fi
	if [[ ${#bugs} -eq 0 ]]; then
		print "\nWarning: no bug ID's in active list."
	fi
	return $rc
}

#
# Do a Teamware putback of active and renamed files.
#
wx_putback() {
	# Use pbargs array to store Teamware putback args.
	# verbatim is for -v verbatim flag which doesn't get passed to
	# putback.
	typeset i verbatim pbargs[] pbfiles narg=false force=false
	typeset nolookup=false

	if $FILES_PASSED; then
		# use the user specified files
		pbfiles=$file_list
	else
		# use the pblist (active and renamed)
		pbfiles=$(wx_active -p)
	fi

	while getopts :fnp:qvN i; do
		case $i in
			# Force the putback (no user interaction)
			f)	force=true;;

			n)	narg=true
				pbargs[${#pbargs[@]}]="-$i" ;;

			q)	pbargs[${#pbargs[@]}]="-$i" ;;

			p)	pbargs[${#pbargs[@]}]="-$i" 
				pbargs[${#pbargs[@]}]="$OPTARG" 
				# setting parent for user prompt below
				parent="$OPTARG" ;; 

				# -v doesn't get passed to putback.
			v)	verbatim='-v';;

			N)	nolookup='-N';;

		  	*)	fail "Invalid flag -$OPTARG. See 'wx help'"\
					"for more info.";;
		esac
	done

	if ! $narg; then
		# real putback

		# get pb comments, will be used later.
		if ! wx_summary -p $verbatim $nolookup >$wxtmp/pb_comments; then
			# Fail if comments have problems.
			fail "\nError, improper comments found. Use -v"\
				"to bypass this check."
		fi

		if ! $force; then
			# not force so give more warning.
			( # using subshell to capture stdout to file.
			cat <<-EOF
Remember to run '$ME pbchk' before doing a final putback (esp. if
doing a putback to an official ON gate).  Make sure your workspace 
parent ($parent) is correct.  
It's a good idea to check your code diffs before putback ('$ME pdiffs').

Also, run '$ME $command -n' and check for conflicts before doing the
final putback.
			EOF

			if [[ -z "$(wx_summary -bo 2>/dev/null)" ]]; then
				cat <<-EOF

Don't forget the ARC ID info in your active list comments if there is an
ARC case associated with your putback.
				EOF
			fi

			echo "\nThe putback comment will be:"
			cat $wxtmp/pb_comments
			print "========== End of putback comments ======="

			# Output warning if RTI isn't approved.
			wx_rtichk $nolookup
			print "========== End of RTI check output ======="

			cat <<-EOF

The following files will be used for putback:
$pbfiles

			EOF
			) | ${PAGER:-more}

			ok_to_proceed "Do you really want to"\
				"'$PUTBACK ${pbargs[@]}' to $parent?"
		fi
	fi

	# Do the putback, passing in active list comments if required.
	# putback both active and renamed/deleted files.
	cd $workspace
	if $narg; then
		# Don't use putback comment if -n is given (trial putback)
		$PUTBACK "${pbargs[@]}" $pbfiles
	else
		# feed active list comments into real putback
		wx_summary $verbatim $nolookup |$PUTBACK "${pbargs[@]}" $pbfiles
	fi
	return
}

outchk() {

	# List files that are checked out but not in active list.
	typeset outfile do_header=true

	wx_checked_out >/dev/null
	# if $wxtmp/checked_out is 0 bytes then return
	[[ -s $wxtmp/checked_out ]] || return

	sort $wxtmp/checked_out > $wxtmp/co_sort
	wx_active | sort > $wxtmp/active_sort
	for outfile in $(comm -12 $wxtmp/active_sort $wxtmp/co_sort); do
		if $do_header; then
			echo "\nWarning, the following active list files are"\
			    "checked out:"
			do_header=false
		fi
		echo "$outfile"
	done
	do_header=true
	for outfile in $(comm -13 $wxtmp/active_sort $wxtmp/co_sort); do
		if $do_header; then
			cat <<-EOF

Warning, the following files are checked out but not in active list
(Run "$ME update -q" to add them to the active list): 
			EOF
			do_header=false
		fi
		echo "$outfile"
	done
	rm -f $wxtmp/co_sort $wxtmp/active_sort
}

#
# run Teamware resolve and do reedit only on merged files.
#
wx_resolve() {
	typeset merged_file

	# clear the file_list, will be set below
	file_list=

	grep -v '^VERSION ' $wsdata/conflicts > $wxtmp/conflicts
	[[ ! -f $wxtmp/conflicts ]] && fail "Error: cannot create $wxtmp/conflicts"

	# run Teamware resolve
	resolve $* || fail "Teamware resolve failed."

	# resolve will remove files from $wsdata/conflicts when
	# successfully merged.

	# set file_list to files that were merged.
	for merged_file in $(cat $wxtmp/conflicts); do
		if ! grep -q '^'"$(escape_re $merged_file)"'$' \
		    $wsdata/conflicts; then
			# set file_list for wx_eval later.
			file_list="$file_list $merged_file"
		fi
	done

	if [[ -n $file_list ]]; then
		ok_to_proceed "Re-edit merged files to collapse merge deltas?"
		echo "Re-editing merged files"
		echo
		wx_eval wx_reedit_file
		echo
		echo "Re-edit complete"
		echo
	else
		echo "No merged files to re-edit."
	fi
}

#########################################################################
#
# Main
#

#
# Do some initial sanity checking and set up.
#

# Set the lang to standard English so wx doesn't get confused. 
export LC_ALL=C

# Turn on debugging output early
if [[ "$*" == *' -D'*( *) ]]; then
	typeset -ft $(typeset +f)
	set -x
fi

ME=$(basename $0)
export ME

if [[ -d /usr/xpg4/bin ]]; then
	# Want to use xpg4 versions of fgrep and grep
	PATH=/usr/xpg4/bin:/usr/bin:/usr/sbin:/usr/ccs/bin:$PATH
else
	fail "Error: directory /usr/xpg4/bin not found."
fi

unset CDPATH	# if set "cd" will print the new directory on stdout
		# which screws up wx_eval.

DEFAULT_SRCDIR=usr

if [[ $# -eq 0 || "$1" == help ]]; then
	# output usage now to avoid unnecessary checking below.
	wx_usage
fi

if [[ "$1" == version ]]; then
	# output version now to avoid unnecessary checking below.
	version
	exit 0
fi

#
# Check to make sure we're not being run from within a Mercurial repo
#
if hg root >/dev/null 2>&1; then
	fail "Error: wx does not support Mercurial repositories.\n"\
"Please see http://opensolaris.org/os/community/tools/hg"
fi

whence workspace >/dev/null || fail "Error: cannot find workspace command in \$PATH."

# Note, PUTBACK can be set to "cm_env -g -o putback" to use Casper Dik's
# turbo-dir.flp scripts to speed up thorough updates.
PUTBACK=${PUTBACK:='putback'}
BRINGOVER=${BRINGOVER:='bringover'}

dot=$PWD

if [[ -n "$CODEMGR_WS" ]]; then
	# ws was used.
	# normalize the workspace name.
	workspace=$(cd $CODEMGR_WS && workspace name)

	# If the current dir is in a workspace check that it is the same
	# as CODEMGR_WS.
	if [[ -n "$(workspace name)" ]]; then
		if [[ "$(/bin/pwd)/" != "$workspace/"* ]]; then
			cat <<-EOF

Warning, $ME will use $ME files in workspace $workspace (the current
directory is not in this workspace).
			EOF
			ok_to_proceed "Okay to proceed?"
		fi
	fi
else
	# If current dir is in a workspace then use output of workspace
	# name as current ws.
	workspace=$(workspace name)
	if [[ -n "$workspace" ]]; then
		CODEMGR_WS=$workspace
		export CODEMGR_WS
	fi
fi

if [[ -z "$workspace" ]]; then
	fail "No active workspace, run \"ws <workspace>\" or"\
		"\"cd <workspace>\"."
fi

workspace_basename=`basename $workspace`
wxdir=${WXDIR:-$workspace/wx}
wxtmp=$wxdir/tmp
wsdata=$workspace/Codemgr_wsdata
node=`uname -n`

if [ -f $wsdata/parent ]; then
	parent=`tail -1 $wsdata/parent`
else
	parent=
fi
if [[ $parent == *:* ]]; then
	parentdir=${parent#*:}
	parentnode=${parent%%:*}
	if [[ $parentnode == $node ]]; then
		parent=$parentdir
	else
		parent=/net/$parentnode$parentdir
	fi
fi

# Store backup state
backup_done=0

# store state if new files are deleted
NEED_WS_CLEAN='n'

# XXX doing this because keywords doesn't work on new files
# Note doing the echo so the tabs are apparent
SCCSKEYWORD=$(echo "ident\t+\"(\%\Z\%\%\M\%\t+\%\I\%|\%W\%)\t+\%\E\% SMI\"")

# file that contains comments for use in create and checkin
comment_file=
# mode for updating comments in active list
comment_mode="replace"

CSTYLE_FLAGS=${CSTYLE_FLAGS:='-P -p -c'}
JSTYLE_FLAGS=${JSTYLE_FLAGS:='-p'}

BACKUP_ERRORS=/tmp/${ME}_berrors_$(/usr/xpg4/bin/id -un)_$$

# global for reedit command, don't checkin by default
CHECKIN=false

# Indicates that the parent nametable cache needs refreshing
need_pnt_refresh=true

# Indicate whether file args were specified
FILES_PASSED=false

# Used to store files that have more than one delta compared to parent
multi_delta_list=

# Used to bringover any files just before exit of wx
bofilelist=

# should codereviews include delta comments?
show_comments=true

# Determines if active list should be sorted by default
# If sort_active contains true then we sort the active list on updates.
if [[ -r $wxdir/sort_active && "$(cat $wxdir/sort_active)" == "true" ]]; then
	ACTSORT=sort
else
	ACTSORT=cat
fi

# These are set depending on what needs sorting
do_renamed_sort=false
do_active_sort=false

# Places to search for approved RTIs
RTIDIRS="/net/wizard.eng/export/consolidation/rtiroute/newrtis
	/net/wizard.eng/export/consolidation/rtiroute/oldrtis
	/net/onstc.eng/export/stc/Rtitool/consolidation/rtiroute/newrtis
	/net/onstc.eng/export/stc/Rtitool/consolidation/rtiroute/oldrtis"

# Places to search for approved Patch RTIs
PRTIDIRS="/net/wizard.eng/export/consolidation/rtiroute/newprtis
	/net/wizard.eng/export/consolidation/rtiroute/oldprtis"

export workspace parent wxdir file dir filepath backup_done DEFAULT_SRCDIR

#
# main section
#

# Get wx command
command=$1
comlist=$command
shift
# throw away -D flag after command assigned as this flag was processed earlier
[[ "$1" == '-D' ]] && shift

case $command in
	apply|eval)	subcommand=$1; shift;;
	grep|egrep|sed|nawk)	pattern=$1; shift;;
	nits)	comlist="cstyle jstyle hdrchk copyright cddlchk keywords"; 
		echo "Note, nits is a subset of pbchk checks.";;
	pbchk)	comlist="cstyle jstyle hdrchk copyright cddlchk keywords"
		comlist="$comlist rmdelchk deltachk comchk rtichk outchk";;
esac

orig_args="$@"
silent=
args=
file_list=
typeset tmp_file_list tmp_args

#
# Some subcommands pass through all arguments.
#
case $command in
	webrev)	args="$orig_args"; shift $#;;
esac

# Parse args
while [ $# -gt 0 ]; do
	case $1 in
		-c|-C) 
			if [[ $command == @(delget|checkin|ci|create) ]]; then
				# set global comment_file
				[[ "$1" == "-C" ]] && comment_mode="append"
				comment_file=$2; 
				if [[ $comment_file != '/'* ]]; then
					comment_file="$(pwd)/$comment_file"
				fi
				if [[ -z "$comment_file" ]]; then
					fail "Missing comment file."\
						"Run 'wx help' for info."
				fi
				[[ ! -r "$comment_file" ]] &&
				    fail "Can not read comment file"\
				    	"$comment_file."
				echo "Using comment file $comment_file"\
					"for comments."
				# shift past the comment_file arg
				shift
			elif [[ $1 == '-C' && $command == 'diffs' || 
				$command == 'tdiffs' &&
				-z $WXDIFFCMD ]]; then
				if [[ $2 != +([0-9]) ]]; then
					# provide default context value for
					# compat with old wx
					args="$args -C5"
				else
					args="$args -C$2"
					# shift past context lines arg
					shift 
				fi
			else
				args="$args $1"
			fi;;
		-p) 	if [[ $command == @(putback|pb) ]]; then
				if workspace access $2 >/dev/null; then
					# 2nd arg is a workspace
					args="$args $1 $2"
				else
					fail "$2 not a workspace."\
						"Run 'wx help' for info."
				fi
				# shift past the parent ws arg
				shift
			else
				# for other commands -p doesn't have a arg
				args="$args $1"
			fi;;
		-r) 	if [[ $command == @(get|extract) ]]; then
				# 2nd arg is the version #
				args="$args $1 $2"
				# shift past 2nd arg
				shift
			else
				# for other commands -r doesn't have a arg
				args="$args $1"
			fi;;
		-s) 	if [[ "$command" == @(update|init) ]]; then
                                args="$args $1"
                        else
                                silent=-s
                        fi;;
		-N)	if [[ "$command" == @(codereview|fullreview) ]]; then
				show_comments=false
			else
				args="$args $1"
			fi ;;
		-*) 	args="$args $1";;
		*)  	if [[ -z "$file_list" ]]; then
				file_list="$1"
			else
				file_list="$file_list $1"
			fi;;
	esac
	shift
done

if [[ "$command" == "init" ]]; then
	if [ -z "$file_list" ]; then
		file_list=$DEFAULT_SRCDIR
	fi
	wx_init $file_list $args
	exit
fi

if [ ! -d $wxdir/tmp ]; then
	echo "Workspace does not appear to be initialized for $ME."
	echo "The initialization process will create a few files under"
	echo "$wxdir but will not otherwise affect your workspace."
	ok_to_proceed 'OK to proceed?'

	ask "Where is the root of the source code in this workspace?" \
		$DEFAULT_SRCDIR
	# wx_init modifies file_list so save current value
	tmp_file_list=$file_list
	file_list=
	# save off args and set to null to avoid side effects
	tmp_args=$args
	args=
	wx_init $answer
	# restore original file list and cd to original dir in case there's
	# a command to execute.
	file_list=$tmp_file_list
	args=$tmp_args
	cd $dot
fi

if [[ ! -f $wxdir/local_nametable ]]; then
	touch $wxdir/local_nametable 
fi

# Doing this for backward compat since old wx doesn't have a renamed list
if [[ ! -f $wxdir/renamed ]]; then
	# if 'wx update' or 'wx update -r' is the command then skip
	# renamed list creation since it will happen anyway.
	if [[ "$command" != "update" ]] || [[ "$args" == *'-q'* ]]; then
		ring_bell
		cat <<-EOF

$ME needs to create a renamed file list.  If you are sure that no files
were renamed or deleted in the current workspace then answer no to the
following question.

		EOF
		yesno "Okay to search for renamed files (can be slow)?"
		if [[ "$answer" == "yes" ]]
		then
			wx_update -r
		else
			touch $wxdir/renamed
		fi
	fi
fi

# Doing this for backward compat since old wx doesn't have a new list
if [[ ! -f $wxdir/new ]]; then
	ring_bell
	cat <<-EOF

$ME needs to create a new-file list (cache names of newly created
files).  Please be patient.
	EOF
	# Avoid a putback -n which is slow, just use lookup_parent()
	touch $wxdir/new || fail "Error: cannot create $wxdir/new list"
	wx_active |
		while read filepath; do
			if ! lookup_parent $filepath; then
				add_new $filepath
			fi
		done
	echo "\nNew files:"
	cat $wxdir/new
	echo
fi

if [[ "$command" == @(restore|backup|bu) ]]; then
	# If the backup dir was specified as a file arg...
	if [ -n "$file_list" ]; then
		backup_dir=$(echo "$file_list"|cut -f1 -d' ')
	fi
	# unset file_list since this file arg has been processed here.
	unset file_list
elif [[ "$command" == "ea" ]]; then
	# Do this command before wx_active is run because the active list
	# may be corrupt.
	cd $wxdir
	exec ${EDITOR-vi} active
elif [[ "$command" == @(unedit|uncheckout|unco) ]]; then
	if [[ -z "$file_list" && $args != *-f ]]; then
		echo "$ME will $command all active files which may remove"\
		    "them from the active list." 
		ok_to_proceed 'Do you REALLY want to do this?'
	fi
	cp $wxdir/active $wxdir/active.old
elif [[ "$command" == @(bugs|arcs) ]]; then
	# -v verbatim is not valid for these commands
	if [[ "$args" == *'-v'* ]]; then
		fail "Invalid flag -v. Run 'wx help' for info."
	fi
elif [[ "$command" == "create" ]]; then
	if [ -z "$file_list" ]; then
		fail "$command missing file arg(s). Run 'wx help' for info."
	fi

	cp $wxdir/active $wxdir/active.old ||
		fail "Error could not backup $wxdir/active"
elif [[ "$command" == @(delget|checkin|ci) && -n "$comment_file" ]]; then
	cp $wxdir/active $wxdir/active.old ||
		fail "Error could not backup $wxdir/active"
elif [[ "$command" == @(mv) ]]; then
	if [[ $(echo "$file_list"|wc -w) -ne 2 ]]; then
		fail "$command requires two args. Run 'wx help' for info."
	fi

	cp $wxdir/active $wxdir/active.old ||
		fail "Error could not backup $wxdir/active"
	cp $wxdir/renamed $wxdir/renamed.old ||
		fail "Error could not backup $wxdir/renamed"
elif [[ "$command" == @(delete|rm) ]]; then

	if [ -z "$file_list" ]; then
		echo "$ME will try to delete all active files which may "\
		    "remove them from the active list."
		ok_to_proceed 'Do you REALLY want to do this?'
	fi

	cp $wxdir/active $wxdir/active.old ||
		fail "Error: could not backup $wxdir/active"
	cp $wxdir/renamed $wxdir/renamed.old ||
		fail "Error: could not backup $wxdir/renamed"
elif [[ "$command" == reset ]]; then
	cp $wsdata/nametable $wxtmp/nametable.orig || \
		fail "Error: cp $wsdata/nametable $wxtmp/nametable.orig failed."
fi

if [ -z "$file_list" ]; then
	basedir=$workspace
	file_list=$(wx_active) || fail
else
	base_file_list=$file_list
	file_list=
	for basefile in $base_file_list; do
		# normalize the filepaths
		if [[ -d $basefile ]]; then
			basedir=$(cd $basefile && /bin/pwd)
			abspath=$basedir
		else
			basedir=$(cd $(dirname $basefile) && /bin/pwd)
			abspath=$basedir/$(basename $basefile)
		fi
		if [[ ! -d $basedir ]]; then
			fail "Error: Path to $basefile does not exist."
                elif [[ $(cd $basedir; workspace name) != $workspace ]]; then
			fail "Error: $basefile isn't in current workspace: $workspace."

		fi
		filepath=${abspath##$workspace/}
		if [[ -z "$file_list" ]]; then
			file_list="$filepath"
		else
			file_list="$file_list $filepath"
		fi
	done
	FILES_PASSED=true
fi

if [[ "$command" == @(nits|pbchk) ]]; then
	tmp_list=
	# skip nits/pbchk checks for files listed in $command.NOT
	if [[ -f $wxdir/${command}.NOT ]]; then
		for _a_file in $file_list; do
			if grep -q "^$(escape_re $_a_file)$" \
				$wxdir/${command}.NOT
			then
				echo "skipping $command checks for "\
				    "$_a_file (skipping)"
			else
				tmp_list="$tmp_list $_a_file"
			fi
		done
		file_list=${tmp_list# }
	fi
	[[ -z $file_list ]] && exit 0
fi

# This is where the commands are executed.
for command in $comlist; do
cd $dot
case $command in
	list|active) wx_active $args ;;
	pblist)	wx_active -p;;
	renamed)	list_renamed $args ;;
	new)	list_new $args;;
	update)	wx_update $args;;
	out)	wx_checked_out; cat $wxtmp/checked_out;;
	diffs)	wx_eval -r 'print -- "\n------- $filepath -------\n";
			sccs get -s -p -k $filepath |
			${WXDIFFCMD:-diff} $args - $filepath';;
	tdiffs)	## As diffs but also shows new files.
		if [[ -r $wxdir/new ]]; then	
		    ## Read names of new files into space separated list.
		    while read new_file
		    do
			new_files="${new_files}${new_file} "
		    done < $wxdir/new
		else
		    new_files=""
		fi
		## For new files a comparison is made with /dev/null thus
		## all lines will appear to have been added.
		wx_eval -r 'print -- "\n------- $filepath -------\n";
		    if [[ ${new_files} == *"${filepath} "* ]]; then
			${WXDIFFCMD:-diff} $args /dev/null $filepath;
		    else
			sccs get -s -p -k $filepath |
			${WXDIFFCMD:-diff} $args - $filepath;
		    fi';;
	pdiffs|tpdiffs) 
		## Parent Diffs - Compare with parent file.  For
		## 'tpdiffs' when the parent file does not exist the
		## child file is assumed new and compared to
		## /dev/null; thus all lines will appear to have been
		## added.
		wx_eval '
		print -- "\n------- $filepath -------\n";
		if wx_pnt_filepath; then
			echo "Index: $filepath";
			${WXDIFFCMD:-diff} $args $parentfilepath
			    $workspace/$filepath;
		    elif [[ $command == 'tpdiffs' ]]; then
			${WXDIFFCMD:-diff} $args /dev/null
			    $workspace/$filepath;
		    else
			print "New file (does not exist in parent).";
		    fi';;
	pvi)	wx_eval '
		echo $filepath;
		if wx_pnt_filepath; then
			${EDITOR-vi} $args $parentfilepath;
		else
			echo "New file (does not exist in parent)";
		fi';;
	edit|checkout|co)	wx_eval wx_edit;;
	unedit|uncheckout|unco)	wx_eval wx_unedit;;
	create)		wx_eval wx_create $args;;
	uncreate)	wx_eval wx_uncreate $args;;
	delete|rm)	wx_eval wx_delete $args;;
	mv)		wx_mv $file_list;;
	delget|checkin|ci)	wx_eval wx_delget $args;;
	get|extract)	wx_eval wx_get;;
	reset)		wx_eval wx_reset $args;;
	putback|pb)	wx_putback $args;;
	resolve)	wx_resolve $args;;
	prt)		wx_eval 'sccs prt $args $file';;
	comments)	wx_eval 'echo $filepath; echo; wx_show_comment; echo';;
	bugs)   wx_summary -ao $args;;
	arcs)   wx_summary -bo $args;;
	pbcom)  wx_summary -po $args;;
	info)	wx_eval wx_info;;
	reedit|recheckout|reco)  wx_reedit $args;;
	redelget|recheckin|reci) CHECKIN=true; wx_reedit $args;;
	cstyle) echo "\nDoing cstyle check:"
		rm -f $wxtmp/wx.cstyle.*;
		export CSTYLE_INDEX=0;
		wx_eval wx_cstyle;
		wait;
		sort -k 1,1 -k 2,2n $wxtmp/wx.cstyle.* 2> /dev/null
		;;
	jstyle) echo "\nDoing jstyle check:"
		rm -f $wxtmp/wx.jstyle.*;
		export JSTYLE_INDEX=0;
		wx_eval wx_jstyle;
		wait;
		sort -k 1,1 -k 2,2n $wxtmp/wx.jstyle.* 2> /dev/null
		;;
	hdrchk)	echo "\nDoing header format check:";
		cd $workspace; 
		hdrchk_files=;
		for filepath in $file_list ; do
			if [[ "$filepath" == *.h ]]; then
				if [[ -s $wxdir/${command}.NOT ]] &&
					grep -q "^$(escape_re $filepath)$" \
						$wxdir/${command}.NOT
				then
					echo "$filepath (skipping)"
				else
					hdrchk_files="$hdrchk_files $filepath"
				fi
			fi
		done
		hdrchk -a $args $hdrchk_files ;;
	makestyle) echo "\nDoing makestyle check:";
		cd $workspace; mlist=$(wx_active | grep '[Mm]akefile');
		[[ -n "$mlist" ]] && makestyle $args $mlist;;

	keywords) 
		echo "\nDoing keywords check:";
		cd $workspace;
		keyword_files=;
		for filepath in $file_list ; do
			if [[ -s $wxdir/${command}.NOT ]] &&
				grep -q "^$(escape_re $filepath)$" \
					$wxdir/${command}.NOT
			then
				echo "$filepath (skipping)"
			else
				keyword_files="$keyword_files $filepath"
			fi
		done
		keywords -p $args $keyword_files;;

	rmdelchk) echo "\nDoing sccs rmdel check:"; wx_eval rmdelchk;;

	rtichk) wx_rtichk;;

	deltachk)  echo "\nDoing multi delta check:"; wx_eval deltachk;;
	copyright) echo "\nDoing copyright check:"; 
		cd $workspace;
		copyright_files=;
		for filepath in $file_list; do
			if [[ -s $wxdir/${command}.NOT ]] &&
				grep -q "^$(escape_re $filepath)$" \
					$wxdir/${command}.NOT
			then
				echo "$filepath (skipping)"
			else
				copyright_files="$copyright_files $filepath"
			fi
		done
		copyrightchk $copyright_files;;

	cddlchk)
		echo "\nDoing CDDL block check:";
		cd $workspace;
		cddlnot="";
		if [[ -s $wxdir/${command}.NOT ]]; then
			cddlnot="-x $wxdir/${command}.NOT"
		fi

		#
		# Split the file list into new files and existing files.
		# New files must have a CDDL block whereas existing files don't
		# necessarily have to have a block, but if they do it must be
		# valid.  Both sets of files are subject to cddlchk.NOT
		# exception processing.
		# 
		old=""
		new=""
		for filepath in $file_list; do
			if wx_pnt_filepath $filepath; then
				old="$old $filepath"
			else
				new="$new $filepath"
			fi
		done
		[[ ! -z $new ]] && cddlchk $cddlnot $args -a $new
		[[ ! -z $old ]] && cddlchk $cddlnot $args $old
		;;
	comchk)	 echo "\nDoing comments check:"; wx_summary -n 2>&1;;
	outchk)	 echo "\nDoing out check:"; outchk;;
	backup|bu) wx_backup $args;;
	restore) wx_restore $args;;
	apply)	wx_eval "$subcommand \$file";;
	eval)	wx_eval "$subcommand";;
	grep|egrep)
		   wx_eval '
		   if egrep -s '\'$pattern\'' $file;
		   then
			   echo $filepath;
			   $command $args '\'$pattern\'' $file;
		   fi';;
	nawk|sed)
		wx_eval 'echo $filepath; $command $args '\'$pattern\'' $file';;
	codereview) args="-e $args"; wx_eval wx_fullreview;;
	fullreview) wx_eval wx_fullreview;;
	webrev) wx_webrev $args;;
	dir)	echo $wxdir;;
	e)	cd $wxdir; exec ${EDITOR-vi} $orig_args;;
	ws)	cd $wsdata; cat $orig_args;;
	args)	cat $wsdata/args;;
	access)	cat $wsdata/access_control;;
	*)	ring_bell;
		echo "Command not found. Run 'wx help' for command list.";
		exit 1;;
esac

done

if [[ $NEED_WS_CLEAN == 'y' ]]; then
	# clean up the nametable
	print -u2 "Running workspace updatenames to clean up nametable, may"\
	    "take a while."
	workspace updatenames >&2
fi

if [[ -n $bofilelist ]]; then
	$BRINGOVER $bofilelist
fi

# save sorting for last for some speed up.
if [[ $ACTSORT == sort ]]; then
	if $do_renamed_sort; then
		sort_renamed
	fi
	if $do_active_sort; then
		sort_active
	fi
fi
