#!/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2025 Oxide Computer Company
#

function cd_git_root
{
	git_root=$(git rev-parse --show-toplevel)

	if [[ ! -d $git_root ]]; then
		echo "Must be run from within git repository"
		exit 1
	fi

	cd $git_root
}

function check_stale
{
	cd_git_root
	awk -f - <<'EOF'
function check_ignore(repo_root, path, seen_lines, printed_header)
{
	fp = repo_root "/" path;
	lnr = 0;
	found = 0;
	while (getline < (repo_root "/" path) > 0) {
		lnr += 1;
		original = $0;
		# trim comments
		sub(/#.*/, "");
		# and white space
		sub(/[ \t]+/, "");

		if (length() == 0) {
			# skip empty lines
			continue;
		}
		if (/^!/) {
			# skip excludes
			continue;
		}
		if (seen_lines[lnr] == 0) {
			if (printed_header == 0) {
				print "Possible stale:" > "/dev/stderr"
				printed_header = 1;
			}
			printf "%s:%u\t%s\n", path, lnr, original;
			found += 1;
		}
	}
	return found;
}

BEGIN {
	cmd_ignored_files = \
	"git ls-files -i -o -x '*' | git check-ignore -v --stdin --no-index";
	FS=":"
	while ((cmd_ignored_files | getline) > 0) {
		# If --verbose is specified, the output is a series of lines of the form:
		# <source> <COLON> <linenum> <COLON> <pattern> <HT> <pathname>
		seen_lines[$1][$2] = 1;
	}

	nignore = 0;
	while (("git ls-files --full-name '*.gitignore'" | getline) > 0) {
		ignores[nignore] = $0;
		nignore += 1;
	}

	"git rev-parse --show-toplevel" | getline repo_root

	total = 0;
	for (n in ignores) {
		path = ignores[n];
		total += check_ignore(repo_root, path, seen_lines[path], total);
	}
}
EOF
}

function check_tracked
{
	cd_git_root
	echo "git-tracked files matched by gitignore:" 1>&2
	git ls-files | git check-ignore --no-index --stdin
}


USAGE='Usage: check-gitignore <check>

Where <check> is one of:
	tracked	- Are any tracked files covered by a gitignore?
	stale	- Are there gitignore definitions which match no files?
'

case $1 in
	tracked )
		check_tracked
		;;
	stale )
		check_stale
		;;
	* )
		echo "$USAGE"
		exit 1
		;;
esac
