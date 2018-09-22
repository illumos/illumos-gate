#!/bin/ksh -p
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2018 Datto Inc.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#
# STRATEGY:
#	1. Ensure empty JSON is printed when there is no channel program output
#	2. Compare JSON output formatting for a channel program to template
#	3. Using bad command line option (-Z) gives correct error output
#

verify_runnable "both"

function cleanup
{
	log_must zfs destroy -r $TESTDS
	return 0
}
log_onexit cleanup

log_assert "Channel programs output valid JSON"

TESTDS="$TESTPOOL/zcp-json"
TESTSNAP="$TESTDS@snap0"
log_must zfs create $TESTDS

# 1. Ensure empty JSON is printed when there is no channel program output
TESTZCP="/$TESTDS/zfs_destroy.zcp"
cat > "$TESTZCP" << EOF
       args = ...
       argv = args["argv"]
       zfs.sync.destroy(argv[1])
EOF

EMPTY_OUTPUT=("{}")
log_must zfs snap $TESTSNAP 2>&1
log_must zfs list $TESTSNAP 2>&1
log_must zfs program $TESTPOOL $TESTZCP $TESTSNAP 2>&1
log_mustnot zfs list $TESTSNAP 2>&1
log_must zfs snap $TESTSNAP 2>&1
log_must zfs list $TESTSNAP 2>&1
log_must zfs program -j $TESTPOOL $TESTZCP $TESTSNAP 2>&1
log_mustnot zfs list $TESTSNAP 2>&1
log_must zfs snap $TESTSNAP 2>&1
log_must zfs list $TESTSNAP 2>&1
OUTPUT=$(zfs program -j $TESTPOOL $TESTZCP $TESTSNAP 2>&1)
if [ "$OUTPUT" != "$EMPTY_OUTPUT" ]; then
       log_note "Got     :$OUTPUT"
       log_note "Expected:$EMPTY_OUTPUT"
       log_fail "Channel program output not empty";
fi
log_mustnot zfs list $TESTSNAP 2>&1

# 2. Compare JSON output formatting for a channel program to template
TESTZCP="/$TESTDS/zfs_rlist.zcp"
cat > "$TESTZCP" << EOF
	succeeded = {}
	failed = {}

	function list_recursive(root, prop)
		for child in zfs.list.children(root) do
			list_recursive(child, prop)
		end
		val, src  = zfs.get_prop(root, prop)
		if (val == nil) then
			failed[root] = val
		else
			succeeded[root] = val
		end
	end

	args = ...

	argv = args["argv"]

	list_recursive(argv[1], argv[2])

	results = {}
	results["succeeded"] = succeeded
	results["failed"] = failed
	return results
EOF

typeset -a pos_cmds=("recordsize" "type")
typeset -a pos_cmds_out=(
"{
    \"return\": {
        \"failed\": {},
        \"succeeded\": {
            \"$TESTDS\": 131072
        }
    }
}"
"{
    \"return\": {
        \"failed\": {},
        \"succeeded\": {
            \"$TESTDS\": \"filesystem\"
        }
    }
}")
typeset -i cnt=0
typeset cmd
for cmd in ${pos_cmds[@]}; do
	log_must zfs program $TESTPOOL $TESTZCP $TESTDS $cmd 2>&1
	log_must zfs program -j $TESTPOOL $TESTZCP $TESTDS $cmd 2>&1
	# json.tool is needed to guarantee consistent ordering of fields
	# sed is needed to trim trailing space in CentOS 6's json.tool output
	OUTPUT=$(zfs program -j $TESTPOOL $TESTZCP $TESTDS $cmd 2>&1 | python -m json.tool | sed 's/[[:space:]]*$//')
	if [ "$OUTPUT" != "${pos_cmds_out[$cnt]}" ]; then
		log_note "Got     :$OUTPUT"
		log_note "Expected:${pos_cmds_out[$cnt]}"
		log_fail "Unexpected channel program output";
	fi
	cnt=$((cnt + 1))
done

# 3. Using bad command line option (-Z) gives correct error output
typeset -a neg_cmds=("-Z")
typeset -a neg_cmds_out=(
"invalid option 'Z'
usage:
	program [-jn] [-t <instruction limit>] [-m <memory limit (b)>] <pool> <program file> [lua args...]

For the property list, run: zfs set|get

For the delegated permission list, run: zfs allow|unallow")
cnt=0
for cmd in ${neg_cmds[@]}; do
	log_mustnot zfs program $cmd $TESTPOOL $TESTZCP $TESTDS 2>&1
	log_mustnot zfs program -j $cmd $TESTPOOL $TESTZCP $TESTDS 2>&1
	OUTPUT=$(zfs program -j $cmd $TESTPOOL $TESTZCP $TESTDS 2>&1)
	if [ "$OUTPUT" != "${neg_cmds_out[$cnt]}" ]; then
		log_note "Got     :$OUTPUT"
		log_note "Expected:${neg_cmds_out[$cnt]}"
		log_fail "Unexpected channel program error output";
	fi
	cnt=$((cnt + 1))
done

log_pass "Channel programs output valid JSON"
