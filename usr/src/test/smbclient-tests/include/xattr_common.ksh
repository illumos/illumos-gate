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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

# a function that takes a file, then creates and verifies
# an xattr on that file. The xattr_contents is the file
# that should appear in the xattr namespace.

function create_xattr
{       # filename xattr_name xattr_contents
	typeset FILE=$1
	typeset XATTR_NAME=$2
	typeset XATTR_CONTENTS=$3

	# read any empty xattr dir on that file
	cti_execute_cmd "runat $FILE ls"

	# create the xattr
	cti_execute FAIL "runat $FILE cp $XATTR_CONTENTS $XATTR_NAME"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function create_xattr: "\
			"create xattr-of-$FILE failed unexpectedly"
	        return
	fi

	verify_xattr $FILE $XATTR_NAME $XATTR_CONTENTS
}

# a function that compares the a single xattr between two files
# and checks to see if their contents are identical

function compare_xattrs
{       # filename1 filename2 xattr_name
	typeset FILE1=$1
	typeset FILE2=$2
	typeset XATTR_NAME=$3

	cti_execute_cmd "runat $FILE1 cat $XATTR_NAME > /tmp/file1.$$"
	cti_execute_cmd "runat $FILE2 cat $XATTR_NAME > /tmp/file2.$$"
	cti_execute_cmd "diff /tmp/file1.$$ /tmp/file2.$$ \
		>> /tmp/diffout.$$ 2>&1"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function compare_xattrs: "\
			"compare xattr-of-$FILE1 with xattr-of-$FILE2 "\
			"failed unexpectedly"
	        cti_report "diff xattrs-of-$FILE1 xattrs-of-$FILE2 "\
			"printed you can see the file /tmp/diffout.$$"
	        return
	else
	        cti_report "PASS:In function compare_xattrs: "\
			"compare xattr-of-$FILE1 with xattr-of-$FILE2 "\
			"succeeded as expected"
	fi

	cti_execute_cmd "rm /tmp/file1.$$ /tmp/file2.$$"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function compare_xattrs: "\
			"rm temp file: /tmp/file1.$$ /tmp/file2.$$ "\
			"failed unexpectedly"
	        return
	else
	        cti_report "PASS:In function compare_xattrs: "\
			"rm temp file: /tmp/file1.$$ /tmp/file2.$$ "\
			"succeeded as expected"
	fi
}

# verify xattr exists and has content matching xattr_contents

function verify_xattr
{       # filename xattr_name xattr_contents
	typeset FILE=$1
	typeset XATTR_NAME=$2
	typeset XATTR_CONTENTS=$3

	cti_execute_cmd "runat $FILE diff $XATTR_NAME $XATTR_CONTENTS"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function verify_xattr: "\
			"verify xattr-of-$FILE failed unexpectedly"
	        return
	fi
}

function delete_xattr
{       # filename xattr_name
	typeset FILE=$1
	typeset XATTR_NAME=$2

	# delete the xattr
	cti_execute_cmd "runat $FILE rm $XATTR_NAME"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function delete_xattr: "\
			"delete xattr-of-$FILE failed unexpectedly"
	        return
	else
	        cti_report "PASS:In function delete_xattr: "\
			"delete xattr-of-$FILE succeeded as expected"
	fi

	# make sure it's gone (ls should fail)
	cti_execute PASS "runat $FILE ls $XATTR_NAME"
	if [[ $? == 0 ]]; then
	        cti_fail "FAIL:In function delete_xattr: "\
			"$FILE has xattr named $XATTR_NAME unexpectedly"
	        return
	else
	        cti_report "PASS:In function delete_xattr: "\
			"$FILE does not have xattr named "\
			"$XATTR_NAME as expected"
	fi

}

# not sure about this : really this should be testing write/append

function verify_write_xattr
{       # filename xattr_name
	typeset FILE=$1
	typeset XATTR_NAME=$2

	cti_execute_cmd "runat $FILE dd if=/etc/passwd of=$XATTR_NAME"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function verify_write_xattr: "\
			"create xattr-of-$FILE named $XATTR_NAME "\
			"failed unexpectedly"
	        return
	else
	cti_report "PASS:In function verify_write_xattr: "\
		"create xattr-of-$FILE named $XATTR_NAME succeeded"
	fi

	cti_execute_cmd "runat $FILE cat $XATTR_NAME \
		> /tmp/$XATTR_NAME.$$ 2>&1"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function verify_write_xattr: "\
			"cat xattr-of-$FILE named $XATTR_NAME "\
			"failed unexpectedly"
	        return
	else
	        cti_report "PASS:In function verify_write_xattr: "\
			"cat xattr-of-$FILE named $XATTR_NAME succeeded"
	fi

	cti_execute_cmd "dd if=/etc/passwd of=/tmp/passwd_dd.$$"
	cti_execute_cmd "diff /tmp/passwd_dd.$$ /tmp/$XATTR_NAME.$$"
	if [[ $? != 0 ]]; then
	        cti_fail "FAIL:In function verify_write_xattr: "\
			"diff xattr-of-$FILE named $XATTR_NAME failed"
	        return
	else
	        cti_report "PASS:In function verify_write_xattr: "\
			"diff xattr-of-$FILE named $XATTR_NAME succeeded"
	fi

	cti_execute_cmd "rm /tmp/passwd_dd.$$ /tmp/$XATTR_NAME.$$"
}

# this function is to create the expected output

function create_expected_output
{       # expected_output_file  contents_of_the_output
	typeset FILE=$1
	shift
	if [[ -e $FILE ]]; then
	        cti_execute_cmd "rm $FILE"
	fi

	for line in $@
	do
	        cti_execute_cmd "echo $line >> $FILE"
	done
 }
