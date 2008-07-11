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
# Easy setup script for populating a user's ~/.hgrc
# This currently does the following:
#	* Load the cadmium extension
#	* Populate the author/email fields to be correct
#	* Alias canonical repositories like onnv-gate
#	* Configures mercurial to use appropriate merge tools
#
# See hgrc(5) for more information
#

HGRC=$HOME/.hgrc

usage() {
	prog=$(basename "$0")
	echo \
"usage: $prog [-f] [-c cdm_path] [-m merge_path] [-n name] [-e email] [-p proxy]
	-f            : force overwriting $HGRC
	-c cdm_path   : override Cadmium path
	-m merge_path : override path to merge tool
	-n name       : override name (for ui.username)
	-e email      : override email (for email.from)
	-p proxy      : enable use of web proxy with specified proxy

	if -e isn't provided, and you are on SWAN, an LDAP query is done
	if -n isn't provided, the entry from /etc/passwd is used
	
	proxy should be in the form of hostname:port
	if on-SWAN, $prog will lookup your email address.  this can be
	overridden by using the -e flag.
	"
	exit 1
}

while getopts c:e:fm:n:p: opt; do
	case "$opt" in
	c) cdm_path=$OPTARG;;
	e) email=$OPTARG;;
	f) force=1;;
	m) merge_path=$OPTARG;;
	n) name=$OPTARG;;
	p) proxy=$OPTARG;;
	*) usage;;
	esac
done

if [ -f $HGRC -a "$force" -eq 0 ]; then
	echo "Error: You have an existing .hgrc in $HGRC"
	echo "Please move it aside."
	exit 1
fi

AWK="/usr/xpg4/bin/awk"
SED="/usr/bin/sed"
LDAPCLIENT="/usr/bin/ldapsearch"

login=$(/usr/bin/id -un)

#
# Try and determine where Cadmium is installed.  In order of
# preference, look in:
#
#   1. $(whence $0), on the assumption that you want the version
#      of cadmium that best matches the hgsetup script you invoked
#
#   2. /opt/onbld, because local is generally better
#
#   3. /ws/onnv-tools/onbld, it's nfs and it might be slow, but it
#      should resolve from most places on-SWAN
#
paths="$(dirname $(whence $0)) /opt/onbld /ws/onnv-tools/onbld"
cdmbin="lib/python/onbld/hgext/cdm.py"

for dir in $paths; do
	if [[ -f "$dir/$cdmbin" && -z "$cdm_path" ]]; then
		cdm_path="$dir/$cdmbin"
		break
	fi
done

if [[ -n $proxy ]]; then
	proxyConfig="[http_proxy]
host=$proxy
"
fi

if getent hosts sunweb.central.sun.com >/dev/null; then
	# on SWAN
	echo "Detected SWAN connection"
	ldapemail='preferredrfc822recipient'
	ldapquery="uid=$login $ldapemail"
	ldapcmd="$LDAPCLIENT -1 -h sun-ds -b dc=sun,dc=com $ldapquery"
	if [[ -z "$email" ]]; then 
		echo "Looking up e-mail address in LDAP"
		email=${email:=$($ldapcmd | $AWK /^$ldapemail:/'{print $2}')}
	fi
fi

if [[ -z $email ]]; then
	my_id=$(id -un)
	my_checkhostname=$(check-hostname)
	my_fqhn=${my_checkhostname##* }
	email="$my_id@$my_fqhn"
	echo "No e-mail address provided, defaulting to $email"
fi

if [[ -z "$name" ]]; then
	name=${name:=$(getent passwd $login | awk -F: '{print $5}')}
fi
username="$name <$email>"

echo "Configured the following:"
if [[ -n $proxy ]]; then
	echo "	proxy: $proxy"
fi
echo "	email: $email"
echo "	username: $name"
echo "	cadmium: $cdm_path"

if [[ -z "$cdm_path" ]]; then
	echo "Warning: you will need to edit your .hgrc file\n" \
	     "to specify a path for cadmium."
fi

if [[ -n $merge_path ]]; then
	echo "	merge: $merge_path"
fi

cat <<EOF >$HGRC
$proxyConfig[extensions]
hgext.cdm=$cdm_path

[email]
from=$email

[paths]
onnv-gate=ssh://anon@hg.opensolaris.org/hg/onnv/onnv-gate

[merge-tools]
filemerge.gui=True
filemerge.args=-a \$base \$local \$other \$output
filemerge.priority=1

meld.gui=True
meld.priority=0

gpyfm.gui=True
gpyfm.priority=0

[ui]
username=$username
EOF

if [[ -n $merge_path ]]; then
	echo "merge=$merge_path" >> $HGRC
fi

echo "Please check $HGRC and verify everything looks correct"
