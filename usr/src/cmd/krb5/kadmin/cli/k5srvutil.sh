#!/bin/sh
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
#
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN

# list_princs keytab
# returns a list of principals in the keytab
# sorted and uniquified
list_princs() {
    klist -k $keytab | tail +4 | awk '{print $2}' | sort | uniq
}

set_command() {
    if [ x$command != x ] ; then
	cmd_error `gettext  "Only one command can be specified"`
	usage
	exit 1
    fi
    command=$1
}

#interactive_prompt prompt princ
# If in interactive mode  return true if the principal  should be acted on
# otherwise return true all the time
#
# SUNW14resync: If in interactive mode the default is now to return false
#               i.e. if in interactive mode unless the user types "Yes" or
#               "yes" false will be returned.
#
interactive_prompt() {
    if [ $interactive = 0 ] ; then
	return 0
    fi
    PROMPT=`gettext  "%s for %s? [yes no] "`
    Y1=`gettext  "yes"`
    Y2=`gettext  "Yes"`
    printf "$PROMPT" "$1" "$2"
    read ans
    case $ans in
    ${Y1}|${Y2})
	return 0
	;;
    esac
    return 1
    }
    
cmd_error() {
    echo $@ 2>&1
    }

usage() {
    USAGE=`gettext "Usage: $0 [-i] [-f file] list|change|delete|delold"`
    echo $USAGE
}



change_key() {
    princs=`list_princs `
    for princ in $princs; do
	ACTION=`gettext  "Change key"`
	if interactive_prompt "$ACTION" $princ; then
	    kadmin -k -t $keytab -p $princ -q "ktadd -k $keytab $princ"
	fi
    done
    }

delete_old_keys() {
    princs=`list_princs `
    for princ in $princs; do
	ACTION=`gettext  "Delete old keys"`
	if interactive_prompt "$ACTION" $princ; then
	    kadmin -k -t $keytab -p $princ -q "ktrem -k $keytab $princ old"
	fi
    done
    }

delete_keys() {
    interactive=1
    princs=`list_princs `
    for princ in $princs; do
	ACTION=`gettext  "Delete all keys"`
	if interactive_prompt "$ACTION" $princ; then
	    kadmin -p $princ -k -t $keytab -q "ktrem -k $keytab $princ all"
	fi
    done
    }


keytab=/etc/krb5/krb5.keytab
interactive=0

CHANGE=`gettext  "change"`
DELOLD=`gettext  "delold"`
DELETE=`gettext  "delete"`
LIST=`gettext  "list"`

while [ $# -gt 0 ] ; do
    opt=$1
    shift
        case $opt in
	"-f")
	keytab=$1
	shift
	;;
	"-i")
	interactive=1
	;;
	${CHANGE}|${DELOLD}|${DELETE}|${LIST})
	set_command $opt
	;;
	*)
	ILLEGAL=`gettext  "Illegal option: "`
	cmd_error $ILLEGAL $opt
	usage
	exit 1
	;;
	esac
done
	

case $command in
    $CHANGE)
    change_key
    ;;
    $DELOLD)
    delete_old_keys
    ;;
    $DELETE)
    delete_keys
    ;;
    $LIST)
    klist -k $keytab
    ;;
    *)
        usage
	;;
    esac
