#!/bin/sh
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
# idsconfig -- script to setup iDS 5.x/6.x/7.x for Native LDAP II.
#
# Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# display_msg(): Displays message corresponding to the tag passed in.
#
display_msg()
{
    case "$1" in
    usage) cat <<EOF
 $PROG: [ -v ] [ -i input file ] [ -o output file ]
   i <input file>     Get setup info from input file.
   o <output file>    Generate a server configuration output file.
   v                  Verbose mode
EOF
    ;;
    backup_server) cat <<EOF
It is strongly recommended that you BACKUP the directory server
before running $PROG.

Hit Ctrl-C at any time before the final confirmation to exit.

EOF
    ;;
    setup_complete) cat <<EOF

$PROG: Setup of iDS server ${IDS_SERVER} is complete.

EOF
    ;;
    display_vlv_list) cat <<EOF

Note: idsconfig has created entries for VLV indexes. 

      For DS5.x, use the directoryserver(1m) script on ${IDS_SERVER}
      to stop the server.  Then, using directoryserver, follow the
      directoryserver examples below to create the actual VLV indexes.

      For DS6.x or later, use dsadm command delivered with DS on ${IDS_SERVER}
      to stop the server.  Then, using dsadm, follow the
      dsadm examples below to create the actual VLV indexes.

EOF
    ;;
    cred_level_menu) cat <<EOF
The following are the supported credential levels:
  1  anonymous
  2  proxy
  3  proxy anonymous
  4  self
EOF
    ;;
    auth_method_menu) cat <<EOF
The following are the supported Authentication Methods:
  1  none
  2  simple
  3  sasl/DIGEST-MD5
  4  tls:simple
  5  tls:sasl/DIGEST-MD5
  6  sasl/GSSAPI
EOF
    ;;
    srvauth_method_menu) cat <<EOF
The following are the supported Authentication Methods:
  1  simple
  2  sasl/DIGEST-MD5
  3  tls:simple
  4  tls:sasl/DIGEST-MD5
  5  sasl/GSSAPI
EOF
    ;;
    prompt_ssd_menu) cat <<EOF
  A  Add a Service Search Descriptor
  D  Delete a SSD
  M  Modify a SSD
  P  Display all SSD's
  H  Help
  X  Clear all SSD's

  Q  Exit menu
EOF
    ;;
    summary_menu)

	SUFFIX_INFO=
	DB_INFO=

	[ -n "${NEED_CREATE_SUFFIX}" ] &&
	{
		SUFFIX_INFO=`cat <<EOF

         Suffix to create          : $LDAP_SUFFIX
EOF
`
		[ -n "${NEED_CREATE_BACKEND}" ] &&
			DB_INFO=`cat <<EOF

         Database to create        : $IDS_DATABASE
EOF
`
	}

	cat <<EOF
              Summary of Configuration

  1  Domain to serve               : $LDAP_DOMAIN
  2  Base DN to setup              : $LDAP_BASEDN$SUFFIX_INFO$DB_INFO
  3  Profile name to create        : $LDAP_PROFILE_NAME
  4  Default Server List           : $LDAP_SERVER_LIST
  5  Preferred Server List         : $LDAP_PREF_SRVLIST
  6  Default Search Scope          : $LDAP_SEARCH_SCOPE
  7  Credential Level              : $LDAP_CRED_LEVEL
  8  Authentication Method         : $LDAP_AUTHMETHOD
  9  Enable Follow Referrals       : $LDAP_FOLLOWREF
 10  iDS Time Limit                : $IDS_TIMELIMIT
 11  iDS Size Limit                : $IDS_SIZELIMIT
 12  Enable crypt password storage : $NEED_CRYPT
 13  Service Auth Method pam_ldap  : $LDAP_SRV_AUTHMETHOD_PAM
 14  Service Auth Method keyserv   : $LDAP_SRV_AUTHMETHOD_KEY
 15  Service Auth Method passwd-cmd: $LDAP_SRV_AUTHMETHOD_CMD
 16  Search Time Limit             : $LDAP_SEARCH_TIME_LIMIT
 17  Profile Time to Live          : $LDAP_PROFILE_TTL
 18  Bind Limit                    : $LDAP_BIND_LIMIT
 19  Enable shadow update          : $LDAP_ENABLE_SHADOW_UPDATE
 20  Service Search Descriptors Menu

EOF
    ;;
    sfx_not_suitable) cat <<EOF

Sorry, suffix ${LDAP_SUFFIX} is not suitable for Base DN ${LDAP_BASEDN}

EOF
    ;;
    obj_not_found) cat <<EOF

Sorry, ${PROG} can't find an objectclass for "$_ATT" attribute

EOF
    ;;
    sfx_config_incons) cat <<EOF

Sorry, there is no suffix mapping for ${LDAP_SUFFIX},
while ldbm database exists, server configuration needs to be fixed manually,
look at cn=mapping tree,cn=config and cn=ldbm database,cn=plugins,cn=config

EOF
    ;;
    ldbm_db_exist) cat <<EOF

Database "${IDS_DATABASE}" already exists,
however "${IDS_DATABASE_AVAIL}" name is available

EOF
    ;;
    unable_find_db_name) cat <<EOF
    
Unable to find any available database name close to "${IDS_DATABASE}"

EOF
    ;;
    create_ldbm_db_error) cat <<EOF

ERROR: unable to create suffix ${LDAP_SUFFIX}
       due to server error that occurred during creation of ldbm database

EOF
    ;;
    create_suffix_entry_error) cat <<EOF

ERROR: unable to create entry ${LDAP_SUFFIX} of ${LDAP_SUFFIX_OBJ} class

EOF
    ;;
    ldap_suffix_list) cat <<EOF

No valid suffixes (naming contexts) were found for LDAP base DN:
${LDAP_BASEDN}

Available suffixes are:
${LDAP_SUFFIX_LIST}

EOF
    ;;
    sorry) cat <<EOF

HELP - No help is available for this topic.

EOF
    ;;
    create_suffix_help) cat <<EOF

HELP - Our Base DN is ${LDAP_BASEDN}
       and we need to create a Directory Suffix,
       which can be equal to Base DN itself or be any of Base DN parents.
       All intermediate entries up to suffix will be created on demand.

EOF
    ;;
    enter_ldbm_db_help) cat <<EOF

HELP - ldbm database is an internal database for storage of our suffix data.
       Database name must be alphanumeric due to Directory Server restriction.

EOF
    ;;
    backup_help) cat <<EOF

HELP - Since idsconfig modifies the directory server configuration,
       it is strongly recommended that you backup the server prior
       to running this utility.  This is especially true if the server
       being configured is a production server.

EOF
    ;;
    port_help) cat <<EOF

HELP - Enter the port number the directory server is configured to
       use for LDAP.

EOF
    ;;
    domain_help) cat <<EOF

HELP - This is the DNS domain name this server will be serving.  You
       must provide this name even if the server is not going to be populated
       with hostnames.  Any unqualified hostname stored in the directory
       will be fully qualified using this DNS domain name.

EOF
    ;;
    basedn_help) cat <<EOF

HELP - This parameter defines the default location in the directory tree for
       the naming services entries.  You can override this default by using 
       serviceSearchDescriptors (SSD). You will be given the option to set up 
       an SSD later on in the setup.

EOF
    ;;
    profile_help) cat <<EOF

HELP - Name of the configuration profile with which the clients will be
       configured. A directory server can store various profiles for multiple 
       groups of clients.  The initialization tool, (ldapclient(1M)), assumes 
       "default" unless another is specified.

EOF
    ;;
    def_srvlist_help) cat <<EOF

HELP - Provide a list of directory servers to serve clients using this profile.
       All these servers should contain consistent data and provide similar 
       functionality.  This list is not ordered, and clients might change the 
       order given in this list. Note that this is a space separated list of 
       *IP addresses* (not host names).  Providing port numbers is optional.

EOF
    ;;
    pref_srvlist_help) cat <<EOF

HELP - Provide a list of directory servers to serve this client profile. 
       Unlike the default server list, which is not ordered, the preferred 
       servers must be entered IN THE ORDER you wish to have them contacted. 
       If you do specify a preferred server list, clients will always contact 
       them before attempting to contact any of the servers on the default 
       server list. Note that you must enter the preferred server list as a 
       space-separated list of *IP addresses* (not host names).  Providing port 
       numbers is optional.

EOF
    ;;
    srch_scope_help) cat <<EOF

HELP - Default search scope to be used for all searches unless they are
       overwritten using serviceSearchDescriptors.  The valid options
       are "one", which would specify the search will only be performed 
       at the base DN for the given service, or "sub", which would specify 
       the search will be performed through *all* levels below the base DN 
       for the given service.

EOF
    ;;
    cred_lvl_help) cat <<EOF

HELP - This parameter defines what credentials the clients use to
       authenticate to the directory server.  This list might contain
       multiple credential levels and is ordered.  If a proxy level
       is configured, you will also be prompted to enter a bind DN
       for the proxy agent along with a password.  This proxy agent
       will be created if it does not exist.

EOF
    ;;
    auth_help) cat <<EOF

HELP - The default authentication method(s) to be used by all services
       in the client using this profile.  This is a ordered list of
       authentication methods separated by a ';'.  The supported methods
       are provided in a menu.  Note that sasl/DIGEST-MD5 binds require
       passwords to be stored un-encrypted on the server.

EOF
    ;;
    srvauth_help) cat <<EOF

HELP - The authentication methods to be used by a given service.  Currently
       3 services support this feature: pam_ldap, keyserv, and passwd-cmd.
       The authentication method specified in this attribute overrides
       the default authentication method defined in the profile.  This
       feature can be used to select stronger authentication methods for
       services which require increased security.

EOF
    ;;
    pam_ldap_help) cat <<EOF

HELP - The authentication method(s) to be used by pam_ldap when contacting
       the directory server.  This is a ordered list, and, if provided, will
       override the default authentication method parameter.

EOF
    ;;
    keyserv_help) cat <<EOF

HELP - The authentication method(s) to be used by newkey(1M) and chkey(1)
       when contacting the directory server.  This is a ordered list and
       if provided will override the default authentication method
       parameter.

EOF
    ;;
    passwd-cmd_help) cat <<EOF

HELP - The authentication method(s) to be used by passwd(1) command when
       contacting the directory server.  This is a ordered list and if
       provided will override the default authentication method parameter.

EOF
    ;;
    referrals_help) cat <<EOF

HELP - This parameter indicates whether the client should follow
       ldap referrals if it encounters one during naming lookups.

EOF
    ;;
    tlim_help) cat <<EOF

HELP - The server time limit value indicates the maximum amount of time the
       server would spend on a query from the client before abandoning it.
       A value of '-1' indicates no limit.

EOF
    ;;
    slim_help) cat <<EOF

HELP - The server sizelimit value indicates the maximum number of entries
       the server would return in respond to a query from the client.  A
       value of '-1' indicates no limit.

EOF
    ;;
    crypt_help) cat <<EOF

HELP - By default iDS does not store userPassword attribute values using
       unix "crypt" format.  If you need to keep your passwords in the crypt
       format for NIS/NIS+ and pam_unix compatibility, choose 'yes'.  If
       passwords are stored using any other format than crypt, pam_ldap
       MUST be used by clients to authenticate users to the system. Note 
       that if you wish to use sasl/DIGEST-MD5 in conjunction with pam_ldap,
       user passwords must be stored in the clear format.

EOF
    ;;
    srchtime_help) cat <<EOF

HELP - The search time limit the client will enforce for directory
       lookups.

EOF
    ;;
    profttl_help) cat <<EOF

HELP - The time to live value for profile.  The client will refresh its
       cached version of the configuration profile at this TTL interval.

EOF
    ;;
    bindlim_help) cat <<EOF

HELP - The time limit for the bind operation to the directory.  This
       value controls the responsiveness of the client in case a server
       becomes unavailable.  The smallest timeout value for a given
       network architecture/conditions would work best.  This is very
       similar to setting TCP timeout, but only for LDAP bind operation.

EOF
    ;;
    ssd_help) cat <<EOF

HELP - Using Service Search Descriptors (SSD), you can override the
       default configuration for a given service.  The SSD can be
       used to override the default search base DN, the default search
       scope, and the default search filter to be used for directory
       lookups.  SSD are supported for all services (databases)
       defined in nsswitch.conf(4).  The default base DN is defined
       in ldap(1).

       Note: SSD are powerful tools in defining configuration profiles
             and provide a great deal of flexibility.  However, care
             must be taken in creating them.  If you decide to make use
             of SSDs, consult the documentation first.

EOF
    ;;
    ssd_menu_help) cat <<EOF

HELP - Using this menu SSD can be added, updated, or deleted from
       the profile.

       A - This option creates a new SSD by prompting for the
           service name, base DN, and scope.  Service name is
           any valid service as defined in ldap(1).  base is
           either the distinguished name to the container where
           this service will use, or a relative DN followed
           by a ','.
       D - Delete a previously created SSD.
       M - Modify a previously created SSD.
       P - Display a list of all the previously created SSD.
       X - Delete all of the previously created SSD.

       Q - Exit the menu and continue with the server configuration.

EOF
    ;;
    ldap_suffix_list_help) cat <<EOF

HELP - No valid suffixes (naming contexts) are available on server 
       ${IDS_SERVER}:${IDS_PORT}.
       You must set an LDAP Base DN that can be contained in 
       an existing suffix.

EOF
    ;;
    enable_shadow_update_help) cat <<EOF

HELP - Enter 'y' to set up the LDAP server for shadow update.
       The setup will add an administrator identity/credential
       and modify the necessary access controls for the client
       to update shadow(4) data on the LDAP server. If sasl/GSSAPI
       is in use, the Kerberos host principal will be used as the
       administrator identity.

       Shadow data is used for password aging and account locking.
       Please refer to the shadow(4) manual page for details.

EOF
    ;;
    add_admin_cred_help) cat <<EOF

HELP - Start the setup to add an administrator identity/credential
       and to modify access controls for the client to update
       shadow(4) data on the LDAP server.

       Shadow data is used for password aging and account locking.
       Please refer to the shadow(4) manual page for details.

EOF
    ;;
    use_host_principal_help) cat <<EOF

HELP - A profile with a 'sasl/GSSAPI' authentication method and a 'self'
       credential level is detected, enter 'y' to modify the necessary
       access controls for allowing the client to update shadow(4) data
       on the LDAP server.

       Shadow data is used for password aging and account locking.
       Please refer to the shadow(4) manual page for details.

EOF
    ;;
    esac
}


#
# get_ans(): gets an answer from the user.
#		$1  instruction/comment/description/question
#		$2  default value
#
get_ans()
{
    if [ -z "$2" ]
    then
	${ECHO} "$1 \c"
    else
	${ECHO} "$1 [$2] \c"
    fi

    read ANS
    if [ -z "$ANS" ]
    then
	ANS=$2
    fi
}


#
# get_ans_req(): gets an answer (required) from the user, NULL value not allowed.
#		$@  instruction/comment/description/question
#
get_ans_req()
{
    ANS=""                  # Set ANS to NULL.
    while [ "$ANS" = "" ]
    do 
	get_ans "$@"
	[ "$ANS" = "" ] && ${ECHO} "NULL value not allowed!"
    done
}


#
# get_number(): Querys and verifies that number entered is numeric.
#               Function will repeat prompt user for number value.
#               $1  Message text.
#		$2  default value.
#               $3  Help argument.
#
get_number()
{
    ANS=""                  # Set ANS to NULL.
    NUM=""

    get_ans "$1" "$2"

    # Verify that value is numeric.
    while not_numeric $ANS
    do
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg ${3:-sorry} ;;
	    * ) ${ECHO} "Invalid value: \"${ANS}\". \c"
	     ;;
	esac
	# Get a new value.
	get_ans "Enter a numeric value:" "$2"
    done
    NUM=$ANS
}


#
# get_negone_num(): Only allows a -1 or positive integer.
#                   Used for values where -1 has special meaning.
#
#                   $1 - Prompt message.
#                   $2 - Default value (require).
#                   $3 - Optional help argument.
get_negone_num()
{
    while :
    do
	get_number "$1" "$2" "$3"
	if is_negative $ANS
	then
	    if [ "$ANS" = "-1" ]; then
		break  # -1 is OK, so break.
	    else       # Need to re-enter number.
		${ECHO} "Invalid number: please enter -1 or positive number."
	    fi
	else
	    break      # Positive number
	fi
    done
}


#
# get_passwd(): Reads a password from the user and verify with second.
#		$@  instruction/comment/description/question
#
get_passwd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_passwd()"

    # Temporary PASSWD variables
    _PASS1=""
    _PASS2=""

    /usr/bin/stty -echo     # Turn echo OFF

    # Endless loop that continues until passwd and re-entered passwd
    # match.
    while :
    do
	ANS=""                  # Set ANS to NULL.

	# Don't allow NULL for first try.
	while [ "$ANS" = "" ]
	do
	    get_ans "$@"
	    [ "$ANS" = "" ] && ${ECHO} "" && ${ECHO} "NULL passwd not allowed!"
	done
	_PASS1=$ANS         # Store first try.

	# Get second try.
	${ECHO} ""
	get_ans "Re-enter passwd:"
	_PASS2=$ANS

	# Test if passwords are identical.
	if [ "$_PASS1" = "$_PASS2" ]; then
	    break
	fi
	
	# Move cursor down to next line and print ERROR message.
	${ECHO} ""
	${ECHO} "ERROR: passwords don't match; try again."
    done

    /usr/bin/stty echo      # Turn echo ON

    ${ECHO} ""
}


#
# get_passwd_nochk(): Reads a password from the user w/o check.
#		$@  instruction/comment/description/question
#
get_passwd_nochk()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_passwd_nochk()"

    /usr/bin/stty -echo     # Turn echo OFF

    get_ans "$@"

    /usr/bin/stty echo      # Turn echo ON

    ${ECHO} ""
}


#
# get_menu_choice(): Get a menu choice from user.  Continue prompting
#                    till the choice is in required range.
#   $1 .. Message text.
#   $2 .. min value
#   $3 .. max value
#   $4 .. OPTIONAL: default value
#
#   Return value: 
#     MN_CH will contain the value selected.
#
get_menu_choice()
{
    # Check for req parameter.
    if [ $# -lt 3 ]; then
	${ECHO} "get_menu_choice(): Did not get required parameters."
	return 1
    fi

    while :
    do
	get_ans "$1" "$4"
	MN_CH=$ANS
	is_negative $MN_CH
	if [ $? -eq 1 ]; then
	    if [ $MN_CH -ge $2 ]; then
		if [ $MN_CH -le $3 ]; then
		    return
		fi
	    fi
	fi
	${ECHO} "Invalid choice: $MN_CH"
    done
}


#
# get_confirm(): Get confirmation from the user. (Y/Yes or N/No)
#                $1 - Message
#                $2 - default value.
#
get_confirm()
{
    _ANSWER=

    while :
    do
	# Display Internal ERROR if $2 not set.
	if [ -z "$2" ]
	then
	    ${ECHO} "INTERNAL ERROR: get_confirm requires 2 args, 3rd is optional."
	    exit 2
	fi

	# Display prompt.
	${ECHO} "$1 [$2] \c"

	# Get the ANSWER.
	read _ANSWER
	if [ "$_ANSWER" = "" ] && [ -n "$2" ] ; then
	    _ANSWER=$2
	fi
	case "$_ANSWER" in
	    [Yy] | yes | Yes | YES) return 1 ;;
	    [Nn] | no  | No  | NO)  return 0 ;;
	    [Hh] | help | Help | \?) display_msg ${3:-sorry};;
	    * ) ${ECHO} "Please enter y or n."  ;;
	esac
    done
}


#
# get_confirm_nodef(): Get confirmation from the user. (Y/Yes or N/No)
#                      No default value supported.
#
get_confirm_nodef()
{
    _ANSWER=

    while :
    do
	${ECHO} "$@ \c"
	read _ANSWER
	case "$_ANSWER" in
	    [Yy] | yes | Yes | YES) return 1 ;;
	    [Nn] | no  | No  | NO)  return 0 ;;
	    * ) ${ECHO} "Please enter y or n."  ;;
	esac
    done
}


#
# is_numeric(): Tells is a string is numeric.
#    0 = Numeric
#    1 = NOT Numeric
#
is_numeric()
{
    # Check for parameter.
    if [ $# -ne 1 ]; then
	return 1
    fi

    # Determine if numeric.
    expr "$1" + 1 > /dev/null 2>&1
    if [ $? -ge 2 ]; then
	return 1
    fi

    # Made it here, it's Numeric.
    return 0
}


#
# not_numeric(): Reverses the return values of is_numeric.  Useful
#                 for if and while statements that want to test for
#                 non-numeric data.
#    0 = NOT Numeric
#    1 = Numeric
#
not_numeric()
{
    is_numeric $1
    if [ $? -eq 0 ]; then
       return 1
    else
       return 0
    fi
}


#
# is_negative(): Tells is a Numeric value is less than zero.
#    0 = Negative Numeric
#    1 = Positive Numeric
#    2 = NOT Numeric
#
is_negative()
{
    # Check for parameter.
    if [ $# -ne 1 ]; then
	return 1
    fi

    # Determine if numeric.  Can't use expr because -0 is 
    # considered positive??
    if is_numeric $1; then
	case "$1" in 
	    -*)  return 0 ;;   # Negative Numeric
	    *)   return 1 ;;   # Positive Numeric
	esac
    else
	return 2
    fi
}


#
# check_domainname(): check validity of a domain name.  Currently we check
#                     that it has at least two components.
#		$1  the domain name to be checked
#
check_domainname()
{
    if [ ! -z "$1" ]
    then
	t=`expr "$1" : '[^.]\{1,\}[.][^.]\{1,\}'`
	if [ "$t" = 0 ]
	then
	    return 1
	fi
    fi
    return 0
}


#
# check_baseDN(): check validity of the baseDN name.
#		$1  the baseDN name to be checked
#
#     NOTE: The check_baseDN function does not catch all invalid DN's.
#           Its purpose is to reduce the number of invalid DN's to 
#           get past the input routine.  The invalid DN's will be 
#           caught by the LDAP server when they are attempted to be 
#           created.
#
check_baseDN()
{
    ck_DN=$1
    ${ECHO} "  Checking LDAP Base DN ..."
    if [ ! -z "$ck_DN" ]; then
        [ $DEBUG -eq 1 ] && ${ECHO} "Checking baseDN: $ck_DN"
        # Check for = (assignment operator)
        ${ECHO} "$ck_DN" | ${GREP} "=" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            [ $DEBUG -eq 1 ] && ${ECHO} "check_baseDN: No '=' in baseDN."
            return 1
        fi
   
        # Check all keys.
        while :
        do
            # Get first key.
            dkey=`${ECHO} $ck_DN | cut -d'=' -f1`

            # Check that the key string is valid
	    check_attrName $dkey
	    if [ $? -ne 0 ]; then 
                [ $DEBUG -eq 1 ] && ${ECHO} "check_baseDN: invalid key=${dkey}" 
                return 1 
            fi

            [ $DEBUG -eq 1 ] && ${ECHO} "check_baseDN: valid key=${dkey}" 

            # Remove first key from DN
            ck_DN=`${ECHO} $ck_DN | cut -s -d',' -f2-`

            # Break loop if nothing left.
            if [ "$ck_DN" = "" ]; then
                break
            fi
        done
    fi
    return 0
}


#
# domain_2_dc(): Convert a domain name into dc string.
#    $1  .. Domain name.
#
domain_2_dc()
{
    _DOM=$1           # Domain parameter.
    _DOM_2_DC=""      # Return value from function.
    _FIRST=1          # Flag for first time.
    
    export _DOM_2_DC  # Make visible for others.

    # Convert "."'s to spaces for "for" loop.
    domtmp="`${ECHO} ${_DOM} | tr '.' ' '`"
    for i in $domtmp; do
	if [ $_FIRST -eq 1 ]; then 
	    _DOM_2_DC="dc=${i}"
	    _FIRST=0
	else
	    _DOM_2_DC="${_DOM_2_DC},dc=${i}"
	fi
    done
}


#
# is_root_user(): Check to see if logged in as root user.
#
is_root_user()
{
    case `id` in
	uid=0\(root\)*) return 0 ;;
	* )             return 1 ;;
    esac
}


#
# parse_arg(): Parses the command line arguments and sets the 
#              appropriate variables.
#
parse_arg()
{
    while getopts "dvhi:o:" ARG
    do
	case $ARG in
	    d)      DEBUG=1;;
	    v)      VERB="";;
	    i)      INPUT_FILE=$OPTARG;;
	    o)      OUTPUT_FILE=$OPTARG;;
	    \?)	display_msg usage
		    exit 1;;
	    *)	${ECHO} "**ERROR: Supported option missing handler!"
		    display_msg usage
		    exit 1;;
	esac
    done
    return `expr $OPTIND - 1`
}


#
# init(): initializes variables and options
#
init()
{
    # General variables.
    PROG=`basename $0`	# Program name
    PID=$$              # Program ID
    VERB='> /dev/null 2>&1'	# NULL or "> /dev/null"
    ECHO="/bin/echo"	# print message on screen
    EVAL="eval"		# eval or echo
    EGREP="/usr/bin/egrep"
    GREP="/usr/bin/grep"
    DEBUG=0             # Set Debug OFF
    BACKUP=no_ldap	# backup suffix
    HOST=""		# NULL or <hostname>
    NAWK="/usr/bin/nawk"
    RM="/usr/bin/rm"
    WC="/usr/bin/wc"
    CAT="/usr/bin/cat"
    SED="/usr/bin/sed"
    MV="/usr/bin/mv"

    DOM=""              # Set to NULL
    # If DNS domain (resolv.conf) exists use that, otherwise use domainname.
    if [ -f /etc/resolv.conf ]; then
        DOM=`/usr/bin/grep -i -E '^domain|^search' /etc/resolv.conf \
	    | awk '{ print $2 }' | tail -1`
    fi

    # If for any reason the DOM did not get set (error'd resolv.conf) set
    # DOM to the domainname command's output.
    if [ "$DOM" = "" ]; then
        DOM=`domainname`	# domain from domainname command.
    fi

    STEP=1
    INTERACTIVE=1       # 0 = on, 1 = off (For input file mode)
    DEL_OLD_PROFILE=0   # 0 (default), 1 = delete old profile.

    # idsconfig specific variables.
    INPUT_FILE=""
    OUTPUT_FILE=""
    LDAP_ENABLE_SHADOW_UPDATE="FALSE"
    NEED_PROXY=0        # 0 = No Proxy,    1 = Create Proxy.
    NEED_ADMIN=0        # 0 = No Admin,    1 = Create Admin.
    NEED_HOSTACL=0      # 0 = No Host ACL, 1 = Create Host ACL.
    EXISTING_PROFILE=0
    LDAP_PROXYAGENT=""
    LDAP_ADMINDN=""
    LDAP_SUFFIX=""
    LDAP_DOMAIN=$DOM	# domainname on Server (default value)
    GEN_CMD=""
    PROXY_ACI_NAME="LDAP_Naming_Services_proxy_password_read"

    # LDAP COMMANDS
    LDAPSEARCH="/bin/ldapsearch -r"
    LDAPMODIFY=/bin/ldapmodify
    LDAPADD=/bin/ldapadd
    LDAPDELETE=/bin/ldapdelete
    LDAP_GEN_PROFILE=/usr/sbin/ldap_gen_profile

    # iDS specific information
    IDS_SERVER=""
    IDS_PORT=389
    NEED_TIME=0
    NEED_SIZE=0
    NEED_SRVAUTH_PAM=0
    NEED_SRVAUTH_KEY=0
    NEED_SRVAUTH_CMD=0
    IDS_TIMELIMIT=""
    IDS_SIZELIMIT=""

    # LDAP PROFILE related defaults
    LDAP_ROOTDN="cn=Directory Manager"   # Provide common default.
    LDAP_ROOTPWD=""                      # NULL passwd as default (i.e. invalid)
    LDAP_PROFILE_NAME="default"
    LDAP_BASEDN=""
    LDAP_SERVER_LIST=""
    LDAP_AUTHMETHOD=""
    LDAP_FOLLOWREF="FALSE"
    NEED_CRYPT=""
    LDAP_SEARCH_SCOPE="one"
    LDAP_SRV_AUTHMETHOD_PAM=""
    LDAP_SRV_AUTHMETHOD_KEY=""
    LDAP_SRV_AUTHMETHOD_CMD=""
    LDAP_SEARCH_TIME_LIMIT=30
    LDAP_PREF_SRVLIST=""
    LDAP_PROFILE_TTL=43200
    LDAP_CRED_LEVEL="proxy"
    LDAP_BIND_LIMIT=10

    # Prevent new files from being read by group or others.
    umask 077

    # Service Search Descriptors
    LDAP_SERV_SRCH_DES=""

    # Set and create TMPDIR.
    TMPDIR="/tmp/idsconfig.${PID}"
    if mkdir -m 700 ${TMPDIR}
    then
	# Cleanup on exit.
	trap 'rm -rf ${TMPDIR}; /usr/bin/stty echo; exit' 1 2 3 6 15
    else
	echo "ERROR: unable to create a safe temporary directory."
	exit 1
    fi
    LDAP_ROOTPWF=${TMPDIR}/rootPWD

    # Set the SSD file name after setting TMPDIR.
    SSD_FILE=${TMPDIR}/ssd_list

    # GSSAPI setup
    GSSAPI_ENABLE=0
    LDAP_KRB_REALM=""
    SCHEMA_UPDATED=0
    
    export DEBUG VERB ECHO EVAL EGREP GREP STEP TMPDIR
    export IDS_SERVER IDS_PORT LDAP_ROOTDN LDAP_ROOTPWD LDAP_SERVER_LIST 
    export LDAP_BASEDN LDAP_ROOTPWF
    export LDAP_DOMAIN LDAP_SUFFIX LDAP_PROXYAGENT LDAP_PROXYAGENT_CRED
    export NEED_PROXY
    export LDAP_ENABLE_SHADOW_UPDATE LDAP_ADMINDN LDAP_ADMIN_CRED
    export NEED_ADMIN NEED_HOSTACL EXISTING_PROFILE
    export LDAP_PROFILE_NAME LDAP_BASEDN LDAP_SERVER_LIST 
    export LDAP_AUTHMETHOD LDAP_FOLLOWREF LDAP_SEARCH_SCOPE LDAP_SEARCH_TIME_LIMIT
    export LDAP_PREF_SRVLIST LDAP_PROFILE_TTL LDAP_CRED_LEVEL LDAP_BIND_LIMIT
    export NEED_SRVAUTH_PAM NEED_SRVAUTH_KEY NEED_SRVAUTH_CMD
    export LDAP_SRV_AUTHMETHOD_PAM LDAP_SRV_AUTHMETHOD_KEY LDAP_SRV_AUTHMETHOD_CMD
    export LDAP_SERV_SRCH_DES SSD_FILE
    export GEN_CMD GSSAPI_ENABLE LDAP_KRB_REALM SCHEMA_UPDATED
}


#
# disp_full_debug(): List of all debug variables usually interested in.
#                    Grouped to avoid MASSIVE code duplication.
#
disp_full_debug()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "  IDS_SERVER = $IDS_SERVER"
    [ $DEBUG -eq 1 ] && ${ECHO} "  IDS_PORT = $IDS_PORT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_ROOTDN = $LDAP_ROOTDN"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_ROOTPWD = $LDAP_ROOTPWD"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_DOMAIN = $LDAP_DOMAIN"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SUFFIX = $LDAP_SUFFIX"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_BASEDN = $LDAP_BASEDN"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_PROFILE_NAME = $LDAP_PROFILE_NAME"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SERVER_LIST = $LDAP_SERVER_LIST"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_PREF_SRVLIST = $LDAP_PREF_SRVLIST"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SEARCH_SCOPE = $LDAP_SEARCH_SCOPE"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_CRED_LEVEL = $LDAP_CRED_LEVEL"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_AUTHMETHOD = $LDAP_AUTHMETHOD"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_FOLLOWREF = $LDAP_FOLLOWREF"
    [ $DEBUG -eq 1 ] && ${ECHO} "  IDS_TIMELIMIT = $IDS_TIMELIMIT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  IDS_SIZELIMIT = $IDS_SIZELIMIT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_CRYPT = $NEED_CRYPT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_SRVAUTH_PAM = $NEED_SRVAUTH_PAM"
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_SRVAUTH_KEY = $NEED_SRVAUTH_KEY"
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_SRVAUTH_CMD = $NEED_SRVAUTH_CMD"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SRV_AUTHMETHOD_PAM = $LDAP_SRV_AUTHMETHOD_PAM"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SRV_AUTHMETHOD_KEY = $LDAP_SRV_AUTHMETHOD_KEY"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SRV_AUTHMETHOD_CMD = $LDAP_SRV_AUTHMETHOD_CMD"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SEARCH_TIME_LIMIT = $LDAP_SEARCH_TIME_LIMIT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_PROFILE_TTL = $LDAP_PROFILE_TTL"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_BIND_LIMIT = $LDAP_BIND_LIMIT"
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_ENABLE_SHADOW_UPDATE = $LDAP_ENABLE_SHADOW_UPDATE"

    # Only display proxy stuff if needed.
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_PROXY = $NEED_PROXY"
    if [ $NEED_PROXY -eq  1 ]; then
	[ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_PROXYAGENT = $LDAP_PROXYAGENT"
	[ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_PROXYAGENT_CRED = $LDAP_PROXYAGENT_CRED"
    fi

    # Only display admin credential if needed.
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_ADMIN = $NEED_ADMIN"
    [ $DEBUG -eq 1 ] && ${ECHO} "  NEED_HOSTACL = $NEED_HOSTACL"
    if [ $NEED_ADMIN -eq  1 ]; then
	[ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_ADMINDN = $LDAP_ADMINDN"
	[ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_ADMIN_CRED = $LDAP_ADMIN_CRED"
    fi

    # Service Search Descriptors are a special case.
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SERV_SRCH_DES = $LDAP_SERV_SRCH_DES"
}


#
# load_config_file(): Loads the config file.
#
load_config_file()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In load_config_file()"

    # Remove SSD lines from input file before sourcing.
    # The SSD lines must be removed because some forms of the 
    # data could cause SHELL errors.
    ${GREP} -v "LDAP_SERV_SRCH_DES=" ${INPUT_FILE} > ${TMPDIR}/inputfile.noSSD

    # Source the input file. 
    . ${TMPDIR}/inputfile.noSSD

    # If LDAP_SUFFIX is no set, try to utilize LDAP_TREETOP since older 
    # config files use LDAP_TREETOP
    LDAP_SUFFIX="${LDAP_SUFFIX:-$LDAP_TREETOP}"

    # Save password to temporary file.
    save_password

    # Create the SSD file.
    create_ssd_file

    # Display FULL debugging info.
    disp_full_debug
}

#
# save_password(): Save password to temporary file.
#
save_password()
{
    cat > ${LDAP_ROOTPWF} <<EOF
${LDAP_ROOTPWD}
EOF
}

######################################################################
# FUNCTIONS  FOR prompt_config_info() START HERE.
######################################################################

#
# get_ids_server(): Prompt for iDS server name.
#
get_ids_server()
{
    while :
    do
	# Prompt for server name.
	get_ans "Enter the JES Directory Server's  hostname to setup:" "$IDS_SERVER" 
	IDS_SERVER="$ANS"

	# Ping server to see if live.  If valid break out of loop.
	ping $IDS_SERVER > /dev/null 2>&1
	if [ $? -eq 0 ]; then
	    break
	fi

	# Invalid server, enter a new name.
	${ECHO} "ERROR: Server '${IDS_SERVER}' is invalid or unreachable."
	IDS_SERVER=""
    done

    # Set SERVER_ARGS and LDAP_ARGS since values might of changed.
    SERVER_ARGS="-h ${IDS_SERVER} -p ${IDS_PORT}"
    LDAP_ARGS="${SERVER_ARGS} ${AUTH_ARGS}"
    export SERVER_ARGS

}

#
# get_ids_port(): Prompt for iDS port number.
#
get_ids_port()
{
    # Get a valid iDS port number.
    while :
    do
	# Enter port number.
	get_number "Enter the port number for iDS (h=help):" "$IDS_PORT" "port_help"
	IDS_PORT=$ANS
	# Do a simple search to check hostname and port number.
	# If search returns SUCCESS, break out, host and port must
	# be valid.
	${LDAPSEARCH} -h ${IDS_SERVER} -p ${IDS_PORT} -b "" -s base "objectclass=*" > /dev/null 2>&1
	if [ $? -eq 0 ]; then
	    break
	fi
	
	# Invalid host/port pair, Re-enter.
	${ECHO} "ERROR: Invalid host or port: ${IDS_SERVER}:${IDS_PORT}, Please re-enter!"
	get_ids_server
    done

    # Set SERVER_ARGS and LDAP_ARGS since values might of changed.
    SERVER_ARGS="-h ${IDS_SERVER} -p ${IDS_PORT}"
    LDAP_ARGS="${SERVER_ARGS} ${AUTH_ARGS}"
    export SERVER_ARGS
}


#
# chk_ids_version(): Read the slapd config file and set variables
#
chk_ids_version() 
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In chk_ids_version()"

    # check iDS version number.
    eval "${LDAPSEARCH} ${SERVER_ARGS} -b cn=monitor -s base \"objectclass=*\" version | ${GREP} \"^version=\" | cut -f2 -d'/' | cut -f1 -d' ' > ${TMPDIR}/checkDSver 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "ERROR: Can not determine the version number of iDS!"
	exit 1
    fi
    IDS_VER=`cat ${TMPDIR}/checkDSver`
    IDS_MAJVER=`${ECHO} ${IDS_VER} | cut -f1 -d.`
    IDS_MINVER=`${ECHO} ${IDS_VER} | cut -f2 -d.`
    case "${IDS_MAJVER}" in
        5|6|7)  : ;;
        *)   ${ECHO} "ERROR: $PROG only works with JES DS version 5.x, 6.x or 7.x, not ${IDS_VER}."; exit 1;;
    esac

    if [ $DEBUG -eq 1 ]; then
	${ECHO} "  IDS_MAJVER = $IDS_MAJVER"
	${ECHO} "  IDS_MINVER = $IDS_MINVER"
    fi
}


#
# get_dirmgr_dn(): Get the directory manger DN.
#
get_dirmgr_dn()
{
    get_ans "Enter the directory manager DN:" "$LDAP_ROOTDN"
    LDAP_ROOTDN=$ANS

    # Update ENV variables using DN.
    AUTH_ARGS="-D \"${LDAP_ROOTDN}\" -j ${LDAP_ROOTPWF}"
    LDAP_ARGS="${SERVER_ARGS} ${AUTH_ARGS}"
    export AUTH_ARGS LDAP_ARGS
}


#
# get_dirmgr_pw(): Get the Root DN passwd. (Root DN found in slapd.conf)
#
get_dirmgr_pw()
{
    while :
    do
	# Get passwd.
	get_passwd_nochk "Enter passwd for ${LDAP_ROOTDN} :" 
	LDAP_ROOTPWD=$ANS

	# Store password in file.
	save_password

	# Update ENV variables using DN's PW.
	AUTH_ARGS="-D \"${LDAP_ROOTDN}\" -j ${LDAP_ROOTPWF}"
	LDAP_ARGS="${SERVER_ARGS} ${AUTH_ARGS}"
	export AUTH_ARGS LDAP_ARGS

	# Verify that ROOTDN and ROOTPWD are valid.
	eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"\" -s base \"objectclass=*\" > ${TMPDIR}/checkDN 2>&1"
	if [ $? -ne 0 ]; then
	    eval "${GREP} credential ${TMPDIR}/checkDN ${VERB}"
	    if [ $? -eq 0 ]; then
		${ECHO} "ERROR: Root DN passwd is invalid."
	    else
		${ECHO} "ERROR: Invalid Root DN <${LDAP_ROOTDN}>."
		get_dirmgr_dn
	    fi
	else
	    break         # Both are valid.
	fi
    done


}


#
# get_domain(): Get the Domain that will be served by the LDAP server.
#               $1 - Help argument.
#
get_domain()
{
    # Use LDAP_DOMAIN as default.
    get_ans "Enter the domainname to be served (h=help):" $LDAP_DOMAIN

    # Check domainname, and have user re-enter if not valid.
    check_domainname $ANS
    while [ $? -ne 0 ]
    do
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg ${1:-sorry} ;;
	    * ) ${ECHO} "Invalid domainname: \"${ANS}\"."
	     ;;
	esac
	get_ans "Enter domainname to be served (h=help):" $DOM
	
	check_domainname $ANS
    done
    
    # Set the domainname to valid name.
    LDAP_DOMAIN=$ANS
}


#
# get_basedn(): Query for the Base DN.
#
get_basedn()
{
    # Set the $_DOM_2_DC and assign to LDAP_BASEDN as default.
    # Then call get_basedn().  This method remakes the default
    # each time just in case the domain changed.
    domain_2_dc $LDAP_DOMAIN
    LDAP_BASEDN=$_DOM_2_DC

    # Get Base DN.
    while :
    do
	get_ans_req "Enter LDAP Base DN (h=help):" "${_DOM_2_DC}"
	check_baseDN "$ANS"
	while [ $? -ne 0 ]
	do
	    case "$ANS" in
		[Hh] | help | Help | \?) display_msg basedn_help ;;
		* ) ${ECHO} "Invalid base DN: \"${ANS}\"."
		;;
	    esac

	    # Re-Enter the BaseDN
	    get_ans_req "Enter LDAP Base DN (h=help):" "${_DOM_2_DC}"
	    check_baseDN "$ANS"
	done

	# Set base DN and check its suffix
	LDAP_BASEDN=${ANS}
	check_basedn_suffix ||
	{
		cleanup
		exit 1
	}

	# suffix may need to be created, in that case get suffix from user
	[ -n "${NEED_CREATE_SUFFIX}" ] &&
	{
		get_suffix || continue
	}

	# suffix is ok, break out of the base dn inquire loop
	break
    done
}

#
# get_want_shadow_update(): Ask user if want to enable shadow update?
#
get_want_shadow_update()
{
    MSG="Do you want to enable shadow update (y/n/h)?"
    get_confirm "$MSG" "n" "enable_shadow_update_help"
    if [ $? -eq 1 ]; then
	LDAP_ENABLE_SHADOW_UPDATE="TRUE"
    else
	LDAP_ENABLE_SHADOW_UPDATE="FALSE"
    fi
}

get_krb_realm() {

    # To upper cases
    LDAP_KRB_REALM=`${ECHO} ${LDAP_DOMAIN} | ${NAWK} '{ print toupper($0) }'`
    get_ans_req "Enter Kerberos Realm:" "$LDAP_KRB_REALM"
    # To upper cases
    LDAP_KRB_REALM=`${ECHO} ${ANS} | ${NAWK} '{ print toupper($0) }'`
}

# $1: DN
# $2: ldif file
add_entry_by_DN() {

    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"${1}\" -s base \"objectclass=*\" ${VERB}"
    if [ $? -eq 0 ]; then
	    ${ECHO} "  ${1} already exists"
	    return 0
    else
	${EVAL} "${LDAPADD} ${LDAP_ARGS} -f ${2} ${VERB}"
	if [ $? -eq 0 ]; then
		${ECHO} "  ${1} is added"
	    	return 0
	else
		${ECHO} "  ERROR: failed to add ${1}"
		return 1
	fi
    fi

}
#
# Kerberos princiapl to DN mapping rules
#
# Add rules for host credentails and user credentials
#
add_id_mapping_rules() {

    ${ECHO} "  Adding Kerberos principal to DN mapping rules..."

    _C_DN="cn=GSSAPI,cn=identity mapping,cn=config"
    ( cat << EOF
dn: cn=GSSAPI,cn=identity mapping,cn=config
objectClass: top
objectClass: nsContainer
cn: GSSAPI
EOF
) > ${TMPDIR}/GSSAPI_container.ldif

    add_entry_by_DN "${_C_DN}" "${TMPDIR}/GSSAPI_container.ldif"
    if [ $? -ne 0 ];
    then
    	${RM} ${TMPDIR}/GSSAPI_container.ldif
	return
    fi

    _H_CN="host_auth_${LDAP_KRB_REALM}"
    _H_DN="cn=${_H_CN}, ${_C_DN}"
    ( cat << EOF
dn: ${_H_DN}
objectClass: top
objectClass: nsContainer
objectClass: dsIdentityMapping
objectClass: dsPatternMatching
cn: ${_H_CN}
dsMatching-pattern: \${Principal}
dsMatching-regexp: host\/(.*).${LDAP_DOMAIN}@${LDAP_KRB_REALM}
dsSearchBaseDN: ou=hosts,${LDAP_BASEDN}
dsSearchFilter: (&(objectClass=ipHost)(cn=\$1))
dsSearchScope: one

EOF
) > ${TMPDIR}/${_H_CN}.ldif

    add_entry_by_DN "${_H_DN}" "${TMPDIR}/${_H_CN}.ldif"

    _U_CN="user_auth_${LDAP_KRB_REALM}"
    _U_DN="cn=${_U_CN}, ${_C_DN}"
    ( cat << EOF
dn: ${_U_DN}
objectClass: top
objectClass: nsContainer
objectClass: dsIdentityMapping
objectClass: dsPatternMatching
cn: ${_U_CN}
dsMatching-pattern: \${Principal}
dsMatching-regexp: (.*)@${LDAP_KRB_REALM}
dsMappedDN: uid=\$1,ou=People,${LDAP_BASEDN}

EOF
) > ${TMPDIR}/${_U_CN}.ldif

    add_entry_by_DN "${_U_DN}" "${TMPDIR}/${_U_CN}.ldif"

}


#
# Modify ACL to allow root to read all the password and only self can read
# its own password when sasl/GSSAPI bind is used
#
modify_userpassword_acl_for_gssapi() {

    _P_DN="ou=People,${LDAP_BASEDN}"
    _H_DN="ou=Hosts,${LDAP_BASEDN}"
    _P_ACI="self-read-pwd"

    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"${_P_DN}\" -s base \"objectclass=*\" > /dev/null 2>&1" 
    if [ $? -ne 0 ]; then
	    ${ECHO} "  ${_P_DN} does not exist"
	# Not Found. Create a new entry
	( cat << EOF
dn: ${_P_DN}
ou: People
objectClass: top
objectClass: organizationalUnit
EOF
) > ${TMPDIR}/gssapi_people.ldif

	add_entry_by_DN "${_P_DN}" "${TMPDIR}/gssapi_people.ldif"
    else 
	${ECHO} "  ${_P_DN} already exists"
    fi

    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"${_P_DN}\" -s base \"objectclass=*\" aci > ${TMPDIR}/chk_gssapi_aci 2>&1"

    if [ $? -eq 0 ]; then
	    ${EVAL} "${GREP} ${_P_ACI} ${TMPDIR}/chk_gssapi_aci > /dev/null 2>&1"
	    if [ $? -eq 0 ]; then
		${ECHO} "  userpassword ACL ${_P_ACI} already exists."
		return
	    else
		${ECHO} "  userpassword ACL ${_P_ACI} not found. Create a new one."
	    fi
    else
	${ECHO} "  Error searching aci for ${_P_DN}"
	cat ${TMPDIR}/chk_gssapi_aci
	cleanup
	exit 1
    fi
    ( cat << EOF
dn: ${_P_DN}
changetype: modify
add: aci
aci: (targetattr="userPassword")(version 3.0; acl self-read-pwd; allow (read,search) userdn="ldap:///self" and authmethod="sasl GSSAPI";)
-
add: aci
aci: (targetattr="userPassword")(version 3.0; acl host-read-pwd; allow (read,search) userdn="ldap:///cn=*+ipHostNumber=*,ou=Hosts,${LDAP_BASEDN}" and authmethod="sasl GSSAPI";)
EOF
) > ${TMPDIR}/user_gssapi.ldif
    LDAP_TYPE_OR_VALUE_EXISTS=20
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/user_gssapi.ldif ${VERB}"

    case $? in
    0)
	${ECHO} "  ${_P_DN} uaserpassword ACL is updated."
	;;
    20)
	${ECHO} "  ${_P_DN} uaserpassword ACL already exists."
	;;
    *)
	${ECHO} "  ERROR: update of userpassword ACL for ${_P_DN} failed!"
	cleanup
	exit 1
	;;
    esac
}
#
# $1: objectclass or attributetyp
# $2: name
search_update_schema() {

    ATTR="${1}es"

    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b cn=schema -s base \"objectclass=*\" ${ATTR} | ${GREP} -i \"${2}\" ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "${1} ${2} does not exist."
        update_schema_attr
        update_schema_obj
	SCHEMA_UPDATED=1
    else
	${ECHO} "${1} ${2} already exists. Schema has been updated"
    fi
}

#
# Set up GSSAPI if necessary
#
gssapi_setup() {

	GSSAPI_ENABLE=0

	# assume sasl/GSSAPI is supported by the ldap server and may be used
	GSSAPI_AUTH_MAY_BE_USED=1

	${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"\" -s base \"objectclass=*\" supportedSASLMechanisms | ${GREP} GSSAPI ${VERB}"
	if [ $? -ne 0 ]; then
		GSSAPI_AUTH_MAY_BE_USED=0
		${ECHO} "  sasl/GSSAPI is not supported by this LDAP server"
		return
	fi

	get_confirm "GSSAPI is supported. Do you want to set up gssapi:(y/n)" "n"
	if [ $? -eq 0 ]; then
		GSSAPI_ENABLE=0
		${ECHO}
		${ECHO} "GSSAPI is not set up."
		${ECHO} "sasl/GSSAPI bind may not work if it's not set up first."
	else
		GSSAPI_ENABLE=1
		get_krb_realm
	fi

}
#
# get_profile_name(): Enter the profile name.
#
get_profile_name()
{
    # Reset Delete Old Profile since getting new profile name.
    DEL_OLD_PROFILE=0

    # Loop until valid profile name, or replace.
    while :
    do
	# Prompt for profile name.
	get_ans "Enter the profile name (h=help):" "$LDAP_PROFILE_NAME"

	# Check for Help.
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg profile_help
				     continue ;; 
	    * )  ;;
	esac

	# Search to see if profile name already exists.
	eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=${ANS},ou=profile,${LDAP_BASEDN}\" -s base \"objectclass=*\" ${VERB}"
	if [ $? -eq 0 ]; then

	    cat << EOF

Profile '${ANS}' already exists, it is possible to enable
shadow update now. idsconfig will exit after shadow update
is enabled. You can also continue to overwrite the profile 
or create a new one and be given the chance to enable
shadow update later.

EOF

	    MSG="Just enable shadow update (y/n/h)?"
	    get_confirm "$MSG" "n" "enable_shadow_update_help"
	    if [ $? -eq 1 ]; then
	        [ $DEBUG -eq 1 ] && ${ECHO} "set up shadow update"
	        LDAP_ENABLE_SHADOW_UPDATE=TRUE
		# display alternate messages
		EXISTING_PROFILE=1
	        # Set Profile Name.
	        LDAP_PROFILE_NAME=$ANS
	        return 0  # set up credentials for shadow update.
	    fi

	    get_confirm_nodef "Are you sure you want to overwrite profile cn=${ANS}?"
	    if [ $? -eq 1 ]; then
		DEL_OLD_PROFILE=1
		return 0  # Replace old profile name.
	    else
		${ECHO} "Please re-enter a new profile name."
	    fi
	else
	    break  # Unique profile name.
	fi
    done

    # Set Profile Name.
    LDAP_PROFILE_NAME=$ANS
}


#
# get_srv_list(): Get the default server list.
#
get_srv_list()
{
    # If LDAP_SERVER_LIST is NULL, then set, otherwise leave alone.
    if [ -z "${LDAP_SERVER_LIST}" ]; then
	LDAP_SERVER_LIST=`getent hosts ${IDS_SERVER} | awk '{print $1}'`
        if [ ${IDS_PORT} -ne 389 ]; then
	    LDAP_SERVER_LIST="${LDAP_SERVER_LIST}:${IDS_PORT}"
	fi
    fi

    # Prompt for new LDAP_SERVER_LIST.
    while :
    do
	get_ans "Default server list (h=help):" $LDAP_SERVER_LIST

	# If help continue, otherwise break.
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg def_srvlist_help ;;
	    * ) break ;;
	esac
    done
    LDAP_SERVER_LIST=$ANS
}


#
# get_pref_srv(): The preferred server list (Overrides the server list)
#
get_pref_srv()
{
    while :
    do
	get_ans "Preferred server list (h=help):" $LDAP_PREF_SRVLIST

	# If help continue, otherwise break.
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg pref_srvlist_help ;;
	    * ) break ;;
	esac
    done
    LDAP_PREF_SRVLIST=$ANS
}


#
# get_search_scope(): Get the search scope from the user.
#
get_search_scope()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_search_scope()"

    _MENU_CHOICE=0
    while :
    do
	get_ans "Choose desired search scope (one, sub, h=help): " "one"
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    one) LDAP_SEARCH_SCOPE="one"
	       return 1 ;;
	    sub) LDAP_SEARCH_SCOPE="sub"
	       return 2 ;;
	    h) display_msg srch_scope_help ;;
	    *) ${ECHO} "Please enter \"one\", \"sub\", or \"h\"." ;;
	esac
    done

}


#
# get_cred_level(): Function to display menu to user and get the 
#                  credential level.
#
get_cred_level()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_cred_level()"

    _MENU_CHOICE=0
    display_msg cred_level_menu
    while :
    do
	if [ $GSSAPI_ENABLE -eq 1 ]; then
	    ${ECHO} '"self" is needed for GSSAPI profile'
	fi
	get_ans "Choose Credential level [h=help]:" "1"
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) LDAP_CRED_LEVEL="anonymous"
	       return 1 ;;
	    2) LDAP_CRED_LEVEL="proxy"
	       return 2 ;;
	    3) LDAP_CRED_LEVEL="proxy anonymous"
	       return 3 ;;
	    4) LDAP_CRED_LEVEL="self"
	       return 4 ;;
	    h) display_msg cred_lvl_help ;;
	    *) ${ECHO} "Please enter 1, 2, 3 or 4." ;;
	esac
    done
}


#
# srvauth_menu_handler(): Enter the Service Authentication method.
#
srvauth_menu_handler()
{
    # Display Auth menu
    display_msg srvauth_method_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer.
	if [ $_FIRST -eq 1 ]; then
	    get_ans "Choose Service Authentication Method:" "1"
	else
	    get_ans "Choose Service Authentication Method (0=reset):"
	fi

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _AUTHMETHOD="simple"
		break ;;
	    2) _AUTHMETHOD="sasl/DIGEST-MD5"
		break ;;
	    3) _AUTHMETHOD="tls:simple"
		break ;;
	    4) _AUTHMETHOD="tls:sasl/DIGEST-MD5"
		break ;;
	    5) _AUTHMETHOD="sasl/GSSAPI"
		break ;;
	    0) _AUTHMETHOD=""
		_FIRST=1
		break ;;
	    *) ${ECHO} "Please enter 1-5 or 0 to reset." ;;
	esac
    done
}


#
# auth_menu_handler(): Enter the Authentication method.
#
auth_menu_handler()
{
    # Display Auth menu
    display_msg auth_method_menu	

    # Get a Valid choice.
    while :
    do
	if [ $GSSAPI_ENABLE -eq 1 ]; then
	    ${ECHO} '"sasl/GSSAPI" is needed for GSSAPI profile'
	fi
	# Display appropriate prompt and get answer.
	if [ $_FIRST -eq 1 ]; then
	    get_ans "Choose Authentication Method (h=help):" "1"
	else
	    get_ans "Choose Authentication Method (0=reset, h=help):"
	fi

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _AUTHMETHOD="none"
		break ;;
	    2) _AUTHMETHOD="simple"
		break ;;
	    3) _AUTHMETHOD="sasl/DIGEST-MD5"
		break ;;
	    4) _AUTHMETHOD="tls:simple"
		break ;;
	    5) _AUTHMETHOD="tls:sasl/DIGEST-MD5"
		break ;;
	    6) _AUTHMETHOD="sasl/GSSAPI"
		break ;;
	    0) _AUTHMETHOD=""
		_FIRST=1
		break ;;
	    h) display_msg auth_help ;;
	    *) ${ECHO} "Please enter 1-6, 0=reset, or h=help." ;;
	esac
    done
}


#
# get_auth(): Enter the Authentication method.
#
get_auth()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_auth()"

    _FIRST=1          # Flag for first time.
    _MENU_CHOICE=0
    _AUTHMETHOD=""    # Tmp method.

    while :
    do
	# Call Menu handler
	auth_menu_handler

	# Add Auth Method to list.
        if [ $_FIRST -eq 1 ]; then 
	    LDAP_AUTHMETHOD="${_AUTHMETHOD}"
	    _FIRST=0
	else
	    LDAP_AUTHMETHOD="${LDAP_AUTHMETHOD};${_AUTHMETHOD}"
	fi

	# Display current Authentication Method.
	${ECHO} ""
	${ECHO} "Current authenticationMethod: ${LDAP_AUTHMETHOD}"
	${ECHO} ""

	# Prompt for another Auth Method, or break out.
	get_confirm_nodef "Do you want to add another Authentication Method?"
	if [ $? -eq 0 ]; then
	    break;
	fi
    done
}


#
# get_followref(): Whether or not to follow referrals.
#
get_followref()
{
    get_confirm "Do you want the clients to follow referrals (y/n/h)?" "n" "referrals_help"
    if [ $? -eq 1 ]; then
	LDAP_FOLLOWREF="TRUE"
    else
	LDAP_FOLLOWREF="FALSE"
    fi
}


#
# get_timelimit(): Set the time limit. -1 is max time.
#
get_timelimit()
{
    # Get current timeout value from cn=config.
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=config\" -s base \"objectclass=*\" nsslapd-timelimit > ${TMPDIR}/chk_timeout 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Could not reach LDAP server to check current timeout!"
	cleanup
	exit 1
    fi
    CURR_TIMELIMIT=`${GREP} timelimit ${TMPDIR}/chk_timeout | cut -f2 -d=`
    
    get_negone_num "Enter the time limit for iDS (current=${CURR_TIMELIMIT}):" "-1"
    IDS_TIMELIMIT=$NUM
}


#
# get_sizelimit(): Set the size limit. -1 is max size.
#
get_sizelimit()
{
    # Get current sizelimit value from cn=config.
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=config\" -s base \"objectclass=*\" nsslapd-sizelimit > ${TMPDIR}/chk_sizelimit 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Could not reach LDAP server to check current sizelimit!"
	cleanup
	exit 1
    fi
    CURR_SIZELIMIT=`${GREP} sizelimit ${TMPDIR}/chk_sizelimit | cut -f2 -d=`

    get_negone_num "Enter the size limit for iDS (current=${CURR_SIZELIMIT}):" "-1"
    IDS_SIZELIMIT=$NUM
}


#
# get_want_crypt(): Ask user if want to store passwords in crypt?
#
get_want_crypt()
{
    get_confirm "Do you want to store passwords in \"crypt\" format (y/n/h)?" "n" "crypt_help"
    if [ $? -eq 1 ]; then
	NEED_CRYPT="TRUE"
    else
	NEED_CRYPT="FALSE"
    fi
}


#
# get_srv_authMethod_pam(): Get the Service Auth Method for pam_ldap from user.
#
#  NOTE: This function is base on get_auth().
#
get_srv_authMethod_pam()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_srv_authMethod_pam()"

    _FIRST=1          # Flag for first time.
    _MENU_CHOICE=0
    _AUTHMETHOD=""    # Tmp method.

    while :
    do
	# Call Menu handler
	srvauth_menu_handler

	# Add Auth Method to list.
        if [ $_FIRST -eq 1 ]; then 
	    if [ "$_AUTHMETHOD" = "" ]; then
		LDAP_SRV_AUTHMETHOD_PAM=""
	    else
		LDAP_SRV_AUTHMETHOD_PAM="pam_ldap:${_AUTHMETHOD}"
	    fi
	    _FIRST=0
	else
	    LDAP_SRV_AUTHMETHOD_PAM="${LDAP_SRV_AUTHMETHOD_PAM};${_AUTHMETHOD}"
	fi

	# Display current Authentication Method.
	${ECHO} ""
	${ECHO} "Current authenticationMethod: ${LDAP_SRV_AUTHMETHOD_PAM}"
	${ECHO} ""

	# Prompt for another Auth Method, or break out.
	get_confirm_nodef "Do you want to add another Authentication Method?"
	if [ $? -eq 0 ]; then
	    break;
	fi
    done

    # Check in case user reset string and exited loop.
    if [ "$LDAP_SRV_AUTHMETHOD_PAM" = "" ]; then
	NEED_SRVAUTH_PAM=0
    fi
}


#
# get_srv_authMethod_key(): Get the Service Auth Method for keyserv from user.
#
#  NOTE: This function is base on get_auth().
#
get_srv_authMethod_key()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_srv_authMethod_key()"

    _FIRST=1          # Flag for first time.
    _MENU_CHOICE=0
    _AUTHMETHOD=""    # Tmp method.

    while :
    do
	# Call Menu handler
	srvauth_menu_handler

	# Add Auth Method to list.
        if [ $_FIRST -eq 1 ]; then 
	    if [ "$_AUTHMETHOD" = "" ]; then
		LDAP_SRV_AUTHMETHOD_KEY=""
	    else
		LDAP_SRV_AUTHMETHOD_KEY="keyserv:${_AUTHMETHOD}"
	    fi
	    _FIRST=0
	else
	    LDAP_SRV_AUTHMETHOD_KEY="${LDAP_SRV_AUTHMETHOD_KEY};${_AUTHMETHOD}"
	fi

	# Display current Authentication Method.
	${ECHO} ""
	${ECHO} "Current authenticationMethod: ${LDAP_SRV_AUTHMETHOD_KEY}"
	${ECHO} ""

	# Prompt for another Auth Method, or break out.
	get_confirm_nodef "Do you want to add another Authentication Method?"
	if [ $? -eq 0 ]; then
	    break;
	fi
    done

    # Check in case user reset string and exited loop.
    if [ "$LDAP_SRV_AUTHMETHOD_KEY" = "" ]; then
	NEED_SRVAUTH_KEY=0
    fi
}


#
# get_srv_authMethod_cmd(): Get the Service Auth Method for passwd-cmd from user.
#
#  NOTE: This function is base on get_auth().
#
get_srv_authMethod_cmd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_srv_authMethod_cmd()"

    _FIRST=1          # Flag for first time.
    _MENU_CHOICE=0
    _AUTHMETHOD=""    # Tmp method.

    while :
    do
	# Call Menu handler
	srvauth_menu_handler

	# Add Auth Method to list.
        if [ $_FIRST -eq 1 ]; then 
	    if [ "$_AUTHMETHOD" = "" ]; then
		LDAP_SRV_AUTHMETHOD_CMD=""
	    else
		LDAP_SRV_AUTHMETHOD_CMD="passwd-cmd:${_AUTHMETHOD}"
	    fi
	    _FIRST=0
	else
	    LDAP_SRV_AUTHMETHOD_CMD="${LDAP_SRV_AUTHMETHOD_CMD};${_AUTHMETHOD}"
	fi

	# Display current Authentication Method.
	${ECHO} ""
	${ECHO} "Current authenticationMethod: ${LDAP_SRV_AUTHMETHOD_CMD}"
	${ECHO} ""

	# Prompt for another Auth Method, or break out.
	get_confirm_nodef "Do you want to add another Authentication Method?"
	if [ $? -eq 0 ]; then
	    break;
	fi
    done

    # Check in case user reset string and exited loop.
    if [ "$LDAP_SRV_AUTHMETHOD_CMD" = "" ]; then
	NEED_SRVAUTH_CMD=0
    fi
}


#
# get_srch_time(): Amount of time to search.
#
get_srch_time()
{
    get_negone_num "Client search time limit in seconds (h=help):" "$LDAP_SEARCH_TIME_LIMIT" "srchtime_help"
    LDAP_SEARCH_TIME_LIMIT=$NUM
}


#
# get_prof_ttl(): The profile time to live (TTL)
#
get_prof_ttl()
{
    get_negone_num "Profile Time To Live in seconds (h=help):" "$LDAP_PROFILE_TTL" "profttl_help"
    LDAP_PROFILE_TTL=$NUM
}


#
# get_bind_limit(): Bind time limit
#
get_bind_limit()
{
    get_negone_num "Bind time limit in seconds (h=help):" "$LDAP_BIND_LIMIT" "bindlim_help"
    LDAP_BIND_LIMIT=$NUM
}


######################################################################
# FUNCTIONS  FOR Service Search Descriptor's START HERE.
######################################################################


#
# add_ssd(): Get SSD's from user and add to file.
#
add_ssd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_ssd()"

    # Enter the service id.  Loop til unique.
    while :
    do
	get_ans "Enter the service id:"
	_SERV_ID=$ANS

	# Grep for name existing.
	${GREP} -i "^$ANS:" ${SSD_FILE} > /dev/null 2>&1
	if [ $? -eq 1 ]; then
	    break
	fi

	# Name exists, print message, let user decide.
	${ECHO} "ERROR: Service id ${ANS} already exists."
    done
    
    get_ans "Enter the base:"
    _BASE=$ANS

    # Get the scope and verify that its one or sub.
    while :
    do
	get_ans "Enter the scope:"
	_SCOPE=$ANS
	case `${ECHO} ${_SCOPE} | tr '[A-Z]' '[a-z]'` in
	    one) break ;;
	    sub) break ;;
	    *)   ${ECHO} "${_SCOPE} is Not valid - Enter 'one' or 'sub'" ;;
	esac
    done

    # Build SSD to add to file.
    _SSD="${_SERV_ID}:${_BASE}?${_SCOPE}"
    
    # Add the SSD to the file.
    ${ECHO} "${_SSD}" >> ${SSD_FILE}
}


#
# delete_ssd(): Delete a SSD from the list.
#
delete_ssd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In delete_ssd()"

    # Get service id name from user for SSD to delete.
    get_ans_req "Enter service id to delete:"

    # Make sure service id exists.
    ${GREP} "$ANS" ${SSD_FILE} > /dev/null 2>&1
    if [ $? -eq 1 ]; then
	${ECHO} "Invalid service id: $ANS not present in list."
	return
    fi

    # Create temporary back SSD file.
    cp ${SSD_FILE} ${SSD_FILE}.bak
    if [ $? -eq 1 ]; then
	${ECHO} "ERROR: could not create file: ${SSD_FILE}.bak"
	exit 1
    fi

    # Use ${GREP} to remove the SSD.  Read from temp file
    # and write to the orig file.
    ${GREP} -v "$ANS" ${SSD_FILE}.bak > ${SSD_FILE} 
}


#
# modify_ssd(): Allow user to modify a SSD.
#
modify_ssd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_ssd()"

    # Prompt user for service id.
    get_ans_req "Enter service id to modify:"
    
    # Put into temp _LINE.
    _LINE=`${GREP} "^$ANS:" ${SSD_FILE}`
    if [ "$_LINE" = "" ]; then
	${ECHO} "Invalid service id: $ANS"
	return
    fi

    # Display current filter for user to see.
    ${ECHO} ""
    ${ECHO} "Current SSD: $_LINE"
    ${ECHO} ""
    
    # Get the defaults.
    _CURR_BASE=`${ECHO} $_LINE | cut -d: -f2 | cut -d'?' -f 1`
    _CURR_SCOPE=`${ECHO} $_LINE | cut -d: -f2 | cut -d'?' -f 2`

    # Create temporary back SSD file.
    cp ${SSD_FILE} ${SSD_FILE}.bak
    if [ $? -eq 1 ]; then
	${ECHO} "ERROR: could not create file: ${SSD_FILE}.bak"
	cleanup
	exit 1
    fi

    # Removed the old line.
    ${GREP} -v "^$ANS:" ${SSD_FILE}.bak > ${SSD_FILE} 2>&1
 
    # New Entry
    _SERV_ID=$ANS
    get_ans_req "Enter the base:" "$_CURR_BASE"
    _BASE=$ANS
    get_ans_req "Enter the scope:" "$_CURR_SCOPE"
    _SCOPE=$ANS

    # Build the new SSD.
    _SSD="${_SERV_ID}:${_BASE}?${_SCOPE}"

    # Add the SSD to the file.
    ${ECHO} "${_SSD}" >> ${SSD_FILE}
}


#
# display_ssd(): Display the current SSD list.
#
display_ssd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In display_ssd()"

    ${ECHO} ""
    ${ECHO} "Current Service Search Descriptors:"
    ${ECHO} "=================================="
    cat ${SSD_FILE}
    ${ECHO} ""
    ${ECHO} "Hit return to continue."
    read __A
}


#
# prompt_ssd(): Get SSD's from user.
#
prompt_ssd()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In prompt_ssd()"    
    # See if user wants SSD's?
    get_confirm "Do you wish to setup Service Search Descriptors (y/n/h)?" "n" "ssd_help"
    [ "$?" -eq 0 ] && return

    # Display menu for SSD choices.
    while :
    do
	display_msg prompt_ssd_menu
	get_ans "Enter menu choice:" "Quit"
	case "$ANS" in
	    [Aa] | add) add_ssd ;;
	    [Dd] | delete) delete_ssd ;;
	    [Mm] | modify) modify_ssd ;;
	    [Pp] | print | display) display_ssd ;;
	    [Xx] | reset | clear) reset_ssd_file ;;
	    [Hh] | Help | help)	display_msg ssd_menu_help 
				${ECHO} " Press return to continue."
				read __A ;;
	    [Qq] | Quit | quit)	return ;;
	    *)    ${ECHO} "Invalid choice: $ANS please re-enter from menu." ;;
	esac
    done
}


#
# reset_ssd_file(): Blank out current SSD file.
#
reset_ssd_file()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In reset_ssd_file()"
    
    rm -f ${SSD_FILE}
    touch ${SSD_FILE}
}


#
# create_ssd_file(): Create a temporary file for SSD's.
#
create_ssd_file()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In create_ssd_file()"

    # Build a list of SSD's and store in temp file.
    ${GREP} "LDAP_SERV_SRCH_DES=" ${INPUT_FILE} | \
	sed 's/LDAP_SERV_SRCH_DES=//' \
	> ${SSD_FILE}
}


#
# ssd_2_config(): Append the SSD file to the output file.
#
ssd_2_config()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In ssd_2_config()"
    
    # Convert to config file format using sed.
    sed -e "s/^/LDAP_SERV_SRCH_DES=/" ${SSD_FILE} >> ${OUTPUT_FILE}
}


#
# ssd_2_profile(): Add SSD's to the GEN_CMD string.
#
ssd_2_profile()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In ssd_2_profile()"

    GEN_TMPFILE=${TMPDIR}/ssd_tmpfile
    touch ${GEN_TMPFILE}

    # Add and convert each SSD to string.
    while read SSD_LINE
    do
	${ECHO} " -a \"serviceSearchDescriptor=${SSD_LINE}\"\c" >> ${GEN_TMPFILE}
    done <${SSD_FILE}

    # Add SSD's to GEN_CMD.
    GEN_CMD="${GEN_CMD} `cat ${GEN_TMPFILE}`"
}

#
# get_adminDN(): Get the admin DN.
#
get_adminDN()
{
    LDAP_ADMINDN="cn=admin,ou=profile,${LDAP_BASEDN}"  # default
    get_ans "Enter DN for the administrator:" "$LDAP_ADMINDN"
    LDAP_ADMINDN=$ANS
    [ $DEBUG -eq 1 ] && ${ECHO} "LDAP_ADMINDN = $LDAP_ADMINDN"
}

#
# get_admin_pw(): Get the admin passwd.
#
get_admin_pw()
{
    get_passwd "Enter passwd for the administrator:"
    LDAP_ADMIN_CRED=$ANS
    [ $DEBUG -eq 1 ] && ${ECHO} "LDAP_ADMIN_CRED = $LDAP_ADMIN_CRED"
}

#
# add_admin(): Add an admin entry for nameservice for updating shadow data.
#
add_admin()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_admin()"

    # Check if the admin user already exists.
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_ADMINDN}\" -s base \"objectclass=*\" ${VERB}"
    if [ $? -eq 0 ]; then
	MSG="Administrator ${LDAP_ADMINDN} already exists."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  NOT ADDED: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`	
	fi
	return 0
    fi

    # Get cn and sn names from LDAP_ADMINDN.
    cn_tmp=`${ECHO} ${LDAP_ADMINDN} | cut -f1 -d, | cut -f2 -d=`

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_ADMINDN}
cn: ${cn_tmp}
sn: ${cn_tmp}
objectclass: top
objectclass: person
userpassword: ${LDAP_ADMIN_CRED}
EOF
) > ${TMPDIR}/admin
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/admin ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Adding administrator identity failed!"
	cleanup
	exit 1
    fi

    ${RM} -f ${TMPDIR}/admin

    # Display message that the administrator identity is added.
    MSG="Administrator identity ${LDAP_ADMINDN}"
    if [ $EXISTING_PROFILE -eq 1 ]; then
	${ECHO} "  ADDED: $MSG."
    else
	${ECHO} "  ${STEP}. $MSG added."
	STEP=`expr $STEP + 1`
    fi
}

#
# allow_admin_read_write_shadow(): Give Admin read/write permission
# to shadow data.
#
allow_admin_read_write_shadow()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In allow_admin_read_write_shadow()"

    # Set ACI Name
    ADMIN_ACI_NAME="LDAP_Naming_Services_admin_shadow_write"

    # Search for ACI_NAME
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" \
    -s base objectclass=* aci > ${TMPDIR}/chk_adminwrite_aci 2>&1"

    # if an ACI with ${ADMIN_ACI_NAME} and "write,compare,read,search"
    # and ${LDAP_ADMINDN} already exists, we are done
    ${EGREP} ".*${ADMIN_ACI_NAME}.*write,compare,read,search.*${LDAP_ADMINDN}.*" \
    	${TMPDIR}/chk_adminwrite_aci 2>&1 > /dev/null
    if [ $? -eq 0 ]; then
	MSG="Admin ACI ${ADMIN_ACI_NAME} already exists for ${LDAP_BASEDN}."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  NOT SET: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`	
	fi
	return 0
    fi

    # If an ACI with ${ADMIN_ACI_NAME} and "(write)" and ${LDAP_ADMINDN}
    # already exists, delete it first.
    find_and_delete_ACI ".*${ADMIN_ACI_NAME}.*(write).*${LDAP_ADMINDN}.*" \
	${TMPDIR}/chk_adminwrite_aci ${ADMIN_ACI_NAME}

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (target="ldap:///${LDAP_BASEDN}")(targetattr="shadowLastChange
 ||shadowMin||shadowMax||shadowWarning||shadowInactive||shadowExpire
 ||shadowFlag||userPassword||loginShell||homeDirectory||gecos")
  (version 3.0; acl ${ADMIN_ACI_NAME}; allow (write,compare,read,search)
  userdn = "ldap:///${LDAP_ADMINDN}";)
EOF
) > ${TMPDIR}/admin_write
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/admin_write ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Allow ${LDAP_ADMINDN} read/write access to shadow data failed!"
	cleanup
	exit 1
    fi

    ${RM} -f ${TMPDIR}/admin_write
    # Display message that the administrator ACL is set.
    MSG="Give ${LDAP_ADMINDN} read/write access to shadow data."
    if [ $EXISTING_PROFILE -eq 1 ]; then
	${ECHO} "  ACI SET: $MSG"
    else
	${ECHO} "  ${STEP}. $MSG"
	STEP=`expr $STEP + 1`
    fi
}

#
# allow_host_read_write_shadow(): Give host principal read/write permission
# for shadow data.
#
allow_host_read_write_shadow()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In allow_host_read_write_shadow()"

    # Set ACI Name
    HOST_ACI_NAME="LDAP_Naming_Services_host_shadow_write"

    # Search for ACI_NAME
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_hostwrite_aci 2>&1"
    ${GREP} "${HOST_ACI_NAME}" ${TMPDIR}/chk_hostwrite_aci > /dev/null 2>&1
    if [ $? -eq 0 ]; then
	MSG="Host ACI ${HOST_ACI_NAME} already exists for ${LDAP_BASEDN}."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  NOT ADDED: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`
	fi
	return 0
    fi

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (target="ldap:///${LDAP_BASEDN}")(targetattr="shadowLastChange||shadowMin||shadowMax||shadowWarning||shadowInactive||shadowExpire||shadowFlag||userPassword||loginShell||homeDirectory||gecos")(version 3.0; acl ${HOST_ACI_NAME}; allow (write,compare,read,search) authmethod="sasl GSSAPI" and userdn = "ldap:///cn=*+ipHostNumber=*,ou=Hosts,${LDAP_BASEDN}";)
EOF
) > ${TMPDIR}/host_read_write
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/host_read_write ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Allow Host Principal to write shadow data failed!"
	cleanup
	exit 1
    fi

    ${RM} -f ${TMPDIR}/host_read_write
    MSG="Give host principal read/write permission for shadow."
    if [ $EXISTING_PROFILE -eq 1 ]; then
	${ECHO} "  ACI SET: $MSG"
    else
	${ECHO} "  ${STEP}. $MSG"
	STEP=`expr $STEP + 1`
    fi
}

#
# Set up shadow update
#
setup_shadow_update() {
    [ $DEBUG -eq 1 ] && ${ECHO} "In setup_shadow_update()"

    # get content of the profile
    PROFILE_OUT=${TMPDIR}/prof_tmpfile
    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=${LDAP_PROFILE_NAME},ou=profile,${LDAP_BASEDN}\" -s base \"objectclass=*\" > $PROFILE_OUT 2>&1"
    ${GREP} -i cn $PROFILE_OUT >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ $DEBUG -eq 1 ] && ${ECHO} "Profile ${LDAP_PROFILE_NAME} does not exist"
	${RM} ${PROFILE_OUT}
	return
    fi

    # Search to see if authenticationMethod has 'GSSAPI' and
    # credentialLevel has 'self'. If so, ask to use the
    # host principal for shadow update
    if [ $GSSAPI_AUTH_MAY_BE_USED -eq 1 ]; then
	if ${GREP} authenticationMethod $PROFILE_OUT | ${GREP} GSSAPI >/dev/null 2>&1
	then
	    if ${GREP} credentialLevel $PROFILE_OUT | ${GREP} self >/dev/null 2>&1
	    then
		NEED_HOSTACL=1
	    fi
	fi
	${RM} ${PROFILE_OUT}
	[ $DEBUG -eq 1 ] && ${ECHO} "NEED_HOSTACL = $NEED_HOSTACL"

	if [ $NEED_HOSTACL -eq 1 ]; then
	    MSG="Use host principal for shadow data update (y/n/h)?"
	    get_confirm "$MSG" "y" "use_host_principal_help"
	    if [ $? -eq 1 ]; then
		delete_proxy_read_pw
		allow_host_read_write_shadow
		deny_non_host_shadow_access
	        ${ECHO} ""
		${ECHO} "  Shadow update has been enabled."
	    else
	        ${ECHO} ""
    		${ECHO} "  Shadow update may not work."
	    fi
	    return
	fi
    fi

    MSG="Add the administrator identity (y/n/h)?"
    get_confirm "$MSG" "y" "add_admin_cred_help"
    if [ $? -eq 1 ]; then
	get_adminDN
	get_admin_pw
	add_admin
	delete_proxy_read_pw
	allow_admin_read_write_shadow
	deny_non_admin_shadow_access
        ${ECHO} ""
	${ECHO} "  Shadow update has been enabled."
	return
    fi

    ${ECHO} "  No administrator identity specified, shadow update may not work."
}


#
# prompt_config_info(): This function prompts the user for the config
# info that is not specified in the input file.  
#
prompt_config_info()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In prompt_config_info()"

    # Prompt for iDS server name.
    get_ids_server

    # Prompt for iDS port number.
    get_ids_port

    # Check iDS version for compatibility.
    chk_ids_version

    # Check if the server supports the VLV.
    chk_vlv_indexes

    # Get the Directory manager DN and passwd.
    get_dirmgr_dn
    get_dirmgr_pw

    #
    # LDAP CLIENT PROFILE SPECIFIC INFORMATION.
    #   (i.e. The fields that show up in the profile.)
    #
    get_domain "domain_help"

    get_basedn

    gssapi_setup

    get_profile_name

    if [ "$LDAP_ENABLE_SHADOW_UPDATE" = "TRUE" ];then
	setup_shadow_update
	cleanup
	exit 0
    fi

    get_srv_list
    get_pref_srv
    get_search_scope

    # If cred is "anonymous", make auth == "none"
    get_cred_level
    if [ "$LDAP_CRED_LEVEL" != "anonymous" ]; then
	get_auth
    fi

    get_followref

    # Query user about timelimt.
    get_confirm "Do you want to modify the server timelimit value (y/n/h)?" "n" "tlim_help"
    NEED_TIME=$?
    [ $NEED_TIME -eq 1 ] && get_timelimit

    # Query user about sizelimit.
    get_confirm "Do you want to modify the server sizelimit value (y/n/h)?" "n" "slim_help"
    NEED_SIZE=$?
    [ $NEED_SIZE -eq 1 ] && get_sizelimit

    # Does the user want to store passwords in crypt format?
    get_want_crypt

    # Prompt for any Service Authentication Methods?
    get_confirm "Do you want to setup a Service Authentication Methods (y/n/h)?" "n" "srvauth_help"
    if [ $? -eq 1 ]; then
	# Does the user want to set Service Authentication Method for pam_ldap?
	get_confirm "Do you want to setup a Service Auth. Method for \"pam_ldap\" (y/n/h)?" "n" "pam_ldap_help"
	NEED_SRVAUTH_PAM=$?
	[ $NEED_SRVAUTH_PAM -eq 1 ] && get_srv_authMethod_pam

	# Does the user want to set Service Authentication Method for keyserv?
	get_confirm "Do you want to setup a Service Auth. Method for \"keyserv\" (y/n/h)?" "n" "keyserv_help"
	NEED_SRVAUTH_KEY=$?
	[ $NEED_SRVAUTH_KEY -eq 1 ] && get_srv_authMethod_key

	# Does the user want to set Service Authentication Method for passwd-cmd?
	get_confirm "Do you want to setup a Service Auth. Method for \"passwd-cmd\" (y/n/h)?" "n" "passwd-cmd_help"
	NEED_SRVAUTH_CMD=$?
	[ $NEED_SRVAUTH_CMD -eq 1 ] && get_srv_authMethod_cmd
    fi
 

    # Get Timeouts
    get_srch_time
    get_prof_ttl
    get_bind_limit

    # Ask whether to enable shadow update
    get_want_shadow_update

    # Reset the sdd_file and prompt user for SSD.  Will use menus
    # to build an SSD File.
    reset_ssd_file
    prompt_ssd

    # Display FULL debugging info.
    disp_full_debug

    # Extra blank line to separate prompt lines from steps.
    ${ECHO} " "
}


######################################################################
# FUNCTIONS  FOR display_summary() START HERE.
######################################################################


#
# get_proxyagent(): Get the proxyagent DN.
#
get_proxyagent()
{
    LDAP_PROXYAGENT="cn=proxyagent,ou=profile,${LDAP_BASEDN}"  # default
    get_ans "Enter DN for proxy agent:" "$LDAP_PROXYAGENT"
    LDAP_PROXYAGENT=$ANS
}


#
# get_proxy_pw(): Get the proxyagent passwd.
#
get_proxy_pw()
{
    get_passwd "Enter passwd for proxyagent:"
    LDAP_PROXYAGENT_CRED=$ANS
}

#
# display_summary(): Display a summary of values entered and let the 
#                    user modify values at will.
#
display_summary()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In display_summary()"

    # Create lookup table for function names.  First entry is dummy for
    # shift.
    TBL1="dummy"
    TBL2="get_domain get_basedn get_profile_name"
    TBL3="get_srv_list get_pref_srv get_search_scope get_cred_level"
    TBL4="get_auth get_followref"
    TBL5="get_timelimit get_sizelimit get_want_crypt"
    TBL6="get_srv_authMethod_pam get_srv_authMethod_key get_srv_authMethod_cmd"
    TBL7="get_srch_time get_prof_ttl get_bind_limit"
    TBL8="get_want_shadow_update"
    TBL9="prompt_ssd"
    FUNC_TBL="$TBL1 $TBL2 $TBL3 $TBL4 $TBL5 $TBL6 $TBL7 $TBL8 $TBL9"

    # Since menu prompt string is long, set here.
    _MENU_PROMPT="Enter config value to change: (1-20 0=commit changes)"

    # Infinite loop.  Test for 0, and break in loop.
    while :
    do
	# Display menu and get value in range.
	display_msg summary_menu
	get_menu_choice "${_MENU_PROMPT}" "0" "20" "0"
	_CH=$MN_CH
	
	# Make sure where not exiting.
	if [ $_CH -eq 0 ]; then
	    break       # Break out of loop if 0 selected.
	fi

	# Call appropriate function from function table.
	set $FUNC_TBL
	shift $_CH
	$1          # Call the appropriate function.
    done

    # If cred level is still see if user wants a change?
    if ${ECHO} "$LDAP_CRED_LEVEL" | ${GREP} "proxy" > /dev/null 2>&1
    then
	if [ "$LDAP_AUTHMETHOD" != "none" ]; then
	    NEED_PROXY=1    # I assume integer test is faster?
	    get_proxyagent
	    get_proxy_pw
	else
	    ${ECHO} "WARNING: Since Authentication method is 'none'."
	    ${ECHO} "         Credential level will be set to 'anonymous'."
	    LDAP_CRED_LEVEL="anonymous"
	fi
    fi

    # If shadow update is enabled, set up administrator credential
    if [ "$LDAP_ENABLE_SHADOW_UPDATE" = "TRUE" ]; then
	NEED_ADMIN=1
	if ${ECHO} "$LDAP_CRED_LEVEL" | ${GREP} "self" > /dev/null 2>&1; then
	    if ${ECHO} "$LDAP_AUTHMETHOD" | ${GREP} "GSSAPI" > /dev/null 2>&1; then
		NEED_HOSTACL=1
		NEED_ADMIN=0
	    fi
	fi
        [ $DEBUG -eq 1 ] && ${ECHO} "NEED_HOSTACL = $NEED_HOSTACL"
        [ $DEBUG -eq 1 ] && ${ECHO} "NEED_ADMIN   = $NEED_ADMIN"
	if [ $NEED_ADMIN -eq 1 ]; then
	    get_adminDN
	    get_admin_pw
	fi
    fi

    # Display FULL debugging info.
    disp_full_debug

    # Final confirmation message. (ARE YOU SURE!)
    ${ECHO} " "
    get_confirm_nodef "WARNING: About to start committing changes. (y=continue, n=EXIT)" 
    if [ $? -eq 0 ]; then
	${ECHO} "Terminating setup without making changes at users request."
	cleanup
	exit 1
    fi

    # Print newline 
    ${ECHO} " "
}


#
# create_config_file(): Write config data to config file specified.
#
create_config_file()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In create_config_file()"

    # If output file exists, delete it.
    [ -f $OUTPUT_FILE ] && rm $OUTPUT_FILE

    # Create output file.
    cat > $OUTPUT_FILE <<EOF
#!/bin/sh
# $OUTPUT_FILE - This file contains configuration information for
#                Native LDAP.  Use the idsconfig tool to load it.
#
# WARNING: This file was generated by idsconfig, and is intended to
#          be loaded by idsconfig as is.  DO NOT EDIT THIS FILE!
#
IDS_SERVER="$IDS_SERVER"
IDS_PORT=$IDS_PORT
IDS_TIMELIMIT=$IDS_TIMELIMIT
IDS_SIZELIMIT=$IDS_SIZELIMIT
LDAP_ROOTDN="$LDAP_ROOTDN"
LDAP_ROOTPWD=$LDAP_ROOTPWD
LDAP_DOMAIN="$LDAP_DOMAIN"
LDAP_SUFFIX="$LDAP_SUFFIX"
GSSAPI_ENABLE=$GSSAPI_ENABLE
LDAP_KRB_REALM="$LDAP_KRB_REALM"

# Internal program variables that need to be set.
NEED_PROXY=$NEED_PROXY
NEED_TIME=$NEED_TIME
NEED_SIZE=$NEED_SIZE
NEED_CRYPT=$NEED_CRYPT
NEED_ADMIN=$NEED_ADMIN
NEED_HOSTACL=$NEED_HOSTACL
EXISTING_PROFILE=$EXISTING_PROFILE

# LDAP PROFILE related defaults
LDAP_PROFILE_NAME="$LDAP_PROFILE_NAME"
DEL_OLD_PROFILE=1
LDAP_BASEDN="$LDAP_BASEDN"
LDAP_SERVER_LIST="$LDAP_SERVER_LIST"
LDAP_AUTHMETHOD="$LDAP_AUTHMETHOD"
LDAP_FOLLOWREF=$LDAP_FOLLOWREF
LDAP_SEARCH_SCOPE="$LDAP_SEARCH_SCOPE"
NEED_SRVAUTH_PAM=$NEED_SRVAUTH_PAM
NEED_SRVAUTH_KEY=$NEED_SRVAUTH_KEY
NEED_SRVAUTH_CMD=$NEED_SRVAUTH_CMD
LDAP_SRV_AUTHMETHOD_PAM="$LDAP_SRV_AUTHMETHOD_PAM"
LDAP_SRV_AUTHMETHOD_KEY="$LDAP_SRV_AUTHMETHOD_KEY"
LDAP_SRV_AUTHMETHOD_CMD="$LDAP_SRV_AUTHMETHOD_CMD"
LDAP_SEARCH_TIME_LIMIT=$LDAP_SEARCH_TIME_LIMIT
LDAP_PREF_SRVLIST="$LDAP_PREF_SRVLIST"
LDAP_PROFILE_TTL=$LDAP_PROFILE_TTL
LDAP_CRED_LEVEL="$LDAP_CRED_LEVEL"
LDAP_BIND_LIMIT=$LDAP_BIND_LIMIT

# Proxy Agent
LDAP_PROXYAGENT="$LDAP_PROXYAGENT"
LDAP_PROXYAGENT_CRED=$LDAP_PROXYAGENT_CRED

# enableShadowUpdate flag and Administrator credential
LDAP_ENABLE_SHADOW_UPDATE=$LDAP_ENABLE_SHADOW_UPDATE
LDAP_ADMINDN="$LDAP_ADMINDN"
LDAP_ADMIN_CRED=$LDAP_ADMIN_CRED

# Export all the variables (just in case)
export IDS_HOME IDS_PORT LDAP_ROOTDN LDAP_ROOTPWD LDAP_SERVER_LIST LDAP_BASEDN
export LDAP_DOMAIN LDAP_SUFFIX LDAP_PROXYAGENT LDAP_PROXYAGENT_CRED
export NEED_PROXY
export LDAP_ENABLE_SHADOW_UPDATE LDAP_ADMINDN LDAP_ADMIN_CRED
export NEED_ADMIN NEED_HOSTACL EXISTING_PROFILE
export LDAP_PROFILE_NAME LDAP_BASEDN LDAP_SERVER_LIST 
export LDAP_AUTHMETHOD LDAP_FOLLOWREF LDAP_SEARCH_SCOPE LDAP_SEARCH_TIME_LIMIT
export LDAP_PREF_SRVLIST LDAP_PROFILE_TTL LDAP_CRED_LEVEL LDAP_BIND_LIMIT
export NEED_SRVAUTH_PAM NEED_SRVAUTH_KEY NEED_SRVAUTH_CMD
export LDAP_SRV_AUTHMETHOD_PAM LDAP_SRV_AUTHMETHOD_KEY LDAP_SRV_AUTHMETHOD_CMD
export LDAP_SERV_SRCH_DES SSD_FILE GSSAPI_ENABLE LDAP_KRB_REALM

# Service Search Descriptors start here if present:
EOF
    # Add service search descriptors.
    ssd_2_config "${OUTPUT_FILE}"

    # Add LDAP suffix preferences
    print_suffix_config >> "${OUTPUT_FILE}"

    # Add the end of FILE tag.
    ${ECHO} "" >> ${OUTPUT_FILE}
    ${ECHO} "# End of $OUTPUT_FILE" >> ${OUTPUT_FILE}
}


#
# chk_vlv_indexes(): Do ldapsearch to see if server supports VLV.
#
chk_vlv_indexes()
{
    # Do ldapsearch to see if server supports VLV.
    ${LDAPSEARCH} ${SERVER_ARGS} -b "" -s base "objectclass=*" > ${TMPDIR}/checkVLV 2>&1
    eval "${GREP} 2.16.840.1.113730.3.4.9 ${TMPDIR}/checkVLV ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "ERROR: VLV is not supported on LDAP server!"
	cleanup
	exit 1
    fi
    [ $DEBUG -eq 1 ] && ${ECHO} "  VLV controls found on LDAP server."
}

#
# get_backend(): this function gets the relevant backend
#                (database) for LDAP_BASED.
#                Description: set IDS_DATABASE; exit on failure.
#                Prerequisite: LDAP_BASEDN and LDAP_SUFFIX are
#                valid.
#
#                backend is retrieved from suffixes and subsuffixes
#                defined under "cn=mapping tree,cn=config". The 
#                nsslapd-state attribute of these suffixes entries
#                is filled with either Backend, Disabled or referrals
#                related values. We only want those that have a true
#                backend database to select the relevant backend.
#                
get_backend()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_backend()"

    cur_suffix=${LDAP_BASEDN}
    prev_suffix=
    IDS_DATABASE=
    while [ "${cur_suffix}" != "${prev_suffix}" ]
    do
	[ $DEBUG -eq 1 ] && ${ECHO} "testing LDAP suffix: ${cur_suffix}"
	eval "${LDAPSEARCH} ${LDAP_ARGS} " \
		"-b \"cn=\\\"${cur_suffix}\\\",cn=mapping tree,cn=config\" " \
		"-s base nsslapd-state=Backend nsslapd-backend 2>&1 " \
		"| ${GREP} 'nsslapd-backend=' " \
		"> ${TMPDIR}/ids_database_name 2>&1"
	NUM_DBS=`wc -l ${TMPDIR}/ids_database_name | awk '{print $1}'`
	case ${NUM_DBS} in
	0) # not a suffix, or suffix not activated; try next
	    prev_suffix=${cur_suffix}
	    cur_suffix=`${ECHO} ${cur_suffix} | cut -f2- -d','`
	    ;;
	1) # suffix found; get database name
	    IDS_DATABASE=`cat ${TMPDIR}/ids_database_name | cut -d= -f2`
	    ;;
	*) # can not handle more than one database per suffix
	    ${ECHO} "ERROR: More than one database is configured "
	    ${ECHO} "       for $LDAP_SUFFIX!"
	    ${ECHO} "       $PROG can not configure suffixes where "
	    ${ECHO} "       more than one database is used for one suffix."
	    cleanup
	    exit 1
	    ;;
	esac
	if [ -n "${IDS_DATABASE}" ]; then
	    break
	fi
    done

    if [ -z "${IDS_DATABASE}" ]; then
	# should not happen, since LDAP_BASEDN is supposed to be valid
	${ECHO} "Could not find a valid backend for ${LDAP_BASEDN}."
	${ECHO} "Exiting."
	cleanup
	exit 1
    fi

    [ $DEBUG -eq 1 ] && ${ECHO} "IDS_DATABASE: ${IDS_DATABASE}"
}

#
# validate_suffix(): This function validates ${LDAP_SUFFIX}
#                  THIS FUNCTION IS FOR THE LOAD CONFIG FILE OPTION.
#
validate_suffix()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In validate_suffix()"

    # Check LDAP_SUFFIX is not null
    if [ -z "${LDAP_SUFFIX}" ]; then
	${ECHO} "Invalid suffix (null suffix)"
	cleanup
	exit 1
    fi

    # Check LDAP_SUFFIX and LDAP_BASEDN are consistent
    # Convert to lower case for basename.
    format_string "${LDAP_BASEDN}"
    LOWER_BASEDN="${FMT_STR}"
    format_string "${LDAP_SUFFIX}"
    LOWER_SUFFIX="${FMT_STR}"

    [ $DEBUG -eq 1 ] && ${ECHO} "LOWER_BASEDN: ${LOWER_BASEDN}"
    [ $DEBUG -eq 1 ] && ${ECHO} "LOWER_SUFFIX: ${LOWER_SUFFIX}"

    if [ "${LOWER_BASEDN}" != "${LOWER_SUFFIX}" ]; then
    	sub_basedn=`basename "${LOWER_BASEDN}" "${LOWER_SUFFIX}"`
    	if [ "$sub_basedn" = "${LOWER_BASEDN}" ]; then
	    ${ECHO} "Invalid suffix ${LOWER_SUFFIX}"
	    ${ECHO} "for Base DN ${LOWER_BASEDN}"
	    cleanup
	    exit 1
	fi
    fi

    # Check LDAP_SUFFIX does exist
    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_SUFFIX}\" -s base \"objectclass=*\" > ${TMPDIR}/checkSuffix 2>&1" && return 0

    # Well, suffix does not exist, try to prepare create it ...
    NEED_CREATE_SUFFIX=1
    prep_create_sfx_entry ||
    {
	cleanup
	exit 1
    }
    [ -n "${NEED_CREATE_BACKEND}" ] &&
    {
	# try to use id attr value of the suffix as a database name
	IDS_DATABASE=${_VAL}
	prep_create_sfx_backend
	case $? in
	1)	# cann't use the name we want, so we can either exit or use
		# some another available name - doing the last ...
		IDS_DATABASE=${IDS_DATABASE_AVAIL}
		;;
	2)	# unable to determine database name
		cleanup
		exit 1
		;;
	esac
    }

    [ $DEBUG -eq 1 ] && ${ECHO} "Suffix $LDAP_SUFFIX, Database $IDS_DATABASE"
}

#
# validate_info(): This function validates the basic info collected
#                  So that some problems are caught right away.
#                  THIS FUNCTION IS FOR THE LOAD CONFIG FILE OPTION.
#
validate_info()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In validate_info()"

    # Set SERVER_ARGS, AUTH_ARGS, and LDAP_ARGS for the config file.
    SERVER_ARGS="-h ${IDS_SERVER} -p ${IDS_PORT}"
    AUTH_ARGS="-D \"${LDAP_ROOTDN}\" -j ${LDAP_ROOTPWF}"
    LDAP_ARGS="${SERVER_ARGS} ${AUTH_ARGS}"
    export SERVER_ARGS

    # Check the Root DN and Root DN passwd.
    # Use eval instead of $EVAL because not part of setup. (validate)
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"\" -s base \"objectclass=*\" > ${TMPDIR}/checkDN 2>&1"
    if [ $? -ne 0 ]; then
	eval "${GREP} credential ${TMPDIR}/checkDN ${VERB}"
	if [ $? -eq 0 ]; then
	    ${ECHO} "ERROR: Root DN passwd is invalid."
	else
	    ${ECHO} "ERROR2: Invalid Root DN <${LDAP_ROOTDN}>."
	fi
	cleanup
	exit 1
    fi
    [ $DEBUG -eq 1 ] && ${ECHO} "  RootDN ... OK"
    [ $DEBUG -eq 1 ] && ${ECHO} "  RootDN passwd ... OK"

    # Check if the server supports the VLV.
    chk_vlv_indexes
    [ $DEBUG -eq 1 ] && ${ECHO} "  VLV indexes ... OK"

    # Check LDAP suffix
    validate_suffix
    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP suffix ... OK"
}

#
# format_string(): take a string as argument and set FMT_STR
# to be the same string formatted as follow:
# - only lower case characters
# - no unnecessary spaces around , and =
#
format_string()
{
    FMT_STR=`${ECHO} "$1" | tr '[A-Z]' '[a-z]' |
	sed -e 's/[ ]*,[ ]*/,/g' -e 's/[ ]*=[ ]*/=/g'`
}

#
# prepare for the suffix entry creation
#
# input  : LDAP_BASEDN, LDAP_SUFFIX - base dn and suffix;
# in/out : LDAP_SUFFIX_OBJ, LDAP_SUFFIX_ACI - initially may come from config.
# output : NEED_CREATE_BACKEND - backend for this suffix needs to be created;
#          _RDN, _ATT, _VAL - suffix's RDN, id attribute name and its value.
# return : 0 - success, otherwise error.
#
prep_create_sfx_entry()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In prep_create_sfx_entry()"

    # check whether suffix corresponds to base dn
    format_string "${LDAP_BASEDN}"
    ${ECHO} ",${FMT_STR}" | ${GREP} ",${LDAP_SUFFIX}$" >/dev/null 2>&1 ||
    {
	display_msg sfx_not_suitable
	return 1
    }

    # parse LDAP_SUFFIX
    _RDN=`${ECHO} "${LDAP_SUFFIX}" | cut -d, -f1`
    _ATT=`${ECHO} "${_RDN}" | cut -d= -f1`
    _VAL=`${ECHO} "${_RDN}" | cut -d= -f2-`

    # find out an objectclass for suffix entry if it is not defined yet
    [ -z "${LDAP_SUFFIX_OBJ}" ] &&
    {
	get_objectclass ${_ATT}
	[ -z "${_ATTR_NAME}" ] &&
	{
		display_msg obj_not_found
		return 1
	}
	LDAP_SUFFIX_OBJ=${_ATTR_NAME}
    }
    [ $DEBUG -eq 1 ] && ${ECHO} "Suffix entry object is ${LDAP_SUFFIX_OBJ}"

    # find out an aci for suffix entry if it is not defined yet
    [ -z "${LDAP_SUFFIX_ACI}" ] &&
    {
	# set Directory Server default aci
	LDAP_SUFFIX_ACI=`cat <<EOF
aci: (targetattr != "userPassword || passwordHistory || passwordExpirationTime
 || passwordExpWarned || passwordRetryCount || retryCountResetTime ||
 accountUnlockTime || passwordAllowChangeTime")
 (
   version 3.0;
   acl "Anonymous access";
   allow (read, search, compare) userdn = "ldap:///anyone";
 )
aci: (targetattr != "nsroledn || aci || nsLookThroughLimit || nsSizeLimit ||
 nsTimeLimit || nsIdleTimeout || passwordPolicySubentry ||
 passwordExpirationTime || passwordExpWarned || passwordRetryCount ||
 retryCountResetTime || accountUnlockTime || passwordHistory ||
 passwordAllowChangeTime")
 (
   version 3.0;
   acl "Allow self entry modification except for some attributes";
   allow (write) userdn = "ldap:///self";
 )
aci: (targetattr = "*")
 (
   version 3.0;
   acl "Configuration Administrator";
   allow (all) userdn = "ldap:///uid=admin,ou=Administrators,
                         ou=TopologyManagement,o=NetscapeRoot";
 )
aci: (targetattr ="*")
 (
   version 3.0;
   acl "Configuration Administrators Group";
   allow (all) groupdn = "ldap:///cn=Configuration Administrators,
                          ou=Groups,ou=TopologyManagement,o=NetscapeRoot";
 )
EOF
`
    }
    [ $DEBUG -eq 1 ] && cat <<EOF
DEBUG: ACI for ${LDAP_SUFFIX} is
${LDAP_SUFFIX_ACI}
EOF

    NEED_CREATE_BACKEND=

    # check the suffix mapping tree ...
    # if mapping exists, suffix should work, otherwise DS inconsistent
    # NOTE: -b 'cn=mapping tree,cn=config' -s one 'cn=\"$1\"' won't work
    #       in case of 'cn' value in LDAP is not quoted by '"',
    #       -b 'cn=\"$1\",cn=mapping tree,cn=config' works in all cases
    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} \
	-b 'cn=\"${LDAP_SUFFIX}\",cn=mapping tree,cn=config' \
	-s base 'objectclass=*' dn ${VERB}" &&
    {
	[ $DEBUG -eq 1 ] && ${ECHO} "Suffix mapping already exists"
	# get_backend() either gets IDS_DATABASE or exits
	get_backend
	return 0
    }

    # no suffix mapping, just in case check ldbm backends consistency -
    # there are must be NO any databases pointing to LDAP_SUFFIX 
    [ -n "`${EVAL} \"${LDAPSEARCH} ${LDAP_ARGS} \
	-b 'cn=ldbm database,cn=plugins,cn=config' \
	-s one 'nsslapd-suffix=${LDAP_SUFFIX}' dn\" 2>/dev/null`" ] &&
    {
	display_msg sfx_config_incons
	return 1
    }

    # ok, no suffix mapping, no ldbm database
    [ $DEBUG -eq 1 ] && ${ECHO} "DEBUG: backend needs to be created ..."
    NEED_CREATE_BACKEND=1
    return 0
}

#
# prepare for the suffix backend creation
#
# input  : IDS_DATABASE - requested ldbm db name (must be not null)
# in/out : IDS_DATABASE_AVAIL - available ldbm db name
# return : 0 - ldbm db name ok
#          1 - IDS_DATABASE exists,
#              so IDS_DATABASE_AVAIL contains available name
#          2 - unable to find any available name
#
prep_create_sfx_backend()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In prep_create_sfx_backend()"

    # check if requested name available
    [ "${IDS_DATABASE}" = "${IDS_DATABASE_AVAIL}" ] && return 0

    # get the list of database names start with a requested name
    _LDBM_DBS=`${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} \
	-b 'cn=ldbm database,cn=plugins,cn=config' \
	-s one 'cn=${IDS_DATABASE}*' cn"` 2>/dev/null

    # find available db name based on a requested name
    _i=""; _i_MAX=10
    while [ ${_i:-0} -lt ${_i_MAX} ]
    do
	_name="${IDS_DATABASE}${_i}"
	${ECHO} "${_LDBM_DBS}" | ${GREP} -i "^cn=${_name}$" >/dev/null 2>&1 ||
	{
		IDS_DATABASE_AVAIL="${_name}"
		break
	}
	_i=`expr ${_i:-0} + 1`
    done

    [ "${IDS_DATABASE}" = "${IDS_DATABASE_AVAIL}" ] && return 0

    [ -n "${IDS_DATABASE_AVAIL}" ] &&
    {
	display_msg ldbm_db_exist
	return 1
    }

    display_msg unable_find_db_name
    return 2
}

#
# add suffix if needed,
#     suffix entry and backend MUST be prepared by
#     prep_create_sfx_entry and prep_create_sfx_backend correspondingly
#
# input  : NEED_CREATE_SUFFIX, LDAP_SUFFIX, LDAP_SUFFIX_OBJ, _ATT, _VAL
#          LDAP_SUFFIX_ACI, NEED_CREATE_BACKEND, IDS_DATABASE
# return : 0 - suffix successfully created, otherwise error occured
#
add_suffix()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_suffix()"

    [ -n "${NEED_CREATE_SUFFIX}" ] || return 0

    [ -n "${NEED_CREATE_BACKEND}" ] &&
    {
	${EVAL} "${LDAPADD} ${LDAP_ARGS} ${VERB}" <<EOF
dn: cn="${LDAP_SUFFIX}",cn=mapping tree,cn=config
objectclass: top
objectclass: extensibleObject
objectclass: nsMappingTree
cn: ${LDAP_SUFFIX}
nsslapd-state: backend
nsslapd-backend: ${IDS_DATABASE}

dn: cn=${IDS_DATABASE},cn=ldbm database,cn=plugins,cn=config
objectclass: top
objectclass: extensibleObject
objectclass: nsBackendInstance
cn: ${IDS_DATABASE}
nsslapd-suffix: ${LDAP_SUFFIX}
EOF
	[ $? -ne 0 ] &&
	{
		display_msg create_ldbm_db_error
		return 1
	}

	${ECHO} "  ${STEP}. Database ${IDS_DATABASE} successfully created"
	STEP=`expr $STEP + 1`
    }

    ${EVAL} "${LDAPADD} ${LDAP_ARGS} ${VERB}" <<EOF
dn: ${LDAP_SUFFIX}
objectclass: ${LDAP_SUFFIX_OBJ}
${_ATT}: ${_VAL}
${LDAP_SUFFIX_ACI}
EOF
    [ $? -ne 0 ] &&
    {
	display_msg create_suffix_entry_error
	return 1
    }

    ${ECHO} "  ${STEP}. Suffix ${LDAP_SUFFIX} successfully created"
    STEP=`expr $STEP + 1`
    return 0
}

#
# interactively get suffix and related info from a user
#
# input  : LDAP_BASEDN - Base DN
# output : LDAP_SUFFIX - Suffix, _ATT, _VAL - id attribute and its value;
#          LDAP_SUFFIX_OBJ, LDAP_SUFFIX_ACI - objectclass and aci;
#          NEED_CREATE_BACKEND - tells whether backend needs to be created;
#          IDS_DATABASE - prepared ldbm db name
# return : 0 - user gave a correct suffix 
#          1 - suffix given by user cann't be created
#
get_suffix()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_suffix()"

    while :
    do
	get_ans "Enter suffix to be created (b=back/h=help):" ${LDAP_BASEDN}
	case "${ANS}" in
	[Hh] | Help | help | \? ) display_msg create_suffix_help ;;
	[Bb] | Back | back | \< ) return 1 ;;
	* )
		format_string "${ANS}"
		LDAP_SUFFIX=${FMT_STR}
		prep_create_sfx_entry || continue

		[ -n "${NEED_CREATE_BACKEND}" ] &&
		{
		    IDS_DATABASE_AVAIL= # reset the available db name

		    reenter_suffix=
		    while :
		    do
			get_ans "Enter ldbm database name (b=back/h=help):" \
				${IDS_DATABASE_AVAIL:-${_VAL}}
			case "${ANS}" in
			[Hh] | \? ) display_msg enter_ldbm_db_help ;;
			[Bb] | \< ) reenter_suffix=1; break ;;
			* )
				IDS_DATABASE="${ANS}"
				prep_create_sfx_backend && break
			esac
		    done
		    [ -n "${reenter_suffix}" ] && continue

		    [ $DEBUG -eq 1 ] && cat <<EOF
DEBUG: backend name for suffix ${LDAP_SUFFIX} will be ${IDS_DATABASE}
EOF
		}

		# eventually everything is prepared
		return 0
		;;
	esac
    done
}

#
# print out a script which sets LDAP suffix related preferences
#
print_suffix_config()
{
    cat <<EOF2
# LDAP suffix related preferences used only if needed
IDS_DATABASE="${IDS_DATABASE}"
LDAP_SUFFIX_OBJ="$LDAP_SUFFIX_OBJ"
LDAP_SUFFIX_ACI=\`cat <<EOF
${LDAP_SUFFIX_ACI}
EOF
\`
export IDS_DATABASE LDAP_SUFFIX_OBJ LDAP_SUFFIX_ACI
EOF2
}

# 
# check_basedn_suffix(): check that there is an existing 
# valid suffix to hold current base DN
# return:
#   0: valid suffix found or new one should be created,
#      NEED_CREATE_SUFFIX flag actually indicates that
#   1: some error occures
#
check_basedn_suffix()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In check_basedn_suffix()"

    NEED_CREATE_SUFFIX=

    # find out existing suffixes
    discover_serv_suffix

    ${ECHO} "  Validating LDAP Base DN and Suffix ..."

    # check that LDAP Base DN might be added
    cur_ldap_entry=${LDAP_BASEDN}
    prev_ldap_entry=
    while [ "${cur_ldap_entry}" != "${prev_ldap_entry}" ]
    do
	[ $DEBUG -eq 1 ] && ${ECHO} "testing LDAP entry: ${cur_ldap_entry}"
	${LDAPSEARCH} ${SERVER_ARGS} -b "${cur_ldap_entry}" \
		-s one "objectclass=*" > /dev/null 2>&1
	if [ $? -eq 0 ]; then 
	    break
	else
	    prev_ldap_entry=${cur_ldap_entry}
	    cur_ldap_entry=`${ECHO} ${cur_ldap_entry} | cut -f2- -d','`
	fi	
    done

    if [ "${cur_ldap_entry}" = "${prev_ldap_entry}" ]; then
	${ECHO} "  No valid suffixes were found for Base DN ${LDAP_BASEDN}"

	NEED_CREATE_SUFFIX=1
	return 0

    else
	[ $DEBUG -eq 1 ] && ${ECHO} "found valid LDAP entry: ${cur_ldap_entry}"

	# Now looking for relevant suffix for this entry.
	# LDAP_SUFFIX will then be used to add necessary
	# base objects. See add_base_objects().
	format_string "${cur_ldap_entry}"
	lower_entry="${FMT_STR}"
	[ $DEBUG -eq 1 ] && ${ECHO} "final suffix list: ${LDAP_SUFFIX_LIST}"
	oIFS=$IFS
	[ $DEBUG -eq 1 ] && ${ECHO} "setting IFS to new line"
	IFS='
'
	for suff in ${LDAP_SUFFIX_LIST}
	do
	    [ $DEBUG -eq 1 ] && ${ECHO} "testing suffix: ${suff}"
	    format_string "${suff}"
	    lower_suff="${FMT_STR}"
	    if [ "${lower_entry}" = "${lower_suff}" ]; then
		LDAP_SUFFIX="${suff}"
		break
	    else
		dcstmp=`basename "${lower_entry}" "${lower_suff}"`
		if [ "${dcstmp}" = "${lower_entry}" ]; then
		    # invalid suffix, try next one
		    continue
		else
		    # valid suffix found
		    LDAP_SUFFIX="${suff}"
		    break
		fi
	    fi
	done
	[ $DEBUG -eq 1 ] && ${ECHO} "setting IFS to original value"
	IFS=$oIFS

	[ $DEBUG -eq 1 ] && ${ECHO} "LDAP_SUFFIX: ${LDAP_SUFFIX}"

	if [ -z "${LDAP_SUFFIX}" ]; then
	    # should not happen, since we found the entry
	    ${ECHO} "Could not find a valid suffix for ${LDAP_BASEDN}."
	    ${ECHO} "Exiting."
	    return 1
	fi
	
	# Getting relevant database (backend)
	# IDS_DATABASE will then be used to create indexes.
	get_backend

	return 0
    fi
}

#
# discover_serv_suffix(): This function queries the server to find 
#    suffixes available
#  return: 0: OK, suffix found
#          1: suffix not determined
discover_serv_suffix()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In discover_serv_suffix()"

    # Search the server for the TOP of the TREE.
    ${LDAPSEARCH} ${SERVER_ARGS} -b "" -s base "objectclass=*" > ${TMPDIR}/checkTOP 2>&1
    ${GREP} -i namingcontexts ${TMPDIR}/checkTOP | \
	${GREP} -i -v NetscapeRoot > ${TMPDIR}/treeTOP
    NUM_TOP=`wc -l ${TMPDIR}/treeTOP | awk '{print $1}'`
    case $NUM_TOP in
	0)
	    [ $DEBUG -eq 1 ] && ${ECHO} "DEBUG: No suffix found in LDAP tree"
	    return 1
	    ;;
	*)  # build the list of suffixes; take out 'namingContexts=' in
	    # each line of ${TMPDIR}/treeTOP
	    LDAP_SUFFIX_LIST=`cat ${TMPDIR}/treeTOP | 
		awk '{ printf("%s\n",substr($0,16,length-15)) }'`
	    ;;
    esac

    [ $DEBUG -eq 1 ] && ${ECHO} "  LDAP_SUFFIX_LIST = $LDAP_SUFFIX_LIST"
    return 0
}


#
# modify_cn(): Change the cn from MUST to MAY in ipNetwork.
#
modify_cn()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_cn()"

    ( cat <<EOF
dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.1.1.2.7 NAME 'ipNetwork' DESC 'Standard LDAP objectclass' SUP top STRUCTURAL MUST ipNetworkNumber MAY ( ipNetmaskNumber $ manager $ cn $ l $ description ) X-ORIGIN 'RFC 2307' )
EOF
) > ${TMPDIR}/ipNetwork_cn

    # Modify the cn for ipNetwork.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/ipNetwork_cn ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of cn for ipNetwork failed!"
	cleanup
	exit 1
    fi
}


# modify_timelimit(): Modify timelimit to user value.
modify_timelimit()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_timelimit()"

    # Here doc to modify timelimit.
    ( cat <<EOF
dn: cn=config
changetype: modify
replace: nsslapd-timelimit
nsslapd-timelimit: ${IDS_TIMELIMIT}
EOF
) > ${TMPDIR}/ids_timelimit

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/ids_timelimit ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of nsslapd-timelimit failed!"
	cleanup
	exit 1
    fi

    # Display messages for modifications made in patch.
    ${ECHO} "  ${STEP}. Changed timelimit to ${IDS_TIMELIMIT} in cn=config."
    STEP=`expr $STEP + 1`
}


# modify_sizelimit(): Modify sizelimit to user value.
modify_sizelimit()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_sizelimit()"

    # Here doc to modify sizelimit.
    ( cat <<EOF
dn: cn=config
changetype: modify
replace: nsslapd-sizelimit
nsslapd-sizelimit: ${IDS_SIZELIMIT}
EOF
) > ${TMPDIR}/ids_sizelimit

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/ids_sizelimit ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of nsslapd-sizelimit failed!"
	cleanup
	exit 1
    fi

    # Display messages for modifications made in patch.
    ${ECHO} "  ${STEP}. Changed sizelimit to ${IDS_SIZELIMIT} in cn=config."
    STEP=`expr $STEP + 1`
}


# modify_pwd_crypt(): Modify the passwd storage scheme to support CRYPT.
modify_pwd_crypt()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_pwd_crypt()"

    # Here doc to modify passwordstoragescheme.
    # IDS 5.2 moved passwordchangesceme off to a new data structure.
    if [ $IDS_MAJVER -le 5 ] && [ $IDS_MINVER -le 1 ]; then 
	( cat <<EOF
dn: cn=config
changetype: modify
replace: passwordstoragescheme
passwordstoragescheme: crypt
EOF
	) > ${TMPDIR}/ids_crypt
    else
	( cat <<EOF
dn: cn=Password Policy,cn=config
changetype: modify
replace: passwordstoragescheme
passwordstoragescheme: crypt
EOF
	) > ${TMPDIR}/ids_crypt
    fi

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/ids_crypt ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of passwordstoragescheme failed!"
	cleanup
	exit 1
    fi

    # Display messages for modifications made in patch.
    ${ECHO} "  ${STEP}. Changed passwordstoragescheme to \"crypt\" in cn=config."
    STEP=`expr $STEP + 1`
}


#
# add_eq_indexes(): Add indexes to improve search performance.
#
add_eq_indexes()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_eq_indexes()"

    # Set eq indexes to add.
    _INDEXES="uidNumber ipNetworkNumber gidnumber oncrpcnumber automountKey"

    if [ -z "${IDS_DATABASE}" ]; then
	get_backend
    fi

    # Set _EXT to use as shortcut.
    _EXT="cn=index,cn=${IDS_DATABASE},cn=ldbm database,cn=plugins,cn=config"

    # Display message to id current step.
    ${ECHO} "  ${STEP}. Processing eq,pres indexes:"
    STEP=`expr $STEP + 1`

    # For loop to create indexes.
    for i in ${_INDEXES}; do
	[ $DEBUG -eq 1 ] && ${ECHO} "  Adding index for ${i}"

	# Check if entry exists first, if so, skip to next.
	${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=${i},${_EXT}\" -s base \
	    \"objectclass=*\" > /dev/null 2>&1"
	if [ $? -eq 0 ]; then
	    # Display index skipped.
	    ${ECHO} "      ${i} (eq,pres) skipped already exists"	
	    continue
	fi

	# Here doc to create LDIF.
	( cat <<EOF
dn: cn=${i},${_EXT}
objectClass: top
objectClass: nsIndex
cn: ${i}
nsSystemIndex: false
nsIndexType: pres
nsIndexType: eq
EOF
) > ${TMPDIR}/index_${i}

	# Add the index.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/index_${i} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Adding EQ,PRES index for ${i} failed!"
	    cleanup
	    exit 1
	fi

	# Build date for task name.
	_YR=`date '+%y'`
	_MN=`date '+%m'`
	_DY=`date '+%d'`
	_H=`date '+%H'`
	_M=`date '+%M'`
	_S=`date '+%S'`

	# Build task name
	TASKNAME="${i}_${_YR}_${_MN}_${_DY}_${_H}_${_M}_${_S}"

	# Build the task entry to add.
	( cat <<EOF
dn: cn=${TASKNAME}, cn=index, cn=tasks, cn=config
changetype: add
objectclass: top
objectclass: extensibleObject
cn: ${TASKNAME}
nsInstance: ${IDS_DATABASE}
nsIndexAttribute: ${i}
EOF
) > ${TMPDIR}/task_${i}

	# Add the task.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/task_${i} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Adding task for ${i} failed!"
	    cleanup
	    exit 1
	fi

	# Wait for task to finish, display current status.
	while :
	do
	    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} \
	        -b \"cn=${TASKNAME}, cn=index, cn=tasks, cn=config\" -s base \
	        \"objectclass=*\" nstaskstatus > \"${TMPDIR}/istask_${i}\" 2>&1"
	    ${GREP} "${TASKNAME}" "${TMPDIR}/istask_${i}" > /dev/null 2>&1
	    if [ $? -ne 0 ]; then
		break
	    fi
	    TASK_STATUS=`${GREP} -i nstaskstatus "${TMPDIR}/istask_${i}" |
	        head -1 | cut -d: -f2`
	    ${ECHO} "      ${i} (eq,pres)  $TASK_STATUS                  \r\c"
	    ${ECHO} "$TASK_STATUS" | ${GREP} "Finished" > /dev/null 2>&1
	    if [ $? -eq 0 ]; then
		break
	    fi
	    sleep 2
	done

	# Print newline because of \c.
	${ECHO} " "
    done
}


#
# add_sub_indexes(): Add indexes to improve search performance.
#
add_sub_indexes()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_sub_indexes()"

    # Set eq indexes to add.
    _INDEXES="ipHostNumber membernisnetgroup nisnetgrouptriple"

    # Set _EXT to use as shortcut.
    _EXT="cn=index,cn=${IDS_DATABASE},cn=ldbm database,cn=plugins,cn=config"


    # Display message to id current step.
    ${ECHO} "  ${STEP}. Processing eq,pres,sub indexes:"
    STEP=`expr $STEP + 1`

    # For loop to create indexes.
    for i in ${_INDEXES}; do
	[ $DEBUG -eq 1 ] && ${ECHO} "  Adding index for ${i}"

	# Check if entry exists first, if so, skip to next.
	${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=${i},${_EXT}\" \
	    -s base \"objectclass=*\" > /dev/null 2>&1"
	if [ $? -eq 0 ]; then
	    # Display index skipped.
	    ${ECHO} "      ${i} (eq,pres,sub) skipped already exists"	
	    continue
	fi

	# Here doc to create LDIF.
	( cat <<EOF
dn: cn=${i},${_EXT}
objectClass: top
objectClass: nsIndex
cn: ${i}
nsSystemIndex: false
nsIndexType: pres
nsIndexType: eq
nsIndexType: sub
EOF
) > ${TMPDIR}/index_${i}

	# Add the index.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/index_${i} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Adding EQ,PRES,SUB index for ${i} failed!"
	    cleanup
	    exit 1
	fi

	# Build date for task name.
	_YR=`date '+%y'`
	_MN=`date '+%m'`
	_DY=`date '+%d'`
	_H=`date '+%H'`
	_M=`date '+%M'`
	_S=`date '+%S'`

	# Build task name
	TASKNAME="${i}_${_YR}_${_MN}_${_DY}_${_H}_${_M}_${_S}"

	# Build the task entry to add.
	( cat <<EOF
dn: cn=${TASKNAME}, cn=index, cn=tasks, cn=config
changetype: add
objectclass: top
objectclass: extensibleObject
cn: ${TASKNAME}
nsInstance: ${IDS_DATABASE}
nsIndexAttribute: ${i}
EOF
) > ${TMPDIR}/task_${i}

	# Add the task.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/task_${i} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Adding task for ${i} failed!"
	    cleanup
	    exit 1
	fi

	# Wait for task to finish, display current status.
	while :
	do
	    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} \
	        -b \"cn=${TASKNAME}, cn=index, cn=tasks, cn=config\" -s base \
	        \"objectclass=*\" nstaskstatus > \"${TMPDIR}/istask_${i}\" 2>&1"
	    ${GREP} "${TASKNAME}" "${TMPDIR}/istask_${i}" > /dev/null 2>&1
	    if [ $? -ne 0 ]; then
		break
	    fi
	    TASK_STATUS=`${GREP} -i nstaskstatus "${TMPDIR}/istask_${i}" |
	        head -1 | cut -d: -f2`
	    ${ECHO} "      ${i} (eq,pres,sub)  $TASK_STATUS                  \r\c"
	    ${ECHO} "$TASK_STATUS" | ${GREP} "Finished" > /dev/null 2>&1
	    if [ $? -eq 0 ]; then
		break
	    fi
	    sleep 2
	done

	# Print newline because of \c.
	${ECHO} " "
    done
}


#
# add_vlv_indexes(): Add VLV indexes to improve search performance.
#
add_vlv_indexes()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_vlv_indexes()"

    # Set eq indexes to add.
    # Note semi colon separators because some filters contain colons
    _INDEX1="${LDAP_DOMAIN}.getgrent;${LDAP_DOMAIN}_group_vlv_index;ou=group;objectClass=posixGroup"
    _INDEX2="${LDAP_DOMAIN}.gethostent;${LDAP_DOMAIN}_hosts_vlv_index;ou=hosts;objectClass=ipHost"
    _INDEX3="${LDAP_DOMAIN}.getnetent;${LDAP_DOMAIN}_networks_vlv_index;ou=networks;objectClass=ipNetwork"
    _INDEX4="${LDAP_DOMAIN}.getpwent;${LDAP_DOMAIN}_passwd_vlv_index;ou=people;objectClass=posixAccount"
    _INDEX5="${LDAP_DOMAIN}.getrpcent;${LDAP_DOMAIN}_rpc_vlv_index;ou=rpc;objectClass=oncRpc"
    _INDEX6="${LDAP_DOMAIN}.getspent;${LDAP_DOMAIN}_shadow_vlv_index;ou=people;objectClass=shadowAccount"

    # Indexes added during NIS to LDAP transition
    _INDEX7="${LDAP_DOMAIN}.getauhoent;${LDAP_DOMAIN}_auho_vlv_index;automountmapname=auto_home;objectClass=automount"
    _INDEX8="${LDAP_DOMAIN}.getsoluent;${LDAP_DOMAIN}_solu_vlv_index;ou=people;objectClass=SolarisUserAttr"
    _INDEX10="${LDAP_DOMAIN}.getauthent;${LDAP_DOMAIN}_auth_vlv_index;ou=SolarisAuthAttr;objectClass=SolarisAuthAttr"
    _INDEX11="${LDAP_DOMAIN}.getexecent;${LDAP_DOMAIN}_exec_vlv_index;ou=SolarisProfAttr;&(objectClass=SolarisExecAttr)(SolarisKernelSecurityPolicy=*)"
    _INDEX12="${LDAP_DOMAIN}.getprofent;${LDAP_DOMAIN}_prof_vlv_index;ou=SolarisProfAttr;&(objectClass=SolarisProfAttr)(SolarisAttrLongDesc=*)"
    _INDEX13="${LDAP_DOMAIN}.getmailent;${LDAP_DOMAIN}_mail_vlv_index;ou=aliases;objectClass=mailGroup"
    _INDEX14="${LDAP_DOMAIN}.getbootent;${LDAP_DOMAIN}__boot_vlv_index;ou=ethers;&(objectClass=bootableDevice)(bootParameter=*)"
    _INDEX15="${LDAP_DOMAIN}.getethent;${LDAP_DOMAIN}_ethers_vlv_index;ou=ethers;&(objectClass=ieee802Device)(macAddress=*)"
    _INDEX16="${LDAP_DOMAIN}.getngrpent;${LDAP_DOMAIN}_netgroup_vlv_index;ou=netgroup;objectClass=nisNetgroup"
    _INDEX17="${LDAP_DOMAIN}.getipnent;${LDAP_DOMAIN}_ipn_vlv_index;ou=networks;&(objectClass=ipNetwork)(cn=*)"
    _INDEX18="${LDAP_DOMAIN}.getmaskent;${LDAP_DOMAIN}_mask_vlv_index;ou=networks;&(objectClass=ipNetwork)(ipNetmaskNumber=*)"
    _INDEX19="${LDAP_DOMAIN}.getprent;${LDAP_DOMAIN}_pr_vlv_index;ou=printers;objectClass=printerService"
    _INDEX20="${LDAP_DOMAIN}.getip4ent;${LDAP_DOMAIN}_ip4_vlv_index;ou=hosts;&(objectClass=ipHost)(ipHostNumber=*.*)"
    _INDEX21="${LDAP_DOMAIN}.getip6ent;${LDAP_DOMAIN}_ip6_vlv_index;ou=hosts;&(objectClass=ipHost)(ipHostNumber=*:*)"

    _INDEXES="$_INDEX1 $_INDEX2 $_INDEX3 $_INDEX4 $_INDEX5 $_INDEX6 $_INDEX7 $_INDEX8 $_INDEX9 $_INDEX10 $_INDEX11 $_INDEX12 $_INDEX13 $_INDEX14 $_INDEX15 $_INDEX16 $_INDEX17 $_INDEX18 $_INDEX19 $_INDEX20 $_INDEX21 "


    # Set _EXT to use as shortcut.
    _EXT="cn=${IDS_DATABASE},cn=ldbm database,cn=plugins,cn=config"


    # Display message to id current step.
    ${ECHO} "  ${STEP}. Processing VLV indexes:"
    STEP=`expr $STEP + 1`

    # Reset temp file for vlvindex commands.
    [ -f ${TMPDIR}/ds5_vlvindex_list ] &&  rm ${TMPDIR}/ds5_vlvindex_list
    touch ${TMPDIR}/ds5_vlvindex_list
    [ -f ${TMPDIR}/ds6_vlvindex_list ] &&  rm ${TMPDIR}/ds6_vlvindex_list
    touch ${TMPDIR}/ds6_vlvindex_list

    # Get the instance name from iDS server.
    _INSTANCE="<server-instance>"    # Default to old output.

    eval "${LDAPSEARCH} -v ${LDAP_ARGS} -b \"cn=config\" -s base \"objectclass=*\" nsslapd-instancedir | ${GREP} 'nsslapd-instancedir=' | cut -d'=' -f2- > ${TMPDIR}/instance_name 2>&1"

    ${GREP} "slapd-" ${TMPDIR}/instance_name > /dev/null 2>&1 # Check if seems right?
    if [ $? -eq 0 ]; then # If success, grab name after "slapd-".
	_INST_DIR=`cat ${TMPDIR}/instance_name`
	_INSTANCE=`basename "${_INST_DIR}" | cut -d'-' -f2-`
    fi

    # For loop to create indexes.
    for p in ${_INDEXES}; do
	[ $DEBUG -eq 1 ] && ${ECHO} "  Adding index for ${i}"

	# Break p (pair) into i and j parts.
        i=`${ECHO} $p | cut -d';' -f1`
        j=`${ECHO} $p | cut -d';' -f2`
        k=`${ECHO} $p | cut -d';' -f3`
        m=`${ECHO} $p | cut -d';' -f4`

	# Set _jEXT to use as shortcut.
	_jEXT="cn=${j},${_EXT}"

	# Check if entry exists first, if so, skip to next.
	${LDAPSEARCH} ${SERVER_ARGS} -b "cn=${i},${_jEXT}" -s base "objectclass=*" > /dev/null 2>&1
	if [ $? -eq 0 ]; then
	    # Display index skipped.
	    ${ECHO} "      ${i} vlv_index skipped already exists"	
	    continue
	fi

	# Compute the VLV Scope from the LDAP_SEARCH_SCOPE. 
	# NOTE: A value of "base (0)" does not make sense.
        case "$LDAP_SEARCH_SCOPE" in
            sub) VLV_SCOPE="2" ;;
            *)   VLV_SCOPE="1" ;; 
        esac

	# Here doc to create LDIF.
	( cat <<EOF
dn: ${_jEXT}
objectClass: top
objectClass: vlvSearch
cn: ${j}
vlvbase: ${k},${LDAP_BASEDN}
vlvscope: ${VLV_SCOPE}
vlvfilter: (${m})
aci: (target="ldap:///${_jEXT}")(targetattr="*")(version 3.0; acl "Config";allow(read,search,compare)userdn="ldap:///anyone";)

dn: cn=${i},${_jEXT}
cn: ${i}
vlvSort: cn uid
objectclass: top
objectclass: vlvIndex
EOF
) > ${TMPDIR}/vlv_index_${i}

	# Add the index.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/vlv_index_${i} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Adding VLV index for ${i} failed!"
	    cleanup
	    exit 1
	fi

	# Print message that index was created.
	${ECHO} "      ${i} vlv_index   Entry created"

	# Add command to list of vlvindex commands to run.
	${ECHO} "  directoryserver -s ${_INSTANCE} vlvindex -n ${IDS_DATABASE} -T ${i}" >> ${TMPDIR}/ds5_vlvindex_list
	${ECHO} "  <install-path>/bin/dsadm reindex -l -t ${i} <directory-instance-path> ${LDAP_SUFFIX}" >> ${TMPDIR}/ds6_vlvindex_list
    done
}


#
# display_vlv_cmds(): Display VLV index commands to run on server.
#
display_vlv_cmds()
{
    if [ -s "${TMPDIR}/ds5_vlvindex_list" -o \
	 -s "${TMPDIR}/ds6_vlvindex_list" ]; then
	display_msg display_vlv_list
    fi

    if [ -s "${TMPDIR}/ds5_vlvindex_list" ]; then
	cat ${TMPDIR}/ds5_vlvindex_list
    fi

    cat << EOF


EOF

    if [ -s "${TMPDIR}/ds6_vlvindex_list" ]; then
	cat ${TMPDIR}/ds6_vlvindex_list
    fi
}

#
# keep_backward_compatibility(): Modify schema for the backward compatibility if
# there are the incompatible attributes already
#
keep_backward_compatibility()
{
    ${EVAL} "${LDAPSEARCH} ${SERVER_ARGS} -b cn=schema -s base \
        \"objectclass=*\" attributeTypes | ${GREP} -i memberGid-oid ${VERB}"
    if [ $? -eq 0 ]; then
        ${SED} -e 's/1\.3\.6\.1\.4\.1\.42\.2\.27\.5\.1\.30\ /memberGid-oid\ /' \
            ${TMPDIR}/schema_attr > ${TMPDIR}/schema_attr.new
        ${MV} ${TMPDIR}/schema_attr.new ${TMPDIR}/schema_attr
    fi

    ${EVAL} "${LDAPSEARCH} ${SERVER_ARGS} -b cn=schema -s base \
        \"objectclass=*\" attributeTypes | ${GREP} -i rfc822mailMember-oid \
        ${VERB}"
    if [ $? -eq 0 ]; then
        ${SED} -e \
            's/1\.3\.6\.1\.4\.1\.42\.2\.27\.2\.1\.15\ /rfc822mailMember-oid\ /' \
            ${TMPDIR}/schema_attr > ${TMPDIR}/schema_attr.new
        ${MV} ${TMPDIR}/schema_attr.new ${TMPDIR}/schema_attr
    fi
}

#
# update_schema_attr(): Update Schema to support Naming.
#
update_schema_attr()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In update_schema_attr()"

    ( cat <<EOF
dn: cn=schema
changetype: modify
add: attributetypes
attributetypes: ( 1.3.6.1.1.1.1.28 NAME 'nisPublickey' DESC 'NIS public key' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.1.1.1.29 NAME 'nisSecretkey' DESC 'NIS secret key' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.1.1.1.30 NAME 'nisDomain' DESC 'NIS domain' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.1.1.1.31 NAME 'automountMapName' DESC 'automount Map Name' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.1.1.1.32 NAME 'automountKey' DESC 'automount Key Value' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.1.1.1.33 NAME 'automountInformation' DESC 'automount information' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.1.1.12 NAME 'nisNetIdUser' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.1.1.13 NAME 'nisNetIdGroup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.1.1.14 NAME 'nisNetIdHost' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.2.1.15 NAME 'rfc822mailMember' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 2.16.840.1.113730.3.1.30 NAME 'mgrpRFC822MailMember' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.15 NAME 'SolarisLDAPServers' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.16 NAME 'SolarisSearchBaseDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.17 NAME 'SolarisCacheTTL' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.18 NAME 'SolarisBindDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.19 NAME 'SolarisBindPassword' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.20 NAME 'SolarisAuthMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.21 NAME 'SolarisTransportSecurity' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.22 NAME 'SolarisCertificatePath' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.23 NAME 'SolarisCertificatePassword' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.24 NAME 'SolarisDataSearchDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.25 NAME 'SolarisSearchScope' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.26 NAME 'SolarisSearchTimeLimit' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.27 NAME 'SolarisPreferredServer' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.28 NAME 'SolarisPreferredServerOnly' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.29 NAME 'SolarisSearchReferral' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.4 NAME 'SolarisAttrKeyValue' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.5 NAME 'SolarisAuditAlways' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.6 NAME 'SolarisAuditNever' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.7 NAME 'SolarisAttrShortDesc' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.8 NAME 'SolarisAttrLongDesc' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.9 NAME 'SolarisKernelSecurityPolicy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.10 NAME 'SolarisProfileType' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.11 NAME 'SolarisProfileId' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.12 NAME 'SolarisUserQualifier' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.13 NAME 'SolarisAttrReserved1' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.14 NAME 'SolarisAttrReserved2' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.1 NAME 'SolarisProjectID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.2 NAME 'SolarisProjectName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.3 NAME 'SolarisProjectAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.30 NAME 'memberGid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.0 NAME 'defaultServerList' DESC 'Default LDAP server host address used by a DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.1 NAME 'defaultSearchBase' DESC 'Default LDAP base DN used by a DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.2 NAME 'preferredServerList' DESC 'Preferred LDAP server host addresses to be used by a DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.3 NAME 'searchTimeLimit' DESC 'Maximum time in seconds a DUA should allow for a search to complete' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.4 NAME 'bindTimeLimit' DESC 'Maximum time in seconds a DUA should allow for the bind operation to complete' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.5 NAME 'followReferrals' DESC 'Tells DUA if it should follow referrals returned by a DSA search result' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.6 NAME 'authenticationMethod' DESC 'A keystring which identifies the type of authentication method used to contact the DSA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.7 NAME 'profileTTL' DESC 'Time to live before a client DUA should re-read this configuration profile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.14 NAME 'serviceSearchDescriptor' DESC 'LDAP search descriptor list used by Naming-DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.9 NAME 'attributeMap' DESC 'Attribute mappings used by a Naming-DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.10 NAME 'credentialLevel' DESC 'Identifies type of credentials a DUA should use when binding to the LDAP server' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.11 NAME 'objectclassMap' DESC 'Objectclass mappings used by a Naming-DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.12 NAME 'defaultSearchScope' DESC 'Default search scope used by a DUA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.13 NAME 'serviceCredentialLevel' DESC 'Search scope used by a service of the DUA' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetypes: ( 1.3.6.1.4.1.11.1.3.1.1.15 NAME 'serviceAuthenticationMethod' DESC 'Authentication Method used by a service of the DUA' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.18.0.2.4.1140 NAME 'printer-uri' DESC 'A URI supported by this printer.  This URI SHOULD be used as a relative distinguished name (RDN).  If printer-xri-supported is implemented, then this URI value MUST be listed in a member value of printer-xri-supported.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1107 NAME 'printer-xri-supported' DESC 'The unordered list of XRI (extended resource identifiers) supported by this printer.  Each member of the list consists of a URI (uniform resource identifier) followed by optional authentication and security metaparameters.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.18.0.2.4.1135 NAME 'printer-name' DESC 'The site-specific administrative name of this printer, more end-user friendly than a URI.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127}  SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1119 NAME 'printer-natural-language-configured' DESC 'The configured language in which error and status messages will be generated (by default) by this printer.  Also, a possible language for printer string attributes set by operator, system administrator, or manufacturer.  Also, the (declared) language of the "printer-name", "printer-location", "printer-info", and "printer-make-and-model" attributes of this printer. For example: "en-us" (US English) or "fr-fr" (French in France) Legal values of language tags conform to [RFC3066] "Tags for the Identification of Languages".' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127}  SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1136 NAME 'printer-location' DESC 'Identifies the location of the printer. This could include things like: "in Room 123A", "second floor of building XYZ".' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1139 NAME 'printer-info' DESC 'Identifies the descriptive information about this printer.  This could include things like: "This printer can be used for printing color transparencies for HR presentations", or "Out of courtesy for others, please print only small (1-5 page) jobs at this printer", or even "This printer is going away on July 1, 1997, please find a new printer".' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1134 NAME 'printer-more-info' DESC 'A URI used to obtain more information about this specific printer.  For example, this could be an HTTP type URI referencing an HTML page accessible to a Web Browser.  The information obtained from this URI is intended for end user consumption.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1138 NAME 'printer-make-and-model' DESC 'Identifies the make and model of the device.  The device manufacturer MAY initially populate this attribute.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{127}  SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1133 NAME 'printer-ipp-versions-supported' DESC 'Identifies the IPP protocol version(s) that this printer supports, including major and minor versions, i.e., the version numbers for which this Printer implementation meets the conformance requirements.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1132 NAME 'printer-multiple-document-jobs-supported' DESC 'Indicates whether or not the printer supports more than one document per job, i.e., more than one Send-Document or Send-Data operation with document data.' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1109 NAME 'printer-charset-configured' DESC 'The configured charset in which error and status messages will be generated (by default) by this printer.  Also, a possible charset for printer string attributes set by operator, system administrator, or manufacturer.  For example: "utf-8" (ISO 10646/Unicode) or "iso-8859-1" (Latin1).  Legal values are defined by the IANA Registry of Coded Character Sets and the "(preferred MIME name)" SHALL be used as the tag.  For coherence with IPP Model, charset tags in this attribute SHALL be lowercase normalized.  This attribute SHOULD be static (time of registration) and SHOULD NOT be dynamically refreshed attributetypes: (subsequently).' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{63} SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1131 NAME 'printer-charset-supported' DESC 'Identifies the set of charsets supported for attribute type values of type Directory String for this directory entry.  For example: "utf-8" (ISO 10646/Unicode) or "iso-8859-1" (Latin1).  Legal values are defined by the IANA Registry of Coded Character Sets and the preferred MIME name.' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{63} )
attributetypes: ( 1.3.18.0.2.4.1137 NAME 'printer-generated-natural-language-supported' DESC 'Identifies the natural language(s) supported for this directory entry.  For example: "en-us" (US English) or "fr-fr" (French in France).  Legal values conform to [RFC3066], Tags for the Identification of Languages.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{63} )
attributetypes: ( 1.3.18.0.2.4.1130 NAME 'printer-document-format-supported' DESC 'The possible document formats in which data may be interpreted and printed by this printer.  Legal values are MIME types come from the IANA Registry of Internet Media Types.' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1129 NAME 'printer-color-supported' DESC 'Indicates whether this printer is capable of any type of color printing at all, including highlight color.' EQUALITY booleanMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1128 NAME 'printer-compression-supported' DESC 'Compression algorithms supported by this printer.  For example: "deflate, gzip".  Legal values include; "none", "deflate" attributetypes: (public domain ZIP), "gzip" (GNU ZIP), "compress" (UNIX).' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{255} )
attributetypes: ( 1.3.18.0.2.4.1127 NAME 'printer-pages-per-minute' DESC 'The nominal number of pages per minute which may be output by this printer (e.g., a simplex or black-and-white printer).  This attribute is informative, NOT a service guarantee.  Typically, it is the value used in marketing literature to describe this printer.' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1126 NAME 'printer-pages-per-minute-color' DESC 'The nominal number of color pages per minute which may be output by this printer (e.g., a simplex or color printer).  This attribute is informative, NOT a service guarantee.  Typically, it is the value used in marketing literature to describe this printer.' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1125 NAME 'printer-finishings-supported' DESC 'The possible finishing operations supported by this printer. Legal values include; "none", "staple", "punch", "cover", "bind", "saddle-stitch", "edge-stitch", "staple-top-left", "staple-bottom-left", "staple-top-right", "staple-bottom-right", "edge-stitch-left", "edge-stitch-top", "edge-stitch-right", "edge-stitch-bottom", "staple-dual-left", "staple-dual-top", "staple-dual-right", "staple-dual-bottom".' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{255} )
attributetypes: ( 1.3.18.0.2.4.1124 NAME 'printer-number-up-supported' DESC 'The possible numbers of print-stream pages to impose upon a single side of an instance of a selected medium. Legal values include; 1, 2, and 4.  Implementations may support other values.' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 )
attributetypes: ( 1.3.18.0.2.4.1123 NAME 'printer-sides-supported' DESC 'The number of impression sides (one or two) and the two-sided impression rotations supported by this printer.  Legal values include; "one-sided", "two-sided-long-edge", "two-sided-short-edge".' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1122 NAME 'printer-media-supported' DESC 'The standard names/types/sizes (and optional color suffixes) of the media supported by this printer.  For example: "iso-a4",  "envelope", or "na-letter-white".  Legal values  conform to ISO 10175, Document Printing Application (DPA), and any IANA registered extensions.' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{255} )
attributetypes: ( 1.3.18.0.2.4.1117 NAME 'printer-media-local-supported' DESC 'Site-specific names of media supported by this printer, in the language in "printer-natural-language-configured".  For example: "purchasing-form" (site-specific name) as opposed to (in "printer-media-supported"): "na-letter" (standard keyword from ISO 10175).' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{255} )
attributetypes: ( 1.3.18.0.2.4.1121 NAME 'printer-resolution-supported' DESC 'List of resolutions supported for printing documents by this printer.  Each resolution value is a string with 3 fields:  1) Cross feed direction resolution (positive integer), 2) Feed direction resolution (positive integer), 3) Resolution unit.  Legal values are "dpi" (dots per inch) and "dpcm" (dots per centimeter).  Each resolution field is delimited by ">".  For example:  "300> 300> dpi>".' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{255} )
attributetypes: ( 1.3.18.0.2.4.1120 NAME 'printer-print-quality-supported' DESC 'List of print qualities supported for printing documents on this printer.  For example: "draft, normal".  Legal values include; "unknown", "draft", "normal", "high".' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1110 NAME 'printer-job-priority-supported' DESC 'Indicates the number of job priority levels supported.  An IPP conformant printer which supports job priority must always support a full range of priorities from "1" to "100" (to ensure consistent behavior), therefore this attribute describes the "granularity".  Legal values of this attribute are from "1" to "100".' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1118 NAME 'printer-copies-supported' DESC 'The maximum number of copies of a document that may be printed as a single job.  A value of "0" indicates no maximum limit.  A value of "-1" indicates unknown.' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1111 NAME 'printer-job-k-octets-supported' DESC 'The maximum size in kilobytes (1,024 octets actually) incoming print job that this printer will accept.  A value of "0" indicates no maximum limit.  A value of "-1" indicates unknown.' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1112 NAME 'printer-current-operator' DESC 'The name of the current human operator responsible for operating this printer.  It is suggested that this string include information that would enable other humans to reach the operator, such as a phone number.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1113 NAME 'printer-service-person' DESC 'The name of the current human service person responsible for servicing this printer.  It is suggested that this string include information that would enable other humans to reach the service person, such as a phone number.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127}  SINGLE-VALUE )
attributetypes: ( 1.3.18.0.2.4.1114 NAME 'printer-delivery-orientation-supported' DESC 'The possible delivery orientations of pages as they are printed and ejected from this printer.  Legal values include; "unknown", "face-up", and "face-down".' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1115 NAME 'printer-stacking-order-supported' DESC 'The possible stacking order of pages as they are printed and ejected from this printer. Legal values include; "unknown", "first-to-last", "last-to-first".' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1116 NAME 'printer-output-features-supported' DESC 'The possible output features supported by this printer. Legal values include; "unknown", "bursting", "decollating", "page-collating", "offset-stacking".' EQUALITY caseIgnoreMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.18.0.2.4.1108 NAME 'printer-aliases' DESC 'Site-specific administrative names of this printer in addition the printer name specified for printer-name.' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX  1.3.6.1.4.1.1466.115.121.1.15{127} )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.63 NAME 'sun-printer-bsdaddr' DESC 'Sets the server, print queue destination name and whether the client generates protocol extensions. "Solaris" specifies a Solaris print server extension. The value is represented by the following value: server "," destination ", Solaris".' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.64 NAME 'sun-printer-kvp' DESC 'This attribute contains a set of key value pairs which may have meaning to the print subsystem or may be user defined. Each value is represented by the following: key "=" value.' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.57 NAME 'nisplusTimeZone' DESC 'tzone column from NIS+ timezone table' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.67 NAME 'ipTnetTemplateName' DESC 'Trusted Solaris network template template_name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetypes: ( 1.3.6.1.4.1.42.2.27.5.1.68 NAME 'ipTnetNumber' DESC 'Trusted Solaris network template ip_address' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
EOF
) > ${TMPDIR}/schema_attr

    keep_backward_compatibility

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/schema_attr ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of schema attributes failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Schema attributes have been updated."
    STEP=`expr $STEP + 1`
}


#
# update_schema_obj(): Update the schema objectclass definitions.
#
update_schema_obj()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In update_schema_obj()"

    # Add the objectclass definitions.
    ( cat <<EOF
dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.1.1.2.14 NAME 'NisKeyObject' SUP top MUST ( cn $ nisPublickey $ nisSecretkey ) MAY ( uidNumber $ description ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.1.1.2.15 NAME 'nisDomainObject' SUP top MUST nisDomain )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.1.1.2.16 NAME 'automountMap' SUP top MUST automountMapName MAY description )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.1.1.2.17 NAME 'automount' SUP top MUST ( automountKey $ automountInformation ) MAY description )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.7 NAME 'SolarisNamingProfile' SUP top MUST ( cn $ SolarisLDAPservers $ SolarisSearchBaseDN ) MAY ( SolarisBindDN $ SolarisBindPassword $ SolarisAuthMethod $ SolarisTransportSecurity $ SolarisCertificatePath $ SolarisCertificatePassword $ SolarisDataSearchDN $ SolarisSearchScope $ SolarisSearchTimeLimit $ SolarisPreferredServer $ SolarisPreferredServerOnly $ SolarisCacheTTL $ SolarisSearchReferral ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 2.16.840.1.113730.3.2.4 NAME 'mailGroup' SUP top MUST mail MAY ( cn $ mgrpRFC822MailMember ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.1.2.5 NAME 'nisMailAlias' SUP top MUST cn MAY rfc822mailMember )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.1.2.6 NAME 'nisNetId' SUP top MUST cn MAY ( nisNetIdUser $ nisNetIdGroup $ nisNetIdHost ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.2 NAME 'SolarisAuditUser' SUP top AUXILIARY MAY ( SolarisAuditAlways $ SolarisAuditNever ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.3 NAME 'SolarisUserAttr' SUP top AUXILIARY MAY ( SolarisUserQualifier $ SolarisAttrReserved1 $ SolarisAttrReserved2 $ SolarisAttrKeyValue ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.4 NAME 'SolarisAuthAttr' SUP top MUST cn MAY ( SolarisAttrReserved1 $ SolarisAttrReserved2 $ SolarisAttrShortDesc $ SolarisAttrLongDesc $ SolarisAttrKeyValue ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.5 NAME 'SolarisProfAttr' SUP top MUST cn MAY ( SolarisAttrReserved1 $ SolarisAttrReserved2 $ SolarisAttrLongDesc $ SolarisAttrKeyValue ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.6 NAME 'SolarisExecAttr' SUP top AUXILIARY MAY ( SolarisKernelSecurityPolicy $ SolarisProfileType $ SolarisAttrReserved1 $ SolarisAttrReserved2 $ SolarisProfileID $ SolarisAttrKeyValue ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.1 NAME 'SolarisProject' SUP top MUST ( SolarisProjectID $ SolarisProjectName ) MAY ( memberUid $ memberGid $ description $ SolarisProjectAttr ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.11.1.3.1.2.4 NAME 'DUAConfigProfile' SUP top DESC 'Abstraction of a base configuration for a DUA' MUST cn MAY ( defaultServerList $ preferredServerList $ defaultSearchBase $ defaultSearchScope $ searchTimeLimit $ bindTimeLimit $ credentialLevel $ authenticationMethod $ followReferrals $ serviceSearchDescriptor $ serviceCredentialLevel $ serviceAuthenticationMethod $ objectclassMap $ attributeMap $ profileTTL ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.2549 NAME 'slpService' DESC 'DUMMY definition' SUP top MUST objectclass )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.254 NAME 'slpServicePrinter' DESC 'Service Location Protocol (SLP) information.' SUP slpService AUXILIARY )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.258 NAME 'printerAbstract' DESC 'Printer related information.' SUP top ABSTRACT MAY ( printer-name $ printer-natural-language-configured $ printer-location $ printer-info $ printer-more-info $ printer-make-and-model $ printer-multiple-document-jobs-supported $ printer-charset-configured $ printer-charset-supported $ printer-generated-natural-language-supported $ printer-document-format-supported $ printer-color-supported $ printer-compression-supported $ printer-pages-per-minute $ printer-pages-per-minute-color $ printer-finishings-supported $ printer-number-up-supported $ printer-sides-supported $ printer-media-supported $ printer-media-local-supported $ printer-resolution-supported $ printer-print-quality-supported $ printer-job-priority-supported $ printer-copies-supported $ printer-job-k-octets-supported $ printer-current-operator $ printer-service-person $ printer-delivery-orientation-supported $ printer-stacking-order-supported $ printer-output-features-supported ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.255 NAME 'printerService' DESC 'Printer information.' SUP printerAbstract STRUCTURAL MAY ( printer-uri $ printer-xri-supported ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.257 NAME 'printerServiceAuxClass' DESC 'Printer information.' SUP printerAbstract AUXILIARY MAY ( printer-uri $ printer-xri-supported ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.256 NAME 'printerIPP' DESC 'Internet Printing Protocol (IPP) information.' SUP top AUXILIARY MAY ( printer-ipp-versions-supported $ printer-multiple-document-jobs-supported ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.18.0.2.6.253 NAME 'printerLPR' DESC 'LPR information.' SUP top AUXILIARY MUST printer-name MAY printer-aliases )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses: ( 1.3.6.1.4.1.42.2.27.5.2.14 NAME 'sunPrinter' DESC 'Sun printer information' SUP top AUXILIARY MUST printer-name MAY ( sun-printer-bsdaddr $ sun-printer-kvp ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses:	( 1.3.6.1.4.1.42.2.27.5.2.12 NAME 'nisplusTimeZoneData' DESC 'NIS+ timezone table data' SUP top STRUCTURAL MUST cn MAY ( nisplusTimeZone $ description ) )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses:  ( 1.3.6.1.4.1.42.2.27.5.2.8 NAME 'ipTnetTemplate' DESC 'Object class for TSOL network templates' SUP top MUST ipTnetTemplateName MAY SolarisAttrKeyValue )

dn: cn=schema
changetype: modify
add: objectclasses
objectclasses:	( 1.3.6.1.4.1.42.2.27.5.2.9 NAME 'ipTnetHost' DESC 'Associates an IP address or wildcard with a TSOL template_name' SUP top AUXILIARY MUST ipTnetNumber )
EOF
) > ${TMPDIR}/schema_obj

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/schema_obj ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of schema objectclass definitions failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Schema objectclass definitions have been added."
    STEP=`expr $STEP + 1`
}

#
# modify_top_aci(): Modify the ACI for the top entry to disable self modify
#                   of user attributes.
#
modify_top_aci()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In modify_top_aci()"

    # Set ACI Name
    ACI_NAME="LDAP_Naming_Services_deny_write_access"

    # Search for ACI_NAME
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_top_aci 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "Error searching aci for ${LDAP_BASEDN}"
	cat ${TMPDIR}/chk_top_aci
	cleanup
	exit 1
    fi
    ${GREP} "${ACI_NAME}" ${TMPDIR}/chk_top_aci > /dev/null 2>&1
    if [ $? -eq 0 ]; then
	${ECHO} "  ${STEP}. Top level ACI ${ACI_NAME} already exists for ${LDAP_BASEDN}."
	STEP=`expr $STEP + 1`
	return 0
    fi

    # Crate LDIF for top level ACI.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (targetattr = "cn||uid||uidNumber||gidNumber||homeDirectory||shadowLastChange||shadowMin||shadowMax||shadowWarning||shadowInactive||shadowExpire||shadowFlag||memberUid||SolarisAttrKeyValue||SolarisAttrReserved1||SolarisAttrReserved2||SolarisUserQualifier")(version 3.0; acl ${ACI_NAME}; deny (write) userdn = "ldap:///self";)
-
EOF
) > ${TMPDIR}/top_aci

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/top_aci ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Modify of top level ACI failed! (restricts self modify)"
	cleanup
	exit 1
    fi

    # Display message that ACI is updated.
    MSG="ACI for ${LDAP_BASEDN} modified to disable self modify."
    if [ $EXISTING_PROFILE -eq 1 ];then
	${ECHO} "  ACI SET: $MSG"
    else
	${ECHO} "  ${STEP}. $MSG"
	STEP=`expr $STEP + 1`
    fi
}

#
# find_and_delete_ACI(): Find an ACI in file $2 with a matching pattern $1.
# Delete the ACI and print a message using $3 as the ACI name. $3 is needed
# because it could have a different value than that of $1.
find_and_delete_ACI()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In find_and_delete_ACI"

    # if an ACI with pattern $1 exists in file $2, delete it from ${LDAP_BASEDN}
    ${EGREP} $1 $2 | ${SED} -e 's/aci=//' > ${TMPDIR}/grep_find_delete_aci 2>&1
    if [ -s ${TMPDIR}/grep_find_delete_aci ]; then
	aci_to_delete=`${CAT} ${TMPDIR}/grep_find_delete_aci`

	# Create the tmp file to delete the ACI.
	( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
delete: aci
aci: ${aci_to_delete}
EOF
	) > ${TMPDIR}/find_delete_aci

	# Delete the ACI
	${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/find_delete_aci ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Remove of $3 ACI failed!"
	    cleanup
	    exit 1
	fi

	${RM} -f ${TMPDIR}/find_delete_aci
	# Display message that an ACL is deleted.
	MSG="ACI $3 deleted."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  ACI DELETED: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`
	fi
    fi
}

#
# Add an ACI to deny non-admin access to shadow data when
# shadow update is enabled.
#
deny_non_admin_shadow_access()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In deny_non_admin_shadow_access()"

    # Set ACI Names
    ACI_TO_ADD="LDAP_Naming_Services_deny_non_admin_shadow_access"
    ACI_TO_DEL="LDAP_Naming_Services_deny_non_host_shadow_access"

    # Search for ACI_TO_ADD
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_aci_non_admin 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "Error searching aci for ${LDAP_BASEDN}"
	cleanup
	exit 1
    fi

    # If an ACI with ${ACI_TO_ADD} already exists, we are done.
    ${EGREP} ${ACI_TO_ADD} ${TMPDIR}/chk_aci_non_admin 2>&1 > /dev/null
    if [ $? -eq 0 ]; then
	MSG="ACI ${ACI_TO_ADD} already set for ${LDAP_BASEDN}."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  NOT SET: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`	
	fi
	return 0
    fi

    # The deny_non_admin_shadow_access and deny_non_host_shadow_access ACIs
    # should be mutually exclusive, so if the latter exists, delete it.
    find_and_delete_ACI ${ACI_TO_DEL} ${TMPDIR}/chk_aci_non_admin ${ACI_TO_DEL}

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (target="ldap:///${LDAP_BASEDN}")(targetattr = "shadowLastChange||
 shadowMin|| shadowMax||shadowWarning||shadowInactive||shadowExpire||
 shadowFlag||userPassword") (version 3.0; acl ${ACI_TO_ADD};
 deny (write,read,search,compare) userdn != "ldap:///${LDAP_ADMINDN}";)
EOF
) > ${TMPDIR}/non_admin_aci_write
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/non_admin_aci_write ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Adding ACI ${ACI_TO_ADD} failed!"
	${CAT} ${TMPDIR}/non_admin_aci_write
	cleanup
	exit 1
    fi

    ${RM} -f ${TMPDIR}/non_admin_aci_write
    # Display message that the non-admin access to shadow data is denied.
    MSG="Non-Admin access to shadow data denied."
    if [ $EXISTING_PROFILE -eq 1 ]; then
	${ECHO} "  ACI SET: $MSG"
    else
	${ECHO} "  ${STEP}. $MSG"
	STEP=`expr $STEP + 1`
    fi
}

#
# Add an ACI to deny non-host access to shadow data when
# shadow update is enabled and auth Method if gssapi.
#
deny_non_host_shadow_access()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In deny_non_host_shadow_access()"

    # Set ACI Names
    ACI_TO_ADD="LDAP_Naming_Services_deny_non_host_shadow_access"
    ACI_TO_DEL="LDAP_Naming_Services_deny_non_admin_shadow_access"

    # Search for ACI_TO_ADD
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_aci_non_host 2>&1"
    if [ $? -ne 0 ]; then
	${ECHO} "Error searching aci for ${LDAP_BASEDN}"
	cleanup
	exit 1
    fi

    # If an ACI with ${ACI_TO_ADD} already exists, we are done.
    ${EGREP} ${ACI_TO_ADD} ${TMPDIR}/chk_aci_non_host 2>&1 > /dev/null
    if [ $? -eq 0 ]; then
	MSG="ACI ${ACI_TO_ADD} already set for ${LDAP_BASEDN}."
	if [ $EXISTING_PROFILE -eq 1 ]; then
	    ${ECHO} "  NOT SET: $MSG"
	else
	    ${ECHO} "  ${STEP}. $MSG"
	    STEP=`expr $STEP + 1`	
	fi
	return 0
    fi

    # The deny_non_admin_shadow_access and deny_non_host_shadow_access ACIs
    # should be mutually exclusive, so if the former exists, delete it.
    find_and_delete_ACI ${ACI_TO_DEL} ${TMPDIR}/chk_aci_non_host ${ACI_TO_DEL}

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (target="ldap:///${LDAP_BASEDN}")(targetattr = "shadowLastChange||
 shadowMin|| shadowMax||shadowWarning||shadowInactive||shadowExpire||
 shadowFlag||userPassword") (version 3.0; acl ${ACI_TO_ADD};
  deny (write,read,search,compare)
  userdn != "ldap:///cn=*+ipHostNumber=*,ou=Hosts,${LDAP_BASEDN}";)
EOF
) > ${TMPDIR}/non_host_aci_write
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/non_host_aci_write ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Adding ACI ${ACI_TO_ADD} failed!"
	${CAT} ${TMPDIR}/non_host_aci_write
	cleanup
	exit 1
    fi

    ${RM} -f ${TMPDIR}/non_host_aci_write
    # Display message that the non-host access to shadow data is denied.
    MSG="Non-host access to shadow data is denied."
    if [ $EXISTING_PROFILE -eq 1 ]; then
	${ECHO} "  ACI SET: $MSG"
    else
	${ECHO} "  ${STEP}. $MSG"
	STEP=`expr $STEP + 1`
    fi
}

#
# add_vlv_aci(): Add access control information (aci) for VLV.
#
add_vlv_aci()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_vlv_aci()"

    # Add the VLV ACI.
    ( cat <<EOF
dn: oid=2.16.840.1.113730.3.4.9,cn=features,cn=config
changetype: modify
replace: aci
aci: (targetattr != "aci") (version 3.0; acl "VLV Request Control"; allow(read,search,compare) userdn = "ldap:///anyone";)
EOF
) > ${TMPDIR}/vlv_aci

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/vlv_aci ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Add of VLV ACI failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Add of VLV Access Control Information (ACI)."
    STEP=`expr $STEP + 1`
}


#
# set_nisdomain(): Add the NisDomainObject to the Base DN.
#
set_nisdomain()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In set_nisdomain()"

    # Check if nisDomain is already set.
    ${EVAL} "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base \
	\"objectclass=*\"" > ${TMPDIR}/chk_nisdomain 2>&1
    ${EVAL} "${GREP} -i nisDomain ${TMPDIR}/chk_nisdomain ${VERB}"
    if [ $? -eq 0 ]; then
	${ECHO} "  ${STEP}. NisDomainObject for ${LDAP_BASEDN} was already set."
	STEP=`expr $STEP + 1`
	return 0
    fi

    # Add the new top level containers.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
objectclass: nisDomainObject
nisdomain: ${LDAP_DOMAIN}
EOF
) > ${TMPDIR}/nis_domain

    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/nis_domain ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: update of NisDomainObject in ${LDAP_BASEDN} failed."
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. NisDomainObject added to ${LDAP_BASEDN}."
    STEP=`expr $STEP + 1`
}


#
# check_attrName(): Check that the attribute name is valid.
#              $1   Key to check.
#         Returns   0 : valid name	1 : invalid name
#
check_attrName()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In check_attrName()"
    [ $DEBUG -eq 1 ] && ${ECHO} "check_attrName: Input Param = $1"

    ${ECHO} $1 | ${EGREP} '^[0-9]+(\.[0-9]+)*$' > /dev/null 2>&1
    if [ $? -eq 0 ]; then	
	${EVAL} "${LDAPSEARCH} ${SERVER_ARGS} -b cn=schema -s base \"objectclass=*\" \
			attributeTypes | ${EGREP} -i '^attributetypes[ ]*=[ ]*\([ ]*$1 ' ${VERB}"
    else	
	${EVAL} "${LDAPSEARCH} ${SERVER_ARGS} -b cn=schema -s base \"objectclass=*\" \
			attributeTypes | ${EGREP} -i \"'$1'\" ${VERB}"
    fi

    if [ $? -ne 0 ]; then
	return 1 
    else
	return 0	
    fi	
}


#
# get_objectclass():   Determine the objectclass for the given attribute name 
#              $1   Attribute name to check.
#      _ATTR_NAME   Return value, Object Name or NULL if unknown to idsconfig.
#
#      NOTE: An attribute name can be valid but still we might not be able
#            to determine the objectclass from the table.
#            In such cases, the user needs to create the necessary object(s).
#
get_objectclass()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In get_objectclass()"
    [ $DEBUG -eq 1 ] && ${ECHO} "get_objectclass: Input Param = $1"

    # Set return value to NULL string.
    _ATTR_NAME=""

    # Test key for type:
    case `${ECHO} ${1} | tr '[A-Z]' '[a-z]'` in
	ou | organizationalunitname | 2.5.4.11) _ATTR_NAME="organizationalUnit" ;;
	dc | domaincomponent | 0.9.2342.19200300.100.1.25) _ATTR_NAME="domain" ;;
	 o | organizationname | 2.5.4.10) _ATTR_NAME="organization" ;;
	 c | countryname | 2.5.4.6) _ATTR_NAME="country" ;;
	 *)  _ATTR_NAME="" ;;
    esac

    [ $DEBUG -eq 1 ] && ${ECHO} "get_objectclass: _ATTR_NAME = $_ATTR_NAME"
}


#
# add_base_objects(): Add any necessary base objects.
#
add_base_objects()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_base_objects()"

    # Convert to lower case for basename.
    format_string "${LDAP_BASEDN}"
    LOWER_BASEDN="${FMT_STR}"
    format_string "${LDAP_SUFFIX}"
    LOWER_SUFFIX="${FMT_STR}"

    [ $DEBUG -eq 1 ] && ${ECHO} "LOWER_BASEDN: ${LOWER_BASEDN}"
    [ $DEBUG -eq 1 ] && ${ECHO} "LOWER_SUFFIX: ${LOWER_SUFFIX}"

    # Create additional components.
    if [ "${LOWER_BASEDN}" = "${LOWER_SUFFIX}" ]; then
	[ $DEBUG -eq 1 ] && ${ECHO} "Base DN and Suffix equivalent"
    else
	# first, test that the suffix is valid
	dcstmp=`basename "${LOWER_BASEDN}" "${LOWER_SUFFIX}"`
	if [ "$dcstmp" = "${LOWER_BASEDN}" ]; then
	    # should not happen since check_basedn_suffix() succeeded
	    ${ECHO} "Invalid suffix ${LOWER_SUFFIX}"
	    ${ECHO} "for Base DN ${LOWER_BASEDN}"
	    cleanup
	    exit 1
	fi
	# OK, suffix is valid, start working with LDAP_BASEDN
	# field separator is ',' (i.e., space is a valid character)
	dcstmp2="`${ECHO} ${LDAP_BASEDN} |
		sed -e 's/[ ]*,[ ]*/,/g' -e 's/[ ]*=[ ]*/=/g'`"
	dcs=""
	# use dcstmp to count the loop, and dcstmp2 to get the correct
	# string case
	# dcs should be in reverse order, only for these components
	# that need to be added
	while [ -n "${dcstmp}" ]
	do
	    i2=`${ECHO} "$dcstmp2" | cut -f1 -d','`
	    dk=`${ECHO} $i2 | awk -F= '{print $1}'`
	    dc=`${ECHO} $i2 | awk -F= '{print $2}'`
	    dcs="$dk=$dc,$dcs";
	    dcstmp2=`${ECHO} "$dcstmp2" | cut -f2- -d','`
	    dcstmp=`${ECHO} "$dcstmp" | cut -f2- -d','`
	    [ $DEBUG -eq 1 ] && \
		${ECHO} "dcs: ${dcs}\ndcstmp: ${dcstmp}\ndcstmp2: ${dcstmp2}\n"
	done



	lastdc=${LDAP_SUFFIX}
	dc=`${ECHO} "${dcs}" | cut -f1 -d','`
	dcstmp=`${ECHO} "${dcs}" | cut -f2- -d','`
	while [ -n "${dc}" ]; do
	    # Get Key and component from $dc.
	    dk2=`${ECHO} $dc | awk -F= '{print $1}'`
	    dc2=`${ECHO} $dc | awk -F= '{print $2}'`

	    # At this point, ${dk2} is a valid attribute name

	    # Check if entry exists first, if so, skip to next.
	    ${LDAPSEARCH} ${SERVER_ARGS} -b "${dk2}=${dc2},$lastdc" -s base "objectclass=*" > /dev/null 2>&1
	    if [ $? -eq 0 ]; then
	        # Set the $lastdc to new dc.
	        lastdc="${dk2}=${dc2},$lastdc"

		# Process next component.
		dc=`${ECHO} "${dcstmp}" | cut -f1 -d','`
		dcstmp=`${ECHO} "${dcstmp}" | cut -f2- -d','`
		continue

	    fi

	    # Determine the objectclass for the entry.
            get_objectclass $dk2
	    OBJ_Name=${_ATTR_NAME}
	    if [ "${OBJ_Name}" = "" ]; then
	        ${ECHO} "Cannot determine objectclass for $dk2"
	        ${ECHO} "Please create ${dk2}=${dc2},$lastdc entry and rerun idsconfig"
	        exit 1 
	    fi

	    # Add the new container.
	    ( cat <<EOF
dn: ${dk2}=${dc2},$lastdc
${dk2}: $dc2
objectClass: top
objectClass: ${OBJ_Name}
EOF
) > ${TMPDIR}/base_objects


	    # Set the $lastdc to new dc.
	    lastdc="${dk2}=${dc2},$lastdc"

	    # Add the entry.
	    ${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/base_objects ${VERB}"
	    if [ $? -ne 0 ]; then
		${ECHO} "  ERROR: update of base objects ${dc} failed."
		cleanup
		exit 1
	    fi

	    # Display message that schema is updated.
	    ${ECHO} "  ${STEP}. Created DN component ${dc}."
	    STEP=`expr $STEP + 1`

	    # Process next component.
	    dc=`${ECHO} "${dcstmp}" | cut -f1 -d','`
	    dcstmp=`${ECHO} "${dcstmp}" | cut -f2- -d','`
	done
    fi
}


#
# add_new_containers(): Add the top level classes.
#
#    $1 = Base DN
#
add_new_containers()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_new_containers()"

    for ou in people group rpc protocols networks netgroup \
	aliases hosts services ethers profile printers projects \
	SolarisAuthAttr SolarisProfAttr Timezone ipTnet ; do

	# Check if nismaps already exist.
	eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"ou=${ou},${LDAP_BASEDN}\" -s base \"objectclass=*\" ${VERB}"
	if [ $? -eq 0 ]; then
	    continue
	fi

	# Create TMP file to add.
	( cat <<EOF
dn: ou=${ou},${LDAP_BASEDN}
ou: ${ou}
objectClass: top
objectClass: organizationalUnit
EOF
) > ${TMPDIR}/toplevel.${ou}

	# Add the entry.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/toplevel.${ou} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Add of ou=${ou} container failed!"
	    cleanup
	    exit 1
	fi
    done

    # Display message that top level OU containers complete.
    ${ECHO} "  ${STEP}. Top level \"ou\" containers complete."
    STEP=`expr $STEP + 1`
}


#
# add_auto_maps(): Add the automount map entries.
#
# auto_home, auto_direct, auto_master, auto_shared
#
add_auto_maps()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_auto_maps()"

    # Set AUTO_MAPS for maps to create.
    AUTO_MAPS="auto_home auto_direct auto_master auto_shared"

    for automap in $AUTO_MAPS; do
	# Check if automaps already exist.
	eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"automountMapName=${automap},${LDAP_BASEDN}\" -s base \"objectclass=*\" ${VERB}"
	if [ $? -eq 0 ]; then
	    continue
	fi

	# Create the tmp file to add.
	( cat <<EOF
dn: automountMapName=${automap},${LDAP_BASEDN}
automountMapName: ${automap}
objectClass: top
objectClass: automountMap
EOF
) > ${TMPDIR}/automap.${automap}
    
	# Add the entry.
	${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/automap.${automap} ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Add of automap ${automap} failed!"
	    cleanup
	    exit 1
	fi
    done

    # Display message that automount entries are updated.
    ${ECHO} "  ${STEP}. automount maps: $AUTO_MAPS processed."
    STEP=`expr $STEP + 1`
}


#
# add_proxyagent(): Add entry for nameservice to use to access server.
#
add_proxyagent()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_proxyagent()"

    # Check if proxy agent already exists.
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_PROXYAGENT}\" -s base \"objectclass=*\" ${VERB}"
    if [ $? -eq 0 ]; then
	${ECHO} "  ${STEP}. Proxy Agent ${LDAP_PROXYAGENT} already exists."
	STEP=`expr $STEP + 1`	
	return 0
    fi

    # Get cn and sn names from LDAP_PROXYAGENT.
    cn_tmp=`${ECHO} ${LDAP_PROXYAGENT} | cut -f1 -d, | cut -f2 -d=`

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_PROXYAGENT}
cn: ${cn_tmp}
sn: ${cn_tmp}
objectclass: top
objectclass: person
userpassword: ${LDAP_PROXYAGENT_CRED}
EOF
) > ${TMPDIR}/proxyagent
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/proxyagent ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Adding proxyagent failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Proxy Agent ${LDAP_PROXYAGENT} added."
    STEP=`expr $STEP + 1`
}

#
# allow_proxy_read_pw(): Give Proxy Agent read permission for password.
#
allow_proxy_read_pw()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In allow_proxy_read_pw()"

    # Search for ACI_NAME
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_proxyread_aci 2>&1"
    ${GREP} "${PROXY_ACI_NAME}" ${TMPDIR}/chk_proxyread_aci > /dev/null 2>&1
    if [ $? -eq 0 ]; then
	${ECHO} "  ${STEP}. Proxy ACI ${PROXY_ACI_NAME=} already exists for ${LDAP_BASEDN}."
	STEP=`expr $STEP + 1`
	return 0
    fi

    # Create the tmp file to add.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
add: aci
aci: (target="ldap:///${LDAP_BASEDN}")(targetattr="userPassword")
  (version 3.0; acl ${PROXY_ACI_NAME}; allow (compare,read,search)
  userdn = "ldap:///${LDAP_PROXYAGENT}";)
EOF
) > ${TMPDIR}/proxy_read
    
    # Add the entry.
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/proxy_read ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Allow ${LDAP_PROXYAGENT} to read password failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Give ${LDAP_PROXYAGENT} read permission for password."
    STEP=`expr $STEP + 1`
}

#  Delete Proxy Agent read permission for password.
delete_proxy_read_pw()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In delete_proxy_read_pw()"

    # Search for ACI_NAME
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"${LDAP_BASEDN}\" -s base objectclass=* aci > ${TMPDIR}/chk_proxyread_aci 2>&1"
    ${GREP} "${PROXY_ACI_NAME}" ${TMPDIR}/chk_proxyread_aci | \
	${SED} -e 's/aci=//' > ${TMPDIR}/grep_proxyread_aci 2>&1
    if [ $? -ne 0 ]; then
	${ECHO} "Proxy ACI ${PROXY_ACI_NAME} does not exist for ${LDAP_BASEDN}."
	return 0
    fi

    # We need to remove proxy agent's read access to user passwords,
    # but We do not know the value of the ${LDAP_PROXYAGENT} here, so
    # 1. if only one match found, delete it
    # 2. if more than one matches found, ask the user which one to delete
    HOWMANY=`${WC} -l ${TMPDIR}/grep_proxyread_aci | ${NAWK} '{print $1}'`
    if [ $HOWMANY -eq 0 ]; then
	${ECHO} "Proxy ACI ${PROXY_ACI_NAME} does not exist for ${LDAP_BASEDN}."
	return 0
    fi
    if [ $HOWMANY -eq 1 ];then
	proxy_aci=`${CAT} ${TMPDIR}/grep_proxyread_aci`
    else
	    ${CAT} << EOF

Proxy agent is not allowed to read user passwords when shadow
update is enabled. There are more than one proxy agents found.
Please select the currently proxy agent being used, so that
idsconfig can remove its read access to user passwords.

The proxy agents are:

EOF
	    # generate the proxy agent list
    	    ${SED} -e "s/.*ldap:\/\/\/.*ldap:\/\/\///" \
	    ${TMPDIR}/grep_proxyread_aci | ${SED} -e "s/\";)//" > \
	    	${TMPDIR}/proxy_agent_list

	    # print the proxy agent list
	    ${NAWK} '{print NR ": " $0}' ${TMPDIR}/proxy_agent_list

	    # ask the user to pick one
	    _MENU_PROMPT="Select the proxy agent (1-$HOWMANY): "
	    get_menu_choice "${_MENU_PROMPT}" "0" "$HOWMANY"
	    _CH=$MN_CH
	    proxy_aci=`${SED} -n "$_CH p" ${TMPDIR}/grep_proxyread_aci`
    fi

    # Create the tmp file to delete the ACI.
    ( cat <<EOF
dn: ${LDAP_BASEDN}
changetype: modify
delete: aci
aci: ${proxy_aci}
EOF
    ) > ${TMPDIR}/proxy_delete

    # Delete the ACI
    ${EVAL} "${LDAPMODIFY} ${LDAP_ARGS} -f ${TMPDIR}/proxy_delete ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Remove of ${PROXY_ACI_NAME} ACI failed!"
	cat ${TMPDIR}/proxy_delete
	cleanup
	exit 1
    fi

    # Display message that ACI is updated.
    MSG="Removed ${PROXY_ACI_NAME} ACI for proxyagent read permission for password."
    ${ECHO} " "
    ${ECHO} "  ACI REMOVED: $MSG"
    ${ECHO} "  The ACI removed is $proxy_aci"
    ${ECHO} " "
}

#
# add_profile(): Add client profile to server.
#
add_profile()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In add_profile()"

    # If profile name already exists, DELETE it, and add new one.
    eval "${LDAPSEARCH} ${LDAP_ARGS} -b \"cn=${LDAP_PROFILE_NAME},ou=profile,${LDAP_BASEDN}\" -s base \"objectclass=*\" ${VERB}"
    if [ $? -eq 0 ]; then
	# Create Delete file.
	( cat <<EOF
cn=${LDAP_PROFILE_NAME},ou=profile,${LDAP_BASEDN}
EOF
) > ${TMPDIR}/del_profile

	# Check if DEL_OLD_PROFILE is set.  (If not ERROR)
	if [ $DEL_OLD_PROFILE -eq 0 ]; then
	    ${ECHO} "ERROR: Profile name ${LDAP_PROFILE_NAME} exists! Add failed!"
	    exit 1
	fi

	# Delete the OLD profile.
	${EVAL} "${LDAPDELETE} ${LDAP_ARGS} -f ${TMPDIR}/del_profile ${VERB}"
	if [ $? -ne 0 ]; then
	    ${ECHO} "  ERROR: Attempt to DELETE profile failed!"
	    cleanup
	    exit 1
	fi
    fi

    # Build the "ldapclient genprofile" command string to execute.
    GEN_CMD="ldapclient genprofile -a \"profileName=${LDAP_PROFILE_NAME}\""

    # Add required argument defaultSearchBase.
    GEN_CMD="${GEN_CMD} -a \"defaultSearchBase=${LDAP_BASEDN}\""

    # Add optional parameters.
    [ -n "$LDAP_SERVER_LIST" ] && \
	GEN_CMD="${GEN_CMD} -a \"defaultServerList=${LDAP_SERVER_LIST}\""
    [ -n "$LDAP_SEARCH_SCOPE" ] && \
	GEN_CMD="${GEN_CMD} -a \"defaultSearchScope=${LDAP_SEARCH_SCOPE}\""
    [ -n "$LDAP_CRED_LEVEL" ] && \
	GEN_CMD="${GEN_CMD} -a \"credentialLevel=${LDAP_CRED_LEVEL}\""
    [ -n "$LDAP_AUTHMETHOD" ] && \
	GEN_CMD="${GEN_CMD} -a \"authenticationMethod=${LDAP_AUTHMETHOD}\""
    [ -n "$LDAP_FOLLOWREF" ] && \
	GEN_CMD="${GEN_CMD} -a \"followReferrals=${LDAP_FOLLOWREF}\""
    [ -n "$LDAP_SEARCH_TIME_LIMIT" ] && \
	GEN_CMD="${GEN_CMD} -a \"searchTimeLimit=${LDAP_SEARCH_TIME_LIMIT}\""
    [ -n "$LDAP_PROFILE_TTL" ] && \
	GEN_CMD="${GEN_CMD} -a \"profileTTL=${LDAP_PROFILE_TTL}\""
    [ -n "$LDAP_BIND_LIMIT" ] && \
	GEN_CMD="${GEN_CMD} -a \"bindTimeLimit=${LDAP_BIND_LIMIT}\""
    [ -n "$LDAP_PREF_SRVLIST" ] && \
	GEN_CMD="${GEN_CMD} -a \"preferredServerList=${LDAP_PREF_SRVLIST}\""
    [ -n "$LDAP_SRV_AUTHMETHOD_PAM" ] && \
	GEN_CMD="${GEN_CMD} -a \"serviceAuthenticationMethod=${LDAP_SRV_AUTHMETHOD_PAM}\""
    [ -n "$LDAP_SRV_AUTHMETHOD_KEY" ] && \
	GEN_CMD="${GEN_CMD} -a \"serviceAuthenticationMethod=${LDAP_SRV_AUTHMETHOD_KEY}\""
    [ -n "$LDAP_SRV_AUTHMETHOD_CMD" ] && \
	GEN_CMD="${GEN_CMD} -a \"serviceAuthenticationMethod=${LDAP_SRV_AUTHMETHOD_CMD}\""

    # Check if there are any service search descriptors to ad.
    if [ -s "${SSD_FILE}" ]; then
	ssd_2_profile
    fi

    # Execute "ldapclient genprofile" to create profile.
    eval ${GEN_CMD} > ${TMPDIR}/gen_profile 2> ${TMPDIR}/gen_profile_ERR
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: ldapclient genprofile failed!"
	cleanup
	exit 1
    fi

    # Add the generated profile..
    ${EVAL} "${LDAPMODIFY} -a ${LDAP_ARGS} -f ${TMPDIR}/gen_profile ${VERB}"
    if [ $? -ne 0 ]; then
	${ECHO} "  ERROR: Attempt to add profile failed!"
	cleanup
	exit 1
    fi

    # Display message that schema is updated.
    ${ECHO} "  ${STEP}. Generated client profile and loaded on server."
    STEP=`expr $STEP + 1`
}


#
# cleanup(): Remove the TMPDIR and all files in it.
#
cleanup()
{
    [ $DEBUG -eq 1 ] && ${ECHO} "In cleanup()"

    rm -fr ${TMPDIR}
}


#
# 			* * * MAIN * * *
#
# Description:
# This script assumes that the iPlanet Directory Server (iDS) is 
# installed and that setup has been run.  This script takes the 
# iDS server from that point and sets up the infrastructure for
# LDAP Naming Services.  After running this script, ldapaddent(1M)
# or some other tools can be used to populate data.

# Initialize the variables that need to be set to NULL, or some 
# other initial value before the rest of the functions can be called.
init

# Parse command line arguments.  
parse_arg $*
shift $?

# Print extra line to separate from prompt.
${ECHO} " "

# Either Load the user specified config file 
# or prompt user for config info.
if [ -n "$INPUT_FILE" ]
then 
    load_config_file
    INTERACTIVE=0      # Turns off prompts that occur later.
    validate_info      # Validate basic info in file.
    chk_ids_version    # Check iDS version for compatibility.
else
    # Display BACKUP warning to user.
    display_msg backup_server
    get_confirm "Do you wish to continue with server setup (y/n/h)?" "n" "backup_help"
    if [ $? -eq 0 ]; then    # if No, cleanup and exit.
	cleanup ; exit 1
    fi

    # Prompt for values.
    prompt_config_info
    display_summary    # Allow user to modify results.
    INTERACTIVE=1      # Insures future prompting.
fi

# Modify slapd.oc.conf to ALLOW cn instead of REQUIRE.
modify_cn

# Modify timelimit to user value.
[ $NEED_TIME -eq 1 ] && modify_timelimit

# Modify sizelimit to user value.
[ $NEED_SIZE -eq 1 ] && modify_sizelimit

# Modify the password storage scheme to support CRYPT.
if [ "$NEED_CRYPT" = "TRUE" ]; then
    modify_pwd_crypt
fi

# Update the schema (Attributes, Objectclass Definitions)
if [ ${SCHEMA_UPDATED} -eq 0 ]; then
        update_schema_attr
        update_schema_obj
fi

# Add suffix together with its root entry (if needed)
add_suffix ||
{
	cleanup
	exit 1
}

# Add base objects (if needed)
add_base_objects

# Update the NisDomainObject.  
#   The Base DN might of just been created, so this MUST happen after
#   the base objects have been added!
set_nisdomain

# Add top level classes (new containers)
add_new_containers

# Add common nismaps.
add_auto_maps

# Modify top ACI.
modify_top_aci

# Add Access Control Information for VLV.
add_vlv_aci

# if Proxy needed, Add Proxy Agent and give read permission for password.
if [ $NEED_PROXY -eq 1 ]; then
    add_proxyagent
    if [ "$LDAP_ENABLE_SHADOW_UPDATE" != "TRUE" ]; then
	allow_proxy_read_pw
    fi
fi

# If admin needed for shadow update, Add the administrator identity and
# give read/write permission for shadow, and deny all others read/write
# access to it.
if [ $NEED_ADMIN -eq 1 ]; then
    add_admin
    allow_admin_read_write_shadow
    # deny non-admin access to shadow data
    deny_non_admin_shadow_access
fi

if [ $GSSAPI_ENABLE -eq 1 ]; then
    add_id_mapping_rules
    # do not modify ACI if "sasl/GSSAPI" and "self" are not selected
    if [ "$LDAP_CRED_LEVEL" = "self" -a "$LDAP_AUTHMETHOD" = "sasl/GSSAPI" ]; then
        modify_userpassword_acl_for_gssapi
    else
        ${ECHO} "  ACL for GSSAPI was not set because of incompatibility in profile."
    fi
fi

# If use host principal for shadow update, give read/write permission for
# shadow, and deny all others' read/write access to it.
if [ $NEED_HOSTACL -eq 1 ]; then
    allow_host_read_write_shadow
    # deny non-host access to shadow data
    deny_non_host_shadow_access
fi


# Generate client profile and add it to the server.
add_profile

# Add Indexes to improve Search Performance.
add_eq_indexes
add_sub_indexes
add_vlv_indexes

# Display setup complete message
display_msg setup_complete

# Display VLV index commands to be executed on server.
display_vlv_cmds

# Create config file if requested.
[ -n "$OUTPUT_FILE" ] && create_config_file

# Removed the TMPDIR and all files in it.
cleanup

exit 0
# end of MAIN.
