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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# inityp2l -- Utility to generate YP (NIS) to LDAP
#             configuration file (/etc/default/ypserv)
#             and mapping file (/var/yp/NISLDAPmapping)
#



#
# Displays message corresponding to the argument tag passed.
#
display_msg()
{
    case "$1" in
    usage) cat <<EOF

 $PROG:  [ -m mapping_file ] [ -c config_file ]
   m <mapping_file> Name of the generated NISLDAP mapping file
                    Default is /var/yp/NISLDAPmapping
   c <config_file>  Name of the generated ypserv configuration file
                    Default is /etc/default/ypserv

EOF
    ;;
    no_config_file_name_specified) cat <<EOF

You have not specified the config file name. You still have the
option to skip creating this file, specify a config file name, or
continue creating it with the default file name (${CONFIG_FILE}).

EOF
    ;;
    no_mapping_file_name_specified) cat <<EOF

You have not specified the mapping file name. You still have the
option to skip creating this file, specify a mapping file name, or
continue creating it with the default file name (${MAP_FILE}).

EOF
    ;;
    new_config_file_name_help) cat <<EOF

You can either specify a new file name, or accept the default
config file name (${CONFIG_FILE}). 

It is recommended not to use the default file name since this
script just helps with rapid creation of a config file. You
should examine it's content before using it.

EOF
    ;;
    new_mapping_file_name_help) cat <<EOF

You can either specify a new file name, or accept the default
mapping file name (${MAP_FILE}). 

It is recommended not to use the default file name since this
script just helps with rapid creation of a mapping file. You
should examine it's content before using it. And if there are
custom maps, then their entries in the mapping file need to be
customized too.

Also, creation of default mapping file would cause NIS components
to work in NIS to LDAP (N2L), rather than traditional NIS, mode
when next restarted.

EOF
    ;;
    backup_config_file) cat <<EOF

The config file "${CONFIG_FILE}" already exists. It is strongly
recommended that you BACKUP this file before running $PROG.

However, even if you continue, you would be given the option to
back up this file before it gets overwritten.

EOF
    ;;
    backup_mapping_file) cat <<EOF

The mapping file "${MAP_FILE}" already exists. It is strongly
recommended that you BACKUP this file before running $PROG.

However, even if you continue, you would be given the option to
back up this file before it gets overwritten.

EOF
    ;;
    warn_n2l_mode) cat <<EOF

Warning : Creation of default mapping file (`basename $MAP_FILE`)
          at default location (`dirname $MAP_FILE`) would cause NIS
          components to work in NIS to LDAP (N2L) mode, rather than
          traditional NIS mode, when next restarted.

          "$PROG" assists with rapid creation of a simple N2L mapping
          file. The user should examine it's content before using it.
          For custom maps, this file needs to be customized which can
          be done using standard text editors.

EOF
    ;;
    config_auth_method_menu) cat <<EOF
    The following are the supported Authentication Methods -
      1  none
      2  simple
      3  sasl/cram-md5
      4  sasl/digest-md5
EOF
    ;;
    auth_method_menu) cat <<EOF
    The following are the supported Authentication Methods -
      1  simple
      2  sasl/cram-md5
      3  sasl/digest-md5
EOF
    ;;
    tls_method_menu) cat <<EOF
    The following are the supported TLS Methods -
      1  none
      2  ssl
EOF
    ;;
    retrieve_error_action_menu) cat <<EOF
    The following are the supported actions -
      1  use_cached
      2  fail
EOF
    ;;
    store_error_action_menu) cat <<EOF
    The following are the supported actions -
      1  retry
      2  fail
EOF
    ;;
    sorry) cat <<EOF

HELP - No help is available for this topic.

EOF
    ;;
    backup_config_file_cont_help) cat <<EOF

HELP - Since $PROG will overwrite the existing config file, it is
       strongly recommended that you backup this file prior to
       running this utility.

       However, even if you continue, you would be given the option
       to back up this file before it gets overwritten.

EOF
    ;;
    backup_config_file_help) cat <<EOF

HELP - If you choose to backup the existing config file, it would be
       saved with current date and time suffix in yymmdd.HH.MM.SS format.

EOF
    ;;
    backup_mapping_file_cont_help) cat <<EOF

HELP - Since $PROG will overwrite the existing mapping file, it is
       strongly recommended that you backup this file prior to running
       this utility.

       However, even if you continue, you would be given the option to
       back up this file before it gets overwritten.

EOF
    ;;
    backup_mapping_file_help) cat <<EOF

HELP - If you choose to backup the existing mapping file, it would be
       saved with current date and time suffix in yymmdd.HH.MM.SS format.

EOF
    ;;
    warn_n2l_mode_help) cat <<EOF

HELP - It is strongly recommended that the mapping file is created at
       non-default location (other than `dirname $MAP_FILE`). After this,
       it's content should be verified, custom maps should be handled,
       and if NIS components are desired to run in NIS to LDAP (N2L),
       then only it should be copied at the default location.

EOF
    ;;
    nisLDAPconfigDN_help) cat <<EOF

HELP - The DN which stores the configuration information in LDAP.
       There is no default value for this field. Leave empty or
       undefined to get this information from config file (ypserv).

EOF
    ;;
    nisLDAPconfigPreferredServerList_help) cat <<EOF

HELP - List of directory servers to provide the configuration
       information. There is no default. The preferred servers
       must be entered IN THE ORDER you wish to have them contacted.
       The preferred server list is a space separated list of IP
       addresses. Providing port numbers is optional, and when not
       supplied, port 389 is assumed. For an LDAP server running
       on this machine, at port 389, use "127.0.0.1:389".

EOF
    ;;
    auth_help) cat <<EOF

HELP - The authentication method to be used to obtain information
       from LDAP server. The supported methods are provided in menu.

EOF
    ;;
    tls_help) cat <<EOF

HELP - The transport layer security used for connection to the LDAP
       server. In order to successfully use transport layer security,
       the server must also support the chosen values. The supported
       methods are provided in menu. Default is "$DEF_TLS".

EOF
    ;;
    TLSCertificateDBPath_help) cat <<EOF

HELP - The absolute path name of the directory containing the certificate
       database. The default value is "$DEF_TLSCertificateDBPath"

EOF
    ;;
    nisLDAPconfigProxyUser_help) cat <<EOF

HELP - The bind DN of the proxy user used to obtain configuration
       information. There is no default value. If the value ends
       with a comma, the value of the nisLDAPconfigDN attribute
       is appended.

EOF
    ;;
    ProxyPassword_warn) cat <<EOF

Warning : In order to avoid having this password publicly visible
          on the machine, the password should appear only in the
          configuration file, and the file should have an appropriate
          owner, group, and file mode.

          So, once this file is ready, please modify appropriately
          to make sure this file is well protected.

EOF
    ;;
    preferredServerList_help) cat <<EOF

HELP - List of directory servers for mapping data to/from LDAP.
       There is no default. The preferred servers must be entered
       IN THE ORDER you wish to have them contacted. The preferred
       server list is a space separated list of IP addresses.
       Providing port numbers is optional, and when not supplied,
       port 389 is assumed. For an LDAP server running on this
       machine, at port 389, use "127.0.0.1:389".

EOF
    ;;
    nisLDAPproxyUser_help) cat <<EOF

HELP - The bind DN of the proxy user the ypserv to read or write
       from or to LDAP. Assumed to have the appropriate permission
       to read and modify LDAP data. There is no default value. If
       the value ends with a comma, the value of the context for
       the current domain (as defined by a nisLDAPdomainContext
       attribute (NISLDAPmapping(4))) is appended.

EOF
    ;;
    nisLDAPbindTimeout_help) cat <<EOF

HELP - The amount of time in seconds after which an LDAP bind operation
       will timeout. Default is $DEF_nisLDAPbindTimeout seconds.
       Decimal values are allowed.

EOF
    ;;
    nisLDAPsearchTimeout_help) cat <<EOF

HELP - The amount of time in seconds after which an LDAP search operation
       will timeout. Default is $DEF_nisLDAPsearchTimeout seconds.
       Decimal values are allowed.

EOF
    ;;
    nisLDAPmodifyTimeout_help) cat <<EOF

HELP - The amount of time in seconds after which an LDAP modify operation
       will timeout. Default is $DEF_nisLDAPmodifyTimeout seconds.
       Decimal values are allowed.

EOF
    ;;
    nisLDAPaddTimeout_help) cat <<EOF

HELP - The amount of time in seconds after which an LDAP add operation
       will timeout. Default is $DEF_nisLDAPaddTimeout seconds.
       Decimal values are allowed.

EOF
    ;;
    nisLDAPdeleteTimeout_help) cat <<EOF

HELP - The amount of time in seconds after which an LDAP delete operation
       will timeout. Default is $DEF_nisLDAPdeleteTimeout seconds.
       Decimal values are allowed.

EOF
    ;;
    nisLDAPsearchTimeLimit_help) cat <<EOF

HELP - Establish a value for the LDAP_OPT_TIMELIMIT option, which
       suggests a time limit for the search operation on the LDAP
       server. The server may impose its own constraints on possible
       values. See your LDAP server documentation. The default is the
       nisLDAPsearchTimeout ($DEF_nisLDAPsearchTimeout seconds) value.
       Only integer values are allowed.

       Since the nisLDAPsearchTimeout limits the amount of time the
       client ypserv will wait for completion of a search operation,
       setting the nisLDAPsearchTimeLimit larger than the
       nisLDAPsearchTimeout is not recommended.

EOF
    ;;
    nisLDAPsearchSizeLimit_help) cat <<EOF

HELP - Establish a value for the LDAP_OPT_SIZELIMIT option, which
       suggests a size limit, in bytes, for the search results on
       the LDAP server. The server may impose its own constraints
       on possible values. See your LDAP server documentation. The
       default is $DEF_nisLDAPsearchSizeLimit, which means unlimited.
       Only integer values are allowed.

EOF
    ;;
    nisLDAPfollowReferral_help) cat <<EOF

HELP - Determines if the ypserv should follow referrals or not.
       Recognized values are yes and no. Default is $DEF_nisLDAPfollowReferral.

EOF
    ;;
    nisLDAPretrieveErrorAction_help) cat <<EOF

HELP - If an error occurs while trying to retrieve an entry from
       LDAP, one of the following actions can be selected:

       use_cached : Retry the retrieval the number of time specified
                    by nisLDAPretrieveErrorAttempts, with the
                    nisLDAPretrieveErrorTimeout value controlling
                    the wait between each attempt.

                    If all attempts fail then log a warning and
                    return the value currently in the cache to the
                    client.  This is the default value.

       fail       : Proceed as for 'use_cached' but if all attempts
                    fail return a YPERR_YPERR error to the client.

EOF
    ;;
    nisLDAPretrieveErrorAttempts_help) cat <<EOF

HELP - The number of times a failed retrieval should be retried.
       The default is unlimited. Note while retries are made, the
       NIS daemon will be prevented from servicing further requests.
       Hence, values other than 1 should be used with caution.

EOF
    ;;
    nisLDAPretrieveErrorTimeout_help) cat <<EOF

HELP - The timeout (in seconds) between each new attempt to retrieve
       LDAP data. Default is $DEF_nisLDAPretrieveErrorTimeout seconds.

EOF
    ;;
    nisLDAPstoreErrorAction_help) cat <<EOF

HELP - If an error occurs while trying to store data to the LDAP
       repository, one of the following actions can be selected :

       retry : Retry operation nisLDAPstoreErrorAttempts times with
               nisLDAPstoreErrorTimeout seconds between each attempt.
               Note while retries are made the NIS daemon will be
               prevented from servicing further requests. Use with
               caution. This is the default value.

       fail  : Return YPERR_YPERR error to the client.

EOF
    ;;
    nisLDAPstoreErrorAttempts_help) cat <<EOF

HELP - The number of times a failed attempt to store data to the
       LDAP repository should be retried. The default is unlimited.

       The value for nisLDAPstoreErrorAttempts is ignored unless
       nisLDAPstoreErrorAction=retry.

EOF
    ;;
    nisLDAPstoreErrorTimeout_help) cat <<EOF

HELP - The timeout (in seconds) between each new attempt to store
       LDAP data. Default is $DEF_nisLDAPstoreErrorTimeout seconds.

       The value for nisLDAPstoreErrorTimeout is ignored unless
       nisLDAPstoreErrorAction=retry.

EOF
    ;;
    selectDomain4N2L_help) cat <<EOF

HELP - Whether this domain needs to be served by YP to LDAP transition
       solution. The default is no in which case the data in this
       domain would not be taken care for transitioning to LDAP.

EOF
    ;;
    generate_comment_info_for_cust_map_help) cat <<EOF

HELP - If selected, this script will try to add relevant comments
       in the mapping file which might help in customizing the
       mapping information for custom maps.

EOF
    ;;
    generate_mapping_info_for_cust_map_help) cat <<EOF

HELP - If selected, this script will try to generate mapping
       information for this map assuming it is a "simple" map.

       A map is assumed to be "simple" if each entry of this map
       has only one "key value" entry in YP, and if each map entry
       can be represented as a single DIT string in the LDAP server.

       If this map is not a simple map and you do want to store it
       in LDAP, you have two options :

       1 - Answer yes, and this script would generate the mapping
           information for this map assuming it is a simple map.
           And once the execution of the script is over, you can
           customize the mapping information by hand editing the
           mapping file.

       2 - Answer no, and this script would not generate mapping
           info for this map. And once the execution of the script
           is over, you can include the customized mapping
           information by hand editing the mapping file.

EOF
    ;;
    nisLDAPdomainContext_help) cat <<EOF

HELP - This parameter defines the context (default location) in
       the directory tree at which all the name service entries
       for this particular domain would be stored.

EOF
    ;;
    nisLDAPyppasswddDomains_help) cat <<EOF

HELP - Lists the domains for which password changes should be
       made.  If this is not present then the value returned by
       'domainname' will be used.

       NIS password change requests do not specify the domains in
       which any given password should be changed. (In traditional
       NIS this information is effectively hard coded in the NIS
       makefile.)

EOF
    ;;
    custom_map_comment_char_help) cat <<EOF

HELP - If selected, it will allow you to specify a character which
       would represent the start of the special 'comment' field in
       a given NIS map. If this attribute is not present then the
       default comment character '#' is used.

       If a map cannot contain comments then the blank comment
       character ('') should be specified (just hit the return key).

EOF
    ;;
    same_comment_char_help) cat <<EOF

HELP - If selected, for a given map, it will allow you to specify
       a common comment character for all the domains.

       Or else by selecting NO, for the same map, you would be
       given the option to specify different comment character
       for different domains.

EOF
    ;;
    secure_flag_on_help) cat <<EOF

HELP - Secure flag is set on maps which are generated with
       "makedbm -s". When converting data from LDAP to YP,
       it adds YP_SECURE entries.
       
EOF
    ;;
    secure_flag_all_domains_help) cat <<EOF

HELP - If selected, it will allow you to set the secure flag on
       for this map for all the domains.

       Or else by selecting NO, you would be given the option to
       set this flag, for the same map, on per domain basis.

EOF
    ;;
    interdomain_flag_on_help) cat <<EOF

HELP - Interdomain flag is set on a set of maps which are generated
       with "makedbm -b". It signals NIS servers to use the domain
       name resolver for host name and address lookups for hosts
       not found in the maps.

       If selected, it adds YP_INTERDOMAIN entries in these maps
       when converting data from LDAP to YP.
       
EOF
    ;;
    interdomain_flag_all_domains_help) cat <<EOF

HELP - If selected, it will allow you to set the interdomain flag
       on for all the domains.

       Or else by selecting NO, you would be given the option to
       set this flag on per domain basis.

EOF
    ;;
    initialTTLlo_help) cat <<EOF

HELP - The lower limit for the initial TTL (in seconds) for data
       read from disk when the ypserv starts. If initialTTLhi also
       is specified, the actual initialTTL will be randomly selected
       from the interval initialTTLlo to initialTTLhi (inclusive).

       Leaving the field empty yields the default value of $DEF_iTTLlo.

EOF
    ;;
    initialTTLhi_help) cat <<EOF

HELP - The upper limit for the initial TTL (in seconds).
       If left empty, defaults to "$DEF_iTTLhi".

EOF
    ;;
    runningTTL_help) cat <<EOF

HELP - The TTL (in seconds) for data retrieved from LDAP while the
       ypserv is running. If left empty, defaults to "$DEF_runTTL".

EOF
    ;;
    default_ttl_help) cat <<EOF

HELP - The default TTL value for each map is set to :
       ${DEF_iTTLlo}:${DEF_iTTLhi}:${DEF_runTTL}

       Select yes if you want to change the current TTL value.

EOF
    ;;
    non_default_same_ttl_help) cat <<EOF

HELP - Select yes if you want to set a new TTL value, but want
       to keep it same for all the maps.
      
EOF
    ;;
    non_default_different_ttl_help) cat <<EOF

HELP - Select yes if you want to set TTL value for each map, but
       want to keep it same for all the domains.
      
EOF
    ;;
    default_different_ttl_help) cat <<EOF

HELP - Select yes if you want to accept the default TTL
       value for this map.
      
EOF
    ;;
    same_ttl_across_domains_help) cat <<EOF

HELP - Select yes if you want to set TTL value for the map,
       but want to keep it same for all the domains.

EOF
    ;;

    esac
}

#
# Echo the message passed only if DEBUG is set.
# Reduces the line width significantly.
#
d_echo()
{
[ DEBUG -eq 1 ] && echo $@
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
	echo "$1 \c"
    else
	echo "$1 [$2] \c"
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
	[ "$ANS" = "" ] && echo "NULL value not allowed!"
    done
}


#
# get_integer(): Querys and verifies that number entered is integer.
#                Function will repeat prompt user for integer value.
#                $1  Message text.
#                $2  default value.
#                $3  Help argument.
#
get_integer()
{
    ANS=""                  # Set ANS to NULL.
    NUM=""

    get_ans "$1" "$2"

    # Verify that value is integer.
    while not_integer $ANS
    do
	case "$ANS" in
	    [Hh] | help | Help | \?) display_msg ${3:-sorry} ;;
	    * ) echo "Invalid value: \"${ANS}\". \c"
	     ;;
	esac

	# Get a new value.
	get_ans "Enter an integer value:" "$2"
    done
    NUM=$ANS
}


#
# get_number(): Querys and verifies that number entered is numeric.
#               Function will repeat prompt user for numeric value.
#               $1  Message text.
#	        $2  default value.
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
	    * ) echo "Invalid value: \"${ANS}\". \c"
	     ;;
	esac

	# Get a new value.
	get_ans "Enter a numeric value:" "$2"
    done
    NUM=$ANS
}


#
# get_pos_int(): Only allows positive integer.
#
#                   $1 - Prompt message.
#                   $2 - Default value (require).
#                   $3 - Optional help argument.
get_pos_int()
{
    while :
    do
	get_integer "$1" "$2" "$3"

	if [ $ANS -lt 0 ]; then
	    echo "Invalid number: please enter a positive integer."
	else
	    break      # Positive integer
	fi
    done
}


#
# get_pos_num(): Only allows positive number.
#
#                   $1 - Prompt message.
#                   $2 - Default value (require).
#                   $3 - Optional help argument.
get_pos_num()
{
    while :
    do
	get_number "$1" "$2" "$3"

	if [ $ANS -lt 0 ]; then
	    echo "Invalid number: please enter a positive number."
	else
	    break      # Positive number
	fi
    done
}


#
#
# get_passwd(): Reads a password from the user and verify with second.
#		$@  instruction/comment/description/question
#
get_passwd()
{
    [ $DEBUG -eq 1 ] && echo "In get_passwd()"

    # Temporary PASSWD variables
    _PASS1=""
    _PASS2=""

    # Handle signals, so that echo can be turned back on if Ctrl-C.
    trap "/usr/bin/stty echo; exit" 1 2 3 6 15

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
	    [ "$ANS" = "" ] && echo "" && echo "NULL passwd not allowed!"
	done
	_PASS1=$ANS         # Store first try.

	# Get second try.
	echo ""
	get_ans "Re-enter passwd:"
	_PASS2=$ANS

	# Test if passwords are identical.
	if [ "$_PASS1" = "$_PASS2" ]; then
	    break
	fi
	
	# Move cursor down to next line and print ERROR message.
	echo ""
	echo "ERROR: passwords don't match; try again."
    done

    /usr/bin/stty echo      # Turn echo ON

    # Removed signal handler
    trap 1 2 3 6 15

    echo ""
}


#
# get_passwd_nochk(): Reads a password from the user w/o check.
#		$@  instruction/comment/description/question
#
get_passwd_nochk()
{
    [ $DEBUG -eq 1 ] && echo "In get_passwd_nochk()"

    # Handle signals, so that echo can be turned back on if Ctrl-C.
    trap "/usr/bin/stty echo; exit" 1 2 3 6 15

    /usr/bin/stty -echo     # Turn echo OFF

    get_ans "$@"

    /usr/bin/stty echo      # Turn echo ON

    # Removed signal handler
    trap 1 2 3 6 15

    echo ""
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
	if [ -z "$2" ]; then
	    echo "INTERNAL ERROR: get_confirm requires 2 args, 3rd is optional."
	    exit 2
	fi

	# Display prompt.
	echo "$1 [$2] \c"

	# Get the ANSWER.
	read _ANSWER
	if [ "$_ANSWER" = "" ] && [ -n "$2" ] ; then
	    _ANSWER=$2
	fi
	case "$_ANSWER" in
	    [Yy] | yes | Yes | YES) return 1 ;;
	    [Nn] | no  | No  | NO)  return 0 ;;
	    [Hh] | help | Help | \?) display_msg ${3:-sorry};;
	    * ) echo "Please enter y or n."  ;;
	esac
    done
}


#
# get_confirm_nodef(): Get confirmation from the user. (Y/Yes or N/No)
#                      No default value supported. Returns 1 for yes.
#
get_confirm_nodef()
{
    _ANSWER=

    while :
    do
	echo "$@ \c"
	read _ANSWER
	case "$_ANSWER" in
	    [Yy] | yes | Yes | YES) return 1 ;;
	    [Nn] | no  | No  | NO)  return 0 ;;
	    * ) echo "Please enter y or n."  ;;
	esac
    done
}


#
# is_integer(): Tells if a string is numeric integer.
#    0 = Integer
#    1 = NOT Integer
#
is_integer()
{
    # Check for parameter.
    if [ $# -ne 1 ]; then
	return 1
    fi

    # Determine if integer.
    expr "$1" + 1 > /dev/null 2>&1

    if [ $? -ge 2 ]; then
	return 1
    fi

    # Made it here, it's Numeric.
    return 0
}


#
# not_integer(): Reverses the return values of is_integer.  Useful
#                for if and while statements that want to test for
#                non-integer data.
#    0 = NOT Integer
#    1 = Integer
#
not_integer()
{
    is_integer $1
    if [ $? -eq 0 ]; then
       return 1
    else
       return 0
    fi
}


#
# is_numeric(): Tells if a string is numeric.
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
    let _NUM="$1 + 1" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
	return 0
    fi
        
}


#
# not_numeric(): Reverses the return values of is_numeric.  Useful
#                for if and while statements that want to test for
#                non-numeric data.
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
    domtmp="`echo ${_DOM} | tr '.' ' '`"
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
# is_root_user(): Check to see if logged in as super user.
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
    while getopts ":dm:c:" ARG
    do
	case $ARG in
	    d)      DEBUG=1;;

	    m)      MAP_FILE=$OPTARG
	            MAPPING_FILE_SPECIFIED=1;;

	    c)      CONFIG_FILE=$OPTARG
                    CONFIG_FILE_SPECIFIED=1;;

	    \?)	    echo "**ERROR: Invalid option '$OPTARG'"
		    display_msg usage
		    exit 1;;
	esac
    done

    shift `expr $OPTIND - 1`
    if [ $# -gt 0 ]; then
        echo "**ERROR: wrong usage "
        display_msg usage
        exit 1
    fi
}


#
# present() : Checks if the first argument exists in the
#            argument list. Returns 0 if found, else 1.
#
present ()
{
_ELEMENT=$1

shift
ARG_LIST=$@

for item in $ARG_LIST
do
  [ "$_ELEMENT" = "$item" ] && return 0
done

# If reached here, then the clement does not exist
return 1
}


#
# remove() : Returns a new string after removing the first
#            argument in the argument list.
#
remove ()
{
_ELEMENT=$1

shift
ARG_LIST=$@

NEW_LIST=""

for item in $ARG_LIST
do
  [ "$_ELEMENT" != "$item" ] && NEW_LIST="$NEW_LIST $item"
done

echo $NEW_LIST
return 0
}


#
# merge_lists() : Returns a list after merging elements
#                 (uniquely) supplied in the argument list.
#
merge_lists()
{
MERGED_LIST=""

for _VAR in "$@"
do
  if ! present $_VAR $MERGED_LIST; then
    MERGED_LIST="$MERGED_LIST $_VAR"
  fi
done

echo $MERGED_LIST
return 0
}


#
# init(): initializes variables and options
#
init()
{
# General variables.
DEBUG=0             		# Set Debug OFF

MAPPING_FILE_SPECIFIED=0	# No file name passed
CONFIG_FILE_SPECIFIED=0		# No file name passed

# Prevent others from snooping
umask 077	

# Set default config and mapping files.
DEFAULT_MAP_FILE="/var/yp/NISLDAPmapping"
DEFAULT_CONFIG_FILE="/etc/default/ypserv"

MAP_FILE="$DEFAULT_MAP_FILE"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"

# Set and create TMPDIR. Use a safe place to discourage hackers.
TMPDIR="/var/yp/inityp2l"

# Temporary file names to be used to prevent system starting in
# N2L mode in case something goes wrong during file creation.
TMPCONF="ypserv-tmp"
TMPMAP="NISLDAPmapping-tmp"

# Remove if the temp directory has been leftover
[ -d "$TMPDIR" ] && rm -rf $TMPDIR
mkdir $TMPDIR
if [ $? -ne 0 ]; then
  echo ERROR : Failed to create temp directory $TMPDIR
  exit 1
fi

# Initialize the default NIS maps.
DEFAULT_NIS_MAPS="passwd.byname
                  passwd.byuid
                  group.byname
                  group.bygid
                  hosts.byaddr
                  hosts.byname
                  ipnodes.byaddr
                  ipnodes.byname
                  ethers.byaddr
                  ethers.byname
                  networks.byaddr
                  networks.byname
                  rpc.bynumber
                  services.byname
                  services.byservicename
                  printers.conf.byname
                  project.byname
                  project.byprojid
                  protocols.byname
                  protocols.bynumber
                  netgroup
                  netgroup.byuser
                  netgroup.byhost
                  bootparams
                  mail.aliases
                  mail.byaddr
                  publickey.byname
                  netid.byname
                  netmasks.byaddr
                  passwd.adjunct.byname
                  group.adjunct.byname
                  timezone.byname
                  auth_attr
                  exec_attr
                  prof_attr
                  user_attr
                  audit_user
                  auto.master
                  auto.home
                  ypservers"

set -A DEF_NIS_MAP_ARRAY $DEFAULT_NIS_MAPS

# The default TTL maps in database ID format.
DEF_TTL_MAPLIST="audit_user
                 auto.home
                 auto.master
                 auth_attr
                 bootparams
                 ethers
                 exec_attr
                 group
                 group.adjunct.byname
                 keys.host
                 keys.pass
                 keys.nobody
                 hosts
                 multihosts
                 ipnodes
                 multiipnodes
                 netgroup
                 networks
                 passwd
                 passwd.adjunct.byname
                 printers.conf.byname
                 prof_attr
                 project
                 protocols
                 services
                 mail.aliases
                 mail.mapping
                 netid.host
                 netid.pass
                 netmasks.byaddr
                 rpc.bynumber
                 ageing.byname
                 timezone.byname
                 user_attr
                 ypservers"


# Initialize default values for config parameters.

configDN_flag=0
DEF_nisLDAPconfigDN=""
DEF_TLS=none
DEF_TLSCertificateDBPath=/var/yp/
DEF_nisLDAPbindTimeout=15
DEF_nisLDAPsearchTimeout=180
DEF_nisLDAPmodifyTimeout=15
DEF_nisLDAPaddTimeout=15
DEF_nisLDAPdeleteTimeout=15
DEF_nisLDAPsearchTimeLimit=${DEF_nisLDAPsearchTimeout}
DEF_nisLDAPsearchSizeLimit=0
DEF_nisLDAPfollowReferral=no
DEF_nisLDAPretrieveErrorAction=use_cached

# The default is unlimited, but since it prevents the NIS daemon,
# from servicing further requests, set 1 as the suggested value.
SUG_nisLDAPretrieveErrorAttempts=1
DEF_nisLDAPretrieveErrorTimeout=15
DEF_nisLDAPstoreErrorAction=retry

# The default is unlimited, but set 1 as the suggested value.
SUG_nisLDAPstoreErrorAttempts=1
DEF_nisLDAPstoreErrorTimeout=15

# Default TTL values (in seconds) for NIS MAPS for mapping file.
DEF_iTTLlo=1800
DEF_iTTLhi=5400
DEF_runTTL=3600

}


#
# config_auth_menu_handler(): Enter the authentication method
#                             for config server.
#
config_auth_menu_handler()
{
    # Display Auth menu
    display_msg config_auth_method_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer.
        get_ans_req "    Choose one Authentication Method (h=help):"

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _AUTHMETHOD="none"
		break ;;
	    2) _AUTHMETHOD="simple"
		break ;;
	    3) _AUTHMETHOD="sasl/cram-md5"
		break ;;
	    4) _AUTHMETHOD="sasl/digest-md5"
		break ;;
	    h) display_msg auth_help ;;
	    *) echo "Please enter 1-4, or h=help." ;;
	esac
    done
}


#
# auth_menu_handler(): Enter the Authentication method for LDAP server.
#
auth_menu_handler()
{
    # Display Auth menu
    display_msg auth_method_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer.
        get_ans_req "    Choose one Authentication Method (h=help):"

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _AUTHMETHOD="simple"
		break ;;
	    2) _AUTHMETHOD="sasl/cram-md5"
		break ;;
	    3) _AUTHMETHOD="sasl/digest-md5"
		break ;;
	    h) display_msg auth_help ;;
	    *) echo "Please enter 1-3, or h=help." ;;
	esac
    done
}


#
# tls_menu_handler(): Enter the transport layer security
#
tls_menu_handler()
{
    # Display TLS menu
    display_msg tls_method_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer.
	# Default value is "none".

        get_ans "    Choose one Transport Layer Security Method (h=help):" "1"

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _TLSMETHOD="none"
		break ;;
	    2) _TLSMETHOD="ssl"
		break ;;
	    h) display_msg tls_help ;;
	    *) echo "Please enter 1, 2, or h=help." ;;
	esac
    done
}


#
# retrieve_error_action_menu_handler(): Enter the retrieve error action
#
retrieve_error_action_menu_handler()
{
    # Display retrieve error action menu
    display_msg retrieve_error_action_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer. use_cached is default
        get_ans "    Choose one retrieval error action (h=help):" "1"

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _RET_ERR_ACT="use_cached"
		break ;;
	    2) _RET_ERR_ACT="fail"
		break ;;
	    h) display_msg nisLDAPretrieveErrorAction_help ;;
	    *) echo "Please enter 1, 2, or h=help." ;;
	esac
    done
}


#
# store_error_action_menu_handler(): Enter the store error action
#
store_error_action_menu_handler()
{
    # Display store error action menu
    display_msg store_error_action_menu	

    # Get a Valid choice.
    while :
    do
	# Display appropriate prompt and get answer. retry is default
        get_ans "    Choose one store error action (h=help):" "1"

	# Determine choice.
	_MENU_CHOICE=$ANS
	case "$_MENU_CHOICE" in
	    1) _STOR_ERR_ACT="retry"
		break ;;
	    2) _STOR_ERR_ACT="fail"
		break ;;
	    h) display_msg nisLDAPstoreErrorAction_help ;;
	    *) echo "Please enter 1, 2, or h=help." ;;
	esac
    done
}


#
# cleanup(): Remove the TMPDIR and all files in it.
#
cleanup()
{
[ $DEBUG -eq 1 ] && echo "In cleanup()"

# Leave the temp directory if debug is set
[ $DEBUG -eq 0 ] && rm -rf $TMPDIR
}


# Save existing config file if elected
check_back_config_file()
{
if [ -f $CONFIG_FILE ]; then
  display_msg backup_config_file

  get_confirm "Do you wish to continue (y/n/h)?" \
              "n" "backup_config_file_cont_help"

  if [ $? -eq 0 ]; then    # if No, cleanup and exit.
    cleanup ; exit 1
  fi

  get_confirm "Do you wish to backup the config file "${CONFIG_FILE}" (y/n/h)?" \
              "y" "backup_config_file_help"

  if [ $? -eq 1 ]; then    # Save the old config file with timestamp

    # SCCS converts '% H %' (without spaces) in current date during putback.
    # So use some other combination.
    SUFFIX=`date '+%d%h%Y.%H:%M:%S'`

    cp -p $CONFIG_FILE ${CONFIG_FILE}-${SUFFIX}
    echo "  Saved existing $CONFIG_FILE as ${CONFIG_FILE}-${SUFFIX}"
  fi
fi
}


# Save existing mapping file if elected
check_back_mapping_file()
{
if [ -f $MAP_FILE ]; then
  display_msg backup_mapping_file

  get_confirm "Do you wish to continue (y/n/h)?" \
              "n" "backup_mapping_file_cont_help"

  if [ $? -eq 0 ]; then    # if No, cleanup and exit.
    cleanup ; exit 1
  fi

  get_confirm "Do you wish to backup the map file "${MAP_FILE}" (y/n/h)?" \
                   "y" "backup_mapping_file_help"

  if [ $? -eq 1 ]; then    # if Yes, save the old map file with timestamp

    # SCCS converts '% H %' (without spaces) in current date during putback.
    # So use some other combination.
    SUFFIX=`date '+%d%h%Y.%H:%M:%S'`

    cp -p $MAP_FILE ${MAP_FILE}-${SUFFIX}
    echo "  Saved existing $MAP_FILE as ${MAP_FILE}-${SUFFIX}"
  fi

else
  if [ "$MAP_FILE" = "$DEFAULT_MAP_FILE" ]; then
    display_msg warn_n2l_mode

    get_confirm "Do you wish to continue (y/n/h)?" \
                "n" "warn_n2l_mode_help"

    if [ $? -eq 0 ]; then
      cleanup ; exit 1
    fi
  fi
fi
}


put_config_file_copyright_info()
{

# Start with an empty file, so don't append, but overwrite here.
# Just change the name, but keep the same date and version number
# as in the ident string of this script.

grep "ident	\"@(#)$PROG" $ABS_PROG | \
      sed "s/${PROG}/${NEW_NAME}/g" > $CONFIG_FILE

echo "\
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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#\
" >> $MAP_FILE
}


get_nisLDAPconfigDN()
{
while :
do

get_ans "DN for configuration information (h=help):"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg nisLDAPconfigDN_help ;;
                       * ) break ;;
esac
done

nisLDAPconfigDN="${ANS}"

# Store in config file only if a non-default value is specified.
if [ "$ANS" != "${DEF_nisLDAPconfigDN}" ]; then
  echo "nisLDAPconfigDN=${ANS}" >> $CONFIG_FILE
fi

# Ask remaining config server related questions only if this
# DN is set. So, if a value is specified, set a flag.

[ "$ANS" != "" ] && configDN_flag=1
}


get_nisLDAPconfigPreferredServerList()
{
while :
do

get_ans_req "Preferred server list for configuration information (h=help):"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg nisLDAPconfigPreferredServerList_help ;;
                       * ) break ;;
esac
done

nisLDAPconfigPreferredServerList=${ANS}
echo "nisLDAPconfigPreferredServerList=${ANS}" >> $CONFIG_FILE
}


get_nisLDAPconfigAuthenticationMethod()
{
_AUTHMETHOD=""

echo "Select the Authentication Method for configuration server :"
config_auth_menu_handler

nisLDAPconfigAuthenticationMethod=${_AUTHMETHOD}
echo "nisLDAPconfigAuthenticationMethod=${_AUTHMETHOD}" >> $CONFIG_FILE
}


get_nisLDAPconfigTLS()
{
_TLSMETHOD=""

echo "Select the Transport Layer Security (TLS) for configuration server :"
tls_menu_handler

nisLDAPconfigTLS=${_TLSMETHOD}

# Store in config file only if a non-default value is specified.
if [ "${_TLSMETHOD}" != "${DEF_TLS}" ]; then
    echo "nisLDAPconfigTLS=${_TLSMETHOD}" >> $CONFIG_FILE
fi
}


get_nisLDAPconfigTLSCertificateDBPath()
{
while :
do

get_ans "Path with TLS Certificate DB for configuration server (h=help):"\
            "${DEF_TLSCertificateDBPath}"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg TLSCertificateDBPath_help ;;
                       * ) break ;;
esac
done

nisLDAPconfigTLSCertificateDBPath=${ANS}

# Store in config file only if a non-default value is specified.
if [ "$ANS" != "${DEF_TLSCertificateDBPath}" ]; then
  echo "nisLDAPconfigTLSCertificateDBPath=${ANS}" >> $CONFIG_FILE
fi
}


get_nisLDAPconfigProxyUser()
{
while :
do

get_ans_req "Proxy user bind DN to obtain configuration information (h=help):"
# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg nisLDAPconfigProxyUser_help ;;
                       * ) break ;;
esac
done

nisLDAPconfigProxyUser=${ANS}
echo "nisLDAPconfigProxyUser=${ANS}" >> $CONFIG_FILE
}


get_nisLDAPconfigProxyPassword()
{
get_passwd "Proxy user password to obtain configuration information :"
nisLDAPconfigProxyPassword=${ANS}

echo "nisLDAPconfigProxyPassword=${ANS}" >> $CONFIG_FILE

display_msg ProxyPassword_warn
}


get_preferredServerList()
{
while :
do

get_ans_req "Preferred server list for mapping data to/from LDAP (h=help):"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg preferredServerList_help ;;
                       * ) break ;;
esac
done

preferredServerList=${ANS}
echo "preferredServerList=${ANS}" >> $CONFIG_FILE
}


get_authenticationMethod()
{
_AUTHMETHOD=""

echo "Select the Authentication Method for mapping data to/from LDAP :"
auth_menu_handler

authenticationMethod=${_AUTHMETHOD}
echo "authenticationMethod=${_AUTHMETHOD}" >> $CONFIG_FILE
}


get_nisLDAPTLS()
{
_TLSMETHOD=""

echo "Select the Transport Layer Security (TLS) for mapping data to/from LDAP :"
tls_menu_handler

nisLDAPTLS=${_TLSMETHOD}

# Store in config file only if a non-default value is specified.
if [ "${_TLSMETHOD}" != "${DEF_TLS}" ]; then
    echo "nisLDAPTLS=${_TLSMETHOD}" >> $CONFIG_FILE
fi
}


get_nisLDAPTLSCertificateDBPath()
{
while :
do

get_ans "Path with TLS Certificate DB for LDAP data server (h=help):"\
        "${DEF_nisLDAPTLSCertificateDBPath}"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg TLSCertificateDBPath_help ;;
                       * ) break ;;
esac
done

nisLDAPTLSCertificateDBPath=${ANS}

# Store in config file only if a non-default value is specified.
if [ "$ANS" != "${DEF_TLSCertificateDBPath}" ]; then
  echo "nisLDAPTLSCertificateDBPath=${ANS}" >> $CONFIG_FILE
fi
}


get_nisLDAPproxyUser()
{
while :
do

get_ans_req "Proxy user bind DN to read/write data from/to LDAP (h=help):"

# If help continue, otherwise break.
case "$ANS" in
  [Hh] | help | Help | \?) display_msg nisLDAPproxyUser_help ;;
                       * ) break ;;
esac
done

nisLDAPproxyUser=${ANS}
echo "nisLDAPproxyUser=${ANS}" >> $CONFIG_FILE
}


get_nisLDAPproxyPassword()
{
get_passwd "Proxy user password to read/write data from/to LDAP :"
nisLDAPproxyPassword=${ANS}

echo "nisLDAPproxyPassword=${ANS}" >> $CONFIG_FILE

display_msg ProxyPassword_warn
}


get_nisLDAPbindTimeout()
{
get_pos_int "Timeout value (in seconds) for LDAP bind operation (h=help):" \
              "${DEF_nisLDAPbindTimeout}" "nisLDAPbindTimeout_help"

nisLDAPbindTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPbindTimeout} ]; then
  echo "nisLDAPbindTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPsearchTimeout()
{
get_pos_int "Timeout value (in seconds) for LDAP search operation (h=help):" \
            "${DEF_nisLDAPsearchTimeout}" "nisLDAPsearchTimeout_help"

nisLDAPsearchTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPsearchTimeout} ]; then
  echo "nisLDAPsearchTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPmodifyTimeout()
{
get_pos_int "Timeout value (in seconds) for LDAP modify operation (h=help):" \
            "${DEF_nisLDAPmodifyTimeout}" "nisLDAPmodifyTimeout_help"

nisLDAPmodifyTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPmodifyTimeout} ]; then
  echo "nisLDAPmodifyTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPaddTimeout()
{
get_pos_int "Timeout value (in seconds) for LDAP add operation (h=help):" \
            "${DEF_nisLDAPaddTimeout}" "nisLDAPaddTimeout_help"

nisLDAPaddTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPaddTimeout} ]; then
  echo "nisLDAPaddTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPdeleteTimeout()
{
get_pos_int "Timeout value (in seconds) for LDAP delete operation (h=help):" \
            "${DEF_nisLDAPdeleteTimeout}" "nisLDAPdeleteTimeout_help"

nisLDAPdeleteTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPdeleteTimeout} ]; then
  echo "nisLDAPdeleteTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPsearchTimeLimit()
{
get_pos_int "Time limit (in seconds) for search operation on LDAP server (h=help):" \
            "${DEF_nisLDAPsearchTimeLimit}" "nisLDAPsearchTimeLimit_help"

nisLDAPsearchTimeLimit=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPsearchTimeLimit} ]; then
  echo "nisLDAPsearchTimeLimit=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPsearchSizeLimit()
{
get_pos_int "Size limit (in bytes) for search operation on LDAP server (h=help):" \
            "${DEF_nisLDAPsearchSizeLimit}" "nisLDAPsearchSizeLimit_help"

nisLDAPsearchSizeLimit=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPsearchSizeLimit} ]; then
  echo "nisLDAPsearchSizeLimit=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPfollowReferral()
{
get_confirm "Should the ypserv follow LDAP referrals (y/n/h):" \
            "n" "nisLDAPfollowReferral_help"

if [ $? -eq 1 ]; then
  _ANS="yes"
else
  _ANS="no"
fi

# Store in config file only if a non-default value is specified.
if [ "${_ANS}" != "${DEF_nisLDAPfollowReferral}" ]; then
  echo "nisLDAPfollowReferral=${_ANS}" >> $CONFIG_FILE
fi
}


get_nisLDAPretrieveErrorAction()
{
_RET_ERR_ACT=""

echo "Select the action to be taken in case of LDAP retrieval error :"
retrieve_error_action_menu_handler

nisLDAPretrieveErrorAction=${_RET_ERR_ACT}

# Store in config file only if a non-default value is specified.
if [ "${_RET_ERR_ACT}" != "${DEF_nisLDAPretrieveErrorAction}" ]; then
    echo "nisLDAPretrieveErrorAction=${_RET_ERR_ACT}" >> $CONFIG_FILE
fi
}


get_nisLDAPretrieveErrorAttempts()
{

get_pos_int "Number of attempts in case of LDAP retrieval error (h=help):" \
            "$SUG_nisLDAPretrieveErrorAttempts" \
            "nisLDAPretrieveErrorAttempts_help"

nisLDAPretrieveErrorAttempts=${NUM}

echo "nisLDAPretrieveErrorAttempts=${NUM}" >> $CONFIG_FILE
}


get_nisLDAPretrieveErrorTimeout()
{
# if nisLDAPretrieveErrorAttempts=0, then no point in asking
# for timeout vales as it is ignored anyway.

[ $nisLDAPretrieveErrorAttempts -eq 0 ] && return 0

get_pos_int "Timeout (in seconds) between each new attempt to retrieve LDAP data (h=help):"\
            "${DEF_nisLDAPretrieveErrorTimeout}" \
            "nisLDAPretrieveErrorTimeout_help"

nisLDAPretrieveErrorTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPretrieveErrorTimeout} ]; then
  echo "nisLDAPretrieveErrorTimeout=${NUM}" >> $CONFIG_FILE
fi
}


get_nisLDAPstoreErrorAction()
{
_STOR_ERR_ACT=""

echo "Select the action to be taken in case of LDAP store error :"
store_error_action_menu_handler

nisLDAPstoreErrorAction=${_STOR_ERR_ACT}

# Store in config file only if a non-default value is specified.
if [ "${_STOR_ERR_ACT}" != "${DEF_nisLDAPstoreErrorAction}" ]; then
    echo "nisLDAPstoreErrorAction=${_STOR_ERR_ACT}" >> $CONFIG_FILE
fi
}


get_nisLDAPstoreErrorAttempts()
{

# if nisLDAPstoreErrorAction="fail", then no point in asking
# for no. of attempts or timeout vales as they are ignored.

[ "$nisLDAPstoreErrorAction" = "fail" ] && return 0

get_pos_int "Number of attempts in case of LDAP store error (h=help):" \
            "$SUG_nisLDAPstoreErrorAttempts" \
            "nisLDAPstoreErrorAttempts_help"

nisLDAPstoreErrorAttempts=${NUM}

echo "nisLDAPstoreErrorAttempts=${NUM}" >> $CONFIG_FILE
}


get_nisLDAPstoreErrorTimeout()
{

# if nisLDAPstoreErrorAction="fail", then no point in asking
# for no. of attempts or timeout vales as they are ignored.

[ "$nisLDAPstoreErrorAction" = "fail" ] && return 0

# Similarly, if nisLDAPstoreErrorAttempts=0, ignore this question.

[ $nisLDAPstoreErrorAttempts -eq 0 ] && return 0

get_pos_int "Timeout (in seconds) between each new attempt to write LDAP data (h=help):"\
            "${DEF_nisLDAPstoreErrorTimeout}" \
            "nisLDAPstoreErrorTimeout_help"

nisLDAPstoreErrorTimeout=${NUM}

# Store in config file only if a non-default value is specified.
if [ $NUM -ne ${DEF_nisLDAPstoreErrorTimeout} ]; then
  echo "nisLDAPstoreErrorTimeout=${NUM}" >> $CONFIG_FILE
fi
}



create_config_file()
{

# To prevent from leaving a partial config file in case some error or
# signal takes place, store the output being generated in a temporary
# file first, and move it at the final destination only at the end if
# everything goes fine.

_CONFIG_FILE=$CONFIG_FILE
CONFIG_FILE=${TMPDIR}/${TMPCONF}.$$

echo "Generating config file temporarily as \"${CONFIG_FILE}\""

# Truncate the file before we append anything.
# Place copyright information
put_config_file_copyright_info

# Filter out all the YP domains in /var/yp
# The list of domains is stored in list "VARYP_DMN_LIST"

echo "\
#
# Configuration file for ypserv(1M); see ypserv(4) for more information,
# and NISLDAPmapping(4) for configuration of NIS to LDAP mapping.

# Unless otherwise noted, commented lines show default values.
" >> $CONFIG_FILE

echo "\
# Where to look for configuration information in LDAP. Leave empty or
# undefined to use this file, in which case the values of the other 
# 'nisLdapConfig*' attributes are ignored. 
#
#nisLDAPconfigDN=\
" >> $CONFIG_FILE

get_nisLDAPconfigDN

echo "

# Server(s) for configuration information. There is no default;
# use the value on the line below for an LDAP server running on
# this machine, at port 389.
#nisLDAPconfigPreferredServerList=127.0.0.1:389\
" >> $CONFIG_FILE

[ $configDN_flag -eq 1 ] && get_nisLDAPconfigPreferredServerList

echo "

# Authentication method(s) to obtain configuration information.
#\
" >> $CONFIG_FILE

[ $configDN_flag -eq 1 ] && get_nisLDAPconfigAuthenticationMethod

echo "

# Transport layer security for configuration information
#
#nisLDAPconfigTLS=${DEF_TLS}\
" >> $CONFIG_FILE

[ $configDN_flag -eq 1 ] && get_nisLDAPconfigTLS

echo "

# Certificate DB for transport layer security
#
#nisLDAPconfigTLSCertificateDBPath=${DEF_TLSCertificateDBPath}\
" >> $CONFIG_FILE

# ask for Certificate DB only if SSL is set
if [ "${nisLDAPconfigTLS}" = "ssl" ]; then
  [ $configDN_flag -eq 1 ] && get_nisLDAPconfigTLSCertificateDBPath
fi

echo "

# Proxy user(s) to obtain configuration information. The line below
# is an example of the format.
#
#nisLDAPconfigProxyUser=cn=nisAdmin,ou=People,\
" >> $CONFIG_FILE

# Ask proxy user bind DN only if needed.
if [ "${nisLDAPconfigAuthenticationMethod}" != "none" ]; then
  [ $configDN_flag -eq 1 ] && get_nisLDAPconfigProxyUser
fi

echo "

# Password for proxy user. Must be supplied if the authentication method
# requires a password. If a password appears in this file, it should be
# protected appropriately against access by unauthorized users.
#
#nisLDAPconfigProxyPassword=\
" >> $CONFIG_FILE

if [ "${nisLDAPconfigAuthenticationMethod}" != "none" ]; then
  [ $configDN_flag -eq 1 ] && get_nisLDAPconfigProxyPassword
fi

echo "

# Server list for mapping data to/from LDAP. There is no default;
# use the value on the line below for an LDAP server running on
# this machine, at port 389.
#preferredServerList=127.0.0.1:389\
" >> $CONFIG_FILE

get_preferredServerList

echo "

# Authentication method for mapping data to/from LDAP
#\
" >> $CONFIG_FILE

get_authenticationMethod

echo "

# Transport layer security for mapping data to/from LDAP.
#
#nisLDAPTLS=${DEF_TLS}\
" >> $CONFIG_FILE

get_nisLDAPTLS

echo "

# Certificate DB for transport layer security
#
#nisLDAPTLSCertificateDBPath=${DEF_TLSCertificateDBPath}\
" >> $CONFIG_FILE

# ask for Certificate DB only if SSL is set
if [ "${nisLDAPTLS}" = "ssl" ]; then
  get_nisLDAPTLSCertificateDBPath
fi

echo "

# Proxy user for ypserv. Assumed to have appropriate permission to read
# and/or create or modify LDAP data. The line below is an example of the
# format.
#
#nisLDAPproxyUser=cn=nisAdmin,ou=People,\
" >> $CONFIG_FILE

# Ask proxy user bind DN only if needed.
if [ "${authenticationMethod}" != "none" ]; then
  get_nisLDAPproxyUser
fi

echo "

# Password for proxy user. Must be supplied if the authentication method
# requires a password. If a password appears in this file, it should be
# protected appropriately against unauthorized access.
#
#nisLDAPproxyPassword=\
" >> $CONFIG_FILE

if [ "${authenticationMethod}" != "none" ]; then
  get_nisLDAPproxyPassword
fi

echo "

# Timeouts and time/size limits for LDAP operations.
#
#nisLDAPbindTimeout=${DEF_nisLDAPbindTimeout}\
" >> $CONFIG_FILE

get_nisLDAPbindTimeout

echo "
#nisLDAPsearchTimeout=${DEF_nisLDAPsearchTimeout}\
" >> $CONFIG_FILE

get_nisLDAPsearchTimeout

echo "
#nisLDAPmodifyTimeout=${DEF_nisLDAPmodifyTimeout}\
" >> $CONFIG_FILE

get_nisLDAPmodifyTimeout

echo "
#nisLDAPaddTimeout=${DEF_nisLDAPaddTimeout}\
" >> $CONFIG_FILE

get_nisLDAPaddTimeout

echo "
#nisLDAPdeleteTimeout=${DEF_nisLDAPdeleteTimeout}\
" >> $CONFIG_FILE

get_nisLDAPdeleteTimeout

echo "
#nisLDAPsearchTimeLimit=${DEF_nisLDAPsearchTimeLimit}\
" >> $CONFIG_FILE

get_nisLDAPsearchTimeLimit

echo "
#nisLDAPsearchSizeLimit=${DEF_nisLDAPsearchSizeLimit}\
" >> $CONFIG_FILE

get_nisLDAPsearchSizeLimit

echo "

# Should the ypserv follow LDAP referrals ?
#
#nisLDAPfollowReferral=${DEF_nisLDAPfollowReferral}\
" >> $CONFIG_FILE

get_nisLDAPfollowReferral

echo "

# Action, number of attempts, and timeout following an LDAP retrieval error
#
#nisLDAPretrieveErrorAction=${DEF_nisLDAPretrieveErrorAction}\
" >> $CONFIG_FILE

get_nisLDAPretrieveErrorAction

echo "
#nisLDAPretrieveErrorAttempts=\
" >> $CONFIG_FILE

get_nisLDAPretrieveErrorAttempts

echo "
#nisLDAPretrieveErrorTimeout=${DEF_nisLDAPretrieveErrorTimeout}\
" >> $CONFIG_FILE

get_nisLDAPretrieveErrorTimeout

echo "

# Action, number of attempts, and timeout following an LDAP store error
#
#nisLDAPstoreErrorAction=${DEF_nisLDAPstoreErrorAction}\
" >> $CONFIG_FILE

get_nisLDAPstoreErrorAction

echo "
#nisLDAPstoreErrorAttempts=\
" >> $CONFIG_FILE

get_nisLDAPstoreErrorAttempts

echo "
#nisLDAPstoreErrorTimeout=${DEF_nisLDAPstoreErrorTimeout}\
" >> $CONFIG_FILE

get_nisLDAPstoreErrorTimeout


# We are done, so move back the config file from temp. location
# to actual location.
# In case the config file name has a directory component which does
# not exist, then create it now, otherwise 'mv' will return error.

DIR_TO_CREATE=`dirname ${_CONFIG_FILE}`
mkdir -p ${DIR_TO_CREATE}

echo "Moving output from temporary file ($CONFIG_FILE) to actual file ($_CONFIG_FILE)"
mv $CONFIG_FILE $_CONFIG_FILE

# Revert back the config file name in case needed.
CONFIG_FILE=$_CONFIG_FILE
echo "Finished creation of config file ( $_CONFIG_FILE )"

}


put_mapping_file_copyright_info()
{

# Start with an emptty file, so don't append, but overwrite here.
# Just change the name and add the word pragma, but keep the same
# date and version number as in the ident string of this script.

grep "ident	\"@(#)$PROG" $ABS_PROG | \
      sed "s/ ident/pragma ident/g" | \
      sed "s/${PROG}/${NEW_NAME}/g" > $MAP_FILE

echo "\
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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#
#-------------------------------------------------------------------
#\
" >> $MAP_FILE
}


#
# Filter out all the YP domains in /var/yp
# The list of domains is stored in list "VARYP_DMN_LIST"
#
create_all_var_yp_domain_list()
{
VARYP_DMN_LIST=""

for entry in /var/yp/*
do
  DMN=`basename $entry`
  if [ -d "/var/yp/$DMN" ] && [ -f "/var/yp/binding/$DMN/ypservers" ]
  then
    VARYP_DMN_LIST="$VARYP_DMN_LIST $DMN"
  fi
done

# d_echo VARYP_DMN_LIST = "$VARYP_DMN_LIST"
[ $DEBUG -eq 1 ] && echo VARYP_DMN_LIST = "$VARYP_DMN_LIST"
}


#
# Ask user which domains would be served by N2L
# The list of N2L domains is stored in global array 
# "N2L_DMN_LIST" and number of domains in N2L_DMN_CNT
#
create_n2l_domain_list()
{
# First make a list of all the domains in /var/yp
create_all_var_yp_domain_list

# Now identify those to be served by N2L
let count=0

for DMN in $VARYP_DMN_LIST
do
  get_confirm "Do you want to store maps from ${DMN} domain to LDAP (y/n/h):" \
              "n" "selectDomain4N2L_help"

  if [ $? -eq 1 ]; then
    N2L_DMN_LIST[count]=$DMN
    let count="count + 1"
  fi

done
N2L_DMN_CNT=$count

[ $DEBUG -eq 1 ] && echo N2L_DMN_LIST=${N2L_DMN_LIST[*]}
[ $DEBUG -eq 1 ] && echo N2L_DMN_CNT=$N2L_DMN_CNT
}


#
# Make various lists for different types of maps for each N2L domain
# and ask user if mapping information and comments need to be generated
# for custom maps.
#
# This function looks big, but since KSH does not support 2-D arrays, or
# two level of dereferencing, it forced to have so many lists and arrays.
# Lists are better for adding or removing elements, and arrays are better
# for accessing with index and in knowing the no. of elements.
#
create_map_lists()
{
# Initialize them with no maps.
ALL_DMN_ALL_MAPLIST=""
ALL_DMN_DEF_MAPLIST=""
ALL_DMN_CUST_MAPLIST=""
ALL_DMN_AUTO_CUST_MAPLIST=""

# Default to don't generate custom mapping info or comment info.
CUST_MAP_NEEDED=0
CUST_CMT_NEEDED=0

let count=0

while (( $count < $N2L_DMN_CNT ))
do
  DMN=${N2L_DMN_LIST[count]}
  MAPDIR=/var/yp/${DMN}

  # Initialize per domain lists to NULL.
  ALL_MAPLIST=""
  DEF_MAPLIST=""
  CUST_MAPLIST=""
  AUTO_CUST_MAPLIST=""

  for dbmfile in $MAPDIR/*.dir
  do
    MAP=`basename $dbmfile .dir`

    # Ignore N2L maps (those with "LDAP_" prefix and ageing.byname)
    if [[ $MAP != LDAP_* ]] && [[ $MAP != "" ]] && \
       [ -f $MAPDIR/${MAP}.pag ] && [[ $MAP != ageing.byname ]]
    then
      ALL_MAPLIST="$ALL_MAPLIST $MAP"

      if present $MAP $DEFAULT_NIS_MAPS
      then
        DEF_MAPLIST="$DEF_MAPLIST $MAP"

      elif [[ $MAP = auto.* ]]
      then
        AUTO_CUST_MAPLIST="$AUTO_CUST_MAPLIST $MAP"

      else
        # If we reached here, means it is custom map.
        get_confirm "Do you want the mapping information to be generated for \"$MAP\" map of $DMN domain (y/n/h)?" \
                    "n" "generate_mapping_info_for_cust_map_help"

        if [ $? -eq 1 ]
        then
          CUST_MAPLIST="$CUST_MAPLIST $MAP"
        else
          # If a customer map is not desired, then delete it from
          # all maplist too.
          ALL_MAPLIST=$(remove $MAP $ALL_MAPLIST)
        fi

      fi

    fi

  done

  # Make ALL_DMN lists as they are very helpful in checking if a map exists.
  ALL_DMN_ALL_MAPLIST=$(merge_lists $ALL_DMN_ALL_MAPLIST $ALL_MAPLIST)
  ALL_DMN_DEF_MAPLIST=$(merge_lists $ALL_DMN_DEF_MAPLIST $DEF_MAPLIST)
  ALL_DMN_CUST_MAPLIST=$(merge_lists $ALL_DMN_CUST_MAPLIST $CUST_MAPLIST)
  ALL_DMN_AUTO_CUST_MAPLIST=$(merge_lists $ALL_DMN_AUTO_CUST_MAPLIST \
                                          $AUTO_CUST_MAPLIST)

  # Store per domain lists in arrays.
  ALL_MAPS[$count]="$ALL_MAPLIST"
  DEF_MAPS[$count]="$DEF_MAPLIST"
  CUST_MAPS[$count]="$CUST_MAPLIST"
  AUTO_CUST_MAPS[$count]="$AUTO_CUST_MAPLIST"

  [ $DEBUG -eq 1 ] && echo ALL_MAPS[$DMN] = ${ALL_MAPS[$count]}
  [ $DEBUG -eq 1 ] && echo DEF_MAPS[$DMN] = ${DEF_MAPS[$count]}
  [ $DEBUG -eq 1 ] && echo CUST_MAPS[$DMN] = ${CUST_MAPS[$count]}
  [ $DEBUG -eq 1 ] && echo AUTO_CUST_MAPS[$DMN] = ${AUTO_CUST_MAPS[$count]}

  let count="count + 1"
done

[ $DEBUG -eq 1 ] && echo ALL_DMN_ALL_MAPLIST = $ALL_DMN_ALL_MAPLIST
[ $DEBUG -eq 1 ] && echo ALL_DMN_DEF_MAPLIST = $ALL_DMN_DEF_MAPLIST
[ $DEBUG -eq 1 ] && echo ALL_DMN_CUST_MAPLIST = $ALL_DMN_CUST_MAPLIST
[ $DEBUG -eq 1 ] && echo ALL_DMN_AUTO_CUST_MAPLIST = $ALL_DMN_AUTO_CUST_MAPLIST

# Store all domain lists in array too.
set -A ALL_DMN_ALL_MAPS $ALL_DMN_ALL_MAPLIST
set -A ALL_DMN_DEF_MAPS $ALL_DMN_DEF_MAPLIST
set -A ALL_DMN_CUST_MAPS $ALL_DMN_CUST_MAPLIST
set -A ALL_DMN_AUTO_CUST_MAPS $ALL_DMN_AUTO_CUST_MAPLIST

# A positive customer map count implies custom mapping information
# is required. Set this flag.
[ ${#ALL_DMN_CUST_MAPS[*]} -gt 0 ] && CUST_MAP_NEEDED=1

# Give bit of info, and ask if comments need to be placed in mapping file
echo "
  This script can place relevant information regarding custom
  maps at appropriate places in the mapping file which can be
  helpful in customizing this file.
"

get_confirm "Do you want such information to be generated (y/n/h)?" \
            "n" "generate_comment_info_for_cust_map_help"

[ $? -eq 1 ] && CUST_CMT_NEEDED=1

[ $DEBUG -eq 1 ] && echo CUST_MAP_NEEDED = $CUST_MAP_NEEDED
[ $DEBUG -eq 1 ] && echo CUST_CMT_NEEDED = $CUST_CMT_NEEDED

}


#
# Ask user the context for each (N2l) domain
#
get_nisLDAPdomainContext()
{
echo "
# List domains and contexts
" >> $MAP_FILE

for DMN in ${N2L_DMN_LIST[*]}
do
  while :
  do
    # Convert to domain in dc format for default choice
    domain_2_dc $DMN

    get_ans "Enter the naming context for $DMN domain (h=help):"\
            "$_DOM_2_DC"

    # If help continue, otherwise break.
    case "$ANS" in
      [Hh] | help | Help | \?) display_msg nisLDAPdomainContext_help ;;
                           * ) break ;;
    esac
  done
  
  # If a value is specified, set it, and save in mapping file too.
  if [ "$ANS" != "" ]; then
    echo "nisLDAPdomainContext $DMN : ${ANS}" >> $MAP_FILE
  fi

  [ $DEBUG -eq 1 ] && echo "nisLDAPdomainContext $DMN : ${ANS}"
done
}


#
# Ask user the domains for which passwords should be changed
#
get_nisLDAPyppasswddDomains()
{

echo "
# List domains for which passwords should be changed. If this is not
# present then the value returned by 'domainname' will be used.
" >> $MAP_FILE

for DMN in ${N2L_DMN_LIST[*]}
do
  get_confirm "Enable password changes for ${DMN} domain (y/n/h)? " \
              "n" "nisLDAPyppasswddDomains_help"

  if [ $? -eq 1 ]; then
      echo "nisLDAPyppasswddDomains $DMN" >> $MAP_FILE
  fi
done

echo "
#
#-------------------------------------------------------------------
#\
" >> $MAP_FILE
}


#
# Create NIS databaseId mappings (aliases)
#
create_nisLDAPdatabaseIdMapping()
{
echo '
# Associate map names with databaseIds (aliases)

# Standard maps
nisLDAPdatabaseIdMapping	ethers: ethers.byaddr ethers.byname
nisLDAPdatabaseIdMapping	group: group.bygid group.byname
nisLDAPdatabaseIdMapping	hosts:[addr="[0-9]*.[0-9]*.[0-9]*.[0-9]*"] \
				hosts.byaddr hosts.byname
# Special mapping to handle the YP_MULTI cases
nisLDAPdatabaseIdMapping        multihosts: \
				[addr="[0-9]*.[0-9]*.[0-9]*.[0-9]*,*"] \
				hosts.byname
nisLDAPdatabaseIdMapping	networks: networks.byaddr networks.byname
nisLDAPdatabaseIdMapping	project: project.byname project.byprojid
nisLDAPdatabaseIdMapping	protocols: protocols.byname protocols.bynumber
nisLDAPdatabaseIdMapping	services: services.byname services.byservicename

# netid.byname is built up from the hosts and passwd files using different
# mappings. It thus has two associated nisLDAPdatabaseIdMappings.
nisLDAPdatabaseIdMapping	netid.host:[number="0"] netid.byname
nisLDAPdatabaseIdMapping	netid.pass:[number="[1-9]*"] netid.byname

# The next two are special databaseIds. They associate maps with databaseIds 
# but additionally identify which maps contain password and password adjunct
# information for yppasswdd. 
nisLDAPdatabaseIdMapping	passwd: passwd.byname passwd.byuid

# mail.byaddr needs to select entries of the form x@y or x!y
nisLDAPdatabaseIdMapping	mail.mapping:[rf_key="*@*", rf_key="*!*"] \
				mail.byaddr

# publickey.byname
# Each entry in publickey map consists of a network user name which
# may refer to a host or a user. It also contains a default entry for nobody.
# Hence, we need three nisLDAPdatabaseIdmappings to support the three
# different types of keys.
nisLDAPdatabaseIdMapping        keys.host:[rf_key="unix.[a-zA-Z]*@*"] \
				publickey.byname
nisLDAPdatabaseIdMapping        keys.pass:[rf_key="unix.[0-9]*@*"] \
				publickey.byname
nisLDAPdatabaseIdMapping        keys.nobody:[rf_key="nobody"] publickey.byname

# Single standard maps. No point aliasing.
# mail.aliases 
# netmasks.byaddr
# rpc.bynumber
# ypservers

# Other maps
# ipnodes looks identical to hosts but maps to a different context.
nisLDAPdatabaseIdMapping	ipnodes:[addr="*:*"] \
				ipnodes.byaddr ipnodes.byname
# Special mapping to handle the YP_MULTI cases
nisLDAPdatabaseIdMapping        multiipnodes: \
				[addr="*:*,*"] \
				ipnodes.byname

# Other single maps. No point aliasing
# audit_user
# auth_attr
# exec_attr
# prof_attr
# user_attr
# auto.home
# auto.master
# bootparams
# timezone.byname
# printers.conf.byname
# passwd.adjunct.byname
# group.adjunct.byname
' >> $MAP_FILE

[ CUST_CMT_NEEDED -eq 1 ] && \
echo "
# If any custom map needs to be aliased, then it should be listed
# here in the following format :
# nisLDAPdatabaseIdMapping databaseId ":" ["["indexlist"]"] mapname[" "...]
" >> $MAP_FILE

[ CUST_MAP_NEEDED -eq 1 ] && \
echo "\
# Not aliasing non-default/custom maps as they are assumed to be
# simple, single maps.\
" >> $MAP_FILE

for MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]} ${ALL_DMN_CUST_MAPS[*]}
do
  echo "# $MAP" >> $MAP_FILE
done

echo "\
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE
}


#
# Finds the domains in which the given map exists in the supplied list.
# Sets result in PRESENT_COUNT and PRESENT_IN_DOMAINS. These fields are
# set globally, so they can be accessed from any where.
# Input : $1 - map, $2 - list name (just name, not the value)
#
find_domains()
{
_MAP=$1
_ARRAY=$2

let PRESENT_COUNT=0
PRESENT_IN_DOMAINS=""

let count=0

while (( $count < $N2L_DMN_CNT ))
do

  # Quick and dirty way to get around unavailability of 2D array
  case "$_ARRAY" in
          ALL_MAPS ) _LIST=${ALL_MAPS[$count]} ;;
          DEF_MAPS ) _LIST=${DEF_MAPS[$count]}  ;;
         CUST_MAPS ) _LIST=${CUST_MAPS[$count]}  ;;
    AUTO_CUST_MAPS ) _LIST=${AUTO_CUST_MAPS[$count]}  ;;
                 * ) echo "Invalid value: \"${_ARRAY}\". \c"
                  ;;
  esac

  if present $_MAP $_LIST
  then
    let PRESENT_COUNT="$PRESENT_COUNT + 1"
    PRESENT_IN_DOMAINS="$PRESENT_IN_DOMAINS ${N2L_DMN_LIST[count]}"
  fi
  let count="count + 1"
done

[ $DEBUG -eq 1 ] && echo "PRESENT_COUNT = $PRESENT_COUNT"
[ $DEBUG -eq 1 ] && echo "PRESENT_IN_DOMAINS = $PRESENT_IN_DOMAINS"

return 0
}


#
# For a given map, find out which list it belongs to (PRESENT_IN_LIST),
# and in how many domains this map shows up (PRESENT_COUNT), and in
# which ones (PRESENT_IN_DOMAINS). These fields are set globally, so
# they can be accessed from any where.
#
find_map_presence_details()
{
_MAP=$1

let PRESENT_COUNT=0
PRESENT_IN_LIST=""
PRESENT_IN_DOMAINS=""

# If the map does not exist, return right away, else
# find which list it belongs to.
# If a map exists in def or auto or cust lists, then
# it also exists in "all" list.

if ! present $_MAP $ALL_DMN_ALL_MAPLIST
then
  return 1

elif present $_MAP $ALL_DMN_DEF_MAPLIST
then
  PRESENT_IN_LIST="DEF_MAPS"

elif present $_MAP $ALL_DMN_CUST_MAPLIST
then
  PRESENT_IN_LIST="CUST_MAPS"

else
  # If map exists, and not in previous two lists,
  # then it has to be here only.
  PRESENT_IN_LIST="AUTO_CUST_MAPS"
fi

# Now we know which list the map belongs to. So, we need to
# find which are the domains in which this map exists.

find_domains $_MAP $PRESENT_IN_LIST

# Since the above function sets the values of PRESENT_COUNT and 
# PRESENT_IN_DOMAINS fields, we don't need to do anything else.

[ $DEBUG -eq 1 ] && echo "PRESENT_IN_LIST = $PRESENT_IN_LIST"

return 0
}


#
# Check if the comment char is a single character, return 0 on success.
# Input is passed via global variable "COMMENT_CHAR"
#
valid_comment_char()
{
COMMENT_CHAR_LENGTH=`echo "${COMMENT_CHAR}" | wc -c`

# echo adds new line character, so adjust length appropriately
if [ $COMMENT_CHAR_LENGTH -gt 2 ]; then
  echo " Comment character has to be a blank or single character; try again."
  return 1
else
  return 0
fi
}


#
# Read the comment character for a MAP. Append in mapping file if valid.
# Input - $1 : MAP name
#
get_comment_char()
{
_MAP=$1

while :
do
  get_ans "Specify the comment character for $_MAP :"
  COMMENT_CHAR=$ANS

  if valid_comment_char; then
    break
  fi
done

echo "nisLDAPcommentChar $_MAP : '${COMMENT_CHAR}'" >> $MAP_FILE
}


#
# Read a seperate comment character for a MAP for each domain and
# update this information in mapping file.
# Input - $1 : MAP name, $@ : list of domains
#
get_comment_char_per_domain()
{
_MAP=$1
shift
_DOMAIN_LIST="$@"

for _DMN in $_DOMAIN_LIST
do

  while :
  do

    get_ans "Specify the comment character for $_MAP,${_DMN} :"
    COMMENT_CHAR=$ANS

    if valid_comment_char; then
      break
    fi

  done
  echo "nisLDAPcommentChar $_MAP,${_DMN} : '${COMMENT_CHAR}'" >> $MAP_FILE

done
}


#
# This function generates custom comment entries. The output is
# appended in the mapping file.
#
get_custom_nisLDAPcommentChar()
{

# All the auto mounter maps are assumed to have '#' as the default comment
# char. But still list the non-default auto map entries here anyway. This
# will make it very easy in case these entries need to be changed.

for MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]}
do
  echo "nisLDAPcommentChar $MAP : '#'" >> $MAP_FILE
done

if [ CUST_MAP_NEEDED -eq 1 ]; then
  get_confirm "Do you wish to specify the comment character for any custom map (y/n/h)?" \
              "n" "custom_map_comment_char_help"

  if [ $? -eq 1 ]; then
    for MAP in ${ALL_DMN_CUST_MAPS[*]}
    do

      get_confirm "Do you wish to specify comment character for \"$MAP\" (y/n/h)?" \
                  "n" "custom_map_comment_char_help"

      if [ $? -eq 1 ]; then
        find_domains $MAP CUST_MAPS
        if [ $PRESENT_COUNT -gt 1 ]; then
          echo "Map \"$MAP\" is present in these domains : $PRESENT_IN_DOMAINS"

          get_confirm "For \"$MAP\", should the same comment character be set for all the domains (y/n/h)?" \
                      "y" "same_comment_char_help"

          if [ $? -eq 1 ]; then
            get_comment_char $MAP
          else
            get_comment_char_per_domain  $MAP "$PRESENT_IN_DOMAINS"
          fi

        else
          get_comment_char $MAP
        fi

      fi
    done
  fi
fi

}


# List comment character (if any) for maps
create_nisLDAPcommentChar()
{

echo "\
# Specify the character representing the start of comments.
" >> $MAP_FILE

[ CUST_CMT_NEEDED -eq 1 ] && echo "\
# The comment character represents the start of the special 'comment'
# field in a given NIS map. If this attribute is not present then the
# default comment character '#' is used. If a map cannot contain comments
# then the NULL ('') comment character should be specified. The format to
# specify the comment character is :
# nisLDAPcommentChar MAP[,DOMAIN] : 'single_comment_char'
" >> $MAP_FILE

echo "\
nisLDAPcommentChar group : ''
nisLDAPcommentChar passwd : ''
nisLDAPcommentChar ageing.byname : ''
nisLDAPcommentChar audit_user : ''
nisLDAPcommentChar auth_attr : ''
nisLDAPcommentChar exec_attr : ''
nisLDAPcommentChar user_attr : ''
nisLDAPcommentChar bootparams : ''
" >> $MAP_FILE

# Need to handle passwd.adjunct.byname map for multiple domain.
_MAP=passwd.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo "#nisLDAPcommentChar passwd.adjunct.byname: ''" >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo "nisLDAPcommentChar passwd.adjunct.byname: ''" >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPcommentChar passwd.adjunct.byname,${_DMN}: ''" >> $MAP_FILE
    done
  fi
fi
# passwd.adjunct.byname done


# Need to handle group.adjunct.byname map for multiple domain.
_MAP=group.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo "#nisLDAPcommentChar group.adjunct.byname: ''" >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo "nisLDAPcommentChar group.adjunct.byname: ''" >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPcommentChar group.adjunct.byname,${_DMN}: ''" >> $MAP_FILE
    done
  fi
fi
# group.adjunct.byname done

echo "" >> $MAP_FILE

# Ask user for comment char for custom maps
get_custom_nisLDAPcommentChar

echo "
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE
}


#
# Generate secure flag entries
#
create_secure_flag_entries()
{
echo "\
# Specify YP_SECURE flags
" >> $MAP_FILE

[ CUST_CMT_NEEDED -eq 1 ] && echo "\
# If a map is secure, then it needs to be mentioned here
# in the following format :
# nisLDAPmapFlags mapname : s
">> $MAP_FILE

# Need to handle passwd.adjunct.byname map for multiple domain.
_MAP=passwd.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo "#nisLDAPmapFlags passwd.adjunct.byname : s" >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo "nisLDAPmapFlags passwd.adjunct.byname : s" >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPmapFlags passwd.adjunct.byname,${_DMN} : s" >> $MAP_FILE
    done
  fi
fi

# Need to handle group.adjunct.byname map for multiple domain.
_MAP=group.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo "#nisLDAPmapFlags group.adjunct.byname : s" >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo "nisLDAPmapFlags group.adjunct.byname : s" >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPmapFlags group.adjunct.byname,${_DMN} : s" >> $MAP_FILE
    done
  fi
fi

echo "" >> $MAP_FILE

STR="any"    # Just to make the question look better.
while :
do
  get_confirm "Do you wish to set the secure flag for $STR map (y/n/h)?" \
              "n" "secure_flag_on_help"

  if [ $? -eq 0 ]; then
    return 0

  else
    get_ans "Enter the MAP name :"
    MAP=$ANS
    
    if [[ $MAP = "" ]]; then
      echo " Error : BLANK map name not allowed; try again"
      continue
    fi

    # Check if the supplied map name exists, and if yes, then
    # set the PRESENT attributes for further processing

    find_map_presence_details $MAP

    case $PRESENT_COUNT in

      0 ) echo " Error : $MAP not found in any domain; try again"
          ;;

      1 ) # The map exists in only one domain.
          echo "nisLDAPmapFlags $MAP : s" >> $MAP_FILE
          STR="another"    # Just to make the question look better.
          ;;

      * ) # The map exists in multiple domain. Ask if this flag needs
          # to be set for all domains, or some specific ones.

          echo "Map \"$MAP\" is present in these domains : $PRESENT_IN_DOMAINS"
          get_confirm "For this map, do you wish to set this flag for all the domains (y/n/h)?" \
                      "y" "secure_flag_all_domains_help"
  
          if [ $? -eq 1 ]; then
            echo "nisLDAPmapFlags $MAP : s" >> $MAP_FILE
          else

            for _DMN in $PRESENT_IN_DOMAINS
            do

              get_confirm_nodef "Set secure flag for $MAP,${_DMN} (y/n)?"

              if [ $? -eq 1 ]; then
                echo "nisLDAPmapFlags $MAP,${_DMN} : s" >> $MAP_FILE
              fi

            done
          fi
          STR="another"    # Just to make the question look better.
          ;;

    esac

  fi
done
}


#
# Generate interdomain flag entries
#
create_interdomain_flag_entries()
{

INTERDOMAIN_MAP_LIST="ipnodes
                       multiipnodes
                       hosts
                       multihosts
                       services.byservicename"

#
# Simple function to avoid duplication of code
#
print_interdomain_entries()
{
for _MAP in $INTERDOMAIN_MAP_LIST
do
  echo "nisLDAPmapFlags ${_MAP} : b" >> $MAP_FILE
done
}

echo "
# Specify YP_INTERDOMAIN flags
" >> $MAP_FILE

[ CUST_CMT_NEEDED -eq 1 ] && echo "\
# It is used to indicate NIS servers to use the domain name resolver for
# host name and address lookups for hosts not found in the maps.
# If set, it adds YP_INTERDOMAIN entries in these maps when converting 
# data from LDAP to YP. It needs to be set in the following format :
# nisLDAPmapFlags mapname : b
" >> $MAP_FILE
 
# List one set of entries in commented form anyway as it might help
# user understand what it means.

echo "\
# If \$B is set in /var/yp/Makefile, then this flag should be
# set for following maps :\
" >> $MAP_FILE

for _MAP in $INTERDOMAIN_MAP_LIST
do
  echo "# nisLDAPmapFlags ${_MAP} : b" >> $MAP_FILE
done

# Put a blank line for indentation purpose
echo  >> $MAP_FILE

get_confirm "Do you wish to set the \"interdomain\" flag for any domain (y/n/h)?" \
            "n" "interdomain_flag_on_help"

if [ $? -eq 1 ]; then

  if [ $N2L_DMN_CNT -gt 1 ]; then

    get_confirm "Should \"interdomain\" flag be set for all domain (y/n/h)?" \
                "y" "interdomain_flag_all_domains_help"

    if [ $? -eq 1 ]; then
      print_interdomain_entries
    else

      for _DMN in ${N2L_DMN_LIST[*]}
      do
        get_confirm_nodef "Set interdomain flag for ${_DMN} (y/n)?"

        if [ $? -eq 1 ]; then
          for _MAP in $INTERDOMAIN_MAP_LIST
          do
            echo "nisLDAPmapFlags ${_MAP},${_DMN} : b" >> $MAP_FILE
          done
        fi

      done
    fi

  else
    print_interdomain_entries
  fi
fi

echo "
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE

return 0
}


#
# List SECURE and INTERDOMAIN flags
#
create_nisLDAPmapFlags()
{
create_secure_flag_entries
create_interdomain_flag_entries
}


#
# Print one Map TTL entry in mapping file using supplied TTL.
#
print_one_map_ttl_entry()
{
_Map=$1
_iTtlLo=$2
_iTtlHi=$3
_runTtl=$4

echo "\
nisLDAPentryTtl        ${_Map}:${_iTtlLo}:${_iTtlHi}:${_runTtl}\
" >> $MAP_FILE

return 0
}


#
# Print all the maps TTL entries of same TTL
# values using the supplied TTL triplet.
#
print_all_same_ttl_entries()
{
_iTTLlo=$1
_iTTLhi=$2
_runTTL=$3

for _MAP in ${DEF_TTL_MAPLIST} ${ALL_DMN_CUST_MAPS[*]} \
            ${ALL_DMN_AUTO_CUST_MAPS[*]}
do

  if [ "$_MAP" != "passwd.adjunct.byname" ] && \
	[ "$_MAP" != "group.adjunct.byname" ]
  then
    print_one_map_ttl_entry $_MAP $_iTTLlo $_iTTLhi $_runTTL

  else

    # adjunct maps might not exist in all the domains.
    find_domains $_MAP DEF_MAPS

    if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
    then

      # Don't put domain info as the map is present in all of them.
      print_one_map_ttl_entry $_MAP $_iTTLlo $_iTTLhi $_runTTL

    else

      for _DMN_ in $PRESENT_IN_DOMAINS
      do
        _STR="${_MAP},${_DMN_}"
        print_one_map_ttl_entry $_STR $_iTTLlo $_iTTLhi $_runTTL
      done

    fi
  fi
done

return 0
}

#
# Read the initialTTLlo. Set the value in global variable.
#
get_ittl_lo()
{
get_pos_int "Lower limit for initial TTL (in seconds) (h=help):" \
            "$DEF_iTTLlo" "initialTTLlo_help"

iTTLlo=${NUM}
}


#
# Read the initialTTLhi. Set the value in global variable.
#
get_ittl_hi()
{
get_pos_int "Higher limit for initial TTL (in seconds) (h=help):" \
            "$DEF_iTTLhi" "initialTTLhi_help"

iTTLhi=${NUM}
}


#
# Read the initialTTLhi. Set the value in global variable.
#
get_run_ttl()
{
get_pos_int "Runtime TTL (in seconds) (h=help):" \
            "$DEF_runTTL" "runningTTL_help"

runTTL=${NUM}
}


#
# Read one TTL triplet. Set the result in global variables.
#
read_one_ttl_triplet()
{
# Just call the individual functions for each TTL.

  get_ittl_lo
  get_ittl_hi
  get_run_ttl

[ $DEBUG -eq 1 ] && \
  echo "TTL = ${iTTLlo}:${iTTLhi}:${runTTL}"

return 0
}

#
# Takes MAP name (with or without domain name) as argument, asks
# user for TTL values, and appends the entry in the mapping file.
#
process_one_map_ttl_value()
{

_Map_="$1"

get_confirm "Retain the default TTL values [$DEF_iTTLlo:$DEF_iTTLhi:$DEF_runTTL] for \"$_Map_\" (y/n/h) ?" \
            "y" "default_different_ttl_help"

if [ $? -eq 1 ]; then
  print_one_map_ttl_entry $_Map_ $DEF_iTTLlo $DEF_iTTLhi $DEF_runTTL
else

  echo "Reading TTL values for $_Map_ :"
  read_one_ttl_triplet
  print_one_map_ttl_entry $_Map_ $iTTLlo $iTTLhi $runTTL

fi
return 0
}


#
# Read only one TTL triplet for each existing MAP without asking
# different values for each domain and update the mapping file.
#
read_all_maps_ttl_values_no_multiple_domain_issue()
{

# Need to read only one TTL triplet for each existing MAP.

for _MAP in ${DEF_TTL_MAPLIST} ${ALL_DMN_CUST_MAPS[*]} \
            ${ALL_DMN_AUTO_CUST_MAPS[*]}
do

  if [ "$_MAP" != "passwd.adjunct.byname" ] && \
	[ "$_MAP" != "group.adjunct.byname" ] 
  then
    process_one_map_ttl_value $_MAP

  else

    # adjunct maps might not exist in all the domains.
    find_domains $_MAP DEF_MAPS

    if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
    then

      # Don't put domain info as the map is present in all of them.
      process_one_map_ttl_value $_MAP

    else

      for _DMN_ in $PRESENT_IN_DOMAINS
      do
        _STR="${_MAP},${_DMN_}"
        process_one_map_ttl_value $_STR
      done

    fi
  fi
done

return 0
}


#
# Read TTL triplet for each default MAP (in database ID form) while
# taking care of multiple domains issue and update the mapping file.
#
read_default_maps_ttl_values_with_multi_domain_issue()
{

for _MAP_ in ${DEF_TTL_MAPLIST}
do
  if [ "$_MAP_" != "passwd.adjunct.byname" ] && \
	[ "$_MAP_" != "group.adjunct.byname" ]
  then

    for _DMN_ in ${N2L_DMN_LIST[*]}
    do
      _STR_="${_MAP_},${_DMN_}"
      # Now process each combination one at a time.
      process_one_map_ttl_value "$_STR_"
    done

  else
    # List only those domains in which adjunct.byname exists.
    find_domains $_MAP_ DEF_MAPS
    for _DMN_ in $PRESENT_IN_DOMAINS
    do
      _STR_="${_MAP_},${_DMN_}"
      process_one_map_ttl_value "$_STR_"
    done
  fi
done

return 0
}


#
# Read TTL triplet for each existing custom MAP while taking
# care of multiple domains issue and update the mapping file.
#
read_custom_maps_ttl_values_with_multi_domain_issue()
{

for _MAP_ in ${ALL_DMN_CUST_MAPS[*]} ${ALL_DMN_AUTO_CUST_MAPS[*]}
do

  find_map_presence_details $_MAP_

  if [ $PRESENT_COUNT -eq 1 ]; then

    # This map exists in only one domain.
    # So, no need to ask for multiple domains.

    process_one_map_ttl_value $_MAP_

  else

    # Handle multiple domains.

    echo "Map \"${_MAP_}\" is present in these domains : $PRESENT_IN_DOMAINS"

    get_confirm "For this map, do you wish to use the same TTL values for all the domains (y/n/h) ?" \
                "y" "same_ttl_across_domains_help"

    if [ $? -eq 1 ]; then

      # Need to read only one TTL triplet for this MAP.
      process_one_map_ttl_value $_MAP_

    else

      # Need to ask for each domain

      for _DMN_ in $PRESENT_IN_DOMAINS
      do
        _STR="${_MAP_},${_DMN_}"

        # Now process each combination one at a time.
        process_one_map_ttl_value "$_STR"

      done
    fi
  fi
done

return 0
}


#
# List the TTL values for various MAPs
#
create_nisLDAPentryTtl()
{

echo "\
# Associate TTLs with NIS entries derived from LDAP
" >> $MAP_FILE

[ CUST_CMT_NEEDED -eq 1 ] && echo "\
# Each map has three TTL values which are specified in seconds.
# 1. initialTTLlo (default $DEF_iTTLlo sec) The lower limit for the initial
#    TTL (in seconds) for data read from disk when the ypserv starts.
#
# 2. initialTTLhi (default $DEF_iTTLhi sec) The upper limit for initial TTL.
#
# 3. runningTTL   (default $DEF_runTTL sec) The TTL (in seconds) for data 
#    retrieved from LDAP while the ypserv is running.
#
# If any value is not specified, then default value is used.
# The format of TTL entry is :
# nisLDAPentryTtl   MAP[,DOMAIN]:initialTTLlo:initialTTLhi:runningTTL
" >> $MAP_FILE

# If no maps are present, just return.
[ ${#ALL_DMN_ALL_MAPS[*]} -eq 0 ] && return 0

echo "The default TTL for each map is set to ${DEF_iTTLlo}:${DEF_iTTLhi}:${DEF_runTTL}"
get_confirm "Do you wish to change the TTL values for any map (y/n/h) ?" \
            "n" "default_ttl_help"

if [ $? -eq 0 ]; then
  # Default values accepted for all the maps.
  # So, just print all the maps with default TTL values.

  print_all_same_ttl_entries $DEF_iTTLlo $DEF_iTTLhi $DEF_runTTL

else
  echo "You would be allowed to enter the new TTL values."
  get_confirm "Do you wish to use the same TTL values for all the maps (y/n/h) ?" \
              "y" "non_default_same_ttl_help"

  if [ $? -eq 1 ]; then
    # Need to read only one TTL triplet.
    # Print all the maps with new TTL triplet.

    # read one ttl triplet
    echo "Enter the new TTL values :"

    read_one_ttl_triplet

    print_all_same_ttl_entries $iTTLlo $iTTLhi $runTTL
    
  else
    if [ $N2L_DMN_CNT -eq 1 ]; then

      # TTL values are different now. But we haev only one domain.
      # So, no need to worry about multiple domains. Need to read
      # only one TTL triplet for each existing MAP.

      read_all_maps_ttl_values_no_multiple_domain_issue

    else

      # TTL values are different now. And we have multiple domains
      # too. Check if MAPS are going to have same TTL across domains.
      # This is just to avoid asking too many TTL triplet inputs 

      echo "You would be allowed to enter different TTL values for each map."

      get_confirm "For a given map, do you wish to use the same TTL values for all the domains (y/n/h) ?" \
                  "y" "non_default_different_ttl_help"

      if [ $? -eq 1 ]; then

        # Need to read only one TTL triplet for each existing MAP.
        read_all_maps_ttl_values_no_multiple_domain_issue

      else

        # We have hit the worst case scenario. TTLs could be 
        # different per map and per domain.

        read_default_maps_ttl_values_with_multi_domain_issue
        read_custom_maps_ttl_values_with_multi_domain_issue
      fi
    fi
  fi
fi

echo "
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE

return 0
}


#
# The custom maps for which we do not have enough
# information to be able to generate specific entries,
# we just log the message that the user needs to take
# care of those entries manually.
#
ask_user_to_update_the_custom_map_entries_too()
{

if [ ${#ALL_DMN_CUST_MAPS[*]} -gt 0 ]; then

  echo "
# Similar entries need to be created
# for following custom maps too :\
" >> $MAP_FILE

  for _MAP in ${ALL_DMN_CUST_MAPS[*]}
  do
    echo "# $_MAP" >> $MAP_FILE
  done
fi
}


put_default_nisLDAPnameFields()
{
echo '
# Associate names with fields in the maps. Must be same for all domains.
nisLDAPnameFields audit_user: \
			("%s:%s:%s", name, alwaysAuditFlags, neverAuditFlags)

nisLDAPnameFields auto.home: \
			("%s",value)

nisLDAPnameFields auto.master: \
			("%s",value)

nisLDAPnameFields auth_attr: \
			("%s:%s:%s:%s:%s:%s", \
			name, res1, res2, short_desc, long_desc, attrs )

nisLDAPnameFields bootparams: \
			("%s", params)

nisLDAPnameFields ethers: \
			("%s %s", addr, name)

nisLDAPnameFields exec_attr: \
			("%s:%s:%s:%s:%s:%s:%s", \
			name, policy, type, res1, res2, id, attrs)

nisLDAPnameFields group: \
			("%s:%s:%s:%s", name, passwd, gid, users)
' >> $MAP_FILE

# Need to handle group.adjunct.byname map for multiple domain. 

_MAP=group.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo '#nisLDAPnameFields group.adjunct.byname: \
#			("%s:%s", name, passwd)
' >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # Don't put domain info as the map is present in all of them.
    echo 'nisLDAPnameFields group.adjunct.byname: \
			("%s:%s", name, passwd)
' >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPnameFields group.adjunct.byname,${_DMN}: \\
			(\"%s:%s\", name, passwd)
" >> $MAP_FILE
    done
  fi
fi

echo 'nisLDAPnameFields keys.host: \
			("%s:%s", publicKey ,secretKey)

nisLDAPnameFields keys.pass: \
			("%s:%s", publicKey ,secretKey)

nisLDAPnameFields keys.nobody: \
			("%s:%s", publicKey ,secretKey)

nisLDAPnameFields hosts: \
			("%a %s %s", addr, canonicalName, aliases)

nisLDAPnameFields multihosts: \
			("%a %s %s", addr, canonicalName, aliases)

nisLDAPnameFields ipnodes: \
			("%a %s %s", addr, canonicalName, aliases)

nisLDAPnameFields multiipnodes: \
			("%a %s %s", addr, canonicalName, aliases)

nisLDAPnameFields mail.aliases: \
			("%s", addresses)

nisLDAPnameFields mail.mapping: \
			("%s", address)

# memberTriples	is split into sub-fields by a latter nisLDAPsplitField
# attribute.
nisLDAPnameFields netgroup: \
			("%s", memberTriples)

nisLDAPnameFields netid.host: \
			("%s:%s", number, data)

nisLDAPnameFields netid.pass: \
			("%s:%s", number, data)

nisLDAPnameFields netmasks.byaddr: \
			("%a", mask)

nisLDAPnameFields networks: \
			("%s %s %s", name, number, aliases)

nisLDAPnameFields project: \
			("%s:%s:%s:%s:%s:%s", \
			name, projID, comment, users, groups, attrs)

nisLDAPnameFields protocols:	\
			("%s %s %s", name, number, aliases)

nisLDAPnameFields rpc.bynumber:	\
			("%s %s %s", name, number, aliases)

nisLDAPnameFields passwd: \
			("%s:%s:%s:%s:%s:%s:%s", \
			name, passwd, uid, gid, gecos, home, shell)

# It is not obvious what the fields in passwd.adjunct are for. They are not
# the same as the shadow map. The following is based on information in:-
#
#	lib/libbc/inc/include/pwdadj.h.
#
# This file implies that these are documented in getpwaent(3) but this man page
# does not seem to exist.
#			
# It is believed that 'min','max' and 'def' labels were reserved fields in 
# SunOS 4.x and are now unused.  'always' and 'never' audit information is 
# now contained in audit_user(4) so is now unused.
#
' >> $MAP_FILE

# Need to handle passwd.adjunct.byname map for multiple domain. 

_MAP=passwd.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo '#nisLDAPnameFields passwd.adjunct.byname: \
#			("%s:%s:%s:%s:%s:%s:%s", \
#			name, passwd, min, max, def, always, \
#			never)
' >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS

  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # Don't put domain info as the map is present in all of them.
    echo 'nisLDAPnameFields passwd.adjunct.byname: \
			("%s:%s:%s:%s:%s:%s:%s", \
			name, passwd, min, max, def, always, \
			never)
' >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPnameFields passwd.adjunct.byname,${_DMN}: \\
			(\"%s:%s:%s:%s:%s:%s:%s\", \\
                        name, passwd, min, max, def, always, \\
                        never)
" >> $MAP_FILE
    done
  fi
fi

echo '
nisLDAPnameFields printers.conf.byname: \
			("%s:%s", names, values)

nisLDAPnameFields prof_attr: \
			("%s:%s:%s:%s:%s", \
			name, res1, res2, desc, attrs)

nisLDAPnameFields services: \
			("%s %s/%s %s", name, port, protocol, aliases)

# This map is never created but yppasswd uses the mapping to extract password
# ageing information from the DIT. The password itself is not required by this
# mechanism so is not included in the ageing mapping.
nisLDAPnameFields ageing.byname: \
			("%s:%s:%s:%s:%s:%s:%s:%s", \
			name, lastchg, min, max, warn, inactive, \
			expire, flag)

nisLDAPnameFields timezone.byname: \
			("%s %s", zoneName, hostName)

nisLDAPnameFields user_attr: \
			("%s:%s:%s:%s:%s", user, qualifier, res1, res2, attrs)
' >> $MAP_FILE
}

#
# List namefields for non-default auto maps and custom maps.
#
put_auto_and_custom_map_nisLDAPnameFields()
{
for _MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]} ${ALL_DMN_CUST_MAPS[*]}
do

  echo "\
nisLDAPnameFields ${_MAP}: \\
                      (\"%s\",value)
" >> $MAP_FILE

done
}


create_nisLDAPnameFields()
{
# Put format information of "nisLDAPnameFields"
[ CUST_CMT_NEEDED -eq 1 ] && echo '
# "nisLDAPnameFields" specifies the content of entries in a NIS map
# and how they should be broken into named fields. It is required as,
# unlike NIS+, NIS maps do not store information in named fields.
#
# Following is the syntax for nisLDAPnameFields :
#
# "nisLDAPnameFields" mapName ":" "(" matchspec "," fieldNames ")"
# fieldName       = nameOrArrayName[","...]
# nameOrArrayName = Name of field or 'array' of repeated fields.
# matchspec       = \" formatString \"
' >> $MAP_FILE

# List the default nameField values
put_default_nisLDAPnameFields

# List the underlying assumption
echo "\
# With the assumption that all the custom maps are simple, single
# map (single key-value pair type), below is the nisLDAPnameFields
# information for all the custom and non-default auto.* maps. If
# this assumption is not valid, then refer to the NISLDAPmapping
# man page for information on how to customize this section.
" >> $MAP_FILE

# List namefields for non-default auto maps and custom maps.
put_auto_and_custom_map_nisLDAPnameFields


echo "
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE

return 0
}


#
# List repeated field seperators
#
create_nisLDAPrepeatedFieldSeparators()
{

[ CUST_CMT_NEEDED -eq 1 ] && echo "
# nisLDAPrepeatedFieldSeparators : It is a character which separates
# the repeatable instnaces of splitable fields. It's format is :
#
# nisLDAPrepeatedFieldSeparators fieldName \"sepChar[...]\"
#               sepChar = A separator character.
#               Default value is space or tab.
" >> $MAP_FILE

echo "\
#nisLDAPrepeatedFieldSeparators memberTriples: \" \t\"
" >> $MAP_FILE

}


#
# List split fields
#
create_nisLDAPsplitField()
{
# List the default split fields

[ CUST_CMT_NEEDED -eq 1 ] && echo '
# nisLDAPsplitFields : It defines how a field, or list of fields,
# named by nisLDAPnameFields is split into sub fields. The original
# field is compared with each line of this attribute until one matches.
# When a match is found named sub-fields are generated. In latter
# operations sub-field names can be used in the same way as other
# field names. The format of nisLDAPsplitFields is :
#
# "nisLDAPsplitFields" fieldName ":" splitSpec[","...]
# splitSpec       = "(" matchspec "," subFieldNames ")"
# fieldName       = Name of a field from nisLDAPnameFields
# subFieldNames   = subFieldname[","...]
# matchspec       = \" formatString \"  
' >> $MAP_FILE

echo '
nisLDAPsplitField memberTriples: \
			("(%s,%s,%s)", host, user, domain), \
			("%s", group)
' >> $MAP_FILE

}

#
# List split fields and repeated field separators.
#
create_split_field_and_repeatedfield_seperators()
{

echo "\
# Specify how to break fields up into sub fields.
" >> $MAP_FILE

create_nisLDAPrepeatedFieldSeparators

create_nisLDAPsplitField

echo "
#
#------------------------------------------------------------------------------
#
" >> $MAP_FILE
}

list_default_nisLDAPobjectDN()
{
echo '
# Associate maps with RDNs and object classes. Base DN comes from the 
# nisLDAPdomainContext.
#
# As supplied this file gives only the most derived objectClass for each map.
# For some servers it may be necessary to add "objectClass=" statements for 
# all the superclasses. This should be done here.

nisLDAPobjectDN	auto.home: \
			automountmapname=auto_home,?one? \
			objectClass=automount:

nisLDAPobjectDN	auto.master: \
			automountmapname=auto_master,?one? \
			objectClass=automount:

nisLDAPobjectDN	auth_attr: \
			ou=SolarisAuthAttr,?one? \
			objectClass=SolarisAuthAttr:

nisLDAPobjectDN	bootparams: \
			ou=ethers,?one? \
			objectClass=bootableDevice, \
			bootParameter=*:\
			ou=ethers,?one? \
			objectClass=device, \
			objectClass=bootableDevice 


nisLDAPobjectDN exec_attr:\
			ou=SolarisProfAttr,?one?objectClass=SolarisExecAttr,\
				SolarisKernelSecurityPolicy=*:\
			ou=SolarisProfAttr,?one?objectClass=SolarisExecAttr,\
				objectClass=SolarisProfAttr,\
				objectClass=top

nisLDAPobjectDN	ethers: \
			ou=ethers,?one? \
			objectClass=ieee802Device, \
			macAddress=*:\
			ou=ethers,?one? \
			objectClass=device, \
			objectClass=ieee802Device

nisLDAPobjectDN	group: \
			ou=group,?one? \
			objectClass=posixGroup:
' >> $MAP_FILE


# Need to handle group.adjunct.byname map for multiple domain.

_MAP=group.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo '#nisLDAPobjectDN group.adjunct.byname: \
#			ou=group,?one? \
#			objectClass=posixGroup:
' >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo 'nisLDAPobjectDN group.adjunct.byname: \
			ou=group,?one? \
			objectClass=posixGroup:
' >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPobjectDN group.adjunct.byname,${_DMN}: \\
			ou=group,?one? \\
			objectClass=posixGroup:
" >> $MAP_FILE
    done
  fi
fi


echo 'nisLDAPobjectDN	hosts: \
			ou=hosts,?one? \
			objectClass=ipHost:\
			ou=hosts,?one? \
			objectClass=device, \
			objectClass=ipHost

nisLDAPobjectDN multihosts: \
			ou=hosts,?one? \
			objectClass=ipHost, \
			ipHostNumber=*.*

nisLDAPobjectDN	ipnodes: \
			ou=hosts,?one? \
			objectClass=ipHost:\
			ou=hosts,?one? \
			objectClass=device, \
			objectClass=ipHost

nisLDAPobjectDN multiipnodes: \
			ou=hosts,?one? \
			objectClass=ipHost, \
			ipHostNumber=*\:*

nisLDAPobjectDN	mail.aliases: \
			ou=aliases,?one? \
			objectClass=mailGroup:

nisLDAPobjectDN	mail.mapping: \
			ou=aliases,?one? \
			objectClass=mailGroup

nisLDAPobjectDN	netgroup: \
			ou=netgroup,?one? \
			objectClass=nisNetgroup:

nisLDAPobjectDN	networks: \
			ou=networks,?one? \
			objectClass=ipNetwork, \
			cn=*:

# Must come after networks (or equivalent) that creates ipNetworks
nisLDAPobjectDN netmasks.byaddr: \
			ou=networks,?one? \
			objectClass=ipNetwork, \
			ipNetMaskNumber=*:

nisLDAPobjectDN	passwd: \
			ou=people,?one? \
			objectClass=posixAccount:\
			ou=people,?one? \
			objectClass=account, \
			objectClass=shadowAccount, \
			objectClass=posixAccount
' >> $MAP_FILE


# Need to handle passwd.adjunct.byname map for multiple domain.

_MAP=passwd.adjunct.byname
if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then
  # Just put the syntax in comment form
  echo '#nisLDAPobjectDN passwd.adjunct.byname: \
#			ou=people,?one? \
#			objectClass=posixAccount:\
#			ou=people,?one? \
#			objectClass=account, \
#			objectClass=shadowAccount, \
#			objectClass=posixAccount
' >> $MAP_FILE
else
  # Find the domains in which this map exists.
  find_domains $_MAP DEF_MAPS
  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then
    # Don't put domain info as the map is present in all of them.
    echo 'nisLDAPobjectDN passwd.adjunct.byname: \
			ou=people,?one? \
			objectClass=posixAccount:\
			ou=people,?one? \
			objectClass=account, \
			objectClass=shadowAccount, \
			objectClass=posixAccount
' >> $MAP_FILE
  else
    # Not every domain has this map. So, list for the ones which do.
    for _DMN in $PRESENT_IN_DOMAINS
    do
      echo "nisLDAPobjectDN passwd.adjunct.byname,${_DMN}: \\
			ou=people,?one? \\
			objectClass=posixAccount:\\
			ou=people,?one? \\
			objectClass=account, \\
			objectClass=shadowAccount, \\
			objectClass=posixAccount
" >> $MAP_FILE
    done
  fi
fi


echo '# Must follow passwd
nisLDAPobjectDN netid.pass: \
			ou=people,?one? \
			objectClass=posixAccount

# Must follow hosts
nisLDAPobjectDN netid.host: \
			ou=hosts,?one? \
			objectClass=ipHost

nisLDAPobjectDN	printers.conf.byname: \
			ou=printers,?one? \
				objectClass=printerService:\
			ou=printers,?one? \
				objectClass=sunPrinter, \
				objectClass=printerService, \
				objectClass=printerLPR, \
				objectClass=printerAbstract

nisLDAPobjectDN prof_attr:\
			ou=SolarisProfAttr,?one?objectClass=SolarisProfAttr,\
				SolarisAttrLongDesc=*:\
			ou=SolarisProfAttr,?one?objectClass=SolarisProfAttr,\
				objectClass=SolarisExecAttr,\
				objectClass=top
nisLDAPobjectDN project: \
			ou=project,?one? \
			objectClass=SolarisProject:

nisLDAPobjectDN	protocols: \
			ou=protocols,?one? \
			objectClass=ipProtocol:

nisLDAPobjectDN rpc.bynumber: \
			ou=rpc,?one? \
			objectClass=oncRpc:

nisLDAPobjectDN	services.byname: \
			ou=services,?one? \
			objectClass=ipService:

# Because services.byservicename contains keys of form both 'name'
# and 'name/protocol' we generate the DIT just from services.byname.
# Hence, write-disabled for services.byservicename
nisLDAPobjectDN	services.byservicename: \
			ou=services,?one? \
			objectClass=ipService

# This map is never created but yppasswd uses the mapping to extract password
# aging information from the DIT.			
nisLDAPobjectDN	ageing.byname: \
			ou=people,?one? \
			objectClass=shadowAccount:

# Using nisplusTimeZoneData objectClass for compatibility with nis+2ldap
nisLDAPobjectDN	timezone.byname: \
			ou=Timezone,?one? \
			objectClass=nisplusTimeZoneData:

nisLDAPobjectDN	user_attr: \
			ou=people,?one? \
			objectClass=SolarisUserAttr:

# Must come after passwd (or equivalent) that creates posixAccounts
nisLDAPobjectDN	audit_user: \
			ou=people,?one? \
			objectClass=SolarisAuditUser:

# Must come after hosts + passwd.
nisLDAPobjectDN keys.host: \
			ou=hosts,?one? \
			objectClass=NisKeyObject:

nisLDAPobjectDN keys.pass: \
			ou=people,?one? \
			objectClass=NisKeyObject:

nisLDAPobjectDN keys.nobody: \
			ou=people,?one? \
			objectClass=NisKeyObject:\
			ou=people,?one? \
			objectClass=account, \
			objectClass=NisKeyObject
			
nisLDAPobjectDN ypservers: \
			ou=ypservers,?one? \
			objectClass=device:
' >> $MAP_FILE
}

# List all the non-default auto.* and custom maps.
list_auto_custom_nisLDAPobjectDN()
{

# auto.* entries are easy. 
if [ ${#ALL_DMN_AUTO_CUST_MAPS[*]} -gt 0 ]; then
  echo "# Non-default custom auto maps (auto.*)\n" >> $MAP_FILE

  for _MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]}
  do

    # We need to find one container for each auto.* map.
    # Assume that each auto.* maps's container is auto_*.

    _MAP_UNDERSCORE=`echo $_MAP | sed "s/auto\./auto_/"`

    echo "\
nisLDAPobjectDN ${_MAP}: \\
                      automountmapname=${_MAP_UNDERSCORE},?one? \\
                      objectClass=automount:
" >> $MAP_FILE
  done
fi

# Since we do not have enough information to generate
# entries for other custom maps, best we can do is to
# log this map names and ask user to take care of them.

ask_user_to_update_the_custom_map_entries_too

}


#
# List association of maps with RDNs and object classes.
#
create_nisLDAPobjectDN()
{

[ CUST_CMT_NEEDED -eq 1 ] && echo '
# nisLDAPobjectDN : It specifies the connection between group of NIS
# maps and the LDAP directory. This attribute also defines the 'order'
# of the NIS maps. When NIS maps are bulk copied to or from the DIT
# they are processed in the same order as related nisLDAPobjectDN
# attributes appear in /var/yp/NISLDAPmapping.
# The format of "nisLDAPobjectDN" is :
# 
# mapName[" "...] ":" objectDN *( ";" objectDN )
# 
# where:
# 
# objectDN        = readObjectSpec [":"[writeObjectSpec]]
# readObjectSpec  = [baseAndScope [filterAttrValList]]
# writeObjectSpec = [baseAndScope [attrValList]]
# baseAndScope    = [baseDN] ["?" [scope]]
# filterAttrValList = ["?" [filter | attrValList]]]
# scope           = "base" | "one" | "sub"
# attrValList     = attribute "=" value
#                       *("," attribute "=" value)
' >> $MAP_FILE

# List all the default entries anyway.
list_default_nisLDAPobjectDN

# List all the non-default auto.* and custom maps.
list_auto_custom_nisLDAPobjectDN

}

#
# List all the default nisLDAPattributeFromField entries
#
list_default_nisLDAPattributeFromField()
{
echo '
# Describe how named fields are mapped to DIT entries.

# audit_user
nisLDAPattributeFromField audit_user: \
			dn=("uid=%s,", rf_key ), \
			SolarisAuditAlways=alwaysAuditFlags, \
			SolarisAuditNever=neverAuditFlags

# auto.home
nisLDAPattributeFromField auto.home: \
			dn=("automountKey=%s,", rf_key ), \
			automountKey=rf_key, \
			automountInformation=value

# auto.master
nisLDAPattributeFromField auto.master: \
			dn=("automountKey=%s,", rf_key ), \
			automountKey=rf_key, \
			automountInformation=value

# auth_attr
nisLDAPattributeFromField auth_attr: \
			dn=("cn=%s,", rf_key ), \
			cn=name, \
			SolarisAttrReserved1=res1, \
			SolarisAttrReserved2=res2, \
			SolarisAttrShortDesc=short_desc, \
			SolarisAttrLongDesc=long_desc, \
			SolarisAttrKeyValue=attrs

# exec_attr. Because of the messy NIS keys special handling is required here
nisLDAPattributeFromField exec_attr: \
			dn=("cn=%s+SolarisKernelSecurityPolicy=%s\
				+SolarisProfileType=%s+SolarisProfileID=%s,", \
				name, policy,type,id), \
			("%s:*", cn)=rf_key, \
			("*:%s:*", SolarisKernelSecurityPolicy)=rf_key, \
			("*:*:%s", SolarisProfileId)=rf_key, \
			solarisProfileType=type, \
			solarisAttrReserved1=res1, \
			SolarisAttrReserved2=res2, \
			solarisAttrKeyValue=attrs

# ethers
nisLDAPattributeFromField ethers.byname: \
			dn=("cn=%s,", rf_key ), \
			macAddress=addr
nisLDAPattributeFromField ethers.byaddr: \
			dn=("cn=%s,", name ), \
			macAddress=rf_key
nisLDAPattributeFromField ethers: \
			cn=name, \
			description=rf_comment

# bootparams. Must be done after ethers
nisLDAPattributeFromField bootparams: \
			dn=("cn=%s,", rf_key ), \
			cn=rf_key, \
			(bootParameter)=(params, " ")
' >> $MAP_FILE

# group syntax is different when group.adjunct map is present.
# So, need to handle the various possibilities

_MAP=group.adjunct.byname

if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then

  # Just put the group.adjunct syntax in comment form

  echo '# group
nisLDAPattributeFromField group.byname: \
			dn=("cn=%s,", rf_key ), \
                        gidNumber=gid
nisLDAPattributeFromField group.bygid: \
		        dn=("cn=%s,", name ), \
                        gidNumber=rf_key
nisLDAPattributeFromField group: \
                        cn=name, \
                        userPassword=("{crypt}%s",passwd), \
                        (memberUid)=(users, ",")

#
# If you are using group.adjunct, comment the group section above
# and uncomment the following group and group.adjunct sections
#
# group
#nisLDAPattributeFromField group.byname: \
#			dn=("cn=%s,", rf_key ), \
#			gidNumber=gid
#nisLDAPattributeFromField group.bygid: \
#			dn=("cn=%s,", name ), \
#			gidNumber=rf_key
#nisLDAPattributeFromField group: \
#			cn=name, \
#			(memberUid)=(users, ",")

# group.adjunct
#nisLDAPattributeFromField group.adjunct.byname: \
#			dn=("cn=%s,", rf_key ), \
#			cn=name, \
#			userPassword=("{crypt}%s",passwd)
' >> $MAP_FILE

else

  # Find the domains in which group.adjunct map exists.
  find_domains $_MAP DEF_MAPS

  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # All the domains have group.adjunct map.

    echo '# group
#nisLDAPattributeFromField group.byname: \
#			dn=("cn=%s,", rf_key ), \
#			gidNumber=gid
#nisLDAPattributeFromField group.bygid: \
#			dn=("cn=%s,", name ), \
#			gidNumber=rf_key
#nisLDAPattributeFromField group: \
#			cn=name, \
#			userPassword=("{crypt}%s",passwd), \
#			(memberUid)=(users, ",")

# If you are not using group.adjunct, uncomment the group section above
# and comment the following group and group.adjunct sections
#
# group
nisLDAPattributeFromField group.byname: \
			dn=("cn=%s,", rf_key ), \
			gidNumber=gid
nisLDAPattributeFromField group.bygid: \
			dn=("cn=%s,", name ), \
			gidNumber=rf_key
nisLDAPattributeFromField group: \
			cn=name, \
			(memberUid)=(users, ",")

# group.adjunct
nisLDAPattributeFromField group.adjunct.byname: \
			dn=("cn=%s,", rf_key ), \
			cn=name, \
			userPassword=("{crypt}%s",passwd)
' >> $MAP_FILE

  else
    # Not every domain has group.adjunct map.

    # First put the password syntax with domain name for domains
    # in which group.adjunct exists.

    echo "# group" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
# domain-specific group
nisLDAPattributeFromField group.byname,${_DMN}: \\
			dn=(\"cn=%s,\", rf_key ), \\
			gidNumber=gid
nisLDAPattributeFromField group.bygid,${_DMN}: \\
			dn=(\"cn=%s,\", name ), \\
			gidNumber=rf_key
nisLDAPattributeFromField group,${_DMN}: \\
			cn=name, \\
			(memberUid)=(users, \",\")
" >> $MAP_FILE
    done

    # Now put the other group syntax. We do not need to
    # append the domain name here.

    echo '
nisLDAPattributeFromField group.byname: \
			dn=("cn=%s,", rf_key ), \
			gidNumber=gid
nisLDAPattributeFromField group.bygid: \
			dn=("cn=%s,", name ), \
			gidNumber=rf_key
nisLDAPattributeFromField group: \
			cn=name, \
			userPassword=("{crypt}%s",passwd), \
			(memberUid)=(users, ",")
' >> $MAP_FILE

    # Now we need to put the group.adjunct syntax for domains
    # in which this map exists.

    echo "# group.adjunct" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPattributeFromField group.adjunct.byname,${_DMN}: \\
			dn=(\"cn=%s,\", rf_key ), \\
			cn=name, \\
			userPassword=(\"{crypt}%s\",passwd)
" >> $MAP_FILE
    done

  fi

fi


echo '
# hosts
# Cannot forward map hosts.byname key as the YP_MULTI entries will not work.
nisLDAPattributeFromField hosts.byname: \
                        cn=rf_searchkey
nisLDAPattributeFromField hosts.byaddr: \
                        ipHostNumber=rf_searchipkey
nisLDAPattributeFromField hosts: \
                        ipHostNumber=addr, \
			dn=("cn=%s+ipHostNumber=%s,", canonicalName, addr), \
                        cn=canonicalName, \
                        (cn)=(aliases, " "), \
                        description=rf_comment

nisLDAPattributeFromField multihosts: \
			("YP_MULTI_%s", cn)=rf_searchkey

# ipnodes
# Cannot forward map ipnodes.byname key as the YP_MULTI entries will not work.
nisLDAPattributeFromField ipnodes.byname: \
                        cn=rf_searchkey
nisLDAPattributeFromField ipnodes.byaddr: \
                        ipHostNumber=rf_searchipkey
nisLDAPattributeFromField ipnodes: \
                        ipHostNumber=addr, \
			dn=("cn=%s+ipHostNumber=%s,", canonicalName, addr), \
			cn=canonicalName, \
                        (cn)=(aliases, " "), \
                        description=rf_comment

nisLDAPattributeFromField multiipnodes: \
			("YP_MULTI_%s", cn)=rf_searchkey

#mail.aliases
nisLDAPattributeFromField mail.aliases: \
			dn=("mail=%s,", rf_key), \
			mail=rf_key, \
			(mgrprfc822mailmember)=(addresses, ",")

#mail.mapping
#Commented out because all NIS->LDAP mappings are done by mail.aliases
#nisLDAPattributeFromField mail.mapping: \
#			dn=("mail=%s,", address), \
#			mail=address, \
#			mgrprfc822mailmember=rf_key
nisLDAPattributeFromField mail.mapping: \
			mgrprfc822mailmember=rf_searchkey

# netgroup.
#
# Only need to create DIT entries for netgroup. This contains a superset of
# the information in netgroup.byhost and netgroup.byuser
nisLDAPattributeFromField netgroup: \
			dn=("cn=%s,", rf_key ), \
			(memberNisNetgroup)=group, \
			(nisNetgroupTriple)= \
					("(%s,%s,%s)", host, user, domain), \
			cn=rf_key, \
			description=rf_comment

# netid.pass
#
# Commented out because, unless remote domains (and thus /etc/netid) is
# supported, all NIS->LDAP mappings are set up from passwd.
#nisLDAPattributeFromField netid.pass: \
#			("unix.%s@*", uidNumber)=rf_key, \
#			(gidNumber)=("%s", (data), " "), \
#			description=rf_comment
nisLDAPattributeFromField netid.pass: \
			("unix.%s@*", uidNumber)=rf_searchkey

# netid.host
#
# Commented out because, unless remote domains (and thus /etc/netid) is
# supported, all NIS->LDAP mappings are set up from hosts.
#nisLDAPattributeFromField netid.host: \
#			dn=("cn=%s+ipHostNumber=%s,", data, \
#			        ldap:ipHostNumber:?one?("cn=%s", data)), \
#			ipHostNumber=ldap:ipHostNumber:?one?("cn=%s", data), \
#			("unix.%s@*", cn)=rf_key, \
#			description=rf_comment
nisLDAPattributeFromField netid.host: \
			("unix.%s@*", cn)=rf_searchkey

# netmasks.byaddr
nisLDAPattributeFromField netmasks.byaddr: \
			dn=("ipNetworkNumber=%s,", rf_ipkey ), \
			ipNetworkNumber=rf_ipkey, \
			ipNetmaskNumber=mask, \
			description=rf_comment

# networks.
nisLDAPattributeFromField networks.byname: \
			dn=("ipNetworkNumber=%s,", number ), \
			cn=name, \
			cn=rf_key
nisLDAPattributeFromField networks.byaddr: \
			dn=("ipNetworkNumber=%s,", rf_key ), \
			cn=name
nisLDAPattributeFromField networks: \
			(cn)=(aliases, " "), \
			ipNetworkNumber=number, \
			description=rf_comment
' >> $MAP_FILE


# passwd syntax is different when passwd.adjunct map is present.
# So, need to handle the various possibilities

_MAP=passwd.adjunct.byname

if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then

  # Just put the passwd.adjunct syntax in comment form

  echo '# passwd
nisLDAPattributeFromField passwd.byname: \
			dn=("uid=%s,", rf_key ), \
			uid=rf_key, \
			uidNumber=uid
nisLDAPattributeFromField passwd.byuid: \
			dn=("uid=%s,", name ), \
			uidNumber=rf_key, \
			uid=name
nisLDAPattributeFromField passwd: \
			cn=name, \
			userPassword=("{crypt}%s",passwd), \
			gidNumber=gid, \
			gecos=gecos, \
			homeDirectory=home, \
			loginShell=shell

#
# If you are using passwd.adjunct, comment the passwd section above
# and uncomment the following passwd and passwd.adjunct sections
#
# passwd
#nisLDAPattributeFromField passwd.byname: \
#			dn=("uid=%s,", rf_key ), \
#			uid=rf_key, \
#			uidNumber=uid
#nisLDAPattributeFromField passwd.byuid: \
#			dn=("uid=%s,", name ), \
#			uidNumber=rf_key, \
#			uid=name
#nisLDAPattributeFromField passwd: \
#			cn=name, \
#			gidNumber=gid, \
#			gecos=gecos, \
#			homeDirectory=home, \
#			loginShell=shell

# passwd.adjunct
#nisLDAPattributeFromField passwd.adjunct.byname: \
#			dn=("uid=%s,", rf_key ), \
#			uid=name, \
#			userPassword=("{crypt}%s",passwd)
' >> $MAP_FILE

else

  # Find the domains in which passwd.adjunct map exists.
  find_domains $_MAP DEF_MAPS

  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # All the domains have passwd.adjunct map. So, put the right
    # passwd syntax and comment-in the passwd.adjunct syntax.


    echo '# passwd
#nisLDAPattributeFromField passwd.byname: \
#			dn=("uid=%s,", rf_key ), \
#			uid=rf_key, \
#			uidNumber=uid
#nisLDAPattributeFromField passwd.byuid: \
#			dn=("uid=%s,", name ), \
#			uidNumber=rf_key, \
#			uid=name
#nisLDAPattributeFromField passwd: \
#			cn=name, \
#			userPassword=("{crypt}%s",passwd), \
#			gidNumber=gid, \
#			gecos=gecos, \
#			homeDirectory=home, \
#			loginShell=shell

# If you are not using passwd.adjunct, uncomment the passwd section above
# and comment the following passwd and passwd.adjunct sections
#
# passwd
nisLDAPattributeFromField passwd.byname: \
			dn=("uid=%s,", rf_key ), \
			uid=rf_key, \
			uidNumber=uid
nisLDAPattributeFromField passwd.byuid: \
			dn=("uid=%s,", name ), \
			uidNumber=rf_key, \
			uid=name
nisLDAPattributeFromField passwd: \
			cn=name, \
			gidNumber=gid, \
			gecos=gecos, \
			homeDirectory=home, \
			loginShell=shell

# passwd.adjunct
nisLDAPattributeFromField passwd.adjunct.byname: \
			dn=("uid=%s,", rf_key ), \
			uid=name, \
			userPassword=("{crypt}%s",passwd)
' >> $MAP_FILE

  else
    # Not every domain has passwd.adjunct map.

    # First put the password syntax with domain name for domains
    # in which passwd.adjunct exists.

    echo "# passwd" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPattributeFromField passwd.byname,${_DMN}: \\
			dn=(\"uid=%s,\", rf_key ), \\
			uid=rf_key, \\
			uidNumber=uid
nisLDAPattributeFromField passwd.byuid,${_DMN}: \\
			dn=(\"uid=%s,\", name ), \\
			uidNumber=rf_key, \\
			uid=name
nisLDAPattributeFromField passwd,${_DMN}: \\
			cn=name, \\
			gidNumber=gid, \\
			gecos=gecos, \\
			homeDirectory=home, \\
			loginShell=shell
" >> $MAP_FILE
    done

    # Now put the other passwd syntax. We do not need to
    # append the domain name here.

    echo '
nisLDAPattributeFromField passwd.byname: \
			dn=("uid=%s,", rf_key ), \
			uid=rf_key, \
			uidNumber=uid
nisLDAPattributeFromField passwd.byuid: \
			dn=("uid=%s,", name ), \
			uidNumber=rf_key, \
			uid=name
nisLDAPattributeFromField passwd: \
			cn=name, \
			userPassword=("{crypt}%s",passwd), \
			gidNumber=gid, \
			gecos=gecos, \
			homeDirectory=home, \
			loginShell=shell
' >> $MAP_FILE

    # Now we need to put the passwd.adjunct syntax for domains
    # in which this map exists.

    echo "# passwd.adjunct" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPattributeFromField passwd.adjunct.byname,${_DMN}: \\
			dn=(\"uid=%s,\", rf_key ), \\
			uid=name, \\
			userPassword=(\"{crypt}%s\",passwd)
" >> $MAP_FILE
    done

  fi

fi

echo '
# This map is never created but yppasswd uses the mapping to extract password
# aging information from the DIT.	
nisLDAPattributeFromField ageing.byname: \
			dn=("uid=%s,", rf_key ), \
			uid=name, \
			shadowLastChange=lastchg, \
			shadowMin=min, \
			shadowMax=max, \
			shadowWarning=warn, \
			shadowInactive=inactive, \
			shadowExpire=expire, \
			shadowFlag=flag

# printers.conf.byname
nisLDAPattributeFromField printers.conf.byname: \
			dn=("printer-uri=%s,", rf_key ), \
			printer-name=rf_key, \
			(printer-aliases)=(names, "|"), \
			sun-printer-bsdaddr=(values, "*bsdaddr=%s:*"), \
			(sun-printer-kvp)=(values,":"), \
			description=rf_comment 

# prof_attr
nisLDAPattributeFromField prof_attr: \
			dn=("cn=%s,", rf_key ), \
			cn=name, \
			SolarisAttrReserved1=res1, \
			SolarisAttrReserved2=res2, \
			SolarisAttrLongDesc=desc, \
			SolarisAttrKeyValue=attrs

# project
nisLDAPattributeFromField project.byname: \
			dn=("SolarisProjectName=%s,", rf_key )
nisLDAPattributeFromField project.byprojid: \
			dn=("SolarisProjectName=%s,", name ), \
			SolarisProjectID=rf_searchkey
nisLDAPattributeFromField project: \
			SolarisProjectName=name, \
			SolarisProjectID=projID, \
			(memberUid)=(users, ","), \
			(memberGid)=(groups, ","), \
			(SolarisProjectAttr)=(attrs, ";"), \
			description=comment

# protocols
nisLDAPattributeFromField protocols.byname: \
                        ipProtocolNumber=number, \
                        cn=rf_searchkey
nisLDAPattributeFromField protocols.bynumber: \
                        ipProtocolNumber=rf_key, \
                        description=rf_comment
nisLDAPattributeFromField protocols: \
			dn=("cn=%s,", name ), \
                        (cn)=(aliases, " "), \
			cn=name

# rpc.bynumber
nisLDAPattributeFromField rpc.bynumber: \
			dn=("cn=%s,", name ), \
			oncRpcNumber=rf_key, \
                        (cn)=(aliases, " "), \
			cn=name, \
			description=rf_comment 

# services
# services.byservicename rule is only used to speed single search
nisLDAPattributeFromField services.byservicename: \
			("%s/%s", cn, ipServiceProtocol) = rf_searchkey

nisLDAPattributeFromField services.byname: \
			dn=("cn=%s+ipServiceProtocol=%s,", name, protocol ), \
     			("*/%s", ipServiceProtocol)=rf_key, \
     			("%s/*", ipServicePort)=rf_key, \
                        (cn)=(aliases, " "), \
			cn=name, \
                        description=rf_comment

# timezone.byname
nisLDAPattributeFromField timezone.byname: \
			dn=("cn=%s,", rf_key ), \
			cn=hostName, \
			nisplusTimeZone=zoneName, \
			description=comment

# user_attr
nisLDAPattributeFromField user_attr: \
			dn=("uid=%s,", rf_key ), \
			uid=rf_key, \
			SolarisUserAttr=qualifier, \
			SolarisUserReserved1=res1, \
			SolarisUserReserved2=res2, \
			SolarisAttrKeyValue=attrs

# publickey.byname
nisLDAPattributeFromField keys.host: \
			dn=("%s", ldap:dn:?one?("cn=%s", (yp:rf_key, "unix.%s@*"))), \
			nisPublicKey=publicKey, \
			nisSecretKey=secretKey

nisLDAPattributeFromField keys.pass: \
			dn=("%s", ldap:dn:?one?("uidNumber=%s", (yp:rf_key, "unix.%s@*"))), \
			nisPublicKey=publicKey, \
			nisSecretKey=secretKey

nisLDAPattributeFromField keys.nobody: \
			dn=("uid=%s,",yp:rf_key), \
			cn=rf_key, \
			nisPublicKey=publicKey, \
			nisSecretKey=secretKey

# ypservers. This derived from IPlanet implementation not RFC.
nisLDAPattributeFromField ypservers: \
			dn=("cn=%s,", rf_key), \
			cn=rf_key
' >> $MAP_FILE
}

#
# List all the non-default auto.* and custom maps.
#
list_auto_and_custom_nisLDAPattributeFromField()
{

# auto.* entries are easy. 
if [ ${#ALL_DMN_AUTO_CUST_MAPS[*]} -gt 0 ]; then
  echo "# Non-default custom auto maps (auto.*)\n" >> $MAP_FILE
fi

for _MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]}
do
  echo "\
# ${_MAP}
nisLDAPattributeFromField ${_MAP}: \\
                        dn=(\"automountKey=%s,\", rf_key ), \\
                        automountKey=rf_key, \\
                        automountInformation=value
" >> $MAP_FILE
done

# Since we do not have enough information to generate
# entries for other custom maps, best we can do is to
# log this map names and ask user to take care of them.

ask_user_to_update_the_custom_map_entries_too

}


#
# List mapping of named fields to DIT entries
#
create_nisLDAPattributeFromField()
{

[ CUST_CMT_NEEDED -eq 1 ] && echo '
# nisLDAPattributeFromField : It specifies how an LDAP attribute
# value is derived from a NIS entries field values.
# 
# The format of nisLDAPattributeFromField entry is :
# mapName ":" fieldattrspec *("," fieldattrspec )
' >> $MAP_FILE

# List all the default entries anyway.
list_default_nisLDAPattributeFromField

# List all the non-default auto.* and custom maps.
list_auto_and_custom_nisLDAPattributeFromField

echo "
#
#------------------------------------------------------------------------------
#			 
" >> $MAP_FILE
}


#
# List all the default nisLDAPattributeFromField entries
#
list_default_nisLDAPfieldFromAttribute()
{
echo '
# Describe how named fields are mapped from DIT entries.

# audit_user
nisLDAPfieldFromAttribute audit_user: \
			("uid=%s,*", rf_key)=dn, \
			("uid=%s,*", name)=dn, \
			alwaysAuditFlags=SolarisAuditAlways, \
			neverAuditFlags=SolarisAuditNever

# auto.home
nisLDAPfieldFromAttribute auto.home: \
			rf_key=automountKey, \
			value=automountInformation

# auto.master
nisLDAPfieldFromAttribute auto.master: \
			rf_key=automountKey, \
			value=automountInformation

# auth_attr
nisLDAPfieldFromAttribute auth_attr: \
			rf_key=cn, \
			name=cn, \
			res1=SolarisAttrReserved1, \
			res2=SolarisAttrReserved2, \
			short_desc=SolarisAttrShortDesc, \
			long_desc=SolarisAttrLongDesc, \
			attrs=SolarisAttrKeyValue

# Exec_attr. Because of messy NIS keys special handlind is required here
nisLDAPfieldFromAttribute exec_attr: \
			rf_key=("%s:%s:%s",cn,SolarisKernelSecurityPolicy, \
				solarisProfileId), \
			name=cn, \
			policy=SolarisKernelSecurityPolicy, \
			type=SolarisProfileType, \
			res1=SolarisAttrReserved1, \
			res2=SolarisAttrReserved2, \
			id=SolarisProfileId, \
			attrs=SolarisAttrKeyValue


# ethers
nisLDAPfieldFromAttribute ethers.byname: \
			rf_key=cn
nisLDAPfieldFromAttribute ethers.byaddr: \
			rf_key=macAddress
nisLDAPfieldFromAttribute ethers: \
			name=cn, \
			addr=macAddress, \
			rf_comment=description

# bootparams. Must be done after ethers
nisLDAPfieldFromAttribute bootparams: \
			rf_key=cn, \
			params=("%s ", (bootParameter), " ")
' >> $MAP_FILE

# group syntax is different when group.adjunct map is present.
# So, need to handle the various possibilities

_MAP=group.adjunct.byname

if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then

  # Just put the group.adjunct syntax in comment form

  echo '# group
nisLDAPfieldFromAttribute group.byname: \
			rf_key=cn
nisLDAPfieldFromAttribute group.bygid: \
                        rf_key=gidNumber
nisLDAPfieldFromAttribute group: \
                        gid=gidNumber, \
                        name=cn, \
			("{crypt}%s", passwd)=userPassword, \
			users=("%s,", (memberUid), ",")

#
# If you are using group.adjunct, comment the group section above
# and uncomment the following group and group.adjunct section
#			
# group
#nisLDAPfieldFromAttribute group.byname: \
#			rf_key=cn
#nisLDAPfieldFromAttribute group.bygid: \
#			rf_key=gidNumber
#nisLDAPfieldFromAttribute group: \
#			gid=gidNumber, \
#			name=cn, \
#			passwd=("#$%s", cn), \
#			users=("%s,", (memberUid), ",")

# group.adjunct
#nisLDAPfieldFromAttribute group.adjunct.byname: \
#			rf_key=cn, \
#			name=cn, \
#			("{crypt}%s", passwd)=userPassword
' >> $MAP_FILE

else

  # Find the domains in which group.adjunct map exists.
  find_domains $_MAP DEF_MAPS

  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # All the domains have group.adjunct map.


    echo '# group
#nisLDAPfieldFromAttribute group.byname: \
#			rf_key=cn
#nisLDAPfieldFromAttribute group.bygid: \
#                        rf_key=gidNumber
#nisLDAPfieldFromAttribute group: \
#                        gid=gidNumber, \
#                        name=cn, \
#			("{crypt}%s", passwd)=userPassword, \
#			users=("%s,", (memberUid), ",")

#
# If you are not using group.adjunct, comment the group section above
# and uncomment the following group and group.adjunct sections
#			
# group 
nisLDAPfieldFromAttribute group.byname: \
			rf_key=cn
nisLDAPfieldFromAttribute group.bygid: \
			rf_key=gidNumber
nisLDAPfieldFromAttribute group: \
			gid=gidNumber, \
			name=cn, \
			passwd=("#$%s", cn), \
			users=("%s,", (memberUid), ",")

#
# group.adjunct
nisLDAPfieldFromAttribute group.adjunct.byname: \
			rf_key=cn, \
			name=cn, \
			("{crypt}%s", passwd)=userPassword
' >> $MAP_FILE

  else
    # Not every domain has group.adjunct map.

    echo "# group" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPfieldFromAttribute group.byname,${_DMN}: \\
			rf_key=cn
nisLDAPfieldFromAttribute group.bygid,${_DMN}: \\
			rf_key=gidNumber
nisLDAPfieldFromAttribute group,${_DMN}: \\
			gid=gidNumber, \\
			name=cn, \\
			passwd=(\"#$%s\", cn), \\
			users=(\"%s,\", (memberUid), \",\")
" >> $MAP_FILE
    done

    # Now put the generic group syntax. We do not need to
    # append the domain name here.

    echo '
nisLDAPfieldFromAttribute group.byname: \
			rf_key=cn
nisLDAPfieldFromAttribute group.bygid: \
                        rf_key=gidNumber
nisLDAPfieldFromAttribute group: \
                        gid=gidNumber, \
                        name=cn, \
			("{crypt}%s", passwd)=userPassword, \
			users=("%s,", (memberUid), ",")
' >> $MAP_FILE

    # Now we need to put the group.adjunct syntax for domains
    # in which this map exists.

    echo "#
# group.adjunct
# " >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPfieldFromAttribute group.adjunct.byname,${_DMN}: \\
			rf_key=cn, \\
			name=cn, \\
			(\"{crypt}%s\", passwd)=userPassword
" >> $MAP_FILE

    done

  fi

fi

echo '
# hosts
nisLDAPfieldFromAttribute hosts.byaddr: \
                        rf_ipkey=ipHostNumber
nisLDAPfieldFromAttribute hosts.byname: \
			(rf_key)=(cn)
nisLDAPfieldFromAttribute hosts: \
			("cn=%s+ipHostNumber=*", canonicalName)=dn, \
                        addr=ipHostNumber, \
			aliases=("%s ", (cn) - yp:canonicalName, " "), \
                        rf_comment=description

nisLDAPfieldFromAttribute multihosts: \
			("cn=%s+ipHostNumber=*", canonicalName)=dn, \
			(rf_key)=("YP_MULTI_%s", cn), \
			aliases=("%s ", (cn) - yp:canonicalName, " "), \
			rf_comment=description, \
			(tmp)=("%s", ipHostNumber:?one?("(&(cn=%s) \
				(ipHostNumber=*.*))", yp:canonicalName)), \
			addr=("%s,", (yp:tmp), ",")

# ipnodes
nisLDAPfieldFromAttribute ipnodes.byaddr: \
                        rf_ipkey=ipHostNumber
nisLDAPfieldFromAttribute ipnodes.byname: \
			(rf_key)=(cn)
nisLDAPfieldFromAttribute ipnodes: \
			("cn=%s+ipHostNumber=*", canonicalName)=dn, \
                        addr=ipHostNumber, \
			aliases=("%s ", (cn) - yp:canonicalName, " "), \
                        rf_comment=description

nisLDAPfieldFromAttribute multiipnodes: \
			("cn=%s+ipHostNumber=*", canonicalName)=dn, \
			(rf_key)=("YP_MULTI_%s", cn), \
			aliases=("%s ", (cn) - yp:canonicalName, " "), \
			rf_comment=description, \
			(tmp)=("%s", ipHostNumber:?one?("(&(cn=%s) \
				(ipHostNumber=*:*))", yp:canonicalName)), \
			addr=("%s,", (yp:tmp), ",")

#mail.aliases
nisLDAPfieldFromAttribute mail.aliases: \
			rf_key=mail, \
			addresses= ("%s,", (mgrprfc822mailmember), ","), \
			rf_comment=description

#mail.mapping
nisLDAPfieldFromAttribute mail.mapping: \
			rf_key=mgrprfc822mailmember, \
			address=mail, \
			rf_comment=description

# netgroup.
nisLDAPfieldFromAttribute netgroup: \
			rf_key=cn, \
			(group)=(memberNisNetgroup), \
			("(%s,%s,%s)", host, user, domain)= \
						(nisNetgroupTriple), \
			rf_comment=description

# netid.pass
nisLDAPfieldFromAttribute netid.pass: \
			number=uidNumber, \
			(tmp)=("%s", gidNumber:ou=group,?one?\
				("memberUid=%s", ldap:uid)), \
			sgid=("%s,", (yp:tmp) - gidNumber, ","), \
			data=("%s,%s", gidNumber, yp:sgid), \
			data=gidNumber, \
			(rf_key)=("unix.%s@%s", yp:number, yp:rf_domain)

# netid.host
nisLDAPfieldFromAttribute netid.host: \
			("cn=%s+ipHostNumber=*", data)=dn, \
			number=("0"), \
			(rf_key)=("unix.%s@%s", yp:data, yp:rf_domain)

# netmasks.byaddr
nisLDAPfieldFromAttribute netmasks.byaddr: \
			("ipNetworkNumber=%s,*", rf_ipkey)=dn, \
			mask=ipNetmaskNumber, \
			rf_comment=description

# networks.
nisLDAPfieldFromAttribute networks.byname: \
			(rf_key)=(cn)
nisLDAPfieldFromAttribute networks.byaddr: \
			("ipNetworkNumber=%s,*", rf_key)=dn
nisLDAPfieldFromAttribute networks: \
			name=cn, \
			aliases=("%s ", (cn) - yp:name, " "), \
			number=ipNetworkNumber, \
			rf_comment=description
' >> $MAP_FILE

# passwd syntax is different when passwd.adjunct map is present.
# So, need to handle the various possibilities

_MAP=passwd.adjunct.byname

if ! present $_MAP $ALL_DMN_DEF_MAPLIST
then

  # Just put the passwd.adjunct syntax in comment form

  echo '# passwd
nisLDAPfieldFromAttribute passwd.byname: \
			rf_key=uid
nisLDAPfieldFromAttribute passwd.byuid: \
			rf_key=uidNumber
nisLDAPfieldFromAttribute passwd: \
			name=uid, \
			uid=uidNumber, \
			("{crypt}%s", passwd)=userPassword, \
			gid=gidNumber, \
			gecos=gecos, \
			home=homeDirectory, \
			shell=loginShell 

#
# If you are using passwd.adjunct, comment the passwd section above
# and uncomment the following passwd and passwd.adjunct sections
#			
# passwd
#nisLDAPfieldFromAttribute passwd.byname: \
#			rf_key=uid
#nisLDAPfieldFromAttribute passwd.byuid: \
#			rf_key=uidNumber
#nisLDAPfieldFromAttribute passwd: \
#			name=uid, \
#			uid=uidNumber, \
#			passwd=("##%s", uid), \
#			gid=gidNumber, \
#			gecos=gecos, \
#			home=homeDirectory, \
#			shell=loginShell

# passwd.adjunct
#nisLDAPfieldFromAttribute passwd.adjunct.byname: \
#			rf_key=uid, \
#			name=uid, \
#			("{crypt}%s", passwd)=userPassword
' >> $MAP_FILE

else

  # Find the domains in which passwd.adjunct map exists.
  find_domains $_MAP DEF_MAPS

  if [ $PRESENT_COUNT -eq $N2L_DMN_CNT ]
  then

    # All the domains have passwd.adjunct map. So, put the right
    # passwd syntax and comment-in the passwd.adjunct syntax.


    echo '# passwd
#nisLDAPfieldFromAttribute passwd.byname: \
#			rf_key=uid
#nisLDAPfieldFromAttribute passwd.byuid: \
#			rf_key=uidNumber
#nisLDAPfieldFromAttribute passwd: \
#			name=uid, \
#			uid=uidNumber, \
#			("{crypt}%s", passwd)=userPassword, \
#			gid=gidNumber, \
#			gecos=gecos, \
#			home=homeDirectory, \
#			shell=loginShell 

#
# If you are not using passwd.adjunct, uncomment the passwd section
# above and comment the following passwd and passwd.adjunct sections
#			
# passwd
nisLDAPfieldFromAttribute passwd.byname: \
			rf_key=uid
nisLDAPfieldFromAttribute passwd.byuid: \
			rf_key=uidNumber
nisLDAPfieldFromAttribute passwd: \
			name=uid, \
			uid=uidNumber, \
			passwd=("##%s", uid), \
			gid=gidNumber, \
			gecos=gecos, \
			home=homeDirectory, \
			shell=loginShell

#
# passwd.adjunct Must follow passwd
#
nisLDAPfieldFromAttribute passwd.adjunct.byname: \
			rf_key=uid, \
			name=uid, \
			("{crypt}%s", passwd)=userPassword
' >> $MAP_FILE

  else
    # Not every domain has passwd.adjunct map.

    # First put the password syntax with domain name for domains
    # in which passwd.adjunct exists.

    echo "# passwd" >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPfieldFromAttribute passwd.byname,${_DMN}: \\
			rf_key=uid
nisLDAPfieldFromAttribute passwd.byuid,${_DMN}: \\
			rf_key=uidNumber
nisLDAPfieldFromAttribute passwd,${_DMN}: \\
			name=uid, \\
			uid=uidNumber, \\
			passwd=(\"##%s\", uid), \\
			gid=gidNumber, \\
			gecos=gecos, \\
			home=homeDirectory, \\
			shell=loginShell
" >> $MAP_FILE
    done

    # Now put the other passwd syntax. We do not need to
    # append the domain name here.

    echo '
nisLDAPfieldFromAttribute passwd.byname: \
			rf_key=uid
nisLDAPfieldFromAttribute passwd.byuid: \
			rf_key=uidNumber
nisLDAPfieldFromAttribute passwd: \
			name=uid, \
			uid=uidNumber, \
			("{crypt}%s", passwd)=userPassword, \
			gid=gidNumber, \
			gecos=gecos, \
			home=homeDirectory, \
			shell=loginShell 
' >> $MAP_FILE

    # Now we need to put the passwd.adjunct syntax for domains
    # in which this map exists.

    echo "#
# passwd.adjunct Must follow passwd
# " >> $MAP_FILE

    for _DMN in $PRESENT_IN_DOMAINS
    do

      echo "\
nisLDAPfieldFromAttribute passwd.adjunct.byname,${_DMN}: \\
			rf_key=uid, \\
			name=uid, \\
			(\"{crypt}%s\", passwd)=userPassword
" >> $MAP_FILE

    done

  fi

fi

echo '
# This map is never created but yppasswd uses the mapping to extract password
# ageing information from the DIT.	
nisLDAPfieldFromAttribute ageing.byname: \
			rf_key=uid, \
			name=uid, \
			lastchg=shadowLastChange, \
			min=shadowMin, \
			max=shadowMax, \
			warn=shadowWarning, \
			inactive=shadowInactive, \
			expire=shadowExpire, \
			flag=shadowFlag

# printers.conf.byname
nisLDAPfieldFromAttribute printers.conf.byname: \
			rf_key=printer-uri, \
			names=("%s|", (printer-aliases), "|"), \
			bsdaddr=("bsdaddr=%s", sun-printer-bsdaddr), \
			kvps=("%s:", (sun-printer-kvp) - yp:bsdaddr), \
			values=("%s:%s", yp:bsdaddr, yp:kvps), \
			values=("%s:", yp:bsdaddr), \
			values=yp:kvps, \
                        rf_comment=description

# prof_attr
nisLDAPfieldFromAttribute prof_attr: \
			rf_key=cn, \
			name=cn, \
			res1=SolarisAttrReserved1, \
			res2=SolarisAttrReserved2, \
			desc=SolarisAttrLongDesc, \
			attrs=SolarisAttrKeyValue

# project
nisLDAPfieldFromAttribute project.byname: \
			rf_key=SolarisProjectName
nisLDAPfieldFromAttribute project.byprojid: \
			rf_key=SolarisProjectID
nisLDAPfieldFromAttribute project: \
			name=SolarisProjectName, \
			projID=SolarisProjectID, \
			comment=description, \
			users=("%s,", (memberUid), ","), \
			groups=("%s,", (memberGid), ","), \
			attrs=("%s;", (SolarisProjectAttr), ";")

# protocols
nisLDAPfieldFromAttribute protocols.byname: \
			("cn=%s,*", rf_key)=dn, \
			(rf_key)=(cn)
nisLDAPfieldFromAttribute protocols.bynumber: \
                        rf_key=ipProtocolNumber, \
                        rf_comment=description
nisLDAPfieldFromAttribute protocols: \
			("cn=%s,*", name)=dn, \
                        number=ipProtocolNumber, \
                        aliases=("%s ", (cn) - yp:name, " ")

# rpc.bynumber
nisLDAPfieldFromAttribute rpc.bynumber: \
			rf_key=oncRpcNumber, \
			number=oncRpcNumber, \
			("cn=%s,*", name)=dn, \
                        aliases=("%s ", (cn) - yp:name, " "), \
			rf_comment=description

# services
nisLDAPfieldFromAttribute services.byname: \
			rf_key = ("%s/%s", ipServicePort, ipServiceProtocol)
nisLDAPfieldFromAttribute services.byservicename: \
			(rf_key)=("%s/%s", cn, ipServiceProtocol), \
			(rf_key)=(cn)
nisLDAPfieldFromAttribute services: \
			("cn=%s+ipServiceProtocol=*", name)=dn, \
     			protocol=ipServiceProtocol, \
     			port=ipServicePort, \
                        aliases=("%s ", (cn) - yp:name, " "), \
                        rf_comment=description

# timezone.byname
nisLDAPfieldFromAttribute timezone.byname: \
			rf_key=cn, \
			hostName=cn, \
			zoneName=nisplusTimeZone, \
			rf_comment=description

# user_attr
nisLDAPfieldFromAttribute user_attr: \
			("uid=%s,*", rf_key)=dn, \
			("uid=%s,*", user)=dn, \
			qualifier=SolarisUserAttr, \
			res1=SolarisUserReserved1, \
			res2=SolarisUserReserved2, \
			attrs=SolarisAttrKeyValue

# publickey.byname
nisLDAPfieldFromAttribute keys.host: \
			("cn=%s+ipHostNumber=*", cname)=dn, \
			rf_key=("unix.%s@%s", yp:cname, yp:rf_domain), \
			publicKey=nisPublicKey, \
			secretKey=nisSecretKey

nisLDAPfieldFromAttribute keys.pass: \
			rf_key=("unix.%s@%s", uidNumber, yp:rf_domain), \
			publicKey=nisPublicKey, \
			secretKey=nisSecretKey

nisLDAPfieldFromAttribute keys.nobody: \
			rf_key=uid, \
			publicKey=nisPublicKey, \
			secretKey=nisSecretKey

# ypservers. This derived from IPlanet implementation not RFC.
nisLDAPfieldFromAttribute ypservers: \
			rf_key=cn
' >> $MAP_FILE
}


#
# List all the non-default auto.* and custom maps.
#
list_auto_and_custom_nisLDAPfieldFromAttribute()
{

# auto.* entries are easy. 
if [ ${#ALL_DMN_AUTO_CUST_MAPS[*]} -gt 0 ]; then
  echo "# Non-default custom auto maps (auto.*)\n" >> $MAP_FILE
fi

for _MAP in ${ALL_DMN_AUTO_CUST_MAPS[*]}
do
  echo "\
# ${_MAP}
nisLDAPfieldFromAttribute ${_MAP}: \\
                        rf_key=automountKey, \\
                        value=automountInformation
" >> $MAP_FILE
done

# Since we do not have enough information to generate
# entries for other custom maps, best we can do is to
# log this map names and ask user to take care of them.

ask_user_to_update_the_custom_map_entries_too

}


#
# List mapping of named fields from DIT entries
#
create_nisLDAPfieldFromAttribute()
{

[ CUST_CMT_NEEDED -eq 1 ] && echo '
# nisLDAPfieldFromAttribute : It specifies how a NIS entries
# field values  are derived from LDAP attribute values. 
# 
# The format of nisLDAPfieldFromAttribute is :
# mapName ":" fieldattrspec *("," fieldattrspec)
' >> $MAP_FILE

# List all the default entries anyway.
list_default_nisLDAPfieldFromAttribute

# List all the non-default auto.* and custom maps.
list_auto_and_custom_nisLDAPfieldFromAttribute

echo "
#
#------------------------------------------------------------------------------
#			 
" >> $MAP_FILE
}



# Main function for creating the mapping file
create_mapping_file()
{
# Ask user the list of domains to be served by N2L
create_n2l_domain_list

# If there are no N2L domains or none selected, then exit 
if [ $N2L_DMN_CNT -eq 0 ]; then
  echo "There are no domains to serve. No mapping file generated."
  return 1
fi

while :
do
  get_ans "Enter the mapping file name (h=help):" "${MAP_FILE}"

  # If help continue, otherwise break.
  case "$ANS" in
    [Hh] | help | Help | \?) display_msg new_mapping_file_name_help ;;
                         * ) break ;;
  esac
done

MAP_FILE=${ANS}
[ $DEBUG -eq 1 ] && MAP_FILE = $MAP_FILE

# Backup existing mapping file if selected
check_back_mapping_file

# To prevent from leaving a partial mapping file in case some error
# or signal takes place which might result in machine starting in N2L
# mode at next reboot, store the output being generated in a temporary
# file first, and move it at the final destination only at the end if
# everything goes fine.

_MAP_FILE=$MAP_FILE
MAP_FILE=${TMPDIR}/${TMPMAP}.$$

echo "Generating mapping file temporarily as \"${MAP_FILE}\""

# Place copyright information
put_mapping_file_copyright_info


# Prepare various map lists for each domain
create_map_lists

# List domains and contexts
get_nisLDAPdomainContext

# List domains for which passwords should be changed
get_nisLDAPyppasswddDomains

# List databaseId mappings (aliases)
create_nisLDAPdatabaseIdMapping

# List comment character for maps
create_nisLDAPcommentChar

# List SECURE and INTERDOMAIN flags
create_nisLDAPmapFlags

# List TTL values
 create_nisLDAPentryTtl

# List name fields
create_nisLDAPnameFields

# List split fields and repeated fields seperators.
create_split_field_and_repeatedfield_seperators

# List association of maps with RDNs and object classes.
create_nisLDAPobjectDN

# List mapping of named fields to DIT entries
create_nisLDAPattributeFromField

# List mapping of named fields from DIT entries
create_nisLDAPfieldFromAttribute


# We are done, so move back the mapping file from temp. location
# to actual location.
# In case the mapping file name has a directory component which does
# not exist, then create it now, otherwise 'mv' will return error.

DIR_TO_CREATE=`dirname ${_MAP_FILE}`
mkdir -p ${DIR_TO_CREATE}

echo "Moving output from temporary file ($MAP_FILE) to actual file ($_MAP_FILE)"
mv $MAP_FILE $_MAP_FILE

# Revert back the mapping file name in case needed.
MAP_FILE=$_MAP_FILE
echo "Finished creation of mapping file ( $MAP_FILE )"

}


#
# Main function for creating config file (ypserv)
#
process_config_file()
{
# Ask for confirmation if the file name is not specified.

if [ $CONFIG_FILE_SPECIFIED -eq 0 ]; then
  display_msg no_config_file_name_specified

  get_confirm_nodef "Do you want to create the config file (y/n) ?"
  
  [ $? -eq 0 ] && return 0

  while :
  do
    get_ans "Enter the config file name (h=help):" "${CONFIG_FILE}"

    # If help continue, otherwise break.
    case "$ANS" in
      [Hh] | help | Help | \?) display_msg new_config_file_name_help ;;
                           * ) break ;;
    esac
  done

  CONFIG_FILE=${ANS}
  [ $DEBUG -eq 1 ] && CONFIG_FILE = $CONFIG_FILE

fi

# Backup existing config file if selected
check_back_config_file

# Create config file
create_config_file
}


#
# Main function for creating mapping file (NISLDAPmapping)
#
process_mapping_file()
{
# Ask for confirmation if the file name is not specified.

if [ $MAPPING_FILE_SPECIFIED -eq 0 ]; then
  display_msg no_mapping_file_name_specified

  get_confirm_nodef "Do you want to create the mapping file (y/n) ?"
  
  [ $? -eq 0 ] && return 0


fi

# Create mapping file
create_mapping_file
}

###########################################
###########	   MAIN		###########
###########################################

PROG=`basename $0`	# Program name
ABS_PROG=$0		# absolute path needed

# Only superuser should be able to run this script.
is_root_user
if [ $? -ne 0 ]; then
  echo "ERROR : Only root can run $PROG"
  exit 1
fi

# Initialize things
init

# Parse command line arguments.  
parse_arg $*

# Create config file (ypserv)
process_config_file

# Create mapping file (NISLDAPmapping).
process_mapping_file

# Cleanup temp files and directories unless debug.
[ $DEBUG -eq 0 ] && cleanup

exit 0
