#!/sbin/sh
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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
#

IPFILTER_FMRI="svc:/network/ipfilter:default"
ETC_IPF_DIR=/etc/ipf
IPNATCONF=`/usr/bin/svcprop -p config/ipnat_config_file $IPFILTER_FMRI \
    2>/dev/null`
if [ $? -eq 1 ]; then
	IPNATCONF=$ETC_IPF_DIR/ipnat.conf
fi
IPPOOLCONF=`/usr/bin/svcprop -p config/ippool_config_file $IPFILTER_FMRI \
    2>/dev/null`
if [ $? -eq 1 ]; then
	IPPOOLCONF=$ETC_IPF_DIR/ippool.conf
fi
VAR_IPF_DIR=/var/run/ipf
IPFILCONF=$VAR_IPF_DIR/ipf.conf
IP6FILCONF=$VAR_IPF_DIR/ipf6.conf
IPFILOVRCONF=$VAR_IPF_DIR/ipf_ovr.conf
IP6FILOVRCONF=$VAR_IPF_DIR/ipf6_ovr.conf
IPF_LOCK=/var/run/ipflock
CONF_FILES=""
CONF6_FILES=""
NAT_FILES=""
IPF_SUFFIX=".ipf"
IPF6_SUFFIX=".ipf6"
NAT_SUFFIX=".nat"

# version for configuration upgrades
CURRENT_VERSION=1

IPF_FMRI="svc:/network/ipfilter:default"
INETDFMRI="svc:/network/inetd:default"
RPCBINDFMRI="svc:/network/rpc/bind:default"

SMF_ONLINE="online"
SMF_MAINT="maintenance"
SMF_NONE="none"

FW_CONTEXT_PG="firewall_context"
METHOD_PROP="ipf_method"

FW_CONFIG_PG="firewall_config"
POLICY_PROP="policy"
APPLY2_PROP="apply_to"
APPLY2_6_PROP="apply_to_6"
EXCEPTIONS_PROP="exceptions"
EXCEPTIONS_6_PROP="exceptions_6"
TARGET_PROP="target"
TARGET_6_PROP="target_6"
BLOCKPOL_PROP="block_policy"

FW_CONFIG_DEF_PG="firewall_config_default"
FW_CONFIG_OVR_PG="firewall_config_override"
CUSTOM_FILE_PROP="custom_policy_file"
CUSTOM_FILE_6_PROP="custom_policy_file_6"
OPEN_PORTS_PROP="open_ports"

PREFIX_HOST="host:"
PREFIX_NET="network:"
PREFIX_POOL="pool:"
PREFIX_IF="if:"

GLOBAL_CONFIG=""
GLOBAL_POLICY=""
GLOBAL_BLOCK_POLICY=""

SERVINFO=/usr/lib/servinfo

#
# Get value(s) for given property from either firewall_config_default or
# firewall_config_override property groups.
# 
# global_get_prop_value pg_name propname
#   pg_name - FW_CONFIG_DEF_PG or FW_CONFIG_OVR_PG 
#   propname - property name
#
global_get_prop_value()
{
	target_pg=$1
	prop=$2

	[ "$1" != $FW_CONFIG_OVR_PG -a "$1" != $FW_CONFIG_DEF_PG ] && return

	[ "$1" == $FW_CONFIG_DEF_PG ] && extra_pg=$FW_CONFIG_OVR_PG  || \
		extra_pg=$FW_CONFIG_DEF_PG

	value=`echo $GLOBAL_CONFIG | awk '{
		found=0
		for (i=1; i<=NF; i++) {
			if (found == 1) {
				if (index($i, target_pg) == 1 || index($i, extra_pg) == 1)
					break;

				print $i;
			}

			if (split($i, values, "/") < 2)
				continue;

			if (values[1] == target_pg && values[2] == prop)
				found=1;
		}
	}' target_pg=$target_pg prop=$prop extra_pg=$extra_pg`

	# Return
	echo "$value"
}

#
# Initialize and cache network/ipfilter configuration, global configuration.
#
# Since an SMF service configuration may get updated during the execution of the
# service method, it's best to read all relevant configuration via one svcprop
# invocation and cache it for later use.
#
# This function reads and stores relevant configuration into GLOBAL_CONFIG and
# initializes the GLOBAL_POLICY and GLOBAL_BLOCK_POLICY variables. GLOBAL_CONFIG
# is a string containing pg/prop and their corresponding values (i.e. svcprop -p
# pg fmri output). To get values for a certain pg/prop, use
# global_get_prop_value().
#
global_init()
{
	GLOBAL_CONFIG=`svcprop -p ${FW_CONFIG_OVR_PG} -p ${FW_CONFIG_DEF_PG} \
        $IPF_FMRI 2>/dev/null | awk '{$2=" "; print $0}'`

	GLOBAL_POLICY=`global_get_prop_value $FW_CONFIG_DEF_PG $POLICY_PROP`
        GLOBAL_BLOCK_POLICY=`global_get_prop_value $FW_CONFIG_DEF_PG \
	   $BLOCKPOL_PROP`
}

#
# Given a service, gets its config pg name 
#
get_config_pg()
{
	if [ "$1" = "$IPF_FMRI" ]; then
		echo "$FW_CONFIG_DEF_PG"
	else
		echo "$FW_CONFIG_PG"
	fi
	return 0
}

#
# Given a service, gets its firewall policy
#
get_policy()
{
	config_pg=`get_config_pg $1`
	svcprop -p $config_pg/${POLICY_PROP} $1 2>/dev/null
}

#
# block policy can be set to "return", which will expand into
# separate block rules for tcp (block return-rst ...) and all other
# protocols (block return-icmp-as-dest ...)
#
get_block_policy()
{
	config_pg=`get_config_pg $1`
	svcprop -p $config_pg/${BLOCKPOL_PROP} $1 2>/dev/null
}

#
# Given a service, gets its source address exceptions for IPv4
#
get_exceptions()
{
	config_pg=`get_config_pg $1`
	exceptions=`svcprop -p $config_pg/${EXCEPTIONS_PROP} $1 2>/dev/null`
        echo $exceptions | sed -e 's/\\//g'
}

#
# Given a service, gets its source address exceptions for IPv6
#
get_exceptions_6()
{
	config_pg=`get_config_pg $1`
	exceptions6=`svcprop -p $config_pg/${EXCEPTIONS_6_PROP} $1 2>/dev/null`
        echo $exceptions6 | sed -e 's/\\//g'
}

#
# Given a service, gets its firewalled source addresses for IPv4
#
get_apply2_list()
{
	config_pg=`get_config_pg $1`
	apply2=`svcprop -p $config_pg/${APPLY2_PROP} $1 2>/dev/null`
        echo $apply2 | sed -e 's/\\//g'
}

#
# Given a service, gets its firewalled source addresses for IPv6
#
get_apply2_6_list()
{
	config_pg=`get_config_pg $1`
	apply2_6=`svcprop -p $config_pg/${APPLY2_6_PROP} $1 2>/dev/null`
        echo $apply2_6 | sed -e 's/\\//g'
}

#
# Given a service, gets its firewalled target addresses for IPv4
#
get_target_list()
{
	config_pg=`get_config_pg $1`
	target=`svcprop -p $config_pg/${TARGET_PROP} $1 2>/dev/null`
	[ -z "$target" -o "$target" = '""' ] && target=any
	echo $target | sed -e 's/\\//g'
}

#
# Given a service, gets its firewalled target addresses for IPv6
#
get_target_6_list()
{
	config_pg=`get_config_pg $1`
	target6=`svcprop -p $config_pg/${TARGET_6_PROP} $1 2>/dev/null`
	[ -z "$target6" -o "$target6" = '""' ] && target6=any
	echo $target6 | sed -e 's/\\//g'
}

check_ipf_dir()
{
	[ -d $VAR_IPF_DIR ] && return 0
	mkdir $VAR_IPF_DIR >/dev/null 2>&1 || return 1
}

#
# fmri_to_file fmri suffix
#
fmri_to_file()
{
	check_ipf_dir || return 1
	fprefix="${VAR_IPF_DIR}/`echo $1 | tr -s '/:' '__'`"
	echo "${fprefix}${2}"
}

#
# Return service's enabled property
#
service_is_enabled()
{
	#
	# Temporary enabled state overrides the persistent state
	# so check it first.
	#
	enabled_ovr=`svcprop -c -p general_ovr/enabled $1 2>/dev/null`
	if [ -n "$enabled_ovr" ]; then
		[ "$enabled_ovr" = "true" ] && return 0 || return 1
	fi

	enabled=`svcprop -c -p general/enabled $1 2>/dev/null`
	[ -n "$enabled" -a "$enabled" = "true" ] && return 0 || return 1
}

#
# Return whether service is desired state
#
# Args: fmri state
# Return:
#  0 - desired state is service's current state  
#  1 - desired state is not service's current state  
#
service_check_state()
{
	#
	# Make sure we're done with ongoing state transition
	#
	while [ "`svcprop -p restarter/next_state $1`" != "$SMF_NONE" ]; do
		sleep 1
	done
	
	[ "`svcprop -p restarter/state $1`" = "$2" ] && return 0 || return 1
}

#
# Deny/Allow list stores values in the form "host:addr", "network:addr/netmask",
# "pool:number", and "if:interface". This function returns the
# IP(addr or addr/netmask) value or a pool number.
#
get_IP()
{
	value_is_interface $1 && return 1
	echo "$1" | sed -n -e "s,^${PREFIX_POOL}\(.*\),pool/\1,p" \
	    -e "s,^${PREFIX_HOST}\(.*\),\1,p" \
	    -e "s,^${PREFIX_NET}\(.*\),\1,p" \
	    -e "s,^any,any,p"
}

get_interface()
{
	value_is_interface $1 || return 1
	scratch=`echo "$1" | sed -e "s/^${PREFIX_IF}//"`

	ifconfig $scratch >/dev/null 2>&1 || return 1
	echo $scratch | sed -e 's/:.*//'
}

#
#
#
value_is_interface()
{
	[ -z "$1" ] && return 1
	echo $1 | grep "^${PREFIX_IF}" >/dev/null 2>&1
}

#
# Remove rules in given file from active list without restarting ipfilter
#
remove_rules()
{
	[ -f "$1" ] && ipf $2 -r -f $1 >/dev/null 2>&1
}

remove_nat_rules()
{
	[ -f "$1" ] && ipnat -r -f $1 >/dev/null 2>&1
}

check_ipf_syntax()
{
	ipf $2 -n -f $1 >/dev/null 2>&1
}

check_nat_syntax()
{
	ipnat -n -f $1 >/dev/null 2>&1
}

unique_ports()
{
	echo $* | xargs -n 1 echo | sort -u
}

file_get_ports()
{
	ipf $2 -n -v -f $1 2>/dev/null | sed -n -e \
	    's/.*to.* port = \([a-z0-9]*\).*/\1/p' | uniq | \
	    awk '{if (length($0) > 1) {printf("%s ", $1)}}'
}

get_active_ports()
{
	ipfstat $1 -io 2>/dev/null | sed -n -e \
	    's/.*to.* port = \([a-z0-9]*\).*/\1/p' | uniq | \
	    awk '{if (length($0) > 1) {printf("%s ",$1)}}'
}

#
# Given two list of ports, return failure if there's a duplicate.
#
sets_check_duplicate()
{
	#
	# If either list is empty, there isn't any conflict.
	#
	[ -z "$1" -o -z "$2" ] && return 0

	for p in $1; do
		for ap in $2; do
			[ "$p" = "$ap" ] && return 1
		done
	done

	return 0
}

#
# Given a file containing ipf rules, check the syntax and verify
# the rules don't conflict, use same port number, with active
# rules (ipfstat -io output).
#
update_check_ipf_rules()
{
	check_ipf_syntax $1 $2 || return 1

	lports=`file_get_ports $1 $2`
	lactive_ports=`get_active_ports $2`

	sets_check_duplicate "$lports" "$lactive_ports" || return 1
}

server_port_list=""
server_port_list_6=""

#
# Given a file containing ipf rules, check the syntax and verify
# the rules don't conflict with already processed services.
#
# The list of processed services' ports are maintained in the global
# variables 'server_port_list' and 'server_port_list_6'.
#
check_ipf_rules()
{

	check_ipf_syntax $1 $2 || return 1

	lports=`file_get_ports $1 $2`

	if [ "$2" = "-6" ]; then
		sets_check_duplicate "$lports" "$server_port_list_6" || return 1
	        server_port_list_6="$server_port_list_6 $lports"
	else
		sets_check_duplicate "$lports" "$server_port_list" || return 1
	        server_port_list="$server_port_list $lports"
	fi

	return 0
}

prepend_new_rules()
{
	check_ipf_syntax $1 $2 && tail -r $1 | sed -e 's/^[a-z]/@0 &/' | \
	    ipf $2 -f - >/dev/null 2>&1
}

append_new_rules()
{
	check_ipf_syntax $1 $2 && ipf $2 -f $1 >/dev/null 2>&1
}

append_new_nat_rules()
{
	check_nat_syntax $1 && ipnat -f $1 >/dev/null 2>&1
}

#
# get port information from string of the form "proto:{port | port-port}"
#
tuple_get_port()
{
	port_str=`echo "$1" | sed -e 's/ //g; s/.*://' 2>/dev/null`
	[ -z "$port_str" ] && return 1

	echo $port_str | grep "-" >/dev/null
	if  [ $? -eq  0 ]; then
		echo $port_str | grep '^[0-9]\{1,5\}-[0-9]\{1,5\}$' >/dev/null || \
		    return 1
		ports=`echo $port_str | ( IFS=- read a b ; \
		    [ $a \-le $b ] && echo $a $b || echo $b $a )`

		for p in $ports; do
			[ $p -gt 65535 ] && return 1
		done
		echo "$ports"
	else
		#
		# port_str is a single port, verify and return it.
		#
		echo "$port_str" | grep '^[0-9]\{1,5\}$' >/dev/null || return 1
		[ $port_str -gt 65535 ] && return 1
		echo "$port_str"
	fi
}

#
# get proto info from string of the form "{tcp | udp}:port"
#
tuple_get_proto()
{
	proto=`echo "$1" | sed -e 's/ //g; s/:.*//' 2>/dev/null`
	[ -z "$proto" ] && return 0

	[ "$proto" = "tcp" -o "$proto" = "udp" ] && echo $proto || return 1
	return 0
}

ipf_get_lock()
{
	newpid=$$

	if [ -f "$IPF_LOCK/pid" ]; then
		curpid=`cat $IPF_LOCK/pid 2>/dev/null`
		[ "$curpid" = "$newpid" ] && return 0

		#
		# Clear lock if the owning process is no longer around.
		#
		ps -p $curpid >/dev/null 2>&1 || rm -r $IPF_LOCK >/dev/null 2>&1
	fi

	#
	# Grab the lock
	#
	while :; do
		mkdir $IPF_LOCK 2>/dev/null && break;
		sleep 1
	done
	echo $newpid > $IPF_LOCK/pid
}

#
# Remove lock if it's ours
#
ipf_remove_lock()
{
	if [ -f "$IPF_LOCK/pid" ]; then
		[ "`cat $IPF_LOCK/pid`" = "$$" ] && rm -r $IPF_LOCK
	fi
	return 0
}

#
# Make IPFILCONF, /var/tmp/ipf/ipf.conf, a symlink to the input file argument.
#
custom_set_symlink()
{
	#
	# Nothing to do if the input file doesn't exist.
	#
	[ ! -f "$1" ] && return 0

	check_ipf_dir || return 1

	rm $IPFILCONF >/dev/null 2>&1
	ln -s $1 $IPFILCONF >/dev/null 2>&1
}

#
# New file replaces original file if they have different content
#
replace_file()
{
	orig=$1	
	new=$2	

	#
	# IPFILCONF may be a symlink, remove it if that's the case
	#
	if [ -L "$orig" ]; then
		rm $orig
		touch $orig
	fi

	check_ipf_dir || return 1
	mv $new $orig && return 0 || return 1
}

#
# Given a service, gets the following details for ipf rule:
# - policy
# - protocol
# - port(IANA port obtained by running servinfo)
#
process_server_svc()
{
	service=$1
        policy=`get_policy ${service}`

	#
	# Empties service's rules file so callers won't use existing rule if
	# we fail here.
	#
	file=`fmri_to_file $service $IPF_SUFFIX`
	file6=`fmri_to_file $service $IPF6_SUFFIX`
	[ -z "$file" ] && return 1
	echo "# $service" >${file}
	echo "# $service" >${file6}

	#
	# Nothing to do if policy is "use_global"
	#
	[ "$policy" = "use_global" ] && return 0

	restarter=`svcprop -p general/restarter $service 2>/dev/null`
	if [ "$restarter" = "$INETDFMRI" ]; then
		iana_name=`svcprop -p inetd/name $service 2>/dev/null`
		isrpc=`svcprop -p inetd/isrpc $service 2>/dev/null`
	else
		iana_name=`svcprop -p $FW_CONTEXT_PG/name $service 2>/dev/null`
		isrpc=`svcprop -p $FW_CONTEXT_PG/isrpc $service 2>/dev/null`
	fi

	#
	# Bail if iana_name isn't defined. Services with static rules
	# like nis/client don't need to generate rules using
	# iana name and protocol information.
	# 
	[ -z "$iana_name" ] && return 1

	#
	# RPC services
	#
	if [ "$isrpc" = "true" ]; then
		# The ports used for IPv6 are usually also reachable
		# through IPv4, so generate IPv4 rules for them, too.
		tports=`$SERVINFO -R -p -t -s $iana_name 2>/dev/null`
		tports6=`$SERVINFO -R -p -t6 -s $iana_name 2>/dev/null`
		if [ -n "$tports" -o -n "$tports6" ]; then
			tports=`unique_ports $tports $tports6`
			for tport in $tports; do 
				generate_rules $service $policy "tcp" \
				    $tport $file
			done
		fi

		if [ -n "$tports6" ]; then
			for tport6 in $tports6; do
				generate_rules $service $policy "tcp" \
				    $tport6 $file6 _6
			done
		fi

		uports=`$SERVINFO -R -p -u -s $iana_name 2>/dev/null`
		uports6=`$SERVINFO -R -p -u6 -s $iana_name 2>/dev/null`
		if [ -n "$uports" ]; then
			uports=`unique_ports $uports $uports6`
			for uport in $uports; do 
				generate_rules $service $policy "udp" \
				    $uport $file
			done
		fi

		if [ -n "$uports6" ]; then
			for uport6 in $uports6; do
				generate_rules $service $policy "udp" \
				    $uport6 $file6 _6
			done
		fi

		return 0
	fi

	#
	# Get the IANA port and supported protocols(tcp and udp)
	#
	tport=`$SERVINFO -p -t -s $iana_name 2>&1`
	if [ $? -eq 0 -a -n "$tport" ]; then
		generate_rules $service $policy "tcp" $tport $file
	fi

	tport6=`$SERVINFO -p -t6 -s $iana_name 2>&1`
	if [ $? -eq 0 -a -n "$tport6" ]; then
		generate_rules $service $policy "tcp" $tport6 $file6 _6
	fi

	uport=`$SERVINFO -p -u -s $iana_name 2>&1`
	if [ $? -eq 0 -a -n "$uport" ]; then
		generate_rules $service $policy "udp" $uport $file
	fi

	uport6=`$SERVINFO -p -u6 -s $iana_name 2>&1`
	if [ $? -eq 0 -a -n "$uport6" ]; then
		generate_rules $service $policy "udp" $uport6 $file6 _6
	fi

	return 0
}

#
# Given a service's name, policy, protocol and port, generate ipf rules
# - list of host/network/interface to apply policy
#
# A 'use_global' policy inherits the system-wided Global Default policy
# from network/ipfilter. For {deny | allow} policies, the rules are
# ordered as:
#
# - make exceptions to policy for those in "exceptions" list
# - apply policy to those specified in "apply_to" list 
# - policy rule
#
generate_rules()
{
	service=$1
	mypolicy=$2
	proto=$3
	port=$4
	out=$5
	_6=$6

	#
	# Default mode is to inherit from global's policy
	#
	[ "$mypolicy" = "use_global" ] && return 0

	tcp_opts=""
	[ "$proto" = "tcp" ] && tcp_opts="flags S keep state keep frags"

	block_policy=`get_block_policy $1`
        if [ "$block_policy" = "use_global" ]; then
		block_policy=${GLOBAL_BLOCK_POLICY}
        fi

	if [ "$block_policy" = "return" ]; then
		[ "$proto" = "tcp" ] && block_policy="return-rst"
		[ "$proto" != "tcp" ] && block_policy="return-icmp-as-dest"
	else
		block_policy=""
        fi

	iplist=`get_target${_6}_list $service`

	#
	# Allow all if policy is 'none'
	#
	if [ "$mypolicy" = "none" ]; then
		for ip in $iplist; do
			daddr=`get_IP ${ip}`
			[ -z "$daddr" -o "$daddr" = '""' ] && continue
			echo "pass in log quick proto ${proto} from any to ${daddr}" \
			    "port = ${port} ${tcp_opts}" >>${out}
		done
		return 0
	fi

	#
	# For now, let's concern ourselves only with incoming traffic.
	#
	[ "$mypolicy" = "deny" ] && { ecmd="pass"; acmd="block ${block_policy}"; }
	[ "$mypolicy" = "allow" ] && { ecmd="block ${block_policy}"; acmd="pass"; }

	for name in `get_exceptions${_6} $service`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			for ip in $iplist; do
				daddr=`get_IP ${ip}`
				[ -z "$daddr" -o "$daddr" = '""' ] && continue
				echo "${ecmd} in log quick on ${ifc} from any to" \
				    "${daddr} port = ${port}" >>${out}
			done
			continue
		fi

		saddr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$saddr" ]; then
			for ip in $iplist; do
				daddr=`get_IP ${ip}`
				[ -z "$daddr" -o "$daddr" = '""' ] && continue
				echo "${ecmd} in log quick proto ${proto} from ${saddr}" \
				    "to ${daddr} port = ${port} ${tcp_opts}" >>${out}
			done
		fi
	done

	for name in `get_apply2${_6}_list $service`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			for ip in $iplist; do
				daddr=`get_IP ${ip}`
				[ -z "$daddr" -o "$daddr" = '""' ] && continue
				echo "${acmd} in log quick on ${ifc} from any to" \
				    "${daddr} port = ${port}" >>${out}
			done
			continue
		fi

		saddr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$saddr" ]; then
			for ip in $iplist; do
				daddr=`get_IP ${ip}`
				[ -z "$daddr" -o "$daddr" = '""' ] && continue
				echo "${acmd} in log quick proto ${proto} from ${saddr}" \
				    "to ${daddr} port = ${port} ${tcp_opts}" >>${out}
			done
		fi
	done

	for ip in $iplist; do
		daddr=`get_IP ${ip}`
		[ -z "$daddr" -o "$daddr" = '""' ] && continue
		echo "${ecmd} in log quick proto ${proto} from any to ${daddr}" \
		    "port = ${port} ${tcp_opts}" >>${out}
	done

	return 0
}

#
# Service has either IANA ports and proto or its own firewall method to
# generate the rules.
#
# - if service has a custom method, use it to populate its rules
# - if service has a firewall_config pg, use process_server_svc
#
# Argument - fmri
#
process_service()
{
	#
	# Don't process network/ipfilter
	#
	[ "$1" = "$IPF_FMRI" ] && return 0

	service_check_state $1 $SMF_MAINT && return 1

	method=`svcprop -p $FW_CONTEXT_PG/$METHOD_PROP $1 2>/dev/null | \
	    sed 's/\\\//g'`
	if [ -n "$method" -a "$method" != '""' ]; then
		( exec $method $1 >/dev/null )
	else
		svcprop -p $FW_CONFIG_PG $1 >/dev/null 2>&1 || return 1
		process_server_svc $1 || return 1
	fi
	return 0
}

#
# Generate rules for protocol/port defined in firewall_config_default/open_ports
# property. These are non-service programs whose network resource info are
# defined as "{tcp | upd}:{PORT | PORT-PORT}". Essentially, these programs need
# some specific local ports to be opened. For example, BitTorrent clients need to
# have 6881-6889 opened.
#
process_nonsvc_progs()
{
	out=$1
	echo "# Non-service programs rules" >>${out}
	progs=`global_get_prop_value $FW_CONFIG_DEF_PG $OPEN_PORTS_PROP`

	for prog in $progs; do
		[ -z "$prog" -o "$prog" = '""' ] && continue

		port=`tuple_get_port $prog`
		[ $? -eq 1 -o -z "$port" ] && continue

		proto=`tuple_get_proto $prog`
		[ $? -eq 1 ] && continue

		set -- $port
		if  [ $# -gt 1 ]; then
			if [ -z "$proto" ]; then
				echo "pass in log quick from any to any" \
				    "port ${1} >< ${2}" >>${out}
			else
				echo "pass in log quick proto ${proto} from any" \
				    "to any port ${1} >< ${2}" >>${out}
			fi
		else
			if [ -z "$proto" ]; then
				echo "pass in log quick from any to any" \
				    "port = ${1}" >>${out}
			else
				echo "pass in log quick proto ${proto} from any" \
				    "to any port = ${1}" >>${out}
			fi
		fi
	done

	return 0
}

#
# Generate a new /etc/ipf/ipf.conf. If firewall policy is 'none',
# ipf.conf is empty .
#
create_global_rules()
{
	if [ "$GLOBAL_POLICY" = "custom" ]; then
		file=`global_get_prop_value $FW_CONFIG_DEF_PG $CUSTOM_FILE_PROP`
		file6=`global_get_prop_value $FW_CONFIG_DEF_PG $CUSTOM_FILE_6_PROP`

		[ -n "$file" ] && custom_set_symlink $file
		[ -n "$file6" ] && custom_set_symlink $file6

		return 0
	fi

	TEMP=`mktemp /var/run/ipf.conf.pid$$.XXXXXX`
	TEMP6=`mktemp /var/run/ipf6.conf.pid$$.XXXXXX`
	process_nonsvc_progs $TEMP
	process_nonsvc_progs $TEMP6

	echo "# Global Default rules" >>${TEMP}
	echo "# Global Default rules" >>${TEMP6}
	if [ "$GLOBAL_POLICY" != "none" ]; then
		echo "pass out log quick all keep state" >>${TEMP}
		echo "pass out log quick all keep state" >>${TEMP6}
	fi

	case "$GLOBAL_POLICY" in
	'none')
		# No rules
		replace_file ${IPFILCONF} ${TEMP}
		replace_file ${IP6FILCONF} ${TEMP6}
		return $?
		;;
	
	'deny')
		ecmd="pass"
		acmd="block"
		;;

	'allow')
		ecmd="block"
		acmd="pass"
		;;
	*)
		return 1;
		;;
	esac

	for name in `global_get_prop_value $FW_CONFIG_DEF_PG $EXCEPTIONS_PROP`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${ecmd} in log quick on ${ifc} all" >>${TEMP} 
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${ecmd} in log quick from ${addr} to any" >>${TEMP}
		fi

	done

	for name in `global_get_prop_value $FW_CONFIG_DEF_PG $EXCEPTIONS_6_PROP`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${ecmd} in log quick on ${ifc} all" >>${TEMP6}
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${ecmd} in log quick from ${addr} to any" >>${TEMP6}
		fi

	done

	for name in `global_get_prop_value $FW_CONFIG_DEF_PG $APPLY2_PROP`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${acmd} in log quick on ${ifc} all" >>${TEMP}
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${acmd} in log quick from ${addr} to any" >>${TEMP}
		fi
	done

	for name in `global_get_prop_value $FW_CONFIG_DEF_PG $APPLY2_6_PROP`; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${acmd} in log quick on ${ifc} all" >>${TEMP6}
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${acmd} in log quick from ${addr} to any" >>${TEMP6}
		fi
	done

	if [ "$GLOBAL_POLICY" = "allow" ]; then
		#
		# Allow DHCP(v6) traffic if running as a DHCP client
		#
		/sbin/netstrategy | grep dhcp >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			echo "pass out log quick from any port = 68" \
			    "keep state" >>${TEMP}
			echo "pass in log quick from any to any port = 68" >>${TEMP}

			echo "pass out log quick from any port = 546" \
			    "keep state" >>${TEMP6}
			echo "pass in log quick from any to any port = 546" >>${TEMP6}
		fi
		echo "block in log all" >>${TEMP}
		echo "block in log all" >>${TEMP6}
	fi

	replace_file ${IPFILCONF} ${TEMP}
	replace_file ${IP6FILCONF} ${TEMP6}
	return $?
}

#
# Generate a new /etc/ipf/ipf_ovr.conf, the override system-wide policy. It's
# a simplified policy that doesn't support 'exceptions' entities.
#
# If firewall policy is "none", no rules are generated.
#
# Note that "pass" rules don't have "quick" as we don't want
# them to override services' block rules.
#
create_global_ovr_rules()
{
	#
	# Simply empty override file if global policy is 'custom'
	#
	if [ "$GLOBAL_POLICY" = "custom" ]; then 
		echo "# 'custom' global policy" >$IPFILOVRCONF
		echo "# 'custom' global policy" >$IP6FILOVRCONF
		return 0
	fi

	#
	# Get and process override policy
	#
	ovr_policy=`global_get_prop_value $FW_CONFIG_OVR_PG $POLICY_PROP`
	if [ "$ovr_policy" = "none" ]; then 
		echo "# global override policy is 'none'" >$IPFILOVRCONF
		echo "# global override policy is 'none'" >$IP6FILOVRCONF
		return 0
	fi

	TEMP=`mktemp /var/run/ipf_ovr.conf.pid$$.XXXXXX`
	[ "$ovr_policy" = "deny" ] && acmd="block in log quick"
	[ "$ovr_policy" = "allow" ] && acmd="pass in log"

	apply2_list=`global_get_prop_value $FW_CONFIG_OVR_PG $APPLY2_PROP`
	for name in $apply2_list; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${acmd} on ${ifc} all" >>${TEMP}
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${acmd} from ${addr} to any" >>${TEMP}
		fi
	done

	apply2_6_list=`global_get_prop_value $FW_CONFIG_OVR_PG $APPLY2_6_PROP`
	for name in $apply2_6_list; do
		[ -z "$name" -o "$name" = '""' ] && continue

		ifc=`get_interface $name`
		if [ $? -eq 0 -a -n "$ifc" ]; then
			echo "${acmd} on ${ifc} all" >>${TEMP6}
			continue
		fi

		addr=`get_IP ${name}`
		if [ $? -eq 0 -a -n "$addr" ]; then
			echo "${acmd} from ${addr} to any" >>${TEMP6}
		fi
	done

	replace_file ${IPFILOVRCONF} ${TEMP}
	replace_file ${IP6FILOVRCONF} ${TEMP6}
	return $?
}

#
# Service is put into maintenance state due to its invalid firewall
# definition and/or policy.
#
svc_mark_maintenance()
{
	svcadm mark maintenance $1 >/dev/null 2>&1

	date=`date`
	echo "[ $date ${0}: $1 has invalid ipf configuration. ]"
	echo "[ $date ${0}: placing $1 in maintenance. ]"

	#
	# Move service's rule files to another location since
	# they're most likely invalid.
	#
	ipfile=`fmri_to_file $1 $IPF_SUFFIX`
	[ -f "$ipfile" ] && mv $ipfile "$ipfile.bak"
	ip6file=`fmri_to_file $1 $IPF6_SUFFIX`
	[ -f "$ip6file" ] && mv $ip6file "$ip6file.bak"

	natfile=`fmri_to_file $1 $NAT_SUFFIX`
	[ -f "$natfile" ] && mv $natfile "$natfile.bak"

	return 0
}

svc_is_server()
{
	svcprop -p $FW_CONFIG_PG $1 >/dev/null 2>&1
}

#
# Create rules for enabled firewalling and client services.
# - obtain the list of enabled services and process them
# - save the list of rules file for later use
#
create_services_rules()
{
	#
	# Do nothing if global policy is 'custom'
	#
	[ "$GLOBAL_POLICY" = "custom" ] && return 0

	ipf_get_lock

	#
	# Get all enabled services
	#
	allsvcs=`svcprop -cf -p general/enabled -p general_ovr/enabled '*' \
	    2>/dev/null | sed -n 's,^\(svc:.*\)/:properties/.* true$,\1,p' | sort -u`

	#
	# Process enabled services 
	#
	for s in $allsvcs; do
		service_is_enabled $s || continue
		process_service $s || continue

		ipfile=`fmri_to_file $s $IPF_SUFFIX`
		if [ -n "$ipfile" -a -r "$ipfile" ]; then
			check_ipf_syntax $ipfile
			if [ $? -ne 0 ]; then
				svc_mark_maintenance $s
				continue
			fi

			svc_is_server $s
			if [ $? -eq 0 ]; then
				check_ipf_rules $ipfile
				if [ $? -ne 0 ]; then
					svc_mark_maintenance $s
					continue
				fi
			fi
			CONF_FILES="$CONF_FILES $ipfile"
		fi

		ip6file=`fmri_to_file $s $IPF6_SUFFIX`
		if [ -n "$ip6file" -a -r "$ip6file" ]; then
			check_ipf_syntax $ip6file -6
			if [ $? -ne 0 ]; then
				svc_mark_maintenance $s
				continue
			fi

			svc_is_server $s
			if [ $? -eq 0 ]; then
				check_ipf_rules $ip6file -6
				if [ $? -ne 0 ]; then
					svc_mark_maintenance $s
					continue
				fi
			fi
			CONF6_FILES="$CONF6_FILES $ip6file"
		fi

		natfile=`fmri_to_file $s $NAT_SUFFIX`
		if [ -n "$natfile" -a -r "$natfile" ]; then
			check_nat_syntax $natfile
			if [ $? -ne 0 ]; then
				svc_mark_maintenance $s
				continue
			fi

			NAT_FILES="$NAT_FILES $natfile"
		fi
	done

	ipf_remove_lock
	return 0
}

#
# We update a services ipf ruleset in the following manners:
# - service is disabled, tear down its rules.
# - service is disable or refreshed(online), setup or update its rules.
#
service_update_rules()
{
	svc=$1

	ipfile=`fmri_to_file $svc $IPF_SUFFIX`
	ip6file=`fmri_to_file $svc $IPF6_SUFFIX`
	[ -n "$ipfile" ] && remove_rules $ipfile
	[ -n "$ip6file" ] && remove_rules $ip6file -6

	[ -z "$ipfile" -a -z "$ip6file" ] && return 0

	natfile=`fmri_to_file $svc $NAT_SUFFIX`
	[ -n "$natfile" ] && remove_nat_rules $natfile

	#
	# Don't go further if service is disabled or in maintenance.
	#
	service_is_enabled $svc || return 0
	service_check_state $1 $SMF_MAINT && return 0

	process_service $svc || return 1
	if [ -f "$ipfile" ]; then
		check_ipf_syntax $ipfile
		if [ $? -ne 0 ]; then
			svc_mark_maintenance $svc
			return 1
		fi
	fi

	if [ -f "$ip6file" ]; then
		check_ipf_syntax $ip6file -6
		if [ $? -ne 0 ]; then
			svc_mark_maintenance $svc
			return 1
		fi
	fi

	if [ -f "$natfile" ]; then
		check_nat_syntax $natfile
		if [ $? -ne 0 ]; then
			svc_mark_maintenance $svc
			return 1
		fi
	fi

	if [ -f "$ipfile" ]; then
		svc_is_server $svc
		if [ $? -eq 0 ]; then
			update_check_ipf_rules $ipfile
			if [ $? -ne 0 ]; then
				svc_mark_maintenance $svc
				return 1
			fi
		fi

		prepend_new_rules $ipfile

		#
		# reload Global Override rules to
		# maintain correct ordering.
		#
		remove_rules $IPFILOVRCONF
		prepend_new_rules $IPFILOVRCONF
	fi

	if [ -f "$ip6file" ]; then
		svc_is_server $svc
		if [ $? -eq 0 ]; then
			update_check_ipf_rules $ip6file -6
			if [ $? -ne 0 ]; then
				svc_mark_maintenance $svc
				return 1
			fi
		fi

		prepend_new_rules $ip6file -6

		#
		# reload Global Override rules to
		# maintain correct ordering.
		#
		remove_rules $IP6FILOVRCONF -6
		prepend_new_rules $IP6FILOVRCONF -6
	fi

	[ -f "$natfile" ] && append_new_nat_rules $natfile

	return 0
}

#
# Call the service_update_rules with appropriate svc fmri.
#
# This is called from '/lib/svc/method/ipfilter fw_update' whenever
# a service is disabled/enabled/refreshed.
#
service_update()
{
	svc=$1
	ret=0

	#
	# If ipfilter isn't online or global policy is 'custom',
	# nothing should be done.
	#
	[ "$GLOBAL_POLICY" = "custom" ] && return 0
	service_check_state $SMF_FMRI $SMF_ONLINE || return 0

	ipf_get_lock
	service_update_rules $svc || ret=1

	ipf_remove_lock
	return $ret
}

#
# Initialize global configuration
# 
global_init

