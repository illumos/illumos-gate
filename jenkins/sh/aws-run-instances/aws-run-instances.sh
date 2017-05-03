#!/bin/bash

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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/aws.sh

check_env REGION IMAGE_ID INSTANCE_TYPE ADD_DISKS_FOR

aws_setup_environment "$REGION"

if [[ "$ADD_DISKS_FOR" == 'run-zfs-tests' ]]; then
	#
	# In order to run the "run-zfs-tests" shscript, the instance
	# must three extra devices attached to it, so that they can be
	# manipulated by the zfstest suite.
	#
	log_must cat >block-device-mappings.json <<-EOF
	[{
	    "DeviceName": "/dev/xvdb",
	    "Ebs": {
	        "VolumeSize": 8,
	        "DeleteOnTermination": true,
	        "VolumeType": "gp2",
	        "Encrypted": false
	    }
	}, {
	    "DeviceName": "/dev/xvdc",
	    "Ebs": {
	        "VolumeSize": 8,
	        "DeleteOnTermination": true,
	        "VolumeType": "gp2",
	        "Encrypted": false
	    }
	}, {
	    "DeviceName": "/dev/xvdd",
	    "Ebs": {
	        "VolumeSize": 8,
	        "DeleteOnTermination": true,
	        "VolumeType": "gp2",
	        "Encrypted": false
	    }
	}]
	EOF
elif [[ "$ADD_DISKS_FOR" == 'rpool-fix-labels' ]]; then
	#
	# In order to run the "rpool-fix-labels" shscript, the instance
	# must have an extra device attached, such that it can use this
	# extra device to perform the "zpool attach/detach" dance.
	#
	# Additionally, this extra device must be equal in size to the
	# rpool's existing device (requirements of "zpool attach").
	#
	# The current AMI uses an rpool device of 64GB in size, but if
	# this ever changes, we'll have to also update the size of the
	# extra device that we're creating here (to match the new size
	# of the rpool device).
	#
	log_must cat >block-device-mappings.json <<-EOF
	[{
	    "DeviceName": "/dev/xvdb",
	    "Ebs": {
	        "VolumeSize": 64,
	        "DeleteOnTermination": true,
	        "VolumeType": "gp2",
	        "Encrypted": false
	    }
	}]
	EOF
elif [[ "$ADD_DISKS_FOR" == 'none' ]]; then
	#
	# If ADD_DISKS_FOR is "none", no extra disks will be attached to
	# the instance.
	#
	log_must cat >block-device-mappings.json <<-EOF
	[]
	EOF
else
	die "Unspported value of ADD_DISKS_FOR parameter: '$ADD_DISKS_FOR'"
fi

#
# We want to cat the contents of this file such that it'll wind up in
# the Jenkins console log, but we need to be careful not to output the
# context to stdout, since we need to reserve that for returning the
# INSTANCE_ID (and _only_ the INSTANCE_ID).
#
log_must cat block-device-mappings.json >&2

INSTANCE_ID=$(log_must aws ec2 run-instances \
	--image-id "$IMAGE_ID" \
	--count 1 \
	--instance-type "$INSTANCE_TYPE" \
	--block-device-mappings file://block-device-mappings.json \
	--associate-public-ip-address \
	| jq -M -r .Instances[0].InstanceId)

#
# This is a hack, but we've seen instances where after calling
# "run-instances" above, the instance returned won't immediately be
# found when calling "aws_wait_for_instance_state" below, which results
# in failure (i.e. "aws_wait_for_instance_state" fails in that scenario).
# By waiting here, we seem to avoid this race condition.
#
log_must sleep 10
log_must aws_wait_for_instance_state "$INSTANCE_ID" "running"
log_must echo "$INSTANCE_ID"
