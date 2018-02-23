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

check_env IMAGE_ID INSTANCE_TYPE ADD_DISKS_FOR SPOT_PRICE

DIR=$(dirname ${BASH_SOURCE[0]})

aws_setup_environment

if [[ "$ADD_DISKS_FOR" == 'run-zfs-tests' ]]; then
	#
	# In order to run the "run-zfs-tests" shscript, the instance
	# must three extra devices attached to it, so that they can be
	# manipulated by the zfstest suite.
	#
	log_must jq -M -r -s '.[0] * .[1]' \
	    $DIR/base-specification.json \
	    $DIR/block-device-mappings/run-zfs-tests.json > request.json
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
	log_must jq -M -r -s '.[0] * .[1]' \
	    $DIR/base-specification.json \
	    $DIR/block-device-mappings/rpool-fix-labels.json > request.json
elif [[ "$ADD_DISKS_FOR" == 'none' ]]; then
	#
	# If ADD_DISKS_FOR is "none", no extra disks will be attached to
	# the instance.
	#
	log_must jq -M -r -s '.[0] * .[1]' \
	    $DIR/base-specification.json \
	    $DIR/block-device-mappings/none.json > request.json
else
	die "Unspported value of ADD_DISKS_FOR parameter: '$ADD_DISKS_FOR'"
fi

#
# Now we need to inject the "ImageId" and "InstanceId" fields of the
# JSON request payload, based on the input parameters to this script.
# The "jq" utility doesn't support editing "in-place" (a la "sed -i"),
# so we have to use a temporary file.
#
log_must mv request.json request.json.temp
log_must jq -M -r \
    ".ImageId = \"$IMAGE_ID\" | .InstanceType = \"$INSTANCE_TYPE\"" \
    request.json.temp > request.json
log_must rm request.json.temp

#
# We want to cat the contents of this file such that it'll wind up in
# the Jenkins console log, but we need to be careful not to output the
# contents to stdout, since we need to reserve that for returning the
# INSTANCE_ID (and _only_ the INSTANCE_ID).
#
log_must cat request.json >&2

REQUEST_ID=$(log_must aws ec2 request-spot-instances \
	--type one-time \
	--instance-count 1 \
	--spot-price $SPOT_PRICE \
	--launch-specification file://request.json \
	| jq -M -r .SpotInstanceRequests[0].SpotInstanceRequestId)

if ! aws_wait_for_spot_request_status "$REQUEST_ID" "fulfilled"; then
	log_must aws ec2 describe-spot-instance-requests \
	    --spot-instance-request-ids "$REQUEST_ID" \
	    | jq .SpotInstanceRequests[0].Status >&2
	log_must aws ec2 cancel-spot-instance-requests \
	    --spot-instance-request-ids "$REQUEST_ID" >&2
	log_must aws_wait_for_spot_request_status \
	    "$REQUEST_ID" "canceled-before-fulfillment"
	exit 1
fi

INSTANCE_ID=$(log_must aws ec2 describe-spot-instance-requests \
    --spot-instance-request-ids "$REQUEST_ID" \
    | jq -M -r .SpotInstanceRequests[0].InstanceId)

#
# This is a hack, but we've seen instances where after getting the
# instance ID above, the instance returned won't immediately be found
# when calling "aws_wait_for_instance_state" below, which results in
# failure (i.e. "aws_wait_for_instance_state" fails in that scenario).
# By waiting here, we seem to avoid this race condition.
#
log_must sleep 10
log_must aws_wait_for_instance_state "$INSTANCE_ID" "running"
log_must echo "$INSTANCE_ID"
