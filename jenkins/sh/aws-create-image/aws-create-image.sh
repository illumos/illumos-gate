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

check_env INSTANCE_ID

aws_setup_environment

#
# The assumption here, is we're creating an image from the system that
# was used to perform the build and upgrade. Additionally, we're
# assuming that the "rpool-fix-labels" script had to be used on that
# system, and thus, it has an "extra disk" attached to it (other than
# the disk used for the root pool). We don't want this extra disk to be
# part of the image that we're creating, so we use this file, and the
# "--block-device-mappings" option to prevent this extra disk from being
# included in the image we create; if it was included, it would cause
# failures when adding disks to the VM that is used to run the ZFS test
# suite.
#
log_must cat >block-device-mappings.json <<EOF
[{
    "DeviceName": "/dev/xvdb",
    "NoDevice": ""
}]
EOF

#
# We want to cat the contents of this file such that it'll wind up in
# the Jenkins console log, but we need to be careful not to output the
# context to stdout, since we need to reserve that for returning the
# IMAGE_ID (and _only_ the IMAGE_ID).
#
log_must cat block-device-mappings.json >&2

IMAGE_ID=$(log_must aws ec2 create-image \
	--instance-id "$INSTANCE_ID" \
	--name "$INSTANCE_ID" \
	--block-device-mappings file://block-device-mappings.json \
	| jq -M -r .ImageId)

log_must aws_wait_for_image_state "$IMAGE_ID" "available"
log_must echo "$IMAGE_ID"
