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
source ${JENKINS_DIRECTORY}/sh/library/vault.sh

function aws_setup_environment() {
	local REGION="$1"
	check_env PWD REGION

	export HOME="$PWD"
	log_must mkdir -p $HOME/.aws

	log_must cat >$HOME/.aws/credentials <<-EOF
	[default]
	aws_access_key_id = $(vault_read_aws_access_key)
	aws_secret_access_key = $(vault_read_aws_secret_key)
	region = $REGION
	EOF
}

function aws_get_instance_state() {
	local INSTANCE_ID="$1"
	check_env INSTANCE_ID

	log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
		| jq -M -r .Reservations[0].Instances[0].State.Name
}

function aws_wait_for_instance_state() {
	local INSTANCE_ID="$1"
	local DESIRED_STATE="$2"
	check_env INSTANCE_ID DESIRED_STATE

	for i in {1..40}; do
		CURRENT_STATE=$(aws_get_instance_state "$INSTANCE_ID")
		[[ "$CURRENT_STATE" == "$DESIRED_STATE" ]] && return 0
		sleep 15
	done

	return 1
}

function aws_get_image_state() {
	local IMAGE_ID="$1"
	check_env IMAGE_ID

	log_must aws ec2 describe-images --image-ids "$IMAGE_ID" \
		| jq -M -r .Images[0].State
}

function aws_wait_for_image_state() {
	local IMAGE_ID="$1"
	local DESIRED_STATE="$2"
	check_env IMAGE_ID DESIRED_STATE

	for i in {1..120}; do
		CURRENT_STATE=$(aws_get_image_state "$IMAGE_ID")
		[[ "$CURRENT_STATE" == "$DESIRED_STATE" ]] && return 0
		sleep 60
	done

	return 1
}
