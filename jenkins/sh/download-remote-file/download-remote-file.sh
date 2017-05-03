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
source ${JENKINS_DIRECTORY}/sh/library/ssh.sh

check_env REGION INSTANCE_ID REMOTE_FILE LOCAL_FILE

aws_setup_environment "$REGION"

HOST=$(log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
	| jq -M -r .Reservations[0].Instances[0].PublicIpAddress)

log_must pushd "$JENKINS_DIRECTORY/ansible" >/dev/null
ssh_wait_for inventory.txt playbook.yml
log_must popd >/dev/null

#
# While we support using shell expansion (i.e. globbing with "*") when
# evaluating REMOTE_FILE, we require the expansion to evaluate to a
# single file on the remote system, which is what we're attempting to
# to verify here.
#
ssh_log_must "test \$(ls -1d $REMOTE_FILE | wc -l) == 1"

ssh_fetch_remote_file "$REMOTE_FILE" >"$LOCAL_FILE"
