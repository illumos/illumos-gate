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
# Copyright (c) 2018 by Delphix. All rights reserved.
#

source ${JENKINS_DIRECTORY}/sh/library/common.sh
source ${JENKINS_DIRECTORY}/sh/library/aws.sh
source ${JENKINS_DIRECTORY}/sh/library/ssh.sh

check_env INSTANCE_ID

aws_setup_environment

HOST=$(log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
	| jq -M -r .Reservations[0].Instances[0].PublicIpAddress)

log_must pushd "$JENKINS_DIRECTORY/ansible" >/dev/null
ssh_wait_for inventory.txt playbook.yml
log_must popd >/dev/null

ssh_log_must <<-EOF
	nohup sudo /usr/sbin/shutdown -g 1 -i 6 -y &
	disown %1
	exit 0
EOF

#
# Before we begin to wait on the SSH service below, we want pause here,
# to try and ensure the SSH is shutdown as part of the reboot prior to
# us waiting below. Otherwise, we might detect SSH is up simply because
# it hasn't been shutdown yet because the reboot hasn't yet initiated.
#
log_must sleep 10

log_must pushd "$JENKINS_DIRECTORY/ansible" >/dev/null
ssh_wait_for inventory.txt playbook.yml
log_must popd >/dev/null
