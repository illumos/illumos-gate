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
source ${JENKINS_DIRECTORY}/sh/library/aws.sh

check_env JENKINS_URL INSTANCE_ID ROLES WAIT_FOR_SSH

aws_setup_environment

log_must cd "$JENKINS_DIRECTORY/ansible"

HOST=$(log_must aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
	| jq -M -r .Reservations[0].Instances[0].PublicIpAddress)

log_must cat >inventory.txt <<EOF
$HOST ansible_ssh_user=root ansible_ssh_pass=root
EOF

log_must cat >playbook.yml <<EOF
---
EOF

if [[ "$WAIT_FOR_SSH" == "yes" ]]; then
	log_must cat >>playbook.yml <<-EOF
	- hosts: localhost
	  gather_facts: no
	  tasks:
	    - wait_for:
	        host: $HOST
	        port: 22
	        state: started
	        timeout: 1800
	EOF
fi

#
# We have to be careful not to leak the contents of these two variables
# to the Jenkins console page, or else we could simply hardcode the
# values, as the console page is readable by anybody. Thus, we can't
# simply pass these to the "ansible-playbook" command using the
# "--extra-vars" option, as we're using "log_must" when executing that
# command (and thus, all the options will be displayed to stdout).
#
# To overcome this issue, instead of using "--extra-vars", we create
# these environment varialbes to hold the username and password, and
# then instruct "ansible-playbook" to retrieve their values from these
# environment variables using the "vars" keyword in the "playbook.yml"
# file. This way, since the contents of the environment variables aren't
# exposed, these secrets remain hidden.
#
export JENKINS_USERNAME=$(vault_read_jenkins_username)
export JENKINS_PASSWORD=$(vault_read_jenkins_password)

log_must cat >>playbook.yml <<EOF
- hosts: $HOST
  vars:
    jenkins_slave_name: "{{ lookup('env', 'INSTANCE_ID') }}"
    jenkins_master_url: "{{ lookup('env', 'JENKINS_URL') }}"
    jenkins_master_username: "{{ lookup('env', 'JENKINS_USERNAME') }}"
    jenkins_master_password: "{{ lookup('env', 'JENKINS_PASSWORD') }}"
  roles:
EOF

for ROLE in $ROLES; do
	log_must cat >>playbook.yml <<-EOF
	  - $ROLE
	EOF
done

#
# Output the contents of this file to have it logged in the Jenkins job's
# console page, making the contents more accessible which can aid debugging.
#
log_must cat playbook.yml

log_must ansible-playbook -vvvv -i inventory.txt playbook.yml
