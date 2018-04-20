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

function vault_setup_environment() {
	#
	# This has a lot of assumptions about the environment that it is
	# running in; it assumes this function will be running inside of a
	# Docker contianer, and the Docker host will be running the
	# Hashicorp Vault service. Thus, we get the Docker host's IP address
	# by inspecting this containers default route, which will be the
	# Docker host. Then we can configure the VAULT_ADDR environment
	# variable to point back to the Docker host that's running the
	# service.
	#
	local address=$(ip route | awk '/default/ { print $3 }')

	export VAULT_ADDR="http://${address}:8200"
	export VAULT_TOKEN="14183ec4-a7f3-10b6-232a-d9f9d63928dc"
}

function vault_read_aws_access_key() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/aws/access-key
}

function vault_read_aws_secret_key() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/aws/secret-key
}

function vault_read_jenkins_username() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/jenkins/username
}

function vault_read_jenkins_password() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/jenkins/password
}

function vault_read_github_user() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/github/user
}

function vault_read_github_token() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/github/token
}

function vault_read_github_public_key() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/github/public-key
}

function vault_read_github_private_key() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/github/private-key
}

function vault_read_smtp_user() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/smtp/user
}

function vault_read_smtp_password() {
	[[ -z "$VAULT_TOKEN" ]] && vault_setup_environment
	vault read -field=value secret/openzfsci/smtp/password
}
