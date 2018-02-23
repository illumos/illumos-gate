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

check_env OPENZFS_DIRECTORY OPENZFS_REMOTE OPENZFS_REPOSITORY OPENZFS_BRANCH \
	ILLUMOS_REMOTE ILLUMOS_REPOSITORY ILLUMOS_BRANCH

#
# We set this to the current directory so that the "hub" command will
# look here for it's configuration file, and we can manipulate the
# configuration without worrying about affecting external proccesses
# using that command (processes that would be using the configuration
# found in the user's normal home directory).
#
export HOME=$PWD

#
# We need to specify a few specific options to "ssh" when "git push" is
# used below, so we use the GIT_SSH environment variable to do this.
#
# We don't use the user's "~/.ssh/config" directory to do this, as that
# isn't a directory that is unique to this specific build; thus,
# failures could be introduced as a result of this shared directory
# being modified by some external process. Using GIT_SSH isolates the
# dependencies of this job to resources that are controlled and managed
# by Jenkins.
#
# Additionally, even though we're specifying the HOME environment
# variable to point to PWD, this variable isn't honored by the "ssh"
# command. Thus, it wasn't as simple as generating a ".ssh" directory
# with the proper "config" file in the current directory, hoping it
# would be used by "ssh" due to the setting of HOME.
#
DIR=$(readlink -f $(dirname ${BASH_SOURCE[0]}))
export GIT_SSH=$DIR/git-ssh.sh

#
# The "git-ssh.sh" will look for the private key using the HOME
# environment variable, which is why we use this variable when creating
# the private key file. Since we've modified the HOME variable above,
# tnis isolates this configuration to only affecting this build, as
# opposed to modifying the user's actual home directory which could
# affect processes outside of this build.
#
log_must mkdir -p $HOME/.ssh
log_must chmod 700 $HOME/.ssh
log_must vault_read_github_private_key >$HOME/.ssh/id_rsa
log_must chmod 400 $HOME/.ssh/id_rsa

GH_USER=$(vault_read_github_user)
GH_TOKEN=$(vault_read_github_token)

log_must mkdir -p $HOME/.config
log_must cat >$HOME/.config/hub <<EOF
github.com:
- user: $GH_USER
  oauth_token: $GH_TOKEN
  protocol: https
EOF

log_must cd "$OPENZFS_DIRECTORY"

log_must git config user.email "zettabot@open-zfs.org"
log_must git config user.name "zettabot"

#
# If the GH_USER doesn't already have the necessary openzfs repository
# created under its GitHub account, this will create it and properly set
# the git remote such that we can "git push" to it later in this script.
#
# Additionally, if the repository already exists under the user's GitHub
# account, only the git remote will be added to point to it.
#
log_must hub fork

log_must git fetch "$OPENZFS_REMOTE"
log_must git fetch "$ILLUMOS_REMOTE"

#
# The merge is not expected to fail or need conflict resolution because
# any PRs that are destined to land in openzfs, will first be RTI'd and
# integrated into illumos first.
#
log_must git checkout -b "illumos-sync" "$OPENZFS_REMOTE/$OPENZFS_BRANCH"
log_must git merge -Xtheirs "$ILLUMOS_REMOTE/$ILLUMOS_BRANCH"
log_must git push -f "$GH_USER" "illumos-sync:illumos-sync"

#
# We don't use "log_must" when executing the "hub" command because this
# command is expected to fail if an open "illumos-sync" pull request
# already exists; and since we don't check to see if there's already an
# open pull request prior to executing this command, this failure mode
# is expected to occur.
#
log_must git log -1 --format=%B | log hub pull-request -F -
