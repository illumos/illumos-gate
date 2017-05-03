/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

currentBuild.displayName = "#${env.BUILD_NUMBER} ${env.OPENZFS_REPOSITORY}"

node('master') {
    def misc = null
    stage('setup') {
        checkout([$class: 'GitSCM', changelog: false, poll: false,
                  userRemoteConfigs: [[name: 'origin', url: "https://github.com/${OPENZFS_REPOSITORY}"]],
                  branches: [[name: OPENZFS_BRANCH]]])
        misc = load('jenkins/pipelines/miscellaneous.groovy')
    }

    stage('send mail') {
        misc.shscript('send-illumos-mail', false, [
            ['REPOSITORY', OPENZFS_REPOSITORY],
        ])
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
