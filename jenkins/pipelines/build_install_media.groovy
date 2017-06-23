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

currentBuild.displayName = "#${env.BUILD_NUMBER} ${OPENZFS_REPOSITORY} ${OPENZFS_BRANCH}"

node('master') {
    def misc = null

    stage('checkout, stash repository') {
        checkout([$class: 'GitSCM', changelog: false, poll: false,
                  userRemoteConfigs: [[name: 'origin', url: "https://github.com/${OPENZFS_REPOSITORY}"]],
                  branches: [[name: OPENZFS_BRANCH]]])
        stash(name: 'openzfs', useDefaultExcludes: false)
        misc = load('jenkins/pipelines/miscellaneous.groovy')
    }

    try {
        stage('create instance') {
            env.INSTANCE_ID = misc.shscript('aws-request-spot-instances', true, [
                ['IMAGE_ID', env.BASE_IMAGE_ID],
                ['INSTANCE_TYPE', 'c4.xlarge'],
                ['ADD_DISKS_FOR', 'none'],
                ['SPOT_PRICE', '0.199']
            ]).trim()
        }

        stage('configure instance') {
            if (!env.INSTANCE_ID) {
                error('Empty INSTANCE_ID environment variable.')
            }

            misc.shscript('ansible-deploy-roles', false, [
                ['INSTANCE_ID', env.INSTANCE_ID],
                ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                ['WAIT_FOR_SSH', 'yes']
            ])
        }

        node(env.INSTANCE_ID) {
            stage('unstash repository') {
                unstash(name: 'openzfs')
            }

            stage('build repository') {
                misc.shscript('nightly-build', false, [
                    ['BUILD_NONDEBUG', 'yes'],
                    ['BUILD_DEBUG', 'no'],
                    ['RUN_LINT', 'no']
                ])
            }

            stage('build install media') {
                misc.shscript('nightly-iso-build', false, [
                    ['INSTALL_DEBUG', 'no']
                ])
            }
        }

        stage('archive install media') {
            misc.shscript('download-remote-directory', false, [
                ['INSTANCE_ID', instance_id],
                ['REMOTE_DIRECTORY', env.MEDIA_DIRECTORY],
                ['LOCAL_FILE', "install-media.tar.xz"]
            ])

            archive(includes: "install-media.tar.xz")
        }
    } finally {
        stage('terminate instance') {
            if (env.INSTANCE_ID) {
                misc.shscript('aws-terminate-instances', false, [
                    ['INSTANCE_ID', env.INSTANCE_ID]
                ])
            }
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
