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
 * Copyright (c) 2018 by Delphix. All rights reserved.
 */

currentBuild.displayName = "#${env.BUILD_NUMBER} ${env.OPENZFS_REPOSITORY}"

node('master') {
    def misc = null
    stage('checkout') {
        /*
         * The script that's used to open the pull request implicitly assumes the only git remotes that will be
         * contained in the local git repository are "OPENZFS_REMOTE" and "ILLUMOS_REMOTE". Thus, we can't
         * simply use the GitSCM's "WipeWorkspace" extension, as that won't remove any extra remotes that might
         * be contained in the repository. By using "deleteDir", we ensure a new git repository will be generated
         * for each build.
         */
        deleteDir()
        checkout([$class: 'GitSCM', changelog: false, poll: false,
                  userRemoteConfigs: [[name: env.ILLUMOS_REMOTE,
                                       url: "https://github.com/${env.ILLUMOS_REPOSITORY}"],
                                      [name: env.OPENZFS_REMOTE,
                                       url: "https://github.com/${env.OPENZFS_REPOSITORY}"]],
                  branches: [[name: "${env.OPENZFS_REMOTE}/${env.OPENZFS_BRANCH}"]]])

        /*
         * If these settings aren't configured, "git cherry-pick" will fail when used below.
         */
        sh('git config user.name zettabot')
        sh('git config user.email zettabot@open-zfs.org')

        misc = load('jenkins/pipelines/miscellaneous.groovy')
    }

    def commits = null
    stage('get commits') {
        commits = misc.shscript('get-illumos-commits', true, [
            ['ILLUMOS_REMOTE', env.ILLUMOS_REMOTE],
            ['ILLUMOS_BRANCH', env.ILLUMOS_BRANCH],
        ]).trim().split('\n')
    }

    for (commit in commits) {
        try {
            stage(commit.take(11)) {
                sh("git cherry-pick ${commit}")
                stash(name: 'openzfs', useDefaultExcludes: false)

                def instance = null
                try {
                    instance = misc.shscript('aws-request-spot-instances', true, [
                        ['IMAGE_ID', misc.BASE_IMAGE_ID],
                        ['INSTANCE_TYPE', 'c4.2xlarge'],
                        ['ADD_DISKS_FOR', 'none'],
                        ['SPOT_PRICE', '0.398']
                    ]).trim()

                    timeout(time: 6, unit: 'HOURS') {
                        if (!instance)
                            error('Failed to create AWS instance.')

                        misc.shscript('ansible-deploy-roles', false, [
                            ['INSTANCE_ID', instance],
                            ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                            ['WAIT_FOR_SSH', 'yes']
                        ])

                        node(instance) {
                            unstash('openzfs')

                            misc.shscript('nightly-build', false, [
                                ['BUILD_VERSION', commit],
                                ['BUILD_NONDEBUG', 'no'],
                                ['BUILD_DEBUG', 'yes'],
                                ['RUN_LINT', 'no']
                            ])

                            misc.shscript('nightly-install', false, [
                                ['INSTALL_DEBUG', 'yes']
                            ])
                        }

                        misc.shscript('reboot-and-verify', false, [
                            ['EXPECTED_VERSION', commit],
                            ['INSTANCE_ID', instance]
                        ])
                    }
                } finally {
                    if (instance) {
                        misc.shscript('aws-terminate-instances', false, [
                            ['INSTANCE_ID', instance]
                        ])
                    }
                }
            }
        } catch (e) {
            /*
             * On failure, we want to proceed on to the next commit, to ensure a single bad commit (or failure
             * due to flakey infrastructure) doesn't halt the entire process. Further, due to JENKINS-28822, we
             * can't distinguish between failures and a user initiated abort/cancel of the job; so these also
             * get ignored, and we proceed to the next commit in ths list.
             */
        }
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
