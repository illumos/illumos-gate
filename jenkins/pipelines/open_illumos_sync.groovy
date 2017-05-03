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
        misc = load('jenkins/pipelines/miscellaneous.groovy')
    }

    stage('illumos sync') {
        misc.shscript('open-illumos-sync', false, [
            ['OPENZFS_REMOTE', env.OPENZFS_REMOTE],
            ['OPENZFS_REPOSITORY', env.OPENZFS_REPOSITORY],
            ['OPENZFS_BRANCH', env.OPENZFS_BRANCH],
            ['ILLUMOS_REMOTE', env.ILLUMOS_REMOTE],
            ['ILLUMOS_REPOSITORY', env.ILLUMOS_REPOSITORY],
            ['ILLUMOS_BRANCH', env.ILLUMOS_BRANCH],
        ])
    }
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
