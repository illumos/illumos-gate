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

pipelineJob('verify-illumos-commits') {
    quietPeriod(0)
    concurrentBuild(false)

    environmentVariables {
        env('OPENZFS_REMOTE', 'openzfs')
        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))

        env('ILLUMOS_REMOTE', 'illumos')
        env('ILLUMOS_REPOSITORY', 'illumos/illumos-gate')
        env('ILLUMOS_BRANCH', 'master')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/verify_illumos_commits.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
