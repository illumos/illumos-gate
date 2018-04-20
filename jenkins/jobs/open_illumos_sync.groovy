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

pipelineJob('open-illumos-sync') {
    quietPeriod(0)
    concurrentBuild(false)

    triggers {
        cron('H 0 * * 0')
    }

    environmentVariables {
        // This must be set to "origin" due to the requirements of the "hub" command.
        env('OPENZFS_REMOTE', 'origin')
        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))

        env('ILLUMOS_REMOTE', 'illumos')
        env('ILLUMOS_REPOSITORY', 'illumos/illumos-gate')
        env('ILLUMOS_BRANCH', 'master')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/open_illumos_sync.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
