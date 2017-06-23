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

pipelineJob('build-install-media') {
    quietPeriod(0)
    concurrentBuild(true)

    environmentVariables {
        env('BASE_IMAGE_ID', 'ami-c5c0a7d3')
        env('MEDIA_DIRECTORY', '/rpool/dc/media')

        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))
        env('OPENZFS_DIRECTORY', 'openzfs')
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/build_install_media.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
