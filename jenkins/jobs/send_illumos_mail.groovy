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

pipelineJob('send-illumos-mail') {
    quietPeriod(0)
    concurrentBuild(false)

    triggers {
        cron('H/5 * * * *')
    }

    environmentVariables {
        env('OPENZFS_REPOSITORY', System.getenv('OPENZFS_REPOSITORY'))
        env('OPENZFS_BRANCH', System.getenv('OPENZFS_BRANCH'))
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/pipelines/send_illumos_mail.groovy'))
            sandbox()
        }
    }
}

// vim: tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
