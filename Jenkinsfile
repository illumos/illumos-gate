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

env.BASE_IMAGE_ID = 'ami-c5c0a7d3'

node('master') {
    stage('checkout, verify, stash') {
        deleteDir()
        checkout scm

        /*
         * We can't allow unpriveledged users from modifying the files in the "jenkins" directory, and then
         * submitting a pull request that would then execute the modified files on the Jenkins master. This
         * would allow a malicious user a way to run arbitary code on the Jenkins master, which could then
         * manipulate our AWS infrastructure, and/or extract secrets (e.g. AWS credentials, etc.) from the
         * vault. The "readTrusted" function used below will cause the build to fail if it detects the file
         * being read was modified, and the user that submitted the PR did not have write access to the
         * repository (to which the PR was opened).
         */
        def files = sh(script: 'find jenkins -type f', encoding: 'UTF-8', returnStdout: true).trim().tokenize('\n')
        for (file in files) {
            readTrusted(file)
        }

        /*
         * When building, we need access to the ".git" directory so that things like "git-describe" will work,
         * which the build systems makes use of. By default, this directory is excluded, so we have to
         * explicitly disable that behavior using the "useDefaultExcludes" parameter. If the ".git" directory
         * was not avaiable later when performing the build, the build will fail.
         */
        stash(name: 'openzfs', useDefaultExcludes: false)

        /*
         * When executing the tests, we only need access to the "jenkins" directory. Thus, we create a second
         * stash such that we can unstash only that directory when running the tests.
         */
        stash(name: 'jenkins', includes: 'jenkins/**')
    }

    try {
        stage('create build instance') {
            env.BUILD_INSTANCE_ID = shscript('aws-request-spot-instances', true, [
                ['IMAGE_ID', env.BASE_IMAGE_ID],
                ['INSTANCE_TYPE', 'c4.xlarge'],
                ['ADD_DISKS_FOR', 'none'],
                ['SPOT_PRICE', '0.199']
            ]).trim()
        }

        timeout(time: 6, unit: 'HOURS') {
            stage('configure build instance') {
                if (!env.BUILD_INSTANCE_ID) {
                    error('Empty BUILD_INSTANCE_ID environment variable.')
                }

                shscript('ansible-deploy-roles', false, [
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID],
                    ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                    ['WAIT_FOR_SSH', 'yes']
                ])
            }

            def build_workspace = null
            node(env.BUILD_INSTANCE_ID) {
                build_workspace = pwd()

                stage('unstash repository') {
                    unstash('openzfs')
                }

                stage('build') {
                    shscript('nightly-build', false, [
                        ['BUILD_NONDEBUG', 'yes'],
                        ['BUILD_DEBUG', 'yes'],
                        ['RUN_LINT', 'yes']
                    ])
                }

                try {
                    stage('nits') {
                        shscript('nightly-nits', false, [])
                    }
                } catch (e) {
                    // If nits fails, don't propagate the failure to the job's result.
                }

                stage('install') {
                    shscript('nightly-install', false, [
                        ['INSTALL_DEBUG', 'yes']
                    ])
                }
            }

            if (build_workspace == null)
                error('could not determine the workspace used to perform the build')

            stage('archive build artifacts') {
                shscript('download-remote-file', false, [
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID],
                    ['REMOTE_FILE', "${build_workspace}/log/*/nightly.log"],
                    ['LOCAL_FILE', 'nightly.log']
                ])
                archive(includes: 'nightly.log')

                shscript('download-remote-file', false, [
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID],
                    ['REMOTE_FILE', "${build_workspace}/log/*/mail_msg"],
                    ['LOCAL_FILE', 'nightly-mail.log']
                ])
                archive(includes: 'nightly-mail.log')

                shscript('download-remote-directory', false, [
                    ['INSTANCE_ID', env.BUILD_INSTANCE_ID],
                    ['REMOTE_DIRECTORY', "${build_workspace}/packages"],
                    ['LOCAL_FILE', 'nightly-packages.tar.xz']
                ])
                archive(includes: 'nightly-packages.tar.xz')
            }
        }

        stage('create image') {
            env.BUILD_IMAGE_ID = shscript('aws-create-image', true, [
                ['INSTANCE_ID', env.BUILD_INSTANCE_ID]
            ]).trim()

            shscript('aws-terminate-instances', false, [
                ['INSTANCE_ID', env.BUILD_INSTANCE_ID]
            ])
        }

        stage('run tests') {
            parallel('run libc-tests': {
                run_test('run-libc-tests', 'm4.large', '0.100', 1, 'none', [
                    ['RUNFILE', '/opt/libc-tests/runfiles/default.run']
                ])
            }, 'run os-tests': {
                run_test('run-os-tests', 'm4.large', '0.100', 1, 'none', [
                    ['RUNFILE', '/opt/os-tests/runfiles/default.run']
                ])
            }, 'run util-tests': {
                run_test('run-util-tests', 'm4.large', '0.100', 1, 'none', [
                    ['RUNFILE', '/opt/util-tests/runfiles/default.run']
                ])
            }, 'run zfs-tests': {
                run_test('run-zfs-tests', 'm4.large', '0.100', 8, 'run-zfs-tests', [
                    ['RUNFILE', '/opt/zfs-tests/runfiles/delphix.run']
                ])
            }, 'run zloop': {
                run_test('run-zloop', 'm4.large', '0.100', 2, 'none', [
                    ['ENABLE_WATCHPOINTS', 'no'],
                    ['RUN_TIME', '6000']
                ])
            })
        }
    } finally {
        stage('delete image') {
            if (env.BUILD_IMAGE_ID && env.BUILD_IMAGE_ID != env.BASE_IMAGE_ID) {
                shscript('aws-delete-image', false, [
                    ['IMAGE_ID', env.BUILD_IMAGE_ID]
                ])
            }
        }
    }
}

def run_test(script, instance_type, spot_price, limit, disks, parameters) {
    /*
     * Ideally, we'd use different Jenkins "stages" from within this function, much like we do for creating,
     * configuring, and executing the build. Unfortuanately, though, "stages" nested inside a "parallel" isn't
     * supported by the Jenkins Blue Ocean visualization; the feature addition is being tracked here:
     *
     *     https://issues.jenkins-ci.org/browse/JENKINS-38442
     *
     * Since this function is intended to be used to execute multiple tests in parallel, we can't define
     * different stages until that bug/feature is implemented.
     */

    if (!env.BUILD_IMAGE_ID) {
        error('Empty BUILD_IMAGE_ID environment variable.')
    }

    /*
     * When we run "shscript" below, we need to be careful to ensure that if the scripts are executed in
     * parallel, they don't overwrite the data in the workspace that another script happens to be using.
     *
     * When the scripts are executed without running on a seperate "node", they will end up sharing the same
     * workspace. Thus, if a script is executed in parallel, the two invocations can easily "corrupt" the
     * workspace by each invocation writing to the same file at (more or less) the same time. To workaround
     * this, we use "ws" to ensure a unique workspace is provided for each script that's invoked.
     *
     * Additionally, since "ws" will allocate a new workspace, we then need to "unstash" the openzfs repository,
     * so the underlying shell script is available to be executed by "shscript". Even though the repository was
     * checked out in the beginning of the job, that copy won't be present in the workspace allocated by "ws".
     */
    ws {
        def instance_id = null
        try {
            deleteDir()
            unstash('jenkins')

            instance_id = shscript('aws-request-spot-instances', true, [
                ['IMAGE_ID', env.BUILD_IMAGE_ID],
                ['INSTANCE_TYPE', instance_type],
                ['SPOT_PRICE', spot_price],
                ['ADD_DISKS_FOR', disks]
            ]).trim()

            timeout(time: 1.5 * limit, unit: 'HOURS') {
                if (!instance_id) {
                    error('Unable to create instance.')
                }

                shscript('ansible-deploy-roles', false, [
                    ['INSTANCE_ID', instance_id],
                    ['ROLES', 'openzfs.build-slave openzfs.jenkins-slave'],
                    ['WAIT_FOR_SSH', 'yes']
                ])

                try {
                    timeout(time: limit, unit: 'HOURS') {
                        node(instance_id) {
                            unstash('jenkins')
                            shscript(script, false, parameters)
                        }
                    }
                } finally {
                    try {
                        shscript('download-remote-directory', false, [
                            ['INSTANCE_ID', instance_id],
                            ['REMOTE_DIRECTORY', '/var/tmp/test_results'],
                            ['LOCAL_FILE', "${script}-results.tar.xz"]
                        ])

                        archive(includes: "${script}-results.tar.xz")
                    } catch (e) {
                        // If this archive fails, don't propagate the failure to the job's result.
                    }

                    try {
                        shscript('download-remote-directory', false, [
                            ['INSTANCE_ID', instance_id],
                            ['REMOTE_DIRECTORY', '/var/crash'],
                            ['LOCAL_FILE', "${script}-crash.tar.xz"]
                        ])

                        archive(includes: "${script}-crash.tar.xz")
                    } catch (e) {
                        // If this archive fails, don't propagate the failure to the job's result.
                    }

                    /*
                     * The 'run-zloop' script creates a different log file than the other test scripts, so we
                     * must add a special case when running that script.
                     */
                    def remote_file = '/var/tmp/test_results/*/log'
                    if (script == 'run-zloop')
                        remote_file = '/var/tmp/test_results/ztest.out'

                    try {
                        shscript('download-remote-file', false, [
                            ['INSTANCE_ID', instance_id],
                            ['REMOTE_FILE', remote_file],
                            ['LOCAL_FILE', "${script}.log"]
                        ])

                        archive(includes: "${script}.log")
                    } catch (e) {
                        // If this archive fails, don't propagate the failure to the job's result.
                    }
                }
            }
        } finally {
            if (instance_id) {
                shscript('aws-terminate-instances', false, [
                    ['INSTANCE_ID', instance_id]
                ])
            }
        }
    }
}

def shscript(script, returnStdout, parameters) {
    def ret = null
    def environment = [
        "OPENZFS_DIRECTORY=.",
        "JENKINS_DIRECTORY=./jenkins",
        "JENKINS_URL=${env.JENKINS_URL}"
    ]

    /*
     * It'd be cleaner to use a map datastructure for the parameters object, but iterating over a map in the Jenkins
     * pipeline plugin does not work properly. Thus, we're forced to use a two dimensional array and a C-sytle loop.
     */
    for (def i = 0; i < parameters.size(); i++) {
        def entry = parameters.get(i)
        def key = entry.get(0)
        def value = entry.get(1)
        environment.add("${key}=${value}")
    }

    withEnv(environment) {
        wrap([$class: 'AnsiColorBuildWrapper']) {
            ret = sh(encoding: 'UTF-8', returnStatus: false, returnStdout: returnStdout,
                script: "${JENKINS_DIRECTORY}/sh/${script}/${script}.sh")
        }
    }

    return ret
}

// vim: syntax=groovy tabstop=4 shiftwidth=4 expandtab textwidth=112 colorcolumn=120
