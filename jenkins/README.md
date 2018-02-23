OpenZFS Continuous Integration Powered by Jenkins
=================================================

This directory contains all of the source code that powers the automated
builds and testing of OpenZFS GitHub Pull Requests. The following is a
brief explanation of the sub-directories contained, and how their
intended to be used:

  - ansible: This directory contains all of the [Ansible][ansible]
    files that are used to configure the [EC2][ec2] VMs that are
    dynamically generated to execute the build and tests. After the VMs
    are started, they must be configured as Jenkins agents with all of
    the necessary dependencies installed (e.g. compilers, etc); these
    Ansible files enable this configuration.

  - sh: This directory contains various [Bash][bash] scripts that are
    used throughout the build and test cycle. This includes, but is not
    limited to, scripts to perform the following tasks:

      - Creating a VM in Amazon's EC2 environment
      - Running Ansible to configure the Amazon EC2 VMs
      - Performing a full "nightly" build of OpenZFS
      - Cloning an upgraded VM, in order to run the tests
      - Executing the various regression tests
      - Terminating all VMs after the build and tests complete
      - Automatic merges of illumos into OpenZFS
      - Creating an OpenIndiana ISO using an OpenZFS nightly build
      - Sending mail with PR info to illumos developer mailing list

  - jobs: This directory contains additional Jenkins jobs that are used
    by the OpenZFS project. The files in this directory are consumed by
    the "Jobs DSL" plugin, allowing Jenkins jobs to be automatically
    generated from the files.

  - pipelines: This directory contains Groovy files that are consumed by
    the "Pipeline" plugin. Most of the files in this directory will
    map 1-1 to an associated file in the "jobs" directory, providing the
    implementation logic for that particular Jenkins job; this isn't a
    requirement, but is a common pattern.

[ansible]: https://en.wikipedia.org/wiki/Ansible_(software)
[ec2]: https://en.wikipedia.org/wiki/Amazon_Elastic_Compute_Cloud
[bash]: https://en.wikipedia.org/wiki/Bash_(Unix_shell)
