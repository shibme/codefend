# CodeInspect
[![Build Status](https://gitlab.com/shibme/codeinspect/badges/master/pipeline.svg)](https://gitlab.com/shibme/codeinspect/pipelines)

A static code analysis tool which makes use of existing open source tools and libraries

### Before we start,
- Install the latest Docker CLI to be installed in the environment
- Have to source code that has to be scanned inside the working directory

#### A bunch of environment variables for CodeInspect 🤷 [All optional]
`CODEINSPECT_PROJECT`
- Project name of the scan [If not set, will use repo slug or sets a random name with TimeStamp]

`CODEINSPECT_DIR`
- Specific directory inside the current directory to be scanned

`CODEINSPECT_CONTEXT`
- Type of scan [SAST or SCA - Does both by default]

`CODEINSPECT_LANG`
- Target language to be scanned [`Go`, `Java`, `JavaScript`, `Python`, `Ruby`, etc - if not specified, detects from source].

`CODEINSPECT_BUILDSCRIPT`
- Any script that needs to be run before scan.

`CODEINSPECT_TOOL`
- One of the available tool's name to be used specifically

`CODEINSPECT_GIT_REPO`
- Git repository URI if source is not available in current directory

`CODEINSPECT_GIT_BRANCH`
- The branch in the repository to be scanned

`CODEINSPECT_GIT_COMMIT`
- The commit hash to be checked out and scanned

`CODEINSPECT_GIT_USERNAME`
- The username of the git account to perform a HTTP based clone

`CODEINSPECT_GIT_TOKEN`
- The password or access token of the git account to perform a HTTP based clone

`CODEINSPECT_GIT_SSHKEY`
- The SSH private key file path to perform SSH based clone
 
#### A few more steps, in case you need to sync the findings to an issue tracker 🙄 [All optional]
- Take a look into [this](https://gitlab.com/shibme/steward/-/blob/master/README.md#configuration-for-consumers) for instructions

### Let's get started 😎
Run the following command on your terminal with the source code in working directory
```
curl -s https://shibme.github.io/codeinspect/init | sh
```