#!/usr/bin/env bash

#===================================================#
#                                                   #
# Downloads the artifacts given on the command line #
# from job/run given in the env. variables          #
# RUNNER_NAME/RUN_NUMBER via zip to save the        #
# download time.                                    #
# After download the artifacts are unziped.         #
#                                                   #
# Usage:                                            #
# download-from-artifacts.sh artf1 artf2 ...        #
#                                                   #
#===================================================#

set -xe

# gives access to regular expressions in glob patterns
shopt -s extglob

echo "Executed from migration-qe-infra/scripts/reportportal_cli/download-from-artifacts.sh"

JENKINS_URL=""
#-- Get the given artifacts
#-- Use wget to utilize the zip to cut down the download time
if [[ $# -gt 0 ]]; then
    for ARTF in "$@"; do
        A_URL="$JENKINS_URL/job/$RUNNER_NAME/$RUN_NUMBER/artifact/$ARTF/*zip*/$ARTF.zip"
        if wget -q "$A_URL"; then
            unzip -q "$ARTF.zip"
        else
            echo "Error downloading $ARTF!"
            exit 1
        fi
    done
else
  echo "Nothing to do!"
fi
