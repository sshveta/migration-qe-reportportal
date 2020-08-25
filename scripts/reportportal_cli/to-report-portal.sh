#!/usr/bin/env bash

#==================================================#
#                                                  #
#               to-report-portal.sh                #
#                                                  #
#  Call rp_cli to upload dat to the Report portal  #
#                                                  #
# Data are expected in following env. variables    #
# WORKSPACE                                        #
# rp_launch                                        #
# rp_launch_description                            #
# rp_launch_tags                                   #
# logs_path                                        #
# strategy                                         #
#                                                  #
#==================================================#
set -xe

# gives access to regular expressions in glob patterns
shopt -s extglob

echo "Executed from migration-qe-infra/scripts/reportportal_cli/to-report-portal.sh"

#-- upload results to RP
export RP_VENV="rp"
rm -rf $RP_VENV
virtualenv $RP_VENV
source $RP_VENV/bin/activate
pip install -U pip
pip install jinja2
pip install -r $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/requirements.txt
export RP_ENDPOINT="$RP_ENDPOINT"
export RP_UUID="$RP_UUID"
rp_out_file="$WORKSPACE/rp_cli.json"
# [[ -e "$rp_out_file" ]] && rm -f "$rp_out_file"

export REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
python $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/rp_cli.py \
        --config $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/rp_conf.yaml \
        --xunit_feed "$WORKSPACE/xunit_output.xml" \
        --launch_name "$rp_launch" \
        --launch_description "$rp_launch_description" \
        --launch_tags "$rp_launch_tags" \
        --test_logs "$logs_path" \
        --strategy "$strategy" \
        --zipped \
        --store_out_file "$rp_out_file"

# end of to-report-portal.sh
