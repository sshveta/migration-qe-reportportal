#!/usr/bin/env bash
# Execute this script from post build task section of jenkins
# Plugins required in Jenkins are
# 1) Hudson Post build plugin
# 2) Multiple SCM
# 3) Docker Plugin
echo "Executed from scripts/reportportal_cli/create_rp_envt_variables.sh"

# Create Virtual env for RP and source it
# ========================================
export RP_VENV="rp"
rm -rf $RP_VENV
virtualenv $RP_VENV
source $RP_VENV/bin/activate
pip install -U pip
pip install jinja2
pip install -r $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/requirements.txt

# Settings for Report Portal
# =============================
launch_name="MTA-5.0.1"
rp_launch="MTA-5.0.1"
rp_launch_description="Description-$launch_name"
rp_launch_tags="mta-5.0.1"
rp_out_file="$WORKSPACE/rp_cli.json"
logs_path=$WORKSPACE/logs_per_test
strategy="Migration"

#-- Save the launch attributes for possible later usage
# =========================================================
rp_launch_info="$WORKSPACE/rp_launch_info.json"

cat > "$rp_launch_info" << __EOF__
{{
  "launch_name": "${{rp_launch}}",
  "launch_description": "${{rp_launch_description}}",
  "launch_tags": "${{rp_launch_tags}}",
  "logs_path": "${{logs_path}}",
  "strategy": "${{strategy}}"
}}
__EOF__


export rp_launch
export rp_launch_description
export rp_launch_tags
export logs_path
export strategy

# Write parameters in rp_conf.yaml
#====================
sed -i "s,^rp_endpoint.\\+$,rp_endpoint: ${RP_ENDPOINT}," $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/rp_conf.yaml
sed -i "s/^rp_uuid.\\+$/rp_uuid: ${RP_UUID}/" $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/rp_conf.yaml
sed -i "s/^rp_project.\\+$/rp_project: ${RP_PROJECT}/" $WORKSPACE/migration-qe-infra/scripts/reportportal_cli/rp_conf.yaml

#-- Do the export to the Report portal
sh "$WORKSPACE/migration-qe-infra/scripts/reportportal_cli/to-report-portal.sh"
# end of create_rp_envt_variables.s