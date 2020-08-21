#!/usr/bin/env bash
echo "Executed from shell-scripts/create_rp_envt_variables.sh"

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
rp_launch="MTA-$VERSION-$launch_name"
rp_launch_description="$TEXT_BUILD_DESCRIPTION-$VERSION-$launch_name"
rp_launch_tags="MTA-$VERSION-$launch_name"
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

#-- Do the export to the Report portal
sh "$WORKSPACE/migration-qe-infra/scripts/reportportal_cli/to-report-portal.sh"
# end of create_rp_envt_variables.sh

