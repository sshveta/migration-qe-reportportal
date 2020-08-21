# migration-qe-reportportal
Infra files for Migration QE
# reportportal_cli

## What does it do?
rp_cli.py is command line utility written in python. It takes xunit output file
and upload it to report portal instance. It is able also to parse the xunit file and feed the results to report portal
while being able to add more information per test like tags and logs.

## Installation
```bash
git clone git@github.com:sshveta/migration-qe-reportportal.git
cd reportportal_cli
virtualenv rp-cli
source rp-cli/bin/activate
pip install -rrequierments.txt
```
Modify the rp_conf.yaml:
```plain/text
rp_endpoint: http://reportportal
rp_uuid: 1111111-1111-1111-1111-111111
rp_project: my_project
```

## Usage

### Upload xunit file as is:

In report portal you have the ability to upload xunit file. That can be done by running:
```bash
python rp_cli.py --config rp_conf.yaml --upload_xunit ./my-product-smoke-tests.zip   --launch_description 'some description of the launch '  --launch_tags 'smoke tag1 tag2 tag3'

python rp_cli.py --config rp_conf.yaml --upload_xunit ./junit-report.zip   --launch_description 'testing reportportal'  --launch_tags 'mta'

```
Note that the xunit file should be zipped and the name of the launch in report portal will be the name of the zip file.
However in this case:
1. you will have no tags per test case
2. only the test case name will be shown in the report portal
3. only the system_out or system_err which appears in the xunit file.

### Parse xunit file and send test case results one by one:
Xunit have more information like properties and full class name from wich for example i can tag the test case to make it easy to lookup in reportportal. This can be achieved by running:
```bash
python rp_cli.py --strategy Migration \
                 --xunit_feed tier1_xunit.xml \
                 --config rp_conf.yaml \
                 --launch_tags 'tier1 tag1 tag2' \
                 --launch_name 'tier1'

python rp_cli.py --config rp_conf.yaml --xunit_feed xunit_output.xml --launch_name MTA-5.0.2 --launch_description launch_desc --launch_tags mta-5.0.2 --strategy Migration 
```
Note here you can set launch_name via command line.

```
