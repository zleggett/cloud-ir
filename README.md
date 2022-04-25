# cloud-ir
Cloud-ir is a python tool that is designed to assist incident responders with the collection and analysis of cloud-based forensics data with an emphasis on scalability. In its current state, cloud-ir works with AWS and linux machines only.

Cloud-ir has the following capabilities:
- Automatically create volume snapshots and memory dumps
- Capture the contents of key files discovered in the volume snapshot
- Initial analysis of memory dump performed using Volatility 2
- All findings are uploaded as reports to an s3 bucket
- Supports multi-threading for additional scalability and efficiency when multiple forensics VMs are used
- Simulates the physical IR process of using external hard drives by collecting and transferring all evidence using EBS volumes

## Geting Started
- Install required pip packages  
`pip install -r requirements.txt`
- Setup an AWS credentials file as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- Edit the [config file](#config-file) with infrastructure information
- Run using `python3 cloud-ir.py` or `./cloud-ir.py`

## Config File
The config file contains information related to the machine that need to be analyzed and the forensics VMs that must be created.

### evidence_bucket
This section contains details about the s3 bucket to place reports with findings.
- `name`: Name of the s3 bucket to be used. Will be created if it doesn't already exist.
- `region`: Specifies the region in which the bucket should be created (only required if creating the bucket).

### forensics_vms
This section lists the VMs that will be used for analysis of the acquired evidence. A name for each forensics VM must be specified. This name will be used in the tool output. Under each name, the following options must be configured.
- `aws_creds`: Path to an AWS credential file that will be used to upload reports to the s3 bucket.
- `exists`: Boolean that indicates if this machine already exists. If false, a new forensics VM will be created using the specified parameters.
- `instance_id`: Id of ec2 instance. Required if the instance already exists but will be automatically filled in if instance is created.
- `ip`: IP address of ec2 instance. Required if the instance already exists but will be automatically filled in if instance is created.
- `key_name`: Name of AWS private key to be used (only required if creating instance).
- `key_path`: Path to the SSH key that should be used to access instance.
- `master_dev_id`: Specifies where to attach master volume (Ex. /dev/sdh)
- `master_volume`: Sub-section that specifies master volume details.
  - `exists`: Boolean that indicates if this volume already exists. If false, a new volume will be created using the specified parameters.
  - `availability_zone`: Zone in which the volume should be created (only required if creating volume).
  - `vol_id`: Id of AWS volume. Required if the volume already exists but will be automatically filled in if volume is created.
  - `vol_size`: Volume size in GB (only required if creating volume).
- `security_groups`: List of security group IDs to be applied to instance (only required if creating instance).
- `subnet_id`: Id of subnet to be used by instance that indicates the avaliability zone (only required if creating instance).
- `target_dev_id`: Specifies where to attach target volume (Ex. /dev/sdg)
- `username`: Username to be used for SSH access.

### target_vms
This section lists the VMs that will be analyzed. A name for each target VM must be specified. This name will be used in the tool output. Under each name, the following options must be configured.
- `instance_id`: Id of ec2 instance.
- `ip`: IP address of ec2 instance.
- `key_path`: Path to the SSH key that should be used to access instance.
- `profile_name`: Filename of volatility profile to be used.
- `profile_path`: Path to volatility profile to be used.
- `volatility_name`: Name of the memory profile as it appears in Volatility (can be found by using `--info` argument with Volatility)
- `target_dev_id`: Specifies where to attach target volume (Ex. /dev/sdg)
- `username`: Username to be used for SSH access.

### target_volume
This section specifies information for the target volumes that will be used to collect and transfer evidence. These volumes are deleted after the necessary data has been transferred to a master volume.
- `availability_zone`: Zone in which the volume should be created.
- `vol_size`: Volume size in GB.

## cloud-ir Design
There are two ec2 VM types referred to by the tool:
- Target VMs: Infected VMs to collect snapshots and memory images from
- Forensics VMs: VMs with forensics tools to perform analysis of volumes and memory
  - Using multiple forensics VMs increases performance

The general flow of cloud-ir is described below:
- If forensics VMs do not exists, create them.
- If master volumes do not exist, create them.
  - Master volumes are attached to their designated forensics VM.
- Data Collection:
  - For each target VM, create a target volume.
  - Attach target volume to forensics VM for configuration.
  - Detach target volume from forensics VM.
  - Attach target volume to target VM.
  - Take snapshot and acquire memory dump.
    - Memory dump acquired using Acquire Volatile Memory for Linux (AVML) tool made by Microsoft.
    - Tools and dumps are stored on target volume.
  - Detach target volume from target VM.
- Data Transfer:
  - Attach target volume to forensics VM.
  - Copy captured evidence to master volume.
  - Detach target volume from forensics VM.
- Data Analysis on Forensics VM:
  - Analyze key volume files.
    - SSH config, hosts, crontab, passwd, shadow, groups, sudoers, logs
  - Analyze memory using Volatility 2.
    - Plugins: linux_pstree, linux_bash, linux_psaux, linux_netstat, linux_mount, linux_lsmod
  - Upload generated reports to s3 bucket.
    - Example reports can be seen [here](./examples/)
- Delete all target volumes.