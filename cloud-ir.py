# cloud-ir v1.0
# 4/25/2022
# Python tool to automate the incident response process for cloud-based machines.
#
# Authors: Zachary Leggett, Jonathan Aldridge
#
#!/usr/bin/env python3

import paramiko
import yaml
import sys
import boto3
from itertools import islice
import time
import threading

DRYRUNFLAG = False
DEBUG = False # Debug flag, set to see verbose output
BENCHMARK = False

# Collects the memory image from the target machine using avml

def collect_mem(host, username, key, dump_name):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=username, pkey=k)

    print('Collecting memory image for', host)

    stdin, stdout, stderr = c.exec_command('sudo /mnt/evidence/avml ' + '/mnt/evidence/' + dump_name + '.lime')
    out = stdout.read().decode("utf-8")
    err = stderr.read().decode("utf-8")
    if DEBUG:
        print(out)
        print(err)
    c.close()

    print('***Memory image created successfully...\n')

# Copies the Volatility profile from the local machine to the forensics vm

def copy_files_to_remote(host, username, key, files):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)

    print("Connected to remote machine")

    sftp = c.open_sftp()
    for local in files:
        sftp.put(local, files[local], confirm=True)

    sftp.close()
    print('***Files successfully copied to remote machine', host, '\n')
    c.close()

# Copies files from forensics vm to local machine (UNUSED)

def copy_files_from_remote(host, username, key, files):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)
    print('connected')

    sftp = c.open_sftp()
    for remote in files:
        sftp.get(remote, files[remote])

    sftp.close()
    print('files copied from remote machine')
    c.close()

# Uses Volatility to analyze the memory images from the target vms and create the report

def analyze_mem(host, username, key, profile, dump_name):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=username, pkey=k)

    print('Starting memory image analysis')

    commands = ['linux_pstree', 'linux_bash', 'linux_psaux', 'linux_netstat', 'linux_mount', 'linux_lsmod']
    dump_path = '/mnt/master/' + dump_name + '_mem.txt'
    c.exec_command('echo -e Memory Information | sudo tee -a ' + dump_path)
    for command in commands:
        c.exec_command('echo -e \"\\n ------------------------ ' + command + ' ------------------------\" | sudo tee -a ' + dump_path)
        stdin, stdout, stderr = c.exec_command('sudo python2 ~/volatility/vol.py ' + command + ' --profile=' + profile + ' -f /mnt/master/' + dump_name + '.lime | sed \'/[***\]/d\' | sudo tee -a ' + dump_path)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)

    print('***Success!! Memory analysis completed successfully...')
    print('Report can be found at', dump_path, '\n')

    c.close()

# Pulls important files off of the volumes from the target vms and creates the report

def analyze_snapshot(host, username, key, dump_name):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)

    print('Analyzing volume snapshot from', host)

    files = {'SSH Config': '/etc/ssh/sshd_config', 'Hosts File': '/etc/hosts', 'Cron Jobs':'/etc/crontab', 'Passwd File': '/etc/passwd', 'Shadow File': '/etc/shadow', 'Groups': '/etc/group', 'Sudoers': '/etc/sudoers', 'Logs': '/var/log/yum.log'}
    dump_path = '/mnt/evidence/' + dump_name + '_vol.txt'
    c.exec_command('sudo bash -c \"echo -e Volume Information >> ' + dump_path + '\"')
    for f in files:
        c.exec_command('sudo bash -c \"echo -e \'\\n ------------------------ ' + f + ' ------------------------\' >> ' + dump_path + '\"')
        stdin, stdout, stderr = c.exec_command('sudo bash -c \"cat ' + files[f] + ' >> ' + dump_path + '\"')
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)
    stdin , stdout, stderr = c.exec_command('cat ' + dump_path)
    out = stdout.read().decode("utf-8")
    if DEBUG:
        print(out)

    print('***Success!! Volume snapshot analysis completed successfully...')
    print('Report can be found at', dump_path, '\n')

# Creates the forensics vm with the parameters specified in the config file

def create_forensics_vm(name, key_name, key_path, security_groups, subnet_id):
    ec2_client = boto3.resource('ec2')

    print('Creating vm with name ' + name)

    instances = ec2_client.create_instances(
        ImageId="ami-04505e74c0741db8d",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        KeyName=key_name,
        SubnetId=subnet_id,
        SecurityGroupIds=security_groups
    )
    print(name + ' created successfully')
    instances[0].wait_until_running()
    print(name + ' is now running')
    instances[0].load()
    public_ip = instances[0].public_ip_address
    instance_id = instances[0].instance_id
    print('public ip of ' + name + ' is: ' + public_ip)

    time.sleep(20)
    # Needed to make sure vm is up and has started ssh before continuing
    check_ssh(public_ip, 'ubuntu', key_path)
    k = paramiko.Ed25519Key.from_private_key_file(key_path)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(public_ip, username='ubuntu', pkey=k)

    commands = ['sudo apt-get update', 'git clone https://github.com/volatilityfoundation/volatility.git', 'curl -L https://github.com/microsoft/avml/releases/download/v0.6.1/avml > avml', 'chmod +x ./avml', 'mkdir ~/.aws/', 'sudo apt-get install python2 awscli -y']
    print('Installing packages for ' + name)
    for command in commands:
        stdin, stdout, stderr = c.exec_command(command, get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)

    print('Finished setting up ' + name)
    return public_ip, instance_id

# Checks if vm can be ssh'ed into

def check_ssh(host, username, key):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print('Checking SSH connection with 10 retries:')
    for i in range(10):
        try:
            c.connect(host, username=username, pkey=k)
            print('SSH successful')
            return True
        except Exception as e:
            print(e)
            time.sleep(5)
    print('Error can not SSH to VM')
    sys.exit()

# Creates forensics volume for holding and transferring forensics data from the target vm to the forensics vm

def create_forensics_vol(client, vol_size, availability_zone):

    print('***Creating volume***')

    response = client.create_volume(
        AvailabilityZone = availability_zone,
        Encrypted = False,
        Size = vol_size,
        VolumeType = 'gp2',
        DryRun = DRYRUNFLAG
    )

    if DEBUG:
        print(response['ResponseMetadata']['HTTPStatusCode'])

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        volume_id = response['VolumeId']
        
        client.get_waiter('volume_available').wait(
            VolumeIds=[volume_id],
            DryRun = DRYRUNFLAG
        )
        print('***Success!! volume:', volume_id, 'created...\n')
    else:
        print('***Volume creation failed***')

    return volume_id

# Configures the forensics volume, sets up the partition correctly 
# and copies over any necessary tools

def configure_forensics_vol(client, instance_id, volume_id, dev_id, mnt_path, host, username, key):

    attach_forensics_vol(client, instance_id, volume_id, dev_id)
    time.sleep(5)
    commands = ['echo \'type=83\' | sudo sfdisk ' + dev_id.replace('s', 'xv', 1), 'sudo mkfs.ext4 ' + dev_id.replace('s', 'xv', 1) + '1', 'sudo mkdir ' + mnt_path, 'sudo mount -t auto -v ' + dev_id.replace('s', 'xv', 1) + '1 ' + mnt_path, 'sudo cp avml /mnt/evidence/avml', 'sudo umount ' + dev_id.replace('s', 'xv', 1) + '1']
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)

    print('Configuring forensics volume', volume_id)

    for command in commands:
        stdin, stdout, stderr = c.exec_command(command, get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)
        time.sleep(2)

    print('***Sucess!! Finsished configuring ' + volume_id + '\n')
    detach_forensics_vol(client, instance_id, volume_id, dev_id)

# Configures, attaches, and mounts the master volume for the forensics vm, sets up the partition

def configure_master_vol(client, instance_id, volume_id, dev_id, mnt_path, host, username, key):

    attach_forensics_vol(client, instance_id, volume_id, dev_id)
    time.sleep(5)
    commands = ['echo \'type=83\' | sudo sfdisk ' + dev_id.replace('s', 'xv', 1), 'sudo mkfs.ext4 ' + dev_id.replace('s', 'xv', 1) + '1', 'sudo mkdir ' + mnt_path, 'sudo mount -t auto -v ' + dev_id.replace('s', 'xv', 1) + '1 ' + mnt_path]
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)

    print('***Configuring master volume', volume_id)

    for command in commands:
        stdin, stdout, stderr = c.exec_command(command, get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)
        time.sleep(2)

    print('Finsished configuring ' + volume_id + '\n')

# Mounts volume to specified machine
    
def mount_volume(host, username, key, dev_id, mnt_path):
    commands = ['sudo mkdir ' + mnt_path, 'sudo mount -t auto -v ' + dev_id.replace('s', 'xv', 1) + '1 ' + mnt_path]
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print('Mounting volume', dev_id, 'to', mnt_path)

    c.connect(host, username=username, pkey=k)
    for command in commands:
        stdin, stdout, stderr = c.exec_command(command, get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)

    print('***Success!! Device', dev_id, 'mounted to host', host, '\n')

# Unmounts volume from specified machine

def unmount_volume(host, username, key, dev_id):
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print('Unmounting volume', dev_id, 'from', host)

    for i in range(10):
        c.connect(host, username=username, pkey=k)
        stdin, stdout, stderr = c.exec_command('sudo umount ' + dev_id.replace('s', 'xv', 1) + '1', get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)
        if 'busy' not in out and 'busy' not in err:
            break
        time.sleep(5)

    print('***Success!! Device', dev_id, 'is unmounted from host', host, '\n')

# Deletes the forensics volume 

def destroy_forensics_vol(client, resource, vol_id):
    volume = resource.Volume(vol_id)

    print('Deleting volume', vol_id)

    if volume.state == 'available':
        response = client.delete_volume(
            VolumeId = vol_id,
            DryRun = DRYRUNFLAG
        )
        print("***Volume deleted...\n")
    else:
        print("Cannot delete volume attatched to an instance")

# Attaches the forensics volume to a specified machine

def attach_forensics_vol(client, instance_id, vol_id, dev_id):

    print('Attaching volume', vol_id, 'to instance', instance_id)

    response = client.attach_volume(
        Device = dev_id,
        InstanceId = instance_id,
        VolumeId = vol_id,
        DryRun = DRYRUNFLAG
    )

    if response['ResponseMetadata']['HTTPStatusCode']== 200:
        client.get_waiter('volume_in_use').wait(
            VolumeIds=[vol_id],
            DryRun=DRYRUNFLAG
        )
        print('***Success!! volume', vol_id,' is attached to instance', instance_id, '\n')

    return vol_id

# Detaches the forensics volume from a specified machine

def detach_forensics_vol(client, instance_id, vol_id, dev_id):

    print('Detaching volume', vol_id, 'from instance', instance_id)

    response = client.detach_volume(
        Device = dev_id,
        InstanceId = instance_id,
        VolumeId = vol_id,
        DryRun = DRYRUNFLAG
    )

    if response['ResponseMetadata']['HTTPStatusCode']== 200:
            client.get_waiter('volume_available').wait(
                VolumeIds=[vol_id],
                DryRun=DRYRUNFLAG
                )
            print('***Success!! volume', vol_id, 'is detached from instance', instance_id, '\n')

# Takes volume snapshot of the target vm

def take_snapshot(resource, instance_id):
    instance = resource.Instance(instance_id)
    volume_iterator = instance.volumes.all()
    snapshots = []

    print('***Taking volume snapshots***')

    for v in volume_iterator:
        snapshot = resource.create_snapshot(
            VolumeId=v.id,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'Snapshot of volume ' + v.id
                        },
                    ]
                },
            ]
        )

        snapshot.wait_until_completed()
        snapshots.append(snapshot.id)

    print('***Success! Volume snapshots created for instance:', instance_id, '\n')

    return snapshots

# Copies forensics data from the forensics volume to the master volume

def copy_files_to_master(host, username, key, dump_name):
    commands = ['sudo cp /mnt/evidence/' + dump_name + '_vol.txt /mnt/master/' + dump_name + '_vol.txt', 'sudo cp /mnt/evidence/' + dump_name + '.lime /mnt/master/' + dump_name + '.lime']
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    c.connect(host, username=username, pkey=k)

    print('Copying incident files to master volume')

    for command in commands:
        c.exec_command(command, get_pty=True)
        time.sleep(2)

    print('***Files successfully copied to master volume...\n')

# Creates s3 bucket to upload the reports to

def create_bucket(client, name, region):

    print('Creating bucket', name, 'in region', region)

    if region == 'us-east-1':
        client.create_bucket(
            Bucket=name
            )
    else:
        client.create_bucket(
        Bucket=name,
        CreateBucketConfiguration={'LocationConstraint': region}
        )

    print('***Success!! Bucket', name, 'created successfully\n')

# Uploads reports from the master volume to the specified s3 bucket

def upload_files_bucket(host, username, key, bucket_name):
    commands = ['aws s3 sync /mnt/master/ s3://' + bucket_name + ' --exclude \"*\" --include \"*.txt\"']
    k = paramiko.Ed25519Key.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print('Uploading reports to bucket', bucket_name)

    c.connect(host, username=username, pkey=k)
    for command in commands:
        stdin, stdout, stderr = c.exec_command(command, get_pty=True)
        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        if DEBUG:
            print(out)
            print(err)

    print('***Reports uploaded successfully to bucket', bucket_name, '\n')

# Analyzes memory images of each target, exists for multithreading

def analyze_targets(target_info, targets, forensic_vm, dump_names):
    for target in targets:
        analyze_mem(forensic_vm['ip'], forensic_vm['username'], forensic_vm['key_path'], target_info[target]['volatility_name'], dump_names[target])

# Captures forensics data from each target

def capture_data(client, resource, target_vol_size, target_availability_zone, target_volumes, target_dumps, forensic_vm, target_info, targets):
    for target in targets:
        print('Creating volumes for ' + target)
        
        # Create forensics volume
        vol_id = create_forensics_vol(client, target_vol_size, target_availability_zone)
        #vol_id = 'vol-01434eb5ba89b2928'

        # Configure forensics volume
        configure_forensics_vol(client, forensic_vm['instance_id'], vol_id, forensic_vm['target_dev_id'], '/mnt/evidence', forensic_vm['ip'], forensic_vm['username'], forensic_vm['key_path'])
        # Associate target with the correct forensics volume
        target_volumes[target] = vol_id
        # Take volume snapshot of target
        take_snapshot(resource, target_info[target]['instance_id'])
        print('Collecting data from ' + target)
        # Create forensics data name with target name & timestamp & associate with correct target
        dump_name = target + '_' + time.strftime("%Y%m%d-%H%M%S")
        target_dumps[target] = dump_name
        # Attach forensics volume to target
        attach_forensics_vol(client, target_info[target]['instance_id'], vol_id, target_info[target]['target_dev_id'])
        # Delay to make sure volume attached correctly
        time.sleep(5)
        # Mount volume to target
        mount_volume(target_info[target]['ip'], target_info[target]['username'], target_info[target]['key_path'], target_info[target]['target_dev_id'], '/mnt/evidence')
        # Collect memory image of target
        collect_mem(target_info[target]['ip'], target_info[target]['username'], target_info[target]['key_path'], dump_name)
        # Pull important files off of target
        analyze_snapshot(target_info[target]['ip'], target_info[target]['username'], target_info[target]['key_path'], dump_name)
        # Delay to make sure files are pulled
        time.sleep(5)
        # Unmount volume from target
        unmount_volume(target_info[target]['ip'], target_info[target]['username'], target_info[target]['key_path'], target_info[target]['target_dev_id'])
        # Delay to make sure volume unmounts fully
        time.sleep(5)
        # Detach forensics volume from target
        detach_forensics_vol(client, target_info[target]['instance_id'], vol_id, target_info[target]['target_dev_id'])

def main():
    start_time = time.time()

    # Open config file and load information from it
    with open('config.yml', 'r') as f:
        config = yaml.safe_load(f)

    target_vms = config['target_vms']
    forensics_vms = config['forensics_vms']
    num_of_forensics_vms = len(config['forensics_vms'])
    num_of_targets = len(config['target_vms'])
    target_vol_size = config['target_volume']['vol_size']
    target_availability_zone = config['target_volume']['availability_zone']
    target_per_forensics = (num_of_targets + num_of_forensics_vms - 1) // num_of_forensics_vms

    # Associate targets with the forensics vm they will use (only important if more than one forensics vm exits)    
    target_count = 0
    target_to_forensics = {}
    for forensics_name in forensics_vms:
        target_to_forensics[forensics_name] = []
        for item in islice(target_vms.items(), target_count, target_count + target_per_forensics):
            target_to_forensics[forensics_name].append(item[0])
        target_count = target_count + target_per_forensics

    client = boto3.client('ec2')
    resource = boto3.resource('ec2')
    bucket = boto3.client('s3')

    master_volumes = {}
    for forensics_name in forensics_vms:
        # Check if forensics vm exists, if not make it
        if forensics_vms[forensics_name]['exists'] is False:
            if forensics_vms[forensics_name]['key_name'] is None:
                print('Error: Key_name must be specified to create a forensics vm')
                sys.exit()
            # Use default security groups if none specified in config
            if forensics_vms[forensics_name]['security_groups'] is None:
                security_groups = ['default']
            else:
                security_groups = forensics_vms[forensics_name]['security_groups']

            print('***Creating forensics VM***\n')

            # Create forensics vm with info from config file
            public_ip, instance_id = create_forensics_vm(forensics_name, forensics_vms[forensics_name]['key_name'], forensics_vms[forensics_name]['key_path'], security_groups, forensics_vms[forensics_name]['subnet_id'])
            user = 'ubuntu'
            config['forensics_vms'][forensics_name]['ip'] = public_ip
            config['forensics_vms'][forensics_name]['exists'] = True
            config['forensics_vms'][forensics_name]['username'] = 'ubuntu'
            config['forensics_vms'][forensics_name]['instance_id'] = instance_id

            print('***Forensics VM created sucessfully***\n')

        # Check if master volume exists, if not make it
        if config['forensics_vms'][forensics_name]['master_volume']['exists'] is False:

            print('***Creating master volume***')

            # Create master volume with info from config file
            master_vol_size = config['forensics_vms'][forensics_name]['master_volume']['vol_size']
            master_availability_zone = config['forensics_vms'][forensics_name]['master_volume']['availability_zone']
            vol_id = create_forensics_vol(client, master_vol_size, master_availability_zone)
            # Configure volume, set up partition
            configure_master_vol(client, config['forensics_vms'][forensics_name]['instance_id'], vol_id, config['forensics_vms'][forensics_name]['master_dev_id'], '/mnt/master', config['forensics_vms'][forensics_name]['ip'], config['forensics_vms'][forensics_name]['username'], config['forensics_vms'][forensics_name]['key_path'])
            #vol_id = 'vol-05ce701af8cc19a75'
            # Associate master volume with forensics vm
            master_volumes[forensics_name] = vol_id
            config['forensics_vms'][forensics_name]['master_volume']['vol_id'] = vol_id
            config['forensics_vms'][forensics_name]['master_volume']['exists'] = True
        else:
            print('***Master volume already exists, using existing volume...***\n')
            master_volumes[forensics_name] = config['forensics_vms'][forensics_name]['master_volume']['vol_id']

    # Create thread for each forensics vm to capture data
    target_volumes = {}
    target_dumps = {}
    capture_threads = []
    for forensics_name in forensics_vms:
        t = threading.Thread(target=capture_data, args=[client, resource, target_vol_size, target_availability_zone, target_volumes, target_dumps, forensics_vms[forensics_name], target_vms, target_to_forensics[forensics_name]])
        t.start()
        capture_threads.append(t)

    # Rejoin threads once all analysis is finished
    for t in capture_threads:
        t.join()

    # Copy files from forensics volume to master volume for each target to forensics vm
    target_count = 0
    for forensics_name in forensics_vms:
        for target in target_to_forensics[forensics_name]:
            #print('Key:{} Value:{}'.format(item[0], item[1]))
            # Get file names to pull
            dump_name = target_dumps[target]
            vol_id = target_volumes[target]
            files = {target_vms[target]['profile_path']: '/home/' + forensics_vms[forensics_name]['username'] + '/volatility/volatility/plugins/overlays/linux/' + target_vms[target]['profile_name'], forensics_vms[forensics_name]['aws_creds']: '/home/' + forensics_vms[forensics_name]['username'] + '/.aws/config'}
            copy_files_to_remote(forensics_vms[forensics_name]['ip'], forensics_vms[forensics_name]['username'], forensics_vms[forensics_name]['key_path'], files)
            # Attach forensics volume to forensics vm
            attach_forensics_vol(client, forensics_vms[forensics_name]['instance_id'], vol_id, forensics_vms[forensics_name]['target_dev_id'])
            # Delay to make sure volume attached correctly
            time.sleep(5)
            # Mount forensics volume to forensics vm
            mount_volume(forensics_vms[forensics_name]['ip'], forensics_vms[forensics_name]['username'], forensics_vms[forensics_name]['key_path'], forensics_vms[forensics_name]['target_dev_id'], '/mnt/evidence')
            # Copy files from forensics volume to master volume
            copy_files_to_master(forensics_vms[forensics_name]['ip'], forensics_vms[forensics_name]['username'], forensics_vms[forensics_name]['key_path'], dump_name)
            # Delay to allow files to copy
            time.sleep(20)
            # Unmount forensics volume from forensics vm
            unmount_volume(forensics_vms[forensics_name]['ip'], forensics_vms[forensics_name]['username'], forensics_vms[forensics_name]['key_path'], forensics_vms[forensics_name]['target_dev_id'])
            # Delay to make sure volume unmounts correctly
            time.sleep(5)
            # Detach forensics volume
            detach_forensics_vol(client, forensics_vms[forensics_name]['instance_id'], vol_id, forensics_vms[forensics_name]['target_dev_id'])
        target_count = target_count + target_per_forensics

    # Create thread for running memory image analysis
    analysis_threads = []
    for forensics_name in forensics_vms:
        t = threading.Thread(target=analyze_targets, args=[target_vms, target_to_forensics[forensics_name], forensics_vms[forensics_name], target_dumps])
        t.start()
        analysis_threads.append(t)

    # Rejoin threads once all analysis is finished
    for t in analysis_threads:
        t.join()

    # Create s3 bucket and upload the report files to it
    create_bucket(bucket, config['evidence_bucket']['name'], config['evidence_bucket']['region'])
    for forensics_name in forensics_vms:
        upload_files_bucket(forensics_vms[forensics_name]['ip'], forensics_vms[forensics_name]['username'], forensics_vms[forensics_name]['key_path'], config['evidence_bucket']['name'])

    # Destroy the no longer needed forensics volumes
    for vol in target_volumes:
        destroy_forensics_vol(client, resource, target_volumes[vol])

    # Write changes to config file
    with open('config.yml', 'w') as f:
        yaml.dump(config, f)
    
    if BENCHMARK:
        print("--- %s seconds ---" % (time.time() - start_time))

if __name__ == "__main__":
    main()
