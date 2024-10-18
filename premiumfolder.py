import os
import datetime
import schedule
import time
import paramiko
import shutil
import hashlib
import json
from icecream import ic


def load_premiumfolders(file_path="premiumfolder.txt"):
    directories = []
    try:
        with open(file_path, 'r') as file:
            directories = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        update_status(f"Error: {file_path} not found.")
    # print(directories)
    return directories


def update_status(message):
    with open("status.txt", 'a') as status_file:
        status_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)  # For console output

# Configuration
# [line.strip() for line in file.readlines() if line.strip()]
REMOTE_SERVER = "192.168.89.132"
REMOTE_USERNAME = "user"
REMOTE_PASSWORD = "kali"
REMOTE_DIR = "/home/user/windows-backup/"

def calculate_file_hash(filepath):
    """Calculate MD5 hash of a file."""
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def get_files_info(directories):
    """Get information about all files in the given directories."""
    files_info = {}
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, directory)
                files_info[relative_path] = {
                    'mtime': os.path.getmtime(full_path),
                    'hash': calculate_file_hash(full_path)
                }
    return files_info

def create_incremental_backup():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"backup_{timestamp}"
    BACKUP_FOLDERS = load_premiumfolders()
    ic(backup_name)
    
    local_temp_dir = os.path.join(os.environ['TEMP'], backup_name)
    os.makedirs(local_temp_dir, exist_ok=True)
    
    try:
        ic("Connecting to SFTP server...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(REMOTE_SERVER, username=REMOTE_USERNAME, password=REMOTE_PASSWORD)
        
        ic("Opening SFTP session...")
        sftp = ssh.open_sftp()
        
        ic("Getting current files info...")

        current_files_info = get_files_info(BACKUP_FOLDERS)
        
        try:
            ic("Checking for previous backups...")
            previous_backups = sftp.listdir(REMOTE_DIR)
            previous_backups = [b for b in previous_backups if b.startswith("backup_") and b.endswith(".zip")]
            previous_backups.sort(reverse=True)
            
            if previous_backups:
                latest_backup = previous_backups[0].replace('.zip', '')
                remote_files_info = os.path.join(REMOTE_DIR, f"{latest_backup}_files_info.txt")
                local_files_info = os.path.join(local_temp_dir, "previous_files_info.txt")
                
                ic("Downloading latest files info...")
                try:
                    sftp.get(remote_files_info, local_files_info)
                    
                    with open(local_files_info, 'r') as f:
                        previous_files_info = json.load(f)
                    
                    ic("Creating incremental backup...")
                    for file, info in current_files_info.items():
                        if file not in previous_files_info or info != previous_files_info[file]:
                            for folder in BACKUP_FOLDERS:
                                local_file = os.path.join(folder, file)
                                if os.path.exists(local_file):  # Ensure file exists in this folder
                                    backup_file = os.path.join(local_temp_dir, file)
                                    os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                                    shutil.copy2(local_file, backup_file)
                    
                    ic("Incremental backup created")
                except IOError:
                    ic("Previous files_info.txt not found. Creating full backup...")
                    for folder in BACKUP_FOLDERS:
                        shutil.copytree(folder, local_temp_dir, dirs_exist_ok=True)
                    ic("Full backup created")
            else:
                ic("No previous backups found. Creating full backup...")
                for folder in BACKUP_FOLDERS:
                    shutil.copytree(folder, local_temp_dir, dirs_exist_ok=True)
                ic("Full backup created")
        
        except IOError as e:
            ic(f"IOError occurred while working with remote files: {str(e)}")
            ic("Attempting full backup due to error...")
            for folder in BACKUP_FOLDERS:
                shutil.copytree(folder, local_temp_dir, dirs_exist_ok=True)
            ic("Full backup created due to error")
        
        ic("Compressing the backup...")
        shutil.make_archive(local_temp_dir, 'zip', local_temp_dir)
        
        ic("Uploading the new backup...")
        remote_backup_file = f"{REMOTE_DIR}/{backup_name}.zip"
        sftp.put(f"{local_temp_dir}.zip", remote_backup_file)
        
        ic("Saving and uploading current files info...")
        local_files_info = os.path.join(os.environ['TEMP'], f"{backup_name}_files_info.txt")
        with open(local_files_info, 'w') as f:
            json.dump(current_files_info, f)
        remote_files_info = f"{REMOTE_DIR}/{backup_name}_files_info.txt"
        sftp.put(local_files_info, remote_files_info)
        
        ic(f"Backup completed and uploaded: {remote_backup_file}")
        ic(f"Files info uploaded: {remote_files_info}")
    
    except Exception as e:
        ic(f"An error occurred: {str(e)}")
    
    finally:
        if 'sftp' in locals():
            sftp.close()
        if 'ssh' in locals():
            ssh.close()
        
        ic("Cleaning up local files...")
        update_status(f"Premium Bridge Updated")
        shutil.rmtree(local_temp_dir, ignore_errors=True)
        if os.path.exists(f"{local_temp_dir}.zip"):
            os.remove(f"{local_temp_dir}.zip")
        if os.path.exists(local_files_info):
            os.remove(local_files_info)

# def start_premiumcover():
#     ic("Starting backup process")
    
#     # Run the first backup immediately
#     ic("Running immediate backup...")
#     create_incremental_backup()
    
#     # Schedule the second backup for 2 minutes from now
#     current_time = datetime.datetime.now()
#     second_backup_time = current_time + datetime.timedelta(minutes=2)
#     second_backup_time_str = second_backup_time.strftime("%H:%M")
    
#     ic(f"Scheduling second backup for {second_backup_time_str}")
#     schedule.every().day.at(second_backup_time_str).do(create_incremental_backup)
    
#     while True:
#         schedule.run_pending()
#         time.sleep(1)  # Check every second
        
#         # Stop after the second backup is complete
#         if datetime.datetime.now() > second_backup_time + datetime.timedelta(minutes=1):
#             ic("Both backups completed. Exiting.")
#             break

if __name__ == "__main__":
    create_incremental_backup()
