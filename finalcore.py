import time
import threading
import os
import stat
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification
import shutil
import ai
import premiumfolder as backup
import ctypes

# Global variables to control monitoring
observer = None
monitoring = False

def load_directories_from_file(file_path="monitoring_locations.txt"):
    directories = []
    try:
        with open(file_path, 'r') as file:
            directories = [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        update_status(f"Error: {file_path} not found.")
    return directories

def delete_file(file_path):
    import os
    import time
    from win32com.shell import shell, shellcon

    max_attempts = 5
    delay = 1  #

    for attempt in range(max_attempts):
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
            print(f"Successfully deleted: {file_path}")
            return True
        except PermissionError:
            print(f"Attempt {attempt + 1}: File is still in use. Retrying in {delay} seconds...")
            time.sleep(delay)
            
            
            if attempt == max_attempts - 1:
                try:
                    shell.SHFileOperation((0, shellcon.FO_DELETE, file_path, None, 
                                           shellcon.FOF_SILENT | shellcon.FOF_ALLOWUNDO | shellcon.FOF_NOCONFIRMATION,
                                           None, None))
                    print(f"Deleted using shell operation: {file_path}")
                    return True
                except Exception as e:
                    print(f"Failed to delete using shell operation: {e}")

    print(f"Failed to delete after {max_attempts} attempts: {file_path}")
    return False

def send_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        app_name="Malware Detector",
        timeout=10
    )

def update_status(message):
    with open("status.txt", 'a') as status_file:
        status_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)

def scanner(file_path):
    is_malicious = ai.scanfile(file_path)
    if is_malicious:
        update_status(f"Malicious file detected: {file_path}")
        send_notification("Malicious File Detected", f"File: {file_path}")
        delete_file(file_path)

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            update_status(f"File modified: {event.src_path}")
            scanner(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            update_status(f"File created: {event.src_path}")
            scanner(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            update_status(f"File deleted: {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory:
            update_status(f"File moved from {event.src_path} to {event.dest_path}")
            scanner(event.dest_path)

def start_monitoring():
    global observer, monitoring
    if monitoring:
        update_status("Already monitoring.")
        return

    directories_to_monitor = set(load_directories_from_file())

    if not directories_to_monitor:
        update_status("No directories to monitor. Please check the file.")
        return

    event_handler = MonitorHandler()
    observer = Observer()

    def add_directory_to_observer(directory):
        try:
            observer.schedule(event_handler, path=directory, recursive=True)
            update_status(f"Monitoring: {directory}")
        except Exception as e:
            update_status(f"Failed to monitor directory {directory}: {str(e)}")

    for directory in directories_to_monitor:
        add_directory_to_observer(directory)

    observer.start()
    monitoring = True
    update_status("Monitoring started.")

def stop_monitoring():
    global observer, monitoring
    if observer and monitoring:
        observer.stop()
        observer.join()
        observer = None
        monitoring = False
        update_status("Monitoring stopped.")
    else:
        update_status("No monitoring session to stop.")

def backup_files(source_dir, backup_dir):
    try:
        if os.path.exists(source_dir):
            shutil.copytree(source_dir, backup_dir, dirs_exist_ok=True)
            update_status(f"Backup completed from {source_dir} to {backup_dir}")
        else:
            update_status(f"Source directory {source_dir} does not exist.")
    except Exception as e:
        update_status(f"Error during backup: {e}")

def save_logs(log_file="logs.txt"):
    with open(log_file, 'a') as file:
        file.write("Log entry...\n")  # Replace with actual log entries
    update_status(f"Logs saved to {log_file}.")

def scan_file(file_path):
    if os.path.isfile(file_path):
        update_status(f"Scanning file: {file_path}")
        scanner(file_path)
    else:
        update_status(f"Error: {file_path} is not a valid file.")

def process_commands(command_file="command.txt"):
    while True:
        try:
            if os.path.isfile(command_file):
                with open(command_file, 'r') as file:
                    commands = [line.strip() for line in file.readlines() if line.strip()]

                for command in commands:
                    if command == "START_MONITORING":
                        start_monitoring()
                    elif command == "STOP_MONITORING":
                        stop_monitoring()
                    elif command == "savelogs":
                        save_logs()
                    elif command.startswith("backup"):
                        backup.create_incremental_backup()
                    elif command.startswith("scanfile"):
                        _, file_path = command.split(maxsplit=1)
                        scan_file(file_path)
                    else:
                        update_status(f"Unknown command: {command}")

                open(command_file, 'w').close()

            time.sleep(5)
        except Exception as e:
            update_status(f"Error processing commands: {e}")

if __name__ == "__main__":
    # Check for admin rights on Windows
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            update_status("Warning: This script may require administrator privileges to delete certain files.")
    
    command_thread = threading.Thread(target=process_commands, daemon=True)
    command_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_monitoring()
        update_status("Program terminated.")