import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import subprocess 


vtapi = "ae030e70e3a27cb96e507044186df0500309e704d74c4c666c9daac02d600128" # virus total free

directories_to_monitor = [
    os.path.expanduser("~\\Documents"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\Desktop")
]

def scan_file_virustotal(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': vtapi}
    files = {'file': (file_path, open(file_path, 'rb'))}
    
    try:
        response = requests.post(url, files=files, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: Received status code {response.status_code} from VirusTotal")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def check_virustotal_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': vtapi, 'resource': resource}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: Received status code {response.status_code} from VirusTotal")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None


def delete_file(file_path):
    if kill_process_using_file(file_path):
        try:
            os.remove(file_path)
            print(f"Deleted flagged file: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {str(e)}")
    else:
        print(f"No process found using the file: {file_path}. Attempting deletion...")
        try:
            os.remove(file_path)
            print(f"Deleted flagged file: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {str(e)}")

def kill_process_using_file(file_path):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for item in proc.open_files():
                if file_path == item.path:
                    print(f"Killing process {proc.name()} (PID: {proc.pid}) using file {file_path}")
                    proc.kill()
                    return True
        except Exception as e:
            continue
    return False

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app
        self.scanned_files = set()  # to track scanned files
    
    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path not in self.scanned_files:
            self.app.update_status(f"File modified: {file_path}")
            self.scan_and_handle_file(file_path)
    
    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path not in self.scanned_files:
            self.app.update_status(f"File created: {file_path}")
            self.scan_and_handle_file(file_path)
    
    def scan_and_handle_file(self, file_path):
        if not os.path.exists(file_path):
            self.app.update_status(f"File no longer exists: {file_path}, skipping scan.")
            return  # xit if the file does not exist

        self.app.update_status(f"Scanning file: {file_path}")
        result = scan_file_virustotal(file_path)
        
        if result is None:  # chk if scan result is none due to an error
            self.app.update_status(f"Scan failed for file: {file_path}")
            return

        resource = result['resource']
        time.sleep(5)  # delay to wait for scan report to be available
        report = check_virustotal_report(resource)

        if report is None:  # check if report is none
            self.app.update_status(f"Report retrieval failed for file: {file_path}")
            return

        if report['positives'] > 0:
            self.app.update_status(f"Virus detected in file: {file_path}, deleting...")
            delete_file(file_path)
        else:
            self.app.update_status(f"No virus found in file: {file_path}")

        self.scanned_files.add(file_path)


def run_windows_defender_scan(app):
    app.update_status("Starting Windows Defender full scan...")
    try:
        scan_process = subprocess.Popen(
            [r"C:\Program Files\Windows Defender\MpCmdRun.exe", "-Scan", "-ScanType", "2"],  # Full scan
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        
        for line in scan_process.stdout:
            if "Scan in progress" in line:
                app.update_status("Scan in progress...")
                app.update_progress(50)  
            elif "Scan completed successfully" in line:
                app.update_status("Scan completed successfully.")
                app.update_progress(100) 
        
        app.update_status("Windows Defender scan finished.")
    except Exception as e:
        app.update_status(f"Error during Windows Defender scan: {str(e)}")


class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Tool")
        self.root.geometry("900x600")
        self.monitor_thread = None
        self.observer = None
        self.is_monitoring = False

        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, padx=20, pady=20)

        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.status_label = tk.Label(self.right_frame, text="Activity Status", font=("Arial", 14))
        self.status_label.pack(pady=10)

        self.status_text = tk.Text(self.right_frame, wrap=tk.WORD, height=25, width=70)
        self.status_text.pack(padx=10, pady=10)

        self.progress = tk.DoubleVar()
        self.progress_bar = tk.ttk.Progressbar(self.right_frame, orient="horizontal", length=400, mode="determinate", variable=self.progress)
        self.progress_bar.pack(pady=10)

        self.create_buttons()

    def create_buttons(self):
        
        start_monitor_btn = tk.Button(self.left_frame, text="Start Monitoring", width=20, command=self.start_monitoring)
        start_monitor_btn.pack(pady=10)

        
        stop_monitor_btn = tk.Button(self.left_frame, text="Stop Monitoring", width=20, command=self.stop_monitoring)
        stop_monitor_btn.pack(pady=10)

        
        system_scan_btn = tk.Button(self.left_frame, text="Full System Scan", width=20, command=self.start_full_system_scan)
        system_scan_btn.pack(pady=10)
    
    def start_monitoring(self):
        if not self.is_monitoring:
            self.update_status("Starting monitoring...")
            self.monitor_thread = threading.Thread(target=self.monitor_directories)
            self.monitor_thread.start()
            self.is_monitoring = True
        else:
            self.update_status("Monitoring already started.")

    def stop_monitoring(self):
        if self.is_monitoring:
            self.observer.stop()
            self.observer.join()
            self.update_status("Monitoring stopped.")
            self.is_monitoring = False
        else:
            self.update_status("No monitoring to stop.")

    def start_full_system_scan(self):
        
        threading.Thread(target=run_windows_defender_scan, args=(self,)).start()

    def monitor_directories(self):
        event_handler = MonitorHandler(self)
        self.observer = Observer()
        for directory in directories_to_monitor:
            self.update_status(f"Monitoring directory: {directory}")
            self.observer.schedule(event_handler, directory, recursive=True)
        self.observer.start()

        try:
            self.observer.join()
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

    def update_status(self, message):
        self.status_text.insert(tk.END, message + '\n')
        self.status_text.see(tk.END)

    def update_progress(self, value):
        self.progress.set(value)
        self.progress_bar.update_idletasks()


if __name__ == "__main__":
    import tkinter.ttk as ttk  # import ttk module for progress bar
    
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
