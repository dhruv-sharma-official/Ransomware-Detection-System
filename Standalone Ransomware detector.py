import os
import time
import psutil
import tkinter as tk
from tkinter import messagebox, filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread
from collections import deque
import random
import string

# defined
CPU_THRESHOLD = 80  #  if monitored in percentage
FILE_MODIFICATION_THRESHOLD = 100  # min number of files modified
TIME_WINDOW = 10  # seconds in which mass file changes should be detected
RANSOMWARE_EXTENSIONS = ['.enc', '.crypt', '.locked', '.payme']

# honey file creation if they dont exists
def create_honey_files(gui):
    honey_files = []
    home_directory = os.path.expanduser('~')
    honey_dir = os.path.join(home_directory, 'ransomware_honey_files')
    
    if not os.path.exists(honey_dir):
        os.makedirs(honey_dir)
        gui.log_alert(f"Honey file directory created: {honey_dir}")

    # checking if files already exists
    existing_honey_files = [f for f in os.listdir(honey_dir) if f.endswith('.txt')]
    
    if len(existing_honey_files) < 2:  # creates files if there are ess htan 2
        for i in range(2 - len(existing_honey_files)):
            honey_file_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '.txt'
            honey_file_path = os.path.join(honey_dir, honey_file_name)
            honey_files.append(honey_file_path)
            
            with open(honey_file_path, 'w') as f:
                f.write("This is a honey file to detect ransomware access.")
            gui.log_alert(f"Honey file created: {honey_file_path}")
    else:
        honey_files = [os.path.join(honey_dir, f) for f in existing_honey_files]
        gui.log_alert("Honey files already exist.")

    return honey_files

# file monnitorng and ransomware soft
class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, gui):
        self.modified_files = deque(maxlen=FILE_MODIFICATION_THRESHOLD)
        self.gui = gui

    def on_modified(self, event):
        if not event.is_directory and self.gui.monitoring_active:
            self.modified_files.append((time.time(), event.src_path))
            self.check_mass_file_modifications()
            if any(event.src_path.endswith(ext) for ext in RANSOMWARE_EXTENSIONS):
                self.gui.log_alert(f"Potential ransomware detected: {event.src_path}")
                self.ask_user_confirmation("File Modification", f"Potential ransomware detected: {event.src_path}")

    def check_mass_file_modifications(self):
        ## detects if toomany files are modified
        current_time = time.time()
        self.modified_files = deque((t, f) for t, f in self.modified_files if current_time - t <= TIME_WINDOW)
        if len(self.modified_files) >= FILE_MODIFICATION_THRESHOLD:
            self.gui.log_alert(f"Suspicious mass file modifications detected (over {FILE_MODIFICATION_THRESHOLD} files in {TIME_WINDOW} seconds).")
            self.ask_user_confirmation("Mass File Modifications", f"Suspicious mass file modifications detected.")

    def ask_user_confirmation(self, title, message):
        user_response = messagebox.askyesno(title, message)
        if user_response:
            self.gui.log_alert("User approved the action.")
        else:
            self.gui.log_alert("User denied the action.")

# feature 2 =  process monitor for cpu usage
def monitor_high_cpu_usage(gui):
    while gui.monitoring_active:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            if proc.info['pid'] == 0:  # skipping pid 2 here
                continue
            if proc.info['cpu_percent'] > CPU_THRESHOLD and gui.monitoring_active:
                gui.log_alert(f"Suspicious process: {proc.info['name']} (PID {proc.info['pid']}) using high CPU.")
                user_response = ask_user_for_process_action(gui, proc.info['name'], proc.info['pid'])
                if user_response:
                    kill_suspicious_process(proc.info['pid'], gui)
        time.sleep(5)


def ask_user_for_process_action(gui, process_name, pid):
    user_response = messagebox.askyesno(
        "High CPU Usage Detected",
        f"Process {process_name} (PID {pid}) is using high CPU.\nDo you want to terminate it?"
    )
    if user_response:
        gui.log_alert(f"User approved to terminate process {process_name} (PID {pid}).")
        return True
    else:
        gui.log_alert(f"User denied termination of process {process_name} (PID {pid}).")
        return False

def kill_suspicious_process(pid, gui):
    try:
        process = psutil.Process(pid)
        process.terminate()
        gui.log_alert(f"Process with PID {pid} terminated.")
    except psutil.NoSuchProcess:
        gui.log_alert(f"Process with PID {pid} not found.")

# featre 3= honey files access monitoring
def monitor_honey_files(gui, honey_files):
    access_times = {file: os.path.getatime(file) for file in honey_files}
    while gui.monitoring_active:
        for file in honey_files:
            current_access_time = os.path.getatime(file)
            if current_access_time != access_times[file]:
                access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_access_time))
                gui.log_alert(f"Honey file {file} accessed at {access_time}! Potential ransomware activity.")
                
                # finding the process that accessed honey files
                accessing_process = find_accessing_process(file)
                if accessing_process:
                    gui.log_alert(f"Accessed by process: {accessing_process['name']} (PID {accessing_process['pid']})")
                
                ask_user_for_honey_file_action(gui, file)
                access_times[file] = current_access_time  # updating access time
        time.sleep(5)

def find_accessing_process(file):
    # taking all current processes
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            #checking process accesss with the honey files if they are same
            for f in proc.open_files():
                if f.path == file:
                    return {'name': proc.info['name'], 'pid': proc.info['pid']}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def ask_user_for_honey_file_action(gui, honey_file):
    user_response = messagebox.askyesno(
        "Honey File Access Detected",
        f"Honey file {honey_file} accessed!\nDo you want to proceed with action?"
    )
    if user_response:
        gui.log_alert(f"User approved action on honey file {honey_file}.")
    else:
        gui.log_alert(f"User denied action on honey file {honey_file}.")

# started file monitoring
def start_file_monitoring(path_to_watch, gui):
    event_handler = RansomwareHandler(gui)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    try:
        while gui.monitoring_active:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# gui interface
class RansomwareDetectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Detection System")
        self.root.geometry("600x500")
        self.root.config(bg="#2b2b2b")
        
        self.monitoring_active = False

        self.status_label = tk.Label(root, text="Monitoring inactive", font=("Arial", 14), fg="white", bg="#2b2b2b")
        self.status_label.pack(pady=10)
        
        self.log_text = tk.Text(root, height=15, bg="#1e1e1e", fg="white", font=("Arial", 10), wrap=tk.WORD)
        self.log_text.pack(pady=10, padx=10, fill=tk.BOTH)
        self.log_text.insert(tk.END, "System Initialized...\n")

        self.monitor_btn = tk.Button(root, text="Start Monitoring", command=self.start_monitoring, font=("Arial", 12), bg="#4CAF50", fg="white")
        self.monitor_btn.pack(pady=10)
        
        self.stop_btn = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, font=("Arial", 12), bg="#f44336", fg="white")
        self.stop_btn.pack(pady=10)

        self.save_btn = tk.Button(root, text="Save Logs", command=self.save_logs, font=("Arial", 12), bg="#2196F3", fg="white")
        self.save_btn.pack(pady=10)

    def log_alert(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.status_label.config(text="Monitoring active")
            
            # create honey files only if they dont already exist
            self.log_alert("Checking for honey files...")
            self.honey_files = create_honey_files(self)
            
            # start file system monitoring
            home_directory = os.path.expanduser('~')
            self.log_alert("Starting file system monitoring...")
            Thread(target=start_file_monitoring, args=(home_directory, self)).start()

            # start process monitoring
            self.log_alert("Starting process monitoring...")
            Thread(target=monitor_high_cpu_usage, args=(self,)).start()

            # start honey file monitoring
            self.log_alert("Starting honey file monitoring...")
            Thread(target=monitor_honey_files, args=(self, self.honey_files)).start()

    def stop_monitoring(self):
        if self.monitoring_active:
            self.monitoring_active = False
            self.status_label.config(text="Monitoring inactive")
            self.log_alert("Monitoring stopped.")

    def save_logs(self):
        ## saves logs to user directed directory
        log_content = self.log_text.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Logs"
        )
        if file_path:
            with open(file_path, "w") as log_file:
                log_file.write(log_content)
            self.log_alert(f"Logs saved to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareDetectionGUI(root)
    root.mainloop()
