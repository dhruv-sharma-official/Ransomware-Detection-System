import os
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, filedialog
import time
import threading

STATUS_FILE = "status.txt"
COMMAND_FILE = "command.txt"
PREMIUM_FOLDERS_FILE = "premiumfolder.txt"
MONITORING_FOLDERS = "monitoring_locations.txt"

class DarkModeMonitorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ransomware Monitor Control Panel")
        self.geometry("750x400")
        self.configure(bg="#2b2b2b")  # Dark background for the main window

        # Output Panel (Scrolled Textbox)
        self.output_panel = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=90, height=20,
                                                      bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff")
        self.output_panel.pack(pady=10)

        # Frame for buttons
        button_frame = tk.Frame(self, bg="#2b2b2b")
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        # Buttons
        button_style = {"bg": "#4a4a4a", "fg": "#ffffff", "activebackground": "#666666", "activeforeground": "#ffffff"}
        
        self.start_button = tk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring, **button_style)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.stop_button = tk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, **button_style)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.premium_folders_button = tk.Button(button_frame, text="Add Monitoring Folders", command=self.add_monitoringfolders, **button_style)
        self.premium_folders_button.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.clear_output_button = tk.Button(button_frame, text="Clear Output", command=self.clear_output, **button_style)
        self.clear_output_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.premium_bridge = tk.Button(button_frame, text="Force Premium Bridge", command=self.backup, **button_style)
        self.premium_bridge.pack(side=tk.LEFT, padx=5, pady=10)
        
        self.premium_folders_button = tk.Button(button_frame, text="Premium Folders", command=self.add_premium_folders, **button_style)
        self.premium_folders_button.pack(side=tk.LEFT, padx=5, pady=10)

        # Start a thread to keep updating the status output
        self.update_thread = threading.Thread(target=self.update_output)
        self.update_thread.daemon = True
        self.update_thread.start()

    def backup(self):
        self.write_command("backup")
        self.output_panel.insert(tk.END, "Command Sent: Backup\n")
        self.output_panel.see(tk.END)

    def add_premium_folders(self):
        folder_path = filedialog.askdirectory(mustexist=True)
        if folder_path:
            with open(PREMIUM_FOLDERS_FILE, 'a') as f:
                f.write(folder_path + '\n')
            self.output_panel.insert(tk.END, f"Added folder: {folder_path}\n")
            self.output_panel.see(tk.END)
        else:
            self.output_panel.insert(tk.END, "No folder selected.\n")
            self.output_panel.see(tk.END)

    def add_monitoringfolders(self):
        folder_path = filedialog.askdirectory(mustexist=True)
        if folder_path:
            with open(MONITORING_FOLDERS, 'a') as f:
                f.write(folder_path + '\n')
            self.output_panel.insert(tk.END, f"Added folder: {folder_path}\n")
            self.output_panel.see(tk.END)
        else:
            self.output_panel.insert(tk.END, "No folder selected.\n")
            self.output_panel.see(tk.END)

    def read_status_file(self):
        try:
            with open(STATUS_FILE, 'r') as file:
                return file.read()
        except FileNotFoundError:
            return "No status file found."

    def update_output(self):
        while True:
            status_content = self.read_status_file()
            self.output_panel.delete(1.0, tk.END)
            self.output_panel.insert(tk.END, status_content)
            self.output_panel.see(tk.END)
            time.sleep(2)

    def write_command(self, command):
        with open(COMMAND_FILE, 'w') as command_file:
            command_file.write(f"{command}\n")

    def start_monitoring(self):
        self.write_command("START_MONITORING")
        self.output_panel.insert(tk.END, "Command Sent: Start Monitoring\n")
        self.output_panel.see(tk.END)

    def stop_monitoring(self):
        self.write_command("STOP_MONITORING")
        self.output_panel.insert(tk.END, "Command Sent: Stop Monitoring\n")
        self.output_panel.see(tk.END)

    def clear_output(self):
        self.output_panel.delete(1.0, tk.END)
        with open(STATUS_FILE, 'w') as command_file:
            command_file.write("")

if __name__ == "__main__":
    gui = DarkModeMonitorGUI()
    gui.mainloop()