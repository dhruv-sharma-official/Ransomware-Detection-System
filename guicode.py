import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import psutil
import os
import time

class AdvancedGUIApp:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_styles()
        self.create_notebook()
        self.create_tabs()
        self.setup_password_screen()

    def setup_window(self):
        self.root.title("Advanced Application")
        self.root.geometry("900x700")
        self.root.configure(bg="#0d0d0d")
        
        # Set app icon if available
        icon_path = "path_to_your_icon.ico"
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        else:
            print(f"Icon file not found at {icon_path}, skipping icon setting.")

    def create_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Consolas", 12), padding=6, background="#ff3333", foreground="white", borderwidth=0)
        style.map("TButton", background=[('active', '#e60000')])
        style.configure("TProgressbar", thickness=25, troughcolor='#262626', background='#ff3333')

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(pady=20, expand=True)

    def create_tabs(self):
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        self.tab4 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text='Tab 1')
        self.notebook.add(self.tab2, text='Tab 2')
        self.notebook.add(self.tab3, text='Tab 3')
        self.notebook.add(self.tab4, text='Tab 4')

        self.setup_tab1()
        self.setup_tab2()
        self.setup_tab3()
        self.setup_tab4()

    def setup_tab1(self):
        # Customize this method to set up your first tab
        title_label = tk.Label(self.tab1, text="Tab 1 Title", font=("Consolas", 24, "bold"), bg="#0d0d0d", fg="#ff3333")
        title_label.pack(pady=10)

        self.progress_bar = ttk.Progressbar(self.tab1, orient="horizontal", length=700, mode="determinate", style="TProgressbar")
        self.progress_bar.pack(pady=20)

        self.status_label = tk.Label(self.tab1, text="Status: Ready", font=("Consolas", 16), bg="#0d0d0d", fg="green")
        self.status_label.pack(pady=10)

    def setup_tab2(self):
        # Customize this method to set up your second tab
        settings_title = tk.Label(self.tab2, text="Settings", font=("Consolas", 20), bg="#0d0d0d", fg="#ff3333")
        settings_title.pack(pady=10)

        option1 = tk.Checkbutton(self.tab2, text="Option 1", font=("Consolas", 14), bg="#0d0d0d", fg="white", selectcolor="#ff3333")
        option1.pack(pady=5)

        option2 = tk.Checkbutton(self.tab2, text="Option 2", font=("Consolas", 14), bg="#0d0d0d", fg="white", selectcolor="#ff3333")
        option2.pack(pady=5)

    def setup_tab3(self):
        # Customize this method to set up your third tab
        logs_title = tk.Label(self.tab3, text="Logs", font=("Consolas", 20), bg="#0d0d0d", fg="#ff3333")
        logs_title.pack(pady=10)

        self.logs_text = tk.Text(self.tab3, height=15, width=80, bg="#1e1e1e", fg="white", font=("Consolas", 12), wrap=tk.WORD)
        self.logs_text.pack(pady=10)

    def setup_tab4(self):
        # Customize this method to set up your fourth tab
        stats_title = tk.Label(self.tab4, text="System Stats", font=("Consolas", 20), bg="#0d0d0d", fg="#ff3333")
        stats_title.pack(pady=10)

        self.cpu_label = tk.Label(self.tab4, text="CPU Usage: ", font=("Consolas", 14), bg="#0d0d0d", fg="white")
        self.cpu_label.pack(pady=5)
        self.memory_label = tk.Label(self.tab4, text="Memory Usage: ", font=("Consolas", 14), bg="#0d0d0d", fg="white")
        self.memory_label.pack(pady=5)

        self.update_system_stats()

    def update_system_stats(self):
        self.cpu_label.config(text=f"CPU Usage: {psutil.cpu_percent()}%")
        self.memory_label.config(text=f"Memory Usage: {psutil.virtual_memory().percent}%")
        self.root.after(1000, self.update_system_stats)

    def setup_password_screen(self):
        self.password_frame = tk.Frame(self.root, bg="#0d0d0d")
        password_label = tk.Label(self.password_frame, text="Enter Access Password", font=("Consolas", 16), fg="#ff3333", bg="#0d0d0d")
        password_label.pack(pady=20)
        self.password_entry = tk.Entry(self.password_frame, show="*", font=("Consolas", 16), width=20)
        self.password_entry.pack(pady=10)
        password_button = ttk.Button(self.password_frame, text="Access", command=self.access_control)
        password_button.pack(pady=20)
        self.password_frame.pack(pady=100)

    def access_control(self):
        password = "1234"  # Change this to your desired password
        user_input = self.password_entry.get()
        if user_input == password:
            self.password_frame.pack_forget()
            self.notebook.pack()
            messagebox.showinfo("Access Granted", "Welcome to the Advanced Application!")
        else:
            messagebox.showerror("Access Denied", "Incorrect Password! Try Again.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedGUIApp(root)
    app.run()