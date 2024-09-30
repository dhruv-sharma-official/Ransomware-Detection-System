# Ransomware-Detection-System

This project is a Python-based tool designed to monitor the entire system for ransomware-related activities. It detects suspicious file changes, tracks potential ransomware processes, and interacts with the user to either quarantine or terminate harmful files and processes. This tool is designed to provide robust protection against ransomware attacks and other malicious encryption behaviors.

# Key Features:

Real-time System Monitoring: Monitors system-wide file changes and process activities.

Honey File Detection: Uses strategically placed honey files to detect unauthorized access, signaling potential ransomware activity.

Process Monitoring: Tracks processes for abnormal behavior, such as excessive file modifications and CPU usage spikes.

User Interaction: Alerts the user when suspicious activity is detected, providing options to quarantine, delete, or terminate malicious processes.

Customizable Extensions: Detects known ransomware file extensions and can be extended with more extensions as needed.

Log Management: Maintains a detailed log of suspicious activity and allows users to save the logs for future analysis.

# How It Works:

Honey Files: The tool creates hidden honey files in your system. If these files are accessed, the tool raises an alarm, as ransomware often accesses many files in bulk.

Process Monitoring: If a process shows unusual activity, such as encrypting multiple files or utilizing excessive CPU resources, it is flagged for user approval.

User-Driven Decisions: The tool provides easy-to-use options for the user to terminate suspicious processes or delete/ quarantine harmful files.

Mass File Modifications: The tool detects mass file modifications (common with ransomware encryptions) within a specified time window, prompting alerts.
