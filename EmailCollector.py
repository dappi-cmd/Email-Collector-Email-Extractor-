import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import requests
from bs4 import BeautifulSoup
import re
import threading
from urllib.parse import urljoin, urlparse
import time
from collections import defaultdict
from datetime import datetime


class WebScraper:
    def __init__(self):
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.lock = threading.Lock()
        self.start_time = None

    def scan_website(self, url, visited, data_types, collected_data):
        if self.stop_event.is_set():
            return

        try:
            # Ignore SSL certificate validation
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Update the current directory (URL) being scanned
            current_directory.set(f"Scanning: {url}")

            # Choose patterns based on the selected data types
            patterns = []
            if "Email" in data_types:
                patterns.append(re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"))
            if "Telephone Numbers" in data_types:
                patterns.append(re.compile(r"\+?[0-9\s-]{7,15}"))

            found_data = defaultdict(set)
            for pattern in patterns:
                for item in pattern.findall(soup.get_text()):
                    found_data[pattern.pattern].add(item)

            with self.lock:
                for pattern, items in found_data.items():
                    for item in items:
                        collected_data[pattern].append((item, url))
                        # Update the Listbox
                        data_listbox.insert(tk.END, f"{item} - Found at: {url}")

                # Update the result count
                unique_items = len(set(item for sublist in collected_data.values() for item, _ in sublist))
                result_count.set(f"Results: {unique_items}")

            # Extract all internal links
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for link in soup.find_all('a', href=True):
                full_url = urljoin(base_url, link['href'])
                # Ensure the link is within the same domain and hasn't been visited
                if urlparse(full_url).netloc == urlparse(url).netloc and full_url not in visited:
                    visited.add(full_url)
                    if self.pause_event.is_set():
                        while self.pause_event.is_set():
                            time.sleep(1)  # Wait while paused
                    self.scan_website(full_url, visited, data_types, collected_data)  # Recursive call to scan the next link
        except requests.exceptions.RequestException as e:
            print(f"Error scanning {url}: {e}")

    def run_scan(self, url, visited, data_types, collected_data):
        self.start_time = datetime.now()
        self.stop_event.clear()
        self.pause_event.clear()
        self.scan_website(url, visited, data_types, collected_data)
        progress_bar.stop()
        end_time = datetime.now()
        total_time = end_time - self.start_time
        current_directory.set(f"Scan Complete - Total Time: {str(total_time).split('.')[0]}")
        scan_time.set(f"Elapsed Time: {str(total_time).split('.')[0]}")


def start_scan():
    global collected_data, url, scan_thread, scraper

    url = entry.get()
    if not url.startswith("http"):
        url = "http://" + url

    data_types = [data_type for data_type, var in data_type_vars.items() if var.get()]
    if not data_types:
        messagebox.showwarning("No Data Type Selected", "Please select at least one data type to scan.")
        return

    visited = set()  # To keep track of visited URLs
    collected_data = defaultdict(list)  # To store found data and associated links

    visited.add(url)
    progress_bar.start()
    scan_start_time.set(f"Scan Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def run_scan_thread():
        scraper.run_scan(url, visited, data_types, collected_data)

    if scan_thread and scan_thread.is_alive():
        scraper.stop_event.set()
        scan_thread.join()

    scraper = WebScraper()
    scan_thread = threading.Thread(target=run_scan_thread)
    scan_thread.start()


def pause_scan():
    if scan_thread and scan_thread.is_alive():
        scraper.pause_event.set()
        current_directory.set("Paused")


def resume_scan():
    if scraper.pause_event.is_set():
        scraper.pause_event.clear()


def stop_scan():
    if scan_thread and scan_thread.is_alive():
        scraper.stop_event.set()
        scan_thread.join()
        progress_bar.stop()
        current_directory.set("Scan Stopped")


def save_data():
    if collected_data:
        # Generate a timestamp for the file name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_location = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"{url.split('//')[-1].replace('www.', '').replace('.com', '').replace('/', '')}_results_{timestamp}.txt"
        )
        if save_location:
            with open(save_location, "w") as file:
                file.write(f"Scan Start Time: {scan_start_time.get()}\n")
                file.write(f"Scan End Time: {current_directory.get().split(' - ')[1]}\n")
                file.write(f"Elapsed Time: {scan_time.get()}\n\n")
                for pattern, items in collected_data.items():
                    for item, link in items:
                        file.write(f"{item} - Found at: {link}\n")
            messagebox.showinfo("Success", f"Data saved to {save_location}")
    else:
        messagebox.showinfo("No Data Found", "No data found on this website.")


def exit_program():
    stop_scan()
    root.quit()


# Create the main window
root = tk.Tk()
root.title("Website Data Scraper")

# Allow resizing of the form
root.geometry("800x600")
root.minsize(600, 400)  # Minimum size for the window
root.resizable(True, True)  # Allow resizing in both directions

# Styling
style = ttk.Style()
style.configure("TButton", relief="raised", padding=6)
style.configure("TCheckbutton", padding=6)
style.configure("TProgressbar", thickness=20)
style.configure("TLabel", padding=6)

# URL entry
tk.Label(root, text="Enter Website URL:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=80, font=("Arial", 12))
entry.pack(pady=10)

# Data type selection
tk.Label(root, text="Select Data Types:", font=("Arial", 12)).pack(pady=10)
checkbox_frame = tk.Frame(root)
checkbox_frame.pack(pady=10)

data_type_vars = {
    "Email": tk.BooleanVar(value=False),
    "Telephone Numbers": tk.BooleanVar(value=False)
}
for data_type, var in data_type_vars.items():
    ttk.Checkbutton(checkbox_frame, text=data_type, variable=var, style="TCheckbutton").pack(anchor='w')

# Progress bar
progress_bar = ttk.Progressbar(root, orient='horizontal', mode='indeterminate', length=700)
progress_bar.pack(pady=20)

# Display current scanning directory (URL)
current_directory = tk.StringVar()
current_directory.set("Ready")
tk.Label(root, textvariable=current_directory, font=("Arial", 12), fg="blue").pack(pady=10, anchor='w')

# Display scan start time
scan_start_time = tk.StringVar()
scan_start_time.set("Scan Start Time: Not Started")
tk.Label(root, textvariable=scan_start_time, font=("Arial", 12), fg="purple").pack(pady=5, anchor='w')

# Display elapsed time
scan_time = tk.StringVar()
scan_time.set("Elapsed Time: 00:00:00")
tk.Label(root, textvariable=scan_time, font=("Arial", 12), fg="green").pack(pady=5)

# Result count label
result_count = tk.StringVar()
result_count.set("Results: 0")
tk.Label(root, textvariable=result_count, font=("Arial", 12), fg="green").pack(pady=10)

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=20)

scan_button = ttk.Button(button_frame, text="Start Scan", command=start_scan)
scan_button.pack(side=tk.LEFT, padx=5)

pause_button = ttk.Button(button_frame, text="Pause", command=pause_scan)
pause_button.pack(side=tk.LEFT, padx=5)

resume_button = ttk.Button(button_frame, text="Resume", command=resume_scan)
resume_button.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(button_frame, text="Stop", command=stop_scan)
stop_button.pack(side=tk.LEFT, padx=5)

save_button = ttk.Button(button_frame, text="Save", command=save_data)
save_button.pack(side=tk.LEFT, padx=5)

exit_button = ttk.Button(button_frame, text="Exit", command=exit_program)
exit_button.pack(side=tk.LEFT, padx=5)

# Listbox to display collected data
listbox_frame = tk.Frame(root)
listbox_frame.pack(fill=tk.BOTH, expand=True, pady=10)

data_listbox = tk.Listbox(listbox_frame, font=("Arial", 10), width=90, height=15)
data_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar to the listbox
scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=data_listbox.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

data_listbox.config(yscrollcommand=scrollbar.set)

# Initialize global variables
scraper = WebScraper()
collected_data = defaultdict(list)
url = ""
scan_thread = None

# Run the application
root.mainloop()