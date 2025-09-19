import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import ipaddress
import threading
import queue
import concurrent.futures
import csv

class CameraScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Camera Scanner")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')

        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Arial', 10, 'bold'), padding=5)
        style.configure('TLabel', font=('Arial', 10), background='#f0f0f0')
        style.configure('TEntry', font=('Arial', 10))
        style.configure('Treeview', font=('Arial', 9), rowheight=25)
        style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))

        self.scanning = False
        self.executor = None
        self.results = []

        # Title
        title_label = ttk.Label(root, text="IP Camera Network Scanner", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)

        # Frame for input
        input_frame = ttk.Frame(root, relief='ridge', borderwidth=2, padding=10)
        input_frame.pack(pady=10, padx=10, fill='x')

        ttk.Label(input_frame, text="Network Range (e.g., 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.network_entry = ttk.Entry(input_frame, width=30)
        self.network_entry.grid(row=0, column=1, padx=5, pady=5)
        self.network_entry.insert(0, self.get_default_network())

        ttk.Label(input_frame, text="Ports to scan (comma-separated):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.ports_entry = ttk.Entry(input_frame, width=30)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ports_entry.insert(0, "80,554,8080,8081")

        ttk.Label(input_frame, text="Max threads:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.threads_entry = ttk.Entry(input_frame, width=10)
        self.threads_entry.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        self.threads_entry.insert(0, "50")

        # Buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        self.scan_button = ttk.Button(button_frame, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(button_frame, text="Save Results", command=self.save_results, state="disabled")
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Separator
        ttk.Separator(root, orient='horizontal').pack(fill='x', padx=10)

        # Status and progress
        status_frame = ttk.Frame(root)
        status_frame.pack(pady=5, padx=10, fill='x')
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress.pack(side=tk.RIGHT, fill='x', expand=True, padx=(10,0))

        # Separator
        ttk.Separator(root, orient='horizontal').pack(fill='x', padx=10)

        # Results
        results_frame = ttk.Frame(root)
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        columns = ("IP", "Open Ports")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Open Ports", text="Open Ports")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Queue for thread communication
        self.queue = queue.Queue()

    def get_default_network(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Assume /24 subnet
            ip_parts = local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except:
            return "192.168.1.0/24"

    def start_scan(self):
        network = self.network_entry.get()
        ports_str = self.ports_entry.get()
        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
            max_threads = int(self.threads_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid format")
            return

        self.scanning = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.save_button.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.status_label.config(text="Starting scan...")

        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

        # Start scan in thread
        thread = threading.Thread(target=self.scan_network, args=(network, ports))
        thread.start()

        # Start checking queue
        self.root.after(100, self.check_queue)

    def scan_network(self, network, ports):
        try:
            net = ipaddress.ip_network(network, strict=False)
            total_hosts = net.num_addresses - 2
            self.progress["maximum"] = total_hosts
            self.progress["value"] = 0

            futures = [self.executor.submit(self.scan_host, str(ip), ports) for ip in net.hosts()]
            for future in concurrent.futures.as_completed(futures):
                if not self.scanning:
                    break
                result = future.result()
                if result:
                    self.queue.put(result)
                self.progress["value"] += 1
                self.queue.put(("PROGRESS", self.progress["value"]))

            self.queue.put("DONE")
        except Exception as e:
            self.queue.put(f"ERROR: {str(e)}")
        finally:
            if self.executor:
                self.executor.shutdown(wait=False)

    def scan_host(self, ip, ports):
        if not self.scanning:
            return None
        self.queue.put(("STATUS", ip))
        open_ports = []
        for port in ports:
            if not self.scanning:
                return None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(str(port))
                sock.close()
            except:
                pass
        if open_ports:
            return (ip, ", ".join(open_ports))
        return None

    def stop_scan(self):
        self.scanning = False
        self.status_label.config(text="Stopping...")
        if self.executor:
            self.executor.shutdown(wait=False)
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def save_results(self):
        if not self.results:
            messagebox.showinfo("No Results", "No results to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP Address", "Open Ports"])
                writer.writerows(self.results)
            messagebox.showinfo("Saved", "Results saved successfully.")

    def check_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item == "DONE":
                    self.scanning = False
                    self.scan_button.config(state="normal")
                    self.stop_button.config(state="disabled")
                    self.save_button.config(state="normal")
                    self.status_label.config(text="Scan complete")
                    messagebox.showinfo("Scan Complete", "Network scan finished.")
                    return
                elif isinstance(item, tuple):
                    if item[0] == "STATUS":
                        self.status_label.config(text=f"Scanning: {item[1]}")
                    elif item[0] == "PROGRESS":
                        self.progress["value"] = item[1]
                    else:
                        self.tree.insert("", tk.END, values=item)
                        self.results.append(item)
                elif item.startswith("ERROR"):
                    self.scanning = False
                    self.scan_button.config(state="normal")
                    self.stop_button.config(state="disabled")
                    messagebox.showerror("Error", item[6:])
                    return
        except queue.Empty:
            pass
        self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = CameraScanner(root)
    root.mainloop()