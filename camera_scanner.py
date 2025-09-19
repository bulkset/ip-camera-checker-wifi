import tkinter as tk
from tkinter import ttk, messagebox
import socket
import ipaddress
import threading
import queue

class CameraScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Camera Scanner")
        self.root.geometry("600x400")

        # Frame for input
        input_frame = ttk.Frame(root)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Network Range (e.g., 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5)
        self.network_entry = ttk.Entry(input_frame, width=30)
        self.network_entry.grid(row=0, column=1, padx=5, pady=5)
        self.network_entry.insert(0, self.get_default_network())

        ttk.Label(input_frame, text="Ports to scan (comma-separated):").grid(row=1, column=0, padx=5, pady=5)
        self.ports_entry = ttk.Entry(input_frame, width=30)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ports_entry.insert(0, "80,554,8080,8081")

        # Scan button
        self.scan_button = ttk.Button(input_frame, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(root, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # Results list
        columns = ("IP", "Open Ports")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Open Ports", text="Open Ports")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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
        except ValueError:
            messagebox.showerror("Error", "Invalid ports format")
            return

        self.scan_button.config(state="disabled")
        self.tree.delete(*self.tree.get_children())

        # Start scan in thread
        thread = threading.Thread(target=self.scan_network, args=(network, ports))
        thread.start()

        # Start checking queue
        self.root.after(100, self.check_queue)

    def scan_network(self, network, ports):
        try:
            net = ipaddress.ip_network(network, strict=False)
            total_hosts = net.num_addresses - 2  # Exclude network and broadcast
            self.progress["maximum"] = total_hosts
            self.progress["value"] = 0

            for ip in net.hosts():
                self.scan_host(str(ip), ports)
                self.progress["value"] += 1

            self.queue.put("DONE")
        except Exception as e:
            self.queue.put(f"ERROR: {str(e)}")

    def scan_host(self, ip, ports):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(str(port))
                sock.close()
            except:
                pass
        if open_ports:
            self.queue.put((ip, ", ".join(open_ports)))

    def check_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item == "DONE":
                    self.scan_button.config(state="normal")
                    messagebox.showinfo("Scan Complete", "Network scan finished.")
                    return
                elif isinstance(item, tuple):
                    self.tree.insert("", tk.END, values=item)
                elif item.startswith("ERROR"):
                    messagebox.showerror("Error", item[6:])
                    self.scan_button.config(state="normal")
                    return
        except queue.Empty:
            pass
        self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = CameraScanner(root)
    root.mainloop()