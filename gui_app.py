import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
import threading
import sys
import logging
from pathlib import Path
import json
import os
import time # For the TkinterLogHandler daemon thread

# Adjust sys.path to ensure modules are found if gui_app.py is run directly
# This assumes gui_app.py is in the project root
sys.path.append(str(Path(__file__).parent))
sys.path.append(str(Path(__file__).parent / 'vulnerability_scanner'))

from scan_pipeline_kali import KaliScanPipeline

# Configure logging for the GUI (important to capture logs from pipeline)
# This setup ensures that logs from all modules (ReconScanner, KaliScanPipeline, etc.)
# are routed through the root logger and then displayed in the GUI's log area.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GUIScanner")

class TextRedirector(object):
    """
    Redirects stdout and stderr to a tkinter Text widget.
    (Less preferred than a custom logging handler, but can catch unhandled prints)
    """
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
        # Store original stdout/stderr to also write there
        self.original_stdout = sys.__stdout__
        self.original_stderr = sys.__stderr__
        
    def write(self, str_to_write):
        self.widget.configure(state='normal')
        self.widget.insert(tk.END, str_to_write, self.tag)
        self.widget.see(tk.END)
        self.widget.configure(state='disabled')
        if self.tag == "stdout":
            self.original_stdout.write(str_to_write)
        else:
            self.original_stderr.write(str_to_write)

    def flush(self):
        self.original_stdout.flush()
        self.original_stderr.flush()

class TkinterLogHandler(logging.Handler):
    """
    Custom logging handler to send log records to a Tkinter Text widget.
    """
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.queue = []
        self.daemon_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.daemon_thread.start()

    def emit(self, record):
        msg = self.format(record)
        self.queue.append((msg, record.levelname))
        # Schedule a call to _update_log_widget in the main Tkinter thread
        # using after_idle to avoid direct GUI access from another thread
        self.text_widget.after_idle(self._update_log_widget)

    def _process_queue(self):
        # This thread's primary job is to format messages and put them in the queue.
        # The actual widget update happens in the main thread via after_idle.
        # No busy-waiting here; queue handling is implicit via emit() and after_idle.
        pass

    def _update_log_widget(self):
        while self.queue:
            msg, level = self.queue.pop(0)
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + "\n", level)
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')

class ScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Web Vulnerability Scanner - PBL6")
        self.geometry("1000x800")

        self.pipeline = None
        self.scan_thread = None
        self.stop_event = threading.Event() 
        self.last_scan_results = {} # To store results for display

        self._create_widgets()
        self._setup_logging_redirection()

    def _create_widgets(self):
        # --- Input Frame ---
        input_frame = ttk.LabelFrame(self, text="Scan Configuration", padding="10 10 10 10")
        input_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(input_frame, text="Target (Domain/IP/CIDR):").grid(row=0, column=0, sticky="w", pady=2)
        self.target_entry = ttk.Entry(input_frame, width=50)
        self.target_entry.insert(0, "localhost") # Default for local testing
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(input_frame, text="Masscan Rate (pps):").grid(row=1, column=0, sticky="w", pady=2)
        self.masscan_rate_entry = ttk.Entry(input_frame, width=50)
        self.masscan_rate_entry.insert(0, "1000")
        self.masscan_rate_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        input_frame.grid_columnconfigure(1, weight=1)

        # --- Control Buttons ---
        button_frame = ttk.Frame(self)
        button_frame.pack(pady=5, padx=10, fill="x")

        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        # --- Log Output ---
        self.log_frame = ttk.LabelFrame(self, text="Scan Logs", padding="10 5 10 10")
        self.log_frame.pack(pady=5, padx=10, fill="both", expand=True)

        # Using a dark theme for logs
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, height=15, state='disabled', bg="#2c2c2c", fg="#a0a0a0", font=("TkFixedFont", 10))
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("INFO", foreground="#CCCCCC")
        self.log_text.tag_config("WARNING", foreground="#FFD700") # Gold
        self.log_text.tag_config("ERROR", foreground="#FF6347") # Tomato
        self.log_text.tag_config("CRITICAL", foreground="#DC143C", background="#333333", font=("TkFixedFont", 10, "bold")) # Crimson
        self.log_text.tag_config("DEBUG", foreground="#778899") # LightSlateGray


        # --- Results Notebook (Tabs) ---
        self.results_notebook = ttk.Notebook(self)
        self.results_notebook.pack(pady=10, padx=10, fill="both", expand=True)

        # Tabs
        self.summary_tab = ttk.Frame(self.results_notebook)
        self.nmap_tab = ttk.Frame(self.results_notebook)
        self.web_discovery_tab = ttk.Frame(self.results_notebook)
        self.vulnerabilities_tab = ttk.Frame(self.results_notebook)

        self.results_notebook.add(self.summary_tab, text="Summary")
        self.results_notebook.add(self.nmap_tab, text="Nmap Services")
        self.results_notebook.add(self.web_discovery_tab, text="Web Discovery")
        self.results_notebook.add(self.vulnerabilities_tab, text="Vulnerabilities")
        
        self._create_summary_tab()
        self._create_nmap_tab()
        self._create_web_discovery_tab()
        self._create_vulnerabilities_tab()

    def _setup_logging_redirection(self):
        # Remove existing handlers to prevent duplicate logging
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Add our custom handler
        self.log_handler = TkinterLogHandler(self.log_text)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        logging.root.addHandler(self.log_handler)
        logging.root.setLevel(logging.INFO) # Set root level to INFO for GUI

        # Redirect stdout/stderr as a fallback or for unhandled prints
        sys.stdout = TextRedirector(self.log_text, "INFO") # Redirect stdout to log
        sys.stderr = TextRedirector(self.log_text, "ERROR") # Redirect stderr to log


    def _create_summary_tab(self):
        self.summary_text = scrolledtext.ScrolledText(self.summary_tab, wrap=tk.WORD, state='disabled', font=("TkFixedFont", 10))
        self.summary_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _create_nmap_tab(self):
        self.nmap_tree = ttk.Treeview(self.nmap_tab, columns=("IP", "Port", "Protocol", "Service", "Product", "Version"), show="headings")
        self.nmap_tree.pack(fill="both", expand=True, padx=5, pady=5)
        for col in self.nmap_tree["columns"]:
            self.nmap_tree.heading(col, text=col)
            self.nmap_tree.column(col, anchor="w", width=100)
        self.nmap_tree.column("IP", width=120)
        self.nmap_tree.column("Port", width=60)
        self.nmap_tree.column("Service", width=100)
        self.nmap_tree.column("Product", width=120)
        self.nmap_tree.column("Version", width=100)

    def _create_web_discovery_tab(self):
        self.web_discovery_tree = ttk.Treeview(self.web_discovery_tab, columns=("Base URL", "Links Found", "Params Found"), show="headings")
        self.web_discovery_tree.pack(fill="both", expand=True, padx=5, pady=5)
        for col in self.web_discovery_tree["columns"]:
            self.web_discovery_tree.heading(col, text=col)
            self.web_discovery_tree.column(col, anchor="w", width=150)
        self.web_discovery_tree.column("Base URL", width=300)

        self.web_discovery_tree.bind("<Double-1>", self._on_web_discovery_double_click)
    
    def _on_web_discovery_double_click(self, event):
        item_id = self.web_discovery_tree.selection()
        if not item_id: return
        item_id = item_id[0]
        item_values = self.web_discovery_tree.item(item_id, 'values')
        if item_values and len(item_values) > 0:
            base_url = item_values[0]
            full_data = self.last_scan_results.get("recon_scanner_web_discovery", {}).get(base_url)
            if full_data:
                links_str = "\n".join(full_data.get("links", []))
                params_str = "\n".join(full_data.get("params", []))
                detail_msg = f"Links:\n{links_str}\n\nParameters:\n{params_str}"
                messagebox.showinfo(f"Details for {base_url}", detail_msg)


    def _create_vulnerabilities_tab(self):
        self.vulnerabilities_tree = ttk.Treeview(self.vulnerabilities_tab, columns=("Type", "URL", "Parameter", "Payload", "DB Type", "Status/Details"), show="headings")
        self.vulnerabilities_tree.pack(fill="both", expand=True, padx=5, pady=5)
        for col in self.vulnerabilities_tree["columns"]:
            self.vulnerabilities_tree.heading(col, text=col)
            self.vulnerabilities_tree.column(col, anchor="w", width=100)
        self.vulnerabilities_tree.column("Type", width=150)
        self.vulnerabilities_tree.column("URL", width=300)
        self.vulnerabilities_tree.column("Parameter", width=100)
        self.vulnerabilities_tree.column("Payload", width=250)
        self.vulnerabilities_tree.column("DB Type", width=80)
        self.vulnerabilities_tree.column("Status/Details", width=150)


    def start_scan(self):
        target = self.target_entry.get().strip()
        masscan_rate = self.masscan_rate_entry.get().strip()

        if not target:
            messagebox.showerror("Input Error", "Target cannot be empty!")
            return
        
        try:
            masscan_rate = int(masscan_rate)
            if masscan_rate <= 0:
                raise ValueError("Masscan rate must be positive.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid Masscan rate: {e}")
            return

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.clear_results()
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')
        logger.info(f"Starting scan for {target} with Masscan rate {masscan_rate} pps...")
        
        # Reset pipeline and thread for a new scan
        self.pipeline = KaliScanPipeline(target=target, masscan_rate=masscan_rate)
        self.scan_thread = threading.Thread(target=self._run_scan_in_thread, daemon=True)
        self.stop_event.clear()
        self.scan_thread.start()
        # self.check_scan_completion() # This is now handled by _scan_finished callback

    def stop_scan(self):
        logger.info("Stopping scan (attempting graceful shutdown)...")
        self.stop_event.set() # Signal the thread to stop
        self.stop_button.config(state="disabled")
        self.start_button.config(state="normal")
        # Note: Actual graceful shutdown in asyncio pipeline needs more integration.
        # For now, it mainly prevents new tasks from starting.

    def _run_scan_in_thread(self):
        # This function runs in a separate thread
        try:
            # Check for root privileges before starting the scan
            if os.geteuid() != 0:
                self.after(0, lambda: messagebox.showerror("Permission Error", "This scanner requires root privileges for Masscan and Nmap. Please run the application with 'sudo'."))
                self.after(0, lambda: self._scan_finished(None, "Permission Error: Not running as root."))
                return

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            final_results = loop.run_until_complete(self.pipeline.run_full_scan())
            self.after(0, lambda: self._scan_finished(final_results, None)) # Schedule update on main thread
        except Exception as e:
            logger.exception("Scan thread encountered an error.")
            self.after(0, lambda: self._scan_finished(None, str(e))) # Schedule error on main thread

    def _scan_finished(self, results, error_message):
        # This runs on the main Tkinter thread
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        
        if error_message:
            messagebox.showerror("Scan Error", f"An error occurred during the scan: {error_message}")
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, f"\n[CRITICAL] Scan finished with an error: {error_message}\n", "ERROR")
            self.log_text.configure(state='disabled')
        elif results:
            self.last_scan_results = results # Store results for detail views
            self.display_results(results)
            logger.info("Scan completed successfully!")
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, "\n[INFO] Scan completed successfully!\n", "INFO")
            self.log_text.configure(state='disabled')
        else:
            logger.warning("Scan finished without results or specific error message.")
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, "\n[WARNING] Scan finished without explicit results or errors.\n", "WARNING")
            self.log_text.configure(state='disabled')


    def clear_results(self):
        self.summary_text.configure(state='normal')
        self.summary_text.delete('1.0', tk.END)
        self.summary_text.configure(state='disabled')
        
        for item in self.nmap_tree.get_children():
            self.nmap_tree.delete(item)
        
        for item in self.web_discovery_tree.get_children():
            self.web_discovery_tree.delete(item)
        
        for item in self.vulnerabilities_tree.get_children():
            self.vulnerabilities_tree.delete(item)

    def display_results(self, results):
        self.clear_results() # Clear previous results

        # --- Summary Tab ---
        summary_content = f"Target: {results.get('target', 'N/A')}\n"
        summary_content += f"Output Directory: {results.get('output_directory', 'N/A')}\n"
        summary_content += f"Timestamp (UTC): {results.get('timestamp_utc', 'N/A')}\n\n"

        if results.get('recon_scanner_passive'):
            summary_content += "--- Passive Recon ---\n"
            passive = results['recon_scanner_passive']
            summary_content += f"  Registrar: {passive.get('whois', {}).get('registrar', 'N/A')}\n"
            summary_content += f"  Creation Date: {passive.get('whois', {}).get('creation_date', 'N/A')}\n"
            if passive.get('dns', {}).get('A'):
                summary_content += f"  DNS A Records: {', '.join(passive['dns']['A'])}\n"
            if passive.get('crtsh_subdomains'):
                summary_content += f"  CRT.sh Subdomains: {len(passive['crtsh_subdomains'])} found\n"
            summary_content += "\n"

        if results.get('masscan_open_ports'):
            total_masscan_ports = sum(len(v) for v in results['masscan_open_ports'].values())
            summary_content += f"--- Masscan ---\n  Found {total_masscan_ports} open ports on {len(results['masscan_open_ports'])} IP(s).\n\n"

        if results.get('nmap_parsed_services'):
            summary_content += f"--- Nmap Services ---\n  Found {len(results['nmap_parsed_services'])} hosts with services.\n\n"
            # Populate Nmap treeview
            for host_data in results['nmap_parsed_services']:
                # Use the first IPv4 address as the primary IP for display
                ip = next((addr['addr'] for addr in host_data['addresses'] if addr['addrtype'] == 'ipv4'), 'N/A')
                for port_data in host_data['ports']:
                    self.nmap_tree.insert("", "end", values=(
                        ip,
                        port_data['portid'],
                        port_data['protocol'],
                        port_data['service']['name'],
                        port_data['service']['product'],
                        port_data['service']['version']
                    ))
            
        if results.get('recon_scanner_web_discovery'):
            total_web_links = sum(len(res.get('links',[])) for res in results['recon_scanner_web_discovery'].values() if res.get('links'))
            total_web_params = sum(len(res.get('params',[])) for res in results['recon_scanner_web_discovery'].values() if res.get('params'))
            summary_content += f"--- Web Discovery ---\n  Found {total_web_links} links and {total_web_params} parameters.\n\n"
            # Populate Web Discovery treeview
            for url, data in results['recon_scanner_web_discovery'].items():
                self.web_discovery_tree.insert("", "end", values=(
                    url,
                    len(data.get('links', [])),
                    len(data.get('params', []))
                ))

        if results.get('web_vulnerabilities'):
            summary_content += f"--- Web Vulnerabilities ---\n  Found {len(results['web_vulnerabilities'])} potential vulnerabilities.\n"
            # Populate Vulnerabilities treeview
            for vuln in results['web_vulnerabilities']:
                details = []
                if vuln.get('response_time_seconds'):
                    details.append(f"Time: {vuln['response_time_seconds']}s")
                if vuln.get('error_detected'):
                    details.append("Error Detected")
                if vuln.get('differential_response'):
                    details.append("Diff. Response")

                self.vulnerabilities_tree.insert("", "end", values=(
                    vuln.get('type', 'N/A'),
                    vuln.get('url', 'N/A'),
                    vuln.get('param', 'N/A'),
                    vuln.get('payload', vuln.get('payload_true', 'N/A'))[:70] + ("..." if len(vuln.get('payload', vuln.get('payload_true', 'N/A'))) > 70 else ""), # Truncate long payloads
                    vuln.get('db_type', 'N/A'),
                    ", ".join(details) if details else f"Status: {vuln.get('response_status', 'N/A')}"
                ))
        else:
            summary_content += "--- Web Vulnerabilities ---\n  No web vulnerabilities found.\n"


        self.summary_text.configure(state='normal')
        self.summary_text.insert(tk.END, summary_content)
        self.summary_text.configure(state='disabled')


if __name__ == "__main__":
    app = ScanApp()
    app.mainloop()
