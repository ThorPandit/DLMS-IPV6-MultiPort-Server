import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import time
import traceback

servers = {}  # {(port, proto): {'thread': t, 'stop': flag, 'count': int}}
lock = threading.Lock()
LOG_FILE = "dlms_server_log.txt"

def log_event(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

def start_server(port, protocol, tree):
    try:
        addr_info = socket.getaddrinfo("::", port, socket.AF_INET6,
                                       socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
        sock_type = socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM
        server_socket = socket.socket(socket.AF_INET6, sock_type)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(addr_info[0][4])

        key = (port, protocol)
        servers[key] = {'stop': False, 'count': 0}

        def run():
            try:
                if protocol == "TCP":
                    server_socket.listen(5)
                    while not servers[key]['stop']:
                        server_socket.settimeout(1.0)
                        try:
                            conn, addr = server_socket.accept()
                            threading.Thread(target=handle_client, args=(conn, addr, key, tree), daemon=True).start()
                        except socket.timeout:
                            continue
                else:  # UDP
                    while not servers[key]['stop']:
                        server_socket.settimeout(1.0)
                        try:
                            data, addr = server_socket.recvfrom(2048)
                            with lock:
                                servers[key]['count'] += 1
                                update_tree(tree, port, protocol, "Listening", addr[0], servers[key]['count'])
                            log_packet(port, protocol, addr[0], data)
                        except socket.timeout:
                            continue
            except Exception as e:
                log_event(f"[{protocol}:{port}] Exception: {e}")
                log_event(traceback.format_exc())
            finally:
                server_socket.close()
                update_tree(tree, port, protocol, "Stopped", "", servers[key]['count'])

        t = threading.Thread(target=run, daemon=True)
        servers[key]['thread'] = t
        t.start()
        update_tree(tree, port, protocol, "Listening", "", 0)
        log_event(f"{protocol}:{port} server started.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not start server on {protocol}:{port}\n{e}")
        log_event(f"Failed to start {protocol}:{port} - {e}")

def handle_client(conn, addr, key, tree):
    port, protocol = key
    with conn:
        while not servers[key]['stop']:
            conn.settimeout(1.0)
            try:
                data = conn.recv(2048)
                if not data:
                    break
                with lock:
                    servers[key]['count'] += 1
                    update_tree(tree, port, protocol, "Listening", addr[0], servers[key]['count'])
                log_packet(port, protocol, addr[0], data)
            except socket.timeout:
                continue
            except ConnectionResetError:
                log_event(f"[{protocol}:{port}] ConnectionResetError from {addr[0]}")
                break
            except Exception as e:
                log_event(f"[{protocol}:{port}] Exception in handler: {e}")
                break

def log_packet(port, protocol, ip, data):
    filename = f"port_{protocol}_{port}.txt"
    with open(filename, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {ip} -> {data.hex()}\n")

def update_tree(tree, port, protocol, status, ip, count):
    identifier = f"{protocol}:{port}"
    if not tree.exists(identifier):
        tree.insert("", "end", iid=identifier, values=(f"{protocol}:{port}", status, ip, count))
    else:
        tree.item(identifier, values=(f"{protocol}:{port}", status, ip, count))

def launch_gui():
    root = tk.Tk()
    root.title("DLMS IPv6 Multi-Port Server")

    frame = tk.Frame(root)
    frame.pack(pady=5)

    tk.Label(frame, text="Port:").pack(side=tk.LEFT)
    port_entry = tk.Entry(frame, width=10)
    port_entry.pack(side=tk.LEFT, padx=5)

    proto_var = tk.StringVar(value="TCP")
    proto_menu = ttk.Combobox(frame, textvariable=proto_var, values=["TCP", "UDP"], width=5, state="readonly")
    proto_menu.pack(side=tk.LEFT)

    def start():
        try:
            port = int(port_entry.get())
            proto = proto_var.get()
            if (port, proto) in servers:
                messagebox.showinfo("Info", f"{proto}:{port} already running or not cleaned up.")
                return
            start_server(port, proto, tree)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")

    def stop():
        try:
            port = int(port_entry.get())
            proto = proto_var.get()
            key = (port, proto)
            if key in servers:
                servers[key]['stop'] = True
                servers[key]['thread'].join(timeout=1.5)
                del servers[key]
                update_tree(tree, port, proto, "Stopped", "", 0)
                messagebox.showinfo("Stopped", f"{proto}:{port} stopped.")
                log_event(f"{proto}:{port} server stopped.")
            else:
                messagebox.showwarning("Not Running", f"{proto}:{port} not running.")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")

    def stop_all():
        for key, info in servers.items():
            info['stop'] = True
            log_event(f"{key[1]}:{key[0]} requested to stop.")
        messagebox.showinfo("Stopped", "Stopping all servers...")

    tk.Button(frame, text="Start Server", command=start).pack(side=tk.LEFT, padx=5)
    tk.Button(frame, text="Stop Server", command=stop).pack(side=tk.LEFT, padx=5)
    tk.Button(frame, text="Stop All", command=stop_all).pack(side=tk.LEFT, padx=5)

    tree = ttk.Treeview(root, columns=("Port", "Status", "Connected IP", "Packets"), show="headings")
    for col in ("Port", "Status", "Connected IP", "Packets"):
        tree.heading(col, text=col)
        tree.column(col, width=130)
    tree.pack(fill="both", expand=True)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
