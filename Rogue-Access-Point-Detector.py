# -*- coding: utf-8 -*-
"""
Created on Fri Feb 14 04:49:25 2025

@author: IAN CARTER KULANI

"""

import tkinter as tk
from tkinter import messagebox
from scapy.all import *
import threading


class RogueAccessPointDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Access Point Detection Tool")
        self.root.geometry("500x400")
        
        # Label for instruction
        self.label = tk.Label(root, text="Enter IP address to monitor for Rogue Access Points:")
        self.label.pack(pady=10)

        # Input field for IP address
        self.ip_entry = tk.Entry(root, width=30)
        self.ip_entry.pack(pady=5)

        # Button to start detection
        self.detect_button = tk.Button(root, text="Start Detection", command=self.start_detection)
        self.detect_button.pack(pady=20)

        # Label to display detection result
        self.result_label = tk.Label(root, text="", fg="red")
        self.result_label.pack(pady=10)

        # Initialize variables for known APs and detected APs
        self.known_aps = set()  # This will store MAC addresses of known APs
        self.detected_aps = set()  # This will store MAC addresses of detected APs

    def start_detection(self):
        # Get the IP address entered by the user
        target_ip = self.ip_entry.get()

        if not target_ip:
            messagebox.showerror("Input Error", "Please enter an IP address.")
            return

        # Update the result label
        self.result_label.config(text="Detecting rogue APs...")

        # Start packet sniffing in a separate thread
        threading.Thread(target=self.detect_rogue_aps, args=(target_ip,)).start()

    def detect_rogue_aps(self, target_ip):
        # We will capture beacon frames to detect Access Points (APs)
        # Use scapy to sniff 802.11 frames
        sniff(prn=self.packet_handler, store=0, iface="wlan0", timeout=60)  # Sniffing for 60 seconds

        # After sniffing finishes, check the detected APs
        rogue_aps = self.detected_aps - self.known_aps

        if rogue_aps:
            self.result_label.config(text=f"Rogue APs detected: {len(rogue_aps)}")
        else:
            self.result_label.config(text="No Rogue APs detected.")

    def packet_handler(self, pkt):
        # We only care about Beacon frames (APs)
        if pkt.haslayer(Dot11Beacon):
            # Extract the MAC address (BSSID) and SSID
            ap_mac = pkt[Dot11].addr2  # MAC address of the AP
            ssid = pkt[Dot11Elt].info.decode()  # SSID of the AP

            # If the AP is not in known APs, add it to detected APs
            if ap_mac not in self.known_aps:
                self.detected_aps.add(ap_mac)

            print(f"Detected AP: {ssid} ({ap_mac})")


# Main GUI setup
def main():
    root = tk.Tk()
    tool = RogueAccessPointDetector(root)
    root.mainloop()


if __name__ == "__main__":
    main()
