import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math
import re
import json
import csv
import requests
from hashlib import sha1

class PasswordAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CipherSense – Advanced Password Strength Analyzer")
        self.geometry("800x600")
        self.configure(bg="#0f172a")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", background="#0f172a", foreground="#e2e8f0")
        self.style.configure("TButton", background="#1e293b", foreground="#e2e8f0", padding=6)
        self.style.configure("TEntry", fieldbackground="#1e293b", foreground="#e2e8f0")
        self.password_var = tk.StringVar()
        self.strength_var = tk.StringVar(value="Enter a password to analyze")
        self.entropy_var = tk.StringVar()
        self.breach_var = tk.StringVar()
        self.history = []
        self._build_ui()

    def _build_ui(self):
        frame = ttk.Frame(self)
        frame.pack(pady=20, fill="x")

        ttk.Label(frame, text="Password:").pack(anchor="w", padx=10)
        entry = ttk.Entry(frame, textvariable=self.password_var, show="*", width=50)
        entry.pack(padx=10, pady=5)
        entry.bind('<KeyRelease>', lambda e: self._analyze())

        self.canvas = tk.Canvas(self, height=30, bg="#1e293b", highlightthickness=0)
        self.canvas.pack(fill="x", padx=20, pady=10)

        ttk.Label(self, textvariable=self.strength_var, font=("Segoe UI", 14, "bold"), foreground="#38bdf8").pack(pady=6)
        ttk.Label(self, textvariable=self.entropy_var, font=("Segoe UI", 10)).pack()
        ttk.Label(self, textvariable=self.breach_var, font=("Segoe UI", 10)).pack(pady=6)

        ttk.Button(self, text="Export Results (CSV)", command=self._export_csv).pack(pady=10)
        ttk.Button(self, text="Export Results (JSON)", command=self._export_json).pack()

        self.tree = ttk.Treeview(self, columns=("Password", "Score", "Entropy", "Strength", "Breach Status"), show="headings")
        for c in ("Password", "Score", "Entropy", "Strength", "Breach Status"):
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor="center", width=140)
        self.tree.pack(fill="both", expand=True, padx=12, pady=12)

    def _calculate_entropy(self, password):
        charset = 0
        if re.search(r"[a-z]", password): charset += 26
        if re.search(r"[A-Z]", password): charset += 26
        if re.search(r"[0-9]", password): charset += 10
        if re.search(r"[^a-zA-Z0-9]", password): charset += 32
        if charset == 0:
            return 0
        entropy = len(password) * math.log2(charset)
        return round(entropy, 2)

    def _score_password(self, password):
        score = 0
        length = len(password)
        if length >= 8: score += 2
        if length >= 12: score += 2
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"[0-9]", password): score += 1
        if re.search(r"[^a-zA-Z0-9]", password): score += 2
        if re.search(r"(.)\\1{2,}", password): score -= 1
        return max(score, 0)

    def _strength_label(self, score, entropy):
        if score <= 2 or entropy < 28:
            return "Very Weak", "#ef4444"
        elif score <= 4 or entropy < 36:
            return "Weak", "#f97316"
        elif score <= 6 or entropy < 60:
            return "Medium", "#facc15"
        elif score <= 8 or entropy < 80:
            return "Strong", "#4ade80"
        else:
            return "Very Strong", "#22c55e"

    def _check_breach(self, password):
        try:
            sha = sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha[:5], sha[5:]
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if res.status_code != 200:
                return "Error"
            hashes = (line.split(":") for line in res.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return f"Breached {count} times"
            return "Safe"
        except Exception:
            return "Check failed"

    def _draw_heatmap(self, score, color):
        self.canvas.delete("all")
        width = self.canvas.winfo_width() or 760
        bar_width = width * (score / 10)
        self.canvas.create_rectangle(0, 0, bar_width, 30, fill=color, width=0)

    def _analyze(self):
        pwd = self.password_var.get()
        if not pwd:
            self.strength_var.set("Enter a password to analyze")
            self.entropy_var.set("")
            self.breach_var.set("")
            self.canvas.delete("all")
            return

        entropy = self._calculate_entropy(pwd)
        score = self._score_password(pwd)
        strength, color = self._strength_label(score, entropy)
        breach_status = self._check_breach(pwd)
        self.strength_var.set(f"Password Strength: {strength}")
        self.entropy_var.set(f"Entropy: {entropy} bits | Score: {score}/10")
        self.breach_var.set(f"Breach Status: {breach_status}")
        self._draw_heatmap(score, color)

        data = {
            "Password": pwd,
            "Score": score,
            "Entropy": entropy,
            "Strength": strength,
            "Breach Status": breach_status
        }
        self.history.append(data)
        self.tree.insert("", "end", values=(pwd, score, entropy, strength, breach_status))

    def _export_csv(self):
        if not self.history:
            messagebox.showwarning("Warning", "No data to export!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], initialfile="password_analysis.csv")
        if not path:
            return
        with open(path, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.history[0].keys())
            writer.writeheader()
            writer.writerows(self.history)
        messagebox.showinfo("Export", "Results exported successfully to CSV.")

    def _export_json(self):
        if not self.history:
            messagebox.showwarning("Warning", "No data to export!")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")], initialfile="password_analysis.json")
        if not path:
            return
        with open(path, "w", encoding='utf-8') as f:
            json.dump(self.history, f, indent=4)
        messagebox.showinfo("Export", "Results exported successfully to JSON.")

if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()
