"""
File: gui/login.py
Purpose: Authentication UI to securely log users into the I2I Messenger.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import logging

from src.auth_manager import AuthManager

BG_DARK = "#0d1117"
BG_MID = "#161b22"
BG_CARD = "#21262d"
ACCENT = "#58a6ff"
TEXT_MAIN = "#e6edf3"
TEXT_DIM = "#8b949e"

logger = logging.getLogger(__name__)

class LoginWindow:
    def __init__(self, on_success):
        self.root = tk.Tk()
        self.root.title("I2I - Authentication")
        self.root.geometry("400x350")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(False, False)
        
        self.on_success = on_success
        
        self._build_ui()
        
    def _build_ui(self):
        title = tk.Label(self.root, text="🔐 Secure Login", bg=BG_DARK, fg=ACCENT, font=("Segoe UI", 16, "bold"))
        title.pack(pady=(30, 20))
        
        frame = tk.Frame(self.root, bg=BG_MID, bd=1, relief="solid")
        frame.pack(padx=40, fill="both", expand=True, pady=(0, 30))
        
        tk.Label(frame, text="Username", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(20, 5))
        self.user_var = tk.StringVar()
        user_entry = tk.Entry(frame, textvariable=self.user_var, bg=BG_CARD, fg=TEXT_MAIN, insertbackground=TEXT_MAIN, bd=0, font=("Segoe UI", 10))
        user_entry.pack(fill="x", padx=20, ipady=4)
        
        tk.Label(frame, text="Password", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(15, 5))
        self.pass_var = tk.StringVar()
        pass_entry = tk.Entry(frame, textvariable=self.pass_var, show="*", bg=BG_CARD, fg=TEXT_MAIN, insertbackground=TEXT_MAIN, bd=0, font=("Segoe UI", 10))
        pass_entry.pack(fill="x", padx=20, ipady=4)
        
        btn_frame = tk.Frame(frame, bg=BG_MID)
        btn_frame.pack(fill="x", padx=20, pady=(25, 20))
        
        btn_login = tk.Button(btn_frame, text="Login", bg=ACCENT, fg="#fff", font=("Segoe UI", 10, "bold"), bd=0, command=self._do_login)
        btn_login.pack(side="left", expand=True, fill="x", padx=(0, 5), ipady=4)
        
        btn_reg = tk.Button(btn_frame, text="Register", bg=BG_CARD, fg=TEXT_MAIN, font=("Segoe UI", 10), bd=0, command=self._do_register)
        btn_reg.pack(side="right", expand=True, fill="x", padx=(5, 0), ipady=4)

    def _do_login(self):
        u = self.user_var.get().strip()
        p = self.pass_var.get().strip()
        
        if not u or not p:
            messagebox.showwarning("Error", "Username and password required")
            return
            
        role = AuthManager.login(u, p)
        if role:
            logger.info("User %s authenticated via UI", u)
            self.root.destroy()
            self.on_success(u, role)
        else:
            messagebox.showerror("Access Denied", "Invalid username or password.")
            
    def _do_register(self):
        u = self.user_var.get().strip()
        p = self.pass_var.get().strip()
        
        if not u or not p:
            messagebox.showwarning("Error", "Username and password required")
            return
            
        role = "USER"
        if u.lower() == "admin":
            from tkinter import simpledialog
            secret = simpledialog.askstring("Admin Verification", "Enter the Admin Secret Code to register as ADMIN:", show='*')
            import os
            expected_secret = os.getenv("I2I_ADMIN_SECRET", "SSD-ADMIN-CODE")
            if secret == expected_secret:
                role = "ADMIN"
            elif secret is not None:
                messagebox.showerror("Access Denied", "Incorrect secret code. Privilege Escalation prevented.")
                return
            else:
                # User clicked Cancel on the prompt
                return
            
        try:
            AuthManager.register(u, p, role)
            messagebox.showinfo("Success", f"User registered successfully! Role: {role}\nYou can now login.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def run(self):
        self.root.mainloop()

def run_login_flow():
    result = {"username": None, "role": None}
    
    def on_login(username, role):
        result["username"] = username
        result["role"] = role
        
    app = LoginWindow(on_login)
    app.run()
    
    return result["username"], result["role"]
