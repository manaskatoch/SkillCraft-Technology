import threading
import time
import os
from datetime import datetime
from pathlib import Path
from tkinter import Tk, Text, Button, END, DISABLED, NORMAL, messagebox, Scrollbar, RIGHT, Y, LEFT, BOTH
from pynput import keyboard

class AdvancedKeylogger:
    def __init__(self, flush_interval=5):
        self.flush_interval = flush_interval
        self.log_buffer = []
        self.running = False
        self.listener = None
        self.log_file_path = self._generate_log_filename()
        self.lock = threading.Lock()
        self.flush_thread = None

        self.root = Tk()
        self.root.title("Advanced Keylogger")
        self.root.geometry("700x400")

        self._setup_widgets()
        self._bind_events()
        self._start_flush_thread()

    def _generate_log_filename(self):
        now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        return log_dir / f"keylog_{now}.txt"

    def _setup_widgets(self):
        self.text_area = Text(self.root, wrap='word', font=("Consolas", 12), state=DISABLED)
        self.text_area.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar = Scrollbar(self.root, command=self.text_area.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.text_area.config(yscrollcommand=scrollbar.set)

        self.btn_frame = self.root

        self.start_btn = Button(self.btn_frame, text="Start Logging", command=self.start_logging, bg='green', fg='white')
        self.start_btn.pack(side='top', pady=5, padx=5, fill='x')

        self.stop_btn = Button(self.btn_frame, text="Stop Logging", command=self.stop_logging, bg='red', fg='white', state=DISABLED)
        self.stop_btn.pack(side='top', pady=5, padx=5, fill='x')

        self.clear_btn = Button(self.btn_frame, text="Clear Log Buffer", command=self.clear_buffer, bg='orange', fg='black')
        self.clear_btn.pack(side='top', pady=5, padx=5, fill='x')

        self.save_btn = Button(self.btn_frame, text="Save Log As...", command=self.save_log_as, bg='blue', fg='white')
        self.save_btn.pack(side='top', pady=5, padx=5, fill='x')

    def _bind_events(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.root.bind("<FocusIn>", lambda e: self._update_status("Window focused - logging allowed"))
        self.root.bind("<FocusOut>", lambda e: self._update_status("Window not focused - logging paused"))

    def _update_status(self, message):
        self.root.title(f"Advanced Keylogger - {message}")

    def on_press(self, key):
        if not self.running:
            return False
        if not self.root.focus_displayof():
            return  # Only log if window is focused

        try:
            if hasattr(key, 'char') and key.char is not None:
                log_entry = key.char
            else:
                log_entry = f"[{key.name.upper()}]"
        except AttributeError:
            log_entry = f"[{str(key)}]"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        entry = f"{timestamp}: {log_entry}"
        with self.lock:
            self.log_buffer.append(entry)
        self._append_to_text_area(entry)

    def _append_to_text_area(self, text):
        self.text_area.config(state=NORMAL)
        self.text_area.insert(END, text + "\n")
        self.text_area.see(END)
        self.text_area.config(state=DISABLED)

    def start_logging(self):
        if self.running:
            messagebox.showinfo("Info", "Logging is already running.")
            return

        self.running = True
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self._update_status("Logging started")

        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()

    def stop_logging(self):
        if not self.running:
            messagebox.showinfo("Info", "Logging is not running.")
            return

        self.running = False
        if self.listener and self.listener.running:
            self.listener.stop()
        self.listener = None
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self._update_status("Logging stopped")
        self._flush_buffer()

    def _flush_buffer(self):
        with self.lock:
            if not self.log_buffer:
                return
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    for line in self.log_buffer:
                        f.write(line + "\n")
                self.log_buffer.clear()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write to log file:\n{e}")

    def _periodic_flush(self):
        while True:
            time.sleep(self.flush_interval)
            if self.running:
                self._flush_buffer()

    def _start_flush_thread(self):
        self.flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.flush_thread.start()

    def clear_buffer(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear the log buffer? This will not delete the saved log file."):
            with self.lock:
                self.log_buffer.clear()
            self.text_area.config(state=NORMAL)
            self.text_area.delete(1.0, END)
            self.text_area.config(state=DISABLED)

    def save_log_as(self):
        try:
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                                                     initialfile=self.log_file_path.name)
            if file_path:
                with self.lock:
                    content = "\n".join(self.log_buffer)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Log saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def on_exit(self):
        if self.running:
            self.stop_logging()
        self._flush_buffer()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    keylogger = AdvancedKeylogger(flush_interval=5)
    keylogger.run()