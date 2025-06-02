import tkinter as tk

def show_timed_popup(parent, message, kind="info", duration_ms=4000):
    """
    Show an auto‐closing popup:
      - kind: "info" (blue text), "confirm" (green text), "error" (red text)
    """
    bg_color = "#333333"
    fg_color = {
        "info":    "#0078d7",  # blue
        "confirm": "#28a745",  # green
        "error":   "#dc3545",  # red
    }.get(kind, "#ffffff")
    popup = tk.Toplevel(parent)
    popup.overrideredirect(True)
    popup.configure(bg=bg_color)
    label = tk.Label(
        popup, text=message, bg=bg_color, fg=fg_color,
        font=("Segoe UI", 10, "bold"), padx=20, pady=10
    )
    label.pack()
    # Center popup over parent
    parent.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() // 2) - (popup.winfo_reqwidth() // 2)
    y = parent.winfo_y() + (parent.winfo_height() // 2) - (popup.winfo_reqheight() // 2)
    popup.geometry(f"+{x}+{y}")
    popup.after(duration_ms, popup.destroy)
