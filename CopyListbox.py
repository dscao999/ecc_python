import tkinter as tk

class CopyListbox(tk.Listbox):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.popup_menu = tk.Menu(self, tearoff=0)
        self.popup_menu.add_command(label='Copy', command=self.cpsel)

        self.bind("<Button-3>", self.popup)

    def popup(self, event):
        self.popup_menu.tk_popup(event.x_root, event.y_root, 0)

    def delsel(self):
        print("Will Delete: ", self.curselection()[0])

    def cpsel(self):
        self.clipboard_clear()
        idx = self.curselection()[0]
        self.clipboard_append(self.get(idx))

class PasteEntry(tk.Entry):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.popup = tk.Menu(self, tearoff=0)
        self.popup.add_command(label='Paste', command=self.paste)
        self.bind("<Button-3>", self.popup_action)

    def popup_action(self, event):
        self.popup.tk_popup(event.x_root, event.y_root, 0)

    def paste(self):
        try:
            item = self.clipboard_get()
        except:
            item = ''
        if len(item) > 0:
            self.delete(0, tk.END)
            self.insert(tk.END, item[0:28])
