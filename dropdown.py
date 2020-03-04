import tkinter as tk
import sys
import mysql.connector as mariadb

class DropDown(tk.OptionMenu):
    def __init__(self, parent, optlist, dv):
        self.vari = tk.StringVar()
        self.vari.set(optlist[dv])
        super().__init__(parent, self.vari, *optlist)

    def getv():
        vstr = self.vari.get()
        return vstr


if __name__ == "__main__":
    root = tk.Tk()
    root.title(sys.argv[0])
    mfont = ('courier', 16, 'bold')
    mylist = ["Sunday", "Monday", "Tuesday", "Wensday", "Thursday", "Friday", "Saturday"]
    mydrop = DropDown(root, mylist, 0);
    mydrop.config(width=10, font=mfont);
    mydrop.pack()

    root.mainloop()
