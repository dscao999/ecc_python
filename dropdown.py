import tkinter as tk
import tkinter.messagebox as mesgbox
import sys
import mysql.connector as mariadb

mariadb_config = {
        'user': 'dscao',
        'host': 'localhost',
        'database': 'electoken'
}

tables = ["vendors", "etoken_cat", "etoken_type", "sales"]

class DropDown(tk.OptionMenu):
    def __init__(self, parent, optlist, dv):
        self.vari = tk.StringVar()
        self.vari.set(optlist[dv])
        super().__init__(parent, self.vari, *optlist)

    def get_choice(self):
        return self.vari.get()


def show_vid():
    vid = mydrop.getv()
    mesgbox.showerror("Info", vid)

if __name__ == "__main__":
    root = tk.Tk()
    root.title(sys.argv[0])
    mfont = ('courier', 16, 'bold')

    cnx = mariadb.connect(**mariadb_config)
    cursor = cnx.cursor()
    vendor_query = ("SELECT * from vendors")
    cursor.execute(vendor_query)
    mylist = []
    for (vid, name, descp) in cursor:
        mylist.append(name)
    cursor.close()

    mydrop = DropDown(root, mylist, 0);
    mydrop.config(width=20, font=mfont);
    mydrop.pack(side=tk.TOP)

    mbut = tk.Button(root, text="Get ID", width=20, command=show_vid);
    mbut.config(font=mfont)
    mbut.pack(side=tk.BOTTOM)


    root.mainloop()
