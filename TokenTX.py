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
        self.vari.set(optlist[dv]['name'])
        self.optlist = optlist
        itmlist = []
        for itm in self.optlist:
            itmlist.append(itm['name'])
        super().__init__(parent, self.vari, *itmlist)

    def get_choice(self):
        return self.vari.get()

    def refresh_option(self, optlist):
        self.optlist = optlist
        self['menu'].delete(0, 'end')
        for itm in self.optlist:
            choice = itm['name']
            self['menu'].add_command(label=choice, command=tk._setit(self.vari, choice))
        self.vari.set(self.optlist[0]['name'])


class TokenTX:
    def __init__(self, master, keylist, mfont):
        self.keys = keylist
        self.master = master
        self.frame = tk.Frame(self.master)
        self.mfont = mfont
        self.idx = 0
        label = tk.Label(self.frame, text="Select Token Type", font=mfont, width=80)
        label.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        lfrm = tk.Frame(self.master)
        lfrm.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        optfrm = tk.Frame(lfrm)
        optfrm.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)

        self.cnx = mariadb.connect(**mariadb_config)
        self.cursor = self.cnx.cursor()
        vendor_query = ("SELECT * from vendors")
        self.cursor.execute(vendor_query)
        self.vendors = []
        for (vid, name, descp) in self.cursor:
            self.vendors.append({'id': vid, 'name': name, 'desc': descp})
        self.vendrop = DropDown(optfrm, self.vendors, self.idx)

        self.cat_query = ("SELECT id, name, descp from etoken_cat where vendor_id = %(vendor_id)s")
        vid = self.vendors[self.idx]['id']
        self.cursor.execute(self.cat_query, {'vendor_id': vid})
        self.cats = []
        for (catid, name, descp) in self.cursor:
            self.cats.append({'id': catid, 'name': name, 'desc': descp})
        self.catdrop = DropDown(optfrm, self.cats, self.idx)

        self.tok_query = ("SELECT * from etoken_type where cat_id = %(cat_id)s")
        cat_id = self.cats[self.idx]['id']
        self.cursor.execute(self.tok_query, {'cat_id': cat_id})
        self.toks = []
        for (tokid, name, descp, catid) in self.cursor:
            self.toks.append({'id': tokid, 'name': name, 'desc': descp})
        self.tokdrop = DropDown(optfrm, self.toks, self.idx)

        self.vendrop.config(font=self.mfont, width=16)
        self.vendrop.pack(side=tk.LEFT)
        self.catdrop.config(font=self.mfont, width=16)
        self.catdrop.pack()
        self.tokdrop.config(font=self.mfont, width=16)
        self.tokdrop.pack(side=tk.RIGHT)

        self.quitbutton = tk.Button(lfrm, text='Quit', width=25, command=self.close_windows)
        self.quitbutton.pack(side=tk.BOTTOM)

        self.frame.pack()

        self.vendrop.vari.trace("w", self.refresh_cat)
        self.catdrop.vari.trace("w", self.refresh_tok)

    def refresh_cat(self, *args):
        self.catdrop['menu'].delete(0, 'end')

    def refresh_tok(self, *args):
        name = self.catdrop.get_choice()
        catid = 0
        for ent in self.cats:
            if ent['name'] == name:
                catid = ent['id']
                break
        print("CAT ID: {}".format(catid))

        self.cursor.execute(self.tok_query, {'cat_id': catid})
        self.toks = []
        for (tokid, name, descp, catid) in self.cursor:
            self.toks.append({'id': tokid, 'name': name, 'desc': descp})
        self.tokdrop.refresh_option(self.toks)

    def close_windows(self):
        self.cursor.close()
        self.cnx.close()
        self.master.destroy()

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
