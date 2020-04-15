import tkinter as tk
import tkinter.messagebox as mesgbox
import sys
import mysql.connector as mariadb
import CopyListbox
from tkinter import simpledialog
import audiorand
import ctypes
import hashlib
import time
import socket

mariadb_config = {
        'user': 'dscao',
        'host': 'localhost',
        'database': 'electoken'
}

tables = ["vendors", "etoken_cat", "etoken_type", "sales"]

class DropDown(tk.OptionMenu):
    def __init__(self, parent, optlist):
        self.vari = tk.StringVar()
        self.vari.set(optlist[0]['name'])
        itmlist = []
        for itm in optlist:
            itmlist.append(itm['name'])
        super().__init__(parent, self.vari, *itmlist)

    def get_choice(self):
        return self.vari.get()

    def refresh_option(self, optlist):
        self['menu'].delete(0, 'end')
        for itm in optlist:
            choice = itm['name']
            self['menu'].add_command(label=choice, command=tk._setit(self.vari, choice))
        self.vari.set(optlist[0]['name'])

class TokenID:
    def __init__(self, parent, cursor, mfont):
        frame = tk.Frame(parent)
        frame.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)

        label = tk.Label(frame, text="Select Token Type", font=mfont, width=80)
        label.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        optfrm = tk.Frame(frame)
        optfrm.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        sep = tk.Frame(optfrm, height=8, bg='black', bd=2, relief=tk.SUNKEN)
        sep.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.cursor = cursor
        vendor_query = ("SELECT * from vendors")
        self.cursor.execute(vendor_query)
        self.vendors = []
        for (vid, name, descp) in self.cursor:
            self.vendors.append({'id': vid, 'name': name, 'desc': descp})
        self.vendrop = DropDown(optfrm, self.vendors)

        self.cat_query = ("SELECT id, name, descp from etoken_cat where vendor_id = %(vendor_id)s")
        vid = self.vendors[0]['id']
        self.cursor.execute(self.cat_query, {'vendor_id': vid})
        self.cats = []
        for (catid, name, descp) in self.cursor:
            self.cats.append({'id': catid, 'name': name, 'desc': descp})
        self.catdrop = DropDown(optfrm, self.cats)

        self.tok_query = ("SELECT * from etoken_type where cat_id = %(cat_id)s")
        cat_id = self.cats[0]['id']
        self.cursor.execute(self.tok_query, {'cat_id': cat_id})
        self.toks = []
        for (tokid, name, descp, catid) in self.cursor:
            self.toks.append({'id': tokid, 'name': name, 'desc': descp})
        self.tokdrop = DropDown(optfrm, self.toks)

        self.vendrop.config(font=mfont, width=16)
        self.vendrop.pack(side=tk.LEFT)
        self.tokdrop.config(font=mfont, width=16)
        self.tokdrop.pack(side=tk.RIGHT)
        self.catdrop.config(font=mfont, width=16)
        self.catdrop.pack()

        self.vendrop.vari.trace("w", self.refresh_cat)
        self.catdrop.vari.trace("w", self.refresh_tok)

    def refresh_cat(self, *args):
        vname = self.vendrop.get_choice()
        vid = 0
        for ent in self.vendors:
            if ent['name'] == vname:
                vid = ent['id']
                break

        self.cursor.execute(self.cat_query, {'vendor_id': vid})
        self.cats = []
        for (catid, name, descp) in self.cursor:
            self.cats.append({'id': catid, 'name': name, 'desc': descp})
        self.catdrop.refresh_option(self.cats)

    def refresh_tok(self, *args):
        name = self.catdrop.get_choice()
        catid = 0
        for ent in self.cats:
            if ent['name'] == name:
                catid = ent['id']
                break

        self.cursor.execute(self.tok_query, {'cat_id': catid})
        self.toks = []
        for (tokid, name, descp, catid) in self.cursor:
            self.toks.append({'id': tokid, 'name': name, 'desc': descp})
        self.tokdrop.refresh_option(self.toks)

    def get_token_id(self):
        tokname = self.tokdrop.get_choice()
        for ent in self.toks:
            if ent['name'] == tokname:
                return ent['id']
        return 0


class TokenTX:
    def __init__(self, parent, glob):
        self.glob = glob
        self.parent = parent
        self.asset = 0

        self.cnx = mariadb.connect(**mariadb_config)
        self.cursor = self.cnx.cursor()

        self.tokid = TokenID(parent, self.cursor, glob.mfont)

        mfrm = tk.Frame(parent)
        mfrm.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)

        ufrm = tk.Frame(mfrm)
        ufrm.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)

        sbut = tk.Button(ufrm, text='Check', width=25, command=self.search_tokens)
        sbut.config(font=glob.mfont)
        sbut.pack(side=tk.TOP)

        sbar = tk.Scrollbar(ufrm)
        self.v_lbox = CopyListbox.CopyListbox(ufrm, relief=tk.SUNKEN, font=glob.mfont, width=46)
        sbar.config(command=self.v_lbox.yview)
        self.v_lbox.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.v_lbox.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.BOTH)

        lfrm = tk.Frame(mfrm)
        lfrm.pack(side=tk.BOTTOM, fill=tk.X, expand=tk.YES)

        llfrm = tk.Frame(lfrm)
        llfrm.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)

        tbut = tk.Button(llfrm, text='Transfer', width=25, command=self.transfer_token)
        tbut.config(font=glob.mfont)
        tbut.pack(side=tk.LEFT)

        cbut = tk.Button(llfrm, text='Create', width=25, command=self.create_token)
        cbut.config(font=glob.mfont)
        cbut.pack(side=tk.RIGHT)
        self.value_str = tk.StringVar()
        self.value_str.set('1000')
        value_entry = tk.Entry(llfrm, textvariable=self.value_str, width=16)
        value_entry.config(font=glob.mfont)
        value_entry.pack()

        ulfrm = tk.Frame(lfrm)
        ulfrm.pack(side=tk.BOTTOM, fill=tk.X, expand=tk.YES)
        tk.Label(ulfrm, text="Transfer to:", font=glob.mfont, width=16).pack(side=tk.LEFT)
        self.recipient = tk.StringVar()
        self.recipient.set('')
        rec_entry = CopyListbox.PasteEntry(ulfrm, textvariable=self.recipient, width=30)
        rec_entry.config(font=glob.mfont)
        rec_entry.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        mfrm = tk.Frame(parent)
        mfrm.pack(side=tk.BOTTOM, fill=tk.X, expand=tk.YES)
        tk.Label(mfrm, text="Use Key:", font=glob.mfont, width=16).pack(side=tk.LEFT)
        self.usekey = tk.StringVar()
        self.usekey.set('')
        rec_entry = CopyListbox.PasteEntry(mfrm, textvariable=self.usekey, width=30)
        rec_entry.config(font=glob.mfont)
        rec_entry.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

    def transfer_token(self):
        token = self.tokid.get_token_id()
        value = int(self.value_str.get())
        print("Will transfer Token ID: {}, number: {}".format(token, value))

    def search_tokens(self):
        self.v_lbox.delete(0, tk.END)
        token = self.tokid.get_token_id()
        selsql = "select value from utxo where " \
                "etoken_id = %(etoken_id)s and keyhash = %(keyhash)s"
        self.asset = 0
        print("Number of Keys: {}".format(len(self.glob.keylist)))
        for keytup in self.glob.keylist:
            keyhash = keytup[1]
            self.cursor.execute(selsql, {"etoken_id": token, "keyhash": keyhash})
            for value in self.cursor:
                item = "Key: {} Token ID: {} Value: {}".format(keyhash, etoken_id, value)
                print(item)
                print(type(value))
                self.v_lbox.insert(tk.END, item)
                self.asset += value

    def send_txrec(self, txrec):
        txf = open("/tmp/txtoken.dat", "wb")
        txf.write(txrec)
        txf.close()

        sha = hashlib.new('sha256')
        sha.update(txrec)
        hashidx = sha.digest()
        packet = len(txrec).to_bytes(2, byteorder='little') + (1).to_bytes(2, byteorder='little') + txrec
        for i in range(10):
            self.glob.sock[0].sendto(packet, self.glob.sock[1])
            time.sleep(0.8)
            ack = self.glob.sock[0].recv(2048, socket.MSG_DONTWAIT)
            if ack:
                acklen = int.from_bytes(ack[:2], 'little')
                ackval = int.from_bytes(ack[2:4], 'little')
                if acklen == 32 and ackval and hashidx == ack[4:]:
                    print("OK!")
                else:
                    print("Not OK!")
                break
        print("Index i: {}".format(i))


    def create_token(self):
        token = self.tokid.get_token_id()
        value = int(self.value_str.get())
        recipient = self.recipient.get().encode('utf-8')
        usekey = self.usekey.get()
        if value > 0 and len(recipient) == 28 and len(usekey) == 28:
            print("Will create Token ID: {}, number: {} for {}".format(token, value, recipient))
            print("Will use key: {}".format(usekey))
        for trikey in self.glob.keylist:
            if trikey[1] == usekey:
                mkey = b'0' + audiorand.bin2str_b64(trikey[0])
                txrec_buf = ctypes.create_string_buffer(2048);
                retv = self.glob.libtoktx.tx_create_token(txrec_buf, 2048, ctypes.c_int(token),
                        ctypes.c_ulong(value), ctypes.c_int(0), recipient, mkey)
                if retv > 0:
                    txrec = bytes(txrec_buf[:retv])
                    self.send_txrec(txrec)
                break


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
        mylist.append({'id': vid, 'name': name, 'desc': descp})
    cursor.close()

    mydrop = DropDown(root, mylist);
    mydrop.config(width=20, font=mfont);
    mydrop.pack(side=tk.TOP)

    mbut = tk.Button(root, text="Get ID", width=20, command=show_vid);
    mbut.config(font=mfont)
    mbut.pack(side=tk.BOTTOM)


    root.mainloop()
