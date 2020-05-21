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
        vendor_query = ("SELECT * FROM vendors")
        self.cursor.execute(vendor_query)
        self.vendors = []
        for (vid, name, descp) in self.cursor:
            self.vendors.append({'id': vid, 'name': name, 'desc': descp})
        self.vendrop = DropDown(optfrm, self.vendors)

        self.cat_query = ("SELECT id, name, descp FROM etoken_cat WHERE vendor_id = %(vendor_id)s")
        vid = self.vendors[0]['id']
        self.cursor.execute(self.cat_query, {'vendor_id': vid})
        self.cats = []
        for (catid, name, descp) in self.cursor:
            self.cats.append({'id': catid, 'name': name, 'desc': descp})
        self.catdrop = DropDown(optfrm, self.cats)

        self.tok_query = ("SELECT * FROM etoken_type WHERE cat_id = %(cat_id)s")
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
        self.asset = {'token': 0, 'by_key': []}

        try:
            self.cnx = mariadb.connect(**mariadb_config)
        except mariadb.Error:
            mesgbox.showerror("Error", "Cannot connect to DB Server")
            sys.exit(1)

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
        def mlst_sort(litem):
            return litem['value']

        token = self.tokid.get_token_id()
        if token != self.asset['token']:
            mesgbox.showerror("Error", "Please Check for your assets");
            return
        value = int(self.value_str.get())
        mvalue = 0
        for item in self.asset['by_key']:
            mvalue += item['value']
        if mvalue < value:
            mesgbox.showerror("Error", "Do not have enough assets")
            return
        payto = self.recipient.get().rstrip(' ')
        if len(payto) != 28:
            mesgbox.showerror("Error", "The Token Recipient must be specified")
            return
        mlst = self.asset['by_key'][:]
        mlst.sort(reverse=True, key=mlst_sort)
        print("Will transfer Token ID: {}, number: {}, payto: {}".format(token, value, payto))

        idx = 1
        sval = 0
        for item in mlst:
            sval += item['value']
            if sval >= value:
                break;
            idx += 1
        if sval < value:
            mesgbox.showerror("Logic Error", "Internal Logic Error")
            return
        lptr = ctypes.create_string_buffer(8)
        retv = self.glob.libtoktx.tx_trans_begin(lptr, token, ctypes.c_ulong(value), payto.encode('utf-8'))
        txrec = int.from_bytes(lptr, byteorder='little')
        print("In Python: {}".format(hex(txrec)))
        keylst = self.glob.keylist
        for i in range(idx):
            pkey = mlst[i]['key']
            for mkey in keylst:
                if mkey[1] == pkey:
                    break
            if pkey != mkey[1]:
                mesgbox.showerror("Logic Error", "Internal Logic Error")
                self.glob.libtoktx.tx_trans_abort(txrec)
                return
            pos = self.glob.libtoktx.tx_trans_add(ctypes.c_ulong(txrec), mkey[0], mlst[i]['value'])
        txbuf = ctypes.create_string_buffer(2048)
        txlen = self.glob.libtoktx.tx_trans_end(txbuf, 2048, ctypes.c_ulong(txrec))


    def search_tokens(self):
        self.v_lbox.delete(0, tk.END)
        token = self.tokid.get_token_id()
        self.asset['token'] = token;
        kvlst = self.asset['by_key']
        kvlst.clear()
        
        reqbuf = token.to_bytes(2, 'little')
        for keytup in self.glob.keylist:
            keyhash = keytup[1]
            reqbuf += (len(keyhash) + 1).to_bytes(2, 'little')
            reqbuf += keyhash.encode('utf8') + int(0).to_bytes(1, 'little')
        reqbuf += int(0).to_bytes(2, 'little')
        reqbuf = len(reqbuf).to_bytes(4, 'little') + int(2).to_bytes(4, 'little') + reqbuf
        retry = 1
        while retry == 1:
            self.glob.sock[0].sendto(reqbuf, self.glob.sock[1])
            rep = 0
            while rep < 3:
                try:
                    ack = self.glob.sock[0].recv(2048, socket.MSG_DONTWAIT)
                    break
                except BlockingIOError:
                    pass
                rep += 1
                time.sleep(1)

            if rep < 3:
                acklen = int.from_bytes(ack[:4], 'little')
                ackval = int.from_bytes(ack[4:8], 'little')
                if ackval != 1:
                    break
                pos = 8
                while pos - 8 < acklen:
                    strlen = int.from_bytes(ack[pos:pos+1], 'little')
                    keyhash = ack[pos+1:pos+strlen].decode('utf8').rstrip('\0')
                    pos += strlen;
                    value = int.from_bytes(ack[pos:pos+8], 'little')
                    pos += 8;
                    while value != 0:
                        kvlst.append({'value': value, 'key': keyhash})
                        litem = keyhash + ' ---> ' + str(value)
                        self.v_lbox.insert(tk.END, litem)
                        value = int.from_bytes(ack[pos:pos+8], 'little')
                        pos += 8
                retry = 0
            else:
                if not mesgbox.askretrycancel("Error", "No response from server. Try Again?"):
                    retry = 0
        print("etoken ID: {}".format(self.asset['token']))
        for item in self.asset['by_key']:
            print("Key: {}, Value: {}".format(item['key'], item['value']))

    def send_txrec(self, txrec):
        txf = open("/tmp/txtoken.dat", "wb")
        txf.write(txrec)
        txf.close()

        sha = hashlib.new('sha256')
        sha.update(txrec)
        hashidx = sha.digest()
        packet = len(txrec).to_bytes(4, byteorder='little') + (1).to_bytes(4, byteorder='little') + txrec
        tagain = 1
        while tagain:
            self.glob.sock[0].sendto(packet, self.glob.sock[1])
            rep = 0
            while rep < 10:
                time.sleep(1)
                try:
                    ack = self.glob.sock[0].recv(2048, socket.MSG_DONTWAIT)
                    break
                except BlockingIOError:
                    pass
                rep += 1

            if rep == 10:
                askbox = mesgbox.askquestion("Error", "No response from server, Try again?")
                if askbox != 'yes':
                    tagain = 0
                    continue
            elif hashidx == ack[8:]:
                acklen = int.from_bytes(ack[:4], 'little')
                ackval = int.from_bytes(ack[4:8], 'little')
                print("Ack: {}".format(ackval))
                if ackval == 1 or ackval == 2:
                    mesgbox.showinfo("Information", "Transaction Accepted")
                elif ackval == 0:
                    mesgbox.showerror("Error", "Transaction Rejected")
                else:
                    mesgbox.showerror("Error", "Server logic failed")
                tagain = 0


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
                txrec_buf = ctypes.create_string_buffer(2048);
                retv = self.glob.libtoktx.tx_create_token(txrec_buf, 2048, ctypes.c_int(token),
                        ctypes.c_ulong(value), ctypes.c_int(0), recipient, trikey[0])
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

    try:
        cnx = mariadb.connect(**mariadb_config)
        cursor = cnx.cursor()
        vendor_query = ("SELECT * FROM vendors")
        cursor.execute(vendor_query)
    except ConnectionRefusedError:
        mesgbox.showerror("Error", "Cannot connect to DB Server");
        sys.exit(1)

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
