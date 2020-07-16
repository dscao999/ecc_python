import tkinter as tk
import tkinter.messagebox as mesgbox
import sys
import CopyListbox
from tkinter import simpledialog
import ctypes
import hashlib
import time
import socket
import base64

mariadb_config = {
        'user': 'dscao',
        'host': 'localhost',
        'database': 'electoken'
}

tables = ["vendors", "etoken_cat", "etoken_type", "sales"]

def bin2str_b64(byte_str):
    return base64.b64encode(byte_str)

def str2bin_b64(cstr):
    return base64.b64decode(cstr)

def send_txreq(socks, reqbuf, tries=25):
    retry = 1
    ack = bytes()
    while retry == 1:
        ctm = int(time.monotonic() * 1000)
        reqbuf = ctm.to_bytes(8, 'little') + reqbuf
        socks['sock'].sendto(reqbuf, socks['sockaddr'])
        retry = 0
        rep = 0
        while rep < tries:
            time.sleep(0.2)
            try:
                ack = socks['sock'].recv(2048)
                if int.from_bytes(ack[:8], 'little') == ctm:
                    break
            except BlockingIOError:
                pass
            rep += 1

        if len(ack) == 0 and rep == tries:
            if mesgbox.askretrycancel("Error", "No response from server. Try Again?"):
                retry = 1
    return ack[8:]

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
    def __init__(self, parent, glob, ekid):
        socks = glob.sock
        mfont = glob.mfont
        self.ekid = ekid
        frame = tk.Frame(parent)
        frame.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)

        label = tk.Label(frame, text="Select Token Type", font=mfont, width=80)
        label.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        optfrm = tk.Frame(frame)
        optfrm.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        sep = tk.Frame(optfrm, height=8, bg='black', bd=2, relief=tk.SUNKEN)
        sep.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.vendors = []
        reqbuf = int(0).to_bytes(4, 'little') + int(3).to_bytes(4, 'little')
        vack = send_txreq(socks, reqbuf, tries=glob.tries)
        if len(vack) == 0:
            raise Exception("Cannot Contact Server")
        total_len = int.from_bytes(vack[:4], 'little')
        ackval = int.from_bytes(vack[4:8], 'little')
        vack = vack[8:]
        while len(vack) > 0:
            vid = int.from_bytes(vack[:4], 'little')
            if vid == 0:
                break
            nlen = int.from_bytes(vack[4:5], 'little')
            pos = 5
            vname = vack[pos:pos+nlen].decode('utf-8')
            pos += nlen
            nlen = int.from_bytes(vack[pos:pos+1], 'little')
            pos += 1
            vdesc = vack[pos:pos+nlen].decode('utf-8')
            pos += nlen
            self.vendors.append({'id': vid, 'name': vname, 'desc': vdesc, 'cats': []})

            reqbuf = int(4).to_bytes(4, 'little') + int(4).to_bytes(4, 'little') + vid.to_bytes(4, 'little')
            catack = send_txreq(socks, reqbuf, tries=glob.tries)
            if len(catack) == 0:
                raise Exception('Cannot Contact Server')
            total_len = int.from_bytes(catack[:4], 'little')
            ackval = int.from_bytes(catack[4:8], 'little')
            catack = catack[8:]
            cats = []
            while len(catack) > 0:
                catid = int.from_bytes(catack[:4], 'little')
                if catid == 0:
                    break
                nlen = int.from_bytes(catack[4:5], 'little')
                catpos = 5
                cname = catack[catpos:catpos+nlen].decode('utf-8')
                catpos += nlen
                nlen = int.from_bytes(catack[catpos:catpos+1], 'little')
                catpos += 1
                cat_desc = catack[catpos:catpos+nlen].decode('utf-8')
                catpos += nlen
                cats.append({'id': catid, 'name': cname, 'desc': cat_desc, 'etokens': []})

                reqbuf = int(4).to_bytes(4, 'little') + int(5).to_bytes(4, 'little') + catid.to_bytes(4, 'little')
                tokack = send_txreq(socks, reqbuf, tries=glob.tries)
                if len(tokack) == 0:
                    raise Exception("Cannot Contact Server")
                total_len = int.from_bytes(tokack[:4], 'little')
                ackval = int.from_bytes(tokack[4:8], 'little')
                toks = []
                tokack = tokack[8:]
                while len(tokack) > 0:
                    tokid = int.from_bytes(tokack[:4], 'little')
                    if tokid == 0:
                        break
                    nlen = int.from_bytes(tokack[4:5], 'little')
                    tokpos = 5
                    tokname = tokack[tokpos:tokpos+nlen].decode('utf-8')
                    tokpos += nlen
                    nlen = int.from_bytes(tokack[tokpos:tokpos+1], 'little')
                    tokpos += 1
                    tokdesc = tokack[tokpos:tokpos+nlen].decode('utf-8')
                    tokpos += nlen
                    rem = tokpos & 3;
                    if rem != 0:
                        tokpos += (4 - rem)
                    toks.append({'id': tokid, 'name': tokname, 'desc': tokdesc})
                    tokack = tokack[tokpos:]

                cats[-1]['etokens'] = toks
                rem = catpos & 3
                if rem != 0:
                    catpos += (4 - rem)
                catack = catack[catpos:]

            self.vendors[-1]['cats'] = cats
            rem = pos & 3
            if rem != 0:
                pos += (4 - rem)
            vack = vack[pos:]

        self.vendrop = DropDown(optfrm, self.vendors)
        self.catdrop = DropDown(optfrm, self.vendors[0]['cats'])
        self.tokdrop = DropDown(optfrm, self.vendors[0]['cats'][0]['etokens'])
        self.ven_idx = 0
        self.cat_idx = 0
        self.tok_idx = 0

        self.vendrop.config(font=mfont, width=16)
        self.vendrop.pack(side=tk.LEFT)
        self.tokdrop.config(font=mfont, width=16)
        self.tokdrop.pack(side=tk.RIGHT)
        self.catdrop.config(font=mfont, width=16)
        self.catdrop.pack()

        self.vendrop.vari.trace("w", self.refresh_cat)
        self.catdrop.vari.trace("w", self.refresh_tok)
        self.tokdrop.vari.trace("w", self.read_token)

        self.ekid.set(str(self.get_token_id()))

    def refresh_cat(self, *args):
        vname = self.vendrop.get_choice()
        idx = 0
        for ent in self.vendors:
            if ent['name'] == vname:
                vid = ent['id']
                break
            idx += 1
        self.ven_idx = idx
        cats = self.vendors[idx]['cats']
        self.cat_idx = 0
        self.catdrop.refresh_option(cats)
        toks = self.vendors[idx]['cats'][0]['etokens']
        self.tok_idx = 0
        self.tokdrop.refresh_option(toks)

    def refresh_tok(self, *args):
        name = self.catdrop.get_choice()
        idx = 0
        for ent in self.vendors[self.ven_idx]['cats']:
            if ent['name'] == name:
                catid = ent['id']
                break
            idx += 1
        self.cat_idx = idx
        self.tok_idx = 0
        toks = self.vendors[self.ven_idx]['cats'][idx]['etokens']
        self.tokdrop.refresh_option(toks)

    def read_token(self, *args):
        self.ekid.set(str(self.get_token_id()))

    def get_token_id(self):
        tokname = self.tokdrop.get_choice()
        for ent in self.vendors[self.ven_idx]['cats'][self.cat_idx]['etokens']:
            if ent['name'] == tokname:
                return ent['id']
        return 0

class TokenTX:
    def __init__(self, parent, glob):
        self.glob = glob
        self.parent = parent
        self.asset = {'token': 0, 'by_key': []}
        self.ekid = tk.StringVar()

        try:
            self.tokid = TokenID(parent, glob, self.ekid)
        except:
            raise Exception("Abort")

        mfrm = tk.Frame(parent)
        mfrm.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)

        ufrm = tk.Frame(mfrm)
        ufrm.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)

        ubar = tk.Frame(ufrm)
        ubar.pack(side=tk.TOP, fill=tk.X, expand=tk.YES)
        tk.Label(ubar, text='Token ID:', font=glob.mfont).pack(side=tk.LEFT)
        sbut = tk.Button(ubar, text='Check', width=25, command=self.search_tokens)
        sbut.config(font=glob.mfont)
        sbut.pack(side=tk.RIGHT)
        tk.Entry(ubar, textvariable=self.ekid, state='disabled', font=glob.mfont).pack(side=tk.TOP)

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

        idx = 0
        sval = 0
        for item in mlst:
            sval += item['value']
            if sval >= value:
                break;
            idx += 1
        if sval < value:
            mesgbox.showerror("Error", "Internal Logic Error")
            return
        owner = str2bin_b64(payto.encode('utf-8'))
        lptr = ctypes.create_string_buffer(8)
        retv = self.glob.libtoktx.tx_trans_begin(lptr, token, ctypes.c_ulonglong(value), owner)
        if retv != 0:
            mesgbox.showerror("Error", "Out of Memory");
            return
        txrec = int.from_bytes(lptr, byteorder='little')
        for i in range(idx+1):
            retv = self.glob.libtoktx.tx_trans_add(ctypes.c_ulonglong(txrec), mlst[i]['txid'], mlst[i]['vout_idx'])
            if retv != 0:
                mesgbox.showerror("Error", "Out of Memory")
                self.glob.libtoktx.tx_trans_abort(ctypes.c_ulonglong(txrec))
                return
        if sval > value:
            owner = str2bin_b64(mlst[0]['key'].encode('utf-8'))
            retv = self.glob.libtoktx.tx_trans_sup(ctypes.c_ulonglong(txrec), ctypes.c_ulonglong(sval-value), owner)
            if retv != 0:
                mesgbox.showerror("Error", "Out of Memory")
                self.glob.libtoktx.tx_trans_abort(ctypes.c_ulonglong(txrec))
                return

        txbuf = ctypes.create_string_buffer(2048)
        keylst = self.glob.keylist
        for i in range(idx+1):
            pkey = mlst[i]['key']
            for mkey in keylst:
                if mkey[1] == pkey:
                    break
            if pkey != mkey[1]:
                mesgbox.showerror("Error", "No Key to transfer the tokens")
                self.glob.libtoktx.tx_trans_abort(ctypes.c_ulonglong(txrec))
                return
            retv = self.glob.libtoktx.tx_trans_sign(ctypes.c_ulonglong(txrec), txbuf, 2048, mkey[0], i)
            if retv != 0:
                mesgbox.showerror("Error", "Out of Memory")
                self.glob.libtoktx.tx_trans_abort(ctypes.c_ulonglong(txrec))
                return

        txlen = self.glob.libtoktx.tx_trans_end(txbuf, 2048, ctypes.c_ulonglong(txrec))
        tx = bytes(txbuf[:txlen])
        self.send_txrec(tx, self.glob.tries)


    def search_tokens(self):
        self.v_lbox.delete(0, tk.END)
        token = self.tokid.get_token_id()
        self.asset['token'] = token;
        kvlst = self.asset['by_key']
        kvlst.clear()
        
        reqbuf = token.to_bytes(4, 'little')
        for keytup in self.glob.keylist:
            keyhash = keytup[1]
            bytestr = str2bin_b64(keyhash)
            reqbuf += len(bytestr).to_bytes(1, 'little')
            reqbuf += bytestr
        reqbuf += int(0).to_bytes(1, 'little')
        reqbuf = len(reqbuf).to_bytes(4, 'little') + int(2).to_bytes(4, 'little') + reqbuf
        ack = send_txreq(self.glob.sock, reqbuf, self.glob.tries)
        if len(ack) == 0:
            return

        acklen = int.from_bytes(ack[:4], 'little')
        ackval = int.from_bytes(ack[4:8], 'little')
        if ackval != 1:
            mesgbox.showerror("Logic Error", "Invalid Response Received")
            return
        pos = 8
        while pos - 8 < acklen:
            strlen = int.from_bytes(ack[pos:pos+1], 'little')
            bkeyhash = ack[pos+1:pos+strlen+1]
            keyhash = bin2str_b64(bkeyhash).decode('utf-8')
            pos += strlen+1;
            value = int.from_bytes(ack[pos:pos+8], 'little')
            while value != 0:
                pos += 8
                strlen = int.from_bytes(ack[pos:pos+1], 'little')
                txid = ack[pos+1:pos+strlen+1]
                pos += strlen + 1
                vout_idx = int.from_bytes(ack[pos:pos+1], 'little')
                pos += 1
                kvlst.append({'value': value, 'key': keyhash, 'txid': txid, 'vout_idx': vout_idx})
                print("at vout index: {}".format(vout_idx))
                litem = keyhash + ' ---> ' + str(value)
                self.v_lbox.insert(tk.END, litem)
                value = int.from_bytes(ack[pos:pos+8], 'little')
            pos += 8
        print("etoken ID: {}".format(self.asset['token']))
        for item in self.asset['by_key']:
            print("Key: {}, Value: {}".format(item['key'], item['value']))

    def send_txrec(self, txrec, tries=25):
        sha = hashlib.new('sha256')
        sha.update(txrec)
        hashidx = sha.digest()
        packet = len(txrec).to_bytes(4, byteorder='little') + (1).to_bytes(4, byteorder='little') + txrec
        ack = send_txreq(self.glob.sock, packet, tries)
        if len(ack) == 0:
            return
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

    def create_token(self):
        sent = 0
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
                            ctypes.c_ulonglong(value), ctypes.c_int(0), recipient, trikey[0])
                    if retv > 0:
                        txrec = bytes(txrec_buf[:retv])
                        self.send_txrec(txrec, self.glob.tries)
                        sent = 1
                    break
        else:
            if value <= 0:
                mesgbox.showerror("Error", "The value must be greater than 0");
            if len(recipient) != 28:
                mesgbox.showerror("Error", "The receipient must be specified");
            if len(usekey) != 28:
                mesgbox.showerror("Error", "The key used to create token is missing");
        if sent == 0:
            mesgbox.showerror("Error", "Cannot create Token")


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
