#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as mesgbox
from Crypto.Cipher import AES
import hashlib
import ctypes
import TokenTX
import CopyListbox
import socket

mfont = ('courier', 16, 'bold')

class SList(tk.Frame):
    def clearlist(self):
        self.hbox.delete(0, tk.END)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pack(expand=tk.YES, fill=tk.BOTH);

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.BOTH)

        tk.Label(f1, text="Public Key Hash:", font=mfont, width=32).pack(side=tk.TOP)

        sbar = tk.Scrollbar(f2)
        hbox = CopyListbox.CopyListbox(f2, relief=tk.SUNKEN, font=mfont, width=32)
        sbar.config(command=hbox.yview)
        hbox.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        hbox.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        self.hbox = hbox

    def append_item(self, pubhash):
        self.hbox.insert(tk.END, pubhash)

class GlobParam:
    def __init__(self, cfg_name):
        self.libtoktx = ctypes.CDLL("../lib/libtoktx.so")
        self.libtoktx.ecc_init()
        self.keylist = []
        self.keymod = 0
        self.mfont = mfont
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        txsvr = socket.getaddrinfo("localhost", "6001", family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock = (sock, txsvr[0][4])

    def append_key(self, keystr):
        pkeyhash = ctypes.create_string_buffer(b'\000', 48)
        self.libtoktx.ecc_key_hash_str(pkeyhash, 48, keystr)
        pkeyhash = bytes(pkeyhash).decode('utf-8').strip("\000")
        self.keylist.append((keystr, pkeyhash))
        self.keymod = 1
        return pkeyhash
    
    def generate_key(self):
        keystr = bytes(ctypes.create_string_buffer(96, '\0x0'))
        gotone = self.libtoktx.ecc_genkey(keystr);
        if gotone != 0:
            mesgbox.showerror("Error", "Cannot Get Enough Random Bits");
        return self.append_key(keystr)

    def clear_key(self):
        self.keylist.clear()
        self.keymod = 0

    def save_key(self, fname, passwd):
        aes = AES.new(passwd, AES.MODE_ECB)
        ofp = open(fname, 'wb')
        for keystr in self.keylist:
            pad = ctypes.create_string_buffer(12, '\000')
            self.libtoktx.rand32bytes(pad, 12, 0)
            plain = keystr[0][:32] + bytes(pad)
            crc32 = self.libtoktx.crc32(plain, len(plain))
            if (crc32 < 0):
                crc32 += 2**32
            plain += crc32.to_bytes(4, 'big')
            scrtext = aes.encrypt(plain)
            ofp.write(scrtext)
        ofp.close()
        self.keymod = 0

    def load_key(self, fname, passwd):
        self.clear_key()
        aes = AES.new(passwd, AES.MODE_ECB)
        ifp = open(fname, 'rb')
        cip = ifp.read(48)
        khashs = []
        while cip:
            pla = aes.decrypt(cip)
            crc32 = self.libtoktx.crc32(pla, len(pla))
            if crc32 != 0:
                mesgbox.showerror("Error", "Invalid Password")
                ifp.close()
                self.clear_key()
                return khashs.clear()
            keystr = pla[:32]
            ecckey = bytes(ctypes.create_string_buffer(96))
            self.libtoktx.ecc_get_public(keystr, ecckey)
            khashs.append(self.append_key(ecckey))
            cip = ifp.read(48)
        ifp.close()
        self.keymod = 0
        return khashs

class KeyFile(tk.Frame):
    def generate_key(self):
        khash = self.glob.generate_key()
        if khash:
            self.publist.append_item(khash)

    def load_key(self):
        if self.glob.keymod and mesgbox.askyesno("Confirm Action", \
                "Keys has been modified, Save it?", master=self):
            self.config(cursor="watch")
            self.save_key()
            self.config(cursor="")
        fname = filedialog.askopenfilename(parent=self, title='Load Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        mh = hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        khashs = self.glob.load_key(fname, passwd[:16])
        if khashs:
            self.publist.clearlist()
            for pkhash in khashs:
                self.publist.append_item(pkhash)

    def __init__(self, parent, glob, width=32):
        super().__init__(parent)
        self.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        f1_1 = tk.Frame(f1)
        f1_1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f1_2 = tk.Frame(f1)
        f1_2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        row2 = tk.Frame(f1_1)
        row2.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        passlab = tk.Label(row2, text='  Passwd:', font=mfont)
        passlab.pack(side=tk.LEFT)
        self.passwd_str = tk.StringVar()
        self.passwd_str.set('')
        passtext = tk.Entry(row2, show="*", textvariable=self.passwd_str, width=width)
        passtext.config(font=mfont)
        passtext.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)


        row4 = tk.Frame(f1_2)
        row4.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        tk.Button(row4, text="Load Keys", font=mfont,
                width=18, command=self.load_key).pack(side=tk.LEFT)
        tk.Button(row4, text="Generate Key", font=mfont,
                width=18, command=self.generate_key).pack(side=tk.RIGHT)
        tk.Button(row4, text="Save Keys", font=mfont,
                width=18, command=self.save_key).pack()

        separator = tk.Frame(f2, height=8, bg='black', bd=2, relief=tk.SUNKEN)
        separator.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.publist = SList(f2)
        self.glob = glob

    def save_key(self):
        fname = filedialog.asksaveasfilename(parent=self, title='Save Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        mh = hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        self.glob.save_key(fname, passwd[:16])

    def mexit(self):
        if self.glob.keymod and mesgbox.askyesno("Confirm Action", \
                "Keys has been modified, Save it?", master=self):
            self.config(cursor="watch")
            self.save_key()
            self.config(cursor="")
        sys.exit(0)


if __name__ == "__main__":
    def ttransfer():
        neww = tk.Toplevel(root)
        token_op = TokenTX.TokenTX(neww, keyfile.glob)
        neww.title("Token Transfer")
        
    fname=os.getcwd() + '/ecc256_key.pri'
    if len(sys.argv) > 1:
        fname = sys.argv[1]

    root = tk.Tk()
    root.title(sys.argv[0])

    fp1 = tk.Frame(root)
    fp1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X);
    fp2 = tk.Frame(root)
    fp2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X);
    glob = GlobParam('')
    keyfile = KeyFile(fp1, glob)

    tk.Button(fp2, text="Token Transfer", font=mfont,
            width=25, command=ttransfer).pack(side=tk.LEFT)
    root.protocol('WM_DELETE_WINDOW', keyfile.mexit)

    root.mainloop()
