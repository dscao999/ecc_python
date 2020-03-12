#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as mesgbox
from Crypto.Cipher import AES
import Crypto.Random as random
import audiorand
import ctypes
import TokenTX
import CopyListbox

mfont = ('courier', 16, 'bold')


class SList(tk.Frame):
    def clearlist(self):
        self.lbox.delete(0, tk.END)
        self.hbox.delete(0, tk.END)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pack(expand=tk.YES, fill=tk.BOTH);

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.BOTH)

        tk.Label(f1, text="Public Keys:", font=mfont, width=32).pack(side=tk.LEFT)
        tk.Label(f1, text="Public Key Hash:", font=mfont, width=32).pack(side=tk.RIGHT)

        f2_l = tk.Frame(f2)
        f2_r = tk.Frame(f2)
        f2_l.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        f2_r.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.BOTH)

        sbar = tk.Scrollbar(f2_l)
        lbox = CopyListbox.CopyListbox(f2_l, relief=tk.SUNKEN, font=mfont, width=46)
        sbar.config(command=lbox.yview)
        lbox.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        lbox.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        self.lbox = lbox

        sbar = tk.Scrollbar(f2_r)
        hbox = CopyListbox.CopyListbox(f2_r, relief=tk.SUNKEN, font=mfont, width=32)
        sbar.config(command=hbox.yview)
        hbox.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        hbox.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        self.hbox = hbox

    def append_item(self, pub, pubhash):
        self.lbox.insert(tk.END, pub)
        self.hbox.insert(tk.END, pubhash)

class KeyFile(tk.Frame):
    def append_key(self, keystr):
        b64key = b'0' + audiorand.bin2str_b64(keystr)
        ecckey = ctypes.create_string_buffer(b'\000', 96)
        self.libecc.ecc_key_import_str(ecckey, b64key)
        pubkey = ctypes.create_string_buffer(b'\000', 48)
        self.libecc.ecc_key_export_str(pubkey, 48, ecckey, 0x7e)
        pubkey = bytes(pubkey).decode('utf-8')
        pkeyhash = ctypes.create_string_buffer(b'\000', 48)
        self.libecc.ecc_key_hash_str(pkeyhash, 48, ecckey)
        pkeyhash = bytes(pkeyhash).decode('utf-8')
        self.keylist.append((keystr, pubkey, pkeyhash))
        self.publist.append_item(pubkey, pkeyhash)

    def generate_key(self):
        keystr = self.sndrnd.ecc256_random(5)
        self.append_key(keystr)
        self.keymod = 1

    def load_key(self):
        fname = filedialog.askopenfilename(parent=self, title='Load Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        self.keylist.clear()
        self.keymod = 0
        self.publist.clearlist()
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ifp = open(fname, 'rb')
        cip = ifp.read(48)
        while cip:
            pla = aes.decrypt(cip)
            crc32 = self.libecc.crc32(pla, len(pla))
            if crc32 != 0:
                mesgbox.showerror("Error", "Invalid Password")
                ifp.close()
                self.keylist.clear()
                return
            keystr = pla[:32]
            self.append_key(keystr)
            cip = ifp.read(48)
        ifp.close()

    def __init__(self, parent=None, fname=None, width=32):
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

        self.sndrnd = audiorand.SndRnd()
        self.keylist = []
        self.keymod = 0
        self.libecc = ctypes.CDLL("../lib/libecc256.so")
        self.libecc.ecc_init()

    def save_key(self):
        fname = filedialog.asksaveasfilename(parent=self, title='Save Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ofp = open(fname, 'wb')
        for keystr in self.keylist:
            appstr = self.sndrnd.ecc256_random(1)
            plain = keystr[0] + appstr[:12]
            crc32 = self.libecc.crc32(plain, len(plain))
            if (crc32 < 0):
                crc32 += 2**32
            plain += crc32.to_bytes(4, 'big')
            scrtext = aes.encrypt(plain)
            ofp.write(scrtext)
        ofp.close()
        self.keymod = 0

    def mexit(self):
        if self.keymod and mesgbox.askyesno("Confirm Action", \
                "Keys has been modified, Save it?", master=self):
            self.config(cursor="watch")
            self.save_key()
            self.config(cursor="")
        sys.exit()


if __name__ == "__main__":
    def ttransfer():
        neww = tk.Toplevel(root)
        token_op = TokenTX.TokenTX(neww, keyfile.keylist, mfont)
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

    keyfile = KeyFile(fp1, fname)

    tk.Button(fp2, text="Token Transfer", font=mfont,
            width=25, command=ttransfer).pack(side=tk.LEFT)
    root.protocol('WM_DELETE_WINDOW', keyfile.mexit)

    root.mainloop()
