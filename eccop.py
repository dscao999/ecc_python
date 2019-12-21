#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
from Crypto.Cipher import AES
import Crypto.Random as random
import audiorand
import binascii

class KeyFile(tk.Frame):
    def generate_key(self):
        keystr = self.sndrnd.ecc256_random(5)
        self.keylist.append(keystr)
        print(audiorand.bin2str_b64(keystr))

    def load_key(self):
        fname = self.fname_str.get()
        if not os.path.exists(fname):
            return
        self.keylist = []
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ifp = open(self.fname_str.get(), 'rb')
        cip = ifp.read(48)
        while cip:
            pla = aes.decrypt(cip)
            crc32 = binascii.crc32(pla[:44])
            crcf = int.from_bytes(pla[44:], 'big')
            if crc32 != crcf:
                print("Invalid Pass Word!")
                cip = ifp.read(48)
                continue
            keystr = pla[:32]
            self.keylist.append(keystr)
            print(audiorand.bin2str_b64(keystr))
            cip = ifp.read(48)
        ifp.close()

    def __init__(self, parent=None, fname=None, width=32):
        super().__init__(parent)
        self.mfont = ('courier', 16, 'bold')
        self.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        f1_1 = tk.Frame(f1)
        f1_1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f1_2 = tk.Frame(f1)
        f1_2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        row1 = tk.Frame(f1_1)
        row1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        keylab = tk.Label(row1, text='Key File:', font=self.mfont)
        keylab.pack(side=tk.LEFT)
        self.fname_str = tk.StringVar()
        self.fname_str.set(fname)
        keyf = tk.Entry(row1, width=width, textvariable=self.fname_str)
        keyf.config(font=self.mfont)
        keyf.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row2 = tk.Frame(f1_1)
        row2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        passlab = tk.Label(row2, text='  Passwd:', font=self.mfont)
        passlab.pack(side=tk.LEFT)
        self.passwd_str = tk.StringVar()
        self.passwd_str.set('')
        passtext = tk.Entry(row2, show="*", textvariable=self.passwd_str, width=width)
        passtext.config(font=self.mfont)
        passtext.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row3 = tk.Frame(f1_2)
        row3.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        tk.Button(row3, text="Select Key File", command=self.select_file,
                font=self.mfont, width=16).pack(side=tk.TOP)

        row4 = tk.Frame(f1_2)
        row4.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        tk.Button(row4, text="Generate New Key", font=self.mfont,
                width=16, command=self.generate_key).pack(side=tk.LEFT)
        tk.Button(row4, text="Save Key", font=self.mfont,
                width=16, command=self.save_key).pack(side=tk.RIGHT)
        tk.Button(row4, text="Load Key", font=self.mfont,
                width=16, command=self.load_key).pack()

        self.sndrnd = audiorand.SndRnd()
        self.keylist = []

    def select_file(self):
        fname = filedialog.asksaveasfilename(parent=self, title='Select Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) != 0:
            self.fname_str.set(fname)


    def save_key(self):
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ofp = open(self.fname_str.get(), 'wb')
        for keystr in self.keylist:
            appstr = self.sndrnd.ecc256_random(1)
            plain = keystr + appstr[:12]
            crc32 = binascii.crc32(bytes(plain))
            plain += crc32.to_bytes(4, 'big')
            scrtext = aes.encrypt(plain)
            ofp.write(scrtext)
        ofp.close()

    def mexit(self):
        print("I'm exiting!")
        sys.exit()

root = tk.Tk()
root.title(sys.argv[0])

fname=os.getcwd() + '/ecc256_key.pri'
if len(sys.argv) > 1:
    fname = sys.argv[1]

width = len(fname)
if (width < 32): width = 32

keyfile = KeyFile(root, fname, width)

root.protocol('WM_DELETE_WINDOW', keyfile.mexit)

root.mainloop()
