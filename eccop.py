#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
import audiorand

class KeyFile(tk.Frame):
    def generate_key(self):
        keystr = self.sndrnd.ecc256_keygen(5)
        print(len(keystr))
##        self.keyf.config(state='normal')
##        self.keyf.delete(0, 'end')
##        self.keyf.insert(0, keystr)
##        self.keyf.config(state='readonly')
        return keystr

    def __init__(self, parent=None, fname=None):
        super().__init__(parent)
        self.mfont = ('courier', 16, 'bold')
        self.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        row1 = tk.Frame(f2)
        row1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        keylab = tk.Label(row1, text='Key Hash File:', font=self.mfont)
        keylab.pack(side=tk.LEFT)

        hname = fname.rsplit('.', 1)[0]
        self.hname_str = tk.StringVar()
        self.hname_str.set(fname)
        keyh = tk.Entry(row1, width=32, textvariable=self.hname_str)
        keyh.config(font=self.mfont, state='readonly')
        keyh.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

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
        keyf = tk.Entry(row1, width=32, textvariable=self.fname_str)
        keyf.bind('<Return>', self.fname_set)
        keyf.bind('<FocusOut>', self.fname_set)
        keyf.config(font=self.mfont)
        keyf.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row2 = tk.Frame(f1_1)
        row2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        passlab = tk.Label(row2, text='  Passwd:', font=self.mfont)
        passlab.pack(side=tk.LEFT)
        passtext = tk.Entry(row2, show="*", width=32)
        passtext.config(font=self.mfont)
        passtext.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row3 = tk.Frame(f1_2)
        row3.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)

        tk.Button(row3, text="Select Key File", command=self.select_file,
                font=self.mfont, width=16).pack(side=tk.TOP)
        tk.Button(row3, text="Generate New Key", font=self.mfont,
                width=16).pack(side=tk.BOTTOM)

        self.sndrnd = audiorand.SndRnd()


    def fname_set(self, sv):
        fname = self.fname_str.get()
        hname = fname.rsplit('.', 1)[0]
        self.hname_str.set(hname+'.pub')

    def select_file(self):
        fname = filedialog.askopenfilename(parent=self, multiple=False,
                title='Select Key File')
        if len(fname) != 0:
            self.fname_str.set(fname)
            hname = fname.rsplit('.', 1)[0]
            self.hname_str.set(hname+'.pub')

root = tk.Tk()
root.title(sys.argv[0])

fname='ecc256_key.dat'
if len(sys.argv) > 1:
    fname = sys.argv[1]

keyfile = KeyFile(root, fname)

root.mainloop()
