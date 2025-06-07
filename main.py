import requests
import threading
import queue
import os
import json
import argparse
import urllib.parse
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
import webbrowser
from PIL import Image, ImageTk

CONFIG_PATH = Path.home() / ".dir_bruteforce_config.json"

class Settings:
    DEFAULTS = {
        "threads": 10,
        "timeout": 5,
        "user_agent": "DirBruteForcer/1.0",
        "recursion_depth": 5,
        "include_status_codes": "<400",
        "file_extensions": "",
        "follow_redirects": True
    }

    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.load()

    def load(self):
        if self.path.exists():
            try:
                with open(self.path, 'r') as f:
                    data = json.load(f)
            except Exception:
                data = {}
        else:
            data = {}
        self.data = {**Settings.DEFAULTS, **data}

    def save(self):
        try:
            with open(self.path, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save settings: {e}")

class DirBruteForcer:
    def __init__(self, base_url, wordlist_file, settings, on_found, on_finish, on_progress=None):
        self.base_url = base_url.rstrip('/')
        self.wordlist_file = wordlist_file
        self.settings = settings
        self.on_found = on_found
        self.on_finish = on_finish
        self.on_progress = on_progress or (lambda p: None)
        self.to_scan = queue.Queue()
        self.seen = set()
        self.running = False
        self.total = 0
        self.processed = 0
        self.threads = []

    def load_wordlist(self):
        with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            return [w.strip() for w in f if w.strip()]

    def start(self):
        if self.running:
            return
        self.running = True
        # clear queue
        while not self.to_scan.empty():
            self.to_scan.get_nowait()
            self.to_scan.task_done()
        # seed
        self.to_scan.put((self.base_url, 0))
        words = self.load_wordlist()
        self.total = len(words)
        self.processed = 0
        # launch worker threads
        for _ in range(int(self.settings.data['threads'])):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.threads.append(t)
        # monitor thread
        monitor = threading.Thread(target=self._monitor, daemon=True)
        monitor.start()

    def stop(self):
        self.running = False

    def worker(self):
        words = self.load_wordlist()
        while self.running:
            try:
                url, depth = self.to_scan.get(timeout=1)
            except queue.Empty:
                break
            if depth > int(self.settings.data['recursion_depth']):
                self.to_scan.task_done()
                continue
            for word in words:
                if not self.running:
                    break
                target = f"{url}/{word}" if not url.endswith('/') else f"{url}{word}"
                try:
                    resp = requests.get(target,
                                         timeout=float(self.settings.data['timeout']),
                                         allow_redirects=bool(self.settings.data['follow_redirects']),
                                         headers={'User-Agent': self.settings.data['user_agent']})
                except requests.RequestException:
                    self._update_progress()
                    continue
                code = resp.status_code
                cond = self.settings.data['include_status_codes']
                ok = False
                if cond.startswith('<') and code < int(cond[1:]): ok = True
                elif cond.startswith('<=') and code <= int(cond[2:]): ok = True
                elif cond.startswith('>') and code > int(cond[1:]): ok = True
                elif cond.startswith('>=') and code >= int(cond[2:]): ok = True
                elif ',' in cond:
                    if code in [int(x) for x in cond.split(',')]: ok = True
                if ok and target not in self.seen:
                    self.seen.add(target)
                    info = {'url': target, 'status': code, 'type': resp.headers.get('Content-Type','')}
                    self.on_found(info)
                    if 'text/html' in resp.headers.get('Content-Type',''):
                        self.to_scan.put((target, depth+1))
                self._update_progress()
            self.to_scan.task_done()

    def _update_progress(self):
        self.processed += 1
        self.on_progress((self.processed / max(self.total,1)) * 100)

    def _monitor(self):
        self.to_scan.join()
        for t in self.threads:
            t.join(timeout=0)
        self.running = False
        self.on_finish()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Recursive Dir Brute Forcer")
        self.geometry("900x650")
        self.settings = Settings()
        self.forcers = {}
        self.scan_count = 0
        self._build_header()
        self._build_notebook()

    def _build_header(self):
        header = ttk.Frame(self)
        header.pack(fill='x', pady=5)
        # logo
        try:
            img = Image.open('logo.png')
            self.update_idletasks()
            max_w = int(self.winfo_width()*0.1)
            ratio = max_w/img.width
            img = img.resize((max_w,int(img.height*ratio)),Image.ANTIALIAS)
            logo_img = ImageTk.PhotoImage(img)
            lbl = ttk.Label(header,image=logo_img)
            lbl.image=logo_img
            lbl.pack(side='left',padx=10)
        except:
            pass
        # links
        for text,url in [("Hackxpert Labs","https://labs.hackxpert.com/"),
                         ("X", "https://x.com/theXSSrat"),
                         ("Courses","https://thexssrat.com/")]:
            l = ttk.Label(header,text=text,foreground='blue',cursor='hand2')
            l.pack(side='right',padx=5)
            l.bind('<Button-1>',lambda e,u=url:webbrowser.open(u))
        self.progress=ttk.Progressbar(header,mode='determinate',length=200)
        self.progress.pack(side='right',padx=10)

    def _build_notebook(self):
        self.nb=ttk.Notebook(self)
        self.nb.pack(fill='both',expand=True)
        self.nb.bind('<Double-1>',self._rename_tab)
        self._build_instruct_tab()
        self._build_scan_tab()
        self._build_settings_tab()

    def _build_instruct_tab(self):
        f=ttk.Frame(self.nb);self.nb.add(f,text='Instructions')
        t=ScrolledText(f,wrap='word');t.pack(fill='both',expand=True,padx=10,pady=10)
        txt=("Combines brute-forcing and crawl: wfuzz only names, ZAP only links, this does both..." )
        t.insert('1.0',txt);t.configure(state='disabled')

    def _build_scan_tab(self):
        f=ttk.Frame(self.nb);self.nb.add(f,text='Scan')
        ttk.Label(f,text='Base URL:').grid(row=0,column=0,padx=5,pady=5)
        self.url= tk.StringVar();ttk.Entry(f,textvariable=self.url,width=60).grid(row=0,column=1)
        ttk.Label(f,text='Wordlist:').grid(row=1,column=0,padx=5)
        self.wl= tk.StringVar();ttk.Entry(f,textvariable=self.wl,width=50).grid(row=1,column=1)
        ttk.Button(f,text='Browse',command=self._browse).grid(row=1,column=2)
        ttk.Button(f,text='New Scan',command=self._new_scan).grid(row=2,column=1,pady=10)

    def _build_settings_tab(self):
        f=ttk.Frame(self.nb);self.nb.add(f,text='Settings')
        opts=[('Threads','threads'),('Timeout','timeout'),('UA','user_agent'),
              ('Depth','recursion_depth'),('Codes','include_status_codes'),('Exts','file_extensions')]
        for i,(lab,key) in enumerate(opts):
            ttk.Label(f,text=lab+':').grid(row=i,column=0,sticky='w',padx=5,pady=5)
            var=tk.StringVar(value=str(self.settings.data[key]))
            setattr(self,f'{key}_var',var)
            ttk.Entry(f,textvariable=var,width=30).grid(row=i,column=1)
        self.redir=tk.BooleanVar(value=self.settings.data['follow_redirects'])
        ttk.Checkbutton(f,text='Follow Redirects',variable=self.redir).grid(row=len(opts),column=1,sticky='w')
        ttk.Button(f,text='Save',command=self._save).grid(row=len(opts)+1,column=1,pady=10)

    def _browse(self):
        p=filedialog.askopenfilename(filetypes=[('TXT','*.txt'),('All','*')]);self.wl.set(p)

    def _new_scan(self):
        u,w=self.url.get(),self.wl.get()
        if not u or not w or not os.path.isfile(w):
            return messagebox.showerror('Err','URL or WL invalid')
        self.scan_count+=1
        tab=ttk.Frame(self.nb);self.nb.add(tab,text=f'Results {self.scan_count}')
        tree=ttk.Treeview(tab,columns=('url','status','type'),show='headings')
        for c in ('url','status','type'):tree.heading(c,text=c);tree.column(c,width=250)
        tree.pack(fill='both',expand=True)
        btnf=ttk.Frame(tab);btnf.pack(fill='x',pady=5)
        ttk.Button(btnf,text='CSV',command=lambda t=tree:self._exp_csv(t)).pack(side='left',padx=5)
        ttk.Button(btnf,text='JSON',command=lambda t=tree:self._exp_json(t)).pack(side='left')
        self.nb.select(tab)
        # update settings
        for key in ['threads','timeout','user_agent','recursion_depth','include_status_codes','file_extensions']:
            self.settings.data[key]=getattr(self,f'{key}_var').get()
        self.settings.data['follow_redirects']=self.redir.get()
        self.settings.save()
        # run
        fns=DirBruteForcer(u,w,self.settings,
            on_found=lambda i,tr=tree:tr.insert('','end',values=(i['url'],i['status'],i['type'])),
            on_finish=lambda:messagebox.showinfo('Done',f'Scan#{self.scan_count} done'),
            on_progress=lambda p:self.progress.configure(value=p)
        )
        self.forcers[self.scan_count]=fns;fns.start()

    def _save(self):
        for key in ['threads','timeout','user_agent','recursion_depth','include_status_codes','file_extensions']:
            self.settings.data[key]=getattr(self,f'{key}_var').get()
        self.settings.data['follow_redirects']=self.redir.get()
        self.settings.save();messagebox.showinfo('Saved','Settings saved')

    def _exp_csv(self,tree):
        f=filedialog.asksaveasfilename(defaultextension='.csv');
        if f:
            with open(f,'w')as fh:
                fh.write('URL,Status,Type\n')
                for r in tree.get_children():u,s,t=tree.item(r)['values'];fh.write(f'"{u}",{s},"{t}"\n')

    def _exp_json(self,tree):
        f=filedialog.asksaveasfilename(defaultextension='.json');
        if f:
            arr=[{'url':tree.item(r)['values'][0],'status':tree.item(r)['values'][1],'type':tree.item(r)['values'][2]}for r in tree.get_children()]
            with open(f,'w')as fh:json.dump(arr,fh,indent=2)

    def _rename_tab(self,event):
        if self.nb.identify(event.x,event.y)=='label':
            i=self.nb.index(f"@{event.x},{event.y}");old=self.nb.tab(i,'text')
            new=simpledialog.askstring('Rename',initialvalue=old)
            if new:self.nb.tab(i,text=new)

    def on_close(self):
        for f in self.forcers.values():f.stop()
        self.destroy()

def cli_mode():
    p=argparse.ArgumentParser()
    p.add_argument('--url',required=True)
    p.add_argument('--wordlist',required=True)
    p.add_argument('--threads',type=int)
    p.add_argument('--timeout',type=float)
    p.add_argument('--depth',type=int)
    p.add_argument('--codes',type=str)
    p.add_argument('--exts',type=str)
    p.add_argument('--no-redirect',action='store_true')
    p.add_argument('--output',required=True)
    p.add_argument('--format',choices=['csv','json'],default='json')
    args=p.parse_args()
    settings=Settings()
    for k,v in [('threads',args.threads),('timeout',args.timeout),('recursion_depth',args.depth),('include_status_codes',args.codes),('file_extensions',args.exts)]:
        if v is not None:settings.data[k]=v
    settings.data['follow_redirects']=not args.no_redirect
    results=[]
    done=threading.Event()
    def on_found(i):results.append(i)
    def on_finish():done.set()
    f=DirBruteForcer(args.url,args.wordlist,settings,on_found,on_finish)
    f.start()
    done.wait()
    if args.format=='json':
        with open(args.output,'w')as fh:json.dump(results,fh,indent=2)
    else:
        with open(args.output,'w')as fh:fh.write('URL,Status,Type\n')
        for i in results:fh.write(f'"{i["url"]}",{i["status"]},"{i["type"]}"\n')
    print(f"Saved {len(results)} entries to {args.output}")

if __name__=='__main__':
    import sys
    if '--cli' in sys.argv:
        cli_mode()
    else:
        app=App();app.protocol('WM_DELETE_WINDOW',app.on_close);app.mainloop()
