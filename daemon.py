#!/usr/bin/env python3.10
# -*- coding: utf-8 -*-
# After upgrade python version from 3.8 to 3.10
# https://stackoverflow.com/questions/70596518/after-upgrading-python-to-3-10-pip-installed-modules-no-longer-work-correctly
# https://copyfuture.com/blogs-details/20210919142426315c
# #upgrading python version
# sudo add-apt-repository ppa:deadsnakes/ppa
# sudo apt-get update
# apt-get update
# apt list | grep python3.10
# sudo apt-get install python3.10
# sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
# sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 2
# sudo update-alternatives --config python3
# python3 --version
# # after upgrading
# sudo apt install python3-pip
# # 'apt_pkg'
# sudo apt-get remove python3-apt
# sudo apt-get install python3-apt
# # curl install
# sudo apt update
# sudo apt upgrade
# sudo apt install curl
# # psutil
# curl -sS https://bootstrap.pypa.io/get-pip.py | sudo python3
# pip install psutil
# # optional
# sudo apt-get install --reinstall python3.10-distutils
# # psutil
# pip install psutil -U
# sudo pip install --upgrade psutil
# # terminal not opening
# sudo apt-get --reinstall install python3-minimal
## make standalone exe file
# sudo apt-get install libpython3.10-dev
# pyinstaller --onefile daemon.py
from gettext import install
from ipaddress import ip_address
import pathlib
import socketserver
import sys
import os
import time
import psutil
import signal
import threading
import socket
import platform
import subprocess
import shlex
import uuid
import grp
import json
import logging
import pwd
import re
import struct
import getpass
import logging.handlers
from colorama import Fore, Back, Style


class Daemon(object):
    def __init__(self, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        """
        Usage: - create your own a subclass Daemon class and override the run() method. Run() will be periodically the calling inside the infinite run loop
            - you can receive reload signal from self.isReloadSignal and then you have to set back self.isReloadSignal = False
        """
        self.systemInfo = {}
        self.path = os.getcwd() + "/outputJsonFiles"
        self.syslogPath = self.path + "/syslogs"
        self.updatedSyslogPath = self.path + "/updatedSyslogs"
        self.logFilePath = [
            "/var/log/alternatives.log",
            "/var/log/apport.log",
            # "/var/log/auth.log",
            # "/var/log/bootstrap.log",
            # "/var/log/dmesg",
            # "/var/log/dpkg.log",
            # "/var/log/fontconfig.log",
            # "/var/log/gpu-manager.log",
            # "/var/log/kern.log",
            # "/var/log/syslog",
            # "/var/log/ubuntu-advantage-timer.log",
            # "/var/log/ufw.log",
            # "/home/lovely/Documents/somewhere/custom.log",
            "/home/lovely/Documents/something.log"
        ]
        self.ver = 0.1  # version
        # 0 means none pause between the calling of run() method.
        self.pauseRunLoop = 0
        # 0 means without a pause between stop and start during the restart of the daemon
        self.restartPause = 1
        # when terminate a process, wait until kill the process with SIGTERM signal
        self.waitToHardKill = 3
        self.isReloadSignal = False
        self._canDaemonRun = True
        self.processName = os.path.basename(sys.argv[0])
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.makeDir()

    def _sigterm_handler(self, signum, frame):
        self._canDaemonRun = False

    def _reload_handler(self, signum, frame):
        self.isReloadSignal = True

    def _makeDaemon(self):
        """
        Make a daemon, do double-fork magic.
        """
        try:
            pid = os.fork()
            if pid > 0:
                # Exit first parent.
                print(" Exit first parent.")
                sys.exit(0)
        except OSError as e:
            m = f"Fork #1 failed: {e}"
            print(m)
            sys.exit(1)
        # Decouple from the parent environment.
        os.chdir("/")
        os.setsid()
        os.umask(0)
        # Do second fork.
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent.
                print(" Exit from second parent.")
                sys.exit(0)
        except OSError as e:
            m = f"Fork #2 failed: {e}"
            print(m)
            sys.exit(1)
        m = "The daemon process is going to background."
        print(m)
        # Redirect standard file descriptors.
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    def _getProces(self):
        procs = []
        for p in psutil.process_iter():
            if self.processName in [part.split('/')[-1] for part in p.cmdline()]:
                # Skip  the current process
                if p.pid != os.getpid():
                    procs.append(p)
        return procs

    def getUidInfo(self):
        print(Fore.GREEN, "----------------UID Info---------------------|", Fore.WHITE)
        HostName = socket.gethostname()
        IpAddress = socket.gethostbyname(HostName)
        OsName = platform.system()
        OsVersion = platform.release()
        # Physicalinfo
        print("Host Name  :" + HostName)
        print("IP Address :" + IpAddress)
        print("OS Version :" + OsName, OsVersion)
        uidInfo = {}
        uidInfo["HostName"] = HostName
        uidInfo["IpAddress"] = IpAddress
        uidInfo["OSVersion"] = OsName + " " + OsVersion
        # Physicalinfo
        self.systemInfo["UIDInfo"] = uidInfo

    def getBiosInfo(self):
        print(Fore.GREEN, "----------------BIOS Info--------------------|", Fore.WHITE)
        # BIOS info
        biosInfo = {}
        print("Platform         :", platform.system())
        print("Platform-Release :", platform.release())
        print("Platform-Version :", platform.version())
        print("Architecture     :", platform.machine())
        print("Hostname         :", socket.gethostname())
        print("IP-Address       :", socket.gethostbyname(socket.gethostname()))
        print("MAC-Address      :",
              ':'.join(re.findall('..', '%012x' % uuid.getnode())))
        print("Processor        :", platform.processor())
        print("RAM              :", str(
            round(psutil.virtual_memory().total / (1024.0 ** 3)))+" GB")
        biosInfo['platform'] = platform.system()
        biosInfo['platform-release'] = platform.release()
        biosInfo['platform-version'] = platform.version()
        biosInfo['architecture'] = platform.machine()
        biosInfo['hostname'] = socket.gethostname()
        biosInfo['ip-address'] = socket.gethostbyname(socket.gethostname())
        biosInfo['mac-address'] = ':'.join(re.findall('..',
                                           '%012x' % uuid.getnode()))
        biosInfo['processor'] = platform.processor()
        biosInfo['ram'] = str(
            round(psutil.virtual_memory().total / (1024.0 ** 3)))+" GB"
        self.systemInfo["BIOSInfo"] = biosInfo

    def getDefaultIPGateway(self):
        print(Fore.GREEN, "----------------Default IP Gateway-----------|", Fore.WHITE)
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                print("Default IP Gateway : " +
                      socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
                defaultIpGateway = socket.inet_ntoa(
                    struct.pack("<L", int(fields[2], 16)))
        self.systemInfo["DefaultIPGateway"] = defaultIpGateway

    def getServiceInfo(self):
        print(Fore.GREEN, "----------------Service Info-----------------|", Fore.WHITE)
        serviceInfo = {}
        serviceInfo["List"] = []

        def show_services():
            return [(
                psutil.Process(p).name(),
                psutil.Process(p).status(),
            ) for p in psutil.pids()]
        i = 0
        for service in show_services():
            i = i+1
            # print("status : " + service[1] + " : Service Name : " + service[0])
            tempService = {}
            tempService["Status"] = service[1]
            tempService["ServiceName"] = service[0]
            serviceInfo["List"].append(tempService)
        print("Service Count : ", i)
        serviceInfo["Count"] = i
        self.systemInfo["ServiceInfo"] = serviceInfo

    def getActiveTcpInfo(self):
        print(Fore.GREEN, "----------------Active TCP Info--------------|", Fore.WHITE)
        activeTcpInfo = {}
        # Active TCP info
        # self.systemInfo["ActiveSystemInfo"] = activeTcpInfo

    def getProcessList(self):
        print(Fore.GREEN, "----------------Process List-----------------|", Fore.WHITE)
        processInfo = {}
        processInfo["List"] = []
        i = 0
        for process in psutil.process_iter():
            i = i + 1
            # print(process.pid, process.name())
            tempProcess = {}
            tempProcess["ProcessId"] = process.pid
            tempProcess["ProcessName"] = process.name()
            processInfo["List"].append(tempProcess)
        print("ProcessCount : ", i)
        processInfo["Count"] = i
        self.systemInfo["ProcessInfo"] = processInfo

    def getUserAccountsInfo(self):
        print(Fore.GREEN, "----------------User Accounts Info-----------|", Fore.WHITE)
        # for p in pwd.getpwall():
        #     print (p[0], "------", grp.getgrgid(p[3])[0])
        print("User Name : ", getpass.getuser())
        self.systemInfo["UserName"] = getpass.getuser()

    def getInstalledSoftwareInfo(self):
        print(Fore.GREEN, "----------------Installed Sofrware Info------|", Fore.WHITE)
        installedSoftwareInfo = {}
        cmd = ['apt', 'list', '--installed']
        software = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = software.communicate()
        # print(stdout.decode().replace('\t',' '))
        installedSoftwareInfo["List"] = stdout.decode().replace(
            '\t', ' ').split('\n')
        print("Installed Software Count : ",
              stdout.decode().replace('\t', ' ').count('\n')+1)
        installedSoftwareInfo["Count"] = stdout.decode().replace(
            '\t', ' ').count('\n')+1
        self.systemInfo["InstalledSoftwareInfo"] = installedSoftwareInfo

    def getFirewallInfo(self):
        print(Fore.GREEN, "----------------Firewall Info----------------|", Fore.WHITE)
        firewallInfo = {}
        # Firewall Info
        cmd = ['sudo', 'iptables', '-S']
        software = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = software.communicate()
        # print(stdout.decode().replace('\t',' '))
        firewallInfo["List"] = stdout.decode().replace('\t', ' ').split('\n')
        firewallInfo["Count"] = stdout.decode().replace(
            '\t', ' ').count('\n')+1
        print("Firewall Count : ", stdout.decode().replace(
            '\t', ' ').count('\n')+1)
        self.systemInfo["FirewallInfo"] = firewallInfo

    def getSystemInfo(self):
        # threading.Timer(4.0, self.getSystemInfo).start()
        print(Fore.YELLOW, "---------------------------------------------|", Fore.WHITE)
        self.getUidInfo()
        self.getBiosInfo()
        # self.getDefaultIPGateway()
        # self.getServiceInfo()
        # self.getActiveTcpInfo()
        self.getProcessList()
        self.getUserAccountsInfo()
        self.getInstalledSoftwareInfo()
        self.getFirewallInfo()
        file = self.path + "/SystemInfo.json"
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(self.systemInfo, f, ensure_ascii=False, indent=4)

    def getSystemLogs(self):
        print(Fore.RED, f"System Event Log", Fore.WHITE)
        tempLog = {}
        # cat /var/log/syslog | grep -w "\[system\]"
        sysLoG = subprocess.getoutput(
            'cat /var/log/syslog | grep -w "\[system\]"')
        print("Syslog Count :", sysLoG.count('\n')+1)
        tempLog["List"] = sysLoG.split('\n')
        tempLog["Count"] = sysLoG.count('\n')+1
        file = self.path + "/EventLog_System.json"
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(tempLog, f, ensure_ascii=False, indent=4)

    def getLogs(self, filePath):
        print(Fore.RED, f"Log file from {filePath}", Fore.WHITE)
        tempLog = {}
        sysLoG = subprocess.getoutput(f'cat {filePath}')
        print("Syslog Count :", sysLoG.count('\n')+1)
        tempLog["List"] = sysLoG.split('\n')
        tempLog["Count"] = sysLoG.count('\n')+1
        file = self.syslogPath + '/' + f'Log{filePath}.json'.replace('/', '_')
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(tempLog, f, ensure_ascii=False, indent=4)

    def dispCommand(self, cmd):
        print(Fore.GREEN, f"Custom Command \"{cmd}\"", Fore.WHITE)
        tempLog = {}
        sysLoG = subprocess.getoutput(cmd)
        print("Line Count :", sysLoG.count('\n')+1)
        tempLog["Lines"] = sysLoG.split('\n')
        tempLog["Count"] = sysLoG.count('\n')+1
        for line in tempLog["Lines"]:
            print("\t" + line)
        file = self.path + '/Custom_Command.json'
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(tempLog, f, ensure_ascii=False, indent=4)

    def getEventLogs(self):
        print(Fore.YELLOW, "---------------------------------------------|", Fore.WHITE)
        # https://www.sentinelone.com/blog/how-search-log-files-extract-data/
        self.getSystemLogs()
        for path in self.logFilePath:
            self.getLogs(path)

    def makeDir(self):
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        if not os.path.exists(self.syslogPath):
            os.mkdir(self.syslogPath)
        # if os.path.isdir(self.updatedSyslogPath) == False:
            # os.mkdir(self.updatedSyslogPath)

    def start(self):
        """
        Start daemon.
        """
        # Handle signals
        signal.signal(signal.SIGINT, self._sigterm_handler)
        signal.signal(signal.SIGTERM, self._sigterm_handler)
        signal.signal(signal.SIGHUP, self._reload_handler)
        # Check if the daemon is already running.
        procs = self._getProces()
        if procs:
            pids = ",".join([str(p.pid) for p in procs])
            m = f"Find a previous daemon processes with PIDs {pids}. Is not already the daemon running?"
            print(m)
            self.getSystemInfo()
            self.getEventLogs()
            # self.timing()
            # sys.exit(1)
            return
        else:
            m = f"Start the daemon version {self.ver}"
            print(m)
            self.getSystemInfo()
            self.getEventLogs()

        # Daemonize the main process
        self._makeDaemon()
        # Start a infinitive loop that periodically runs run() method
        self._infiniteLoop()

    def version(self):
        m = f"The daemon version {self.ver}"
        print(m)

    def status(self):
        """
        Get status of the daemon.
        """
        procs = self._getProces()
        if procs:
            pids = ",".join([str(p.pid) for p in procs])
            m = f"The daemon is running with PID {pids}."
            print(m)
        else:
            m = "The daemon is not running!"
            print(m)

    def reload(self):
        """
        Reload the daemon.
        """
        procs = self._getProces()
        if procs:
            for p in procs:
                os.kill(p.pid, signal.SIGHUP)
                m = f"Send SIGHUP signal into the daemon process with PID {p.pid}."
                print(m)
        else:
            m = "The daemon is not running!"
            print(m)

    def stop(self):
        """
        Stop the daemon.
        """
        procs = self._getProces()

        def on_terminate(process):
            m = f"The daemon process with PID {process.pid} has ended correctly."
            print(m)
        if procs:
            for p in procs:
                p.terminate()
            gone, alive = psutil.wait_procs(procs, timeout=self.waitToHardKill, callback=on_terminate)
            for p in alive:
                m = f"The daemon process with PID {p.pid} was killed with SIGTERM!"
                print(m)
                p.kill()
        else:
            m = "Cannot find some daemon process, I will do nothing."
            print(m)

    def restart(self):
        """
        Restart the daemon.
        """
        self.stop()
        if self.restartPause:
            time.sleep(self.restartPause)
        self.start()

    def _infiniteLoop(self):
        try:
            if self.pauseRunLoop:
                time.sleep(self.pauseRunLoop)
                while self._canDaemonRun:
                    self.run()
                    time.sleep(self.pauseRunLoop)
            else:
                while self._canDaemonRun:
                    self.run()
        except Exception as e:
            m = f"Run method failed: {e}"
            sys.stderr.write(m)
            sys.exit(1)
    # this method you have to override

    def run(self):
        cmd = "cd /home/lovely \n ls"
        self.dispCommand(cmd)
# ----------------------------------------------------------------------------------------------------
# an example of a custom run method where you can set your useful python code


# ----------------------------------------------------------------------------------------------------
# the main section
if __name__ == "__main__":
    daemon = Daemon()
    # Initialize IP address1 or IP address2
    if not os.path.exists("outputJsonFiles/IP_addresses.txt"):
        f = open("outputJsonFiles/IP_addresses.txt", "w+")
        f.close()
    ip_textfile = open("outputJsonFiles/IP_addresses.txt", "r")
    ip_address_list = ip_textfile.readlines()
    ip_textfile.close()
    if len(ip_address_list) == 0:
        ip_address1 = "127.0.0.1"
        ip_address2 = "127.0.0.2"
    elif len(ip_address_list) == 1:
        ip_address1 = ip_address_list[0].strip()
        ip_address2 = "127.0.0.2"
    else:
        ip_address1 = ip_address_list[0].strip()
        ip_address2 = ip_address_list[1].strip()
    while True:
        print("============================")
        print("| Red Squirrel Agent UI    |")
        print("+--------------------------+")
        print("| 1: Start Agent.          |")
        print("| 2: Stop Agent.           |")
        print("| 3: Settings.             |")
        print("| 4: Save and Exit.        |")
        print("| 5: Exit without Saving.  |")
        print("+--------------------------+")
        enterSelection = input(" Enter Selection: ")
        match enterSelection:
            case "1":
                print("[NOTICE] Starting Agent...")
                daemon.start()
            case "2":
                print("[NOTICE] Stopping Agent...")
                daemon.stop()
            case "3":
                while True:
                    print("+--------------------------+")
                    print("| Red Squirrel Agent UI    |")
                    print("+--------------------------+")
                    print("| 1: Server's IP address   |")
                    print("| 2: QA IP address         |")
                    print("| 3: Return                |")
                    print("+--------------------------+")
                    settingSelection = input(" Enter Selection: ")
                    match settingSelection:
                        case "1":
                            ip_address1 = input(" Server's IP address : ")
                        case "2":
                            ip_address2 = input(" QA IP address : ")
                        case "3":
                            break
                        case _:
                            print("[ERROR] Invalid input... Try Again...")
            case "4":
                print("[NOTICE] Saving and exiting program...")
                ip_textfile = open("outputJsonFiles/IP_addresses.txt", "w")
                n = ip_textfile.write(ip_address1 + "\n" + ip_address2)
                ip_textfile.close()
                break
            case "5":
                print("[NOTICE] Exiting program without saving...")
                break
            case _:
                print("[ERROR] Invalid input... Try Again...")
                print("ip_address1: ", ip_address1,
                      "\nip_address2: ", ip_address2)

    # usageMessage = f"Usage: {sys.argv[0]} (start|stop|restart|status|reload|version)"
    # if len(sys.argv) == 2:
    #     choice = sys.argv[1]
    #     if choice == "start":
    #         daemon.start()
    #     elif choice == "stop":
    #         daemon.stop()
    #     elif choice == "restart":
    #         daemon.restart()
    #     elif choice == "status":
    #         daemon.status()
    #     elif choice == "reload":
    #         daemon.reload()
    #     elif choice == "version":
    #         daemon.version()
    #     elif choice == "run":
    #         daemon.run()
    #     else:
    #         print("Unknown command.")
    #         print(usageMessage)
    #         sys.exit(1)
    #     sys.exit(0)
    # else:
    #     print(usageMessage)
    #     sys.exit(1)
