#!/usr/bin/python3

import sys
import argparse
import paramiko
import json
import yaml
import getpass
from .printcolours import PrintColours
from subprocess import (
    CalledProcessError,
    run,
)


def _run(cmd):
    """ Runs a command on local machine - equivalent to using Bash in terminal"""
    try:
        run(cmd, shell=True, check=True)
    
    except CalledProcessError:
        raise


def generate_key_pair():
    """
    Generates a new key pair locally saves in .ssh/ and copies it into the project directory
    """
    _run('ssh-keygen -f ~/.ssh/py_deploy')
    _run('cp ~/.ssh/py_deploy.pub ./public_keys/py_deploy.pub')

    with open('./public_keys/py_deploy.pub', 'r') as key_file:

        pub_key = key_file.read()

    return pub_key


class Deploy:
    """
    Automation tool for remote Linux system commands
    """
    DEFAULT_USER = "root"
    DEPLOYMENT_PATH = "./deployments/"

    def __init__(self, hosts, deploy_file, user=DEFAULT_USER):
        self.targets = []
        self.commands = dict()
        self.hostfile = "./hosts"
        self.hostfile_format = ""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.hosts = hosts
        self.get_hosts()
        self.commands_file = deploy_file
        self.user = user
        self.valid_hosts = []

    def get_host_file_format(self):
        """
        Check current directory for host file in either YAML or JSON format
        """
        try:
            open(self.hostfile + ".yaml", 'r')
            self.hostfile_format = ".yaml"
        
        except OSError:
            try:
                open(self.hostfile + ".yml", 'r')
                self.hostfile_format = ".yml"
            
            except OSError:
                try:
                    open(self.hostfile + ".json", 'r')
                    self.hostfile_format = ".json"
                
                except OSError:
                    print("No valid hosts file found - Accepted file format are YAML & JSON")

    def get_hosts(self):
        """
        Get all hosts from host file
        """
        self.get_host_file_format()

        try:
            with open(self.hostfile + self.hostfile_format) as file:

                if self.hostfile_format == ".json":
                    host_data = json.load(file)
                    self.targets = host_data[self.hosts]
                else:
                    host_data = yaml.safe_load(file)
                    self.targets = host_data[self.hosts]

        except:
            print("Error opening file")

    def new_conn(self, host, uname, pword=""):
        """
        Create new SSH connection with remote server
        """
        try:
            if pword:
                self.ssh.connect(host, port=22, username=uname, password=pword)
                self.ask_to_generate_key_pair()
            else:
                self.ssh.connect(host, port=22, username=uname)

        except paramiko.ssh_exception.SSHException:
            print(f"{PrintColours.FAIL}[{host}][{self.hosts}] - FAILED - Please setup SSH keys this host"
                  f"{PrintColours.ENDC}")

            new_user, new_pass = self.ask_manual_auth()

            if new_user:
                self.new_conn(host, new_user, new_pass)
            else:
                print(f"{PrintColours.FAIL}[{host}][{self.hosts}] - FAILED - Please setup SSH keys this host"
                      f"{PrintColours.ENDC}")
                sys.exit()

    def close_conn(self):
        """
        Close SSH connection to remote server
        """
        self.ssh.close()

    def valid_host(self):
        """
        Checks each host for ssh connection validity & a Linux OS is present
        """
        for host in self.targets:
            try:
                self.new_conn(host, self.user)

                stdin, stdout, stderr = self.ssh.exec_command("uname -s")
                output = [line for line in stdout]
                self.valid_hosts.append(host)

                if str(output).find("Linux"):
                    print(f"{PrintColours.OKGREEN}[{host}][{self.hosts}] - OK - valid Linux host{PrintColours.ENDC}")
                else:
                    print(f"{PrintColours.FAIL}[{host}][{self.hosts}] - FAILED - only Linux is supported"
                          f"{PrintColours.ENDC}")

                self.close_conn()

            except paramiko.ssh_exception.SSHException:

                ask_user, ask_pass = self.ask_manual_auth()

                if ask_user:
                    self.new_conn(host, ask_user, ask_pass)

                else:
                    print(f"{PrintColours.FAIL}[{host}][{self.hosts}] - FAILED - Please setup SSH keys this host"
                          f"{PrintColours.ENDC}")
                    sys.exit()

    def ask_manual_auth(self):
        """
        If SSH key authentication fails this function is called to ask for username & password instead and offers
        to generate a key pair and place the necessary key on the remote server.
        """
        user = ""
        passwd = ""
        man_auth = input("Would you like to authenticate with username & password? (Y/N) ")
        if man_auth.upper() == "Y" or man_auth.upper() == "YES":
            user = input("Enter username: ")
            passwd = getpass.getpass("Enter password: ")

        return user, passwd

    def ask_to_generate_key_pair(self):
        """
        Check whether user would like to generate a key pair and share with the remote server
        If yes, call generate_key_pair and subsequently pass_key_paid_to_remote to put in place.
        """
        key_pair = input("Would you like to generate & add a key pair for this host? (Y/N) ")

        if key_pair.upper() == "Y" or key_pair.upper() == "YES":

            self.pass_key_pair_to_remote()

        else:
            pass

    def pass_key_pair_to_remote(self):
        """
        Calls new_conn and then copies the public key to authorised keys directory in .ssh/
        """

        new_key = generate_key_pair()

        stdin, stdout, stderr = self.ssh.exec_command(f'"echo {new_key}" >> ~/.ssh/authorized_hosts')
        output = [line for line in stdout]
        errors = [line for line in stderr]
        print(output)
        print(errors)

        return

    def get_commands(self):
        """
        Collect commands from deployment file
        """
        with open(self.DEPLOYMENT_PATH + self.commands_file, 'r') as file:
            self.commands = yaml.safe_load(file)

    def run_commands(self):
        """
        Run the collected commands against the specified hosts
        """
        self.valid_host()
        self.get_commands()

        for host in self.targets:
            try:
                
                if host in self.valid_hosts:
                    self.ssh.connect(host, username=self.user)

                    for cmd in self.commands:
                        std_output = []
                        err_output = []
                        stdin, stdout, stderr = self.ssh.exec_command(self.commands[cmd])
                        std_output = [str(line).strip('\n') for line in stdout]
                        err_output = [str(line).strip('\n') for line in stderr]

                        # Print message dependent on the outcome of each command
                        if not std_output:
                            print(f"{PrintColours.FAIL}[{host}][{self.hosts}] - FAILED - {self.commands[cmd]}"
                                f" - {err_output[-1]}")

                        elif str(err_output).find("WARNING: apt"):
                            print(f"{PrintColours.WARNING}[{host}][{self.hosts}] - OK - {self.commands[cmd]}"
                                f" - (minor error - APT CLI warning){PrintColours.ENDC}")

                        else:
                            print(f"{PrintColours.OKGREEN}[{host}][{self.hosts}] - OK - {self.commands[cmd]}")

                    self.close_conn()

                else:
                    print(f"{PrintColours.FAIL}Skipping [{host}][{self.hosts}] as not a valid host.")

            except:
                print("Unknown Error - Please review your host & deployment files")


# Check for command line arguments and parse accordingly
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-u', '--user', help='Specify remote username if not root', type=str, required=False)
    parser.add_argument('-g', '--hostgroup', help='Key to use from hosts file', type=str, required=True)
    parser.add_argument('-d', '--deployment', help='Deployment yaml file to use', type=str, required=True)

    args = parser.parse_args()

    hostgroup = args.hostgroup
    deployment = args.deployment

    if args.user:
        arg_user = args.user
        new_deployment = Deploy(hostgroup, deployment, arg_user)

    else:
        new_deployment = Deploy(hostgroup, deployment)

    new_deployment.run_commands()
