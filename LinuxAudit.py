#!/usr/bin/python

"""

The purpose of this program is to perform a security audit agasint various distributions of the Linux Operating System. Primarily, it analyzes configuration settings of the Pluggable Authentication Modules (PAM) mechanism.

Currently, this program has only been tested on:

[+] Ubuntu 14.04

"""

__author__      =           'Donald Whitfield'
__copyright__   =           '(c) 2019, S-Box Security'
__version__     =           '1.0.0'
__maintainer__  =           'Donald Whitfield'
__email__       =           'donaldwhitfield@icloud.com'
__status__      =           'Development'


import platform
import re
import sys
import time
import subprocess


SELINUX_CMD = 'getsebool -a'

req_version = (2,7)
cur_version = sys.version_info

if cur_version >= req_version:
    pass
else:
    print "Python Interpreter May Be Too Old"
    sys.exit()


print '\n'
print '\033[1mMachine Name:\033[1;m\t', platform.node()
print '\033[1mSystem:\033[1;m\t\t',     platform.system()
print '\033[1mRelease:\033[1;m\t',      platform.release()
print '\033[1mVersion:\033[1;m\t',      platform.version()
print '\033[1mProcessor:\033[1;m\t',    platform.processor()
print '\n' + '\n'



"""

MODULE ONE: Check to Determine If Password Complexity Check Is Enabled

"""

def check_cracklibobscurity():
    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("obscure", line):
                print "\033[1;32m[+] Password Complexity Check Is Enabled\033[1;m"
                found = True
                break
                #if not found:
                #print "\033[1;31mPassword Complexity Check Is Disabled\033[1;m"
        else:
            print "\033[1;31m[-] Not Enforced: Password Complexity Check Is Disabled\033[1;m"
time.sleep(2.5)
check_cracklibobscurity()



"""

MODULE TWO: Perform Check for Min Password Length Requirement

"""

def check_minpasswdlength():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("minlen", line):
                print "\033[1;32m[+] Minimum Password Length Set\033[1;m"
                found = True
                break
        else:
            print "\033[1;31m[-] Not Enforced: Minimum Password Length Not Set\033[1;m"
time.sleep(2.5)
check_minpasswdlength()




"""

MODULE THREE: Perform Check for Min Number of Lowercase Letters

"""

def check_lcredit():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("lcredit", line):
                print "\033[1;32m[+] Minimum Number of Required Lowercase Characters Defined\033[1;m"
                found = True

                #if not found:
        else:
            print "\033[1;31m[-] Not Enforced: Minimum Number of Required Lowercase Characters\033[1;m"
time.sleep(2.5)
check_lcredit()



"""

MODULE FOUR: Check for Min Number of Uppercase Letters

"""

def check_ucredit():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("ucredit", line):
                print "\033[1;32m[+] Minimum Number of Required Uppercase Characters Defined\033[1;m"
                found = True

                #if not found:
        else:
            print "\033[1;31m[-] Not Enforced: Minimum Number of Required Uppercase Characters\033[1;m"
time.sleep(2.5)
check_ucredit()



"""

MODULE FIVE: Checks for Min Number of Digits Used in Passwords

"""

def check_dcredit():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("dcredit", line):
                print "\033[1;32m[+] Minimum Number of Digits Defined\033[1;m"
                found = True

                #if not found:
        else:
            print "\033[1;31m[-] Not Enforced: Minimum Number of Digits\033[1;m"
time.sleep(2.5)
check_dcredit()



"""

MODULE SIX: Does Check for Special Characters in Passwords

"""

def check_ocredit():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("ocredit", line):
                print "\033[1;32m[+] Use of Special Characters Enforced\033[1;m"
                found = True

                #if not found:
        else:
            print "\033[1;31m[-] Not Enforced: Use of Special Characters\033[1;m"
time.sleep(2.5)
check_ocredit()



"""

MODULE SEVEN: Perform Check for Min Number of Lowercase Letters

"""

def check_difok():

    with open("/etc/pam.d/common-password") as pipe:
        found = False
        for line in pipe:
            if re.search("difok", line):
                print "\033[1;32m[+] Requires Min Number of Different Characters from Previous Password\033[1;m"
                found = True

                #if not found:
        else:
            print "\033[1;31m[-] Not Enforced: No Password Reuse Policy Defined\033[1;m"
time.sleep(2.5)
check_difok()



"""

MODULE EIGHT

"""

def check_selinux():

    subprocess.call(SELINUX_CMD)
check_selinux()

