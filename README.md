# Ansible with OnCommand API Services

This repository contains Ansible modules and sample playbooks which enables you to configure NetApp element based storage management using NetApp OnCommand API Services. Ansible behaves as the orchestrator tool.

# Disclaimer
These Ansible modules and sample playbooks are written as best effort and provide no warranties or SLAs, expressed or implied.

# Repository includes:
1. Ansible OnCommand API Services Modules
2.	Sample Playbooks
3.	README
 
# Supported configurations:
1.	Control server distros: RHEL 7.x CentOS 7.x
2.	OnCommand API Services - 2.0 RC1
3.	Minimum ONTAP version - ONTAP 9.x

# Overview
These Ansible modules enables you to configure NetApp element based storage management using NetApp OnCommand API Services.

These modules can be downloaded on your ansible server using the configuration steps below. Once these modules are configured, they can be used in custom written playbook according to specific use cases or requirements.
The functionality of these modules is to act as an interface between Ansible and OnCommand API Services. With these modules the commands given at the Ansible server will be translated to RESTful api calls to OnCommand API Services and communicated back.


# Configuration

1. Get a working Ansible Setup (rhel-7 or centos-7)
2. Get a working OnCommand API Services setup
3. Sign-in as root at the Ansible Master machine and the Ansible Slave servers
4. Edit the ansible.cfg file to edit the ansible modules library folder. Run command: vi /etc/ansible/ansible.cfg
5. Find the commented line for library default value. Remove the # sign from start of the line. Edit it to library = /root/modules
6. At the Ansible server, sign-in with root privileges
7. Create a new directory. Command: mkdir modules
8. Run Command: cd modules
9. Run Command: pwd
10. Verify that the output is "/root/modules"
11. Now download all the modules from ‘modules/OnCommand API Services’ inside "/root/modules"(download these modules to either Master Ansible server or the Slave Ansible servers)
12. Install 'requests' python package pip install requests
13. Make use of sample playbooks provided to get started

# Related Project

Ansible with NetApp Service Level for service level based NetApp storage management. Look https://github.com/NetApp/Ansible-with-NetApp-Service-Level-Manager/

# Support
Please enter an issue if you would like to report a defect
