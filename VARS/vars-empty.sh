#!/bin/bash
######## tested on Ubuntu 18.04 Server
#"Host1"
HostName=""
#"user@example.com"
AdminMail=""
#"MyCompanyName"
Company=""
# "Europe/Moscow" 
Timezone="" 
# NTP Server "10.0.0.1"
NtpServer=""
#Send logs to "10.0.0.2"
Syslog=""
#Port "514"
SyslogPort=""
#When to reboot the server on updates "05:00"
UntupgrAutoRebootTime=""
#"your.smtpserver.com"
SMTPServer=""
#Port "587"
SMTPServerPort=""
#Smtp server masqarad FQDN "server.mycompany.com"
ExtFQDN=""
myDestination="$HostName@$Company.local, $ExtFQDN, $HostName, localhost.localdomain, localhost" 
#SMTP User and Pass
SMTPUser=""
SMTPPass=""

#Add tasks. This is task block with number
#Task1Comment=" - Reboot every sat at 3:00"
#Task1time="0 3 * * 6"
#Task1="sudo sh -c '/bin/date>>/var/log/reboot.log && uptime>>/var/log/reboot.log && /sbin/reboot'"
Task1Comment=""
Task1time=""
Task1=""
# Docker stack user
dockerUser=""
# prefix for testing in different path`s ""
rootpath=""

#Config files locations "/etc/ssh/sshd_config" and etc. defaults for Ubuntu 18.04
sshdfile="/etc/ssh/sshd_config"                    
sysctlfile="/etc/sysctl.conf"                      
grubfile="/etc/default/grub"                       
usbfile="/etc/modprobe.d/disable-usb-storage.conf" 
firewirefile="/etc/modprobe.d/firewire.conf"       
thunderboltfile="/etc/modprobe.d/thunderbolt.conf" 
rkhunterfile="/etc/rkhunter.conf"
unattendedupgrades="/etc/apt/apt.conf.d/50unattended-upgrades"
syslogfile="/etc/rsyslog.conf"
mailfile="/etc/postfix/main.cf"

# Tab count to use before strings in config files
FirstLevel=1
SecondLevel=2

