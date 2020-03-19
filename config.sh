#!/bin/bash

source ./general.sh
source ./vars.sh

clear

echo "Ubuntu 18.04 config started..."
echo "Set hostname..."
echo "========================================================================================"
sudo hostnamectl set-hostname $HostName
echo $HostName
echo ""
echo "Set NTP server..."
echo "========================================================================================"
echo "NTP=$NtpServer" >> /etc/systemd/timesyncd.conf
echo $NtpServer
timedatectl set-ntp true
service systemd-timesyncd  restart
service systemd-timesyncd status
sleep 5s
echo ""
echo "Packets update..."
echo "========================================================================================"
	sudo apt-get update && apt-get upgrade -y
echo ""
sleep 2s
echo "Time zone and Locale Configuring..."
echo "========================================================================================"
	sudo ln -fs /usr/share/zoneinfo/$Timezone /etc/localtime \
	&& dpkg-reconfigure -f noninteractive tzdata
	sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
	&& locale-gen
echo ""
sleep 2s
echo "SSHD Configuring..."
echo "========================================================================================"
	file=$rootpath$sshdfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Disable root login for ssh" "" $file 
		AddOrReplaceParamInFile "PermitRootLogin " "no"  $file $FirstLevel
		AddOrReplaceParamInFile "ChallengeResponseAuthentication " "no" $file $FirstLevel
		AddOrReplaceParamInFile "PasswordAuthentication " "no"  $file $FirstLevel
		AddOrReplaceParamInFile "# Disable password based login" "" $file
		AddOrReplaceParamInFile "AuthenticationMethods " "publickey"   $file $FirstLevel
		AddOrReplaceParamInFile "PubkeyAuthentication " "yes"  $file $FirstLevel
		AddOrReplaceParamInFile "# Limit Users’ ssh access" "" $file
		AddOrReplaceParamInFile "AllowUsers " "alex" $file $FirstLevel
		AddOrReplaceParamInFile "# Disable Empty Passwords" "" $file
		AddOrReplaceParamInFile "PermitEmptyPasswords " "no" $file $FirstLevel
		AddOrReplaceParamInFile "# Configure idle log out timeout interval" "" $file
		AddOrReplaceParamInFile "ClientAliveInterval " "3000" $file $FirstLevel
		AddOrReplaceParamInFile "ClientAliveCountMax " "0" $file $FirstLevel
		AddOrReplaceParamInFile "# Disable .rhosts files (verification)" "" $file
		AddOrReplaceParamInFile "IgnoreRhosts " "yes" $file $FirstLevel
		AddOrReplaceParamInFile "# Disable host-based authentication (verification)" "" $file
		AddOrReplaceParamInFile "HostbasedAuthentication " "no" $file $FirstLevel
		AddOrReplaceParamInFile "# Supported HostKey algorithms by order of preference" "" $file
		AddOrReplaceParamInFile "HostKey /etc/ssh/ssh_host_ed25519_key" "" $file $FirstLevel
		AddOrReplaceParamInFile "HostKey /etc/ssh/ssh_host_rsa_key" "" $file $FirstLevel
		AddOrReplaceParamInFile "HostKey /etc/ssh/ssh_host_ecdsa_key" "" $file $FirstLevel
		AddOrReplaceParamInFile "# Specifies the available KEX (Key Exchange) algorithms." "" $file
		AddOrReplaceParamInFile "KexAlgorithms " "curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" $file $FirstLevel
		AddOrReplaceParamInFile "# Specifies the ciphers allowed" "" $file
		AddOrReplaceParamInFile "Ciphers " "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" $file $FirstLevel
		AddOrReplaceParamInFile "# Specifies the available MAC (message authentication code) algorithms" "" $file
		AddOrReplaceParamInFile "MACs " "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" $file $FirstLevel
		AddOrReplaceParamInFile "# LogLevel VERBOSE logs users key fingerprint on login. Needed to have a clear audit track of which key was using to log in." "" $file
		AddOrReplaceParamInFile "LogLevel " "VERBOSE" $file $FirstLevel
		AddOrReplaceParamInFile "# Log sftp level file access" "" $file
		AddOrReplaceParamInFile "Subsystem sftp " "/usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO" $file $FirstLevel
		AddOrReplaceParamInFile "# Enable only Ipv4" "" $file
		AddOrReplaceParamInFile "ListenAddress " "0.0.0.0" $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi	
echo ""
sleep 2s
echo "KERNEL Configuring..."
echo "========================================================================================"
	file=$rootpath$sysctlfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Turn on execshield" ""  $file
		#AddOrReplaceParamInFile "kernel.exec-shield" "=1"  $file $FirstLevel #options turned off in Ubuntu 18
		AddOrReplaceParamInFile "kernel.randomize_va_space" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Enable IP spoofing protection" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.rp_filter" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Disable IP source routing" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.accept_source_route" "=0"  $file $FirstLevel
		AddOrReplaceParamInFile "# Ignoring broadcasts request" ""  $file
		AddOrReplaceParamInFile "net.ipv4.icmp_echo_ignore_broadcasts" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "net.ipv4.icmp_ignore_bogus_error_responses" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Make sure spoofed packets get logged" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.log_martians" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Anti TCP syn ddos" ""  $file
		AddOrReplaceParamInFile "net.ipv4.tcp_syncookies" "=1"  $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi
echo ""
sleep 2s
echo "Disable IPV6..."
echo "========================================================================================"
	file=$rootpath$grubfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Disable IPV6" ""  $file
		AddOrReplaceParamInFile "GRUB_CMDLINE_LINUX_DEFAULT=" '"ipv6.disable=1"'  $file $FirstLevel
		AddOrReplaceParamInFile "GRUB_CMDLINE_LINUX=" '"ipv6.disable=1"'  $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi	
echo ""
sleep 2s
echo "Disable USB/firewire/thunderbolt devices..."
echo "========================================================================================"
	file=$rootpath$usbfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Disable USB devices" ""  $file
		AddOrReplaceParamInFile "install usb-storage " "/bin/true"  $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi

	file=$rootpath$firewirefile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Disable firewire devices" ""  $file
		AddOrReplaceParamInFile "blacklist firewire-core" ""  $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi

	file=$rootpath$thunderboltfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "# Disable thunderbolt devices" ""  $file
		AddOrReplaceParamInFile "blacklist thunderbolt" ""  $file $FirstLevel
		RemoveEmptyStrings $file
	else
        echo "file $file - NOT exist!!!!"
    fi
echo ""
echo "Config Mail..."
echo "========================================================================================"	
	file=$rootpath$mailfile
	if [ -n $SMTPServer ]; then
		if [ -f $file ]; then
		 	true
		else
			touch $file
		fi

		if [ -f $file ]; then
			echo "file $file - exist!"
			AddOrReplaceParamInFile "myhostname = " "$ExtFQDN"  $file
			AddOrReplaceParamInFile "mydestination = " "$myDestination"  $file	
			AddOrReplaceParamInFile "# Enable auth" ""  $file
			AddOrReplaceParamInFile "smtp_sasl_auth_enable = " "yes"  $file	
			AddOrReplaceParamInFile "# Set username and password" ""  $file	
			AddOrReplaceParamInFile "smtp_sasl_password_maps = " "static:$SMTPUser:$SMTPPass"  $file	
			AddOrReplaceParamInFile "smtp_sasl_security_options = " "noanonymous"  $file	
			AddOrReplaceParamInFile "# Turn on tls encryption" ""  $file
			AddOrReplaceParamInFile "smtp_tls_security_level = " "encrypt"  $file
			AddOrReplaceParamInFile "header_size_limit = " "4096000"  $file
			AddOrReplaceParamInFile "# Set external SMTP relay host here IP or hostname accepted along with a port number." ""  $file
			AddOrReplaceParamInFile "relayhost = " "[$SMTPServer]:$SMTPServerPort"  $file
			AddOrReplaceParamInFile "# accept email from our server only" ""  $file
			AddOrReplaceParamInFile "inet_interfaces = " "127.0.0.1"  $file	
			RemoveEmptyStrings $file
		fi
		sudo service postfix restart
		sudo service postfix status
		netstat -tulpn | grep :25
		echo "This is a test email body." | mail -s "Test email" -a "From: $SMTPUser" $AdminMail
		sudo tail /var/log/mail.log
		sleep 5s
	fi
echo ""
echo "Config Syslog..."
echo "========================================================================================"	
	file=$rootpath$syslogfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "*.Warning @$Syslog:$SyslogPort" ""  $file		
		RemoveEmptyStrings $file
		sudo service rsyslog restart
		#sudo service rsyslog status
	else
        echo "file $file - NOT exist!!!!"
    fi	
echo ""
echo "Config Unattended-Upgrades..."
echo "========================================================================================"
	file=$rootpath$unattendedupgrades
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "Unattended-Upgrade::MinimalSteps " '"false";'  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::InstallOnShutdown " '"false";'  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::Mail " "\"$AdminMail\";"  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::Remove-Unused-Kernel-Packages " '"true";'  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::Remove-Unused-Dependencies " '"true";'  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::Automatic-Reboot-Time " '"05:00";'  $file
		AddOrReplaceParamInFile "Unattended-Upgrade::Remove-Unused-Dependencies " '"true";'  $file
		if [ -n $Syslog ]; then
			AddOrReplaceParamInFile "Unattended-Upgrade::SyslogEnable " '"true";'  $file
		fi
		RemoveEmptyStrings $file
		unattended-upgrade -v --dry-run
	else
        echo "file $file - NOT exist!!!!"
    fi	
echo ""
sleep 2s
echo "Remove boot delay..."
echo "========================================================================================"
	#sudo systemctl edit --full systemd-networkd-wait-online.service
	#ExecStart=/lib/systemd/systemd-networkd-wait-online --timeout 1
echo ""
	sleep 2s
echo "Install RKHunter IDS..."
echo "========================================================================================"
	sudo apt-get install rkhunter -y
	sleep 20s
	file=$rootpath$rkhunterfile
	if [ -f $file ]; then
        echo "file $file - exist!"
		AddOrReplaceParamInFile "UPDATE_MIRRORS=" "1"  $file $FirstLevel
		AddOrReplaceParamInFile "MIRRORS_MODE=" "0"  $file $FirstLevel
		AddOrReplaceParamInFile "/'WEB_CMD=" "/"/"/'"  $file $FirstLevel
	else
        echo "file $file - NOT exist!!!!"
    fi
	#echo 'WEB_CMD=""' >> /etc/rkhunter.conf
	sudo rkhunter --check --sk
	sudo rkhunter --update
echo ""
	sleep 2s
echo "Installing Fail2ban..."
echo "========================================================================================"
	sudo apt-get install fail2ban -y	
echo ""
echo "Remove unused packages..."
echo "========================================================================================"
	sudo apt autoremove -y
echo ""
echo "Add scheduled tasks..."
echo "========================================================================================"
	#write out current crontab
	file="/tmp/mycron"
	sudo crontab -l > $file
	#echo new cron into cron file
echo " - Reboot every sat at 3:00"   
	AddOrReplaceParamInFile "0 3 * * 6 sudo sh -c '/bin/date>>/var/log/reboot.log && uptime>>/var/log/reboot.log && /sbin/reboot'" ""  $file $FirstLevel
echo " - Update rkhunter every night at 2:30"     
	AddOrReplaceParamInFile "30 2 * * * sudo sh -c '/usr/bin/rkhunter --update>>/var/log/rkhunter-upd.log'" ""  $file $FirstLevel
echo " - Run rkhunter every night at 2:40"     
	AddOrReplaceParamInFile "40 2 * * * sudo sh -c '/usr/bin/rkhunter'" ""  $file $FirstLevel
echo " - Send rkhunter logs every night at 2:55"
	AddOrReplaceParamInFile "55 2 * * 7 grep -e 'Warning' -e 'Error' -e 'Fail' /var/log/rkhunter.log | mail -s '$Company RKHunter' -a 'From: RKHunter@$HostName.$Company.local' $AdminMail" ""  $file $FirstLevel    
	#install new cron file
	sudo crontab $file
	sudo rm $file

echo "Check config files..."
echo "========================================================================================"
CheckResult="/opt/projects/scripts/CheckResult.txt"

file=$rootpath$sshdfile
CorrectAction="service sshd restart"
CheckConfigFile "sshd -t -f $file" $file $CheckResult "$CorrectAction"

echo ""
file=$rootpath$sysctlfile
CheckConfigFile "sysctl -p $file | grep 'sysctl:'" $file $CheckResult

rm $CheckResult

echo ""
echo "Script complited!"
read -p "Reboot the system now? [Y/N]" answer
case $answer in
   [yY]* ) sudo reboot;;

   [nN]* ) exit;;

   * )     exit;;
esac