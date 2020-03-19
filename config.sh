#!/bin/bash
source /home/alex/scripts/general.sh

clear

HostName="Host1"
AdminMail="ivanovv@advocate-upt.com"
Company="AB"

FirstLevel=1
SecondLevel=2

rootpath=""

sshdfile="/etc/ssh/sshd_config"#"sshd_config" 
sysctlfile="/etc/sysctl.conf"#"sysctl.conf"
grubfile="/etc/default/grub"#"grub"
usbfile="/etc/modprobe.d/disable-usb-storage.conf"#"disable-usb-storage.conf"
firewirefile="/etc/modprobe.d/firewire.conf"#"firewire.conf"
thunderboltfile="/etc/modprobe.d/thunderbolt.conf"#"thunderbolt.conf"
rkhunterfile="/etc/rkhunter.conf"

echo "Ubuntu 18.04 config started..."
	echo "Packets update..."
	echo "========================================================================================"
		sudo apt-get update && apt-get upgrade -y
	echo ""
	sleep 2s
	echo "Time zone and Locale Configuring..."
	echo "========================================================================================"
		sudo ln -fs /usr/share/zoneinfo/Europe/Moscow /etc/localtime \
    	&& dpkg-reconfigure -f noninteractive tzdata
		sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    	&& locale-gen
	echo ""
	sleep 2s
	echo "SSHD Configuring..."
	echo "========================================================================================"
		file=$rootpath$sshdfile
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
	echo ""
	sleep 2s
	echo "KERNEL Configuring..."
	echo "========================================================================================"
		file=$rootpath$sysctlfile
		AddOrReplaceParamInFile "# Turn on execshield" ""  $file
		AddOrReplaceParamInFile "kernel.exec-shield" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "kernel.randomize_va_space" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Enable IP spoofing protection" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.rp_filter" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Disable IP source routing" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.accept_source_route" "=0"  $file $FirstLevel
		AddOrReplaceParamInFile "# Ignoring broadcasts request" ""  $file
		AddOrReplaceParamInFile "net.ipv4.icmp_echo_ignore_broadcasts" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "net.ipv4.icmp_ignore_bogus_error_messages" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Make sure spoofed packets get logged" ""  $file
		AddOrReplaceParamInFile "net.ipv4.conf.all.log_martians" "=1"  $file $FirstLevel
		AddOrReplaceParamInFile "# Anti TCP syn ddos" ""  $file
		AddOrReplaceParamInFile "net.ipv4.tcp_syncookies" "=1"  $file $FirstLevel
		RemoveEmptyStrings $file
	echo ""
	sleep 2s
	echo "Disable IPV6..."
	echo "========================================================================================"
		file=$rootpath$grubfile
		AddOrReplaceParamInFile "# Disable IPV6" ""  $file
		AddOrReplaceParamInFile "GRUB_CMDLINE_LINUX_DEFAULT=" '"ipv6.disable=1"'  $file $FirstLevel
		AddOrReplaceParamInFile "GRUB_CMDLINE_LINUX=" '"ipv6.disable=1"'  $file $FirstLevel
		RemoveEmptyStrings $file	
	echo ""
	sleep 2s
	echo "Disable USB/firewire/thunderbolt devices..."
	echo "========================================================================================"
		file=$rootpath$usbfile
		AddOrReplaceParamInFile "# Disable USB devices" ""  $file
		AddOrReplaceParamInFile "install usb-storage " "/bin/true"  $file $FirstLevel
		RemoveEmptyStrings $file

		file=$rootpath$firewirefile
		AddOrReplaceParamInFile "# Disable firewire devices" ""  $file
		AddOrReplaceParamInFile "blacklist firewire-core" ""  $file $FirstLevel
		RemoveEmptyStrings $file

		file=$rootpath$thunderboltfile
		AddOrReplaceParamInFile "# Disable thunderbolt devices" ""  $file
		AddOrReplaceParamInFile "blacklist thunderbolt" ""  $file $FirstLevel
		RemoveEmptyStrings $file
	echo ""
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
		AddOrReplaceParamInFile "UPDATE_MIRRORS=" "1"  $file $FirstLevel
        AddOrReplaceParamInFile "MIRRORS_MODE=" "0"  $file $FirstLevel
        AddOrReplaceParamInFile "/'WEB_CMD=" "/"/"/'"  $file $FirstLevel
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
	echo "Script complited!"