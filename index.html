>       42

#       Born2Reboot

#INDEX
------
##  Help
##  Post-it
##  Roadmap
###     VM
###     Install
###     Partitioning
###     Comfort
###     Sudoers
###     UFW (Uncomplicated Firewall)
###     SSH Daemon
###     SSH Connection
###     Password Policy
###     Update Passwords
###     Groups and Users
###     Crontab Monitoring
##  LLMP
###     Lighttpd
###     MariaDB
###     PHP
###     WP
###     IPFS

##  Help
->`Select/Click -able`
> **definition**
> precision.
<variable_placeholder>
`$ user command`
`# root command`
`> plain text`
https://www.external_link

##  Post-it

* Services:

List services:
    # service --status-all
List running services:
    # systemctl status
List all services status:
    # systemctl

* Networking:

List currently used ports:
    $ ss -tunlp
Find which services use <port>:
    $ ss -tulp
List of ports and their default usage:
    $ vi /etc/services

* Errors:

Fix the startup error `*ERROR* Failed to send host log message.`:
    # /etc/default/grub
    > GRUB_CMDLINE_LINUX_DEFAULT="quiet nomodeset"
    # update-grub

* Misc:

Display who is logged in and what they are doing:
    $ w

Check updates:
    $ apt update
    $ apt upgrade
    $ apt dist-upgrade
    $ apt autoremove

Cycle ttys:
    Alt + Left/Right
    Ctrl + Alt + <f1_to_f6>

Changes the hostname:
    # hostnamectl set-hostname <new_name>
Edit '/etc/hosts':
    # vi /etc/hosts
    > 127.0.0.1   localhost
    > 127.0.0.1   <new_name>
    # reboot
Check the current hostname:
    $ hostnamectl

##  Roadmap

###     VM

Download VirtualBox
Download Debian latest stable release:
https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/

 VirtualBox ->`New`
 Name: `debian-server`
 Machine Folder: `somewhere`
 Version: `Debian (64-bit)`
 ->`Continue`
    1024 MB
 ->`Continue`
    8 GB
    VDI (VirtualBox Disk Image)
    Dynamically allocated
 ->`Create`

 VirtualBox ->`Settings` ->`Storage`
 `Controller: IDE` ->💿 `Empty`
 `Optical Drive:` ->💿
    debian-11.1.0-amd64-netinst.iso
 ->`OK`

 VirtualBox ->`Start`

Be able to use CMD-TAB switch between host and VM windows:
 VirtualBox ->`Input` ->`Keyboard/Keyboard Settings`
 `Auto Capture Keyboard` `OFF`

Screen size:
 VirtualBox ->`View` ->`Virtual Screen`: 200%

###     Install

 ->`Install`
 Hostname: `cvidon42`
 Domain name:
 Root password: `toor`
 Full name for the new user: `clement`
 Username for your account: `cvidon`
 Choose a password for the new user: `resu`
 Select your time zone: `Central`

###     Partitioning

-----[SIMPLE]-----

 Partitioning method: `…encrypted LVM`
 Partitioning scheme: `Separate /home partition`
 Encryption passphrase: `ksid`
 Amount of volume group to use for guided partitioning: `max`
 Finish partitioning:
 ->`#1` ->`4.0 GB` ->`ext4 /home`
 ->`#2` ->`3.0 GB` ->`ext4 /`
 ->`#3` ->`1.0 GB` ->`swap swap`

-----[ADVANCED]------

Partitioning method: `Manual`
 ->`SCSI1 (0,0,0) (sda) - 8.6 GB ATA VBOX HARDDISK`

Create `/boot` *primary partition*:
> Bootable partition that it contains the operating system.
 ->`FREE SPACE` ->`Create a new partition`
 New partition size: `500M`
 ->`Primary` ->`Beginning`
 Mount point: `/boot`
 ->`Done setting up the partition`

Set the rest as *logical partition* (LPAR):
> Portion of a computer's hardware that is set aside and virtualised
> as an additional computer.
 ->`FREE SPACE` ->`Create a new partition`
 New partition size: `max` ->`Logical` ->`Beginning`
 Mount point: `Do not mount it` ->`Done setting up the partition`

Encrypt it:
 ->`Configure encrypted volumes` ->`Create encrypted volumes`
 -> 2nd partition (the bigger one) ->`Done setting up the partition`
 ->`Finish`
 Encryption passphrase: `ksid`

Create the logical partitions:
 ->`Configure the Logical Volume Manager` ->`Create volume group`
 Volume group name: `LVMGroup`
 -> 1st partition (the bigger one) ->`Done setting up the partition`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `root`
 Logical volume size: `2G`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `swap`
 Logical volume size: `1024M`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `home`
 Logical volume size: `1G`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `var`
 Logical volume size: `1G`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `srv`
 Logical volume size: `1G`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `tmp`
 Logical volume size: `1G`

 ->`Create logical volume` ->`LVMGroup`
 Logical volume name: `var-log`
 Logical volume size: `1056MG`

 ->`Finish`

 ->`#1` ->`Use as:…` ->`Ext4` ->`Mount point` ->`home`
 ->`#1` ->`Use as:…` ->`Ext4` ->`Mount point` ->`/`
 ->`#1` ->`Use as:…` ->`Ext4` ->`Mount point` ->`srv`
 ->`#1` ->`Use as:…` ->`swap` ->`Mount point` ->`swap`
 ->`#1` ->`Use as:…` ->`Ext4` ->`Mount point` ->`tmp`
 ->`#1` ->`Use as:…` ->`Ext4` ->`Mount point` ->`var`
 ->`#1` ->`Use as:…` ->`Ext4` ->`Moun…` ->`Enter Manually`->`/var/log`

 ->`Finish…`

------------------

 Scan extra installation media: `No`
 Choose software to install: NONE
 Device for boot loader installation: `/dev/sda …`

Log in as 'root'.
List block devices informations:
    # lsblk

* Partitions and hard disks:
> **/dev/hda** is the 'master *IDE*' (Integrated Drive Electronics)
> drive on the primary 'IDE controller'. Partitions of this disk are
> named hda1, hda2. A 'second IDE' device would be named hdb.  (The
> motherboard has two IDE connectors on which we plug the cables which
> can each accommodate 2 peripherals.
    IDE connector 0 -> master: /dev/hda -> slave: /dev/hdb
    IDE connector 1 -> master: /dev/hdc -> slave: /dev/hdd
> 'hda1' to 'hda4' will be **primary** partitions.
> 'hda5' to 'hda…' will be **logical** partitions (of an extended partition).
> An **extended** partition is a primary partition which itself
> contains another partition table.

> *SCSI* disks (Small Computer System Interface) will be same as above
> with a 's' **dev/sda**.

The active partition is indicated by an *
    # fdisk -l
List devices files under root:
    $ ls /dev
> 'dev' stands for device, contains all the peripherals.

http://stephane.boireau.free.fr/informatique/samba/samba/partitions_et_disques_durs.htm

###     Comfort

Look for packages update:
    $ apt update
Upgrade what is upgradable:
    $ apt upgrade

Swap Caps-lock and Ctrl:
    $ vi /etc/default/keyboard
    > XKBOPTIONS="ctrl:swapcaps"

Install zsh, wget, curl, git, tmux, vim:
    $ apt install zsh wget curl git tmux vim
Install man pages
    apt install man-db manpages-dev

Change default Shell:
    $ chsh -s /bin/zsh
    $ zsh

Import my mini-conf (for root)
    $ mkdir ~/Documents
    $ cd !$
    $ git clone https://github.com/clem9nt/mini-conf
    $ bash mini-conf/installer.sh
    $ source ~/.zshrc

Set Vim as the default editor:
    $ update-alternatives --list editor
    $ update-alternatives --set editor /usr/bin/vim.basic

Install sudo:
    $ apt update
    $ apt install sudo

Add 'cvidon' to 'sudo' group:
    $ usermod -aG sudo cvidon
Check entry:
    $ getent group sudo

Login as 'cvidon':
    $ su - cvidon

Change default Shell:
    $ chsh -s /bin/zsh
    $ zsh

Import my mini-conf (for cvidon)
    $ mkdir ~/Documents
    $ cd !$
    $ git clone https://github.com/clem9nt/mini-conf
    $ bash mini-conf/installer.sh
    $ source ~/.zshrc

Update the time:
Install 'dbus' package:
    $ apt install dbus
    $ reboot
Check current timezone:
    $ timedatectl
Find a timezone:
    $ timedatectl list-timezones | grep Paris
Change the timezone:
    # timedatectl set-timezone Europe/Paris

###     Sudoers

Create 'mysudoers' to configure 'sudoers' group:
    # touch /etc/sudoers.d/mysudoers

> Writing to **sudoers.d/mysudoers** instead of 'sudoers' is safer
> because 'sudoers' is under control of the distribution package
> manager and an upgrade can overwrite it.
https://superuser.com/questions/869144/why-does-the-system-have-etc-sudoers-d-how-should-i-edit-it

Add the rules:
    # visudo -f /etc/sudoers.d/mysudoers
    > Defaults  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    > Defaults  passwd_tries=3
    > Defaults  badpass_message="Wrong password.  This incident will be reported."
    > Defaults  iolog_dir=/var/log/sudo/%{user}
    > Defaults  log_input,log_output
    > Defaults  requiretty

Create '/var/log/sudo/' for 'logfile'
    # mv /var/log/sudo

> **secure_path** prevent any script to be executed with sudo unless
> it matches the secure path.
> **requiretty** prevents sudo from being used from daemons or
> other detached processes (cronjobs, web server plugins).

###     UFW (Uncomplicated Firewall)

Install UFW:
    # apt update
    # apt install ufw
Enable UFW at system startup:
    # ufw enable

> A `# systemctl status ufw` will display '*active (exited)*' because
> it is a oneshot service.  **Oneshot services** are expected to take
> action and exit immediately, thus they are not really services, no
> running processes remain.

###     SSH Daemon

> **SSH** Secure Shell or Secure Socket Shell, allows to securely
> connect to a remote computer or a server by using a text based
> interface.

Install:
    # apt update
    # apt install openssh-server

Check if SSH daemon is running:
    # service ssh status
> Same as 'sshd'.

Change SSH default port 22 to port 4242:
    # cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    # vi /etc/ssh/sshd_config
Replace `#Port 22` with
    > Port 4242
Make sure we can not connect with root through SSH:
    > PermitRootLogin no

Add firewall exceptions to *tcp* port 4242:
    # ufw allow 4242/tcp
Check firewall exceptions:
    # ufw status

Restart SSH:
    # service ssh restart

###     SSH Connection

Open the VM ports:
MyVM ->`Settings` ->`Network`
 Attached to: `NAT`
 ->`Advanced` ->`Port Forwarding`
 ->(+) Name:`SSH`| Host Port:`4242`| Guest Port:`4242`

Check the Port 4242 host NAT:
    # netstat -an | grep 4242

Connect to guest from host:
    $ ssh -p 4242 cvidon@127.0.0.1

SFTP (Secure File Transfer Protocol):
Connect to guest from host:
    $ sftp -P 4242 cvidon@127.0.0.1
Put, get, rm a file:
    sftp> put <filename>
    sftp> get <filename>
    sftp> rm  <filename>

###     Password Policy

* Install password quality checking library:
    # apt install libpam-pwquality

* Configure a strong password policy:
    # cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
    # vi /etc/pam.d/common-password

* To the end of the line matching `requisite  pam_pwquality.so`
  after `retry=3` (space separated) append:
> 10 chars long minimum.
    > minlen=10
> At least 1 special char and 1 lcase.
    > ocredit=-1 lcredit=-1
> At least 1 ucase, 1 number and 3 consecutive identical chars max.
    > ucredit=-1 dcredit=-1 maxrepeat=3
> Shouldn't include the username.
    > reject_username
> At least 7 chars that are not part of the former password.
    > difok=7
> Previous rules also apply to root.
    > enforce_for_root

> **pam_pwquality**: `-N` means 'minimum of N' and `+N` means 'maximum
> of N'. Also `enforce_for_root`won't apply to `difok` because "root
> is not asked for an old password so the checks that compare the old
> and new password are not performed."

* Configure password expiration:
    # cp /etc/login.defs /etc/login.defs.bak
    # vi /etc/login.defs
    > PASS_MAX_DAYS 30
    > PASS_MIN_DAYS 2
    > PASS_WARN_AGE 7
> Expire every 30 days.
> 2 days minimum between the modifications of a password
> Warning message 7 days before password expire.

Apply this parameters to existing users:
PASS_MIN_DAYS 2:
    # chage --mindays 2 <user>
PASS_MAX_DAYS 30:
    # chage --maxday 30 <user>
PASS_WARN_AGE 7:
    # chage --warndays 7 <user>

Check the password policy:
    $ chage -l <user>

###     Update Passwords

* Change disk password:
Find UUID of the drive:
    $ cat /etc/crypttab
Find the ID of the drive:
    # blkid | grep <some_UUID_chars> | cut -d : -f 1
Add a passphrase:
    # cryptsetup luksAddKey <ID>
Remove a passphrase:
    # cryptsetup luksRemoveKey <ID>

> It is *important* keep at least one passphrase before removing last
> one.

Change users password:
    # passwd <user>
    > <pass>

###     Groups and Users

> **usermod** modifies or changes any attributes of an 'already
> existing' user.  (unlike `adduser` used to 'create' an user account)
> `-G` specifies the list of supplementary groups,`-a` to 'append'
> instead of 'replaces' the user's group with the supplementary ones.

> **getent** get a databases text file entries (ie. `group` database's
> entries `sudo` and `user`).

* Create 'user42' group:
    # groupadd user42
Check if the group is created:
    # getent group user42

* Set 'cvidon' groups to 'user42':
    # usermod -aG user42 cvidon
Check 'cvidon' groups:
    # groups cvidon

Check all the local users:
    $ cut -d: -f1 /etc/passwd

Delete <group>:
    $ delgroup <group>
Delete <user> (and all its files):
    $ deluser --remove-all-files <user>

###     Crontab Monitoring

Install 'netstat tools':
    # apt update
    # apt install net-tools

Create and place 'monitoring.sh' in /usr/local/bin/:
    > #!/bin/bash
    > arc=$(uname -a)
    > pcpu=$(grep "physical id" /proc/cpuinfo | sort | uniq | wc -l)
    > vcpu=$(grep "^processor" /proc/cpuinfo | wc -l)
    > fram=$(free -m | grep Mem: | awk '{print $2}')
    > uram=$(free -m | grep Mem: | awk '{print $3}')
    > pram=$(free    | grep Mem: | awk '{printf("%.2f"), $3/$2*100}')
    > fdisk=$(df -Bg | grep '^/dev/' | grep -v '/boot$' | awk '{ft += $2} END {print ft}')
    > udisk=$(df -Bm | grep '^/dev/' | grep -v '/boot$' | awk '{ut += $3} END {print ut}')
    > pdisk=$(df -Bm | grep '^/dev/' | grep -v '/boot$' | awk '{ut += $3} {ft+= $2} END {printf("%d"), ut/ft*100}')
    > cpul=$(top -bn1 | grep '^%Cpu' | cut -c 9- | xargs | awk '{printf("%.1f%%"), $1 + $3}')
    > lb=$(who -b | awk '$1 == "system" {print $3 " " $4}')
    > lvmt=$(lsblk -o TYPE | grep "lvm" | wc -l)
    > lvmu=$(if [ $lvmt -eq 0 ]; then echo no; else echo yes; fi)
    >
    > # net-tools required:
    > ctcp=$(cat /proc/net/tcp | wc -l | awk '{print $1-1}' | tr '' ' ')
    > ulog=$(users | wc -w)
    > ip=$(hostname -I)
    > mac=$(ip link show | awk '$1 == "link/ether" {print $2}')
    >
    > # journalctl can run because the script exec from sudo cron
    > cmds=$(journalctl _COMM=sudo | grep COMMAND | wc -l)
    >
    > echo "  #Architecture: $arc
    >     #CPU physical: $pcpu
    >     #vCPU: $vcpu
    >     #Memory Usage: $uram/${fram}MB ($pram%)
    >     #Disk Usage: $udisk/${fdisk}Gb ($pdisk%)
    >     #CPU load: $cpul
    >     #Last boot: $lb
    >     #LVM use: $lvmu
    >     #Connexions TCP : $ctcp ESTABLISHED
    >     #User log: $ulog
    >     #Network: IP $ip ($mac)
    >     #Sudo: $cmds cmd"

Check the script output:
    $ bash /usr/local/bin/monitoring.sh
Open crontab and add the rule (that will be executed as root):
    # crontab -u root -e
Append:
    > */10 * * * * bash /usr/local/bin/monitoring.sh | wall

https://crontab.guru/#*/10_*_*_*_*/

Check Cron service status:
    # systemctl status cron
Check that a silent script executes:
    # grep -a "monitoring.sh" /var/log/syslog

##  LLMP

> **LLMP Stack**: Linux Lighttpd MySQL and PHP.

###     Lighttpd

Install 'Lighttpd' web server:
    # apt install lighttpd
Check that Lighttpd is active and enabled:
    # systemctl status lighttpd | grep -o "active\|; enabled;"

> **Lighttpd** (pronounced lighty) is a fast, secure, flexible and
> open source web server optimized for high performance environments.
> Suited to handle loads of traffic with minimal memory consumption.

Add firewall exceptions to *tcp* port 80:
    # ufw allow 80/tcp
Check firewall exceptions:
    # ufw status

* Check Lighttpd welcome page from the host web browser:

Open the VM ports:
MyVM ->`Settings` ->`Network`
 Attached to: `NAT`
 ->`Advanced` ->`Port Forwarding`
 ->(+) Name:`WWW`| Host Port:`80`| Guest Port:`80`

Check the Port 80 host NAT:
    # netstat -an | grep 80

Visit Lighttpd welcome page at the address 127.0.0.1 from the host web browser.

###     MariaDB

Install 'MariaDB':
    # apt install mariadb-server
Check that MariaDB is active and enabled:
    # systemctl status mariadb | grep -o "active\|; enabled;"

> **MariaDB** is a DBMS (Relational Database Management System) that
> is a fork and an alternative to MySQL (that uses some proprietary
> code).  https://kinsta.com/blog/mariadb-vs-mysql/

Configure MariaDB security settings:
    # mysql_secure_installation
 Enter current password for root (enter for none): `enter`
 Switch to unix_socket authentication? `n`
> 'unix_socket' auth. plugin is a passwordless security mechanism.
 Set root password? `n`
 Remove anonymous users? `Y`
 Disallow root login remotely? `Y`
 Remove test database and access to it? `Y`
 Reload privilege tables now? `Y`

Log in to MariaDB console:
    # mysql
> Same as `# mariadb`.

Create 'clem-db' new database:
    mysql> CREATE DATABASE clem_db;

Create 'clem' database user identified by 'melc' password:
    mysql> CREATE USER clem@localhost IDENTIFIED BY 'melc';
Give full privileges on 'clem_db' to 'clem':
    mysql> GRANT ALL ON clem_db.* TO clem@localhost WITH GRANT OPTION;

Makes those changes take effect (without reload/restart MariaDB):
    mysql> FLUSH PRIVILEGES;

Check all users and host name where they are allowed to login:
    mysql> SELECT host, user FROM mysql.user;
Exit MariaDB shell: `exit`

Log into MariaDB server with the new user:
    # mysql -u clem -p

Check which databases user has access to:
    mysql> SHOW DATABASES;
Exit MariaDB shell: `exit`

###     PHP

Install php and php-mysql
    # apt install php-cgi php-mysql

> **php-mysql** package provides SQL modules for PHP.

> **CGI** (Common Gateway Interface) is a protocol used by most Web
> servers to capture and communicate session information to and from
> server-side processes. It *connects the front and the back* end to
> make web pages dynamic and interactive.
http://www.uvm.edu/~hag/naweb96/zshoecraft.html

> **PHP CGI** is the legacy way of running applications, it goes with very
> *poor performance* for busier websites: each time we load a page,
> PHP needs read php.ini, set its settings, loads all its extensions,
> and finally start work parsing the script.
> - One key *advantage* to using the CGI version is that PHP reads its
>   settings every time you load a page.  With PHP running as a module,
>   any changes you make in the php.ini file do not kick in until we
>   restart our web server, so the CGI version is preferable if we *testing*
>   new settings and want to see instant responses.
> - Another *benefit* of CGI is that it keeps the code execution
>   separate from the web server, increasing the *security*.

> **PHP-FPM** (FastCGI Process Manager) is an alternative that allows
> a website to handle strenuous loads. *Modern, optimized, robust* for
> busier websites and low resources consumption but *lower security*
> than CGI and require more *complicated configuration* than CGI.
https://www.basezap.com/difference-php-cgi-php-fpm/

Enable FastCGI Lighttpd modules:
    # lighty-enable-mod fastcgi
    # lighty-enable-mod fastcgi-php
Restart server:
    # service lighttpd force-reload

###     WP

Download WP to '/var/www/html'
    # wget http://wordpress.org/latest.tar.gz
Extract content:
    # tar -xzvf latest.tar.gz
Copy content of '/var/www/html/wordpress' to '/var/www/html':
    # cp -r wordpress/* /var/www/html
Remove 'latest.tar.gz' and 'wordpress':
    # rm -rf latest.tar.gz wordpress

Create WP config file:
    # cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
Reference 'clem_db' and 'clem' into config:
    # vi /var/www/html/wp-config.php
    > define( 'DB_NAME', 'clem_db' );
    > define( 'DB_USER', 'clem' );
    > define( 'DB_PASSWORD', 'melc' );

Visit localhost from the host web browser to see the WP default page.

###     IPFS

Download GO:
    $ curl -O https://dl.google.com/go/go1.17.5.linux-amd64.tar.gz
    $ sha256sum go1.17.5.linux-amd64.tar.gz
Compare with the online hash: https://go.dev/dl/

Extract to '/usr/local':
    # tar -C /usr/local -xzf go1.17.5.linux-amd64.tar.gz

Update zsh env:
    $ echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a ~/.zprofile
    $ echo 'export GOPATH="$HOME/go"' | sudo tee -a ~/.zprofile
    $ echo 'PATH="$GOPATH/bin:$PATH"' | sudo tee -a ~/.zprofile
Source zprofile:
    $ source ~/.zprofile

Check that GO is installed:
    $ go version

Download IPFS:
    $ go install github.com/ipfs/ipfs-update@latest

Check that IPFS is up to date:
    $ ipfs-update versions
Update to whatever version is the latest:
    $ ipfs-update install v0.11.0

Increase maximum buffer size (from 300k to to 2500k):
    # sysctl -w net.core.rmem_max=2500000
Initialize IPFS:
    $ ipfs init --profile server

Change IPFS repo size (default 10GB):
    $ ipfs config Datastore.StorageMax 50MB

Create a systemd service to make sure IPFS is running all the time:
    # vi /etc/systemd/system/ipfs.service
    > [Unit]
    > Description=IPFS Daemon
    > [Service]
    > Type=simple
    > ExecStart=/home/cvidon/go/bin/ipfs daemon --enable-gc
    > Group=cvidon
    > Restart=always
    > Environment="IPFS_PATH=/home/cvidon/.ipfs"
    > [Install]
    > WantedBy=multi-user.target

Enable IPFS service:
    # systemctl daemon-reload
    # systemctl enable ipfs
    # systemctl start ipfs
Check:
    # systemctl status ipfs | grep -o "active\|; enabled;"

Add firewall exceptions to *tcp* port 4001:
    # ufw allow 4001/tcp
Check firewall exceptions:
    # ufw status

Open the VM ports:
MyVM ->`Settings` ->`Network`
 Attached to: `NAT`
 ->`Advanced` ->`Port Forwarding`
 ->(+) Name:`IPFS`| Host Port:`4001`| Guest Port:`4001`

Check the Port 4001 host NAT:
    # netstat -an | grep 4001

https://docs.ipfs.io/how-to/observe-peers/
See whose peer we are directly connected to:
    $ ipfs swarm peers
Print bandwidth information.
    $ ipfs stats bw
