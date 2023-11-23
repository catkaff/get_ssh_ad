dnf module enable python39
dnf install python39
python3 -m pip install --upgrade pip
pip3 install python-dotenv
pip3 install ldap3

[root@ipa6 ~]# pip3 list
Package       Version
------------- -------
ldap3         2.9.1
pip           23.3.1
pyasn1        0.5.1
python-dotenv 1.0.0
setuptools    50.3.2

/usr/local/bin/script.py

/etc/pki/ca-trust/source/anchors/adca.crt
update-ca-trust

[root@ipa6 ~]# ls -la /usr/local/bin/get_ssh_key.conf
-r-------- 1 root root 652 Nov 22 22:50 /usr/local/bin/get_ssh_key.conf


Nov 22 23:21:21 ipa6 sshd[436469]: AuthorizedKeysCommand /usr/local/bin/get_ssh_pub_key.py adtest03@dserver.cat failed, status 1

chmod 666 /var/log/ssh_get_key.log

[root@ipa6 ~]# sudo -u nobody /usr/local/bin/get_ssh_pub_key.py adtest03
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIACCi6g92QyHKkY/OnL7kApm1BWz57OZElwTO+NjXqj8
[root@ipa6 ~]# sudo -u nobody /usr/local/bin/get_ssh_pub_key.py evkazakov
[root@ipa6 ~]#

nobody УЗ не годится, у него доступа к локальным пользакам, у него доступов ходить проверять ключи пользаков

"/etc/ssh/sshd_config"
AuthorizedKeysCommand /usr/local/bin/get_ssh_pub_key.py
AuthorizedKeysCommandUser root



sudo useradd -m -s /bin/bash имя_пользователя
ssh-keygen -t ed25519 -C "your_email@example.com"