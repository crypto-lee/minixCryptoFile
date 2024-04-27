```shell
echo export TZ=Europe/Copenhagen > /etc/rc.timezone
pkgin update
pkgin install nano
pkgin install openssh
cp /use/pkg/etc/rc.d/sshd /etc/rc.d/
nano /etc/rc.conf
```

add sshd=YES

```shell
reboot
ssh root@localhost
yes
nano /usr/pkg/etc/ssh/sshd_config

```

update PermitRootLogin yes

```shell
/etc/rc.d/sshd restart
ssh root@localhost
pkgin update
pkgin_sets
```
