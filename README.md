```shell
echo export TZ=Europe/Copenhagen > /etc/rc.timezone
pkgin update
pkgin install nano
pkgin install openssh
cp /usr/pkg/etc/rc.d/sshd /etc/rc.d/
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

git pull code

```shell
git config --global http.sslVerify false
git clone https://github.com/crypto-lee/minixCryptoFile.git
git pull
```

clang

```shell
cd /home/project/minixCryptoFile
clang function.c -o function -lmthread -lcrypto -L/usr/lib
 ./function -e test.txt ttt.txt.cry abcdefghijklmnop
./function -d ttt.txt.cry dfsf.txt abcdefghijklmnop

```

新版本

```shell
cd /home/project/minixCryptoFile
clang main.c aes.c user.c -o main -lmthread -lcrypto -L/usr/lib
./main
```

先注册再登录 再加密解密文件
