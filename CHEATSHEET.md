# ISP SYS ADMIN CHEATSHEET

# 1. Prepare environment
Download [installation script](https://raw.githubusercontent.com/rlamp/isp-handson/master/install.sh) and run it to install all necessery stuff. Do not forget to `Reinitialize the MAC address of all network cards` when cloning images! Also pay attention when setting machines' network adapter `Attach to` to select `NAT network` and not `NAT`.


### 1.1 Change machine's hostname
Open `/etc/hosts` and add `127.0.1.1 new-name`. The run `sudo hostnamectl set-hostname new-name`. Restart terminal.


### 1.2 Set up networking
Always run `sudo sysctl -p` when starting images!

*Note: Adapter 1 = `enp0s3`, Adapter 2 = `enp0s8`, Adapter 3 = `enp0s9`*

Open `/etc/network/interfaces` and insert something like
```sh
auto enp0s8
iface enp0s8 inet static
  address 10.0.0.2
  netmask 255.255.255.0
  gateway 10.0.0.1
  dns-nameservers 8.8.8.8
```

Then restart network manager and bring interface up if it is down.
```sh
sudo service network-manager restart
sudo ifup enp0s8
```

On routers enable routing. To route internet-bound traffic from private subnets enable NAT.
```sh
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
```


## 2. Assignments
### 2.1 Firewall rules
In `~/isp-iptables` should be solved `iptables*.sh` scripts. Just reuse those and run `sudo ./iptables2.sh [start|reset]`. For more `iptables` references go [here][iptables]. To list all `iptables` rules run `sudo iptables --list -nv`.

Different options for `-m` are:
```sh
-m state --state NEW,ESTABLISHED,RELATED
-m multiport --[d,s]ports 22,80,443
-m limit --limit 1/s
```
>The limit feature in iptables specifies the maximum average number of matches to allow per second. You can specify time intervals in the format /second, /minute, /hour, or /day, or you can use abbreviations so that 3/second is the same as 3/s.

`-A ` is for append and `-I` is for insert at specific place `[rulenum]`, default is 1 (beginnging of chain)

>-A, --append chain rule-specification
-I, --insert chain [rulenum] rule-specification

Remember to include `! --syn` for statless INPUT chain for reply packets.

### 2.2 SSH protocol
##### (Re)generate keys
Make sure you provide an empty passphrase when asked!
Name the keys according to `HostKey` directive in `/etc/ssh/sshd_config file`.

On server:
```sh
sudo ssh-keygen -t ecdsa   -f /etc/ssh/ssh_host_ecdsa_key
sudo ssh-keygen -t rsa     -f /etc/ssh/ssh_host_rsa_key
sudo ssh-keygen -t dsa     -f /etc/ssh/ssh_host_dsa_key
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key
```
On client (stored in `~/.ssh`):
```sh
ssh-keygen -t rsa
ssh-keygen -t dsa
ssh-keygen -t ecdsa
```
##### Authenticating the client with its public key
To use a key run with `-i` e.g. `ssh -i ~/.ssh/id_rsa isp@$SERVER`.
> To **enable public key authentication**, you have to (1) copy your public key to the remote computer and then (2) enable and link it to specific account. Simply run: `ssh-copy-id isp@$SERVER`.

> To **disable password-based login** attempts and always require client authentication with public keys. On the `ssh-server`, open file `/etc/ssh/sshd_config` and add command `PasswordAuthentication no`. Save the file and restart the SSH server with sudo `service ssh restart`.

##### Tunneling with SSH
> On `ssh-client`, set up a **tunnel** by issuing `ssh -L 127.0.0.1:8080:127.0.0.1:80 -N $SERVER`
The `-L` switch denotes local port-forwarding and the `-N` prevents executing remote commands; this is useful for only setting up forwarded ports and not actually running terminal on the remote machine.

> Set up a **reverse tunnel**  on `ssh-server` with `ssh -R 127.0.0.1:8080:127.0.0.1:80 -N isp@$CLIENT`


### 2.3 VPN with IPsec
##### Create a VPN IPsec tunnel using PSK
At the `hq_router` open the `/etc/ipsec.conf` and fill it with the following content.
```sh
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret
	    ike=aes256gcm16-aesxcbc-modp2048!
	    esp=aes256gcm16-modp2048!

conn net-net
        leftsubnet=10.1.0.0/16
        leftfirewall=yes
        leftid=@hq
        right=$BRANCH_IP
        rightsubnet=10.2.0.0/16
        rightid=@branch
        auto=add
```
Next, open file `/etc/ipsec.secrets` and add the following line.
```
@hq @branch : PSK "secret"
```
Routers will be using a pre-shared key (PSK) to authenticate each other. The key is set to `secret`.
Finally, restart the IPsec `sudo ipsec restart` so that the changes get loaded.

Do the same on `branch_router`, just make sure to chage the left<->right appropriately.
To establish the tunnel, invoke `sudo ipsec up net-net` on either routher.You can see the IPsec status by running `sudo ipsec status[all]`

##### Create a VPN IPsec tunnel using digital certificates
*Detailed (official) description is [here][ca]. More `ipsec pki` reference [here][ipsec pki].*

First, generate a private key, the default generates a 2048 bit RSA key. Then self-sign a CA certificate using the generated key.
```sh
ipsec pki --gen > caKey.der
ipsec pki --self --in caKey.der --dn "C=SL, O=FRI-UL, CN=FRI CA" --ca > caCert.der
```
For each peer, i.e. for all VPN clients and VPN gateways in your network, generate an individual private key and issue a matching certificate using your new CA:
```sh
ipsec pki --gen > peerKey.der
ipsec pki --pub --in peerKey.der | ipsec pki --issue --cacert caCert.der --cakey caKey.der --dn "C=SL, O=FRI-UL, CN=branch" --san @branch > branchCert.der
```
Store the certificates and keys in the `/etc/ipsec.d/` tree:
 - `/etc/ipsec.d/private/peerKey.der` holds the private key of the given peer. Configure it in `ipsec.secrets` to load it.
 - `/etc/ipsec.d/certs/peerCert.der` holds the end-entity certificate of the given peer. Reference it in `ipsec.conf` to use it.
 - `/etc/ipsec.d/cacerts/caCert.der` holds the CA certificate which issued and signed all peer certificates, gets loaded automatically.

Configuration changes slightely, in `/etc/ipsec.conf` put machines certificate `leftcert=moonCert.der` and list it in `/etc/ipsec.secrets` like this `: RSA moonKey.der`. Restart the IPsec `sudo ipsec restart`. For more see [this example](https://www.strongswan.org/testing/testresults/ikev2/net2net-cert/).


##### IPsec connection that enables *RoadWarrior*  scenarios
*Check out the [PSK](https://www.strongswan.org/testing/testresults/ikev2/rw-psk-ipv4/) and [certificates+virtual IP](https://www.strongswan.org/testing/testresults/ikev2/ip-pool/) RoadWarrior examples.*

On the **gateway** add a new connection to `/etc/ipsec.conf`:
```sh
conn rw
	left=192.168.0.1
	leftsubnet=10.0.0.0/14
	[leftcert=moonCert.der]
	leftid=@moon.strongswan.org
	leftfirewall=yes
	right=%any
	rightsourceip=10.3.0.0/16 # Virtual IP network
	auto=add
```
*Notice the `right=%any` and `rightsourceip=10.3.0.0/16`.*

On **RoadWarrior** add the following to `/etc/ipsec.conf`:
```sh
conn home
	left=192.168.0.100
	leftsourceip=%config
	leftcert=carolCert.pem
	leftid=carol@strongswan.org
	leftfirewall=yes
	right=192.168.0.1
	rightsubnet=10.0.0.0/14
	rightid=@moon.strongswan.org
	auto=add
```
*Notice the `leftsourceip=%config` which is need for virtual IP assignment.*
*Also pay attention to `rightsubnet=10.1.0.0/16` **vs.** `rightsubnet=10.0.0.0/14`.*
*Remember that you can set multiple CIDR values, if you separate them with a comma e.g. `leftsubnet=10.1.0.0/16,10.2.0.0/16`.*

When using PSK, PSKs for all RoadWarriors must be listed in `/etc/ipsec.secrets` (and each RoadWarrir must have their PSK in their secrets file):
```sh
# /etc/ipsec.secrets - strongSwan IPsec secrets file
192.168.0.100 : PSK "secret1"
192.168.0.200 : PSK "secret2"
```
When using certificates make sure you have the keys and certificates in the right place and add `: RSA moonKey.pem` to `/etc/ipsec.secrets` on all machines.

Donf forget to restart the IPsec `sudo ipsec restart` so that the changes get loaded.

### 2.4 AAA with FreeRADIUS
##### Radius server with a test client
Register a **new client (NAS)** to the Radius server. Open `/etc/freeradius/clients.conf` and make sure it contains the following entry:
```sh
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nastype = other
}
```

Add a **new supplicant (end-user)** to the database. Open `/etc/freeradius/users` and add:
```
"alice" Cleartext-Password := "password"
    Reply-Message = "Hello, %{User-Name}"
```
Restart FreeRADIUS and test if it all works:
```sh
sudo service freeradius restart
echo "User-Name=alice, User-Password=password" | radclient 127.0.0.1 auth testing123 -x
```

##### HTTP Basic authentication with Apache and FreeRADIUS
Enable `auth_radius` module for apache and restart the apache server.
```
sudo a2enmod auth_radius
sudo service apache2 restart
```
Next, configure Apache Radius settings in `/etc/apache2/ports.conf`. Add the following:
```sh
AddRadiusAuth localhost:1812 testing123 5:3
AddRadiusCookieValid 1
```
> Apache will authenticate itself to the AAA server with PSK 'testing123'.
The request shall time-out after 5 seconds, and retry at most 3 times.
...the time (in minutes) in which the authentication cookie set by the Apache server expires

Next, tell Apache which pages require authentication. Open `/etc/apache2/sites-available/000-default.conf` and add the following lines inside `<VirtualHost *:80>` block.
```
<Directory /var/www/html>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride None
    AuthType Basic
    AuthName "RADIUS Authentication for my site"
    AuthBasicProvider radius
    Require valid-user
</Directory>
```
Reload Apache's configuration file with `sudo service apache2 reload`. Restart the FreeRADIUS server with `sudo service freeradius restart`.

##### Roaming and federation
On `radius1`, create a **new domain** (or realm) called `finland`. Open `/etc/freeradius/proxy.conf` and add the following.
```sh
home_server hs_finland {
        type = auth+acct
        ipaddr = $RADIUS2
        port = 1812
        secret = testing123
}

home_server_pool pool_finland {
        type = fail-over
        home_server = hs_finland
}

realm finland {
        pool = pool_finland
        nostrip
}
```
On `radius2`, create a **new (local) domain** called `finland`. Open `/etc/freeradius/proxy.conf` and add the following two lines.
```sh
realm finland {
}
```
On `radius2`, define a **new AAA client** (AAA proxy) and define its credentials. Open `/etc/freeradius/clients.conf` and add the following lines.
```sh
client $RADIUS1 {
    secret = testing123
}
```
On `radius2`, create a **new supplicant (end-user)**. Open `/etc/freeradius/users` and define his or hers credentials. An instance is given below. Make sure the second line is tab-indented.
```sh
"pekka" Cleartext-Password := "password"
    Reply-Message = "Hello, %{User-Name}"
```
Restart FreeRADIUS with `sudo sevice freeradius restart`.

##### Authenticating IPsec RoadWarriors with Radius
*See [2.3 VPN with IPsec](#23_VPN_with_IPsec_8) to setup basic IPsec configurations.
For all further references see [this example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/).*

On `gateway` add new IPsec connection to `/etc/ipsec.conf` ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/moon.ipsec.conf)):
```
conn rw-eap
	left=192.168.0.1
	leftsubnet=10.1.0.0/16
	leftid=@moon.strongswan.org
	leftcert=moonCert.pem
	leftauth=pubkey
	leftfirewall=yes
	rightid=*@strongswan.org
	rightauth=eap-radius
	rightsendcert=never
	right=%any
	auto=add
```
Setup `/etc/ipsec.secrets` appropriately (PSK/RSA).

On `gateway` use file `/etc/strongswan.conf` ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/moon.strongswan.conf)) to tell the StrongSwan how to connect to Radius:
```
load = [...] eap-radius
plugins {
    eap-radius {
        secret = testing123 
        server = [10.1.0.10|localhost]
}}
```

On RADIUS server (can be the same machine as `gateway`) appropriately setup:
 - `/etc/freeradius/clients.conf`: check if default (*localhost, testing123*) is ok or add new client (NAS) ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/alice.clients.conf))
 - `/etc/freeradius/proxy.conf/`: add a domain for RoadWarriors? set `type = radius` ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/alice.proxy.conf))
 - `/etc/freeradius/users`: add end-users and credentials ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/alice.users))


On RoadWarriors add a connection to `/etc/ipsec.conf` ([example](https://www.strongswan.org/testing/testresults/ikev2/rw-eap-md5-radius/carol.ipsec.conf)) and put FreeRADIUS users' credentials in `/etc/ipsec.secrets` like this:
```
# /etc/ipsec.secrets - strongSwan IPsec secrets file

carol@strongswan.org : EAP "secret"
```

Restart services `sudo ipsec restart` and `sudo service freeradius restart`.

[//]: #
   [iptables]: <http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch14_:_Linux_Firewalls_Using_iptables>
   [ca]: <https://wiki.strongswan.org/projects/strongswan/wiki/SimpleCA>
   [ipsec pki]: <https://wiki.strongswan.org/projects/strongswan/wiki/IpsecPKI>