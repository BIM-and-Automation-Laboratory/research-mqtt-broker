# BIMAL Research MQTT Broker
Research MQTT Broker implemented on top of EMQX 4.3.2. Supports IoT protocols, such as MQTT, CoAP and LwM2M. 
Available for use upon request and approval.

![1600px-MQTT_publish](https://user-images.githubusercontent.com/46814008/173225481-666f0012-41ce-408c-a094-0ae72e740d01.png)


https://mqtt.jyings.com:18084/

## Getting started with our broker
Just like any other MQTT broker, you need a few configurations to get started and ours are summarized here

* **Host**: mqtt.jyings.com
* **Username**: available upon request and approval (terms and conditions will apply)
* **Password**: available upon request and approval (terms and conditions will apply)
* **Port**: Choose from the options below depending on your usecase.

| TCP Ports     | MQTT Port     |
| ------------- |:-------------:|
| 1883      | MQTT Port |
| 8883      | MQTT/SSL Port      |
| 8083      | MQTT/WebSocket/SSL Port      |
| 8084      | MQTT/WebSocket Port      |
| 8080      | HTTP Management API Port     |

An example MQTT connection for SSL in javascript using the [mqtt.js library](https://github.com/mqttjs/MQTT.js) is shown below.

```
const mqtt = require('mqtt')

const mqttHost = mqtt.jyings.com;
const mqttPort = 8883;
const mqttClientId = `mqtt_${Math.random().toString(16).slice(3)}`;
const mqttConnectUrl = `mqtts://${mqttHost}:${mqttPort}`;
const client  = mqtt.connect('mqtt://test.mosquitto.org')

const mqttClient = mqtt.connect(mqttConnectUrl, {
  clientId: mqttClientId,
  clean: true,
  connectTimeout: 4000,
  username: provided-username,
  password: ****************,
  reconnectPeriod: 1000,
});

const topic = "sensors/temp-humidity-sensor/tts5";

mqttClient.on("connect", () => {
  console.log("⚡ MQTT-client ---> Connected");
  mqttClient.subscribe([topic], () => {
    mqttClient.publish('presence', 'Hello mqtt');
  });
});

mqttClient.on('message', function (topic, message) {
  // message is Buffer
  console.log(message.toString())
})
```

## Getting started with your own
Using our broker might be convinient bu t wouldn't it be cool if you could set up one for your experiments in the future. And yes, you will fully own it. Let's show you how. These steps make the following assumptions.

- [x] You are familiar with **UNIX** specifically **Linux**.
- [x] You are using a cloud server with **Ubuntu 20.04LTS**
- [x] You own a domain named **research.my-mqtt-broker.com**

#### Provision a cloud server instance

A number of cloud hosting servers exist today such as [Linode](https://www.linode.com/), [Google Cloud](https://cloud.google.com/), [AWS](https://aws.amazon.com/) etc. The provisioning process is documented on the respective provider's websites and is beyond the scope of our documentation here. 

#### Set up your cloud server instance and get things rolled up. 
* Log in to the server for the first time using ```ssh root@your-server-ip```. Make sure to replace ```your-server-ip``` with the actual IP address provided by your cloud server vendor.

* Run some security updates and system upgrades using ```apt update && apt upgrade```.

* Set the hostname of the server to whatever you need. For this documentation, we shall use **mqqt-broker**. To set the hostname, use the command below;<br/>
```hostnamectl set-hostname mqtt-broker```<br/>
You can confirm that the hostname was set using the command
```hostname```

* You then need to set the hostname in the server's host file. You can use the inbuilt linux editor nano for this. Use the command ```nano /etc/hosts``` to open up the host file.</br> 
Add the host ```your-server-ip	mqtt-broker``` under the default host ```127.0.0.1  localhost``` as shown below. Save the file when done </br>
**Hint**: Use Tab Button to space ```your-server-ip``` from the your hostname ```mqtt-broker```
```
# /etc/hosts
127.0.0.1       localhost
your-server-ip  mqtt-broker

# The following lines are desirable for IPv6 capable hosts
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

* Add a limited user to the machine and stop using the root. Root user has the permissions to do anything and this sounds cool 😁 but it is catastrophic. Long story short, it is dangerous to use root. We shall add a limited user called **researcher**. To do this use the command ```adduser researcher```

* Add this user to the ```sudo``` group so they are able to run admin commands in ```sudo``` mode. To do this use the command ```adduser researcher sudo```

* Logout of the server to try and login as the new user **researcher**. Logout using the command ```exit``` and log back in as **researcher** using ```ssh researcher@your-server-ip```

* Is is best to set up ssh-key-based authentication instead of signing in with a password to your server each time. First create a ```.ssh``` directory within the home directory. To confirm the directory u are in, use the ```pwd``` command. If this command returns ```/home/researcher```, you are in your home directory. Create the ```.ssh``` directory using the command ```mkdir .ssh```

* Open up a new terminal on your local machine to create new ssh keys there. We shall copy our public key to the server later and leave the private key on our local machine. I suggest using **bash**. Use the command ```ssh-keygen -b 4096```to generate new ssh keys on your local machine. This will bring up a promp for you to choose a  file to save the ssh-keys as shown below. This is to ensure you do not override any of your pre-existing SSH keys by mistake. If this is not a concern for you, just run the command and press enter on all the requested prompts to maintain defaults. For this documentation, let's say we have exisitng ssh keys called ```id_rsa``` and don't want to replace them, we provide a new ssh-key key file name called **mqtt-broker_rsa**.
**Hint**: ```/my/ssh/keys/directory/``` will be your actual path directory.

```
$ ssh-keygen -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/my/ssh/keys/directory/.ssh/id_rsa): /my/ssh/keys/directory/.ssh/mqtt-broker_rsa

```

* When this is done and you press enter, you will get a message telling you that two files were created i.e. A public and private key as shown below.
```
Your identification has been saved in /my/ssh/keys/directory/.ssh/mqtt-broker_rsa
Your public key has been saved in /my/ssh/keys/directory/.ssh/mqtt-broker_rsa.pub
```

* We need to move the public key ```mqtt-broker_rsa.pub``` to the server and leave the private key ```mqtt-broker_rsa``` safe on our local machine. Use the comman below to copy the ssh public key from ur local machine to the ~/.ssh/authorized folder on ur remote server. You will be asked to authenticate yourself to the remote server to proceed with the copying process.</br>
 ```
 scp /my/ssh/keys/directory/.ssh/mqtt-broker_rsa.pub researcher@your-server-ip:~/.ssh/authorized_keys
 ```

* Go back to your remote server's terminal and update some permissions as shown below
```
sudo chmod 700 ~/.ssh/
sudo chmod 600 ~/.ssh/*
```

* Logout nad try logging in to the server with the ssh private key ```mqtt-broker_rsa``` stored on your local machine using the command below. You will notice that you can login without a password.
```
ssh researcher@your-server-ip -i /my/ssh/keys/directory/.ssh/mqtt-broker_rsa
```

* We now need to disable root login over ssh by editing the ssh config. Remember using the root user is catastrophic. Just don't. Open the ssh config file using the command below.
```
sudo nano /etc/ssh/sshd_config
```

* Look for the lines that say
```
PermitRootLogin yes
PasswordAuthentication yes
```

* Change each of them as shown below and save the file.
```
PermitRootLogin no 
PasswordAuthentication no
```

* Restart the ssh service using ```sudo systemctl restart sshd```

* Next is setting up a firewall for the server. First install ufw using the command below
```
sudo apt install ufw
```

* Then setup some firewall rules using the commands below. Read [here](https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands) for more information on what they mean.
```
sudo ufw default allow outgoing
sudo ufw default deny incoming
```

* The rules above can lock you out of the system if you don't set the explicit rules below 
to allow ports for ssh, http and other traffic you might need for your server later. Set the rules appropriately using the commands below.
```
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 18084/tcp
sudo ufw allow 18083/tcp
sudo ufw allow 1883/tcp
sudo ufw allow 8083/tcp
sudo ufw allow 8081/tcp
sudo ufw allow 8883/tcp
sudo ufw allow 8084/tcp
```

* Then run the comman below to persist the firewall rules
```
sudo ufw enable
```
#### Setting up the EMQX Broker
* First install the dependencies below
```
sudo apt install curl vim unzip
```

* Install EMQX using the script below which is the easiest route. This will get the latest stable version. At the time of writing this documentation, this was 4.3.5. 
```
curl https://repos.emqx.io/install_emqx.sh | sudo bash
```
* A specific version of emqx can be installed using APT. I recommend using this to avoid the headache of breaking changes. I have used version 4.3.5

* After the installation is complete, you can start the EMQX broker using the command below
```
sudo systemctl start emqx && sudo systemctl enable emqx
```

* Verify if the service is running properly using this command
```
systemctl status emqx
```

* Next we need to configure the broker to use SSL. Run all the commands below on the server to install certbot. If you don't know [certbot](https://certbot.eff.org/), it is a service that can help us generate and renew certificates for our domains.

```
sudo apt-get update
sudo apt-get install software-properties-common
sudo apt-get update
sudo apt install certbot python3-certbot-apache
```

* Find out if any service is using port 80, this port is needed by certbot for cert generation. If any service exists, kill them appropriately. Use the command below to find out the services using port 80, if any.
```
netstat -tulpn | grep :80
```

* Next we run certbot and get SSL certificates for our domain. Let's assume you own a domain called **research.my-mqtt-broker.com**. Use the command below to generate the certificates. Review the [certbot](https://certbot.eff.org/) documentation to understand this command better.
* 
```
sudo certbot certonly --standalone -d research.my-mqtt-broker.com
```

* Keys and certtificates will be generated and stored in the location ```/etc/letsencrypt/live/research.my-mqtt-broker.com```

* We need to copy these certificates from their original location to EMQX's cert folder located at ```/etc/emqx/certs``` and assign the necessary permissions to emqx to access them. Use the command below to do this.

```
sudo cp /etc/letsencrypt/live/research.my-mqtt-broker.com/privkey.pem /etc/letsencrypt/live/research.my-mqtt-broker.com/fullchain.pem /etc/emqx/certs
```

* Assign permissions using the command below
```
sudo chown -R emqx:emqx /etc/emqx/certs
```

#### Configure the EMQX Broker dashboard to use SSl

* Open the configuration file for the EMQX dashboard using the command below
```
sudo nano /etc/emqx/plugins/emqx_dashboard.conf
```

* Update the following lines
```
dashboard.listener.https = 18084
dashboard.listener.https.acceptors = 2
dashboard.listener.https.max_clients = 512
dashboard.listener.https.keyfile = /etc/emqx/certs/privkey.pem
dashboard.listener.https.certfile = /etc/emqx/certs/fullchain.pem
```

#### Configure the EMQX's MQTT and MQTT Websocket protocols to support SSL.
* Open EMQX's configuration file using the command below
```
sudo nano /etc/emqx/emqx.conf
```

* Update the following lines
```
listener.ssl.external.keyfile = /etc/emqx/certs/privkey.pem
listener.ssl.external.certfile = /etc/emqx/certs/fullchain.pem
listener.wss.external.keyfile = /etc/emqx/certs/privkey.pem
listener.wss.external.certfile = /etc/emqx/certs/fullchain.pem
```

* Restart the EMQX broker and test for both the SSL & NON-SSL connections in the browser </br>
For SSL, use
https://research.my-mqtt-broker.com:18084 </br>
For NON-SSL use
http://research.my-mqtt-broker.com:18083 </br>

#### Configure efficient certificate renewal.

Certbot will automatically renew our SSL certificates but there's one caveat. The certificates are always stored in a location where EMQX doesnt have access permissions. Even if we changed the permissions of give EMQX the necessary permissions, certbot will override these permissions sometime later during renewal. There's a simple but efficient fix for this. Create a script to execute everytime certbot is finished with renewing our domain certificates. This script will copy the certificates from the letsencrypt folder to our emqx broker certs folder. The script will also apply the necessary permissions for emqx to use the certs properly. The next time certbot renews the SSL certificates, this script will run after automatically.

* First create a new file called post-script.sh in the directory /etc/letsencrypt/renewal-hooks/post using the command below
```
sudo nano /etc/letsencrypt/renewal-hooks/post/post-script.sh
```

* This will open up an editor. Copy the script below and paste it in and save the file.

```
#!/bin/sh

set -e

for domain in $RENEWED_DOMAINS; do
        case $domain in
        research.my-mqtt-broker.com)
                daemon_cert_root=/etc/emqx/certs

                # Make sure the certificate and private key files are
                # never world readable, even just for an instant while
                # we're copying them into daemon_cert_root.
                umask 077

                cp "$RENEWED_LINEAGE/fullchain.pem" "$daemon_cert_root/fullchain.pem"
                cp "$RENEWED_LINEAGE/privkey.pem" "$daemon_cert_root/privkey.pem"

                # Apply the proper file ownership and permissions for
                # the daemon to read its certificate and key.
                chown emqx:emqx "$daemon_cert_root/fullchain.pem" \
                        "$daemon_cert_root/privkey.pem" 

                chmod 400 "$daemon_cert_root/fullchain.pem" \
                        "$daemon_cert_root/privkey.pem"

                service emqx restart >/dev/null
                ;;
        esac
done
echo "ssl certs copied to emqx and permissions set successfully"
```

#### Get the SSL cert fingerprint for IoT devices (can be used later for IoT devices that need to access the broker via SSL)

Usually the IoT devices need the SSL certificate's fingerprint to operate properly using SSL, 
To get the SSL Cert SHA1 fingerprint, use the command;
```
sudo openssl x509 -noout -fingerprint -sha1 -inform pem -in /etc/letsencrypt/live/research.my-mqtt-broker.com/cert.pem
```
Use the returned fingerprint appropriately in any IoT device scripts.

#### Things to think about
- [x] Each SSL certificate has its own fingerprint. When a certificate expires and a new one is generated. The fingerprint of the old certificate needs to be updated on the deployed IoT devices. A good strategy for this is required.
- [x] Implement a database for persistence.

