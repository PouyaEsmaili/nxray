# NXRay

This is not XRay!

It's just a simple udp port-forwarding app over tcp. It uses tls to secure the connection. It works like `ssh -L`, However, `ssh -L` handles tcp port-forwarding while this app forwards udp connections.

## Team

Nazanin Azarian `98105568`

Pouya Esmaili `98105581`

## Server Example

```bash
python XServer/main.py -s :1234
```

## Client Example

```bash
sudo python XClient/main.py -s localhost:1234 -ut localhost:53:8.8.8.8:53
```

## How to Test

After server and client are running, every dns query to the 127.0.0.1 will be forwarded to google.
So it can be tested using the following command:

```bash
dig @127.0.0.1 google.com -4
```

If the client or server don't work correctly, this command will timeout because there is no dns server.
However, if everything works as expected, the command will show the ip address of google.
