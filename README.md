# curl-websocket

Build in `ubuntu`
```
sudo su
apt-get update -y
apt-get install cmake git make zlib1g zlib1g-dev build-essential autoconf libtool openssl libssl-dev -y
exit

git clone https://github.com/ssrlive/curl-websocket.git
cd curl-websocket
git submodule update --init
cmake . && make

```
