<h1 align="center">
  <img src="static/proxify-logo.png" alt="proxify" width="200px"></a>
  <br>
</h1>


<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/projectdiscovery/proxify/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/proxify"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/proxify"></a>
<a href="https://github.com/projectdiscovery/proxify/releases"><img src="https://img.shields.io/github/release/projectdiscovery/proxify"></a>
<a href="https://hub.docker.com/r/projectdiscovery/proxify"><img src="https://img.shields.io/docker/pulls/projectdiscovery/proxify.svg"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-proxify">Running Proxify</a> •
  <a href="#installing-ssl-certificate">Installing SSL Certificate</a> •
  <a href="#applications-of-proxify">Applications of Proxify</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy.
Additionally a replay utility allows to import the dumped traffic (request/responses with correct domain name) into burp or any other proxy by simply setting the upstream proxy to proxify.

# Features

<h1 align="left">
  <img src="static/proxify-run.png" alt="proxify" width="700px"></a>
  <br>
</h1>


 - Simple and modular code base making it easy to contribute.
 - **HTTP** and **SOCKS5** support for upstream proxy
 - Native MITM support
 - Full traffic dump (request/responses)
 - Traffic Match / Filter with DSL language
 - Traffic Match and Replace support
 - Traffic replay in Burp

# Installation

Download the ready to run [binary](https://github.com/projectdiscovery/proxify/releases/) or install using GO

```sh
GO111MODULE=on go get -v github.com/projectdiscovery/proxify/cmd/proxify
```

# Usage

```sh
proxify -h
```

This will display help for the tool. Here are all the switches it supports.

<details>
<summary> 👉 proxify help menu 👈</summary>

```
  -addr string
      Listen Ip and port (ip:port) (default "127.0.0.1:8888")
  -allow value
      Whitelist ip/cidr
  -cert-cache-size int
      Number of certificates to cache (default 256)
  -config string
      Directory for storing program information (default "/Users/geekboy/.config/proxify")
  -deny value
      Blacklist ip/cidr
  -dns-addr string
      Listen DNS Ip and port (ip:port)
  -dns-mapping string
      DNS A mapping (eg domain:ip,domain:ip,..)
  -dns-resolver string
      Listen DNS Ip and port (ip:port)
  -dump-req
      Dump requests in separate files
  -dump-resp
      Dump responses in separate files
  -http-proxy string
      Upstream HTTP Proxy (eg http://proxyip:proxyport
  -no-color
      No Color (default true)
  -output string
      Output Folder (default "logs")
  -request-dsl string
      Request Filter DSL
  -request-match-replace-dsl string
      Request Match-Replace DSL
  -response-dsl string
      Response Filter DSL
  -response-match-replace-dsl string
      Request Match-Replace DSL
  -silent
      Silent
  -socks5-proxy string
      Upstream SOCKS5 Proxy (eg socks5://proxyip:proxyport)
  -v  Verbose
  -version
      Version
```

</details>

### Running Proxify

Runs a HTTP proxy on port **8888**
```sh
proxify
```

Runs a HTTP proxy on custom port **1111**
```sh
proxify -addr ":1111"
```

### Proxify with upstream proxy

Runs a HTTP proxy on port 8888 and forward the traffic to burp on port 8080
```sh
proxify -http-proxy http://127.0.0.1:8080
```

Runs a HTTP proxy on port 8888 and forward the traffic to the TOR network
```sh
proxify -socks5-proxy socks5://127.0.0.1:9050
```


### Dump all the HTTP/HTTPS traffic

Dump all the traffic into separate files with request followed by the response.

```sh
proxify -output logs
```

As default, proxied request/resposed are stored in the **logs** folder. Additionally **dump-req** or **dump-resp** flag can be used for saving specfic part of the request to the file.


### Hostname mapping with Local DNS resolver

Proxify supports embedding DNS resolver to map hostnames to specific addresses and define an upstream dns server for any other domain name

Runs a HTTP proxy on port `8888` using an embedded dns server listening on port `53` and resolving `www.google.it` to `192.168.1.1` and all other `fqdn` are forwarded upstream to `1.1.1.1`

```sh
proxify -dns-addr ":53" -dns-mapping "www.google.it:192.168.1.1" -dns-resolver "1.1.1.1:53"
```

This feature is used for example by the `replay` utility to hijack the connections and simulate responses. It may be useful during internal assessments with private dns servers. Using `*` as domain name matches all dns requests.

### Match/Filter traffic with with DSL language.

If the request or response match the filters the dump is tagged with `.match.txt` suffix:

```sh
proxify -request-dsl "contains(request,'firefox')" -response-dsl "contains(response, md5('test'))"
```

### Match and Replace on the fly

Proxify supports modifying Request and Responses on the fly with DSL language.

```sh
proxify -request-match-replace-dsl "replace(request,'firefox','chrome')" -response-match-replace-dsl "regex(response, '^authentication failed$', 'authentication ok')"
```

### Replay all traffic into burp

Replay all the dumped requests/responses into the destination URL (http://127.0.0.1:8080) if not specified. For this to work it's necessary to configure burp to use proxify as upstream proxy, as it will take care to hijack the dns resolutions and simulate the remote server with the dumped request. This allows to have in the burp history exactly all requests/responses as if they were originally sent through it, allowing for example to perform a remote interception on cloud, and merge all results locally within burp.

```sh
replay -output "logs/"
```

### Installing SSL Certificate

A certificate authority is generated for proxify which is stored in the folder `~/.config/proxify/` as default, manually can be specified by `-config` flag. The generated certificate can be imported by visiting [http://proxify/cacert.crt](http://proxify/cacert.crt) in a browser connected to proxify. 

Installation steps for the Root Certificate is similar to other proxy tools which includes adding the cert to system trusted root store.

### Applications of Proxify

Proxify can be used for multiple places, here are some common example where Proxify comes handy:-

<details>
<summary>👉 Storing all the burp proxy history logs locally. </summary>

Runs a HTTP proxy on port 8888 and forward the traffic to burp on port 8080

```
proxify -http-proxy http://127.0.0.1:8080
```

From burp, set the Upstream Proxy to forward all the traffic back to `proxify`

```
User Options > Upstream Proxy > Proxy & Port > 127.0.0.1 & 8888
```
Now all the request/response history will be stored in `logs` folder that can be used later for post processing.

</details>


<details>
<summary>👉 Store all your browse history locally. </summary>


While you browse the application, you can point the browser to `proxify` to store all the HTTP request / response to file.

Start proxify on default or any port you wish,

```
proxify -output chrome-logs
```

Start Chrome browser in Mac OS,
```
/Applications/Chromium.app/Contents/MacOS/Chromium --ignore-certificate-errors --proxy-server=http://127.0.0.1:8888 &
```

</details>

<details>
<summary>👉 Store all the response of while you fuzz as per you config at run time. </summary>


Start proxify on default or any port you wish,

```
proxify -output ffuf-logs
```

Run `FFuF` with proxy pointing to `proxify`

```
ffuf -x http://127.0.0.1:8888 FFUF_CMD_HERE
```

</details>

------

Proxify is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/proxify/blob/master/THANKS.md)** file for more details.
