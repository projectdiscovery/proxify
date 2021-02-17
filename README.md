<h1 align="center">
  <img src="static/proxify-logo.png" alt="proxify" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/proxify)](https://goreportcard.com/report/github.com/projectdiscovery/proxify)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/proxify/issues)
[![Follow on Twitter](https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter)](https://twitter.com/pdiscoveryio)
[![Chat on Discord](https://img.shields.io/discord/695645237418131507.svg?logo=discord)](https://discord.gg/KECAGdH)

Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy.
Additionally a replay utility allows to import the dumped traffic (request/responses with correct domain name) into burp or any other proxy by simply setting the upstream proxy to proxify.

# Resources

- [Features](#features)
- [Installation](#installation)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
    - [From Github](#from-github)
- [Usage](#usage)
    - [Use Upstream proxy](#use-upstream-proxy)
    - [Dump all the HTTP/HTTPS traffic](#dump-all-the-httphttps-traffic)
    - [Hostname mapping with Local DNS resolver](#hostname-mapping-with-local-dns-resolver)
    - [Match/Filter traffic with with DSL language.](#matchfilter-traffic-with-with-dsl-language)
    - [Match and Replace on the fly](#match-and-replace-on-the-fly)
    - [Replay all traffic into burp](#replay-all-traffic-into-burp)
- [Installing SSL Certificate](#installing-ssl-certificate)
- [Applications of Proxify](#applications-of-proxify)

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

### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/proxify/releases/) page. Extract them using tar, move it to your `$PATH`and you're ready to go.

```sh
▶ tar -xvf proxify-linux-amd64.tar
▶ mv proxify-linux-amd64 /usr/local/bin/proxify
▶ proxify -version
```

**proxify** requires **go1.14+** to install successfully. Run the following command to get the repo -

### From Source

```sh
▶ GO111MODULE=on go get -v github.com/projectdiscovery/proxify/cmd/proxify
```

### From Github

```sh
▶ git clone https://github.com/projectdiscovery/proxify.git; cd proxify/cmd/proxify; go build; cp proxify /usr/local/bin; proxify -version
```

# Usage

```sh
▶ proxify -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag                       | Description                     | Example                                                      |
| -------------------------- | ------------------------------- | ------------------------------------------------------------ |
| addr                       | Listen HTTP IP and Port         | proxify -addr 127.0.0.1:8080                                 |
| config                     | Config data path                | proxify -config certs                                        |
| cert-cache-size            | Number of certificates to cache | proxify -cert-cache-size 1024                                |
| dns-addr                   | Listen DNS IP and Port          | proxify -dns-addr '127.0.0.1:80'                             |
| dns-mapping                | DNS A mapping                   | proxify -dns-mapping test.com:80                             |
| dns-resolver               | Listen DNS IP and Port          | proxify -dns-resolver '127.0.0.1:5353'                       |
| http-proxy                 | Upstream HTTP Proxy             | proxify -http-proxy hxxp://127.0.0.1:8080                    |
| no-color                   | No Color in output              | proxify -no-color                                            |
| output                     | Output Folder                   | proxify -output logs                                         |
| request-dsl                | Request Filter DSL              | proxify -request-dsl "contains(request,'admim')"             |
| request-match-replace-dsl  | Request Match-Replace DSL       | proxify -request-match-replace-dsl "replace(request,'false','true')" |
| response-dsl               | Response Filter DSL             | proxify -response-dsl "contains(response, md5('test'))"      |
| response-match-replace-dsl | Response Match-Replace DSL      | proxify -response-match-replace-dsl "regex(response, '^authentication failed$', 'authentication ok')" |
| silent                     | Silent output                   | proxify -silent                                              |
| socks5-proxy               | Upstream socks5 proxy           | proxify -socks5-proxy socks5://proxy-ip:port                 |
| v                          | Verbose output                  | proxify -v                                                   |
| version                    | Current version                 | proxify -version                                             |


### Use Upstream proxy


Open a local proxy on port 8081 and forward the traffic to burp on port 8080

```sh
▶ proxify -addr ":8081" -http-proxy http://127.0.0.1:8080
```

Open a local proxy on port 8080 and forward the traffic to the TOR network
```sh
▶ proxify -socks5-proxy socks5://127.0.0.1:9050
```

### Dump all the HTTP/HTTPS traffic

Dump all the traffic into separate files with request followed by the response, as default `proxify` listen to `http://127.0.0.0:8080`. Custom address and port can be defined using `addr` flag.

As default, proxied request/resposed are stored in the `logs` folder.


```sh
▶ proxify -output db
```


### Hostname mapping with Local DNS resolver

Proxify supports embedding DNS resolver to map hostnames to specific addresses and define an upstream dns server for any other domain name

start a local http proxy on port 8080 using an embedded dns server listening on port 53 and resolving www.google.it to 192.168.1.1, all other fqdn are forwarded upstream to 1.1.1.1
```sh
▶ proxify -dns-addr ":53" -dns-mapping "www.google.it:192.168.1.1" -dns-resolver "1.1.1.1:53"
```

This feature is used for example by the `replay` utility to hijack the connections and simulate responses. It may be useful during internal assessments with private dns servers. Using `*` as domain name matches all dns requests.

### Match/Filter traffic with with DSL language.

If the request or response match the filters the dump is tagged with `.match.txt` suffix:

```sh
▶ proxify -request-dsl "contains(request,'firefox')" -response-dsl "contains(response, md5('test'))"
```

### Match and Replace on the fly

Proxify supports modifying Request and Responses on the fly with DSL language.

```sh
▶ proxify -request-match-replace-dsl "replace(request,'firefox','chrome')" -response-match-replace-dsl "regex(response, '^authentication failed$', 'authentication ok')"
```

### Replay all traffic into burp

Replay all the dumped requests/responses into the destination URL (http://127.0.0.1:8080) if not specified. For this to work it's necessary to configure burp to use proxify as upstream proxy, as it will take care to hijack the dns resolutions and simulate the remote server with the dumped request. This allows to have in the burp history exactly all requests/responses as if they were originally sent through it, allowing for example to perform a remote interception on cloud, and merge all results locally within burp.

```sh
▶ replay -output "logs/"
```

### Installing SSL Certificate

A certificate authority is generated for proxify which is stored in the folder `~/.config/proxify/` as default, manually can be specified by `-config` flag. The generated certificate can be imported by visiting [http://proxify/cacert.crt](http://proxify/cacert.crt) in a browser connected to proxify. 

Installation steps for the Root Certificate is similar to other proxy tools which includes adding the cert to system trusted root store.

### Applications of Proxify

Proxify can be used for multiple places, here are some common example where Proxify comes handy:-

<details>
<summary> Storing all the burp proxy history logs locally. </summary>

Start a proxify on port `8081` with HTTP Proxy pointing to burp suite port `8080`

```
proxify -addr "127.0.0.1:8081" -http-proxy "http://127.0.0.1:8080"
```

From burp, set the Upstream Proxy to forward all the traffic back to `proxify`

```
User Options > Upstream Proxy > Proxy & Port > 127.0.0.1 & 8081
```
Now all the request/response history will be stored in `logs` folder that can be used later for post processing.

</details>


<details>
<summary> Store all your browse histroy locally. </summary>


While you browse the application, you can point the browser to `proxify` to store all the HTTP request / response to file.

Start proxify on default or any port you wish,

```
proxify -output chrome-logs -addr ":9999"
```

Start Chrome browser in Mac OS,
```
/Applications/Chromium.app/Contents/MacOS/Chromium --ignore-certificate-errors --proxy-server=http://127.0.0.1:9999 &
```

</details>

<details>
<summary> Store all the response of while you fuzz as per you config at run time. </summary>


Start proxify on default or any port you wish,

```
proxify -output ffuf-logs -addr ":9999"
```

Run `FFuF` with proxy pointing to `proxify`

```
ffuf -x http://127.0.0.1:9999 FFUF_CMD_HERE
```

</details>


Proxify is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/proxify/blob/master/THANKS.md)** file for more details.
