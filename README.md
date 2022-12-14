![NPM](https://img.shields.io/npm/l/whois-node-json?style=flat-square)
![npm bundle size](https://img.shields.io/bundlephobia/min/whois-node-json?style=flat-square)
![GitHub package.json version](https://img.shields.io/github/package-json/v/denisix/whois-node-json?style=flat-square)
![Lines of code](https://img.shields.io/tokei/lines/github/denisix/whois-node-json?style=flat-square)

# whois-node-json
Whois-Node-JSON - WHOIS fetch &amp; output in JSON, slim &amp; fast, without any dependencies

## Features
- **zero** dependencies!
- raw whois client from scratch
- as fast as possible!
- built-in whois parser that outputs **JSON** structured data!
- pre-bootstraped IANA RIRs ASNs / network prefixes / whoises map to make requests even faster!
- retries & timeouts
- automatically follows refering whois servers
- supports **domain** / **ASN** / **networks** queries
- supports **IPv6** resources

## API
- as simple as possible, query can be any domain, ASN or IPv4 address/network:
```js
const whois = require('whois-node-json')

whois('google.com').then(result => console.log('domain whois:', result))
whois('AS3333').then(result => console.log('asn whois:', result))
whois('193.0.0.0/21').then(result => console.log('network whois:', result))
whois('2001:67c:2e8:22::c100:68b').then(result => console.log('network ipv6:', result))
```

## Examples
More examples can be found in [test.js](https://github.com/denisix/whois-node-json/blob/main/test.js).

## Tests
Please ensure you have stable internet connectivity and run:
```js
npm run test
```

#whois #whois-json #whois-query #whois-client #whois-as #whois-network
