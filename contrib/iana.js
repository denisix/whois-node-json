const fs = require('fs')

// required files - download from IANA:
// https://data.iana.org/rdap/asn.json
// https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv
// https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv
const asn = require('./asn.json')
const ipv4 = fs.readFileSync('ipv4-address-space.csv').toString()
const ipv6 = fs.readFileSync('ipv6-unicast-address-assignments.csv').toString()

const map = {}

ipv4.split('\n').forEach(i => {
  const a = i.split(',')
  let k = a[3]
  if (k?.startsWith('whois')) {
    k = k.split('.')[1]
    map[k] || (map[k] = [])
    map[k].push(+a[0].split('/')[0])
  }
})

ipv6.split('\n').forEach(i => {
  const a = i.split(',')
  let k = a[3]
  if (k?.startsWith('whois')) {
    k = k.split('.')[1]
    if (k === 'iana') return
    let ip = a[0].split('/')
    ip[0] = ip[0]
      .replace('::', ':0000:')
      .split(':')
      .reduce((a, b, c) => {
        if (c > (ip[1] > 16 ? 1 : 0)) return a
        return a + new Array(4 - b.length).fill(0).join('') + b
      }, '')

    map[k] || (map[k] = [])
    map[k].push(ip.join('/'))
  }
})

asn.services.forEach(i => {
  const k = i[1][0].match(/(\w+)\.net/)[1]
  map[k].push(...i[0])
})

// afrinic AS33764 doesnt exists (it's a fork from RIPE):
map.afrinic.push('33764')

fs.writeFileSync('../iana.json', JSON.stringify(map))
