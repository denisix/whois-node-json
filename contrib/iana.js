const fs = require('fs')

// required files - download from IANA:
// https://data.iana.org/rdap/asn.json
// https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv

const asn = require('./asn.json')
const raw = fs.readFileSync('ipv4-address-space.csv').toString()

const map = {}
raw.split('\n').forEach(i => {
  const a = i.split(',')
  let k = a[3]
  if (k?.startsWith('whois')) {
    k = k.split('.')[1]
    map[k] || (map[k] = [])
    map[k].push(+a[0].split('/')[0])
  }
})

asn.services.forEach(i => {
  const k = i[1][0].match(/(\w+)\.net/)[1]
  map[k].push(...i[0])
})

// afrinic AS33764 doesnt exists (it's a fork from RIPE):
map.afrinic.push('33764')

fs.writeFileSync('../iana.json', JSON.stringify(map))
