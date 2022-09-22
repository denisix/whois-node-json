const iana = require('../iana.json')

const v6whois = v6 => {
  const ip = v6
    .replace('::', ':0000:')
    .split(':')
    .reduce((a, b, c) => {
      if (c > 1) return a
      const out = parseInt(b, 16).toString(2)
      return a + new Array(16 - out.length).fill(0).join('') + out
    }, '')

  console.log('- ip ->', ip)

  const rir = Object.keys(iana).find(i =>
    iana[i].find(n => {
      if (typeof n !== 'string') return
      let [net, pref] = n.split('/')
      if (!pref) return
      net = parseInt(net, 16).toString(2)
      net = new Array((net.length > 16 ? 32 : 16) - net.length).fill(0).join('') + net
      // console.log('- net->', net, pref, net.length)
      // console.log('- ip ->', ip, '->', ip.startsWith(net), '\n')
      return ip.startsWith(net)
    })
  )

  console.log('- rir ->', rir)
}

v6whois('2001::10:0:1:100')
