const whois = require('./')

const tests = [
  ['google.com', i => i?.registrant_organization === 'Google LLC'],

  // RIPE
  ['193.0.0.0/21', i => i?.inetnum?.netname === 'RIPE-NCC'],
  ['AS3333', i => i?.aut_num?.aut_num === 3333 && i?.aut_num?.as_name === 'RIPE-NCC-AS'],
  ['2001:67c:2e8:22::c100:68b', i => i?.inet6num?.netname === 'RIPE-NCC-NET'],

  // ARIN
  ['199.5.26.46', i => i?.inetnum?.netname === 'ARIN-PFS-SEA'],
  ['AS394018', i => i?.aut_num?.aut_num === 394018 && i?.aut_num?.as_name === 'ARIN-PFS-SEA'],
  ['2001:500:a9::46', i => i?.inetnum?.netname === 'ARIN-PFS-SEA-1'],

  // APNIC
  ['203.119.101.0/24', i => i?.inetnum.netname === 'APNIC-SERVICES-AU'],
  ['AS4608', i => i?.aut_num?.aut_num === 4608 && i?.aut_num?.as_name === 'APNIC-SERVICES'],
  ['2001:dd8:9:2::101:61', i => i?.inet6num?.netname === 'APNIC-SERVICES-AU'],

  // LACNIC
  ['200.3.12.0/22', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],
  ['as28001', i => i?.aut_num?.aut_num === 28001 && i?.aut_num?.ownerid === 'UY-LACN-LACNIC'],
  ['2001:13c7:7001:110::15', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],

  // AFRINIC
  ['196.216.2.0/23', i => i?.inetnum?.netname === 'AFRINIC'],
  ['AS33764', i => i?.aut_num?.aut_num === 33764 && i?.aut_num?.as_name === 'AFRINIC-ZA-JNB-AS'],
  ['2001:42d0:0:201::20', i => i?.inet6num?.netname === 'AFRINIC-Ops']
]

if (process.argv[2]) return whois(process.argv[2]).then(ret => console.log('ret ->', ret))

tests.forEach(([q, f]) => {
  whois(q).then(ret => console.log(`- query [${q}] ->`, f(ret) || ret))
})
