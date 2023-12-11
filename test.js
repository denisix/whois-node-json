const whois = require('./')

const tests = [
  ['google.com', i => false || i?.registrant_organization === 'Google LLC'],
  ['facebook.com', i => false || i?.admin_email === 'domain@fb.com'],

  // RIPE
  ['AS3333', i => i?.aut_num?.aut_num === 3333 && i?.aut_num?.as_name === 'RIPE-NCC-AS'],
  ['193.0.0.0', i => i?.inetnum?.netname === 'RIPE-NCC'],
  ['193.0.0.0/21', i => i?.inetnum?.netname === 'RIPE-NCC'],
  ['2001:67c:2e8:22::c100:68b', i => i?.inet6num?.netname === 'RIPE-NCC-NET'],
  ['2001:67c:2e8::/48', i => i?.inet6num?.netname === 'RIPE-NCC-NET'],
  ['ORG-RIEN1-RIPE', i => i?.org?.email === 'ncc@ripe.net'],

  // ARIN
  ['AS394018', i => i?.aut_num?.aut_num === 394018 && i?.aut_num?.as_name === 'ARIN-PFS-SEA'],
  ['199.5.26.46', i => i?.inetnum?.netname === 'ARIN-PFS-SEA'],
  ['199.5.26.0/24', i => i?.inetnum?.netname === 'ARIN-PFS-SEA'],
  ['2001:500:a9::46', i => i?.inetnum?.netname === 'ARIN-PFS-SEA-1'],
  ['2001:500:A9::/48', i => i?.inetnum?.netname === 'ARIN-PFS-SEA-1'],
  ['7ESG', i => i?.org?.org === 'Air Force Systems Networking'],

  // APNIC
  ['AS4608', i => i?.aut_num?.aut_num === 4608 && i?.aut_num?.as_name === 'APNIC-SERVICES'],
  ['203.119.101.0', i => i?.inetnum?.netname === 'APNIC-SERVICES-AU'],
  ['203.119.101.0/24', i => i?.inetnum?.netname === 'APNIC-SERVICES-AU'],
  ['2001:dd8:9:2::101:61', i => i?.inet6num?.netname === 'APNIC-SERVICES-AU'],
  ['2001:dd8:9::/48', i => i?.inet6num?.netname === 'APNIC-SERVICES-AU'],
  ['ORG-SPL5-AP', i => i?.org?.email === 'dcinfo@sententia.com.au'],

  // LACNIC
  ['as28001', i => i?.aut_num?.aut_num === 28001 && i?.aut_num?.ownerid === 'UY-LACN-LACNIC'],
  ['200.3.12.0', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],
  ['200.3.12.0/22', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],
  ['2001:13c7:7001:110::15', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],
  ['2001:13c7:7001::/48', i => i?.inetnum?.ownerid === 'UY-LACN-LACNIC'],
  ['AR-CGVI1-LACNIC', i => i?.nic_hdl?.email === 'wschiavone@ceviamonte.com.ar'],

  // AFRINIC
  ['AS33764', i => i?.aut_num?.aut_num === 33764 && i?.aut_num?.as_name === 'AFRINIC-ZA-JNB-AS'],
  ['196.216.2.0', i => i?.inetnum?.netname === 'AFRINIC'],
  ['196.216.2.0/23', i => i?.inetnum?.netname === 'AFRINIC'],
  ['2001:42d0:0:201::20', i => i?.inet6num?.netname === 'AFRINIC-Ops'],
  ['2001:42d0::/40', i => i?.inet6num?.netname === 'AFRINIC-Ops'],
  ['ORG-GTBP1-AFRINIC', i => i?.org?.email.includes('networksupport@gtbank.com')],
]

if (process.argv[2]) return whois(process.argv[2]).then(ret => console.log('ret ->', ret))

tests.forEach(([q, f]) => {
  whois(q).then(ret => console.log(`- query [${q}] ->`, f(ret) || ret))
})
