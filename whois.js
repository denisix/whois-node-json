const net = require('net')
const iana = require('./iana.json')

const req = async (domain, whoisServer = 'whois.verisign-grs.com', timeout = 10000) => {
  const buf = await new Promise(r => {
    const s = net.connect({ host: whoisServer, port: 43 }, () => {
      let b = Buffer.alloc(0)
      s.setTimeout(timeout)
        .on('timeout', s.end)
        .on('data', c => (b = Buffer.concat([b, c])))
        .on('end', () => r(b))
        .on('error', e => r(e))
        .write(domain + '\n')
    })
  })

  return buf.toString()
}

const map = {
  domain_status: 'status',
  name_server: 'ns',
  creation_date: 'date_created',
  updated_date: 'date_updated',
  organisation: 'org',
  orgname: 'org',
  asname: 'as_name',
  ashandle: 'aut_num',
  asnumber: 'aut_num',
  netrange: 'inetnum'
}

const parseDomain = raw => {
  const o = { raw }
  let ok = false
  raw.split('\n').forEach(i => {
    const m = i.trim().match(/^(\w.{1,50}):\s+(\S.+)$/)
    if (m && m[1] && m[2]) {
      let k = m[1].toLowerCase().replace(/[\s/\-.]+/g, '_')
      if (k === 'domain_name') ok = true
      if (k === 'domain_name' || k === 'dnssec' || k === 'notice' || k === 'note' || k.match(/under_no_circumstances_will_you|terms_of_use|url_of_the|_privacy_|_complaint_/)) return

      let v = m[2].replace(/[\s(]+https?:\/\/www.icann.org.*/, '').trim()
      if (k === 'domain_status') v = v.split(' ')[0]
      if (v === 'DATA REDACTED' || v === 'Non-Public Data' || (v.match(/REDACTED/i) && v.match(/PRIVACY/i))) v = ''
      if (parseInt(v, 10) === +v) v = +v
      if (k.match(/_date$/)) v = +new Date(v) / 1000
      if (k.match(/expir/) && k.match(/date/)) k = 'date_exp'
      if (k.match(/_email$/) && v.match(/https?:\/\//)) v = ''
      if (map[k]) k = map[k]
      if (o[k]) {
        if (typeof o[k] !== 'object') o[k] = [o[k]]
        o[k].push(v)
      } else {
        o[k] = v
      }
    }
  })

  if (o.ns) {
    if (typeof o.ns === 'object') {
      o.ns = o.ns.map(i => i.toLowerCase()).sort()
    } else {
      o.ns = o.ns.toLowerCase()
    }
  }

  if (!Object.keys(o).length) {
    if (raw.match(/No match/i)) {
      o.free = true
    } else {
      return false
    }
  }

  if (!ok) return false

  return o
}

const parseBlocks = raw => {
  let m,
    k,
    v,
    main = { raw },
    o = {}

  const lines = raw.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i],
      okeys = Object.keys(o)

    // empty lines -> end blocks
    if (line === '' && okeys.length) {
      k = okeys[0]
      if (main[k]) {
        if (!main[k][0]) main[k] = [main[k]]
        main[k].push(o)
      } else {
        main[k] = o
      }
      o = {}
    } else if (line.match(/^Abuse contact for/)) {
      // abuse contacts
      m = line.match(/is '([^']+)'/)
      if (m && m[1]) o.abuse_mailbox = m[1]
    } else {
      // key-values
      m = line.trim().match(/^([\w-]{3,50}):\s+(\S.+)$/)
      if (m && m[2]) {
        k = m[1].toLowerCase().replace(/[\s/\-.]+/g, '_')
        v = m[2].trim()
        if (map[k]) k = map[k]
        if (o[k]) {
          if (typeof o[k] !== 'object') o[k] = [o[k]]
          o[k].push(v)
        } else {
          o[k] = v
        }
        if (k === 'aut_num') o[k] = +v.replace(/as/i, '')
      }
    }
  }

  return main
}

const whois = async (q, timeout = 10000) => {
  let whoisServer, prevWhois, raw, rir, isBlock, isCIDR, m

  // ASN
  m = q.match(/^as(\d+)$/i)
  if (m && m[1]) {
    isBlock = true
    rir = Object.keys(iana).find(i => {
      if (iana[i].includes(m[1])) return true
      iana[i].find(x => {
        if (typeof x !== 'string') return false
        if (x === m[1]) return true

        const r = x.split('-')
        if (+r[0] <= +m[1] && +m[1] <= +r[1]) return true
      })
    })

    whoisServer = rir ? `whois.${rir}.net` : 'whois.iana.org'
  } else {
    // IPv4
    m = q.match(/^(\d+)\.\d+\.\d+\.\d+(\/?\d*)/)
    if (m && m[1]) {
      isBlock = true
      isCIDR = !!m[2]
      rir = Object.keys(iana).find(i => iana[i].includes(+m[1]))
      whoisServer = rir ? `whois.${rir}.net` : 'whois.iana.org'
    } else {
      // IPv6
      m = q.match(/^([a-fA-F0-9:]+)(\/?)/)
      if (m && m[1]) {
        isBlock = true
        isCIDR = !!m[2]

        const ip = m[1]
          .replace('::', ':0000:')
          .split(':')
          .reduce((a, b, c) => {
            if (c > 1) return a
            const out = parseInt(b, 16).toString(2)
            return a + new Array(16 - out.length).fill(0).join('') + out
          }, '')

        const rir = Object.keys(iana).find(i =>
          iana[i].find(n => {
            if (typeof n !== 'string') return
            let [net, pref] = n.split('/')
            if (!pref) return
            net = parseInt(net, 16).toString(2)
            net = new Array((net.length > 16 ? 32 : 16) - net.length).fill(0).join('') + net
            return ip.startsWith(net)
          })
        )

        whoisServer = rir ? `whois.${rir}.net` : 'whois.iana.org'
      }
    }
  }

  do {
    prevWhois = whoisServer
    if (isCIDR && whoisServer.indexOf('arin') > -1) q = 'r = ' + q
    raw = await req(q, whoisServer, timeout)

    if (!raw || !raw.length || raw.length < q.length * 3 || raw.match(/try again/i)) return false

    const m = raw.match(/whois(\s*server|):\s+([\w\d.-]+)/i)
    if (m && m[2]) whoisServer = m[2].toLowerCase()
  } while (whoisServer && whoisServer !== prevWhois)

  // parse
  if (raw) return isBlock ? parseBlocks(raw) : parseDomain(raw)

  return false
}

module.exports = whois
