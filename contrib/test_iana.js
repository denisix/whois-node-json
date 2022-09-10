const iana = require('./iana.json')

const as2rir = as =>
  Object.keys(iana).find(i =>
    iana[i].find(x => {
      if (typeof x !== 'string') return false
      if (x === as) return true

      const r = x.split('-')
      if (+r[0] <= +as && +as <= +r[1]) return true
    })
  )

console.log(process.argv[2], as2rir(process.argv[2]))
