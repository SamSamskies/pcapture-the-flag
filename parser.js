// http://blog.paracode.com/2013/04/24/parsing-binary-data-with-node-dot-js/
// https://github.com/substack/node-binary

const fs = require('fs')
const binary = require('binary')

const file = fs.readFileSync('net.cap')
const packets = getPackets(file)

console.log(getFileHeader(file))
console.log('packets.length', packets.length);

function getFileHeader(file) {
  return binary.parse(file)
    .word32lu('magicNumber')
    .word16lu('majorVersion')
    .word16lu('minorVersion')
    .word32lu('tzOffset')
    .word32lu('tzAccuracy')
    .word32lu('snapshotLength')
    .word32lu('linkType')
    .tap((vars) => vars.magicNumber = vars.magicNumber.toString(16))
    .vars
}

function getPackets(file) {
  const packets = []

  binary.parse(file)
    .skip(24)
    .loop(function (endSeg, vars) {
      if (this.eof()) {
        endSeg()
      }

      this.skip(8)
        .word32lu('packetLength')
        .buffer('packet', vars.packetLength)
        .tap(function (vars) {
          if (vars.packetLength === null) {
            return
          }

          packets.push(vars.packet)
        })
        .skip(4)
    })

  return packets
}

function getEthernetHeader(packet) {

}

function getIpHeader(packet) {

}

function getTcpHeader(packet) {

}

function getHttpHeader(packet) {

}
