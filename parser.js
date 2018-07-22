// http://blog.paracode.com/2013/04/24/parsing-binary-data-with-node-dot-js/
// https://github.com/substack/node-binary

const fs = require('fs')
const binary = require('binary')

const file = fs.readFileSync('net.cap')
const packets = getPackets(file)
const fileHeader = getFileHeader(file)

console.log(parseFileHeader(fileHeader))
console.log('packets.length', packets.length);

const firstEthernetHeader = getEthernetHeader(packets[0])

console.log(firstEthernetHeader)
console.log(parseEthernetHeader(firstEthernetHeader))
console.log('All packets have same format: ', verifyAllPacketsHaveSameIpFormat(packets))

function getFileHeader(file) {
  return file.slice(0, 24)
}

function parseFileHeader(fileHeader) {
  return binary.parse(fileHeader)
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

// https://en.wikipedia.org/wiki/Ethernet_frame
function getEthernetHeader(packet) {
  return packet.slice(0, 18)
}

// what is preamble? Wireshark doesn't include it.
function parseEthernetHeader(ethernetHeader) {
  const humanizeMacAddress = (buf) => [...buf.values()].map((x) => x.toString(16)).join(':')

  return {
    destination: humanizeMacAddress(ethernetHeader.slice(4, 10)),
    source: humanizeMacAddress(ethernetHeader.slice(10, 16)),
    type: ethernetHeader.slice(16, 18).toString('hex') === '0800' ? 'IPv4' : 'IPv6'
  }
}

function verifyAllPacketsHaveSameIpFormat(packets) {
  const type = parseEthernetHeader(getEthernetHeader(packets[0])).type

  return packets.every((p) => parseEthernetHeader(getEthernetHeader(p)).type === type)
}

// https://en.wikipedia.org/wiki/IPv4#Header
function getIpHeader(packet) {

}

// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
function getTcpHeader(packet) {

}

function getHttpHeader(packet) {

}

function getIpVersion(packets) {
  // throw error if not all the same ip version
}

function getMacAddresses(packets) {
  // verify only two unique MAC addresses
}
