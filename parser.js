// http://blog.paracode.com/2013/04/24/parsing-binary-data-with-node-dot-js/
// https://github.com/substack/node-binary

const fs = require('fs')
const binary = require('binary')

const file = fs.readFileSync('net.cap')
const packets = getPackets(file)
const fileHeader = getFileHeader(file)
const firstEthernetHeader = getEthernetHeader(packets[0])
const firstIpHeader = getIpHeader(packets[0])

console.log('Parsed file header:', parseFileHeader(fileHeader))
console.log('Number of packets:', packets.length);
console.log('First ethernet header:', firstEthernetHeader)
console.log('First ethernet header parsed:', parseEthernetHeader(firstEthernetHeader))
console.log('All packets have same format:', verifyAllPacketsHaveSameIpFormat(packets))
console.log('Unique MAC addresses:', getUniqueMacAddresses(packets))
console.log('First IP header:', firstIpHeader)

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
  const parsedEthernetHeaders = packets.map((p) => parseEthernetHeader(getEthernetHeader(p)))

  return parsedEthernetHeaders.every(({ type }) => type === parsedEthernetHeaders[0].type)
}

function printMacAddresses(packets) {
  const parsedEthernetHeaders = packets.map((p) => parseEthernetHeader(getEthernetHeader(p)))

  parsedEthernetHeaders.forEach(({ source, destination }) => {
    console.log(`source: ${source}\tdestination: ${destination}`)
  })
}

function getUniqueMacAddresses(packets) {
  const uniqueMacAddresses = new Set()

  packets.forEach((p) => {
    const { source, destination } = parseEthernetHeader(getEthernetHeader(p))

    uniqueMacAddresses.add(source)
    uniqueMacAddresses.add(destination)
  })

  return Array.from(uniqueMacAddresses)
}

// https://en.wikipedia.org/wiki/IPv4#Header
function getIpHeader(packet) {
  return packet.slice(18, 38)
}

// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
function getTcpHeader(packet) {

}

function getHttpHeader(packet) {

}
