package protocol

// crc16 is CRC-16/XMODEM: polynomial 0x1021, init 0, no reflection, no final
// XOR (spec §5). It equals Python's binascii.crc_hqx(data, 0).
func crc16(data []byte) uint16 {
	var c uint16
	for _, b := range data {
		c ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}

func appendCRC(b []byte) []byte {
	c := crc16(b)
	return append(b, byte(c>>8), byte(c))
}

func crcOK(b []byte) bool {
	n := len(b)
	return n >= 2 && crc16(b[:n-2]) == uint16(b[n-2])<<8|uint16(b[n-1])
}
