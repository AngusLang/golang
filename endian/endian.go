package endian

//got this from https://github.com/virtao

import (
	"unsafe"
)

const INT_SIZE int = int(unsafe.Sizeof(0))

func IsBigEndian() bool {
	
	var i int = 0x1

	bs := (*[INT_SIZE]byte)(unsafe.Pointer(&i))

	if bs[0] == 0 {

		return true

	} else {

		return false

	}
}
