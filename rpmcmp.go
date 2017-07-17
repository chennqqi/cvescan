package cvescan

/*
#include "rpm.hxx"
*/
import "C"
import (
	"unsafe"
)

/*
	@brief compare pire of rpm version a and b
	@return
		if a>b return 1
		if a==b return 0
		if a<b return -1
*/
func RpmCompare(a, b string) int {
	pva := &C.EVR{}
	pvb := &C.EVR{}
	// go initialized memory no need free
	//	defer C.free(unsafe.Pointer(pva))
	//	defer C.free(unsafe.Pointer(pvb))

	pStrA := C.CString(a)
	defer C.free(unsafe.Pointer(pStrA))
	pStrB := C.CString(b)
	defer C.free(unsafe.Pointer(pStrB))

	C.parseEVR(pStrA, pva)
	C.parseEVR(pStrB, pvb)

	return int(C.rpmVersionCompare(pva, pvb))
}
