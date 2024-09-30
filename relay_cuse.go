package tpmproxy

/*
#cgo LDFLAGS: -lfuse
#cgo CFLAGS: -D_FILE_OFFSET_BITS=64

#include <fuse/cuse_lowlevel.h>
#include <errno.h>

typedef struct cuse_info CUSE_INFO;
typedef struct fuse_file_info FUSE_FILE_INFO;
typedef const char cchar_t;

extern void CuseTpmOpen(fuse_req_t req, struct fuse_file_info *fi);
extern void CuseTpmRead(fuse_req_t req, size_t size, off_t off, struct fuse_file_info *fi);
extern void CuseTpmWrite(fuse_req_t req, cchar_t *buf, size_t size, off_t off, struct fuse_file_info *fi);

static const struct cuse_lowlevel_ops operations = {
	.open  = CuseTpmOpen,
	.read  = CuseTpmRead,
	.write = CuseTpmWrite,
};

static int cuse_main(int argc, char **argv, const CUSE_INFO ci) {
	return cuse_lowlevel_main(argc, argv, &ci, &operations, NULL);
}
*/
import "C"
import (
	"unsafe"
)

var (
	CuseForwarder Forwarder
)

func SetCuseForwarder(forwarder Forwarder) {
	CuseForwarder = forwarder
}

//export CuseTpmOpen
func CuseTpmOpen(req C.fuse_req_t, fi *C.FUSE_FILE_INFO) {
	C.fuse_reply_open(req, fi)
}

//export CuseTpmRead
func CuseTpmRead(req C.fuse_req_t, size C.size_t, off C.off_t, fi *C.FUSE_FILE_INFO) {
	if size == 0 {
		C.fuse_reply_err(req, C.EINVAL)
		return
	}

	buffer := make([]byte, size)
	nread, err := CuseForwarder.Read(buffer)
	if err != nil {
		C.fuse_reply_err(req, C.EIO)
		return
	}
	buffer = buffer[:nread]

	cbuf := unsafe.Pointer(&buffer[0])
	// log.Printf("read: %s\n", hex.EncodeToString(buffer))
	C.fuse_reply_buf(req, (*C.char)(cbuf), C.size_t(nread))
}

//export CuseTpmWrite
func CuseTpmWrite(req C.fuse_req_t, buf *C.cchar_t, size C.size_t, off C.off_t, fi *C.FUSE_FILE_INFO) {
	if size == 0 {
		C.fuse_reply_err(req, C.EINVAL)
		return
	}

	buffer := make([]byte, size)
	copy(buffer, C.GoBytes(unsafe.Pointer(buf), C.int(size)))
	nwrite, err := CuseForwarder.Write(buffer)
	if err != nil {
		C.fuse_reply_err(req, C.EIO)
		return
	}
	// log.Printf("write: %s\n", hex.EncodeToString(buffer))
	C.fuse_reply_write(req, C.size_t(nwrite))
}

// CuseRelay is a special relayer function that uses CUSE to relay TPM commands
// and responses.
// CuseRelay requires root privilege to run.
// It is a blocking function that will return when the relay is done.
// The devname is the device name that will be used to create the relay device.
// The devname must be a valid device name that can be used in the filesystem.
// The function will return the exit code of the relay.
func CuseRelay(devname string) int {
	argv := []*C.char{C.CString(""), C.CString("-f")} // foreground
	argc := C.int(len(argv))

	var ci C.CUSE_INFO
	ci.dev_major = 0
	ci.dev_minor = 0
	ci.dev_info_argc = 1
	c_dev_info_argv := []*C.char{C.CString("DEVNAME=" + devname)}
	ci.dev_info_argv = (**C.char)(unsafe.Pointer(&c_dev_info_argv[0]))
	ci.flags = 0
	ret := C.cuse_main(argc, (**C.char)(unsafe.Pointer(&argv[0])), ci)
	return int(ret)
}
