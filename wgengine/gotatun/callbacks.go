// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_use_gotatun && cgo

package gotatun

/*
#include "rust/gotatun_ffi.h"
*/
import "C"

import (
	"unsafe"
)

// These are Go functions exported to C, called by the Rust FFI layer.
// They bridge gotatun's I/O back into Go's tstun.Wrapper and magicsock.

//export gotatun_tun_read_cb
func gotatun_tun_read_cb(buf *C.uint8_t, buf_len C.int32_t, ctx unsafe.Pointer) C.int32_t {
	// TODO: Call into tstun.Wrapper.Read()
	// For now, return -1 (not yet connected)
	return -1
}

//export gotatun_tun_write_cb
func gotatun_tun_write_cb(buf *C.uint8_t, buf_len C.int32_t, ctx unsafe.Pointer) C.int32_t {
	// TODO: Call into tstun.Wrapper.Write()
	// For now, return -1 (not yet connected)
	return -1
}

//export gotatun_udp_send_cb
func gotatun_udp_send_cb(buf *C.uint8_t, buf_len C.int32_t, endpoint *C.uint8_t, endpoint_len C.int32_t, ctx unsafe.Pointer) C.int32_t {
	// TODO: Call into magicsock.Conn.Send()
	// For now, return -1 (not yet connected)
	return -1
}

//export gotatun_udp_recv_cb
func gotatun_udp_recv_cb(buf *C.uint8_t, buf_len C.int32_t, endpoint_buf *C.uint8_t, endpoint_buf_len C.int32_t, endpoint_len_out *C.int32_t, ctx unsafe.Pointer) C.int32_t {
	// TODO: Call into magicsock.Conn.Recv()
	// For now, return -1 (not yet connected)
	return -1
}

//export gotatun_log_cb
func gotatun_log_cb(level C.int32_t, msg *C.char, msg_len C.int32_t, ctx unsafe.Pointer) {
	cbID := uintptr(ctx)
	cs := lookupCallback(cbID)
	if cs == nil || cs.logf == nil {
		return
	}

	goMsg := C.GoStringN(msg, msg_len)
	if filterLogLine(goMsg) {
		return
	}

	prefix := logLevelPrefix(int(level))
	cs.logf("%s%s", prefix, goMsg)
}
