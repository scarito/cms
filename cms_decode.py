#!/usr/bin/python3
"""Provides functions to decode CMS telemetry data."""

import asyncio
import struct
import datetime
import sys
import time


CMS_DEFAULT_IP = '202.114.4.119'
CMS_PORT = 515

_SHOW_UNKNOWN = False


def _get_block(length, block_type, data):
    try:
        if block_type == 0x3E:
            return CmsDataBlock3E(length, data)
        if block_type == 0x43:
            return CmsDataBlock43(length, data)
        if block_type == 0x45:
            return CmsDataBlock45(length, data)
        if block_type == 0x46:
            return CmsDataBlock46(length, data)
        if block_type == 0x47:
            return CmsDataBlock47(length, data)
        if block_type == 0x49:
            return CmsDataBlock49(length, data)
        return CmsDataBlock(length, block_type, data)
    except AssertionError as e:
        data_str = " ".join(["%02x" % d for d in data])
        sys.stderr.write(f"Error during decode block type {block_type:02x} length {length:04x} "
                         f"data {data_str}\n")
        raise e


def cms_read_block_from_bytes(data, offset=0):
    length, = struct.unpack("<H", data[offset:offset+2])
    assert length >= 2
    hdr, block_type = struct.unpack("<BB", data[offset+2:offset+4])
    assert hdr == 0x05
    length -= 2
    data = data[offset+4:offset+4+length]
    return _get_block(length, block_type, data)


async def cms_read_block_from_stream(stream):
    length, = struct.unpack("<H", await stream.read(2))
    assert length >= 2
    hdr, block_type = struct.unpack("<BB", await stream.read(2))
    assert hdr == 0x05
    length -= 2
    data = await stream.read(length)
    return _get_block(length, block_type, data)


class CmsDataBlock:
    def __init__(self, length, block_type, data):
        self.length = length
        self.block_type = block_type
        self.data = data
        assert self.length == len(data)
        if not data:
            self.data = bytes()

    def __str__(self):
        data_str = " ".join(["%02x" % d for d in self.data])
        return f"message type {self.block_type:02x}, length {self.length:4x}, data: {data_str}"


class CmsDataBlock3E(CmsDataBlock):
    def __init__(self, length, data):
        def _decode(data):
            return data.decode().strip('\x00')

        super().__init__(length, 0x3E, data)
        self.values = {}
        self.unk = {}
        self.values['department'] = _decode(data[0x0:0x20])
        assert data[0x20] == 0 and data[0x21] == 0
        self.values['bed'] = int(data[0x22])
        self.values['patient_name'] = _decode(data[0x23:0x43])
        self.values['patient_number'] = _decode(data[0x43:0x63])
        admit_year = int(_decode(data[0x63:0x68]))
        admit_month = int(_decode(data[0x68:0x6B]))
        admit_day = int(_decode(data[0x6B:0x6E]))
        self.values['admit_date'] = datetime.date(admit_year, admit_month, admit_day)
        for i in range(0x6E, 0x74):
            assert data[i] == 0, i
        height, weight = struct.unpack("<HH", data[0x74:0x78])
        self.values['height_m'] = height / 1000
        self.values['weight_kg'] = weight / 10
        self.unk['unk_78'] = " ".join("%02x" % d for d in data[0x78:0x7C])
        birth_year = int(_decode(data[0x7C:0x81]))
        birth_month = int(_decode(data[0x81:0x84]))
        birth_day = int(_decode(data[0x84:0x87]))
        self.values['birth_date'] = datetime.date(birth_year, birth_month, birth_day)
        for i in range(0x87, 0x8B):
            assert data[i] == 0, i
        self.values['blood_type'] = data[0x8C]
        self.values['doctor_name'] = _decode(data[0x8D:0xAD])
        for i in range(0xAD, len(data)):
            assert data[i] == 0, i

    def __str__(self):
        values_str = ", ".join([f"{name}: {val}" for name, val in sorted(self.values.items())])
        unk_str = "".join([f"\n  {name}: {val}" for name, val in sorted(self.unk.items())])
        if _SHOW_UNKNOWN:
            return (f"message type {self.block_type:02x} [patient_info], length {self.length:4x}, "
                    f"values: [{values_str}]\nunk:{unk_str}")
        else:
            return (f"message type {self.block_type:02x} [patient_info], length {self.length:4x}, "
                    f"values: [{values_str}]")


class CmsDataBlock43(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x43, data)
        assert len(data) == 0

    def __str__(self):
        return "block 43"


class CmsDataBlock45(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x45, data)
        assert len(data) == 4
        u1, u2, bed, u3 = struct.unpack("<BBBB", data)
        assert u1 == 0 and u2 == 0 and u3 == 0xFF
        self.bed = bed

    def __str__(self):
        return f"bed number: {self.bed}"


class CmsDataBlock46(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x46, data)
        u1, u2, self.lead, u3 = struct.unpack("<BBBB", data[0:4])
        assert u1 == 0 and u2 == 0 and u3 == 0
        self.leads = {}
        self.values = {}
        self.unk = {}

        if self.lead == 0x14:
            self._decode_lead_14(data)
        elif self.lead == 0x15:
            self._decode_lead_15(data)
        elif self.lead == 0x16:
            self._decode_lead_16(data)
        elif self.lead == 0x17:
            self._decode_lead_17(data)
        else:
            self.unk['unk_4'] = " ".join("%02x" % d for d in data[0x4:])

    def _decode_lead_14(self, data):
        self.leads['ecg1'] = [int(d) for d in data[0x4:0x104]]
        self.leads['ecg2'] = [int(d) for d in data[0x104:0x204]]
        self.leads['ecg3'] = [int(d) for d in data[0x204:0x304]]
        self.leads['resp'] = [int(d) for d in data[0x304:0x384]]
        hr, hr_valid, rr, rr_valid = struct.unpack("<BBBB", data[0x384:0x388])
        assert hr_valid == 0 or hr_valid == 255
        hr_valid = hr_valid == 0
        assert rr_valid == 0 or rr_valid == 255
        rr_valid = rr_valid == 0
        self.values['hr'] = hr if hr_valid else None
        self.values['hr_valid'] = hr_valid
        self.values['resp'] = rr if rr_valid else None
        self.values['resp_valid'] = rr_valid
        (self.unk['unk_388_f'], self.unk['unk_38c_f'], self.unk['unk_390_f']
         ) = struct.unpack("<fff", data[0x388:0x394])
        hr_max, hr_min, hr_alm, resp_max, resp_min, resp_alm = struct.unpack(
            "<HHHHHH", data[0x3A3:0x3AF])
        self.values['alarm/hr_max'] = hr_max
        self.values['alarm/hr_min'] = hr_min
        self.values['alarm/hr_set'] = hr_alm
        self.values['alarm/resp_max'] = resp_max
        self.values['alarm/resp_min'] = resp_min
        self.values['alarm/resp_set'] = resp_alm
        self.unk['unk_394'] = " ".join("%02x" % d for d in data[0x394:0x3A3])
        (self.unk['unk_3af_f'], self.unk['unk_3b3_f'], self.unk['unk_3b7_d'],
         self.unk['unk_3b9_f'], self.unk['unk_3bb_f'], self.unk['unk_3bf_d'],
         self.unk['unk_3c1_f'], self.unk['unk_3c5_f'], self.unk['unk_3c9_d']
         ) = struct.unpack("<ffHffHffH", data[0x3AF:0x3CD])
        pvc_max, pvc_min, pvc_alm = struct.unpack("<HHH", data[0x3CD:0x3D3])
        self.values['alarm/pvc_min'] = pvc_min
        self.values['alarm/pvc_max'] = pvc_max
        self.values['alarm/pvc_set'] = pvc_alm
        for i in range(0x3D3, len(data)):
            assert data[i] == 0

    def _decode_lead_15(self, data):
        self.leads['pleth'] = [int(d) for d in data[0x4:0x104]]
        spo2, spo2_attached, spo2_hr, spo2_valid = struct.unpack("<BBBB", data[0x104:0x108])
        assert spo2_attached == 0 or spo2_attached == 255
        spo2_attached = spo2_attached == 0
        assert spo2_valid == 0 or spo2_valid == 255
        spo2_valid = spo2_valid == 0
        if not spo2_valid:
            assert spo2 == 255 and spo2_hr == 255
        (spo2_min, spo2_max, spo2_alm, spo2_hr_min, spo2_hr_max, spo2_hr_alm
         ) = struct.unpack("<HHHHHH", data[0x108:0x114])
        self.values['spo2'] = spo2 if spo2_valid else None
        self.values['spo2_attached'] = spo2_attached
        self.values['spo2_hr'] = spo2_hr if spo2_valid else None
        self.values['spo2_valid'] = spo2_valid
        self.values['alarm/spo2_max'] = spo2_max
        self.values['alarm/spo2_min'] = spo2_min
        self.values['alarm/spo2_set'] = spo2_alm
        self.values['alarm/spo2_hr_max'] = spo2_hr_max
        self.values['alarm/spo2_hr_min'] = spo2_hr_min
        self.values['alarm/spo2_hr_set'] = spo2_hr_alm
        for i in range(0x114, len(data)):
            assert data[i] == 0

    def _decode_lead_16(self, data):
        (bp_year, bp_mon, bp_day, bp_hr, bp_min, bp_sec, bp_sys, bp_dia, bp_map
         ) = struct.unpack("<HBBBBBHHH", data[0x04:0x11])
        self.values['nibp_time'] = datetime.datetime(
            bp_year, bp_mon, bp_day, bp_hr, bp_min, bp_sec)
        self.values['nibp_sys'] = bp_sys
        self.values['nibp_dia'] = bp_dia
        self.values['nibp_map'] = bp_map
        (bp_sys_max, bp_sys_min, bp_sys_alm, bp_dia_max, bp_dia_min, bp_dia_alm,
         bp_map_max, bp_map_min, bp_map_alm) = struct.unpack("<HHHHHHHHH", data[0x11:0x23])
        self.values['alarm/bp_sys_max'] = bp_sys_max
        self.values['alarm/bp_sys_min'] = bp_sys_min
        self.values['alarm/bp_sys_set'] = bp_sys_alm
        self.values['alarm/bp_dia_max'] = bp_dia_max
        self.values['alarm/bp_dia_min'] = bp_dia_min
        self.values['alarm/bp_dia_set'] = bp_dia_alm
        self.values['alarm/bp_map_max'] = bp_map_max
        self.values['alarm/bp_map_min'] = bp_map_min
        self.values['alarm/bp_map_set'] = bp_map_alm
        for i in range(0x23, len(data)):
            assert data[i] == 0

    def _decode_lead_17(self, data):
        (t1, t2, td, t1_max, t1_min, t1_alm, t2_max, t2_min, t2_alm, td_max, td_min, td_alm
         ) = struct.unpack("<fffffHffHffH", data[0x04:0x2E])
        self.values['t1'] = t1
        self.values['t2'] = t2
        self.values['td'] = td
        self.values['alarm/t1_max'] = t1_max
        self.values['alarm/t1_min'] = t1_min
        self.values['alarm/t1_set'] = t1_alm
        self.values['alarm/t2_max'] = t2_max
        self.values['alarm/t2_min'] = t2_min
        self.values['alarm/t2_set'] = t2_alm
        self.values['alarm/td_max'] = td_max
        self.values['alarm/td_min'] = td_min
        self.values['alarm/td_set'] = td_alm
        for i in range(0x2E, len(data)):
            assert data[i] == 0

    def __str__(self):
        values_str = ", ".join([f"{name}: {val}" for name, val in sorted(self.values.items())])
        lead_str = "".join([f"\n  {name}: {val}" for name, val in sorted(self.leads.items())])
        unk_str = "".join([f"\n  {name}: {val}" for name, val in sorted(self.unk.items())])
        if _SHOW_UNKNOWN:
            return (f"message type {self.block_type:02x} [telemetry], length {self.length:4x}, "
                    f"lead_type: {self.lead:02x}, values: [{values_str}]\nleads:{lead_str}"
                    f"\nunk:{unk_str}")
        else:
            return (f"message type {self.block_type:02x} [telemetry], length {self.length:4x}, "
                    f"lead_type: {self.lead:02x}, values: [{values_str}]\nleads:{lead_str}")


class CmsDataBlock47(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x47, data)
        assert not data

    def __str__(self):
        return "message type 47 [synchronization?]"


class CmsDataBlock49(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x49, data)
        self.code = int(data[0])
        self.message = data[1:].decode()

    def __str__(self):
        return f"error code: {self.code:02x}, message: {self.message}"


async def _handle_cms(reader, writer):
    del writer  # unused
    ctime = time.time()
    print("Connection received")
    while True:
        print(f"t {time.time() - ctime:7.3f}  " + str(await cms_read_block_from_stream(reader)))


async def main():
    server = await asyncio.start_server(
        _handle_cms, CMS_DEFAULT_IP, CMS_PORT)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
