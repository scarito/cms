import asyncio
import struct
import datetime
import sys
import time

SHOW_UNKNOWN = False

class CmsDataBlock:
    def __init__(self, length, type, data):
        self.length = length
        self.type = type
        self.data = data
        assert self.length == len(data)
        if not data:
            self.data = bytes()

    def __str__(self):
        data_str = " ".join(["%02x" % d for d in self.data])
        return f"message type {self.type:02x}, length {self.length:4x}, data: {data_str}"
            
    @staticmethod
    async def ReadFromStream(stream):
        length, = struct.unpack("<H", await stream.read(2))
        assert length >= 2
        hdr, type = struct.unpack("<BB", await stream.read(2))
        assert hdr == 0x05
        length -= 2
        data = await stream.read(length)
        try:
            if type == 0x3E:
                return CmsDataBlock3E(length, data)
            elif type == 0x43:
                return CmsDataBlock43(length, data)
            elif type == 0x45:
                return CmsDataBlock45(length, data)
            elif type == 0x46:
                return CmsDataBlock46(length, data)
            elif type == 0x47:
                return CmsDataBlock47(length, data)
            elif type == 0x49:
                return CmsDataBlock49(length, data)
            else:
                return CmsDataBlock(length, type, data)
        except AssertionError as e:
            data_str = " ".join(["%02x" % d for d in data])
            sys.stderr.write(f"Error during decode block type {type:02x} length {length:04x} data {data_str}\n")
            raise e


def _decode(data):
    return data.decode().strip('\x00')
        
class CmsDataBlock3E(CmsDataBlock):
    def __init__(self, length, data):
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
        if SHOW_UNKNOWN:
            return f"message type {self.type:02x} [patient_info], length {self.length:4x}, values: [{values_str}]\nunk:{unk_str}"
        else:
            return f"message type {self.type:02x} [patient_info], length {self.length:4x}, values: [{values_str}]"

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
        if self.lead == 0x15:
            self.leads['pleth'] = [int(d) for d in data[0x4:0x104]]
            spo2, spo2_attached, spo2_hr, spo2_valid = struct.unpack("<BBBB", data[0x104:0x108])
            assert spo2_attached == 0 or spo2_attached == 255
            spo2_attached = spo2_attached == 0
            assert spo2_valid == 0 or spo2_valid == 255
            spo2_valid = spo2_valid == 0
            if not spo2_valid:
                assert spo2 == 255 and spo2_hr == 255
            self.values['SpO2'] = spo2 if spo2_valid else None
            self.values['SpO2_attached'] = spo2_attached
            self.values['SpO2_HR'] = spo2_hr if spo2_valid else None
            self.values['SpO2_valid'] = spo2_valid
            self.unk['unk_108'] = " ".join("%02x" % d for d in data[0x108:])
        elif self.lead == 0x14:
            self.leads['ecg1'] = [int(d) for d in data[0x4:0x104]]
            self.leads['ecg2'] = [int(d) for d in data[0x104:0x204]]
            self.leads['ecg3'] = [int(d) for d in data[0x204:0x304]]
            self.leads['resp'] = [int(d) for d in data[0x304:0x384]]
            hr, hr_valid, rr, rr_valid = struct.unpack("<BBBB", data[0x384:0x388])
            assert hr_valid == 0 or hr_valid == 255
            hr_valid = hr_valid == 0
            assert rr_valid == 0 or rr_valid == 255
            rr_valid = rr_valid == 0
            self.values['HR'] = hr if hr_valid else None
            self.values['HR_valid'] = hr_valid
            self.values['RR'] = rr if rr_valid else None
            self.values['RR_valid'] = rr_valid
            self.unk['unk_388_f'], self.unk['unk_38c_f'], self.unk['unk_390_f'] = struct.unpack("<fff", data[0x388:0x394])
            self.unk['unk_394'] = " ".join("%02x" % d for d in data[0x394:0x3AF])
            self.unk['unk_3af_f'], self.unk['unk_3b3_f'], self.unk['unk_3b7_d'], self.unk['unk_3b9_f'], self.unk['unk_3bb_f'], self.unk['unk_3bf_d'], self.unk['unk_3c1_f'], self.unk['unk_3c5_f'], self.unk['unk_3c9_d'] = struct.unpack("<ffHffHffH", data[0x3AF:0x3CD])
            self.unk['unk_3cd'] = " ".join("%02x" % d for d in data[0x3CD:])
        elif self.lead == 0x16:
            bp_year, bp_mon, bp_day, bp_hr, bp_min, bp_sec, bp_sys, bp_dia, bp_map = struct.unpack("<HBBBBBHHH", data[0x04:0x11])
            self.values['NIBP_time'] = datetime.datetime(bp_year, bp_mon, bp_day, bp_hr, bp_min, bp_sec)
            self.values['NIBP_sys'] = bp_sys
            self.values['NIBP_dia'] = bp_dia
            self.values['NIBP_map'] = bp_map
            self.unk['unk_11'] = " ".join("%02x" % d for d in data[0x11:])
        elif self.lead == 0x17:
            t1, t2, td, t1_max, t1_min, t1_alm, t2_max, t2_min, t2_alm, td_max, td_min, td_alm = struct.unpack("<fffffHffHffH", data[0x04:0x2E])
            for i in range(0x2E, len(data)):
                assert data[i] == 0
            self.values['t1'] = t1
            self.values['t2'] = t2
            self.values['td'] = td
            self.values['t1_alm_max'] = t1_max
            self.values['t1_alm_min'] = t1_min
            self.values['t1_alm'] = t1_alm
            self.values['t2_alm_max'] = t2_max
            self.values['t2_alm_min'] = t2_min
            self.values['t2_alm'] = t2_alm
            self.values['td_alm_max'] = td_max
            self.values['td_alm_min'] = td_min
            self.values['td_alm'] = td_alm
        else:
            self.unk['unk_4'] = " ".join("%02x" % d for d in data[0x4:])
                          
    def __str__(self):
        values_str = ", ".join([f"{name}: {val}" for name, val in sorted(self.values.items())])
        lead_str = "".join([f"\n  {name}: {val}" for name, val in sorted(self.leads.items())])
        unk_str = "".join([f"\n  {name}: {val}" for name, val in sorted(self.unk.items())])
        if SHOW_UNKNOWN:
            return f"message type {self.type:02x} [telemetry], length {self.length:4x}, lead_type: {self.lead:02x}, values: [{values_str}]\nleads:{lead_str}\nunk:{unk_str}"
        else:
            return f"message type {self.type:02x} [telemetry], length {self.length:4x}, lead_type: {self.lead:02x}, values: [{values_str}]\nleads:{lead_str}"

class CmsDataBlock47(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x47, data)
        assert len(data) == 0

    def __str__(self):
        return "block 47"
    
class CmsDataBlock49(CmsDataBlock):
    def __init__(self, length, data):
        super().__init__(length, 0x49, data)
        self.code = int(data[0])
        self.message = data[1:].decode()

    def __str__(self):
        return f"error code: {self.code:02x}, message: {self.message}"

    
async def handle_cms(reader, writer):
    ctime = time.time()
    print("Connection received")
    while True:
        print(f"t {time.time() - ctime:7.3f}  " + str(await CmsDataBlock.ReadFromStream(reader)))
            
    
async def main():
    server = await asyncio.start_server(
        handle_cms, '202.114.4.119', 515)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
        
