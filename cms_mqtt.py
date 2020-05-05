import asyncio
import json
import paho.mqtt.client as mqtt

import cms_decode

_PUBLISH_UNKNOWN = True

async def handle_cms(reader, writer):
    client = mqtt.Client(client_id='ekg_publisher')
    print("Connection received")
    client.connect("127.0.0.1", 1883)
    print("Connected to mqtt")
    state = {"department": "unknown", "bed": 0}
    while True:
        data = await cms_decode.CmsDataBlock.ReadFromStream(reader)
        if hasattr(data, 'values'):
            state.update(data.values)
        devicepath = f"patient_monitor/{state['department']}_{state['bed']}"
        if hasattr(data, 'values'):
            for k, v in data.values.items():
                client.publish(f"{devicepath}/values/{k}", json.dumps(v, default=str))
        if hasattr(data, 'leads'):
            state.update(data.leads)
            for k, v in data.leads.items():
                client.publish(f"{devicepath}/leads/{k}", json.dumps(v))
        if _PUBLISH_UNKNOWN and hasattr(data, 'unk'):
            if hasattr(data, 'lead'):
                for k, v in data.unk.items():
                    client.publish(f"{devicepath}/unk/{data.type:02x}/{data.lead:02x}/{k}", json.dumps(v))
            else:
                for k, v in data.unk.items():
                    client.publish(f"{devicepath}/unk/{data.type:02x}/{k}", json.dumps(v))

    
async def main():
    server = await asyncio.start_server(
        handle_cms, '202.114.4.119', 515)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
        
