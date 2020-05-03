import asyncio
import json
import paho.mqtt.client as mqtt

import cms_decode

async def handle_cms(reader, writer):
    client = mqtt.Client(client_id='ekg_publisher')
    print("Connection received")
    client.connect("127.0.0.1", 1883)
    print("Connected to mqtt")
    state  = {}
    while True:
        data = await cms_decode.CmsDataBlock.ReadFromStream(reader)
        if hasattr(data, 'values'):
            for k, v in data.values.items():
                client.publish(f"monitor/values/{k}", json.dumps(v, default=str))
        if hasattr(data, 'leads'):
            for k, v in data.leads.items():
                client.publish(f"monitor/leads/{k}", json.dumps(v))            
    
async def main():
    server = await asyncio.start_server(
        handle_cms, '202.114.4.119', 515)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
        
