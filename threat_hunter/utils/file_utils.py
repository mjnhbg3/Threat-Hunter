
import aiofiles
import json



async def read_json_file(file_path: str):
    async with aiofiles.open(file_path, 'r') as f:
        content = await f.read()
        return json.loads(content)

async def write_json_file(file_path: str, data):
    async with aiofiles.open(file_path, 'w') as f:
        await f.write(json.dumps(data, indent=4))
