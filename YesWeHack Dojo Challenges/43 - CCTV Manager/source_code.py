import time, yaml, random
from urllib.parse import unquote
from jinja2 import Environment, FileSystemLoader
template = Environment(
    autoescape=True,
    loader=FileSystemLoader('/tmp/templates'),
).get_template('index.html')
os.chdir('/tmp')

class Firmware():
    def __init__(self, version:str):
        self.version = version
    
    def update(self):
        pass

def genToken(seed:str) -> str:
    random.seed(seed)
    return ''.join(random.choices('abcdef0123456789', k=16))


def main():
    tokenRoot = genToken(int(time.time()) // 1)

    yamlConfig = unquote("")
    tokenGuest = unquote("")

    access = bool(tokenGuest == tokenRoot)

    firmware = None
    if access:
        try:
            data = yaml.load(yamlConfig, Loader=yaml.Loader)
            firmware = Firmware(**data["firmware"])
            firmware.update()
        except:
            pass
        
    print( template.render(access=access) )

main()