import sys
from random import random

from librwrt.core import FridaManager
from librwrt.enums import FridaConnectionTypes
from time import time
import json
import rich
from random import choice

def clean_profile(json):
    # used to solve a bug in the generator, if there are no constructors
    for className in json['profile']['classes']:
        _class = json['profile']['classes'][className]
        if len(_class['constructors']) == 1:
            onlyConstructor = _class['constructors'][0]
            if len(onlyConstructor['arguments']) == 0:
                json['profile']['classes'][className]['constructors'] =  []
    return json

class Profile:
    def __init__(self, connection_type: FridaConnectionTypes, application_uid: str, remote_device=None,
                 static_profile: str = 'static.rwrt.json', script_debugging: bool = False, startup_script: str = '', uid = None, spawn=True):
        self.manager = FridaManager(connection_type, self.on_crash, remote_device, debug=script_debugging, uid=uid, spawn=True)

        if not (self.manager.connect()):
            print('Something went wrong starting a connection to the frida server')
            exit(1)

        self.manager.init_application(application_uid, spawn=spawn)

        self.static_profile = static_profile
        self.data = {'metadata': {'date': time(), 'type': 'static', 'uid': application_uid},
                     'profile': {'classes': {}, 'native': {}}}
        self.classes = self.data['profile']['classes']
        self.i = 0
        self.startup_script = startup_script

    def on_crash(self, reason, frame=None):
        # Gracefully handle close and output status
        if hasattr(reason, "report"):
            print(reason.report)

        self.data = clean_profile(self.data)

        with open(self.static_profile, 'w') as fd:
            json.dump(self.data, fd)
        methods = 0
        for _class in self.classes:
            methods += len(self.classes[_class])
        rich.print(
            f"\n[magenta]Saved static profile with [green]{len(self.classes)} classes[/green] and [yellow]{methods} methods[/yellow] to {self.static_profile}[/magenta]")
        exit(0)

    def execute(self, settings: dict = {}):
        # It would be cool to pass the arguments to the subparser directly as settings to the script
        self.manager.execute_file(sys.argv[0][:sys.argv[0].rfind("/")] + "/agents/profile.js", self.handle, settings, startup_script=self.startup_script)
        self.data['metadata']['settings'] = settings
        self.manager.resume()

    """
        Each of the handle method will be unique to the specific subcommand
    """

    def handle(self, data: any, payload: any):
        if data.get('payload') is not None:
            if data.get('payload').get('class') is not None:
                color = choice(['red', 'blue', 'green', 'yellow', 'magenta'])
                symbol = choice(['.', ',', '-', '|', '_', '`'])
                rich.print(f"[{color}]{symbol}[/{color}]", end='')

                if self.i % 500 == 0 and self.i != 0:
                    print('')

                self.classes[data['payload']['class']] = {}
                self.classes[data['payload']['class']]["methods"] = data['payload']['methods']
                self.classes[data['payload']['class']]["constructors"] = data['payload']['constructors']
                return
        print(data)
        print("Error in profile handler")
