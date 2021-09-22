# There's a lot to do here, we need to create the right kind of connection and then execute the agent,
# which runs until the target process is terminated or an interrupt is triggered

# Some commands trigger agents while some of them trigger functions that take profiles as input
from typing import Callable

from librwrt.enums import FridaConnectionTypes, FridaScriptRuntimes
import frida


class FridaManager:
    def __init__(self, connection_type: FridaConnectionTypes, crash_handler: Callable, remote_device=None, spawn=True,
                 debug=False, uid=None):
        self.uid = uid
        self.spawn = spawn
        self.signalled = False
        self.connection_type = connection_type
        self.debug = debug
        if connection_type == FridaConnectionTypes.NETWORK:
            if remote_device is None:
                raise RuntimeError(
                    'When specifying a remote connection, the optional parameter remoteDevice is required.')
            else:
                self.device = frida.get_device_manager().add_remote_device(remote_device)
        self.device = None
        self.session = None
        self.pid = None
        self.script = None
        if crash_handler is None:
            raise RuntimeError(
                'You need to specify a crash handler.')
        self.crash_handler = crash_handler

    def connect(self) -> bool:
        if self.connection_type == FridaConnectionTypes.USB:
            # Perform usb connection
            self.device = frida.get_usb_device()
            return True
        elif self.connection_type == FridaConnectionTypes.NETWORK:
            return True
        elif self.connection_type == FridaConnectionTypes.LOCAL:
            self.device = frida.get_local_device()
            return True
        return False

    def init_application(self, application_uid: str, resume_after: Callable = None, spawn = True):
        self.spawn = spawn
        if spawn:
            if self.uid is not None:
                self.pid = self.device.spawn([application_uid], uid=int(self.uid))
            else:
                self.pid = self.device.spawn([application_uid])
            print("pid: " + str(self.pid))
            self.session = self.device.attach(self.pid)
        else:
            self.session = self.device.attach(int(application_uid))
            self.pid = int(application_uid)
        if self.debug:
            self.session.enable_debugger()
        self.session.on('detached', lambda x: self.crash_handler(x))
        self.session.on('detached', lambda x, y: self.crash_handler(f'{x}\n{y}'))
        self.session.on('detached', lambda *args: self.crash_handler(args))
        self.device.on('process-crashed', lambda reason: self.crash_handler(reason))

        if resume_after is not None:
            resume_after()
            self.device.resume(self.pid)

    def resume(self):
        if self.spawn == True:
            self.device.resume(self.pid)

    def execute(self, script_source: str, execute_function: Callable, settings: dict = {},
                runtime=FridaScriptRuntimes.QJS.value) -> bool:
        # print(script_source)
        self.script = self.session.create_script(script_source, runtime)
        self.script.on('message', execute_function)
        self.script.load()
        self.script.exports.execute(settings)
        return True


    def execute_file(self, script_path: str, execute_function: Callable, settings: dict = {},
                     runtime=FridaScriptRuntimes.QJS.value, startup_script: str = '') -> bool:
        with open(script_path, 'r') as fd:
            source = fd.read()

            if startup_script != '':
                with open(startup_script, 'r') as fd:
                    startup_source = fd.read()
                source = f'function __rwrt_startup_script__(){{\n{startup_source}\n}}\n__rwrt_startup_script__()\n\n\n' + source


            return self.execute(source, execute_function, settings, runtime)

        return False
