#!/usr/bin/env python3
import json

import click
import signal

from librwrt.enums import FridaConnectionTypes
from librwrt.handlers.profile import Profile

@click.group()
@click.option('--debug/--no-debug', default=False)
@click.pass_context
def cli(ctx, debug):
    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below)
    ctx.ensure_object(dict)

    ctx.obj['DEBUG'] = debug


@cli.command()
@click.pass_context
@click.option('-a', '--application', help="The package name of your Android application. Alternatively specify the process PID and --spawn false to attach", default="")
@click.option('-c', '--connection', default="USB")
@click.option('-fs', '--frida-server', help="Specified as an <ip>:<port> pair", default="")
@click.option('-b', '--blacklist', help="The regex pattern used to exclude classes")
@click.option('-fb', '--function-blacklist', help="The regex pattern used to exclude methods")
@click.option('-w', '--whitelist', help="The regex pattern used to include classes")
@click.option('-fw', '--function-whitelist', help="The regex pattern used to include methods")
@click.option('-s', '--static-profile', default="static.rwrt.json", help="The output profile name")
@click.option('--spawn', help="Only specify this as false when specifying a PID via -a", default='True')
@click.option('-pi', '--profile-interval', help="The interval (in seconds) in which loaded classes/methods should be checked", default="5")
@click.option('-S', '--startup-script', help="Specify a frida script to be run before profiling starts", default='')
@click.option('-u', '--uid', help="Can be used to specify the UID to run as (Android for work)",default=None)
def profile(ctx, application: str, connection: str, frida_server: str, blacklist: str, function_blacklist: str,
            whitelist: str, function_whitelist: str, static_profile: str, profile_interval: str,
            startup_script: str, uid: str, spawn:bool):
    connection_type = None
    if spawn != 'True':
        spawn = False
    else:
        spawn = True

    if connection.upper() == "USB":
        connection_type = FridaConnectionTypes.USB
    elif connection.upper() == "LOCAL":
        connection_type = FridaConnectionTypes.LOCAL
    elif connection.upper() == "NETWORK":
        connection_type = FridaConnectionTypes.NETWORK
    if frida_server == "":
        profile_agent = Profile(connection_type, application, None, static_profile, startup_script=startup_script, uid=uid, spawn=spawn)
    else:
        profile_agent = Profile(connection_type, application, frida_server, static_profile, startup_script=startup_script, uid=uid, spawn=spawn)

    profile_agent.execute({
        "classBlacklist": blacklist,
        "functionBlacklist": function_blacklist,
        "classWhitelist": whitelist,
        "functionWhitelist": function_whitelist,
        "profile_interval": profile_interval
    })

    signal.signal(signal.SIGINT, profile_agent.on_crash)
    print("Press Ctrl+C to stop tracing!")

    while True:
        input()


if __name__ == '__main__':
    cli()
