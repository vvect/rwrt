let done = true
rpc.exports = {
    execute: (settings) => {
        main(settings)
    },
}

function scanForClasses(settings) {
    if (done) {
        let java = new fsJava()
        done = false
        Java.performNow(() => {
            java.hookSetup(settings['classWhitelist'], settings['classBlacklist'], settings['functionWhitelist'], settings['functionBlacklist'])
        })
        done = true
    }
}

function main(settings) {
    setTimeout(() => {
        scanForClasses(settings)
        setInterval(() => {
            scanForClasses(settings)
        }, parseInt(settings['profile_interval'] * 1000, 10))
    }, 0)
}

class fsJava {
    constructor() {
        this.seen = {}
    }

    getClassMethods(_class) {
        try {
            var classHook = Java.use(_class)
        } catch (ex) {
            return []
        }

        if (classHook.class === undefined) {
            return []
        }

        var methods = classHook.class.getDeclaredMethods()
        var names = methods.map(item => item.toString().replace(_class + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1])

        classHook.$dispose
        return names
    }

    hook_constructors(_class) {
        let _hi = Java.use(_class)

        let messsage_overloads = []

        let constructors_avail = true;
        try {
            let access = _hi.$init
        } catch (error) {
            // Typically these classes don't have constructors
            constructors_avail = false
        }

        if (constructors_avail) {
            let overloads = _hi.$init.overloads
            for (var i in overloads) {
                let args = {}
                let overload = overloads[i]
                messsage_overloads.push(overload.argumentTypes)
            }
        }

        _hi.$dispose
        return messsage_overloads
    }

    hook(_class, methods) {
        let _hi = Java.use(_class)
        let message = {'class': _class, 'methods': {}, 'constructors': []}
        let _cons_overloads = []
        let res = this.hook_constructors(_class)
        if (res.length == 0) {
            _cons_overloads = [{'arguments': []}]
        } else {
            for (let i in res) {
                _cons_overloads.push({'arguments': res[i]})
            }
        }
        message['constructors'] = _cons_overloads
        message['constructors']['return_value'] = _hi.$className

        // We have the list of methods, need to overload them all
        methods.forEach(method => {
            message['methods'][method] = {'overloads': []}

            let messsage_overloads = message['methods'][method]['overloads']
            if (_hi[method] === undefined || _hi[method] == null) {
                // messsage_overloads.push({'arguments': _hi[method].argumentTypes, 'returnType': _hi[method].returnType})
                // TODO: Investigate why this method would not exist but is returned
                // by the enumeration process
                // console.log(method)
            } else {
                let overloads = _hi[method].overloads
                for (var i in overloads) {
                    let overload = overloads[i]
                    // Sometimes,
                    if (overload.returnType['defaultValue'] == null){
                        const returnType = {
                                        "className": overload.returnType.$className,
                        }
                        messsage_overloads.push({'arguments': overload.argumentTypes, 'returnType': returnType})
                    }else{
                        messsage_overloads.push({'arguments': overload.argumentTypes, 'returnType': overload.returnType})
                    }
                }
            }


        })
        send(message)
        _hi.$dispose
    }

    /*
        We cannot inspect method names dynamically without loading the classes,
        so the Android hookSetup function takes two addtional lists which will allow/deny
        on function names to facilitate somewhat similar behaviour to iOS.
    */

    hookSetup(whitelist = null, blacklist = null, functionWhitelist = null, functionBlacklist = null) {
        if (whitelist === null) {
            whitelist = ".*"
        }

        if (functionWhitelist === null) {
            functionWhitelist = ".*"
        }

        let watchClasses = [];
        let watchMethods = [];
        let java = this;

        Java.performNow(() => {
            Java.enumerateLoadedClasses({
                onMatch: function (className) {
                    if (java.seen[className] === undefined) {
                        if (className.match(whitelist)) {
                            if (blacklist !== null) {
                                if (className.match(blacklist)) {
                                    return
                                }
                            }

                            java.seen[className] = true
                            watchClasses.push(className);
                            let methods = java.getClassMethods(className);
                            let hookMethods = [];
                            methods.forEach((_method) => {
                                if (_method.match(functionWhitelist)) {
                                    if (functionBlacklist !== null) {
                                        if (_method.match(functionBlacklist)) {
                                            return
                                        }
                                    }

                                    let x = className + "." + _method;
                                    watchMethods.push(x);
                                    hookMethods.push(_method);
                                    return;
                                }
                            });
                            if (hookMethods.length > 0)
                                java.hook(className, hookMethods)
                        }
                    }
                },
                onComplete: function () {
                },
            });
        });
    }
}