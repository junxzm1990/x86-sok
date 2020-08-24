"""
file: executeIDAScript.py 
date: 05/30/2019 
author: binpang

execute the ida pro script by cli
"""

import os
import subprocess
import optparse
import sys
import traceback

def executeIDAScript(idaPath, binaryPath, scriptFile, scriptArgs):
    """
    params:
        idaPath: ida pro path
        binaryPath: 
        scriptFile: script file path
        scriptArgs:
    """
    ## set up the environment
    env = dict()
    ida_disass_path = os.path.abspath(__file__)
    ida_dir = os.path.dirname(ida_disass_path)
    #env["IDALOG"] = os.devnull # disable the ida pro log
    env["IDALOG"] = '/tmp/ida_script.log' # specify the ida log path
    env['TVHEADLESS'] = '1' # disable all output (for i/o redirection)
    env['HOME'] = os.path.expanduser('~') # necessary. otherwise can't find file path
    env["IDA_PATH"] = os.path.dirname(idaPath)
    env["PYTHONPATH"] = os.path.dirname(ida_dir)
    if "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]

    ## ida pro script cmd
    script_cmd = []
    script_cmd.append(scriptFile)
    if len(scriptArgs) > 0:
        script_cmd.append(scriptArgs)
    print("script cmd is %s" % (" ".join(script_cmd)))
    
    ## ida pro cmd
    cmd = []
    cmd.append(idaPath)
    cmd.append("-B") # batch mode
    cmd.append("-S\"{}\"".format(" ".join(script_cmd)))
    cmd.append(binaryPath)

    try:
        with open(os.devnull, "w") as devnull:
            return subprocess.call(
                    " ".join(cmd),
                    env = env,
                    stdin = None,
                    stdout = devnull,
                    stderr = sys.stderr,
                    shell = True) 

    except:
        sys.stderr.write(traceback.format_exc())
        return 1

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-d", "--decompiler", dest = "decompiler", action = "store", type = "string", \
            help = "the path of decompiler", default = "/opt/idapro-7.4/idat64")
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "the path of the binary file", default = None)
    parser.add_option("-s", "--script", dest = "script", action = "store", type = "string", \
            help = "the path of script file", default = None)
    
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("Please input the binary file path")
        exit(-1)
    if options.script == None:
        print("Please input the script file path")
        exit(-1)
    executeIDAScript(options.decompiler, options.binary, options.script, args)
