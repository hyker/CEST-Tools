from shutil import ExecError
import subprocess
import xmltodict
import json
import os
import re
from cestcrypto import dohash

TOOL = "Cppcheckv 2.7"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"


def init_tool():
    return


def run_tool(result_folder, argument, tools_are_silent):
    output_file = INTERMEDIATE_RESULT + "temp"
    args = "{} --xml --output-file={}".format(argument, output_file)

    command = "/cppcheck/build/bin/cppcheck {} {}".format(args, READABLE_TOE)
    command_no_extra_spaces = re.sub(" +", " ", command)

    # Save tool, version and command to file
    tool_and_args = {
        "tool": TOOL,
        "args": [command_no_extra_spaces],
    }

    # Run analysis
    result = subprocess.run(
        command_no_extra_spaces.split(" "), capture_output=True, text=True)

    try:
        with open(output_file, "r") as output_file_bytes:
            output = output_file_bytes.read()
    except:
        raise Exception(result.stdout)

    result_json = xmltodict.parse(output)
    full_report = {
        "tool": TOOL,
        "command": [command_no_extra_spaces],
        "report": result_json,
    }

    os.remove(output_file)

    report_with_std = {
        "full_report": full_report,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    return report_with_std
