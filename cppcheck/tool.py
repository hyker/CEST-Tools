import subprocess
import xmltodict
import os
import re

TOOL = "Cppcheckv 2.7"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

class FailedProcess:
    def __init__(self, stderr):
        self.stdout = ""
        self.stderr = stderr


def init_tool():
    return


def run_tool(result_folder, argument, tools_are_silent):
    output_file = INTERMEDIATE_RESULT + "temp"
    args = "{} --xml --output-file={}".format(argument, output_file)

    command = "/cppcheck/build/bin/cppcheck {} {}".format(args, READABLE_TOE)
    command_no_extra_spaces = re.sub(" +", " ", command)

    # Run analysis
    try:
        result = subprocess.run(
            command_no_extra_spaces.split(" "), capture_output=True, text=True)
    except Exception as e:
        result = FailedProcess(str(e))

    if os.path.exists(output_file):
        with open(output_file, "r") as output_file_bytes:
            output = output_file_bytes.read()
        result_json = xmltodict.parse(output)
    else:
        result_json = {"error": "no output file found"}

    
    full_report = {
        "tool": TOOL,
        "port_version": 1,
        "command": [command_no_extra_spaces],
        "report": result_json,
    }

    if os.path.exists(output_file):
        os.remove(output_file)

    report_with_std = {
        "full_report": full_report,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    return report_with_std
