import subprocess
import re
import json
from cestcrypto import dohash

TOOL = "Flawfinder 2.0.19"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"


def init_tool():
    return


def run_tool(result_folder, argument, tools_are_silent):
    command = "/usr/local/bin/flawfinder --sarif {} {}".format(
        argument, READABLE_TOE)
    command_no_extra_spaces = re.sub(" +", " ", command)

    result = subprocess.run(command_no_extra_spaces.split(
        " "), capture_output=True, text=True)
    if (not result.stdout.startswith("{")):
        raise Exception(str(result.stdout))

    result_json = json.loads(result.stdout)

    full_report = {
        "tool": TOOL,
        "command": [command_no_extra_spaces],
        "report": result_json,
    }

    report_with_std = {
        "full_report": full_report,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    
    return report_with_std
