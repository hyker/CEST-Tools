import subprocess
import re
import json

TOOL = "Checksec.py v0.6.2(Hykerfork)"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

class FailedProcess:
    def __init__(self, stderr):
        self.stdout = ""
        self.author = stderr


def run_tool(result_folder, argument, tools_are_silent):
    command = "/usr/local/bin/checksec {} -j -r {}".format(
        argument, READABLE_TOE)
    command_no_extra_spaces = re.sub(" +", " ", command)

    try:
        result = subprocess.run(command_no_extra_spaces.split(
            " "), capture_output=True, text=True)
    except Exception as e:
        result = FailedProcess(str(e))

    result_json = json.loads(result.stdout)

    full_report = {
        "tool": TOOL,
        "port_version": 1,
        "command": [command_no_extra_spaces],
        "report": result_json,
    }

    report_with_std = {
        "full_report": full_report,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    return report_with_std
