import subprocess
import json
import os
import re
from cestcrypto import dohash

TOOL = "Dependency-Check 7.2.1"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"


def init_tool():
    return


def run_tool(result_folder, argument, tools_are_silent):
    args = "{} --noupdate -s /toe -o {} --disableOssIndex --disableCentral --disableRetireJS --format JSON".format(
        argument, INTERMEDIATE_RESULT)

    command = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java -Xmx4G -classpath /dependency-check/plugins/*:/dependency-check/lib/* -Dapp.name=dependency-check -Dapp.pid=1 -Dapp.repo=/dependency-check/lib -Dapp.home=/dependency-check -Dbasedir=/dependency-check org.owasp.dependencycheck.App {}".format(
        args)
    command_no_extra_spaces = re.sub(" +", " ", command)

    # Run analysis
    result = subprocess.run(command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent, text=True)

    with open(INTERMEDIATE_RESULT + "dependency-check-report.json", "r") as f:
        result_json = json.load(f)

    # Tool specific clean up
    os.remove(INTERMEDIATE_RESULT + "dependency-check-report.json")

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
