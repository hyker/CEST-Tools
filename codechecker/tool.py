import subprocess
import os
import shutil
import re
import json

TOOL = "CodeChecker 6.18.2"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

class FailedProcess:
    def __init__(self, stderr):
        self.stdout = ""
        self.stderr = stderr


def init_tool():
    return


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def run_tool(result_folder, argument, tools_are_silent):

    makefile_path = find("Makefile", READABLE_TOE)
    if makefile_path == None:
        raise Exception("No makefile found")
    head_tail = os.path.split(makefile_path)
    makefile_folder_path = head_tail[0]

    # Run tool
    output_file = INTERMEDIATE_RESULT + "temp"
    result_file = result_folder + "/result"

    log_command = "/usr/share/clang/scan-build-py-10/bin/intercept-build --cdb {}_cc make -j1 -C {}".format(
        output_file, makefile_folder_path)

    analyse_command = "/usr/local/bin/CodeChecker analyze {}_cc {} --output {}_analyze".format(
        output_file, argument, output_file)

    parse_command = "/usr/local/bin/CodeChecker parse --export json --output {} {}_analyze".format(
        result_file, output_file)

    log_command_no_extra_spaces = re.sub(" +", " ", log_command)
    analyze_command_no_extra_spaces = re.sub(" +", " ", analyse_command)
    parse_command_no_extra_spaces = re.sub(" +", " ", parse_command)

    # Save tool, version and command to file
    tool_and_args = {
        "tool": TOOL,
        "port_version": 1,
        "args": [
            log_command_no_extra_spaces,
            analyze_command_no_extra_spaces,
            parse_command_no_extra_spaces
        ],
    }

    with open(result_folder + "/args", "w") as args_file:
        json.dump(tool_and_args, args_file)

    try:
        result_log = subprocess.run(log_command_no_extra_spaces.split(
            " "), capture_output=tools_are_silent, text=True)
    except Exception as e:
        result_log = FailedProcess(str(e))

    try: 
        result_analyze = subprocess.run(analyze_command_no_extra_spaces.split(
            " "), capture_output=tools_are_silent, text=True)
    except Exception as e:
        result_analyze = FailedProcess(str(e))
    
    try:
        result_parse = subprocess.run(parse_command_no_extra_spaces.split(
            " "), capture_output=tools_are_silent, text=True)
    except Exception as e:
        result_parse = FailedProcess(str(e))

    try:
        with open(result_file, "r") as f:
            result_json = json.load(f)
    except:
        result_json = {"error": "analysis failed, no output file found"}

    if os.path.exists(output_file + "_cc"):
        os.remove(output_file + "_cc")
    if os.path.exists(output_file + "_analyze"):
        shutil.rmtree(output_file + "_analyze")

    full_report = {
        "tool": TOOL,
        "port_version": 1,
        "command": [
            log_command_no_extra_spaces,
            analyze_command_no_extra_spaces,
            parse_command_no_extra_spaces
        ],
        "report": result_json,
    }

    report_with_std = {
        "full_report": full_report,
        "stdout": "{}\n{}\n{}".format(result_log.stdout, result_analyze.stdout, result_parse.stdout),
        "stderr": "{}\n{}\n{}".format(result_log.stderr, result_analyze.stderr, result_parse.stderr),
    }

    return report_with_std
