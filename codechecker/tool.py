import subprocess
import glob
import os
import shutil
import re
import json
from cestcrypto import dohash

TOOL = "CodeChecker 6.18.2"
TOOL_FOLDER = "/pod-storage/{}/".format(TOOL.replace(" ", ""))
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"


def init_tool():
    return


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def run_tool(result_folder, argument, tools_are_silent):
    # Get project path
    project_folder_path = READABLE_TOE

    # toe_dir_list = glob.glob(READABLE_TOE + "*")
    # if len(toe_dir_list) == 1 and os.path.isdir(toe_dir_list[0]):
    #     project_folder_path = toe_dir_list[0]

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
        "args": [
            log_command_no_extra_spaces,
            analyze_command_no_extra_spaces,
            parse_command_no_extra_spaces
        ],
    }

    with open(result_folder + "/args", "w") as args_file:
        json.dump(tool_and_args, args_file)

    result_log = subprocess.run(log_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent, text=True)
    result_analyze = subprocess.run(analyze_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent, text=True)
    result_parse = subprocess.run(parse_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent, text=True)

    with open(result_file, "r") as f:
        result_json = json.load(f)

    os.remove(output_file + "_cc")
    shutil.rmtree(output_file + "_analyze")

    full_report = {
        "tool": TOOL,
        "command": [
            log_command_no_extra_spaces,
            analyze_command_no_extra_spaces,
            parse_command_no_extra_spaces
        ],
        "report": result_json,
    }

    report_with_std = {
        "full_report": full_report,
        "stdout": "{}\n{}\n{}".format(result_log.stdout, result_analyze.stdout, result_parse.stdout) ,
        "stderr": "{}\n{}\n{}".format(result_log.stderr, result_analyze.stderr, result_parse.stderr) ,
    }

    return report_with_std
