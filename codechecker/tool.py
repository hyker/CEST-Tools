import subprocess
import glob
import os
import shutil
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/CodeChecker6.18.2/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"


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

    subprocess.run(log_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent)
    subprocess.run(analyze_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent)
    subprocess.run(parse_command_no_extra_spaces.split(
        " "), capture_output=tools_are_silent)

    output_hash = ""
    with open (result_file, "r") as f:
      output_hash = dohash(f.read().encode("utf-8"))

    with open("/dev/attestation/user_report_data", "wb") as user_report_data:
      user_report_data.write(output_hash)

    # generating the quote
    with open("/dev/attestation/quote", "rb") as q:
      quote = q.read()

    with open(result_folder + "/quote", "wb") as f:
      f.write(quote)

    # Tool specific clean up
    os.remove(output_file + "_cc")
    shutil.rmtree(output_file + "_analyze")