import subprocess
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/Scancode30.1.0/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

def run_tool(result_folder, argument, tools_are_silent):
  command = "/usr/local/bin/scancode -i {} -n 0 --json-pp {} {}".format(argument, result_folder + "/result", READABLE_TOE)
  command_no_extra_spaces = re.sub(" +", " ", command)

  subprocess.run(command_no_extra_spaces.split(" "), capture_output=tools_are_silent)

  output_hash = ""
  with open (result_folder + "/result", "r") as f:
    output_hash = dohash(f.read().encode("utf-8"))

  with open("/dev/attestation/user_report_data", "wb") as user_report_data:
    user_report_data.write(output_hash)

  # generating the quote
  with open("/dev/attestation/quote", "rb") as q:
    quote = q.read()

  with open(result_folder + "/quote", "wb") as f:
    f.write(quote)