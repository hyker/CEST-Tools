import subprocess
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/Flawfinder2.0.19/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

def run_tool(result_folder, argument, tools_are_silent):
  command = "/usr/local/bin/flawfinder --sarif {} {}".format(argument, READABLE_TOE)
  command_no_extra_spaces = re.sub(" +", " ", command)
  result = subprocess.run(command_no_extra_spaces.split(" "), capture_output=True, text=True)
  with open(result_folder + "/result", "w") as result_file:
      result_file.write(result.stdout)

  output_hash = dohash(result.stdout.encode("utf-8"))

  with open("/dev/attestation/user_report_data", "wb") as user_report_data:
    user_report_data.write(output_hash)

  # generating the quote
  with open("/dev/attestation/quote", "rb") as q:
    quote = q.read()

  with open(result_folder + "/quote", "wb") as f:
    f.write(quote)