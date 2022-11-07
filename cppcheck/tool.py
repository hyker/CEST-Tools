from shutil import ExecError
import subprocess
import xmltodict
import json
import os
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/Cppcheckv2.7/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

def init_tool():
  return

def run_tool(result_folder, argument, tools_are_silent):
  output_file = INTERMEDIATE_RESULT + "temp"
  args = "{} --xml --output-file={}".format(argument, output_file)

  # Run analysis
  command = "/cppcheck/build/bin/cppcheck {} {}".format(args, READABLE_TOE)
  command_no_extra_spaces = re.sub(" +", " ", command)
  result = subprocess.run(command_no_extra_spaces.split(" "), capture_output=True)
  
  # Move result to shared folder as json
  output_as_json = ""
  try: 
    with open(output_file, "r") as output_file_bytes:
        output = output_file_bytes.read()
        output_as_json = json.dumps(xmltodict.parse(output))
        with open(result_folder + "/result", "w") as result_file:
            result_file.write(output_as_json)
  except:
    raise Exception(result.stdout.decode("utf-8"))

  output_hash = dohash(output_as_json.encode("utf-8"))

  with open("/dev/attestation/user_report_data", "wb") as user_report_data:
    user_report_data.write(output_hash)

  #generating the quote
  with open("/dev/attestation/quote", "rb") as q:
    quote = q.read()

  with open(result_folder + "/quote", "wb") as f:
    f.write(quote)
  
  # Tool specific clean up
  os.remove(output_file)