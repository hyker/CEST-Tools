import subprocess
import xmltodict
import json
import os
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/Dependency-Check7.2.1/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

def run_tool(result_folder, argument, tools_are_silent):
  args = "{} --noupdate -s /toe -o {} --disableOssIndex --format JSON".format(argument, INTERMEDIATE_RESULT);

  # Run analysis
  command = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java -Xmx4G -classpath /dependency-check/plugins/*:/dependency-check/lib/* -Dapp.name=dependency-check -Dapp.pid=1 -Dapp.repo=/dependency-check/lib -Dapp.home=/dependency-check -Dbasedir=/dependency-check org.owasp.dependencycheck.App {}".format(args)
  command_no_extra_spaces = re.sub(" +", " ", command)
  subprocess.run(command_no_extra_spaces.split(" "), capture_output=tools_are_silent)

  with open(INTERMEDIATE_RESULT + "dependency-check-report.json", "r") as f:
    result = f.read()
    with open(result_folder + "/result", "w") as g:
      g.write(result)
  
  # Tool specific clean up
  os.remove(INTERMEDIATE_RESULT + "dependency-check-report.json")
  
  with open (result_folder + "/result", "r") as f:
    output_hash = dohash(f.read().encode("utf-8"))

  with open("/dev/attestation/user_report_data", "wb") as user_report_data:
    user_report_data.write(output_hash)

  # generating the quote
  with open("/dev/attestation/quote", "rb") as q:
    quote = q.read()

  with open(result_folder + "/quote", "wb") as f:
    f.write(quote)