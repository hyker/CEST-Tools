import subprocess
import shutil
import glob
import os
import re
from cestcrypto import dohash

TOOL_FOLDER = "/pod-storage/Dependency-Check7.2.1/"
INTERMEDIATE_RESULT = "/result/"
READABLE_TOE = "/toe/"

def init_tool():
  return
  # source = '/dependency-check/databackup'
  # destination = '/dependency-check/data'

  # for root, subdirs, files in os.walk(source):
  #   rel_root = os.path.relpath(root, source)
  #   if rel_root == ".":
  #     rel_root = ""
  #   new_root = os.path.join(destination, rel_root)

  #   for file in files: 
  #     new_file = os.path.join(new_root, file)
  #     with open(os.path.join(root, file), "rb") as f:
  #       with open(new_file, "wb") as g:
  #         g.write(f.read())

  #   for dir in subdirs:
  #     new_dir = os.path.join(new_root, dir)
  #     os.mkdir(new_dir)
  
  # shutil.rmtree("/dependency-check/databackup")
  # print(glob.glob("/dependency-check/data/*"), flush=True)

def run_tool(result_folder, argument, tools_are_silent):
  args = "{} --noupdate -s /toe -o {} --disableOssIndex --disableCentral --disableRetireJS --format JSON".format(argument, INTERMEDIATE_RESULT);

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