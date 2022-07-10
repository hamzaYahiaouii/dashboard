import sys
import requests
import json
from datetime import date
import os
import re
import subprocess


def get_vulnerabilities(docker_version, runc_version, containerd_version):
    def function(start, end, ver):

        if re.search('alpine', start, re.IGNORECASE):
            start = start.split("-", 1)
            start = start[0]
            end = end.split("-", 1)
            end = end[0]

        try:
            start = float(start)
            start = f'{start}.0'
        except:
            pass

        start = start.split(".", 1)
        end = end.split(".", 1)
        ver = ver.split(".", 1)

        try:
            start[1] = float(start[1])
            end[1] = float(end[1])
        except:
            start = start[1].split(".", 1)
            end = end[1].split(".", 1)
            ver = ver[1].split(".", 1)

        ver[1] = float(ver[1])
        float(start[0]), float(end[0]), float(
            ver[0]), float(start[1]), float(end[1]),
        float(ver[1])

        if (start[0] == end[0] == ver[0]):
            if (start[1] <= ver[1] and end[1] > ver[1]):
                return True
            else:
                return False
        elif (ver[0] == start[0]):
            if (start[1] <= ver[1]):
                return True
            else:
                return False
        elif (ver[0] == end[0]):
            if (end[1] > ver[1]):
                return True
            else:
                return False
        elif (start[0] <= ver[0] and end[0] > ver[0]):
            return True
        else:
            return False

    daemon_correction = """
    This version of docker is vulnerable.

    To fix this problem, you should update your docker by removing the outdated version and install the latest
    1. Uninstall the old version:
        $ sudo apt-get remove docker docker-engine docker.io containerd runc

    2. Set up the repository:
        - Update the apt package
        $ sudo apt-get update
        $ sudo apt-get install ca-certificates curl gnupg lsb-release
        
        - Add Docker’s official GPG key
        $ sudo mkdir -p /etc/apt/keyrings
        $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        - Use the following command to set up the repository
        $ echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    3. Install the docker engine:
        $ sudo apt-get update
        $ sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
    In case of an error or for more information, go check the docker installation manual 
            * https://docs.docker.com/engine/install/ubuntu/ *
    ---------------------------------------------------------------------------------------------
            """

    runc_correction = """
    This version of docker is vulnerable.

    To fix this vulnerability, follow this commands:
        $ sudo apt-get update -y
        $ sudo apt-get install -y libseccomp-dev
        $ git clone https://github.com/opencontainers/runc
        $ cd runc
        $ make
        $ sudo make install
    With this, runc will be installed to /usr/local/sbin/runc on your system.
    More information in * https://github.com/containerd/containerd/blob/main/docs/getting-started.md *
    ----------------------------------------------------------------------------------------------
        """

    containerd_correction = """
    This version of containerd is vulnerable.

    To fix this vulnerability, Download the `containerd-<VERSION>-<OS>-<ARCH>.tar.gz` archive from https://github.com/containerd/containerd/releases , then extract it under /usr/local 
        * tar Cxzvf /usr/local containerd-1.6.2-linux-amd64.tar.gz
    More information in * https://github.com/containerd/containerd/blob/main/docs/getting-started.md *
    ----------------------------------------------------------------------------------------------
        """

    fault = [0, 0, 0]
    docker_list= dict()
    runc_list= dict()
    containerd_list= dict()
    docker_result_ID = []
    docker_result_DIS = []
    docker_result_SCO = []
    runc_result_ID = []
    runc_result_DIS = []
    runc_result_SCO = []
    containerd_result_ID = []
    containerd_result_DIS = []
    containerd_result_SCO = []
    daemon = {"Test": "docker", "version": docker_version}
    runc = {"Test": "runc", "version": runc_version}
    containerd = {"Test": "containerd", "version": containerd_version}

    table = [daemon, runc, containerd]
    q = 0

    for test in table:
        ID = []
        discription = []
        score = []

        platform = test["Test"]
        version = test["version"]
        mounths = [["01", "03"], ["04", "06"], ["07", "09"], ["10", "12"]]

        todays_date = date.today()
        years = [int(todays_date.year) - i for i in range(1, 11)]
        database = dict()

        for year in years:
            for mounth in mounths:
                year = str(year)
                start = mounth[0]
                end = mounth[1]
                url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate={year}-{start}-01T13:00:00:000%20UTC%2B01:00&modEndDate={year}-{end}-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
                req = requests.get(url)
                r = requests.get(url)
                try:
                    file = open(f"/tmp/ll/file-{year}-{start}", "x")
                    file.write(r.text)
                    file.close()
                except:
                    pass

                file = open(f"/tmp/ll/file-{year}-{start}", "r")
                x = json.loads(file.read())["result"]
                string = "versionStart"
                k = 0
                while k < len(x["CVE_Items"]):

                    f = x["CVE_Items"][k]["configurations"]["nodes"][0]["cpe_match"]
                    match = re.search(string, str(f), re.IGNORECASE)
                    if not match:
                        a = re.search(platform, str(f), re.IGNORECASE)
                        b = re.search(version, str(f), re.IGNORECASE)
                        if a and b:
                            ID.append(x["CVE_Items"][k]["cve"]
                                      ["CVE_data_meta"]["ID"])
                            discription.append(
                                x["CVE_Items"][k]["cve"]["description"]["description_data"][0]["value"])
                            score.append(x["CVE_Items"][k]["impact"]
                                         ["baseMetricV3"]["cvssV3"]["baseScore"])
                            fault[q] = 1

                        else:
                            pass
                    else:
                        j = 0
                        file = open("/tmp/lopo", "w")
                        file.write(f"{str(f)}\n")
                        file.close()
                        os.system(
                            "cat /tmp/lopo | grep -o -P '.{0,70}versionStart.{0,78}' > /tmp/cut")
                        #length = os.popen("cat /tmp/cut | wc -l")
                        length = subprocess.check_output(
                            "cat /tmp/cut | wc -l", shell=True)
                        length = int(length)

                        while j < length:
                            plat = os.popen(
                                f"cat /tmp/cut | grep {platform}").read()
                            commande1 = f"cat /tmp/cut | cut -d 'S' -f 2 | cut -d \"'\" -f 3 | sed -n {j+1}p"
                            #commande2 =  f"cat /tmp/cut | cut -d 'E' -f 3 | cut -d \"'\" -f 3 | sed -n {j+1}p"
                            commande2 = f"cat /tmp/cut | cut -d 'S' -f 2 | cut -d ',' -f 2 | cut -d \"'\" -f 4 | sed -n {j+1}p"
                            start = subprocess.check_output(
                                commande1, shell=True).decode("utf-8")
                            end = subprocess.check_output(
                                commande2, shell=True).decode("utf-8")
                            result = function(start, end, version)

                            if plat and result:
                                ID.append(x["CVE_Items"][k]["cve"]
                                          ["CVE_data_meta"]["ID"])
                                discription.append(
                                    x["CVE_Items"][k]["cve"]["description"]["description_data"][0]["value"])
                                score.append(
                                    x["CVE_Items"][k]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
                                fault[q] = 1

                                break
                            else:
                                pass
                                j += 1

                    k += 1
        if platform == "docker":
            docker_result_ID.append(ID)
            docker_result_DIS.append(discription)
            docker_result_SCO.append(score)
        

        elif platform == "runc":
            runc_result_ID.append(ID)
            runc_result_DIS.append(discription)
            runc_result_SCO.append(score)
            
        else:
            containerd_result_ID.append(ID)
            containerd_result_DIS.append(discription)
            containerd_result_SCO.append(score)

        q += 1

    docker_list= { "ID": docker_result_ID,
                    "discription": docker_result_DIS,
                    "Score": docker_result_SCO }
    runc_list= { "ID": runc_result_ID,
                    "discription": runc_result_DIS,
                    "Score": runc_result_SCO }
    containerd_list= { "ID": containerd_result_ID,
                    "discription": containerd_result_DIS,
                    "Score": containerd_result_SCO }
   
    return docker_list, runc_list, containerd_list

get_vulnerabilities("1.11.0", "0.1.1", "1.2.1")

# docker version | grep  Engine -A 1 | sed -n 2p | cut -d " " -f 13
# runc -v | grep runc | cut -d " " -f 3
# docker version | grep -P containerd -A 1 | sed -n 2p | cut -d " " -f 13
