import sys
import os
import json
import subprocess
from Tests.test_utils import print_warning, print_error
import Tests.scripts.awsinstancetool.aws_functions as aws_functions


def main():
    circle_aritfact = sys.argv[1]
    envfile = sys.argv[2]

    with open(envfile, 'r') as json_file:
        env_results = json.load(json_file)

    for env in env_results:
        if not os.path.isfile("./Tests/is_build_failed_{}.txt".format(env["Role"].replace(' ', ''))):
            ssh_string = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{} ' \
                         '"sudo chmod -R 755 /var/log/demisto"'
            scp_string = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ' \
                         '{}@{}:/var/log/demisto/server.log {} || echo "WARN: Failed downloading server.log"'

            try:
                subprocess.check_output(
                    ssh_string.format(env["SSHuser"], env["InstanceDNS"]), shell=True)

            except subprocess.CalledProcessError as exc:
                print(exc.output)

            try:
                subprocess.check_output(
                    scp_string.format(
                        env["SSHuser"],
                        env["InstanceDNS"],
                        "{}/server_{}.log".format(circle_aritfact, env["Role"].replace(' ', ''))),
                    shell=True)

            except subprocess.CalledProcessError as exc:
                print(exc.output)

            rminstance = aws_functions.destroy_instance(env["Region"], env["InstanceID"])
            if aws_functions.isError(rminstance):
                print_error(rminstance)
        else:
            print_warning("Tests failed on {} ,keeping instance alive".format(env["Role"]))


if __name__ == "__main__":
    main()
