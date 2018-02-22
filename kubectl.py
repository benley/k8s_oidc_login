"""Thin shim around kubectl."""

import gflags

import resources
import basewrapper

gflags.DEFINE_string(
    "kubectl_path",
    resources.get_resource_filename(
        "com_postmates_pi_k8s/third_party/kubectl/kubectl",
    ),
    "Path to kubectl. Default is to use built-in version.")

FLAGS = gflags.FLAGS


class Kubectl(basewrapper.ToolWrapper):
    def extract(self):
        return FLAGS.kubectl_path or resources.get_resource_filename(
            "com_postmates_pi_k8s/third_party/kubectl/kubectl")


_kubectl = Kubectl()
call = Kubectl().call
check_call = Kubectl().check_call
check_output = Kubectl().check_output
