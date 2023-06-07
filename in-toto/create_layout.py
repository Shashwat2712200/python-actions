from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock

def main():
  # Load Owner's private key to later sign the layout
  key_own = interface.import_rsa_privatekey_from_file("in-toto/own")
  # Fetch and load functionary's public keys
  # to specify that they are authorized to perform certain step in the layout
  key_fun1 = interface.import_rsa_publickey_from_file("in-toto/fun1.pub")
  key_fun2 = interface.import_rsa_publickey_from_file("in-toto/fun2.pub")

  layout = Layout.read({
      "_type": "layout",
      "keys": {
          key_fun1["keyid"]: key_fun1,
          key_fun2["keyid"]: key_fun2,
      },
      "steps": [
        {
          "name": "docker_build",
          "expected_materials": [],
          "expected_products": [["ALLOW", "*"]],
          "pubkeys": [key_fun1["keyid"]],
          "expected_command": [
              "docker",
              "build",
              "- t"
          ],
          "threshold": 1,
        },
        {
          "name": "checkov_scan",
          "expected_materials": [],
          "expected_products": [["ALLOW", "*"]],
          "pubkeys": [key_fun1["keyid"]],
          "expected_command": [
              "checkov",
              "- d"
          ],
          "threshold": 1,
        },
        {
          "name": "trivy_scan",
          "expected_materials": [],
          "expected_products": [["ALLOW", "*"]],
          "pubkeys": [key_fun1["keyid"]],
          "expected_command": [
              "trivy",
              "image",
              "--exit-code",
              "0"
          ],
          "threshold": 1,
        },
        {
          "name": "docker_push",
          "expected_materials": [],
          "expected_products": [["ALLOW", "*"]],
          "pubkeys": [key_fun2["keyid"]],
          "expected_command": [
              "docker",
              "push"
          ],
          "threshold": 1,
        }
        ],
      "inspect": []
    })

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  metadata.sign(key_own)
  metadata.dump("root.layout")
  print('Created demo in-toto layout as "root.layout".')

if __name__ == '__main__':
  main()