import subprocess

def rule_binding_apply_test(test_framework):
    print("Running rule binding apply test")

    try:
        subprocess.check_call(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/all-valid.yaml"])
        subprocess.check_call(["kubectl", "delete", "-f", "system-tests/rule_binding_crds_files/all-valid.yaml"])
        # invalid fields
        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/invalid-name.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Invalid name test failed")
            return 1

        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/invalid-id.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Invalid id test failed")
            return 1

        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/invalid-tag.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Invalid tag test failed")
            return 1

        # duplicate fields
        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/dup-fields-name-tag.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Duplicate fields name-tag test failed")
            return 1

        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/dup-fields-name-id.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Duplicate fields name-id test failed")
            return 1

        proc_stat = subprocess.run(["kubectl", "apply", "-f", "system-tests/rule_binding_crds_files/dup-fields-id-tag.yaml"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc_stat.returncode == 0:
            print("Duplicate fields id-tag test failed")
            return 1

    except Exception as e:
        print("Exception occured: %s" % e)
        return 1

    return 0