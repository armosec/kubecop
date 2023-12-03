package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/armosec/kubecop/pkg/engine/rule"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	// "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// Main
func main() {
	// Print out a markdown table containing all the rules
	fmt.Printf("| ID | Rule | Description | Tags | Priority | Application profile |\n")
	fmt.Printf("|----|------|-------------|------|----------|---------------------|\n")
	idsList := []string{}
	namesList := []string{}
	tagsList := []string{}
	tagsMap := make(map[string]struct{})

	for _, rule := range rule.GetAllRuleDescriptors() {
		fmt.Printf("| %s | %s | %s | %s | %d | %v |\n", rule.ID, rule.Name, rule.Description, rule.Tags, rule.Priority, rule.Requirements.NeedApplicationProfile)
		idsList = append(idsList, rule.ID)
		namesList = append(namesList, rule.Name)
		for _, tag := range rule.Tags {
			tagsMap[tag] = struct{}{}
		}
	}
	for tag := range tagsMap {
		tagsList = append(tagsList, tag)
	}
	slices.Sort(tagsList)
	fillListsInCRD(idsList, namesList, tagsList)
}

func fillListsInCRD(idsList []string, namesList []string, tagsList []string) {
	gitRoot := "../../"
	pwd, err := os.Getwd()
	if err == nil {
		gitRoot, err = findGitRootDir(pwd)
		if err != nil {
			fmt.Printf("Error finding git root dir: %v\n", err)
		}
	}

	crdFilePath := "chart/kubecop/crds/runtime-rule-binding.crd.yaml"
	crdFile, err := os.OpenFile(filepath.Join(gitRoot, crdFilePath), os.O_RDWR, 0644)
	if err != nil {
		fmt.Printf("Error opening CRD file: %v\n", err)
		return
	}
	defer crdFile.Close()

	// read CRD YAML file into struct
	crDef := apiextensionsv1.CustomResourceDefinition{}
	originalFileContent := make([]byte, 4096)
	if nBytes, err := crdFile.Read(originalFileContent); err != nil {
		fmt.Printf("Error reading CRD file: %v\n", err)
		return
	} else {
		// trim to actual length to avoid unmarshalling errors like: error converting YAML to JSON: yaml: control characters are not allowed
		originalFileContent = originalFileContent[:nBytes]
	}

	if err := yaml.Unmarshal(originalFileContent, &crDef); err != nil {
		fmt.Printf("Error decoding CRD file: %v\n", err)
		return
	}
	spec := crDef.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	specRules := spec.Properties["rules"]
	// handle ruleIDs
	specRuleIDs := specRules.Items.Schema.Properties["ruleID"]
	enumVals := []apiextensionsv1.JSON{}
	for _, id := range idsList {
		enumVals = append(enumVals, apiextensionsv1.JSON{Raw: []byte("\"" + id + "\"")})
	}
	specRuleIDs.Enum = enumVals
	specRules.Items.Schema.Properties["ruleID"] = specRuleIDs
	// handle ruleNames
	specRuleNames := specRules.Items.Schema.Properties["ruleName"]
	enumVals = []apiextensionsv1.JSON{}
	for _, name := range namesList {
		enumVals = append(enumVals, apiextensionsv1.JSON{Raw: []byte("\"" + name + "\"")})
	}
	specRuleNames.Enum = enumVals
	specRules.Items.Schema.Properties["ruleName"] = specRuleNames
	// handle ruleTags
	specRuleTags := specRules.Items.Schema.Properties["ruleTags"]
	enumVals = []apiextensionsv1.JSON{}
	for _, tag := range tagsList {
		enumVals = append(enumVals, apiextensionsv1.JSON{Raw: []byte("\"" + tag + "\"")})
	}
	specRuleTags.Items.Schema.Enum = enumVals
	specRules.Items.Schema.Properties["ruleTags"] = specRuleTags
	// write back
	spec.Properties["rules"] = specRules
	crDef.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"] = spec

	// write CRD YAML file
	crdFile.Seek(0, 0)
	var jbytes []byte
	if jbytes, err = json.Marshal(crDef); err != nil {
		fmt.Printf("Error encoding CRD file to JSON: %v\n", err)
		return
	}
	// convert JSON to map[string]interface{} to remove empty fields
	var jmap map[string]interface{}
	if err := json.Unmarshal(jbytes, &jmap); err != nil {
		fmt.Printf("Error decoding CRD file from JSON: %v\n", err)
		return
	}
	// remove empty fields
	delete(jmap, "status")
	// delete(, "creationTimestamp")

	// convert back to JSON
	if jbytes, err = json.Marshal(jmap); err != nil {
		fmt.Printf("Error encoding CRD file back to JSON: %v\n", err)
		return
	}
	if newFileContent, err := yaml.JSONToYAML(jbytes); err != nil {
		fmt.Printf("Error encoding CRD file: %v\n", err)
		return
	} else {
		if nBytes, err := crdFile.Write(newFileContent); err != nil {
			fmt.Printf("Error writing CRD file: %v\n", err)
			return
		} else if nBytes != len(newFileContent) {
			fmt.Printf("Error writing CRD file: %d/%d bytes written\n", nBytes, len(newFileContent))
			return
		}
	}
}

func findGitRootDir(startDir string) (string, error) {
	currentDir := startDir
	for {
		// Check if .git directory or file exists in the current directory
		if _, err := os.Stat(filepath.Join(currentDir, ".git")); !os.IsNotExist(err) {
			return currentDir, nil
		}

		// Move up one directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// We've reached the root of the filesystem
			return "", fmt.Errorf("not a git repository (or any of the parent directories)")
		}
		currentDir = parentDir
	}
}
