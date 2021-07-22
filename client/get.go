package client

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/pinterest/knox"
)

func init() {
	cmdGet.Run = runGet // break init cycle
}

var cmdGet = &Command{
	UsageLine: "get [-v key_version] [-n] [-j] [-a] [--tink-keyset] [--tink-keyset-info] <key_identifier>",
	Short:     "get a knox key",
	Long: `
Get gets the key data for a key.

-v specifies the key_version to get. If it is not provided, this returns the primary version.
-j returns the json version of the key as specified in the knox API.
-n forces a network call. This will avoid cache issues where the ACL is out of date.
-a returns all key versions (including inactive ones). Only works when -j is specified.
--tink-keyset retrieve all the primary and active versions of this identifier in knox, combine them, and return one tink keyset. Force to retrieve tink keyset if -n is specified.
--tink-keyset-info retrieves keyset metadata for primary and active versions without revealing the secret keys. Force to retrieve tink keyset metadata if -n is specified.

This requires read access to the key.

For more about knox, see https://github.com/pinterest/knox.

See also: knox create, knox daemon, knox register, knox keys
	`,
}
var getVersion = cmdGet.Flag.String("v", "", "")
var getJSON = cmdGet.Flag.Bool("j", false, "")
var getNetwork = cmdGet.Flag.Bool("n", false, "")
var getAll = cmdGet.Flag.Bool("a", false, "")
var getTinkKeyset = cmdGet.Flag.Bool("tink-keyset", false, "get the stored tink keyset of the given knox identifier entirely")
var getTinkKeysetInfo = cmdGet.Flag.Bool("tink-keyset-info", false, "get the metadata of the stored tink keyset of the given knox identifier")

func runGet(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("get takes only one argument. See 'knox help get'")
	}
	keyID := args[0]

	var err error
	var key *knox.Key
	if *getTinkKeyset {
		tinkKeysetInBytes, err := retrieveTinkKeyset(keyID, *getNetwork)
		if err != nil {
			fatalf(err.Error())
		}
		fmt.Printf("%s", string(tinkKeysetInBytes))
		return
	}
	if *getTinkKeysetInfo {
		tinkKeysetInfo, err := retrieveTinkKeysetInfo(keyID, *getNetwork)
		if err != nil {
			fatalf(err.Error())
		}
		fmt.Println(tinkKeysetInfo)
		return
	}
	if *getAll {
		// By specifying status as inactive, we can get all key versions (active + inactive + primary)
		// from knox server
		if *getNetwork {
			key, err = cli.NetworkGetKeyWithStatus(keyID, knox.Inactive)
		} else {
			key, err = cli.GetKeyWithStatus(keyID, knox.Inactive)
		}
	} else {
		if *getNetwork {
			key, err = cli.NetworkGetKey(keyID)
		} else {
			key, err = cli.GetKey(keyID)
		}
	}
	if err != nil {
		fatalf("Error getting key: %s", err.Error())
	}
	if *getJSON {
		data, err := json.Marshal(key)
		if err != nil {
			fatalf(err.Error())
		}
		fmt.Printf("%s", string(data))
		return
	}
	if *getVersion == "" {
		fmt.Printf("%s", string(key.VersionList.GetPrimary().Data))
		return
	}
	for _, v := range key.VersionList {
		if strconv.FormatUint(v.ID, 10) == *getVersion {
			fmt.Printf("%s", string(v.Data))
			return
		}
	}
	fatalf("Key version not found.")

}

func retrieveTinkKeyset(keyID string, getFromNetwork bool) ([]byte, error) {
	if !isIDforTinkKeyset(keyID) {
		return nil, fmt.Errorf("this knox identifier is not for tink keyset")
	}
	// get the primary and all active versions of this knox identifier.
	var primaryAndActiveVersions *knox.Key
	var err error
	if getFromNetwork {
		primaryAndActiveVersions, err = cli.NetworkGetKey(keyID)
	} else {
		primaryAndActiveVersions, err = cli.GetKey(keyID)
	}
	if err != nil {
		return nil, fmt.Errorf("error getting key: %s", err.Error())
	}
	keysetHandle, _, err := getTinkKeysetHandleFromKnoxVersionList(primaryAndActiveVersions.VersionList)
	if err != nil {
		return nil, err
	}
	tinkKeysetInBytes, err := convertTinkKeysetHandleToBytes(keysetHandle)
	if err != nil {
		return nil, err
	}
	return tinkKeysetInBytes, nil
}

func retrieveTinkKeysetInfo(keyID string, getFromNetwork bool) (string, error) {
	if !isIDforTinkKeyset(keyID) {
		return "", fmt.Errorf("this knox identifier is not for tink keyset")
	}
	// get the primary and all active versions of this knox identifier.
	var primaryAndActiveVersions *knox.Key
	var err error
	if getFromNetwork {
		primaryAndActiveVersions, err = cli.NetworkGetKey(keyID)
	} else {
		primaryAndActiveVersions, err = cli.GetKey(keyID)
	}
	keysetHandle, tinkKeyIDToKnoxVersionID, err := getTinkKeysetHandleFromKnoxVersionList(primaryAndActiveVersions.VersionList)
	if err != nil {
		return "", err
	}
	tinkKeysetInfo, err := getKeysetInfoFromTinkKeysetHandle(keysetHandle, tinkKeyIDToKnoxVersionID)
	if err != nil {
		return "", err
	}
	return tinkKeysetInfo, nil
}
