package settings

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func getCertificates(configdir string) ([][]string, error) {
	files, err := ioutil.ReadDir(configdir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	rv := [][]string{}
	for _, st := range files {
		if st.IsDir() || strings.HasPrefix(st.Name(), ".") {
			continue
		}

		fp, err := os.Open(filepath.Join(configdir, st.Name()))
		if err != nil {
			return nil, err
		}
		defer fp.Close()

		scanner := bufio.NewScanner(fp)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if strings.HasPrefix(line, "#") {
				continue
			}

			names := strings.Fields(line)
			if len(names) != 0 {
				if strings.HasPrefix(names[0], "*.") {
					return nil, fmt.Errorf("settings: common name (first name in a certificate) must not be wildcard: %s", names[0])
				}
				for _, r := range rv {
					if r[0] == names[0] {
						return nil, fmt.Errorf("settings: common name found in 2 or more certificates: %s", names[0])
					}
				}
				rv = append(rv, names)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}

	return rv, nil
}
