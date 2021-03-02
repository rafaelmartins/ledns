package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Lock struct {
	fpath string
}

func NewLock(fpath string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(fpath), 0700); err != nil {
		return nil, err
	}

	fp, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("lock: lock exists: %s", fpath)
		}
		return nil, err
	}
	defer fp.Close()

	if _, err := fp.Write([]byte(fmt.Sprintf("%d\n", int32(time.Now().Unix())))); err != nil {
		return nil, err
	}

	return &Lock{fpath: fpath}, nil
}

func (l *Lock) Close() error {
	return os.Remove(l.fpath)
}
