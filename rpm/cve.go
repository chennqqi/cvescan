package rpm

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

var ErrNotUpdated = errors.New("Not Update")

type Resource struct {
	Url  string
	Path string
}

func (r *Resource) FetchUpdateResource() (bool, error) {
	var exist bool
	st, err := os.Stat(r.Path)
	if err != nil && os.IsNotExist(err) {
		exist = false
	} else if err != nil {
		return false, err
	} else {
		exist = true
	}

	client := &http.Client{}

	downloadFunc := func(fpath, furl string) error {
		req, _ := http.NewRequest("GET", furl, nil)
		req.Header.Set("", "")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		etype := resp.Header.Get("EncodingType")
		var reader io.Reader
		var gzipReader *gzip.Reader
		if strings.Contains(etype, "gzip") {
			gzipReader, _ = gzip.NewReader(resp.Body)
			reader = gzipReader
		} else {
			reader = resp.Body
		}

		f, err := os.OpenFile(fpath, os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		io.Copy(f, reader)

		if gzipReader != nil {
			gzipReader.Close()
		}
		return nil
	}

	checkUpdateFunc := func(fpath, furl string) (bool, error) {
		req, _ := http.NewRequest("HEAD", furl, nil)
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()

		if resp.ContentLength != st.Size() {
			return false, nil
		}
		return true, nil
	}

	var retry int
	var down bool

	//checkupdate
	for retry = 0; retry < 3; {
		down, err = checkUpdateFunc(r.Path, r.Url)
		if err == nil {
			break
		}
	}

	//network error
	if retry == 3 {
		return exist, err
	}
	if !down {
		return exist, nil
	}

	//download
	retry = 0
	for retry < 3 {
		err = downloadFunc(r.Path, r.Url)
		if err == nil {
			break
		}
		retry++
	}
	if retry == 3 {
		os.Remove(r.Path)
		return false, err
	}
	return true, nil
}
