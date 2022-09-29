package gateway_plugin_auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type (
	FormAuthorization    func(url.Values)
	RequestAuthorization func(*http.Request)
)

func HttpRequest(client *http.Client, req *http.Request, response interface{}) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status not ok: %s %s", resp.Status, body)
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v %s", err, body)
	}
	return nil
}
