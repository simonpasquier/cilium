package client

import (
	"io"
	"net/url"
	"time"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/engine-api/types"
	timetypes "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/engine-api/types/time"
)

// ContainerLogs returns the logs generated by a container in an io.ReadCloser.
// It's up to the caller to close the stream.
func (cli *Client) ContainerLogs(options types.ContainerLogsOptions) (io.ReadCloser, error) {
	query := url.Values{}
	if options.ShowStdout {
		query.Set("stdout", "1")
	}

	if options.ShowStderr {
		query.Set("stderr", "1")
	}

	if options.Since != "" {
		ts, err := timetypes.GetTimestamp(options.Since, time.Now())
		if err != nil {
			return nil, err
		}
		query.Set("since", ts)
	}

	if options.Timestamps {
		query.Set("timestamps", "1")
	}

	if options.Follow {
		query.Set("follow", "1")
	}
	query.Set("tail", options.Tail)

	resp, err := cli.get("/containers/"+options.ContainerID+"/logs", query, nil)
	if err != nil {
		return nil, err
	}
	return resp.body, nil
}
