// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"path"
	"sync"
	"syscall"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
)

type preFilterMapType int

const (
	prefixesV4Dyn preFilterMapType = iota
	prefixesV4Fix
	prefixesV6Dyn
	prefixesV6Fix
	mapCount
)

const (
	maxLKeys = 1024 * 64
	maxHKeys = 1024 * 1024 * 20
)

type preFilterMaps [mapCount]*cidrmap.CIDRMap

type preFilterConfig struct {
	dyn4Enabled bool
	dyn6Enabled bool
	fix4Enabled bool
	fix6Enabled bool
}

// PreFilter holds global info on related CIDR maps participating in prefilter
type PreFilter struct {
	Maps     preFilterMaps
	Config   preFilterConfig
	Revision int64
	Mutex    sync.RWMutex
}

// WriteConfig dumps the configuration for the corresponding header file
func (p *PreFilter) WriteConfig(fw io.Writer) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	fmt.Fprintf(fw, "#define CIDR4_HMAP_ELEMS %d\n", maxHKeys)
	fmt.Fprintf(fw, "#define CIDR4_LMAP_ELEMS %d\n", maxLKeys)

	fmt.Fprintf(fw, "#define CIDR4_HMAP_NAME %s\n", path.Base(p.Maps[prefixesV4Fix].String()))
	fmt.Fprintf(fw, "#define CIDR4_LMAP_NAME %s\n", path.Base(p.Maps[prefixesV4Dyn].String()))
	fmt.Fprintf(fw, "#define CIDR6_HMAP_NAME %s\n", path.Base(p.Maps[prefixesV6Fix].String()))
	fmt.Fprintf(fw, "#define CIDR6_LMAP_NAME %s\n", path.Base(p.Maps[prefixesV6Dyn].String()))

	if p.Config.fix4Enabled {
		fmt.Fprintf(fw, "#define CIDR4_FILTER\n")
		if p.Config.dyn4Enabled {
			fmt.Fprintf(fw, "#define CIDR4_LPM_PREFILTER\n")
		}
	}
	if p.Config.fix6Enabled {
		fmt.Fprintf(fw, "#define CIDR6_FILTER\n")
		if p.Config.dyn6Enabled {
			fmt.Fprintf(fw, "#define CIDR6_LPM_PREFILTER\n")
		}
	}
}

func (p *PreFilter) dumpOneMap(which preFilterMapType, to []string) []string {
	if p.Maps[which] == nil {
		return to
	}
	return p.Maps[which].CIDRDump(to)
}

// Dump dumps revision and CIDRs as string slice of all participating maps
func (p *PreFilter) Dump(to []string) ([]string, int64) {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	for i := prefixesV4Dyn; i < mapCount; i++ {
		to = p.dumpOneMap(i, to)
	}
	return to, p.Revision
}

func (p *PreFilter) selectMap(ones, bits int) preFilterMapType {
	if bits == 32 {
		if ones == bits {
			return prefixesV4Fix
		}
		return prefixesV4Dyn
	} else if bits == 128 {
		if ones == bits {
			return prefixesV6Fix
		}
		return prefixesV6Dyn
	} else {
		return mapCount
	}
}

// Insert inserts slice of CIDRs (doh!) for the latest revision
func (p *PreFilter) Insert(revision int64, cidrs []net.IPNet) error {
	var undoQueue []net.IPNet
	var ret error

	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	if p.Revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.Revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		if which == mapCount || p.Maps[which] == nil {
			ret = fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
			break
		}
		err := p.Maps[which].InsertCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error inserting CIDR string %s: %s", cidr.String(), err)
			break
		} else {
			undoQueue = append(undoQueue, cidr)
		}
	}
	if ret == nil {
		p.Revision++
		return ret
	}
	for _, cidr := range undoQueue {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		p.Maps[which].DeleteCIDR(cidr)
	}
	return ret
}

// Delete deletes slice of CIDRs (doh!) for the latest revision
func (p *PreFilter) Delete(revision int64, cidrs []net.IPNet) error {
	var undoQueue []net.IPNet
	var ret error

	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	if p.Revision != revision {
		return fmt.Errorf("Latest revision is %d not %d", p.Revision, revision)
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		if which == mapCount || p.Maps[which] == nil {
			ret = fmt.Errorf("No map enabled for CIDR string %s", cidr.String())
			break
		}
		// Lets check obvious cases first, so we don't need to painfully unroll
		if p.Maps[which].CIDRExists(cidr) == false {
			ret = fmt.Errorf("No map entry for CIDR string %s", cidr.String())
			break
		}
	}
	if ret != nil {
		return ret
	}
	for _, cidr := range cidrs {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		err := p.Maps[which].DeleteCIDR(cidr)
		if err != nil {
			ret = fmt.Errorf("Error deleting CIDR string %s: %s", cidr.String(), err)
			break
		} else {
			undoQueue = append(undoQueue, cidr)
		}
	}
	if ret == nil {
		p.Revision++
		return ret
	}
	for _, cidr := range undoQueue {
		ones, bits := cidr.Mask.Size()
		which := p.selectMap(ones, bits)
		p.Maps[which].InsertCIDR(cidr)
	}
	return ret
}

func (p *PreFilter) initOneMap(which preFilterMapType) error {
	var prefixdyn bool
	var prefixlen int
	var maxelems uint32
	var path string
	var err error
	var skip bool

	switch which {
	case prefixesV4Dyn:
		prefixlen = 32
		prefixdyn = true
		maxelems = maxLKeys
		path = bpf.MapPath(cidrmap.MapName + "v4_dyn")
		skip = p.Config.dyn4Enabled == false
	case prefixesV4Fix:
		prefixlen = 32
		prefixdyn = false
		maxelems = maxHKeys
		path = bpf.MapPath(cidrmap.MapName + "v4_fix")
		skip = p.Config.fix4Enabled == false
	case prefixesV6Dyn:
		prefixlen = 128
		prefixdyn = true
		maxelems = maxLKeys
		path = bpf.MapPath(cidrmap.MapName + "v6_dyn")
		skip = p.Config.dyn6Enabled == false
	case prefixesV6Fix:
		prefixlen = 128
		prefixdyn = false
		maxelems = maxHKeys
		path = bpf.MapPath(cidrmap.MapName + "v6_fix")
		skip = p.Config.fix4Enabled == false
	}
	if skip == false {
		p.Maps[which], _, err = cidrmap.OpenMapElems(path, prefixlen, prefixdyn, maxelems)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PreFilter) init() (*PreFilter, error) {
	var err error
	for i := prefixesV4Dyn; i < mapCount; i++ {
		err = p.initOneMap(i)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ProbePreFilter checks whether XDP mode is supported on given device
func ProbePreFilter(device, mode string) error {
	cmd := exec.Command("ip", "-force", "link", "set", "dev", device, mode, "off")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Cannot run ip command: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				switch status.ExitStatus() {
				case 0:
				case 2:
					return fmt.Errorf("Mode %s not supported on device %s", mode, device)
				default:
					return fmt.Errorf("Prefilter not supported on OS")
				}
			}
		} else {
			return fmt.Errorf("Cannot wait for ip command: %v", err)
		}
	}
	return nil
}

// NewPreFilter returns prefilter handle
func NewPreFilter() (*PreFilter, error) {
	// dyn{4,6} officially disabled for now due to missing
	// dump (get_next_key) from kernel side.
	c := preFilterConfig{
		dyn4Enabled: false,
		dyn6Enabled: false,
		fix4Enabled: true,
		fix6Enabled: true,
	}
	p := &PreFilter{
		Config: c,
	}
	// Only needed here given we access pinned maps.
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.init()
}
