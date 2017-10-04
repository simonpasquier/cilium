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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/policy/api"
)

// L7ParserType is the type used to indicate what L7 parser to use and
// defines all supported types of L7 parsers
type L7ParserType string

const (
	// ParserTypeHTTP specifies a HTTP parser type
	ParserTypeHTTP L7ParserType = "http"
	// ParserTypeKafka specifies a Kafka parser type
	ParserTypeKafka L7ParserType = "kafka"
)

func httpEqual(a, b api.PortRuleHTTP) bool {
	if a.Path != b.Path ||
		a.Method != b.Method ||
		a.Host != b.Host ||
		len(a.Headers) != len(b.Headers) {
		return false
	}

	for i, value := range a.Headers {
		if b.Headers[i] != value {
			return false
		}
	}
	return true
}

func kafkaEqual(a, b api.PortRuleKafka) bool {
	return a.APIVersion == b.APIVersion && a.APIKey == b.APIKey && a.Topic == b.Topic
}

type L4Filter struct {
	// Port is the destination port to allow
	Port int
	// Protocol is the L4 protocol to allow or NONE
	Protocol string
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser L7ParserType
	// L7RedirectPort is the L7 proxy port to redirect to (optional)
	L7RedirectPort int
	// L7Rules is a list of L7 rules which are passed to the L7 proxy (optional)
	L7Rules api.L7Rules
	// Ingress is true if filter applies at ingress
	Ingress bool
}

// PolicyEqual returns true if the L4 filters are the same.
func (l4 L4Filter) PolicyEqual(l4b L4Filter) bool {
	if l4.Port != l4b.Port ||
		l4.Protocol != l4b.Protocol ||
		l4.L7Parser != l4b.L7Parser ||
		l4.L7RedirectPort != l4b.L7RedirectPort ||
		len(l4.L7Rules.HTTP) != len(l4b.L7Rules.HTTP) ||
		len(l4.L7Rules.Kafka) != len(l4b.L7Rules.Kafka) ||
		l4.Ingress != l4b.Ingress {
		return false
	}
	// different order => not equal
	for i, h := range l4.L7Rules.HTTP {
		if !httpEqual(h, l4b.L7Rules.HTTP[i]) {
			return false
		}
	}
	for i, k := range l4.L7Rules.Kafka {
		if !kafkaEqual(k, l4b.L7Rules.Kafka[i]) {
			return false
		}
	}
	return true
}

// CreateL4Filter creates an L4Filter based on an api.PortRule and api.PortProtocol
func CreateL4Filter(rule api.PortRule, port api.PortProtocol, direction string, protocol string) L4Filter {
	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)

	l4 := L4Filter{
		Port:           int(p),
		Protocol:       protocol,
		L7RedirectPort: rule.RedirectPort,
	}

	if strings.ToLower(direction) == "ingress" {
		l4.Ingress = true
	}

	if rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		}
		l4.L7Rules = *rule.Rules
	}

	return l4
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ""
}

// MarshalIndent returns the `L4Filter` in indented JSON string.
func (l4 *L4Filter) MarshalIndent() string {
	b, err := json.MarshalIndent(l4, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// String returns the `L4Filter` in a human-readable string.
func (l4 L4Filter) String() string {
	b, err := json.Marshal(l4)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// L4PolicyMap is a list of L4 filters indexable by protocol/port
// key format: "port/proto"
type L4PolicyMap map[string]L4Filter

// PolicyEqual returns true if the L4 policy maps are the same.
func (l4 L4PolicyMap) PolicyEqual(l4b L4PolicyMap) bool {
	if len(l4) != len(l4b) {
		return false
	}
	for key, value := range l4 {
		if l4b[key].PolicyEqual(value) {
			return false
		}
	}
	return true
}

// HasRedirect returns true if at least one L4 filter contains a port
// redirection
func (l4 L4PolicyMap) HasRedirect() bool {
	for _, f := range l4 {
		if f.IsRedirect() {
			return true
		}
	}

	return false
}

// containsAllL4 checks if the L4PolicyMap contains all `l4Ports`. Returns false
// if the `L4PolicyMap` has a single rule and l4Ports is empty or if a single
// `l4Port`'s port is not present in the `L4PolicyMap`.
func (l4 L4PolicyMap) containsAllL4(l4Ports []*models.Port) api.Decision {
	if len(l4) == 0 {
		return api.Allowed
	}

	if len(l4Ports) == 0 {
		return api.Denied
	}

	for _, l4CtxIng := range l4Ports {
		lwrProtocol := strings.ToLower(l4CtxIng.Protocol)
		switch lwrProtocol {
		case "", models.PortProtocolAny:
			tcpPort := fmt.Sprintf("%d/tcp", l4CtxIng.Port)
			_, tcpmatch := l4[tcpPort]
			udpPort := fmt.Sprintf("%d/udp", l4CtxIng.Port)
			_, udpmatch := l4[udpPort]
			if !tcpmatch && !udpmatch {
				return api.Denied
			}
		default:
			port := fmt.Sprintf("%d/%s", l4CtxIng.Port, lwrProtocol)
			if _, match := l4[port]; !match {
				return api.Denied
			}
		}
	}
	return api.Allowed
}

type L4Policy struct {
	Ingress L4PolicyMap
	Egress  L4PolicyMap
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress: make(L4PolicyMap),
		Egress:  make(L4PolicyMap),
	}
}

// IngressCoversDPorts checks if the receiver's ingress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) IngressCoversDPorts(dPorts []*models.Port) api.Decision {
	return l4.Ingress.containsAllL4(dPorts)
}

// EgressCoversDPorts checks if the receiver's egress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) EgressCoversDPorts(dPorts []*models.Port) api.Decision {
	return l4.Egress.containsAllL4(dPorts)
}

// HasRedirect returns true if the L4 policy contains at least one port redirection
func (l4 *L4Policy) HasRedirect() bool {
	return l4 != nil && (l4.Ingress.HasRedirect() || l4.Egress.HasRedirect())
}

// RequiresConntrack returns true if if the L4 configuration requires
// connection tracking to be enabled.
func (l4 *L4Policy) RequiresConntrack() bool {
	return l4 != nil && (len(l4.Ingress) > 0 || len(l4.Egress) > 0)
}

func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []string{}
	for _, v := range l4.Ingress {
		ingress = append(ingress, v.MarshalIndent())
	}

	egress := []string{}
	for _, v := range l4.Egress {
		egress = append(egress, v.MarshalIndent())
	}

	return &models.L4Policy{
		Ingress: ingress,
		Egress:  egress,
	}
}

func (l4 *L4Policy) DeepCopy() *L4Policy {
	cpy := &L4Policy{
		Ingress: make(L4PolicyMap, len(l4.Ingress)),
		Egress:  make(L4PolicyMap, len(l4.Egress)),
	}

	for k, v := range l4.Ingress {
		cpy.Ingress[k] = v
	}

	for k, v := range l4.Egress {
		cpy.Egress[k] = v
	}

	return cpy
}

// PolicyEqual returns true if the L4 policies are the same.
func (l4 *L4Policy) PolicyEqual(l4b *L4Policy) bool {
	if l4 == nil && l4b == nil {
		return true
	}
	if l4 == nil || l4b == nil {
		return false
	}
	return l4.Ingress.PolicyEqual(l4b.Ingress) && l4.Egress.PolicyEqual(l4b.Egress)
}
